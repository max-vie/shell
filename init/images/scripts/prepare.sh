#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
images_dir=$(cd -- "$script_dir/.." && pwd)
repo_root=$(cd -- "$images_dir/../.." && pwd)
lock_file=$images_dir/images.lock.json
private_root=$(realpath -m -- "$repo_root/.local")
local_root=$(realpath -m -- "${SHELL_IMAGE_ROOT:-$private_root/init-images}")
public_key_file=${INIT_PUBLIC_KEY_FILE:-}

case "$local_root/" in
  "$private_root/"*) ;;
  *)
    printf 'SHELL_IMAGE_ROOT must stay under %s\n' "$private_root" >&2
    exit 2
    ;;
esac

if [[ -z "$public_key_file" || ! -f "$public_key_file" || ! -r "$public_key_file" ]]; then
  printf 'INIT_PUBLIC_KEY_FILE must name one readable public key.\n' >&2
  exit 2
fi
for required_command in \
  curl flock jq qemu-img realpath sha256sum sha512sum ssh-keygen \
  virt-cat virt-customize virt-inspector virt-sysprep; do
  command -v "$required_command" >/dev/null || {
    printf 'Missing required image tool: %s\n' "$required_command" >&2
    exit 2
  }
done
ssh-keygen -l -f "$public_key_file" >/dev/null
[[ "$(wc -l <"$public_key_file")" -eq 1 ]]
grep -Eq '^ssh-(ed25519|rsa|ecdsa-sha2-nistp(256|384|521)) ' \
  "$public_key_file"

source_dir=$local_root/source
output_dir=$local_root/prepared
manifest_file=$local_root/manifest.json
variables_file=$local_root/proxmox-k3s.tfvars.json

for private_directory in "$source_dir" "$output_dir"; do
  if [[ -L "$private_directory" ]]; then
    printf 'Refusing symlinked image directory: %s\n' "$private_directory" >&2
    exit 2
  fi
done
mkdir -p "$source_dir" "$output_dir"
chmod 0700 "$local_root" "$source_dir" "$output_dir"

exec 9>"$local_root/prepare.lock"
flock -n 9 || {
  printf 'Another Debian image preparation is already running.\n' >&2
  exit 2
}

build_dir=$(mktemp -d "$local_root/work.XXXXXX")
cleanup() {
  if [[ -d "$build_dir" ]]; then
    rm -r -- "$build_dir"
  fi
}
trap cleanup EXIT

source_url=$(jq -er '.images.debian.source_url' "$lock_file")
source_file=$(jq -er '.images.debian.source_file' "$lock_file")
source_algorithm=$(jq -er '.images.debian.checksum_algorithm' "$lock_file")
expected_checksum=$(jq -er '.images.debian.checksum' "$lock_file")
output_file=$(jq -er '.images.debian.output_file' "$lock_file")

[[ "$source_url" == https://* ]]
[[ "$source_algorithm" == sha512 ]]
[[ "$source_file" == "$(basename -- "$source_file")" ]]
[[ "$output_file" == "$(basename -- "$output_file")" ]]
[[ "$source_file" == *.qcow2 && "$output_file" == *.qcow2 ]]

source_image=$source_dir/$source_file
if [[ -L "$source_image" ]]; then
  printf 'Refusing symlinked cached source image: %s\n' "$source_image" >&2
  exit 2
fi
if [[ ! -f "$source_image" ]]; then
  downloaded_image=$build_dir/source.download
  curl \
    --fail \
    --location \
    --proto '=https' \
    --retry 3 \
    --show-error \
    --tlsv1.2 \
    --output "$downloaded_image" \
    "$source_url"
  downloaded_checksum=$(sha512sum "$downloaded_image" | cut -d' ' -f1)
  if [[ "$downloaded_checksum" != "$expected_checksum" ]]; then
    printf 'Downloaded Debian image checksum does not match the lock.\n' >&2
    exit 2
  fi
  mv -- "$downloaded_image" "$source_image"
fi
source_checksum=$(sha512sum "$source_image" | cut -d' ' -f1)
if [[ "$source_checksum" != "$expected_checksum" ]]; then
  printf 'Cached Debian image checksum does not match the lock: %s\n' \
    "$source_image" >&2
  exit 2
fi

working_image=$build_dir/$output_file
converted_image=$build_dir/prepared.qcow2
cp --reflink=auto -- "$source_image" "$working_image"

# `--network` lets virt-customize install current Debian packages. The source
# image and output are hash-pinned, but package bytes can still drift until TAR
# supplies a dated Debian snapshot repository.
virt-customize --no-logfile --network -a "$working_image" \
  --install "ca-certificates,curl,cloud-init,openssh-server,python3,qemu-guest-agent,sudo,systemd-resolved" \
  --run "$images_dir/files/prepare-guest.sh" \
  --ssh-inject "init:file:$public_key_file" \
  --run-command "dpkg-query -W -f='\${Package}=\${Version}\\n' ca-certificates cloud-init curl openssh-server python3 qemu-guest-agent sudo systemd-resolved | sort > /var/lib/init/package-versions.txt"

package_versions=$(virt-cat -a "$working_image" /var/lib/init/package-versions.txt)
virt-sysprep \
  --operations machine-id,ssh-hostkeys,dhcp-client-state,net-hostname,logfiles,tmp-files,udev-persistent-net \
  -a "$working_image"

qemu-img check "$working_image"
qemu-img convert -p -O qcow2 -c "$working_image" "$converted_image"
qemu-img check "$converted_image"

inspector_file=$build_dir/debian-virt-inspector.xml
virt-inspector -a "$converted_image" >"$inspector_file"
grep -q '<distro>debian</distro>' "$inspector_file"
grep -q '<major_version>13</major_version>' "$inspector_file"

prepared_sha256=$(sha256sum "$converted_image" | cut -d' ' -f1)
prepared_name=${output_file%.qcow2}-${prepared_sha256:0:12}.qcow2
output_image=$output_dir/$prepared_name
temporary_manifest=$build_dir/manifest.json
temporary_variables=$build_dir/proxmox-k3s.tfvars.json

if [[ -L "$output_image" ]]; then
  printf 'Refusing symlinked prepared image: %s\n' "$output_image" >&2
  exit 2
fi

jq -n \
  --arg source_url "$source_url" \
  --arg source_file "$source_file" \
  --arg source_checksum "$expected_checksum" \
  --arg source_path "$source_image" \
  --arg output_path "$output_image" \
  --arg output_file "$prepared_name" \
  --arg output_checksum "$prepared_sha256" \
  --arg guestfs_version "$(virt-customize --version)" \
  --arg package_versions "$package_versions" \
  '{schema_version:1,
    sources:{debian:{url:$source_url,file_name:$source_file,checksum_algorithm:"sha512",checksum:$source_checksum,path:$source_path}},
    toolchain:{guestfs:$guestfs_version},
    package_contract:{debian:($package_versions | split("\n") | map(select(length > 0)))},
    prepared:{debian:{path:$output_path,file_name:$output_file,sha256:$output_checksum}},
    vm_image:{path:$output_path,file_name:$output_file,sha256:$output_checksum}}' \
  >"$temporary_manifest"

jq -n \
  --arg path "$output_image" \
  --arg file_name "$prepared_name" \
  --arg sha256 "$prepared_sha256" \
  '{debian_image:{path:$path,file_name:$file_name,sha256:$sha256}}' \
  >"$temporary_variables"

if [[ -f "$output_image" ]]; then
  existing_checksum=$(sha256sum "$output_image" | cut -d' ' -f1)
  if [[ "$existing_checksum" != "$prepared_sha256" ]]; then
    printf 'Prepared image name collides with different content: %s\n' \
      "$output_image" >&2
    exit 2
  fi
  rm -- "$converted_image"
else
mv -- "$converted_image" "$output_image"
fi
mv -- "$inspector_file" "$local_root/debian-virt-inspector.xml"
mv -- "$temporary_variables" "$variables_file"
mv -- "$temporary_manifest" "$manifest_file"
printf 'Prepared Debian image manifest: %s\n' "$manifest_file"

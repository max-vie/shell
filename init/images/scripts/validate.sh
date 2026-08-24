#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
images_dir=$(cd -- "$script_dir/.." && pwd)
repo_root=$(cd -- "$images_dir/../.." && pwd)
lock_file=$images_dir/images.lock.json
manifest_file=${SHELL_IMAGE_ROOT:-$repo_root/.local/init-images}/manifest.json

for required_command in \
  curl flock jq qemu-img realpath sha256sum sha512sum shellcheck ssh-keygen \
  virt-cat virt-customize virt-inspector virt-sysprep; do
  command -v "$required_command" >/dev/null || {
    printf 'Missing required image validation tool: %s\n' \
      "$required_command" >&2
    exit 2
  }
done

jq -e '
  .schema_version == 1 and
  (.images | keys == ["debian"]) and
  (.images.debian.family == "debian") and
  (.images.debian.version == "13") and
  (.images.debian.source_url | startswith("https://")) and
  (.images.debian.source_file | test("^[A-Za-z0-9._+-]+[.]qcow2$")) and
  (.images.debian.checksum_algorithm == "sha512") and
  (.images.debian.checksum | test("^[0-9a-f]{128}$")) and
  (.images.debian.output_file | test("^[A-Za-z0-9._+-]+[.]qcow2$"))
' "$lock_file" >/dev/null

if [[ -f "$manifest_file" ]]; then
  jq -e '
    .schema_version == 1 and
    (.sources.debian.checksum | test("^[0-9a-f]{128}$")) and
    (.prepared.debian.sha256 | test("^[0-9a-f]{64}$")) and
    (.vm_image.sha256 == .prepared.debian.sha256) and
    (.package_contract.debian | any(startswith("qemu-guest-agent=")))
  ' "$manifest_file" >/dev/null
fi

bash -n "$script_dir/prepare.sh"
sh -n "$images_dir/files/prepare-guest.sh"
shellcheck "$script_dir/prepare.sh" "$script_dir/validate.sh" \
  "$images_dir/files/prepare-guest.sh"

available_operations=$(virt-sysprep --list-operations | awk '{print $1}')
for operation in \
  machine-id ssh-hostkeys dhcp-client-state net-hostname logfiles tmp-files \
  udev-persistent-net; do
  grep -Fx "$operation" <<<"$available_operations" >/dev/null
done

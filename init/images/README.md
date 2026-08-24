# Debian guest image

This directory prepares one reusable Debian 13 baseline for the nested
Proxmox K3s guests. The source checksum is tracked; downloaded sources,
prepared images, manifests, and generated OpenTofu inputs stay under ignored
`.local/init-images/`.

`virt-customize` installs the common guest packages, the `init` account, SSH
policy, and the QEMU guest agent. `virt-sysprep` removes machine-specific
state. Proxmox initialization supplies each guest's hostname and network;
Ansible owns later guest configuration.

The key-only `init` account has passwordless root sudo for the guest
configuration boundary. SUDO must review and replace that broad bootstrap
authority before the account becomes a long-lived service identity.

The manifest records the exact package versions installed during preparation.
The package repository is networked and can change between builds, so the
prepared image checksum remains the authoritative input. Prepared filenames
include that checksum, so publishing a new manifest cannot invalidate the
previous image. A future TAR-owned snapshot repository is required before this
workflow can claim byte-for-byte reproducibility.

Packer is deliberately deferred until this simpler offline path has a proven
guest contract.

# INIT runtime guidance

INIT uses private routes, credentials, and local state for provider access and
guest configuration. This page groups those operating rules by concern.

## Access

### Routes

| Consumer | Target | Route | Required private inputs |
| --- | --- | --- | --- |
| OpenTofu Google roots | Google Cloud resources | Google provider API | Application default credentials or workload identity federation |
| OpenTofu Proxmox root | Nested Proxmox API | IAP TCP tunnel to the private GCP host | Proxmox endpoint, API token, IAP identity, and reviewed host trust |
| OpenTofu Proxmox image upload | Proxmox node SSH | SSH through the private IAP tunnel | OS Login identity, SSH agent, and host-key policy |
| Ansible GCP guests | Direct GCP guests | GCP IAP `ProxyCommand` and OS Login | Private inventory, project, zone, user, SSH agent, and `known_hosts` |
| Ansible Proxmox guests | Nested guest network | Private route through the Proxmox host | Private inventory route, guest user, SSH material, and host-key policy |

Ansible's generated inventory supplies the instance name, zone, project,
private address, and transport label. The private inventory supplies the OS
Login user, SSH agent or key handoff, and reviewed `known_hosts` file.

The Proxmox host has no external address. A private execution wrapper provides
two IAP TCP tunnels: local port `18006` to API port `8006`, and local port
`10022` to SSH port `22`. Set `PROXMOX_VE_ENDPOINT` to the private local API
endpoint without an `/api2/json` suffix. Keep TLS verification enabled, and
make sure the Proxmox certificate matches the private API name. The provider
uses `SSH_AUTH_SOCK` for image upload.

Ansible reaches Proxmox guests through the private route recorded in the
ignored inventory. Keep the route on `10.66.0.0/24` and target the declared
Proxmox guests only. Provider authentication, tunnel reachability, guest
readiness, and K3s API health need separate approved execution and evidence.

## Secrets

### Inventory and handling

| Material | Owner | Used by | Private location or handoff |
| --- | --- | --- | --- |
| Google application credentials | SUDO and the execution environment | OpenTofu Google provider | Outside the checkout, through application default credentials or workload identity federation |
| Proxmox API token | SUDO | OpenTofu Proxmox provider | Private process environment or wrapper |
| SSH agent and key material | SUDO and the execution environment | OpenTofu image upload and Ansible | SSH agent or private files outside Git |
| K3s join token | SUDO/TAR | INIT K3s playbooks | Private token-file path supplied at runtime |
| Administrator kubeconfig | INIT | Later cluster consumers | Ignored `.local/ansible/kubeconfig/` state, mode `0600` |

Keep credentials, private keys, token values, kubeconfigs, state, plans, and
generated inventories out of Git. Keep real variable files outside tracked
source and use `.tfvars` files for private input values. Pass process
credentials through a private wrapper or environment, never shell history.
Use `umask 077` for private handoff files, private `.local/` directories, and
TLS and SSH host-key verification.

The Proxmox provider reads `PROXMOX_VE_ENDPOINT` and
`PROXMOX_VE_API_TOKEN` from the private process environment. Use a
privilege-separated `root@pam` token limited to the INIT pool, image and guest
datastores, bridge, and declared VM IDs. INIT leaves creation of this identity,
token, and access-control tree to SUDO.

The K3s configuration playbook reads the join token from the private
SUDO/TAR-provided path, trims the source value, and writes one trailing
newline to the guest token file with mode `0600`. It renders the K3s
configuration with mode `0600` and exports the administrator kubeconfig to
ignored local state. The complete K3s contract lives in
[`k3s-runtime.md`](k3s-runtime.md).

### OpenBao transition

The provider and Ansible handoff is temporary. When OpenBao becomes the
approved secret owner, replace the private environment and file-path inputs
with the reviewed OpenBao handoff. Record the transition after the new owner
and read-only retrieval path have source and live evidence.

## State

### State map

| State | Location | Owner or producer |
| --- | --- | --- |
| Shared GCP state | `.local/opentofu/gcp/shared/` | `init/opentofu/gcp/shared` |
| Direct GCP K3s state | `.local/opentofu/gcp/k3s/` | `init/opentofu/gcp/k3s` |
| Nested Proxmox host state | `.local/opentofu/gcp/proxmox-host/` | `init/opentofu/gcp/proxmox-host` |
| Proxmox K3s guest state | `.local/opentofu/proxmox/k3s/` | `init/opentofu/proxmox/k3s` |
| Rendered Ansible inventory | `.local/ansible/inventory.json` | `init/scripts/render_node_inventory.py` |
| K3s administrator kubeconfig | `.local/ansible/kubeconfig/` | K3s configuration playbook |
| Prepared image inputs and outputs | `.local/init-images/` | `init/images/` |
| Proxmox image-upload temporary files | Private `PROXMOX_VE_TMPDIR` | Proxmox provider wrapper |

Keep state, plans, provider caches, private SSH configuration, runtime inputs,
and generated inventory under private ignored state. Use mode `0700` for
directories, mode `0600` for sensitive files, mode `0644` for public files,
and `umask 077` for private handoffs. Remove temporary plans, credentials,
image staging files, and tunnel state when the owning process exits. Local
state proves that a handoff was written; provider access, guest startup,
network reachability, K3s quorum, and recovery need separate evidence.

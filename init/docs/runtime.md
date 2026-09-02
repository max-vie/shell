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
The renderer rejects duplicate JSON keys, sensitive OpenTofu output envelopes,
and K3s output that omits its operating-system or image identity.

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

## Identity and delivery contract previews

SUDO owns the source-only FreeIPA policy for `identity-01` and the trust and
private-input boundary for `delivery-01`. The identity target is AlmaLinux 9,
which is RHEL-compatible. INIT records the separate GCP image contract and
keeps the identity host out of the direct-GCP Debian baseline group, but does
not yet prepare or prove the identity image.

TAR owns the source-reference delivery image lock. MAKE owns the delivery-node
consumer requirements and the later Forgejo service deployment. INIT consumes
these public contracts through the identity and delivery preview playbooks.
The previews validate ownership, host identity, DNS and service references,
artifact pins, and private-input shapes, then refuse normal execution while
artifact and credential handoffs remain incomplete.

The delivery image tags and linux/amd64 digests were resolved through registry
inspection on 26.08.2026. The lock remains source-reference-only because the
images have not been acquired, staged, signature-verified, or run.

The refusal gates apply when Ansible selects the declared role group and runs
the `always` pre-tasks. An empty or excluded target can produce a no-host
result, so these previews must be wrapped by an exact-target preflight before
any mutation tasks are added.

No FreeIPA package installation, credential generation, image acquisition,
guest startup, Forgejo deployment, or live DNS proof is included in this
source-only boundary.

### GCP platform add-ons

The GCP platform launcher prepares the three K3s hosts for later MAKE-owned
workloads. INIT installs the required host packages, mounts one dedicated
ext4 data disk per node at `/var/lib/longhorn`, and installs the SUDO-owned
platform certificate authority. The GCP OpenTofu roots also own the internal
proxy load-balancer subnet and the `.221` and `.222` service frontends. INIT
does not install MetalLB, Longhorn, Harbor, Argo CD, OpenBao, or release-feed.
MAKE remains the only lifecycle that may change Kubernetes workloads.

The service frontends pass TLS on port `443` to the MAKE-owned Harbor and
release-feed NodePorts `30443` and `30444`. Provider state, health checks,
backend reachability, and service traffic require separate live evidence.

The disk gate accepts an existing ext4 filesystem only when the device is
unmounted or already mounted at `/var/lib/longhorn`. Formatting is allowed
only when `blkid` finds no recognized filesystem, `lsblk` finds no partition
or mount, and the operator has reviewed the exact device and supplied the
separate destructive approval. A device with any other recognized type is
refused. The source must not describe an unrecognized device as empty because
this check does not prove that it holds no recoverable data.

The launcher accepts only the fixed GCP K3s group and host-preparation
playbooks. Source checks and Ansible lint do not prove the disk identity or
contents, mounted state, node certificate trust, K3s restart safety, or any
Kubernetes storage and load-balancer behavior.

## Secrets

### Inventory and handling

| Material | Owner | Used by | Private location or handoff |
| --- | --- | --- | --- |
| Google application credentials | SUDO and the execution environment | OpenTofu Google provider | Outside the checkout, through application default credentials or workload identity federation |
| Proxmox API token | SUDO | OpenTofu Proxmox provider | Private process environment or wrapper |
| SSH agent and key material | SUDO and the execution environment | OpenTofu image upload and Ansible | SSH agent or private files outside Git |
| K3s server token | SUDO | INIT K3s playbooks | Fixed per-cluster path derived by INIT |
| Administrator kubeconfig | INIT | Later cluster consumers | Ignored `.local/ansible/kubeconfig/` state, mode `0600` |

Keep credentials, private keys, token values, kubeconfigs, state, plans, and
generated inventories out of Git, regardless of their storage format. Keep
real variable files outside tracked source and use `.tfvars` files for private
input values. Pass process
credentials through a private wrapper or environment, never shell history.
Use `umask 077` for private handoff files, private `.local/` directories, and
TLS and SSH host-key verification.

The Proxmox provider reads `PROXMOX_VE_ENDPOINT` and
`PROXMOX_VE_API_TOKEN` from the private process environment. Use a
privilege-separated `root@pam` token limited to the INIT pool, image and guest
datastores, bridge, and declared VM IDs. INIT leaves creation of this identity,
token, and access-control tree to SUDO.

The K3s configuration playbook reads the server token from the private
SUDO-provided path, trims the source value, and writes one trailing newline
to the guest token file with mode `0600`. The first server uses the short
server-token form because a self-signed certificate-authority hash does not
exist before startup. K3s later writes secure token material that must remain
protected and be backed up with the matching datastore. The playbook renders
the K3s configuration with mode `0600` and exports the administrator kubeconfig
to ignored local state. The complete K3s contract lives in
[`k3s-runtime.md`](k3s-runtime.md).

### OpenBao handoff

The source contracts select OpenBao as the intended runtime secret owner for
release-feed. SUDO defines encrypted bootstrap custody and release-feed input
shapes. MAKE defines a Kubernetes-authenticated role and an agent that would
render only the read and write token files into the release-feed pod.

This handoff cannot run yet. The K3s API certificate authority and reviewer
identity handoffs, a supported route to the ClusterIP-only OpenBao service,
independent custody of Shamir shares, Raft member joins, and per-node unseal
are unresolved. Source validation does not prove bootstrap, custody, unseal,
token issuance, or retrieval.

## State

### State map

| State | Location | Owner or producer |
| --- | --- | --- |
| Shared GCP state | `.local/opentofu/gcp/shared/` | `init/opentofu/gcp/shared` |
| Direct GCP K3s state | `.local/opentofu/gcp/k3s/` | `init/opentofu/gcp/k3s` |
| Nested Proxmox host state | `.local/opentofu/gcp/proxmox-host/` | `init/opentofu/gcp/proxmox-host` |
| Proxmox K3s guest state | `.local/opentofu/proxmox/k3s/` | `init/opentofu/proxmox/k3s` |
| Rendered Ansible inventory | `.local/ansible/inventory.json` | `init/scripts/render_node_inventory.py` |
| Private Ansible connection inventory | `.local/ansible/connection-inventory.yml` | private INIT input |
| K3s runtime variables | `.local/ansible/k3s-runtime/<cluster>.json` | private INIT input |
| K3s administrator kubeconfig | `.local/ansible/kubeconfig/` | K3s configuration playbook |
| Prepared image inputs and outputs | `.local/init-images/` | `init/images/` |
| Proxmox image-upload temporary files | Private `PROXMOX_VE_TMPDIR` | Proxmox provider wrapper |

Keep state, plans, provider caches, private SSH configuration, runtime inputs,
and generated inventory under private ignored state. Use mode `0700` for
directories, mode `0600` for sensitive files, mode `0644` for public files,
and `umask 077` for private handoffs. The SUDO token generator requires the
existing `.local` root to already be `0700` and refuses to repair it — set it
once with `chmod 0700 .local` before the first `--generate`. Remove temporary
plans, credentials, image staging files, and tunnel state when the owning
process exits. Local state proves that a handoff was written; provider access,
guest startup, network reachability, K3s quorum, and recovery need separate
evidence.

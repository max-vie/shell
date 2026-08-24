# Use the BPG Proxmox provider for K3s guests

Last updated: 24.08.2026

## Summary

Use `bpg/proxmox` `0.111.1` for the Proxmox K3s guest root.
Read credentials from a private process environment, verify TLS, and keep
guest state under the ignored `.local/` directory.

## Context

The Proxmox host runs inside GCP, but INIT still needs one guest root without
hardcoded credentials or guest network values. BPG provides the required
OpenTofu VM resources and API-token authentication.

## Decision

Use `bpg/proxmox` in `init/opentofu/proxmox/k3s/`. Read
`PROXMOX_VE_ENDPOINT` and `PROXMOX_VE_API_TOKEN` from a private process
environment. Keep TLS verification enabled and keep credentials out of HCL,
variable files, state, and plans.

Upload one checksum-verified prepared Debian image and import it into
`proxmox-k3s-01`, `proxmox-k3s-02`, and `proxmox-k3s-03`. Keep the node,
datastores, bridge, VM IDs, CPU, memory, image path, and image checksum as
private inputs. Keep state under `.local/opentofu/proxmox/k3s/`.

## Consequences

INIT gains a repeatable guest plan but depends on a reachable Proxmox API, a
prepared Debian image, and valid private inputs. The lockfile pins the provider.
Disabling automatic cloud-init package upgrades currently requires a
privilege-separated `root@pam` token with ACLs limited to the INIT resources;
the runtime secret note records this provider limitation.
The root proves guest configuration only; K3s readiness, etcd quorum, network
reachability, and recovery remain separate verification work.

## References

- [BPG Proxmox provider documentation](https://github.com/bpg/terraform-provider-proxmox/blob/main/docs/index.md)

# Use the BPG Proxmox provider for K3s guests

Last updated: 24.08.2026

## Summary

Use `bpg/proxmox` `0.111.1` for the location-neutral Proxmox K3s guest root.
Read credentials from a private process environment, verify TLS, and keep
guest state under the ignored `.local/` directory.

## Context

ADR 002 leaves the Proxmox host in GCP or on premises. INIT therefore needs one
guest root without hardcoded placement, credentials, or network values. BPG
provides the required OpenTofu VM resources and API-token authentication.

## Decision

Use `bpg/proxmox` in `init/opentofu/proxmox/k3s/`. Read
`PROXMOX_VE_ENDPOINT` and `PROXMOX_VE_API_TOKEN` from a private process
environment. Keep TLS verification enabled and keep credentials out of HCL,
variable files, state, and plans.

Clone an existing template into `proxmox-k3s-01`, `proxmox-k3s-02`, and
`proxmox-k3s-03`. Keep the node, datastore, bridge, VM IDs, CPU, and memory as
private inputs. Keep state under `.local/opentofu/proxmox/k3s/`.

## Consequences

INIT gains a repeatable guest plan but depends on a reachable Proxmox API, a
usable template, and valid private inputs. The lockfile pins the provider.
The root proves guest configuration only; K3s readiness, etcd quorum, network
reachability, and recovery remain separate verification work.

## References

- [BPG Proxmox provider documentation](https://github.com/bpg/terraform-provider-proxmox/blob/main/docs/index.md)

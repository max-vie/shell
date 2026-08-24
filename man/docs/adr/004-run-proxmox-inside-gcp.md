# Run Proxmox inside GCP

Last updated: 24.08.2026

## Summary

Run the single Proxmox host as a private Debian GCP VM with nested
virtualization enabled. Keep the direct-GCP K3s cluster independent and run
the second K3s cluster as three Debian guests inside Proxmox.

## Context

The two-cluster topology in ADR 002 needs a placement for its Proxmox host.
The repository already owns a shared private GCP network. An on-premises host
would introduce a second physical environment and transport path before this
portfolio project has a local host contract.

The GCP VPC uses `10.77.0.0/24`. Nested Proxmox guests therefore require a
separate network so their bridge and NAT cannot overlap the GCP addresses.

## Decision

Create one private GCP VM named `proxmox-host` at `10.77.0.220` with
`enable_nested_virtualization = true`, IAP-only SSH, and a persistent data
disk for Proxmox storage. IAP also carries the private Proxmox API tunnel.
The implementation boundary assigns Proxmox installation, host
configuration, and verification of `/dev/kvm`, storage, bridge, forwarding,
and NAT to Ansible.

Use `10.66.0.0/24` for the isolated Proxmox guest network, with gateway
`10.66.0.1` and the three K3s guests at `10.66.0.201` through `10.66.0.203`.
The guest network is masqueraded through the GCP uplink; Ansible reaches the
guests through the outer host.

Prepare one Debian 13 guest baseline with `virt-customize` and
`virt-sysprep`. OpenTofu imports that checksum-verified image and supplies
per-guest initialization data. Ansible owns guest verification and later K3s
configuration. Packer remains a later replacement or reproducibility path.

## Consequences

Nested virtualization adds a single-host failure boundary for the Proxmox
cluster and requires enough GCP CPU, memory, and disk for the outer host and
three guests. The Proxmox guest network is not directly routable from the GCP
VPC; guest access uses the host jump path and outbound NAT.

The default `n2-standard-8` host has 8 virtual CPUs and 32 GiB of memory. The
three guest definitions assign 12 virtual CPUs and 24 GiB in total, leaving
host memory headroom and using a deliberate 1.5:1 CPU overcommit. This is a lab
capacity boundary, not a production sizing claim.

The outer host and K3s routing nodes enable packet forwarding deliberately.
GCP disks use Google-managed encryption until SUDO owns a customer-managed key
contract; static analysis records both choices as reviewed exceptions.

The direct-GCP K3s root remains unchanged as the primary independent cluster.
The first Debian image path is simpler than the later Packer workflow, but its
source checksum and prepared-image manifest must be rotated deliberately. The
manifest records installed package versions; package repository snapshots
remain a TAR follow-up.

This ADR records the architecture and implementation boundary. It does not
claim that Proxmox has been installed, guests have been started, or host
verification has passed. It also does not authorize those operations. K3s,
identity, and delivery service implementation details remain outside this
decision.

## References

- [Google Cloud nested virtualization](https://cloud.google.com/compute/docs/instances/nested-virtualization/overview)
- [BPG Proxmox virtual machine resource](https://github.com/bpg/terraform-provider-proxmox/blob/main/docs/resources/virtual_environment_vm.md)
- [Proxmox VE package repositories](https://pve.proxmox.com/pve-docs/pve-package-repos-plain.html)

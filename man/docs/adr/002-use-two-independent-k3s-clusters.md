# Use two independent K3s clusters

Last updated: 24.08.2026

## Summary

Run one three-server K3s cluster on direct Google Cloud Platform (GCP) virtual
machines and a second three-server K3s cluster on Proxmox guests. Keep their
control planes, embedded etcd datastores, cluster networks, and API endpoints
independent. This ADR decides only the K3s topology and node identities.

## Context

SHELL needs separate K3s foundations for direct GCP compute and Proxmox
guests. The direct cluster is the primary environment. The Proxmox cluster
provides a second isolated K3s failure domain without changing the direct
cluster.

K3s requires three or more server nodes for high availability with embedded
etcd. Those servers must reach each other over private addresses and should be
in the same location. Stretching one embedded etcd control plane between the
direct and Proxmox environments would make cluster health depend on the network
between them.

One direct cluster would cost less and be easier to operate, but it would not
exercise a second K3s control plane. One stretched cluster would mix failure
domains and couple control-plane health, pod networking, and recovery to the
link between environments. Two independent clusters keep each K3s failure
domain explicit.

The Proxmox guests require one Proxmox host. Two placement options remain
open:

1. Run Proxmox on one GCP virtual machine with nested virtualization.
2. Run Proxmox on one on-premises host.

This ADR records both placement options but selects neither. A separate ADR
must choose the Proxmox host placement before provisioning. Other host
infrastructure and all services running on or around the clusters remain
outside this ADR.

## Decision

Create two independent clusters:

| Cluster | K3s servers | Purpose |
| --- | --- | --- |
| `gcp` | `gcp-k3s-01` through `gcp-k3s-03` | Primary K3s environment |
| `proxmox` | `proxmox-k3s-01` through `proxmox-k3s-03` | Independent secondary K3s environment |

Use these cluster and server names in K3s configuration and shared contracts.
The server names identify the cluster, K3s distribution, server role, and
ordinal.

Each cluster keeps embedded etcd quorum after one server fails, provided the
remaining servers and their underlying compute, storage, and network remain
available. Losing the Proxmox host may lose the entire `proxmox` cluster, but
it must not affect the `gcp` control plane.

Give each cluster its own control plane, embedded etcd datastore, pod and
service network ranges, server token, API endpoint, and cluster certificate
authority. Do not join servers across the two environments, stretch etcd, or
connect their pod networks.

## Consequences

The design requires two K3s control planes, two embedded etcd datastores, two
API endpoints, and separate pod and service networks. K3s upgrades, certificate
rotation, and control-plane troubleshooting must be handled independently for
each cluster.

A control-plane or pod-network failure in one cluster must not remove quorum
or API availability from the other cluster. The single Proxmox host remains a
host-level failure boundary for `proxmox`, but it is not part of the `gcp`
failure domain.

Before installing K3s, validate unique server names, SSD-backed etcd storage,
required K3s ports, private server-to-server reachability, and non-overlapping
pod and service ranges. After installation, verify three Ready server nodes,
three embedded etcd members, and one independent API endpoint in each cluster.

This ADR makes no decision beyond K3s topology, node identities, quorum,
networking, and API boundaries.

## References

- [K3s high availability with embedded etcd](https://docs.k3s.io/datastore/ha-embedded)
- [K3s hybrid and multicloud networking](https://docs.k3s.io/networking/distributed-multicloud)
- [Proxmox VE administration guide](https://pve.proxmox.com/pve-docs/pve-admin-guide.pdf)

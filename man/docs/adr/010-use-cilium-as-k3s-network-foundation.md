# Use Cilium as the K3s network foundation

Last updated: 02.09.2026

## Summary

Use Cilium 1.18.2 as the CNI and kube-proxy replacement for both SHELL K3s
clusters. TAR owns the verified Helm client, chart, and image pins; INIT owns
installation and read-only foundation verification.

## Context

The K3s runtime currently uses Flannel VXLAN and its built-in network-policy
controller and kube-proxy. That provides the basic cluster network but leaves
the richer CNI, eBPF service path, and policy foundation outside the current
runtime. The shellprod donor supplies a useful Cilium pattern, but its single
cluster topology, artifact contract, and bootstrap playbook do not match this
checkout.

SHELL has two independent three-server clusters with different API endpoints
and transport paths. Cilium must therefore consume the selected cluster API
host and pod CIDR without changing the existing target gate. The workstation
cannot be assumed to route directly to either private API endpoint, so the
cluster node must run Helm against its local K3s kubeconfig.

## Decision

Use one shared Cilium configuration for the `gcp` and `proxmox` K3s clusters.
TAR records and stages Helm `v3.18.4`, the Cilium `1.18.2` chart, and every
image emitted by that chart for `linux/amd64`. The locked image set includes
the Cilium agent, Cilium Envoy, and generic Cilium operator.

INIT renders each cluster with `flannel-backend: none`,
`disable-network-policy: true`, and `disable-kube-proxy: true`. After the
three K3s servers join through the existing cluster-specific endpoint, INIT
installs the pinned chart with cluster-pool IPAM using the declared pod CIDR,
VXLAN tunneling, exclusive CNI ownership, kube-proxy replacement, socket load
balancing limited to the host namespace, and one operator replica. The chart
and values are copied to the first server only for the Helm operation and are
removed afterward. Helm uses an atomic, waited release operation.

The Cilium handoff lives separately from the existing K3s and Kube-VIP supply
handoff. The relevant source boundaries are the TAR network supply contract
and stager, the INIT runtime launcher and Cilium values template, the K3s
configuration and verification playbooks, and the runtime guides. MAKE remains
the owner of workloads and platform add-ons; WATCH remains read-only.

Do not switch a running Flannel cluster in place. A cluster already created
with the old network foundation requires a reviewed fresh rebuild before this
configuration is applied. This decision does not add Cilium-specific policy
objects, Hubble relay or user interface, service address pools, or workload
connectivity tests.

## Consequences

Cilium becomes a required K3s foundation gate. A missing or mismatched local
artifact, unsupported image platform, incompatible guest kernel, unavailable
Quay image, failed Helm release, or failed agent/operator readiness check stops
the run without falling back to Flannel. Cilium's one-replica operator keeps
the small bootstrap deterministic but leaves operator availability as a
single-pod failure boundary.

The source checks can prove contract shape, private handoff paths, checksums,
digest-pinned rendered images, K3s flag selection, and refusal behavior. The
read-only verifier can prove live daemonset, operator, node, API, and selected
configuration state when authorized. These checks do not prove pod-to-pod
connectivity, policy enforcement, kernel compatibility under load, recovery,
image provenance beyond the recorded pins, or workload behavior.

## References

- [Cilium on K3s](https://docs.cilium.io/en/stable/installation/k3s/)
- [Cilium kube-proxy replacement](https://docs.cilium.io/en/stable/network/kubernetes/kubeproxy-free/)
- [Cilium IP address management](https://docs.cilium.io/en/stable/network/concepts/ipam/)
- [K3s networking options](https://docs.k3s.io/networking/basic-network-options)

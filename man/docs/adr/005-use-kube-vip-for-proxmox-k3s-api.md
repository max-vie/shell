# Use Kube-VIP for the Proxmox K3s API endpoint

Last updated: 25.08.2026

## Summary

Use a guest-network Kube-VIP address at `10.66.0.200` for the Proxmox K3s
control-plane endpoint. Keep Kube-VIP limited to control-plane address
ownership; service load balancing belongs to a later decision.

## Context

The Proxmox K3s guests use `10.66.0.201` through `10.66.0.203` on the
isolated `10.66.0.0/24` bridge. The K3s runtime needs one stable API endpoint
for server joins, the API certificate, kubeconfig output, and read-only
verification. The Proxmox OpenTofu root creates the guests but has no API VIP
or load-balancer resource.

The nested guest bridge provides the local network needed for an ARP-based VIP.
The single Proxmox host remains the failure boundary for the whole Proxmox
cluster. Host-level TCP forwarding would keep that failure boundary at the API
endpoint. Using `proxmox-k3s-01` directly would change the endpoint when that
server fails.

## Decision

Reserve `10.66.0.200` as the Proxmox K3s API VIP. Render Kube-VIP as an
INIT-owned, host-networked DaemonSet on the three control-plane guests. Use
ARP mode and leader election so one control-plane guest announces the VIP at a
time. Set `cp_enable=true` and `svc_enable=false`; Kube-VIP owns the API
address only.

Keep the guest interface, image repository, and image digest in the private
SUDO/TAR runtime handoff. The direct-GCP K3s root keeps its existing private
load-balancer endpoint. Service load balancing, MetalLB, Cilium, Longhorn,
identity, delivery, and application workloads remain outside this decision.

## Consequences

K3s server joins and TLS SANs use one stable Proxmox address. A server failure
can move the API address to another control-plane guest while the Proxmox host
and guest network remain available.

INIT gains a small RBAC and DaemonSet manifest with host networking and
`NET_ADMIN`/`NET_RAW` capabilities. The design depends on ARP behavior across
the Proxmox guest bridge and keeps the Proxmox host as a cluster-wide failure
boundary. TAR must supply a reviewed Kube-VIP image digest before runtime
execution.

The runtime source adds the manifest template, Proxmox VIP contract checks,
Kube-VIP readiness verification, and a pinned `ansible.utils` collection
requirement. Source validation covers YAML, Ansible syntax and lint, secret
scanning, template rendering, and the existing Python tests.

## References

- [Kube-VIP ARP mode](https://kube-vip.io/docs/modes/arp/)
- [Kube-VIP DaemonSet installation](https://kube-vip.io/docs/installation/daemonset/)
- [Kube-VIP flags and environment variables](https://kube-vip.io/docs/installation/flags/)

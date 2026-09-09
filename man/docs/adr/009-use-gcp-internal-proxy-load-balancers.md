# Use GCP internal proxy load balancers for GCP services

Last updated: 02.09.2026

## Summary

Use regional GCP internal proxy load balancers for the Harbor and release-feed
frontends in the direct-GCP K3s environment. Keep the frontend addresses in
GCP, the backend NodePorts in MAKE, and MetalLB limited to its controller
foundation.

## Context

The direct GCP K3s cluster uses the `gcp/network`-owned `10.77.0.0/24` VPC subnet. Harbor
and release-feed need stable internal HTTPS addresses, but direct BGP peering
from MetalLB speakers to Cloud Router is not a supported direct-GCP boundary.
The donor shellprod checkout used a different topology and its MetalLB
assumptions do not transfer.

The current source names `.221` for Harbor and `.222` for release-feed. The
cluster has no Kubernetes cloud controller, so a `LoadBalancer` Service cannot
create the required GCP forwarding resources by itself.

## Decision

Use one regional GCP internal proxy Network Load Balancer per service. INIT
owns the GCP resources in the `gcp/network` and `gcp/k3s` OpenTofu roots:

- Keep `10.77.0.0/24` for the shared VPC and use `10.77.2.0/23` for the
  regional managed proxy subnet.
- Reserve `10.77.0.221:443` for Harbor and forward it to NodePort `30443`.
- Reserve `10.77.0.222:443` for release-feed and forward it to NodePort
  `30444`.
- Use TLS passthrough, named instance-group ports, regional TCP health checks,
  and no global access.
- Allow only the proxy-only subnet and the declared health-check sources to
  reach the backend NodePorts.

MAKE changes the Harbor and release-feed Services to `NodePort` with
`externalTrafficPolicy: Cluster`. MetalLB remains pinned and may be installed
as a controller foundation, but this slice creates no BGP peer, BGP
advertisement, layer-2 advertisement, or service address pool.

MAKE installs Longhorn with `/var/lib/longhorn` as the default data path and
keeps Longhorn as the only default storage class. TAR supplies the pinned
charts and image digests. WATCH verifies the resulting resources without
mutating them.

This decision covers the direct-GCP service frontend and platform add-on source
boundary. It does not add a router appliance, a Network Connectivity Center
spoke, Proxmox service parity, public access, Harbor deployment, OpenBao
bootstrap, Argo CD bootstrap, release-feed deployment, chart publication, or
release-feed image promotion.

## Consequences

The service frontend and Kubernetes backend are separate handoffs. A GCP
forwarding rule can exist before its Kubernetes Service is ready, so live
verification must cover the forwarding resource, health checks, NodePort
target, and endpoint traffic. The proxy-only subnet adds regional address
consumption and a firewall source that must remain restricted to the K3s
backend nodes.

The GCP load balancers are internal. External access, direct MetalLB service
advertisement, direct BGP peering, and Proxmox service parity remain separate
decisions. The implementation follows the shared routing contract in
`tar/manifests/platform-addons-supply.json`, the GCP resources in the two INIT
OpenTofu roots, the MAKE add-on controller and NodePort consumers, and WATCH
source and read-only verification.

Source checks cover address and port collisions, chart and image pins, target
and approval gates, and the absence of MetalLB service advertisements. They do
not prove provider state, forwarding health, NodePort reachability, Longhorn
disk attachment, or service traffic. Those claims need separate authorized
provider, guest, cluster, and endpoint evidence.

## References

- [GCP internal proxy Network Load Balancer](https://cloud.google.com/load-balancing/docs/tcp/internal-proxy)
- [MetalLB configuration](https://metallb.io/configuration/)

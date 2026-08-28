# Use operator port forwarding for Grafana access

Last updated: 28.08.2026

## Summary

Use anonymous Viewer access for environment-gcp Grafana behind deny-pod-ingress
controls. Require the pinned chart to render a ClusterIP Service and use a
node-side loopback `kubectl port-forward` as the supported operator procedure.

## Context

The environment-gcp monitoring slice needs a read-only Grafana view without
adding a credential lifecycle or exposing a web endpoint. Anonymous Viewer
access meets that need when network reachability remains bounded.

Keeping Grafana disabled would reduce the monitoring surface but remove the
operator view. Using the chart-default administrator and basic authentication
would create credentials before SUDO provides an owned handoff. Exposing
anonymous or authenticated Grafana through an Ingress or load balancer would
add routing, transport security, and access controls outside this slice.

## Decision

Enable Grafana only for environment-gcp. Configure anonymous access with the
Viewer role, disable basic authentication, and disable initial administrator
creation. Enforce a NetworkPolicy that selects the Grafana pods and denies all
pod ingress. The pinned chart render must produce a ClusterIP Service. Do not
add an Ingress, load balancer, NodePort, or other public or external route.

The repository-supported operator procedure runs `kubectl port-forward` on a
K3s node, binds the local listener to loopback, and targets the Grafana Service.
This procedure does not technically force every principal authorized to use
the Kubernetes port-forward API to choose the same host or bind address. Other
port-forward procedures and wider listeners are unsupported.

MAN records this decision; TAR owns the pinned chart and Grafana image supply;
MAKE deploys the controls; WATCH verifies the source contract and live state
without mutation; SUDO owns future credential and access-authorization handoffs.

This decision is GCP-only. It does not cover the Proxmox cluster or any public
or external Grafana exposure.

## Consequences

Anonymous Viewer access provides no per-user identity or Grafana audit trail.
Kubernetes authorization controls who may request a port-forward, while the
supported host and loopback bind remain an operating convention.

An authorized principal could run the port-forward from another host or bind
it to a non-loopback address, exposing anonymous Grafana beyond the intended
boundary. That exposure is unsupported. A future in-cluster integration,
external route, or credential-backed access model requires a deliberate
decision and matching network and authorization controls.

Source and static checks, including a checksum-verified pinned chart render,
prove the intended configuration and required ClusterIP result. They do not
prove deployment, live NetworkPolicy enforcement, Grafana reachability,
operator authorization, or restriction of alternate port-forward choices.

## References

- [Grafana: Configure anonymous access](https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-authentication/anonymous-auth/)
- [Kubernetes: Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Kubernetes: kubectl port-forward](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_port-forward/)

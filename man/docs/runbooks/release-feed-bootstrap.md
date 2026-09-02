# Release-feed bootstrap

Last updated: 2026-09-02

## Current boundary

This runbook records the gates for the proposed `environment-gcp`
release-feed slice. It is not an executable rollout. The supported MAKE
targets refuse Harbor, Harbor robot, Argo CD, OpenBao, and release-feed
mutation before private inputs are needed.

Harbor uses the source-defined GCP internal proxy frontend `10.77.0.221`, and
release-feed uses `10.77.0.222`. Their provider state and reachability are not
yet live-proven. The frontends listen on `443` and forward to MAKE-owned
NodePorts `30443` and `30444`. Argo CD and OpenBao remain ClusterIP-only.

## Ownership

INIT owns the GCP proxy subnet, reserved service frontends, forwarding rules,
health checks, firewalls, and the three-host preparation: required packages,
the dedicated ext4 data mount, and node trust for the SUDO-owned certificate
authority. MAKE owns MetalLB, Longhorn, and the NodePort workloads. TAR owns
artifact staging and promotion. SUDO owns trust and private custody. WATCH
owns read-only policy and evidence. MAN records the operating boundary.

## Blocking gates

Resolve these gates in order. Recheck source after each gate because later
steps depend on the exact outputs of earlier ones.

1. Apply and review the INIT OpenTofu changes for the proxy-only subnet,
   reserved `.221`/`.222` frontends, backend named ports, health checks, and
   firewalls. Apply the MAKE platform-add-on path and leave MetalLB without a
   service address pool.
2. Harden TAR platform staging with size bounds and no-follow publication.
   Add Helm provenance checks and isolated publisher credentials before chart
   publication. Lock every Argo CD runtime image digest.
3. Define Harbor signing-key custody, project immutability, and durable robot
   replacement. Keep Harbor apply and robot registration blocked until those
   policies and the `.221` route exist.
4. Publish the reviewed MAKE GitOps tree and bind Argo CD to an immutable
   revision. Keep the Argo CD install, repository handoff, and root application
   blocked until the runtime image and source locks exist. The project
   destinations are `argocd` and `openbao`; release-feed is not an Argo CD
   destination in this slice.
5. Define a supported operator route to the ClusterIP-only OpenBao service.
   Add the K3s API certificate authority and reviewer identity handoffs,
   independent Shamir share custody, Raft member joins, and per-node unseal.
   Keep the bootstrap helper blocked until the whole ceremony is reviewable.
6. Add Harbor immutability checks and a create-only TAR promotion handoff for
   the scanned release-feed image. Keep release-feed publication and apply
   blocked while the manifest contains the unpromoted digest placeholder.
7. Generate or read private inputs only after the owning live gate is complete
   and separately authorized. The current source checks need no private
   values, guest access, provider access, or cluster connection.

## Verification after implementation

Run component source checks before requesting live authorization. A later
authorized WATCH verifier can confirm the declared GCP frontend and NodePort
Service,
one converged StatefulSet replica, a retained and bound 1 GiB Longhorn claim,
successful health and metrics requests, and remaining capacity below the
1,000-record limit.

That verifier does not write a record, restart the pod, read data before and
after a restart, query Prometheus alert state, or wait through the two-minute
alert hold. Persistence across restart and the alert's pending, firing, and
resolved lifecycle require separate guarded evidence paths.

## Failure and recovery boundary

When live implementation exists, keep retained Harbor, OpenBao, and
release-feed volumes during a failed rollout. OpenBao initialization must stay
create-only. Recovery must use independently held custody material and a
documented per-node join and unseal procedure. Release-feed rollback must use
a previously recorded immutable image digest and must prove health without
deleting the retained claim.

Source validation proves contracts and refusal gates only. It does not prove
artifact provenance, registry immutability, network routing, chart or image
availability, Kubernetes reconciliation, OpenBao custody, volume recovery,
service reachability, alert delivery, or release readiness.

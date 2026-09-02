# Use Harbor, OpenBao, and Argo CD for the release feed

Last updated: 02.09.2026

## Summary

Use Harbor for private artifact distribution, OpenBao for release-feed runtime
secrets, Argo CD for OpenBao desired state, Longhorn for retained state, and
MAKE for all Kubernetes mutation. Keep every live entry point blocked until
its supply, network, custody, and promotion handoffs are complete.

The GCP service frontend decision is recorded separately: Harbor and
release-feed use GCP internal proxy load balancers with MAKE-owned NodePort
backends. MetalLB does not advertise those two addresses.

## Context

The checkout now contains source contracts, manifests, validators, and
guarded controllers for the first `environment-gcp` stateful workload. It does
not contain a complete bootstrap path. INIT prepares the K3s hosts but has no
Kubernetes workload controller. TAR validates supply descriptors and now
stages the pinned MetalLB and Longhorn add-on charts; chart publication and
release-feed publication remain explicit refusal gates. MAKE blocks the Harbor,
Harbor robot, Argo CD, OpenBao, and release-feed mutation targets before
private inputs are needed.

Address `10.77.0.220` belongs to `proxmox-host`. INIT now owns the source
definition for GCP internal proxy frontends at `10.77.0.221` and
`10.77.0.222`; provider state and live reachability remain unproven.

Deploying release-feed directly without a registry and runtime-secret boundary
would leave artifact and credential promotion undefined. Letting Argo CD own
its own bootstrap dependencies would create a cycle among the registry, chart
source, and secret service. Public Argo CD or OpenBao endpoints would add an
access surface that this slice does not require.

## Decision

Limit this slice to `environment-gcp`. INIT owns the GCP proxy subnet,
reserved service frontends, forwarding rules, health checks, firewalls, host
packages, the dedicated data-disk mount, and node trust for the SUDO-owned
certificate authority. INIT does not apply charts or other Kubernetes
resources. MAKE remains the sole Kubernetes workload mutator, including
MetalLB and Longhorn installation.

TAR owns pinned supply, hardened staging, and artifact promotion. SUDO owns
private input contracts, trust material, and custody policy. MAKE owns the
eventual Harbor, Argo CD, OpenBao, and release-feed changes. WATCH owns
read-only policy and evidence. MAN owns this cross-lifecycle decision.

Use Harbor's full profile with Trivy and persistent storage once service
routing, SUDO signing-key custody, repository immutability, and robot
credential replacement are resolved. Run Argo CD as a ClusterIP service. Its
project may target only `argocd` and `openbao`; release-feed stays under direct
MAKE ownership. Do not apply the root application until the GitOps tree and a
reviewed revision are published and Argo CD runtime images are digest locked.

Use a three-node OpenBao high-availability Raft design with retained Longhorn
claims and no public endpoint. Before bootstrap, define a supported route to
the ClusterIP service, K3s API certificate authority and reviewer handoffs,
independent custody for the five Shamir shares, Raft member joins, and per-node
unseal. The current single-endpoint helper is not an approved ceremony.

Keep release-feed as one MAKE-owned StatefulSet with a retained 1 GiB SQLite
claim. Cap it at 1,000 records and warn when fewer than 100 slots remain. Its
image remains unpromoted until TAR produces an immutable digest and a reviewed
promotion handoff. Proxmox workload parity, external object
storage, Keycloak, public Argo CD or OpenBao access, image signing, admission
policy, and a shared root runner remain outside this decision.

## Consequences

The dependency order stays explicit, but no live bootstrap sequence is ready.
TAR add-on staging now has bounded, checksum-verified publication. Chart
publication awaits Helm provenance, isolated credentials, and Argo CD runtime
image locks. Release-feed publication awaits Harbor immutability and a
promotion handoff. Harbor and robot registration await authorized provider
reachability and durable custody. Argo CD awaits GitOps publication. OpenBao awaits its trust,
transport, custody, join, and unseal design. Release-feed apply awaits routing
and TAR promotion.

Longhorn adds a storage failure boundary. A single SQLite writer keeps the
application small but limits horizontal scaling and cross-cluster failover.
The source-defined `.221` and `.222` addresses remain subject to provider and
live reachability verification.

Source checks can prove contract shape, manifest relationships, digest guards,
and refusal behavior. With separate authorization, WATCH can read the Service,
StatefulSet, retained persistent-volume claim, health endpoint, and metrics
endpoint. It does not prove data across a restart or the alert's pending,
firing, and resolved lifecycle. Provider access, artifact provenance, registry
immutability, reconciliation, secret issuance, storage attachment, routing,
recovery, and release readiness all remain unproven.

## References

- [Harbor documentation](https://goharbor.io/docs/)
- [OpenBao Kubernetes deployment](https://openbao.org/docs/platform/k8s/helm/)
- [Argo CD documentation](https://argo-cd.readthedocs.io/en/stable/)
- [Longhorn documentation](https://longhorn.io/docs/latest/)

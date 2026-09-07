# MAKE

The delivery and Kubernetes workload boundary for SHELL.

## Contents

- `contracts/` contains trust, service, secret, backup, and delivery inputs.
- `gitops/`, `apps/`, and platform directories contain workload source.
- `forgejo/` contains delivery-node playbooks.
- `scripts/` and `tests/` contain guarded controllers and checks.

## Boundary

MAKE owns Kubernetes workload mutation. Source checks cover contracts and
guards; running clusters, reconciled services, and recovery require separate
evidence.

## Documentation

- [Platform architecture](../man/docs/architecture/platform-nodes.md)
- [Release-feed bootstrap](../man/docs/runbooks/release-feed-bootstrap.md)
- [WATCH Grafana recovery](../man/docs/runbooks/watch-grafana-recovery.md)

# WATCH

Monitoring policy, read-only checks, and recovery evidence for SHELL.

## Contents

- `contracts/` contains monitoring, tracing, release-feed, recovery, audit,
  and load-test policy.
- `monitoring/` contains alert rules.
- `scripts/` and `tests/` contain validators, observers, verifiers, and
  evidence checks.

## Boundary

WATCH observes and records evidence. MAKE owns workload mutation. Live
monitoring, recovery, load, and audit results require their own approvals and
evidence records.

## Documentation

- [Platform architecture](../man/docs/architecture/platform-nodes.md)
- [WATCH Grafana recovery](../man/docs/runbooks/watch-grafana-recovery.md)
- [Release-feed bootstrap](../man/docs/runbooks/release-feed-bootstrap.md)

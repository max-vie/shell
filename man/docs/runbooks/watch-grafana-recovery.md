# WATCH Grafana recovery

Last updated: 2026-08-29

## Purpose

This page records the source policy for a bounded Grafana recovery drill in the
GCP monitoring stack. It covers the one-replica Grafana target, its unavailable
alert, and the stability conditions a future execution must prove.

The repository now contains the MAKE fault/restore controller, the WATCH
observer, and the bounded evidence validator. No live recovery claim follows
from this page until an explicitly approved drill produces evidence.

## Ownership

MAN owns this runbook. WATCH owns the contract, alert, observations, and
evidence policy. MAKE owns the Kubernetes mutation controller. TAR supplies the
pinned monitoring artifacts, and INIT owns the GCP K3s guests and private
transport.

The contract lives at `watch/contracts/grafana-recovery-drill.json`. The rule
adds `ShellWatchGrafanaUnavailable`; chart default alerts, including
`Watchdog`, remain separate. The target is the `monitoring` namespace's
one-replica `shell-watch-grafana` Deployment.

## Policy

The future drill must use the fixed GCP cluster and the existing private INIT
transport. It must stop before fault injection if the source revision, target
state, alert path, node health, monitoring stability, or memory limits do not
match the contract. The contract requires 20 samples 30 seconds apart and a
maximum 300-second outage. An explicit live authorization will be required;
the approval string in the contract is only a command interlock.

MAKE records an operation boundary, applies only the contract target, restores
only its matching operation, and leaves a private evidence record. WATCH
remains read-only. The source controller refuses a non-GCP target, a dirty
source tree, an unsafe private output, or a mismatched restore operation.

## Local checks

These checks validate the contract and rule without private runtime inputs or
cluster access:

```sh
make -C watch check-recovery
make -C watch check
make -C make watch-recovery-check
```

The checks prove source shape, policy consistency, and controller guards. They
do not prove Helm rendering, rule loading, alert timing, memory headroom,
restoration, or recovery duration. A mocked test message is not live recovery
evidence.

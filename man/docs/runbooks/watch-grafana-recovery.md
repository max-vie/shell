# WATCH Grafana recovery

Last updated: 2026-08-29

## Purpose

This page records the source policy for a bounded Grafana recovery drill in the
GCP monitoring stack. It covers the one-replica Grafana target, its unavailable
alert, and the stability conditions a future execution must prove.

The policy is source-only. MAKE does not yet implement the fault, restore
guard, or evidence journal. No live recovery claim follows from this page.

## Ownership

MAN owns this runbook. WATCH owns the contract, alert, observations, and
evidence policy. MAKE will own the Kubernetes mutation. TAR supplies the pinned
monitoring artifacts, and INIT owns the GCP K3s guests and private transport.

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

The mutation and restoration path is deliberately deferred. When MAKE owns
that implementation, it must record an operation boundary, restore only its
matching operation, and leave a private evidence record. WATCH remains
read-only.

## Local checks

These checks validate the contract and rule without private runtime inputs or
cluster access:

```sh
make -C watch check-recovery
make -C watch check
```

The checks prove source shape and policy consistency. They do not prove Helm
rendering, rule loading, alert timing, memory headroom, restoration, or
recovery duration.

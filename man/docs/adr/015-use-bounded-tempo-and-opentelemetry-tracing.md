# Use bounded Tempo and OpenTelemetry tracing

Last updated: 03.09.2026

## Summary

Use one cluster-local Tempo instance and one OpenTelemetry Collector in the
GCP monitoring namespace. Keep trace storage on a small Longhorn volume for
the first source-defined slice, and defer an instrumented application,
external trace storage, and public trace access.

## Context

SHELL has source-defined metrics and logs but no trace receiver or trace store.
The archived shellprod files provide a useful Helm and pipeline shape, while
their mirrored image identities and broader runtime assumptions do not fit
the current TAR, MAKE, and WATCH contracts.

The first tracing slice needs a bounded OTLP path with explicit resource and
network limits. The current checkout has no instrumented workload, so source
validation and readiness checks must not claim that a trace was received or
searched.

## Decision

TAR records the Tempo 1.24.4 and OpenTelemetry Collector 0.165.0 charts plus
digest-pinned linux/amd64 images. MAKE owns the two Argo applications and
their Helm values in the existing `monitoring` namespace. WATCH owns the
separate tracing contract and read-only verification.

Tempo runs one replica with the local backend, a 2 GiB Longhorn claim, 24-hour
retention, and OTLP gRPC and HTTP receivers. Its query and ingest services
remain ClusterIP-only. A namespace-bounded NetworkPolicy permits monitoring
ingress on the query and OTLP ports and DNS egress only.

The collector runs one deployment replica with OTLP gRPC and HTTP receivers,
an 8889 Prometheus exporter, a memory limiter, and a batch processor. Traces
go to Tempo over cluster-local OTLP HTTP; metrics remain available for the
existing Prometheus scrape path. Logs collection, host access, Kubernetes
discovery, cluster RBAC, persistence, ingress, and gateway routes stay
disabled.

## Consequences

The source slice defines a usable in-cluster OTLP destination without adding a
public endpoint or an unbounded storage dependency. Local trace retention is
small and intentionally limited to the first learning and integration step.

The collector can receive telemetry from future instrumented workloads, but
none exists in the current source tree. Source validation can prove chart and
image pins, pipeline shape, service exposure, storage settings, and policy
boundaries. Read-only verification can prove workload readiness, service
ports, and Tempo readiness; it cannot prove trace ingestion, trace search,
retention under load, or recovery.

## References

- [Grafana Tempo](https://grafana.com/docs/tempo/latest/)
- [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/)
- [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

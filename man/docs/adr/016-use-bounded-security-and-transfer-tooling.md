# Use bounded security and transfer tooling

Last updated: 03.09.2026

## Summary

Use digest-locked Trivy, kube-bench, k6, and Skopeo workflows for the first
GCP delivery and cluster checks. Keep scan and transfer inputs immutable,
make temporary audit and load resources explicit, and leave every live
operation behind its own approval.

## Context

SHELL has source-defined runtime images and a delivery host contract, but no
complete vulnerability gate, cluster audit, controlled load check, or image
promotion workflow. The archived shellprod tooling supplies useful command
and resource shapes, while its mirrored image names, credentials, and
execution paths do not match this checkout.

These tools have different owners. TAR controls public image pins and the
local Trivy report gate. WATCH controls audit and load policy plus evidence
parsing. MAKE is the only owner allowed to create temporary Kubernetes Jobs or
DaemonSets. Skopeo runs on the INIT-prepared delivery host and must not expose
registry credentials in arguments or logs.

## Decision

TAR records linux/amd64 pins for Trivy 0.73.0, kube-bench 0.16.0, and k6
2.1.0 in the Kubernetes ecosystem supply lock. Trivy scans an immutable image
reference with a preloaded vulnerability database, skips database updates,
and writes one mode-0600 report without overwriting existing evidence. HIGH
and CRITICAL findings fail the report gate.

WATCH defines a temporary host-read-only kube-bench DaemonSet for the K3s CIS
benchmark and a 600-request, two-minute k6 check against the internal
release-feed health endpoint. The kube-bench resource uses read-only host
mounts and host PID visibility without container privilege. The k6 resource
uses the tracked SUDO root certificate, no service-account token, no host
namespace, and a namespace-bounded network policy. MAKE applies and removes
these temporary resources only with the exact audit or load approval; WATCH
stores create-only evidence.

Skopeo transfers one exact locked image at a time to the Harbor system project
through `delivery-01`. The remote command preserves the source digest,
accepts credentials only on standard input, permits identical existing
content, and refuses a destination digest conflict. Harbor routing, robot
custody, and live transfer remain separate gates.

## Consequences

The source tree now defines reproducible tool versions, bounded request and
audit budgets, private evidence modes, and explicit refusal behavior. The
temporary kube-bench namespace requires a documented privileged Pod Security
label because host inspection needs host PID and host paths; the container
itself remains unprivileged and read-only.

Source checks and synthetic reports do not prove the Trivy database freshness,
vulnerability completeness, CIS results, release-feed health, k6 latency, or
registry transfer. They also do not create credentials, apply Kubernetes
resources, contact the delivery host, or publish an image.

## References

- [Trivy image scanning](https://trivy.dev/latest/docs/target/container_image/)
- [kube-bench](https://github.com/aquasecurity/kube-bench)
- [k6](https://grafana.com/docs/k6/latest/)
- [Skopeo](https://github.com/containers/skopeo)

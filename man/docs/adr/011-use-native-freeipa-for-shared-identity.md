# Use native FreeIPA for shared identity and DNS

Last updated: 02.09.2026

## Summary

Use one native FreeIPA installation on the shared AlmaLinux 9 identity host
for SHELL identity groups, proof principals, and internal DNS. SUDO owns the
policy and encrypted credentials, TAR owns the package source contract, and
INIT owns the guarded host configuration and verification.

## Context

SHELL already reserves `identity-01` at `10.77.0.210` as the shared identity
host and defines the `shell.internal` domain, `SHELL.INTERNAL` realm, groups,
DNS forwarders, and four service records. The current checkout describes those
rules but its identity playbook stops at a source-only preview.

The service must support both independent K3s clusters without moving identity
or DNS ownership into a cluster workload. Credentials cannot be tracked in the
repository, and the identity host is deliberately outside the Debian K3s and
delivery baseline. A Kubernetes identity operator or a separate login service
would add a dependency before the base identity and DNS boundary exists.

## Decision

Install FreeIPA from the TAR-owned AlmaLinux 9 native-package contract on the
single shared GCP identity host. INIT uses a fixed controller and requires an
explicit identity-service approval before it reads the encrypted SOPS/age
input or connects to the guest. The input contains only the Directory Manager,
administrator, and two proof-principal passwords and is created locally by
SUDO with create-only publication.

Initialize the `shell.internal` realm with the declared hostname, address,
forwarders, DNS setup, no reverse zone, and no NTP. Create the three declared
groups and the `shell-operator` and `shell-denied` proof principals. Add only
the allowed proof principal to `platform-operators`. Manage only the current
`delivery-01`, `forgejo`, `registry`, and `releases` A records.

Record an immutable completion-marker digest after successful initialization.
Treat a realm without a matching marker as partial state and stop for explicit
recovery. Do not reset existing passwords, delete a realm, or enroll K3s,
Keycloak, or application workloads in this decision.

## Consequences

The shared identity host remains a single service and failure boundary for
both clusters. Native package availability and the host's network and SELinux
state remain prerequisites. Passwords may appear in root-visible installer
arguments during the approved initialization, so the playbook suppresses
output, keeps the input short-lived, and destroys the temporary Kerberos cache.

Source validation can prove the host, group, DNS, package, custody, approval,
and marker contracts. The read-only verifier can check the installed packages,
FreeIPA service status, listeners, and consumer reachability when authorized.
Those checks do not prove live package acquisition, realm convergence,
authentication, authorization, DNS answers, idempotent reruns, or recovery.

Keycloak federation is now recorded separately for the cluster-local login
service. Downstream OIDC integration, Kubernetes enrollment, workload
authorization, multi-master FreeIPA, and backup restoration still require
separate decisions.

## References

- [FreeIPA](https://www.freeipa.org/)
- [Red Hat Identity Management documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/installing_identity_management/)

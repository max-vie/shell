# Use a cluster-local Keycloak login service

Last updated: 02.09.2026

## Summary

Use one cluster-local Keycloak service in the GCP K3s cluster for the SHELL
realm and FreeIPA-backed login foundation. Keep its PostgreSQL state on
Longhorn, expose only ClusterIP services, and retain a local break-glass
administrator. SUDO owns policy and credentials, TAR owns image pins, INIT
owns the FreeIPA bind principal, and MAKE owns the Kubernetes workload.

## Context

SHELL now has a source-defined native FreeIPA identity service on
`identity-01`, but no login service that can federate its users. The current
platform does not reserve a public Keycloak address or an external routing
path. The archived shellprod manifests used a MetalLB LoadBalancer and
downstream OIDC clients that do not fit the current GCP-only routing contract.

Keycloak needs a durable database, TLS, a read-only LDAP connection, and
group-to-role mapping without receiving permission to change FreeIPA. Its
initial bootstrap also needs a separate administrator credential, while all
private values must stay outside Git.

## Decision

Run one Keycloak Deployment and one PostgreSQL StatefulSet in the
`shell-identity` namespace. Use the existing `shell-cluster-intermediate`
issuer for service certificates, ClusterIP for HTTPS and management services,
and a retained 8 GiB Longhorn claim for PostgreSQL.

Federate the `shell` realm to `identity-01.shell.internal:636` over required
LDAPS using the read-only `keycloak-bind` principal. Map the FreeIPA
`platform-admins`, `platform-operators`, and `auditors` groups to the
corresponding Keycloak realm roles. Keep user registration and password reset
disabled. The realm contains no downstream Argo CD, Grafana, or Harbor OIDC
clients in this slice.

SUDO creates the encrypted Keycloak input under its private keycloak custody
root. INIT creates or verifies the FreeIPA bind principal only after the exact
bind approval. MAKE applies the protected Kubernetes Secrets and owns the
Keycloak manifests through the Argo child application. TAR records fixed
linux/amd64 Keycloak and PostgreSQL image identities.

Do not add an external address, DNS record, NodePort, LoadBalancer, Ingress,
workload login integration, Proxmox deployment, or live authentication proof
as part of this decision.

## Consequences

Keycloak is reachable only from declared cluster consumers or an explicitly
authorized operator path. PostgreSQL and Keycloak each have resource limits,
readiness and liveness checks, non-root security settings, and default-deny
network policy with explicit LDAP, database, DNS, and management paths.

The database and realm introduce a stateful migration boundary. Realm JSON is
appropriate for initial creation; later realm changes require a separate
migration decision. Existing resources or claims must not be adopted or
deleted automatically.

Source validation can prove the contracts, pins, manifests, private-input
guards, and refusal paths. It does not prove image availability, FreeIPA
convergence, certificate issuance, PostgreSQL readiness, Argo reconciliation,
LDAP authentication, group mapping, login behavior, or recovery.

## References

- [Keycloak server administration guide](https://www.keycloak.org/server-admin)
- [Keycloak realm import and export](https://www.keycloak.org/server/importExport)
- [Red Hat Identity Management documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/installing_identity_management/)

# FreeIPA identity service

INIT owns the native FreeIPA service on the single shared GCP identity host
`identity-01` (`10.77.0.210`). SUDO owns the identity policy, password
contract, encrypted input, and age-key custody. TAR owns the source-reference
package contract. The identity service serves both the `gcp` and `proxmox`
cluster domains through `shell.internal`.

## Controller boundary

Use `init/scripts/run_identity_service.py` for identity configuration and
verification. The controller accepts only the fixed `identity_nodes` target,
the fixed playbooks, the generated private inventories, and the declared GCP
IAP route. Configuration requires the exact approval
`environment-gcp/init/identity-service`; verification is read-only.

Check mode validates public contracts and stops before private input access or
guest connection. Apply mode requires the SOPS/age identity and encrypted
FreeIPA input under private `.local/sudo/identity/` state. The separate bind
action uses the fixed Keycloak input under `.local/sudo/keycloak/` and requires
`environment-gcp/init/keycloak-ldap-bind`. The controller does not accept
arbitrary Ansible selectors or extra-variable paths.

## Bootstrap behavior

The configuration playbook validates SUDO and TAR contracts before reading the
encrypted input. It confirms the AlmaLinux 9 host, sets the declared FQDN,
installs the native FreeIPA packages, and initializes the realm with the
declared domain, realm, address, DNS forwarders, no reverse zone, and no NTP.
The four current managed records are the only records this playbook changes:
`delivery-01`, `forgejo`, `registry`, and `releases`.

The playbook writes `/var/lib/shell/freeipa-install-complete` only after realm
initialization succeeds. The marker contains a digest of the immutable host,
realm, domain, and forwarder contract. A configuration without a matching
marker is treated as partial state and stops for explicit recovery. Existing
passwords are not reset during an idempotent run.

The playbook creates the three declared identity groups and the
`shell-operator` and `shell-denied` proof principals. Only the allowed proof
principal is added to `platform-operators`. The temporary Kerberos cache is
destroyed after the authenticated convergence block, including failure paths.

`configure-keycloak-ldap-bind.yml` is a separate INIT handoff. It verifies the
FreeIPA completion marker, creates `keycloak-bind` only when absent, and tests
that principal over strict LDAPS. It does not reset passwords, change other
FreeIPA users, or deploy a Kubernetes workload.

## Verification boundary

`verify-identity-service.yml` is read-only. It checks the fixed host, AlmaLinux
version, required native packages, completion marker, FreeIPA configuration,
service status, and declared TCP listeners. It also checks DNS and HTTPS port
reachability from the first GCP K3s server. It does not change realm data,
rotate passwords, delete a realm, or prove workload authorization.

The source contract, package lock, encrypted-input generator tests, launcher
tests, Ansible syntax and lint checks, and mocked source checks do not prove
package availability, guest readiness, realm convergence, DNS answers,
authentication, authorization, live idempotency, or recovery. A failed first
installation leaves the guest for diagnosis; replacing the guest or removing
realm state requires a separate approved recovery decision.

Keycloak workload reconciliation, downstream OIDC clients, Kubernetes
enrollment, and workload access remain separate slices. The Keycloak bind
handoff itself is source-defined but has no live LDAPS proof in this checkout.

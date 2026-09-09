# Use service-account impersonation for local operator runs

Last updated: 09.09.2026

## Summary

Use a human Google login to bootstrap a dedicated `shell-local-deployer`
service account. Local OpenTofu and Identity-Aware Proxy runs use a short-lived
token for that account, with a lifetime no longer than one hour. The initial
permission contract covers the GCP network foundation and the declared IAP
target; each additional GCP root requires its own permission review. Do not
use a long-lived operator key or add Workload Identity Federation in this
slice.

## Context

The local Google Cloud provider currently allows ambient application default
credentials and describes external Workload Identity Federation as a future
option. The local Ansible route also starts an IAP tunnel through `gcloud`.
Without one deliberate identity boundary, provider and tunnel commands can
silently use different credentials or broader human permissions.

Direct human credentials are easy to start but make the permission boundary
depend on the human account. A long-lived service-account key creates private
key custody and rotation risks. Workload Identity Federation needs an external
issuer and provider that this project does not have. An attached host identity
would move the operator workflow to a new execution host.

Short-lived service-account impersonation keeps the human principal visible in
the authorization path while giving local runs a stable account and a
reviewable permission boundary.

## Decision

During bootstrap, the operator signs in with a human Google account. SUDO
defines the `shell-local-deployer` account, its allow-list, and a
service-account-scoped binding that lets the approved human principal obtain
short-lived access tokens. The predefined
`roles/iam.serviceAccountTokenCreator` is a role, so its included permissions
must be reviewed as part of that binding.

The deployment account receives only the permissions required by the reviewed
network resources and declared IAP target. The IAP command must receive the
resource lookup and tunnel permissions it needs. Do not grant Owner, Editor,
Viewer, broad project IAM administration, service-account key creation, or
permissions for roots that have not passed a separate review.

INIT provides the local authentication boundary. It passes the exact
impersonated target to the Google Cloud provider and every `gcloud` command in
the IAP route, requests a token of no more than 3,600 seconds, and fails
closed when the target, token, or approved proxy command is missing. It refuses
operator service-account key files and alternate targets. The non-root guest
SSH user, private SSH handoff, and strict host-key checking remain unchanged.

This decision governs the local operator identity. It does not replace
workload credentials such as the dedicated Velero service-account key, change
the Proxmox provider identity, or authorize unattended deployment.

## Consequences

The operator must complete a human login and may need to reauthenticate after
token expiry. A copied token has a short useful lifetime, and audit records can
associate the human principal with the deployment account. The account still
has meaningful infrastructure authority, so SUDO must review its allow-list
and binding as the GCP roots change.

The current source contract and tests prove intended identity boundaries only.
They do not prove that the account, IAM binding, token issuance, IAP tunnel,
provider plan, or guest login exists or works. Live IAM and IAP checks require
separate authorization and evidence.

Revisit this decision when an external issuer, a continuous integration
runner, unattended operation, another project or environment, or token access
longer than one hour becomes necessary. Workload Identity Federation then
requires its own issuer, provider, conditions, ownership, and migration
decision.

## References

- [Service account impersonation](https://docs.cloud.google.com/iam/docs/service-account-impersonation)
- [Service account permissions](https://docs.cloud.google.com/iam/docs/service-account-permissions)
- [Identity-Aware Proxy TCP forwarding](https://docs.cloud.google.com/iap/docs/using-tcp-forwarding)
- [Workload Identity Federation](https://docs.cloud.google.com/iam/docs/workload-identity-federation)

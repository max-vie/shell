# Use AlmaLinux 9 for the FreeIPA identity host

Last updated: 02.09.2026

## Summary

Use AlmaLinux 9 as the source-contract target for the shared FreeIPA identity
host. AlmaLinux is RHEL-compatible and provides a clear native-package target
for the source-defined FreeIPA service path.

## Context

The FreeIPA host needs one explicit operating-system contract before INIT can
select an image or add guest configuration. The direct-GCP Debian baseline is
appropriate for the delivery and K3s nodes, but it cannot also describe the
RHEL-compatible package, service, and SELinux behavior required by FreeIPA.

AlmaLinux 9 provides a RHEL-compatible native-package target for the new
identity implementation. The source contract must remain independent of any
private credentials, running host, or live verification result.

Rocky Linux 9 is a compatible alternative, but choosing it would require a
separate image, package, SELinux, and FreeIPA compatibility proof. Debian 13
matches the current shared-node baseline, but would require a separate FreeIPA
platform path.

## Decision

SUDO and MAN record `almalinux-9` as the identity-host target. INIT owns image
selection, GCP placement, firewall rules, inventory metadata, and later guest
configuration. SUDO owns the domain, realm, DNS, group, signing, trust, and
credential contracts. TAR owns the verified identity artifact supply.

The GCP node contract accepts an exact image self-link from the
`almalinux-cloud` AlmaLinux 9 image line for `identity-01`. Delivery uses the
`debian-cloud` Debian 13 image line. A custom image requires an explicit source
contract update that binds its provenance and operating system.

The source implementation records the target OS, native package contract,
private SOPS/age credential handoff, fixed INIT controller, and FreeIPA
completion-marker boundary. These source contracts do not authorize package
installation, guest startup, FreeIPA initialization, DNS publication, or live
verification.

The shared-node contract records the operating system alongside the pinned GCP
image, exposes it to the inventory renderer, and keeps the identity host out of
the Debian baseline group. The identity firewall targets only the identity
node and matches the SUDO FreeIPA port contract. The fixed INIT controller
refuses configuration without the exact approval and private handoffs.

## Consequences

The project has one explicit identity-host target and a clear RHEL-compatible
platform boundary. Choosing Rocky Linux later requires a new or superseding
decision. Debian 13 remains the target for delivery and K3s guests.

Static JSON, Python, Ansible syntax, and lint checks can prove contract shape,
private-input guards, and controller preview safety. The package contract is
source-reference-only, and the encrypted input is generated only after its
separate SUDO approval. These checks do not prove image or package
availability, guest readiness, FreeIPA convergence, DNS reachability, identity
authentication, or recovery.

## References

- [AlmaLinux](https://almalinux.org/)
- [FreeIPA](https://www.freeipa.org/)

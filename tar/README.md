# TAR

Artifact locks, validation, staging, and transfer handoffs for SHELL.

## Contents

- `manifests/` contains versions, checksums, and image digests.
- `scripts/` contains validators, staging tools, scan gates, and transfer
  controllers.
- `tests/` covers supply contracts and approval guards.

## Boundary

TAR records and checks the inputs consumed by INIT, MAKE, and WATCH. Artifact
acquisition, registry access, publication, and runtime use require separate
evidence.

## Documentation

- [Release-feed bootstrap](../man/docs/runbooks/release-feed-bootstrap.md)

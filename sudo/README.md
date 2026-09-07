# SUDO

Identity, access, signing, and trust contracts for SHELL.

## Contents

- `access/` contains identity and platform access profiles.
- `secrets/` contains private-input and trust-handoff contracts.
- `pki/` contains the tracked offline trust certificate.
- `scripts/` and `tests/` validate contracts and guarded generators.

## Boundary

SUDO records public contract shapes and prepares approved private handoffs.
Credentials, secret custody, and live identity behavior require separate
evidence.

## Documentation

- [K3s server-token decision](docs/adr/001-use-sudo-owned-k3s-server-tokens.md)

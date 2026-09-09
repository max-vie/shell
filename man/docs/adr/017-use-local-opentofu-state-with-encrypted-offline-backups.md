# Use local OpenTofu state with encrypted offline backups

Last updated: 09.09.2026

## Summary

For the first single-operator Free Trial run, keep one local OpenTofu state
file per INIT root and keep encrypted offline copies for recovery. Record the
exact digest of every approved plan and require a zero-change plan after an
apply. Do not add a Google Cloud Storage backend in this slice.

## Context

INIT manages six independent roots: `gcp/network`, `gcp/shared-nodes`,
`gcp/k3s`, `gcp/proxmox-host`, `proxmox/k3s`, and `gcs-backup`. Their local
state paths keep root boundaries visible and let source validation run without
provider access, credentials, or guest access.

The first run has one operator and no need for concurrent state writers. A
Google Cloud Storage backend would require bucket bootstrap, API access, IAM,
and a custody model before the platform exists. Using the Velero bucket for
OpenTofu state would also couple two unrelated lifecycle boundaries.

The alternatives are a private remote backend, state only on the working
machine, or local state with an encrypted offline copy. The first adds a
bootstrap dependency, the second leaves one machine as the recovery boundary,
and the third preserves the current root separation while adding a manual
recovery path.

Any state left by the former combined `gcp/shared` root must be classified
before a new root is planned. This ADR does not authorize moving, importing,
or overwriting existing state.

## Decision

Use one private local state path under `.local/opentofu/` for each INIT root.
Keep local remote-state references aligned with those paths. Do not put state,
plans, credentials, variable files, encryption keys, or offline backup media
in Git, and do not combine the roots into one state file.

Create a private encrypted offline snapshot of the root state and its integrity
metadata after an approved apply. State can contain sensitive provider values,
so the snapshot requires encryption and controlled custody. Separate
credentials and unencrypted private inputs remain outside the snapshot unless a
separate custody decision includes them.

The workflow records the approved plan digest, applies one fixed root at a
time, and runs a same-input zero-change plan before treating that root as
converged. State migration, snapshot creation, and restore are separate
state-operation gates. The existing Velero bucket and its workload credential
remain governed by their own decision; they are not an OpenTofu state backend.

INIT owns the state layout and workflow. SUDO owns encryption-key review and
custody. A later change to a shared backend requires a new decision and a
tested migration with state lineage, locking, access, and restore evidence.

## Consequences

Local state avoids a backend bootstrap cycle and preserves the existing root
boundaries. Encrypted offline copies provide recovery when the working machine
is unavailable.

The operator must manage locking, snapshot rotation, media custody, key
recovery, and restore tests. Local state does not support concurrent operators
or controllers, and a lost or unavailable offline copy remains a recovery
risk.

Source checks can prove the checked-in backend declarations, root structure,
provider schemas, and refusal boundaries. They do not prove provider state,
successful plans or applies, encryption, media durability, or restore success.

Reconsider this decision when the project needs concurrent operation, a second
operator, unattended runs, or a durable central recovery service.

## References

- [OpenTofu backends](https://opentofu.org/docs/language/settings/backends/)
- [OpenTofu local backend](https://opentofu.org/docs/language/settings/backends/local/)
- [OpenTofu plan command](https://opentofu.org/docs/cli/commands/plan/)

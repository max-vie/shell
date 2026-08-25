# Use SUDO-owned K3s server-token handoffs

Last updated: 25.08.2026

## Summary

Make SUDO the owner of the two K3s server-token handoffs. Generate one
independent short server token for each cluster in ignored private state, and
let INIT consume only the cluster-specific file path. Keep token values out of
Git, TAR, public output, and documentation.

## Context

SHELL has two independent K3s clusters, `gcp` and `proxmox`. Each cluster must
have its own server token and certificate authority. The current INIT runtime
already accepts `shell_k3s_token_path`, but no tracked SUDO source defines who
creates that file, how it is protected, or how the two cluster paths stay
separate.

TAR owns verified artifact identity and must not receive secret material. INIT
owns guest configuration and execution, but should consume a reviewed private
handoff rather than generate credentials. The existing generic token path and
length-only validation do not express those ownership or storage rules.

K3s supports secure and short server-token formats. The first server creates a
self-signed certificate authority during startup, so its CA hash is not
available before the token is supplied. The first server therefore uses a
short password-only token. K3s later writes secure token material; that token
is cluster authority and also protects bootstrap data stored with the
datastore.

Generating a secure `K10<CA hash>::<credentials>` token before the first
server starts is unavailable with the default self-signed CA. Generating a
token inside INIT would mix SUDO policy with guest execution. Introducing
SOPS, age, or OpenBao now would add a secret system before the source-only
handoff and storage contracts are complete.

## Decision

SUDO owns a versioned public contract at
`sudo/secrets/k3s-server-token-contract.json` and a standard-library generator
at `sudo/scripts/generate_k3s_server_tokens.py`.

The contract defines exactly two server-token outputs:

| Cluster | INIT group | Private path |
| --- | --- | --- |
| `gcp` | `gcp_k3s_servers` | `.local/sudo/k3s/gcp/server-token` |
| `proxmox` | `proxmox_k3s_servers` | `.local/sudo/k3s/proxmox/server-token` |

Each token contains 32 random bytes encoded as 64 lowercase hexadecimal
characters followed by one newline. The generator requires current-user
ownership, mode `0700` for private directories, mode `0600` for token files,
create-only publication, and manual rotation. It never prints token values,
offers output-path overrides, or reads the existing `sudo/access/**` work.

`--validate-only` checks the public contract and writes nothing. `--generate`
is a separately approved local operation. It creates both values before
publishing, refuses unsafe or partial state, preserves an existing valid pair
without replacement, and leaves a first file in place if the second
publication fails. Recovery from that partial state is manual and reviewed.

The implementation keeps private traversal and publication no-follow and
descriptor-anchored. It checks ownership, modes, regular files, special files,
malformed state, equal tokens, and partial state. Tests cover temporary-root
generation, token format, independent values, idempotency, publication
failure, unsafe paths, controlled errors, and secret-free output.

The real `.local` root must already be mode `0700`; the generator refuses to
repair an existing unsafe mode. Set it once with `chmod 0700 .local` before
the first `--generate` — subsequent runs keep the created private parents at
`0700` automatically. This decision does not authorize changing
`.local` permissions, generating real tokens, creating certificate authorities,
running Ansible, starting guests, applying OpenTofu, or changing Kubernetes
resources. Secure-token capture, datastore backup, rotation, SOPS/age/OpenBao,
and live proof remain later decisions.

## Consequences

SUDO has a clear producer boundary, and INIT receives two explicit private
paths without learning token-generation policy. The two clusters cannot
accidentally share a generated value. Create-only publication and manual
recovery preserve existing secret material when a write fails.

The short token leaves the first connection without CA-hash identity
verification. The later secure token must be protected and backed up with the
matching datastore. Server-token rotation must account for snapshots that
still require the old token.

Plaintext local files remain a temporary custody model. Before live bootstrap,
the project needs protected local permissions, durable secret backup, secure
token capture, rotation rules, and an approved secret-store transition. This
ADR does not claim any of those proof stages are complete.

## References

- [K3s token management](https://docs.k3s.io/cli/token)
- [K3s backup and restore](https://docs.k3s.io/datastore/backup-restore)

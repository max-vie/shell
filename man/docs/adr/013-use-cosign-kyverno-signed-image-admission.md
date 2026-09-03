# Use Cosign and Kyverno for signed-image admission

Last updated: 02.09.2026

## Summary

Use a SUDO-owned Cosign key and Kyverno to enforce signatures on selected SHELL
images. Begin with the GCP K3s source boundary, match only namespaces labelled
`shell.platform/policy: enforced`, and keep controller namespaces outside that
label until their image and admission dependencies are proven.

## Context

SHELL has a private Harbor registry contract and a source-defined workload
stack, but no image-signing or admission path. The archived shellprod policy
offers a useful shape, while its broad ecosystem handoff, domains, and
partially pinned Kyverno images do not fit this checkout.

Admission needs a public trust key without placing a private key or password
in Git or in the cluster. Kyverno also needs narrowly scoped access to that
key, digest-pinned runtime images, and an explicit failure behavior. A
transparency-log dependency would add a separate availability and evidence
boundary before the first local trust path exists.

## Decision

SUDO owns one Cosign trust identity and its encrypted private handoff. The
public key is published separately to the `shell-trust/cosign-public-keys`
Secret by MAKE after explicit approval. The Kyverno admission service account
may read only that named Secret key through a namespaced Role.

TAR owns the checksum-locked Kyverno chart, its linux/amd64 controller and
readiness images, and the Cosign linux/amd64 binary. MAKE owns the Kyverno
GitOps application, the label-scoped `shell-require-signed-images`
ClusterPolicy, and the trust Secret application. The policy requires one
Cosign public-key attestor, verifies image digests, does not mutate digests,
and uses `failurePolicy: Fail` and `validationFailureAction: Enforce` for the
selected namespaces.

The first policy verifies only the private Harbor image prefix
`registry.shell.internal/shell/*`. Rekor inclusion and certificate
transparency are explicitly ignored in this bounded local-key policy. Key
rotation is never automatic; replacement requires a separate approval and
signature migration decision. WATCH owns later read-only admission evidence.

## Consequences

An enforced namespace cannot admit an unsigned or mutable private image once
Kyverno and its public key are live. Current controller namespaces remain
outside the label-scoped rule, so this source slice does not strand the
foundation while its own supply and trust gates are incomplete.

The policy depends on Harbor pull credentials, a published GitOps revision,
Kyverno readiness, and a matching public-key Secret. A key replacement can
invalidate existing signatures and therefore must be coordinated with image
promotion.

Source validation can prove ownership, contract shape, digest pins, CA data,
RBAC narrowness, policy matching, and refusal behavior. It does not prove
Cosign key generation, Harbor publication, signature provenance, Kyverno
readiness, admission denial, or live cluster enforcement.

## References

- [Kyverno verify images](https://kyverno.io/docs/policy-types/cluster-policy/verify-images/)
- [Sigstore Cosign](https://docs.sigstore.dev/cosign/)
- [Kubernetes admission controllers](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)

# Use Google Cloud Storage for Velero backups

Last updated: 02.09.2026

## Summary

Use a private, versioned Google Cloud Storage bucket as the GCP Velero backup
store. INIT owns the independent bucket and service-account root, MAKE owns the
Velero workload and credential Secret, TAR owns the chart and image pins, and
WATCH owns later backup and restore evidence.

## Context

Velero has no current implementation in SHELL. Keeping backups on Longhorn
would leave workload data and its backup copy in the same cluster failure
domain. A self-hosted K3s cluster also has no configured Google Workload
Identity Federation path, so the initial GCS plugin handoff requires a
dedicated service-account JSON key held in private local state.

The backup path needs a separate OpenTofu state root, bucket-level access
control, CSI snapshot support for Longhorn, and explicit network access to the
Google storage and OAuth endpoints. The archived shellprod configuration
contains a useful migration pattern but uses its own project, domains, and
retired object-store assumptions.

## Decision

Create an independent `gcs-backup` OpenTofu root with a bucket in
`europe-west4`, uniform bucket-level access, enforced public-access prevention,
object versioning, lifecycle expiry, and `force_destroy = false`. Create one
`velero-backup` service account and grant it only
`roles/storage.objectAdmin` on that bucket. Export its sensitive JSON key only
to ignored private INIT state; key creation and rotation require explicit
approval.

Configure the GCP Velero release with the pinned GCS plugin, Kopia uploader,
CSI data movement, no cloud volume-snapshot location, a retained Longhorn
snapshot class, and one daily `release-feed` schedule. MAKE applies the
credential as `velero-object-store` only after its exact approval. The
standard and Cilium network policies allow only Kubernetes API, cluster DNS,
Google Storage, and OAuth traffic, plus monitoring ingress.

Keep the bucket name as an explicit deployment input rather than reusing a
donor project identifier. Do not delete or adopt an existing bucket, PVC,
BackupStorageLocation, RustFS resource, or snapshot controller without a
separate migration decision.

## Consequences

Backup objects live outside the cluster's Longhorn failure domain, while the
CSI data mover still uses Longhorn for the source snapshot. The service-account
key becomes a rotation and recovery responsibility; the OpenTofu state and
private credential file require the same custody care as other INIT state.

The snapshot controller adds cluster-scoped CRDs, RBAC, and a controller in
`kube-system`. The first GCS BSL is source-defined but its placeholder bucket
must be replaced by an approved unique name before deployment.

Source checks can prove the bucket policy, IAM role, chart and image pins,
manifest relationships, credential shape, and refusal boundaries. They do not
prove provider state, bucket access, key creation, Velero readiness, snapshot
movement, backup objects, restore parity, node-loss recovery, or key rotation.

## References

- [Velero GCP plugin](https://github.com/vmware-tanzu/velero-plugin-for-gcp)
- [Velero CSI data movement](https://velero.io/docs/main/csi/)
- [Google Cloud Storage IAM](https://cloud.google.com/storage/docs/access-control/iam-roles)
- [Google Cloud Storage public access prevention](https://cloud.google.com/storage/docs/public-access-prevention)

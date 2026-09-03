# Keep backups outside the cluster's Longhorn failure domain. The bucket is
# private, versioned, and protected from accidental destroy.
resource "google_storage_bucket" "backups" {
  project                     = var.project_id
  name                        = var.bucket_name
  location                    = upper(var.region)
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  labels                      = var.labels

  versioning {
    enabled = var.enable_versioning
  }

  lifecycle_rule {
    condition {
      age = 35
    }
    action {
      type = "Delete"
    }
  }

  lifecycle_rule {
    condition {
      days_since_noncurrent_time = 7
    }
    action {
      type = "Delete"
    }
  }
}

resource "google_service_account" "velero" {
  project      = var.project_id
  account_id   = var.service_account_id
  display_name = var.service_account_display_name
  description  = "SHELL Velero object-store identity for ${var.bucket_name}."
}

# Grant only object operations on this bucket; no project-wide storage role is
# needed by the GCS Velero plugin.
resource "google_storage_bucket_iam_member" "velero_object_admin" {
  bucket = google_storage_bucket.backups.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.velero.email}"
}

# The self-hosted K3s plugin uses a service-account JSON key. Key creation is a
# separate approved provider operation; the sensitive output is written only
# to ignored INIT state and is never printed or committed.
resource "google_service_account_key" "velero" {
  service_account_id = google_service_account.velero.name
}

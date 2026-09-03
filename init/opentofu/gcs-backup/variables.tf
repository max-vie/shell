variable "project_id" {
  description = "GCP project containing the Velero backup bucket."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid GCP project ID."
  }
}

variable "region" {
  description = "GCP region used for the bucket location."
  type        = string
  default     = "europe-west4"

  validation {
    condition     = var.region == "europe-west4"
    error_message = "region must be europe-west4 for the current backup contract."
  }
}

variable "bucket_name" {
  description = "Globally unique GCS bucket name for Velero backups."
  type        = string

  validation {
    condition = (
      length(var.bucket_name) >= 3 && length(var.bucket_name) <= 63 &&
      can(regex("^[a-z0-9][a-z0-9._-]*[a-z0-9]$", var.bucket_name)) &&
      !can(regex("goog", var.bucket_name)) &&
      !can(regex("^[0-9]+[.]([0-9]+[.]){2}[0-9]+$", var.bucket_name))
    )
    error_message = "bucket_name must be a valid non-IP GCS bucket name."
  }
}

variable "service_account_id" {
  description = "Account ID for the Velero GCS service account."
  type        = string
  default     = "velero-backup"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.service_account_id))
    error_message = "service_account_id must be a valid GCP service-account ID."
  }
}

variable "service_account_display_name" {
  description = "Display name for the Velero GCS service account."
  type        = string
  default     = "SHELL Velero backup"
}

variable "enable_versioning" {
  description = "Keep prior object generations recoverable."
  type        = bool
  default     = true
}

variable "labels" {
  description = "Stable labels applied to the backup bucket."
  type        = map(string)
  default = {
    environment = "shell"
    role        = "velero-backup"
  }
}

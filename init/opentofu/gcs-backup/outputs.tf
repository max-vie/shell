output "bucket_name" {
  description = "GCS bucket used by the Velero BackupStorageLocation."
  value       = google_storage_bucket.backups.name
}

output "bucket_url" {
  description = "GCS URL of the Velero backup bucket."
  value       = google_storage_bucket.backups.url
}

output "service_account_email" {
  description = "Dedicated Velero GCS service-account email."
  value       = google_service_account.velero.email
}

output "credentials_json" {
  description = "Sensitive service-account JSON for the Velero Secret."
  value       = base64decode(google_service_account_key.velero.private_key)
  sensitive   = true
}

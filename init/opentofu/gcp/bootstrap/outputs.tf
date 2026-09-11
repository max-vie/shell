output "project_id" {
  description = "Bootstrap project ID."
  value       = google_project.bootstrap.project_id
}

output "project_number" {
  description = "Bootstrap project number."
  value       = google_project.bootstrap.number
}

output "billing_enabled" {
  description = "Billing link state for the bootstrap project."
  value       = google_billing_project_info.bootstrap.billing_account != null
}

output "deployment_service_account" {
  description = "Deployment service account email."
  value       = google_service_account.deployer.email
}

output "custom_role" {
  description = "Custom role name bound to the deployment service account."
  value       = google_project_iam_custom_role.deployer.id
}

output "required_apis" {
  description = "APIs enabled by the bootstrap root."
  value       = sort(var.required_apis)
}

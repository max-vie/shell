locals {
  # SUDO owns the operator access profile. The custom role permissions are
  # read from that contract so the live role cannot drift from the reviewed
  # permission list.
  operator_profile = jsondecode(file("${path.root}/../../../../sudo/access/operator-access-profile.json"))
  role_permissions = flatten([
    for role_class in local.operator_profile.access_boundary.deployment_service_account.role_classes : role_class.permissions
  ])
}

resource "google_project" "bootstrap" {
  project_id = var.project_id
  name       = var.project_id
  # No organization or folder: the project is placed outside any organization.
  # Billing is linked through google_billing_project_info, not the project
  # resource, so the link is explicit and reviewable.
  auto_create_network = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_billing_project_info" "bootstrap" {
  project         = google_project.bootstrap.project_id
  billing_account = var.billing_account
}

resource "google_billing_budget" "bootstrap" {
  billing_account = var.billing_account
  display_name    = "${var.project_id} budget"

  budget_filter {
    projects = ["projects/${google_project.bootstrap.number}"]
  }

  amount {
    specified_amount {
      currency_code = var.budget_currency
      units         = var.budget_amount_units
    }
  }

  dynamic "threshold_rules" {
    for_each = var.budget_thresholds
    content {
      threshold_percent = threshold_rules.value
    }
  }

  all_updates_rule {
    monitoring_notification_channels = []
    enable_project_level_recipients  = true
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_project_service" "required" {
  for_each           = toset(var.required_apis)
  project            = google_project.bootstrap.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_service_account" "deployer" {
  project      = google_project.bootstrap.project_id
  account_id   = var.deployment_service_account
  display_name = "SHELL local deployer"
}

resource "google_project_iam_custom_role" "deployer" {
  project     = google_project.bootstrap.project_id
  role_id     = var.custom_role_id
  title       = "SHELL local deployer"
  description = "Exact SUDO-defined permissions for the shell-local-deployer service account."
  permissions = local.role_permissions
  stage       = "GA"
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_project_iam_member" "deployer" {
  project = google_project.bootstrap.project_id
  role    = google_project_iam_custom_role.deployer.id
  member  = "serviceAccount:${google_service_account.deployer.email}"
}

resource "google_service_account_iam_member" "operator" {
  service_account_id = google_service_account.deployer.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "user:${var.operator_email}"
}

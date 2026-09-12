terraform {
  required_version = ">= 1.11.0, < 1.12.0"

  # Remote state is generally recommended. This single-owner project uses a
  # local backend for ease of operation, with state kept under private .local.
  backend "local" {
    path = "../../../../.local/opentofu/gcp/k3s/terraform.tfstate"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.41"
    }
  }
}

provider "google" {
  # Use the exact short-lived deployment account after bootstrap.
  project                     = var.project_id
  impersonate_service_account = "shell-local-deployer@${var.project_id}.iam.gserviceaccount.com"
}

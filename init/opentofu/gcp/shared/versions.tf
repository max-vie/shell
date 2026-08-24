terraform {
  required_version = ">= 1.11.0, < 1.12.0"

  # Remote state is generally recommended. This single-owner project uses a
  # local backend for ease of operation, with state kept under private .local.
  backend "local" {
    path = "../../../../.local/opentofu/gcp/shared/terraform.tfstate"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.41"
    }
  }
}

provider "google" {
  # Use ADC locally or Workload Identity Federation externally; keep
  # credential files outside the checkout and out of HCL, state, and plans.
  project = var.project_id
  region  = var.region
}

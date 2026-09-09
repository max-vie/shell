terraform {
  required_version = ">= 1.11.0, < 1.12.0"

  # Remote state is generally recommended. This single-owner project uses a
  # local backend for ease of operation, with state kept under private .local.
  backend "local" {
    path = "../../../../.local/opentofu/gcp/network/terraform.tfstate"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.41"
    }
  }
}

provider "google" {
  # Slice 2 source validation remains credential-free. Slice 3 will supply
  # short-lived shell-local-deployer impersonation outside HCL and state.
  project = var.project_id
  region  = var.region
}

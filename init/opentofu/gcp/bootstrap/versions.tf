terraform {
  required_version = ">= 1.11.0, < 1.12.0"

  # Single-owner project uses a local backend per root, with state kept
  # under private .local. See ADR 017.
  backend "local" {
    path = "../../../../.local/opentofu/gcp/bootstrap/terraform.tfstate"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.41"
    }
  }
}

provider "google" {
  # Slice 2 source validation remains credential-free. The live run supplies
  # short-lived shell-local-deployer impersonation outside HCL and state.
  project = var.project_id
  region  = var.region
}

terraform {
  required_version = ">= 1.11.0, < 1.12.0"

  # Keep backup state separate from the shared network and cluster roots.
  backend "local" {
    path = "../../../../.local/opentofu/gcs-backup/terraform.tfstate"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.41"
    }
  }
}

provider "google" {
  # Authentication stays in ADC or a private federation wrapper.
  project = var.project_id
  region  = var.region
}

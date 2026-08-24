terraform {
  required_version = ">= 1.11.0, < 1.12.0"

  # Remote state is generally recommended. This single-owner project uses a
  # local backend for ease of operation, with state kept under private .local.
  backend "local" {
    path = "../../../../.local/opentofu/proxmox/k3s/terraform.tfstate"
  }

  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "= 0.111.1"
    }
  }
}

provider "proxmox" {
  # Read the endpoint and API token from PROXMOX_VE_* environment variables;
  # keep credentials out of HCL, state, plans, Git, and shell history.
}

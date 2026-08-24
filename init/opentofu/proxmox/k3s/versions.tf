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
  ssh {
    # source_file/import_from needs SSH to the node; the private runtime wrapper
    # supplies the IAP tunnel endpoint and the SSH agent supplies the key.
    agent    = true
    username = var.ssh_username

    # A private GCP host is not directly routable from the control machine.
    # A private wrapper owns the matching IAP TCP tunnel.
    node {
      name    = var.pve_node_name
      address = var.ssh_address
      port    = var.ssh_port
    }
  }
}

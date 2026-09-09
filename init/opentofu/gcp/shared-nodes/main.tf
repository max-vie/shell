data "terraform_remote_state" "network" {
  # The network root owns the VPC and subnet. Consume its outputs so this root
  # follows the real dependency instead of repeating resource names.
  backend = "local"

  config = {
    path = "../../../../.local/opentofu/gcp/network/terraform.tfstate"
  }
}

locals {
  network = data.terraform_remote_state.network.outputs
}

resource "terraform_data" "network_contract" {
  input = {
    project_id = local.network.project_id
    region     = local.network.region
  }

  lifecycle {
    precondition {
      condition = (
        var.project_id == try(local.network.project_id, "") &&
        var.region == try(local.network.region, "")
      )
      error_message = "shared-nodes project_id and region must match network state."
    }
  }
}

module "shared_nodes" {
  for_each = var.shared_nodes
  source   = "../../modules/gcp-private-node"

  project_id        = local.network.project_id
  region            = local.network.region
  subnetwork_id     = local.network.subnetwork_self_link
  node_name         = each.key
  zone              = each.value.zone
  internal_address  = each.value.address
  machine_type      = each.value.machine_type
  source_image      = each.value.source_image
  boot_disk_size_gb = each.value.boot_disk_size_gb
  data_disk_size_gb = each.value.data_disk_size_gb
  tags = concat(
    ["shell-shared"],
    each.key == "identity-01" ? ["shell-identity"] : ["shell-delivery"],
  )
  deletion_protection = var.deletion_protection
  data_device_name    = "shell-${each.key}-data"
  depends_on          = [terraform_data.network_contract]
}

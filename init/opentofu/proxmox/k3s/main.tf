data "proxmox_virtual_environment_pool" "k3s" {
  pool_id = var.pool_id
}

resource "proxmox_virtual_environment_vm" "k3s" {
  for_each = var.k3s_nodes

  name                = each.key
  description         = "SHELL ${each.key} K3s server"
  tags                = ["init", "platform", "k3s", "proxmox"]
  node_name           = var.pve_node_name
  pool_id             = data.proxmox_virtual_environment_pool.k3s.pool_id
  vm_id               = each.value.vm_id
  started             = var.start_guests
  on_boot             = var.start_guests
  stop_on_destroy     = true
  reboot_after_update = false

  agent {
    enabled = var.guest_agent_enabled
  }

  clone {
    vm_id        = var.template_vm_id
    full         = true
    datastore_id = var.datastore_id
  }

  cpu {
    cores = each.value.cpu_cores
    type  = "host"
  }

  memory {
    dedicated = each.value.memory_mib
  }

  network_device {
    bridge = var.bridge_name
    model  = "virtio"
  }

  initialization {
    ip_config {
      ipv4 {
        address = each.value.address
        gateway = var.guest_gateway
      }
    }

    dynamic "dns" {
      for_each = length(var.guest_dns_servers) > 0 ? [true] : []

      content {
        servers = var.guest_dns_servers
      }
    }
  }
}

data "proxmox_virtual_environment_pool" "k3s" {
  pool_id = var.pool_id
}

resource "proxmox_virtual_environment_file" "debian" {
  # Local image upload requires provider SSH, configured through the private
  # IAP tunnel and agent in versions.tf. API-only auth is insufficient here.
  content_type   = "import"
  datastore_id   = var.image_datastore_id
  node_name      = var.pve_node_name
  overwrite      = false
  timeout_upload = 1800

  source_file {
    path      = var.debian_image.path
    file_name = var.debian_image.file_name
    checksum  = var.debian_image.sha256
    insecure  = false
  }
}

resource "proxmox_virtual_environment_vm" "k3s" {
  for_each = var.k3s_nodes

  name                = each.key
  description         = "SHELL ${each.key} K3s server"
  tags                = ["debian-13", "init", "k3s", "platform", "proxmox"]
  node_name           = var.pve_node_name
  pool_id             = data.proxmox_virtual_environment_pool.k3s.pool_id
  vm_id               = each.value.vm_id
  started             = var.start_guests
  on_boot             = var.start_guests
  stop_on_destroy     = true
  reboot_after_update = false
  scsi_hardware       = "virtio-scsi-single"
  protection          = true

  lifecycle {
    # A VM replacement would destroy its embedded etcd state; rotate images
    # through an explicit, reviewed lifecycle change.
    prevent_destroy = true
  }

  agent {
    # The prepared Debian image enables the agent before this VM can start.
    enabled = true
  }

  disk {
    datastore_id = var.datastore_id
    import_from  = proxmox_virtual_environment_file.debian.id
    interface    = "scsi0"
    size         = each.value.root_disk_gib
    discard      = "on"
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
    mtu    = 1
  }

  initialization {
    datastore_id = var.datastore_id
    # The BPG provider documents this as root@pam-only; the runtime contract
    # uses a privilege-separated token with narrowly scoped ACLs.
    upgrade = false

    ip_config {
      ipv4 {
        address = each.value.address
        gateway = var.guest_gateway
      }
    }

    dns {
      servers = var.guest_dns_servers
    }
  }

  operating_system {
    type = "l26"
  }
}

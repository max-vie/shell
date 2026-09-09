data "terraform_remote_state" "shared" {
  # The network root owns the VPC and subnet. Consume its outputs instead of
  # repeating network names between independently managed roots.
  backend = "local"

  config = {
    path = "../../../../.local/opentofu/gcp/network/terraform.tfstate"
  }
}

locals {
  shared = data.terraform_remote_state.shared.outputs
}

resource "google_compute_firewall" "iap_management" {
  project       = var.project_id
  name          = "${var.name}-allow-iap-management"
  network       = local.shared.network_self_link
  direction     = "INGRESS"
  source_ranges = var.iap_source_ranges
  target_tags   = var.tags

  allow {
    protocol = "tcp"
    ports    = ["22", "8006"]
  }
}

resource "google_compute_address" "host" {
  project      = var.project_id
  name         = "${var.name}-internal"
  region       = local.shared.region
  address_type = "INTERNAL"
  subnetwork   = local.shared.subnetwork_self_link
  address      = var.internal_address
}

resource "google_compute_disk" "data" {
  #checkov:skip=CKV_GCP_37:Google-managed encryption remains until SUDO owns a KMS key contract.
  project = var.project_id
  name    = "${var.name}-data"
  zone    = var.zone
  type    = var.data_disk_type
  size    = var.data_disk_size_gb
  labels  = var.labels

  lifecycle {
    prevent_destroy = true
  }
}

# No runtime service account is attached. Add a SUDO-owned, least-privilege
# identity only when software inside this host needs to call GCP APIs.
resource "google_compute_instance" "proxmox_host" {
  #checkov:skip=CKV_GCP_36:The nested guest NAT requires forwarding on the outer host.
  #checkov:skip=CKV_GCP_38:Google-managed encryption remains until SUDO owns a KMS key contract.
  project                   = var.project_id
  name                      = var.name
  zone                      = var.zone
  machine_type              = var.machine_type
  can_ip_forward            = true
  allow_stopping_for_update = true
  deletion_protection       = var.deletion_protection
  tags                      = var.tags
  labels                    = var.labels

  boot_disk {
    auto_delete = true

    initialize_params {
      # The reviewed Debian image self-link is pinned in private
      # variables and needs manual CVE rotation for ease of operation.
      image = var.source_image
      size  = var.boot_disk_size_gb
      type  = "pd-balanced"
    }
  }

  attached_disk {
    source      = google_compute_disk.data.id
    device_name = "proxmox-data"
    mode        = "READ_WRITE"
  }

  network_interface {
    # No access_config block keeps the outer host private; SSH uses IAP.
    subnetwork = local.shared.subnetwork_self_link
    network_ip = google_compute_address.host.address
  }

  metadata = {
    # OS Login is the host access boundary; project-wide SSH keys remain
    # disabled. The API and SSH ports are reachable only through IAP.
    block-project-ssh-keys = "TRUE"
    enable-oslogin         = "TRUE"
  }

  advanced_machine_features {
    # Proxmox is itself a guest on this GCP VM, so nested virtualization is
    # required before it can expose hardware virtualization to K3s guests.
    enable_nested_virtualization = true
  }

  scheduling {
    # The single-owner lab keeps host restart behavior explicit; recovery of
    # the nested cluster remains an approved operational action.
    automatic_restart   = false
    on_host_maintenance = "MIGRATE"
    provisioning_model  = "STANDARD"
  }

  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_secure_boot          = false
    enable_vtpm                 = true
  }
}

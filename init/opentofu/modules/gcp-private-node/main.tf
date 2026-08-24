resource "google_compute_address" "node" {
  project      = var.project_id
  name         = "${var.node_name}-internal"
  region       = var.region
  address_type = "INTERNAL"
  subnetwork   = var.subnetwork_id
  address      = var.internal_address
}

resource "google_compute_disk" "data" {
  project = var.project_id
  name    = "${var.node_name}-data"
  zone    = var.zone
  type    = "pd-balanced"
  size    = var.data_disk_size_gb

  lifecycle {
    prevent_destroy = true
  }
}

# No service_account block is declared here. The VM needs a dedicated,
# least-privilege identity only when software inside the guest calls GCP APIs;
# OpenTofu authentication through ADC is a separate concern.
resource "google_compute_instance" "node" {
  project                   = var.project_id
  name                      = var.node_name
  zone                      = var.zone
  machine_type              = var.machine_type
  can_ip_forward            = var.can_ip_forward
  deletion_protection       = var.deletion_protection
  allow_stopping_for_update = true
  tags                      = var.tags

  boot_disk {
    auto_delete = true

    # The boot image is pinned by self-link. CVE updates require manual image
    # rotation; keeping that process manual makes operation easier here.
    initialize_params {
      image = var.source_image
      size  = var.boot_disk_size_gb
      type  = "pd-balanced"
    }
  }

  attached_disk {
    source      = google_compute_disk.data.id
    device_name = coalesce(var.data_device_name, "${var.node_name}-data")
    mode        = "READ_WRITE"
  }

  network_interface {
    subnetwork = var.subnetwork_id
    network_ip = google_compute_address.node.address
  }

  metadata = {
    enable-oslogin = "TRUE"
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
    provisioning_model  = "STANDARD"
  }

  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_secure_boot          = true
    enable_vtpm                 = true
  }
}

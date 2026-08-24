resource "google_project_service" "compute" {
  project            = var.project_id
  service            = "compute.googleapis.com"
  disable_on_destroy = false
}

resource "google_compute_network" "shared" {
  project                 = var.project_id
  name                    = var.network_name
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
  # GCP defaults to 1460; pin it so the nested bridge and guest NICs use the
  # same frame size instead of depending on an implicit provider default.
  mtu = 1460

  depends_on = [google_project_service.compute]
}

resource "google_compute_subnetwork" "shared" {
  project                  = var.project_id
  name                     = var.subnet_name
  region                   = var.region
  network                  = google_compute_network.shared.id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true

  # Flow logs improve incident evidence but include metadata and add logging
  # cost; this is an intentional platform-observability tradeoff.
  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_router" "shared" {
  project = var.project_id
  name    = "${var.network_name}-router"
  region  = var.region
  network = google_compute_network.shared.id
}

resource "google_compute_router_nat" "shared" {
  project                            = var.project_id
  name                               = "${var.network_name}-nat"
  router                             = google_compute_router.shared.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.shared.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

resource "google_compute_firewall" "iap_ssh" {
  project       = var.project_id
  name          = "${var.network_name}-allow-iap-ssh"
  network       = google_compute_network.shared.name
  direction     = "INGRESS"
  source_ranges = var.iap_source_ranges
  target_tags   = ["shell-shared"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "shared_internal" {
  project       = var.project_id
  name          = "${var.network_name}-allow-shared-internal"
  network       = google_compute_network.shared.name
  direction     = "INGRESS"
  source_ranges = [var.subnet_cidr]
  target_tags   = ["shell-shared"]

  allow {
    protocol = "tcp"
    ports    = ["22", "53", "80", "443", "389", "636"]
  }

  allow {
    protocol = "udp"
    ports    = ["53"]
  }
}

module "shared_nodes" {
  for_each = var.shared_nodes
  source   = "../../modules/gcp-private-node"

  project_id          = var.project_id
  region              = var.region
  subnetwork_id       = google_compute_subnetwork.shared.id
  node_name           = each.key
  zone                = each.value.zone
  internal_address    = each.value.address
  machine_type        = each.value.machine_type
  source_image        = each.value.source_image
  boot_disk_size_gb   = each.value.boot_disk_size_gb
  data_disk_size_gb   = each.value.data_disk_size_gb
  tags                = ["shell-shared"]
  deletion_protection = var.deletion_protection
  data_device_name    = "shell-${each.key}-data"

  depends_on = [google_compute_router_nat.shared]
}

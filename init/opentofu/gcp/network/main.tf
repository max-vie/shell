locals {
  # TAR owns the public platform supply contract. The routing subsection is
  # consumed here for the GCP-managed proxy subnet and by the K3s root for
  # service frontends.
  platform_supply = jsondecode(file("${path.root}/../../../../tar/manifests/platform-addons-supply.json"))
  service_routing = local.platform_supply.service_routing
}

resource "google_compute_network" "shared" {
  project                 = var.project_id
  name                    = var.network_name
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
  # GCP defaults to 1460; pin it so the nested bridge and guest NICs use the
  # same frame size instead of depending on an implicit provider default.
  mtu = 1460
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

resource "google_compute_subnetwork" "proxy_only" {
  project       = var.project_id
  name          = local.service_routing.proxy_only_subnet.name
  region        = google_compute_subnetwork.shared.region
  network       = google_compute_network.shared.id
  ip_cidr_range = local.service_routing.proxy_only_subnet.cidr
  purpose       = "REGIONAL_MANAGED_PROXY"
  role          = "ACTIVE"
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
    ports    = ["22"]
  }

  # Establish service-specific rules before narrowing an existing shared rule.
  depends_on = [
    google_compute_firewall.identity_internal,
    google_compute_firewall.delivery_internal,
  ]
}

resource "google_compute_firewall" "identity_internal" {
  project       = var.project_id
  name          = "${var.network_name}-allow-identity-internal"
  network       = google_compute_network.shared.name
  direction     = "INGRESS"
  source_ranges = [var.subnet_cidr]
  target_tags   = ["shell-identity"]

  allow {
    protocol = "tcp"
    ports    = ["53", "80", "88", "389", "443", "464", "636"]
  }

  allow {
    protocol = "udp"
    ports    = ["53", "88", "464"]
  }
}

resource "google_compute_firewall" "delivery_internal" {
  project       = var.project_id
  name          = "${var.network_name}-allow-delivery-internal"
  network       = google_compute_network.shared.name
  direction     = "INGRESS"
  source_ranges = [var.subnet_cidr]
  target_tags   = ["shell-delivery"]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

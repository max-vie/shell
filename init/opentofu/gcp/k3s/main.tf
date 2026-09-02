data "terraform_remote_state" "shared" {
  # The shared root owns the VPC and subnet. Consume its outputs so this root
  # follows the real dependency instead of repeating resource names.
  backend = "local"

  config = {
    path = "../../../../.local/opentofu/gcp/shared/terraform.tfstate"
  }
}

locals {
  shared          = data.terraform_remote_state.shared.outputs
  platform_supply = jsondecode(file("${path.root}/../../../../tar/manifests/platform-addons-supply.json"))
  service_routing = local.platform_supply.service_routing
  services        = local.service_routing.services
}

resource "google_compute_firewall" "iap_ssh" {
  project       = var.project_id
  name          = "${var.api_name}-allow-iap-ssh"
  network       = local.shared.network_self_link
  direction     = "INGRESS"
  source_ranges = var.iap_source_ranges
  target_tags   = ["shell-gcp-k3s"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "cluster_internal" {
  project       = var.project_id
  name          = "${var.api_name}-allow-cluster-internal"
  network       = local.shared.network_self_link
  direction     = "INGRESS"
  source_ranges = [local.shared.subnet_cidr]
  target_tags   = ["shell-gcp-k3s"]

  allow {
    protocol = "tcp"
    ports    = ["22", "53", "80", "443", "2379", "2380", "6443", "9345", "10250"]
  }

  allow {
    protocol = "udp"
    ports    = ["53", "8472"]
  }
}

resource "google_compute_firewall" "api_health_checks" {
  project       = var.project_id
  name          = "${var.api_name}-allow-health-checks"
  network       = local.shared.network_self_link
  direction     = "INGRESS"
  source_ranges = var.health_check_source_ranges
  target_tags   = ["shell-gcp-k3s"]

  allow {
    protocol = "tcp"
    ports    = ["6443"]
  }
}

resource "google_compute_firewall" "service_proxy_access" {
  project       = var.project_id
  name          = "${var.api_name}-allow-service-proxies"
  network       = local.shared.network_self_link
  direction     = "INGRESS"
  source_ranges = [local.shared.proxy_only_subnet_cidr]
  target_tags   = ["shell-gcp-k3s"]

  allow {
    protocol = "tcp"
    ports    = [for service in values(local.services) : tostring(service.backend_port)]
  }
}

resource "google_compute_firewall" "service_health_checks" {
  project       = var.project_id
  name          = "${var.api_name}-allow-service-health-checks"
  network       = local.shared.network_self_link
  direction     = "INGRESS"
  source_ranges = var.health_check_source_ranges
  target_tags   = ["shell-gcp-k3s"]

  allow {
    protocol = "tcp"
    ports    = [for service in values(local.services) : tostring(service.health_check_port)]
  }
}

module "k3s_nodes" {
  for_each = var.k3s_nodes
  source   = "../../modules/gcp-private-node"

  project_id        = var.project_id
  region            = local.shared.region
  subnetwork_id     = local.shared.subnetwork_self_link
  node_name         = each.key
  zone              = each.value.zone
  internal_address  = each.value.address
  machine_type      = each.value.machine_type
  source_image      = each.value.source_image
  boot_disk_size_gb = each.value.boot_disk_size_gb
  data_disk_size_gb = each.value.data_disk_size_gb
  tags              = ["shell-gcp-k3s"]
  # K3s/CNI routing needs forwarding for pod and service traffic.
  can_ip_forward      = true
  deletion_protection = var.deletion_protection
}

resource "google_compute_instance_group" "k3s" {
  for_each  = var.k3s_nodes
  project   = var.project_id
  name      = "${each.key}-group"
  zone      = each.value.zone
  instances = [module.k3s_nodes[each.key].self_link]

  named_port {
    name = local.services.harbor.backend_port_name
    port = local.services.harbor.backend_port
  }

  named_port {
    name = local.services.release_feed.backend_port_name
    port = local.services.release_feed.backend_port
  }
}

resource "google_compute_address" "api" {
  project      = var.project_id
  name         = var.api_name
  region       = local.shared.region
  address_type = "INTERNAL"
  subnetwork   = local.shared.subnetwork_self_link
  address      = var.api_address
}

resource "google_compute_health_check" "api" {
  project = var.project_id
  name    = var.api_name

  tcp_health_check {
    port = 6443
  }
}

resource "google_compute_region_backend_service" "api" {
  project               = var.project_id
  name                  = var.api_name
  region                = local.shared.region
  protocol              = "TCP"
  load_balancing_scheme = "INTERNAL"
  health_checks         = [google_compute_health_check.api.id]
  network               = local.shared.network_self_link

  dynamic "backend" {
    for_each = google_compute_instance_group.k3s

    content {
      group          = backend.value.self_link
      balancing_mode = "CONNECTION"
    }
  }
}

resource "google_compute_forwarding_rule" "api" {
  project               = var.project_id
  name                  = var.api_name
  region                = local.shared.region
  ip_address            = google_compute_address.api.address
  backend_service       = google_compute_region_backend_service.api.id
  ip_protocol           = "TCP"
  load_balancing_scheme = "INTERNAL"
  network               = local.shared.network_self_link
  subnetwork            = local.shared.subnetwork_self_link
  ports                 = ["6443"]
}

resource "google_compute_address" "service" {
  for_each     = local.services
  project      = var.project_id
  name         = "${var.api_name}-${replace(each.key, "_", "-")}"
  region       = local.shared.region
  address_type = "INTERNAL"
  subnetwork   = local.shared.subnetwork_self_link
  address      = each.value.address
}

resource "google_compute_region_health_check" "service" {
  for_each = local.services
  project  = var.project_id
  name     = "${var.api_name}-${replace(each.key, "_", "-")}"
  region   = local.shared.region

  tcp_health_check {
    port = each.value.health_check_port
  }
}

resource "google_compute_region_backend_service" "service" {
  for_each              = local.services
  project               = var.project_id
  name                  = "${var.api_name}-${replace(each.key, "_", "-")}"
  region                = local.shared.region
  protocol              = local.service_routing.protocol
  load_balancing_scheme = "INTERNAL_MANAGED"
  port_name             = each.value.backend_port_name
  health_checks         = [google_compute_region_health_check.service[each.key].id]
  network               = local.shared.network_self_link

  dynamic "backend" {
    for_each = google_compute_instance_group.k3s

    content {
      group          = backend.value.self_link
      balancing_mode = "CONNECTION"
    }
  }
}

resource "google_compute_region_target_tcp_proxy" "service" {
  for_each        = local.services
  project         = var.project_id
  name            = "${var.api_name}-${replace(each.key, "_", "-")}"
  region          = local.shared.region
  backend_service = google_compute_region_backend_service.service[each.key].id
}

resource "google_compute_forwarding_rule" "service" {
  for_each              = local.services
  project               = var.project_id
  name                  = "${var.api_name}-${replace(each.key, "_", "-")}"
  region                = local.shared.region
  ip_address            = google_compute_address.service[each.key].address
  target                = google_compute_region_target_tcp_proxy.service[each.key].id
  ip_protocol           = local.service_routing.protocol
  load_balancing_scheme = "INTERNAL_MANAGED"
  network               = local.shared.network_self_link
  subnetwork            = local.shared.subnetwork_self_link
  ports                 = [tostring(local.service_routing.frontend_port)]
  allow_global_access   = local.service_routing.global_access
}

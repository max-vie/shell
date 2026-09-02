output "network_name" {
  description = "The authoritative shared VPC name."
  value       = google_compute_network.shared.name
}

output "network_self_link" {
  description = "The authoritative shared VPC self-link."
  value       = google_compute_network.shared.self_link
}

output "subnetwork_name" {
  description = "The authoritative shared subnet name."
  value       = google_compute_subnetwork.shared.name
}

output "subnetwork_self_link" {
  description = "The authoritative shared subnet self-link."
  value       = google_compute_subnetwork.shared.self_link
}

output "subnet_cidr" {
  description = "The authoritative shared subnet CIDR."
  value       = google_compute_subnetwork.shared.ip_cidr_range
}

output "proxy_only_subnetwork_self_link" {
  description = "Regional proxy-only subnet used by GCP internal proxy load balancers."
  value       = google_compute_subnetwork.proxy_only.self_link
}

output "proxy_only_subnet_cidr" {
  description = "CIDR reserved for GCP-managed internal load-balancer proxies."
  value       = google_compute_subnetwork.proxy_only.ip_cidr_range
}

output "region" {
  description = "The authoritative GCP region for the shared subnet."
  value       = google_compute_subnetwork.shared.region
}

output "project_id" {
  description = "The authoritative GCP project for the shared platform."
  value       = var.project_id
}

output "shared_nodes" {
  description = "Shared platform node names and private addresses."
  value = {
    for name, node in module.shared_nodes : name => {
      name             = node.name
      zone             = node.zone
      internal_ip      = node.internal_ip
      operating_system = var.shared_nodes[name].operating_system
      project_id       = var.project_id
    }
  }
}

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

output "region" {
  description = "The authoritative GCP region for the shared subnet."
  value       = google_compute_subnetwork.shared.region
}

output "shared_nodes" {
  description = "Shared platform node names and private addresses."
  value = {
    for name, node in module.shared_nodes : name => {
      name        = node.name
      zone        = node.zone
      internal_ip = node.internal_ip
    }
  }
}

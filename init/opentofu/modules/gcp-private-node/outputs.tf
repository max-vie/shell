output "name" {
  description = "Created GCP instance name."
  value       = google_compute_instance.node.name
}

output "zone" {
  description = "Created GCP instance zone."
  value       = google_compute_instance.node.zone
}

output "internal_ip" {
  description = "Reserved private address assigned to the instance."
  value       = google_compute_instance.node.network_interface[0].network_ip
}

output "self_link" {
  description = "Created GCP instance self-link."
  value       = google_compute_instance.node.self_link
}

output "data_disk_name" {
  description = "Created persistent data disk name."
  value       = google_compute_disk.data.name
}

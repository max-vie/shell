output "instance_name" {
  description = "Nested Proxmox host name."
  value       = google_compute_instance.proxmox_host.name
}

output "zone" {
  description = "Nested Proxmox host zone."
  value       = google_compute_instance.proxmox_host.zone
}

output "internal_ip" {
  description = "Private GCP address of the nested Proxmox host."
  value       = google_compute_address.host.address
}

output "data_disk_name" {
  description = "Persistent Proxmox data disk name."
  value       = google_compute_disk.data.name
}

output "ssh_command" {
  description = "IAP SSH command for the nested Proxmox host."
  value       = "gcloud compute ssh ${google_compute_instance.proxmox_host.name} --project=${var.project_id} --zone=${var.zone} --tunnel-through-iap"
}

output "proxmox_host" {
  description = "Nested Proxmox host facts for the private Ansible handoff."
  value = {
    instance_name = google_compute_instance.proxmox_host.name
    zone          = google_compute_instance.proxmox_host.zone
    internal_ip   = google_compute_address.host.address
  }
}

output "api_address" {
  description = "Internal GCP load-balancer address for the K3s API."
  value       = google_compute_address.api.address
}

output "api_endpoint" {
  description = "Internal HTTPS endpoint for the direct-GCP K3s API."
  value       = "https://${google_compute_address.api.address}:6443"
}

output "k3s_nodes" {
  description = "Direct-GCP K3s node names, zones, and private addresses."
  value = {
    for name, node in module.k3s_nodes : name => {
      name        = node.name
      zone        = node.zone
      internal_ip = node.internal_ip
      project_id  = var.project_id
    }
  }
}

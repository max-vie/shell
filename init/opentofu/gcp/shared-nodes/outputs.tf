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

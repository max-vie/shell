output "nodes" {
  description = "Declared Proxmox K3s guests and their private addresses."
  value = {
    for name, vm in proxmox_virtual_environment_vm.k3s : name => {
      name    = vm.name
      vm_id   = vm.vm_id
      address = var.k3s_nodes[name].address
      node    = var.pve_node_name
    }
  }
}

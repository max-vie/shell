output "nodes" {
  description = "Declared Proxmox K3s guest identity and prepared-image facts."
  value = {
    for name, vm in proxmox_virtual_environment_vm.k3s : name => {
      name             = vm.name
      vm_id            = vm.vm_id
      address          = var.k3s_nodes[name].address
      node             = var.pve_node_name
      operating_system = "debian-13"
      image_file_name  = var.debian_image.file_name
      image_sha256     = var.debian_image.sha256
    }
  }
}

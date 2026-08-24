variable "pve_node_name" {
  description = "Proxmox node that owns the K3s guests."
  type        = string
}

variable "pool_id" {
  description = "Proxmox pool receiving the K3s guests."
  type        = string
}

variable "template_vm_id" {
  description = "Existing Proxmox template VM ID cloned for each K3s guest."
  type        = number

  validation {
    condition     = var.template_vm_id > 0
    error_message = "template_vm_id must be a positive VM ID."
  }
}

variable "datastore_id" {
  description = "Proxmox datastore receiving cloned guest disks."
  type        = string
}

variable "bridge_name" {
  description = "Proxmox bridge connected to the K3s guest network."
  type        = string
}

variable "guest_gateway" {
  description = "Gateway configured in the cloned guests through cloud-init."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{1,3}([.][0-9]{1,3}){3}$", var.guest_gateway)) && can(cidrhost("${var.guest_gateway}/32", 0))
    error_message = "guest_gateway must be a valid IPv4 host address without a CIDR suffix."
  }
}

variable "guest_dns_servers" {
  description = "DNS servers configured in the cloned guests."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for server in var.guest_dns_servers : can(regex("^[0-9]{1,3}([.][0-9]{1,3}){3}$", server)) && can(cidrhost("${server}/32", 0))
    ])
    error_message = "guest_dns_servers must contain valid IPv4 host addresses."
  }
}

variable "guest_agent_enabled" {
  description = "Enable the QEMU guest agent contract in Proxmox."
  type        = bool
  default     = false
}

variable "start_guests" {
  description = "Start the cloned K3s guests after creation."
  type        = bool
  default     = false
}

variable "k3s_nodes" {
  description = "The three Proxmox K3s guests and their private placement inputs."
  type = map(object({
    vm_id      = number
    address    = string
    cpu_cores  = number
    memory_mib = number
  }))

  validation {
    condition = length(var.k3s_nodes) == 3 && alltrue([
      for name in ["proxmox-k3s-01", "proxmox-k3s-02", "proxmox-k3s-03"] : contains(keys(var.k3s_nodes), name)
    ])
    error_message = "k3s_nodes must contain exactly proxmox-k3s-01, proxmox-k3s-02, and proxmox-k3s-03."
  }

  validation {
    condition = alltrue([
      for node in values(var.k3s_nodes) : can(regex("^[0-9]{1,3}([.][0-9]{1,3}){3}/[0-9]{1,2}$", node.address)) && can(cidrhost(node.address, 0))
    ])
    error_message = "Each Proxmox K3s address must be a valid IPv4 CIDR address with a prefix from /0 through /32."
  }

  validation {
    condition = alltrue([
      for node in values(var.k3s_nodes) : node.vm_id > 0 && node.cpu_cores > 0 && node.memory_mib > 0
    ])
    error_message = "Each Proxmox K3s node must have positive VM ID, CPU, and memory values."
  }
}

variable "pve_node_name" {
  description = "Proxmox node that owns the K3s guests."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._-]*$", var.pve_node_name))
    error_message = "pve_node_name must be a non-empty Proxmox node name."
  }
}

variable "pool_id" {
  description = "Proxmox pool receiving the K3s guests."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._-]*$", var.pool_id))
    error_message = "pool_id must be a non-empty Proxmox pool ID."
  }
}

variable "ssh_username" {
  description = "OS Login user for the private Proxmox host SSH tunnel."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z_][A-Za-z0-9._-]*$", var.ssh_username))
    error_message = "ssh_username must be a valid host account name."
  }
}

variable "ssh_address" {
  description = "Loopback address of the private IAP SSH tunnel."
  type        = string
  default     = "127.0.0.1"

  validation {
    condition     = var.ssh_address == "127.0.0.1"
    error_message = "ssh_address must remain 127.0.0.1 for the private tunnel."
  }
}

variable "ssh_port" {
  description = "Local port of the private IAP SSH tunnel."
  type        = number
  default     = 10022

  validation {
    condition     = var.ssh_port == 10022
    error_message = "ssh_port must remain 10022 for the private tunnel contract."
  }
}

variable "datastore_id" {
  description = "Proxmox datastore receiving imported guest disks."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._-]*$", var.datastore_id))
    error_message = "datastore_id must be a non-empty Proxmox datastore ID."
  }
}

variable "image_datastore_id" {
  description = "Proxmox datastore receiving the prepared Debian image upload."
  type        = string
  default     = "local"

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._-]*$", var.image_datastore_id))
    error_message = "image_datastore_id must be a non-empty Proxmox datastore ID."
  }
}

variable "debian_image" {
  description = "Prepared Debian image produced by the private INIT image workflow."
  type = object({
    path      = string
    file_name = string
    sha256    = string
  })

  validation {
    condition = (
      startswith(var.debian_image.path, "/") &&
      basename(var.debian_image.file_name) == var.debian_image.file_name &&
      endswith(var.debian_image.file_name, ".qcow2") &&
      can(regex("^[0-9a-f]{64}$", var.debian_image.sha256))
    )
    error_message = "debian_image requires a path, file name, and 64-character SHA-256 checksum."
  }
}

variable "bridge_name" {
  description = "Proxmox bridge connected to the K3s guest network."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._-]*$", var.bridge_name))
    error_message = "bridge_name must be a non-empty Proxmox bridge name."
  }
}

variable "guest_gateway" {
  description = "Gateway configured in the imported guests through cloud-init."
  type        = string

  validation {
    condition     = var.guest_gateway == "10.66.0.1"
    error_message = "guest_gateway must be 10.66.0.1 for the nested Proxmox guest network."
  }
}

variable "guest_dns_servers" {
  description = "DNS servers configured in the imported guests."
  type        = list(string)
  default     = ["10.77.0.210"]

  validation {
    condition     = try(length(var.guest_dns_servers) == 1 && var.guest_dns_servers[0] == "10.77.0.210", false)
    error_message = "guest_dns_servers must contain only the shared identity DNS address."
  }
}

variable "start_guests" {
  description = "Start the imported K3s guests after creation."
  type        = bool
  default     = false
}

variable "k3s_nodes" {
  description = "The three Proxmox K3s guests and their private placement inputs."
  type = map(object({
    vm_id         = number
    address       = string
    cpu_cores     = number
    memory_mib    = number
    root_disk_gib = number
  }))

  validation {
    condition = length(var.k3s_nodes) == 3 && alltrue([
      for name in ["proxmox-k3s-01", "proxmox-k3s-02", "proxmox-k3s-03"] : contains(keys(var.k3s_nodes), name)
    ])
    error_message = "k3s_nodes must contain exactly proxmox-k3s-01, proxmox-k3s-02, and proxmox-k3s-03."
  }

  validation {
    condition = alltrue([
      try(var.k3s_nodes["proxmox-k3s-01"].address, "") == "10.66.0.201/24",
      try(var.k3s_nodes["proxmox-k3s-02"].address, "") == "10.66.0.202/24",
      try(var.k3s_nodes["proxmox-k3s-03"].address, "") == "10.66.0.203/24",
    ])
    error_message = "Proxmox K3s addresses must match the 10.66.0.201-203 contract."
  }

  validation {
    condition = alltrue([
      for node in values(var.k3s_nodes) : (
        node.vm_id >= 100 && node.vm_id == floor(node.vm_id) &&
        node.cpu_cores > 0 && node.cpu_cores == floor(node.cpu_cores) &&
        node.memory_mib >= 2048 && node.memory_mib == floor(node.memory_mib) &&
        node.root_disk_gib >= 16 && node.root_disk_gib == floor(node.root_disk_gib)
      )
    ])
    error_message = "Each Proxmox K3s node needs integer VM, CPU, memory, and disk values within the supported minimums."
  }

  validation {
    condition = length(distinct([
      for node in values(var.k3s_nodes) : node.vm_id
    ])) == length(var.k3s_nodes)
    error_message = "Proxmox K3s VM IDs must be unique."
  }
}

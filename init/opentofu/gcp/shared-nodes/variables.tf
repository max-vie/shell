variable "project_id" {
  description = "GCP project containing the shared platform nodes."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid GCP project ID."
  }
}

variable "region" {
  description = "GCP region for the shared subnet and private addresses."
  type        = string
  default     = "europe-west4"

  validation {
    condition     = var.region == "europe-west4"
    error_message = "region must be europe-west4 for the current platform contract."
  }
}

variable "deletion_protection" {
  description = "Protect shared VM resources from accidental deletion."
  type        = bool
  default     = true
}

variable "shared_nodes" {
  description = "The two shared platform nodes and their private GCP shape."
  type = map(object({
    zone              = string
    address           = string
    machine_type      = string
    operating_system  = string
    source_image      = string
    boot_disk_size_gb = number
    data_disk_size_gb = number
  }))

  validation {
    condition = length(var.shared_nodes) == 2 && alltrue([
      for name in ["identity-01", "delivery-01"] : contains(keys(var.shared_nodes), name)
    ])
    error_message = "shared_nodes must contain exactly identity-01 and delivery-01."
  }

  validation {
    condition     = try(var.shared_nodes["identity-01"].address, "") == "10.77.0.210" && try(var.shared_nodes["delivery-01"].address, "") == "10.77.0.211"
    error_message = "The shared node contract addresses are 10.77.0.210 and 10.77.0.211."
  }

  validation {
    condition     = try(var.shared_nodes["identity-01"].operating_system, "") == "almalinux-9" && try(var.shared_nodes["delivery-01"].operating_system, "") == "debian-13"
    error_message = "identity-01 must use AlmaLinux 9 and delivery-01 must use Debian 13."
  }

  validation {
    condition = (
      can(regex("^https://www[.]googleapis[.]com/compute/v1/projects/almalinux-cloud/global/images/almalinux-9([-a-z0-9]*[a-z0-9])?$", var.shared_nodes["identity-01"].source_image)) &&
      can(regex("^https://www[.]googleapis[.]com/compute/v1/projects/debian-cloud/global/images/debian-13([-a-z0-9]*[a-z0-9])?$", var.shared_nodes["delivery-01"].source_image))
    )
    error_message = "Shared-node images must be pinned AlmaLinux 9 and Debian 13 images from their official GCP image projects."
  }

  validation {
    condition = alltrue([
      for node in values(var.shared_nodes) : can(regex("^[0-9]{1,3}([.][0-9]{1,3}){3}$", node.address)) && can(cidrhost("${node.address}/32", 0))
    ])
    error_message = "Each shared node address must be a valid IPv4 host address without a CIDR suffix."
  }

  validation {
    condition = alltrue([
      for node in values(var.shared_nodes) : (
        can(regex("^[a-z][a-z0-9-]+[0-9]-[a-z]$", node.zone)) &&
        length(trimspace(node.machine_type)) > 0 &&
        length(trimspace(node.operating_system)) > 0 &&
        can(regex("^https://www[.]googleapis[.]com/compute/v1/projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/global/images/[a-z]([-a-z0-9]*[a-z0-9])?$", node.source_image)) &&
        node.boot_disk_size_gb >= 10 && node.boot_disk_size_gb == floor(node.boot_disk_size_gb) &&
        node.data_disk_size_gb > 0 && node.data_disk_size_gb == floor(node.data_disk_size_gb)
      )
    ])
    error_message = "Each shared node needs a valid zone, machine type, pinned image self-link, and positive integer disk sizes."
  }
}

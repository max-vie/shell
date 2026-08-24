variable "project_id" {
  description = "GCP project containing the shared platform nodes."
  type        = string
}

variable "region" {
  description = "GCP region for the shared subnet and private addresses."
  type        = string
  default     = "europe-west4"
}

variable "network_name" {
  description = "Name of the VPC owned by the shared platform root."
  type        = string
  default     = "shell-shared-vpc"
}

variable "subnet_name" {
  description = "Name of the shared platform subnet."
  type        = string
  default     = "shell-shared"
}

variable "subnet_cidr" {
  description = "Private CIDR containing the shared and direct-GCP nodes."
  type        = string
  default     = "10.77.0.0/24"

  validation {
    condition = can(regex("^[0-9]{1,3}([.][0-9]{1,3}){3}/[0-9]{1,2}$", var.subnet_cidr)) && try(
      cidrhost(var.subnet_cidr, 0) == split("/", var.subnet_cidr)[0],
      false,
    )
    error_message = "subnet_cidr must be a canonical IPv4 network CIDR with a valid prefix."
  }
}

variable "iap_source_ranges" {
  description = "Google IAP source ranges allowed to reach SSH."
  type        = list(string)
  default     = ["35.235.240.0/20"]

  validation {
    condition = alltrue([
      for source_range in var.iap_source_ranges : can(regex("^[0-9]{1,3}([.][0-9]{1,3}){3}/[0-9]{1,2}$", source_range)) && can(cidrhost(source_range, 0))
    ])
    error_message = "iap_source_ranges must contain valid IPv4 CIDR ranges."
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
    condition = alltrue([
      for node in values(var.shared_nodes) : can(regex("^[0-9]{1,3}([.][0-9]{1,3}){3}$", node.address)) && can(cidrhost("${node.address}/32", 0))
    ])
    error_message = "Each shared node address must be a valid IPv4 host address without a CIDR suffix."
  }
}

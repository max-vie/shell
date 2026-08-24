variable "project_id" {
  description = "GCP project containing the node."
  type        = string

  validation {
    condition     = length(trimspace(var.project_id)) > 0
    error_message = "project_id must not be empty."
  }
}

variable "region" {
  description = "GCP region for the node's internal address."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]+[0-9]$", var.region))
    error_message = "region must be a valid GCP region name."
  }
}

variable "subnetwork_id" {
  description = "Self-link or ID of the existing private subnet."
  type        = string

  validation {
    condition     = length(trimspace(var.subnetwork_id)) > 0
    error_message = "subnetwork_id must not be empty."
  }
}

variable "node_name" {
  description = "GCP instance and disk name."
  type        = string

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]*[a-z0-9])?$", var.node_name))
    error_message = "node_name must be a valid GCP resource name."
  }
}

variable "zone" {
  description = "GCP zone for the node and its data disk."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]+[0-9]-[a-z]$", var.zone))
    error_message = "zone must be a valid GCP zone name."
  }
}

variable "internal_address" {
  description = "Reserved private IPv4 address for the node."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{1,3}([.][0-9]{1,3}){3}$", var.internal_address)) && can(cidrhost("${var.internal_address}/32", 0))
    error_message = "internal_address must be a valid IPv4 host address without a CIDR suffix."
  }
}

variable "machine_type" {
  description = "GCP machine type for the node."
  type        = string

  validation {
    condition     = length(trimspace(var.machine_type)) > 0
    error_message = "machine_type must not be empty."
  }
}

variable "source_image" {
  description = "Pinned boot image self-link."
  type        = string

  validation {
    condition = can(regex(
      "^https://www[.]googleapis[.]com/compute/v1/projects/.+/global/images/.+$",
      var.source_image,
    ))
    error_message = "source_image must be a full pinned GCP image self-link."
  }
}

variable "boot_disk_size_gb" {
  description = "Boot disk size in GiB."
  type        = number

  validation {
    condition     = var.boot_disk_size_gb >= 10 && var.boot_disk_size_gb == floor(var.boot_disk_size_gb)
    error_message = "boot_disk_size_gb must be an integer of at least 10 GiB."
  }
}

variable "data_disk_size_gb" {
  description = "Persistent data disk size in GiB."
  type        = number

  validation {
    condition     = var.data_disk_size_gb > 0 && var.data_disk_size_gb == floor(var.data_disk_size_gb)
    error_message = "data_disk_size_gb must be a positive integer."
  }
}

variable "tags" {
  description = "Network tags applied to the node."
  type        = list(string)

  validation {
    condition     = length(var.tags) > 0 && alltrue([for tag in var.tags : length(trimspace(tag)) > 0])
    error_message = "tags must contain at least one non-empty network tag."
  }
}

variable "can_ip_forward" {
  description = "Allow the node to forward packets for its cluster network."
  type        = bool
  default     = false
}

variable "deletion_protection" {
  description = "Protect the node from accidental deletion."
  type        = bool
  default     = true
}

variable "data_device_name" {
  description = "Optional device name for the attached data disk."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      var.data_device_name == null ||
      can(regex("^[a-z]([-a-z0-9]*[a-z0-9])?$", var.data_device_name))
    )
    error_message = "data_device_name must be null or a valid GCP device name."
  }
}

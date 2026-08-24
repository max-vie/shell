variable "project_id" {
  description = "GCP project containing the nested Proxmox host."
  type        = string

  validation {
    condition     = length(trimspace(var.project_id)) > 0
    error_message = "project_id must not be empty."
  }
}

variable "region" {
  description = "GCP region for the provider and shared subnet."
  type        = string
  default     = "europe-west4"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]+[0-9]$", var.region))
    error_message = "region must be a valid GCP region name."
  }
}

variable "zone" {
  description = "GCP zone for the nested Proxmox host."
  type        = string
  default     = "europe-west4-a"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]+[0-9]-[a-z]$", var.zone))
    error_message = "zone must be a valid GCP zone name."
  }
}

variable "name" {
  description = "Name of the outer GCP VM running Proxmox."
  type        = string
  default     = "proxmox-host"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]*[a-z0-9])?$", var.name))
    error_message = "name must be a valid GCP resource name."
  }
}

variable "internal_address" {
  description = "Stable private address for the nested Proxmox host."
  type        = string
  default     = "10.77.0.220"

  validation {
    condition     = var.internal_address == "10.77.0.220"
    error_message = "internal_address must be 10.77.0.220 for the platform contract."
  }
}

variable "machine_type" {
  description = "Machine type for the nested Proxmox host."
  type        = string
  default     = "n2-standard-8"

  validation {
    condition     = can(regex("^n2-", var.machine_type))
    error_message = "machine_type must use the N2 family for nested virtualization."
  }
}

variable "source_image" {
  description = "Pinned Debian boot image self-link for the outer host."
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
  default     = 32

  validation {
    condition     = var.boot_disk_size_gb >= 10 && var.boot_disk_size_gb == floor(var.boot_disk_size_gb)
    error_message = "boot_disk_size_gb must be an integer of at least 10 GiB."
  }
}

variable "data_disk_size_gb" {
  description = "Persistent Proxmox data disk size in GiB."
  type        = number
  default     = 200

  validation {
    condition     = var.data_disk_size_gb > 0 && var.data_disk_size_gb == floor(var.data_disk_size_gb)
    error_message = "data_disk_size_gb must be a positive integer."
  }
}

variable "data_disk_type" {
  description = "GCP disk type for Proxmox guest storage."
  type        = string
  default     = "pd-balanced"

  validation {
    condition     = contains(["pd-balanced", "pd-ssd"], var.data_disk_type)
    error_message = "data_disk_type must be pd-balanced or pd-ssd."
  }
}

variable "iap_source_ranges" {
  description = "Google IAP source ranges allowed to reach host SSH."
  type        = list(string)
  default     = ["35.235.240.0/20"]

  validation {
    condition     = try(length(var.iap_source_ranges) == 1 && var.iap_source_ranges[0] == "35.235.240.0/20", false)
    error_message = "iap_source_ranges must contain only the Google IAP TCP range."
  }
}

variable "deletion_protection" {
  description = "Protect the nested Proxmox host from accidental deletion."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Network tags applied to the nested Proxmox host."
  type        = list(string)
  default     = ["shell-proxmox-host"]

  validation {
    condition     = length(var.tags) > 0 && alltrue([for tag in var.tags : length(trimspace(tag)) > 0])
    error_message = "tags must contain at least one non-empty network tag."
  }
}

variable "labels" {
  description = "Labels applied to the nested Proxmox host and data disk."
  type        = map(string)
  default = {
    environment = "shell"
    role        = "proxmox-host"
  }
}

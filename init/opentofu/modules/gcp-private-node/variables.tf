variable "project_id" {
  description = "GCP project containing the node."
  type        = string
}

variable "region" {
  description = "GCP region for the node's internal address."
  type        = string
}

variable "subnetwork_id" {
  description = "Self-link or ID of the existing private subnet."
  type        = string
}

variable "node_name" {
  description = "GCP instance and disk name."
  type        = string
}

variable "zone" {
  description = "GCP zone for the node and its data disk."
  type        = string
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
}

variable "source_image" {
  description = "Pinned boot image self-link."
  type        = string
}

variable "boot_disk_size_gb" {
  description = "Boot disk size in GiB."
  type        = number
}

variable "data_disk_size_gb" {
  description = "Persistent data disk size in GiB."
  type        = number
}

variable "tags" {
  description = "Network tags applied to the node."
  type        = list(string)
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
}

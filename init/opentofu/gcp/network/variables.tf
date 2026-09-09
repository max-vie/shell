variable "project_id" {
  description = "GCP project containing the shared platform network."
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

variable "network_name" {
  description = "Name of the VPC owned by the network root."
  type        = string
  default     = "shell-shared-vpc"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]*[a-z0-9])?$", var.network_name))
    error_message = "network_name must be a valid GCP resource name."
  }
}

variable "subnet_name" {
  description = "Name of the shared platform subnet."
  type        = string
  default     = "shell-shared"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]*[a-z0-9])?$", var.subnet_name))
    error_message = "subnet_name must be a valid GCP resource name."
  }
}

variable "subnet_cidr" {
  description = "Private CIDR containing the shared and direct-GCP nodes."
  type        = string
  default     = "10.77.0.0/24"

  validation {
    condition     = var.subnet_cidr == "10.77.0.0/24"
    error_message = "subnet_cidr must be 10.77.0.0/24 for the platform contract."
  }
}

variable "iap_source_ranges" {
  description = "Google IAP source ranges allowed to reach SSH."
  type        = list(string)
  default     = ["35.235.240.0/20"]

  validation {
    condition     = try(length(var.iap_source_ranges) == 1 && var.iap_source_ranges[0] == "35.235.240.0/20", false)
    error_message = "iap_source_ranges must contain only the Google IAP TCP range."
  }
}

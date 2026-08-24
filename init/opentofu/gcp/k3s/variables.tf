variable "project_id" {
  description = "GCP project containing the direct GCP K3s cluster."
  type        = string
}

variable "iap_source_ranges" {
  description = "Google IAP source ranges allowed to reach cluster SSH."
  type        = list(string)
  default     = ["35.235.240.0/20"]

  validation {
    condition = alltrue([
      for source_range in var.iap_source_ranges : can(regex("^[0-9]{1,3}([.][0-9]{1,3}){3}/[0-9]{1,2}$", source_range)) && can(cidrhost(source_range, 0))
    ])
    error_message = "iap_source_ranges must contain valid IPv4 CIDR ranges."
  }
}

variable "health_check_source_ranges" {
  description = "Google Cloud health-check source ranges allowed to reach port 6443."
  type        = list(string)
  default     = ["35.191.0.0/16"]

  validation {
    condition = alltrue([
      for source_range in var.health_check_source_ranges : can(regex("^[0-9]{1,3}([.][0-9]{1,3}){3}/[0-9]{1,2}$", source_range)) && can(cidrhost(source_range, 0))
    ])
    error_message = "health_check_source_ranges must contain valid IPv4 CIDR ranges."
  }
}

variable "api_name" {
  description = "Name of the internal GCP K3s API endpoint."
  type        = string
  default     = "shell-gcp-k3s-api"
}

variable "api_address" {
  description = "Optional reserved address for the internal K3s API endpoint."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.api_address == null || (can(regex("^[0-9]{1,3}([.][0-9]{1,3}){3}$", var.api_address)) && can(cidrhost("${var.api_address}/32", 0)))
    error_message = "api_address must be null or a valid IPv4 host address without a CIDR suffix."
  }
}

variable "deletion_protection" {
  description = "Protect direct-GCP K3s VM resources from accidental deletion."
  type        = bool
  default     = true
}

variable "k3s_nodes" {
  description = "The three direct-GCP K3s server nodes."
  type = map(object({
    zone              = string
    address           = string
    machine_type      = string
    source_image      = string
    boot_disk_size_gb = number
    data_disk_size_gb = number
  }))

  validation {
    condition = length(var.k3s_nodes) == 3 && alltrue([
      for name in ["gcp-k3s-01", "gcp-k3s-02", "gcp-k3s-03"] : contains(keys(var.k3s_nodes), name)
    ])
    error_message = "k3s_nodes must contain exactly gcp-k3s-01, gcp-k3s-02, and gcp-k3s-03."
  }

  validation {
    condition = alltrue([
      for node in values(var.k3s_nodes) : can(regex("^[0-9]{1,3}([.][0-9]{1,3}){3}$", node.address)) && can(cidrhost("${node.address}/32", 0))
    ])
    error_message = "Each K3s node address must be a valid IPv4 host address without a CIDR suffix."
  }
}

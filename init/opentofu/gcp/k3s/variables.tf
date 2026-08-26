variable "project_id" {
  description = "GCP project containing the direct GCP K3s cluster."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid GCP project ID."
  }
}

variable "iap_source_ranges" {
  description = "Google IAP source ranges allowed to reach cluster SSH."
  type        = list(string)
  default     = ["35.235.240.0/20"]

  validation {
    condition     = try(length(var.iap_source_ranges) == 1 && var.iap_source_ranges[0] == "35.235.240.0/20", false)
    error_message = "iap_source_ranges must contain only the Google IAP TCP range."
  }
}

variable "health_check_source_ranges" {
  description = "Google Cloud health-check source ranges allowed to reach port 6443."
  type        = list(string)
  default     = ["35.191.0.0/16"]

  validation {
    condition     = try(length(var.health_check_source_ranges) == 1 && var.health_check_source_ranges[0] == "35.191.0.0/16", false)
    error_message = "health_check_source_ranges must contain the internal passthrough load-balancer probe range."
  }
}

variable "api_name" {
  description = "Name of the internal GCP K3s API endpoint."
  type        = string
  default     = "shell-gcp-k3s-api"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]*[a-z0-9])?$", var.api_name))
    error_message = "api_name must be a valid GCP resource name."
  }
}

variable "api_address" {
  description = "Optional reserved address for the internal K3s API endpoint."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.api_address == null || try(
      regex("^10[.]77[.]0[.][0-9]{1,3}$", var.api_address) != "" &&
      cidrhost("${var.api_address}/24", 0) == "10.77.0.0" &&
      cidrhost("${var.api_address}/24", 0) != var.api_address &&
      cidrhost("${var.api_address}/24", -1) != var.api_address &&
      !contains([
        "10.77.0.201",
        "10.77.0.202",
        "10.77.0.203",
        "10.77.0.210",
        "10.77.0.211",
        "10.77.0.220",
      ], var.api_address),
      false,
    )
    error_message = "api_address must be null or an unused host in 10.77.0.0/24."
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
    operating_system  = string
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
      try(var.k3s_nodes["gcp-k3s-01"].address, "") == "10.77.0.201",
      try(var.k3s_nodes["gcp-k3s-02"].address, "") == "10.77.0.202",
      try(var.k3s_nodes["gcp-k3s-03"].address, "") == "10.77.0.203",
    ])
    error_message = "GCP K3s addresses must match the 10.77.0.201-203 contract."
  }

  validation {
    condition = alltrue([
      for node in values(var.k3s_nodes) : (
        can(regex("^[a-z][a-z0-9-]+[0-9]-[a-z]$", node.zone)) &&
        length(trimspace(node.machine_type)) > 0 &&
        node.operating_system == "debian-13" &&
        can(regex("^https://www[.]googleapis[.]com/compute/v1/projects/debian-cloud/global/images/debian-13([-a-z0-9]*[a-z0-9])?$", node.source_image)) &&
        node.boot_disk_size_gb >= 10 && node.boot_disk_size_gb == floor(node.boot_disk_size_gb) &&
        node.data_disk_size_gb > 0 && node.data_disk_size_gb == floor(node.data_disk_size_gb)
      )
    ])
    error_message = "Each GCP K3s node needs Debian 13 from the official GCP image project, a valid zone and machine type, and positive integer disk sizes."
  }
}

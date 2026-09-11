variable "project_id" {
  description = "GCP project created and owned by the bootstrap root."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid GCP project ID."
  }
}

variable "region" {
  description = "GCP region for the platform contract."
  type        = string
  default     = "europe-west4"

  validation {
    condition     = var.region == "europe-west4"
    error_message = "region must be europe-west4 for the current platform contract."
  }
}

variable "billing_account" {
  description = "Billing account linked to the bootstrap project."
  type        = string

  validation {
    condition     = can(regex("^[0-9A-Z]{6}-[0-9A-Z]{6}-[0-9A-Z]{6}$", var.billing_account))
    error_message = "billing_account must be a GCP billing account ID."
  }
}

variable "operator_email" {
  description = "Human operator granted impersonation on the deployment service account."
  type        = string

  validation {
    condition     = can(regex("^[^@]+@[^@]+$", var.operator_email))
    error_message = "operator_email must be a valid email address."
  }
}

variable "budget_amount_units" {
  description = "Whole units of the project budget amount in the billing currency."
  type        = number

  validation {
    condition     = var.budget_amount_units > 0
    error_message = "budget_amount_units must be positive."
  }
}

variable "budget_currency" {
  description = "ISO 4217 currency code of the billing account."
  type        = string
  default     = "EUR"

  validation {
    condition     = can(regex("^[A-Z]{3}$", var.budget_currency))
    error_message = "budget_currency must be a three-letter ISO 4217 code."
  }
}

variable "budget_thresholds" {
  description = "Budget alert thresholds as fractions of the budget amount."
  type        = list(number)
  default     = [0.5, 0.9, 1.0]

  validation {
    condition     = length(var.budget_thresholds) == 3 && alltrue([for value in var.budget_thresholds : value > 0 && value <= 1.0])
    error_message = "budget_thresholds must be exactly 0.5, 0.9, and 1.0."
  }
}

variable "deployment_service_account" {
  description = "Logical name of the deployment service account."
  type        = string
  default     = "shell-local-deployer"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]*[a-z0-9])?$", var.deployment_service_account))
    error_message = "deployment_service_account must be a valid GCP service account ID."
  }
}

variable "custom_role_id" {
  description = "ID of the custom role bound to the deployment service account."
  type        = string
  default     = "shell_local_deployer"

  validation {
    condition     = can(regex("^[a-z]([_a-z0-9]*[a-z0-9])?$", var.custom_role_id))
    error_message = "custom_role_id must be a valid GCP custom role ID."
  }
}

variable "required_apis" {
  description = "APIs enabled by the bootstrap root."
  type        = list(string)
  default = [
    "compute.googleapis.com",
    "iamcredentials.googleapis.com",
    "iap.googleapis.com",
    "oslogin.googleapis.com",
    "storage.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "serviceusage.googleapis.com",
    "cloudbilling.googleapis.com",
    "billingbudgets.googleapis.com",
  ]

  validation {
    condition     = alltrue([for api in var.required_apis : can(regex("^[a-z0-9-]+\\.googleapis\\.com$", api))])
    error_message = "required_apis must be valid Google API names."
  }
}

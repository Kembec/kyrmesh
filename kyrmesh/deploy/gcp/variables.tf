variable "project_id" {
  type        = string
  description = "Existing GCP project, with billing enabled, that hosts the server."
}

variable "region" {
  type        = string
  description = "Free-tier region for the e2-micro."
  default     = "us-east1"

  validation {
    condition     = contains(["us-east1", "us-central1", "us-west1"], var.region)
    error_message = "The e2-micro is free only in us-east1, us-central1 or us-west1."
  }
}

variable "zone" {
  type        = string
  description = "Compute zone inside the region."
  default     = "us-east1-b"

  validation {
    condition     = can(regex("^us-(east1|central1|west1)-[a-z]$", var.zone))
    error_message = "The zone must be in a free-tier region (us-east1, us-central1, us-west1)."
  }
}

variable "server_host" {
  type        = string
  description = "Name the devices use to reach the server, e.g. ctrl.net.example.com. Its A record is managed by the VM."

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", var.server_host))
    error_message = "server_host must be a lowercase DNS name."
  }
}

variable "cloudflare_zone" {
  type        = string
  description = "Cloudflare zone that holds server_host, e.g. example.com."

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", var.cloudflare_zone))
    error_message = "cloudflare_zone must be a lowercase DNS name."
  }
}

variable "cloudflare_token" {
  type        = string
  description = "Cloudflare API token limited to editing the zone's DNS. Write-only: never stored in state or plans. Needed to create or rotate the secret; null otherwise."
  sensitive   = true
  ephemeral   = true
  nullable    = true
  default     = null
}

variable "cloudflare_token_version" {
  type        = string
  description = "Change (e.g. \"1\" to \"2\") to store a new cloudflare_token (rotation)."
  default     = "1"
}

variable "first_user" {
  type        = string
  description = "First user of the network; the default policy lets its devices reach each other."
  default     = "admin"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,30}$", var.first_user))
    error_message = "first_user must be a short lowercase name."
  }
}

variable "acme_url" {
  type        = string
  description = "ACME directory. Let's Encrypt staging (acme-staging-v02) is useful for a first trial."
  default     = "https://acme-v02.api.letsencrypt.org/directory"

  validation {
    condition     = startswith(var.acme_url, "https://")
    error_message = "acme_url must be https."
  }
}

variable "instance_id" {
  type        = string
  description = "Two-digit suffix of every resource name, to run more than one server in a project."
  default     = "01"

  validation {
    condition     = can(regex("^[0-9]{2}$", var.instance_id))
    error_message = "instance_id must be two digits."
  }
}

variable "deletion_protection" {
  type        = bool
  description = "Refuse to delete the VM. Set false and apply before a terraform destroy."
  default     = true
}

terraform {
  # 1.11: write-only arguments, so the Cloudflare token never reaches the state or a plan file.
  required_version = ">= 1.11"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.12"
    }
  }
  # Local state by default: up.sh keeps it next to this file. A team can add a gcs backend.
}

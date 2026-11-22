provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

locals {
  # Names follow {env}-{project}-{type}-{purpose}-{id}.
  name = "prod-kyrmesh-%s-core-${var.instance_id}"
  # The release the VM installs, pinned with its SHA-256 per architecture in ../RELEASE.
  release = {
    for line in compact(split("\n", file("${path.module}/../RELEASE"))) :
    trimspace(split("=", line)[0]) => trimspace(split("=", line)[1])
    if !startswith(trimspace(line), "#") && strcontains(line, "=")
  }
}

# Compute for the VM, Secret Manager for the token, IAP and OS Login for SSH without a public port.
resource "google_project_service" "apis" {
  for_each           = toset(["compute.googleapis.com", "secretmanager.googleapis.com", "iap.googleapis.com", "oslogin.googleapis.com"])
  service            = each.value
  disable_on_destroy = false
}

# Own network: a new project may not have the default one.
resource "google_compute_network" "core" {
  name                    = format(local.name, "vpc")
  auto_create_subnetworks = false
  depends_on              = [google_project_service.apis]
}

resource "google_compute_subnetwork" "core" {
  name                     = format(local.name, "snet")
  network                  = google_compute_network.core.id
  region                   = var.region
  ip_cidr_range            = "10.10.0.0/24"
  private_ip_google_access = true
}

# Control and DERP over TLS on 443, STUN on 3478. Nothing else is public.
resource "google_compute_firewall" "ingress" {
  name          = format(local.name, "fw")
  network       = google_compute_network.core.id
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["kyrmesh"]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  allow {
    protocol = "udp"
    ports    = ["3478"]
  }
}

# Administration only through IAP: SSH is never open to the internet.
resource "google_compute_firewall" "iap_ssh" {
  name          = format(local.name, "fw-iap")
  network       = google_compute_network.core.id
  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["kyrmesh"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

# The VM runs as an account whose only grant is reading its own token: the default compute
# account is Editor.
resource "google_service_account" "core" {
  account_id   = format(local.name, "sa")
  display_name = "Kyrmesh core VM (reads its token only)"
  depends_on   = [google_project_service.apis]
}

resource "google_secret_manager_secret" "cloudflare" {
  secret_id = format(local.name, "sm-cloudflare")

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]
}

# Write-only: the token goes to Secret Manager and never to the Terraform state or a plan.
resource "google_secret_manager_secret_version" "cloudflare" {
  secret                 = google_secret_manager_secret.cloudflare.id
  secret_data_wo         = var.cloudflare_token
  secret_data_wo_version = var.cloudflare_token_version
}

resource "google_secret_manager_secret_iam_member" "core" {
  secret_id = google_secret_manager_secret.cloudflare.id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.core.member
}

# Free tier: one e2-micro in us-east1/us-central1/us-west1 with a 30 GB pd-standard disk.
resource "google_compute_instance" "core" {
  name                      = format(local.name, "vm")
  machine_type              = "e2-micro"
  zone                      = var.zone
  tags                      = ["kyrmesh"]
  allow_stopping_for_update = true
  deletion_protection       = var.deletion_protection

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 30
      type  = "pd-standard"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.core.id
    # Ephemeral address: the VM points its A record at whatever address it boots with, so a
    # stop/start never leaves the server unreachable. PREMIUM keeps the free-tier egress.
    access_config {
      network_tier = "PREMIUM"
    }
  }

  # Everything the VM installs is here, so the plan shows exactly what will run.
  metadata = {
    enable-oslogin       = "TRUE"
    startup-script       = file("${path.module}/startup.sh")
    kyrmesh-install      = file("${path.module}/../install.sh")
    kyrmesh-host         = var.server_host
    kyrmesh-zone         = var.cloudflare_zone
    kyrmesh-user         = var.first_user
    kyrmesh-acme-url     = var.acme_url
    kyrmesh-version      = local.release["version"]
    kyrmesh-sha256-amd64 = local.release["sha256_amd64"]
    kyrmesh-sha256-arm64 = lookup(local.release, "sha256_arm64", "")
    kyrmesh-secret       = google_secret_manager_secret.cloudflare.id
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  # cloud-platform is the only scope Secret Manager accepts; the account's IAM limits it to one secret.
  service_account {
    email  = google_service_account.core.email
    scopes = ["cloud-platform"]
  }

  lifecycle {
    precondition {
      condition     = lookup(local.release, "version", "") != "" && can(regex("^[0-9a-f]{64}$", lookup(local.release, "sha256_amd64", "")))
      error_message = "../RELEASE has no pinned version and sha256_amd64: the VM would refuse to install."
    }
  }

  # The token and its grant exist before the first boot reads them.
  depends_on = [google_secret_manager_secret_version.cloudflare, google_secret_manager_secret_iam_member.core]
}

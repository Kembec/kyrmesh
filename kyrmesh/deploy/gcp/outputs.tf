output "server_url" {
  value = "https://${var.server_host}"
}

output "instance" {
  value = google_compute_instance.core.name
}

output "zone" {
  value = google_compute_instance.core.zone
}

output "external_ip" {
  value = google_compute_instance.core.network_interface[0].access_config[0].nat_ip
}

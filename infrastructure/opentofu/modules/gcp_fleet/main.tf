data "google_project" "current" {}

resource "google_compute_network" "fleet" {
  name                    = "${var.project}-${var.environment}"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

resource "google_compute_subnetwork" "private" {
  name                     = "${var.project}-${var.environment}-${var.region}"
  region                   = var.region
  network                  = google_compute_network.fleet.id
  ip_cidr_range            = var.network_cidr
  private_ip_google_access = true
  stack_type               = "IPV4_ONLY"
}

resource "google_compute_router" "fleet" {
  name    = "${var.project}-${var.environment}"
  region  = var.region
  network = google_compute_network.fleet.id
}

resource "google_compute_router_nat" "fleet" {
  name                                = "${var.project}-${var.environment}"
  router                              = google_compute_router.fleet.name
  region                              = var.region
  nat_ip_allocate_option              = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat  = "LIST_OF_SUBNETWORKS"
  min_ports_per_vm                    = 2048
  enable_endpoint_independent_mapping = false

  subnetwork {
    name                    = google_compute_subnetwork.private.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

}

resource "google_service_account" "node" {
  for_each     = var.nodes
  account_id   = substr("or-${replace(each.key, "_", "-")}", 0, 30)
  display_name = "OnionRoute ${each.value.role} identity (${each.key})"
  description  = "Identity-only service account for Vault GCP auth"
}

resource "google_kms_key_ring" "node_disks" {
  name     = "${var.project}-${var.environment}-node-disks"
  location = var.region
}

resource "google_kms_crypto_key" "node_disk" {
  for_each        = var.nodes
  name            = "${each.key}-disk"
  key_ring        = google_kms_key_ring.node_disks.id
  rotation_period = "7776000s"
  lifecycle { prevent_destroy = true }
}

resource "google_kms_crypto_key_iam_member" "compute_agent" {
  for_each      = var.nodes
  crypto_key_id = google_kms_crypto_key.node_disk[each.key].id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.current.number}@compute-system.iam.gserviceaccount.com"
}

resource "google_compute_firewall" "allow_tcp_out" {
  name                    = "${var.project}-${var.environment}-allow-tcp-out"
  network                 = google_compute_network.fleet.name
  direction               = "EGRESS"
  priority                = 900
  destination_ranges      = ["0.0.0.0/0"]
  target_service_accounts = [for account in google_service_account.node : account.email]
  allow { protocol = "tcp" }
}

resource "google_compute_firewall" "allow_dns_ntp_out" {
  name                    = "${var.project}-${var.environment}-allow-dns-ntp-out"
  network                 = google_compute_network.fleet.name
  direction               = "EGRESS"
  priority                = 900
  destination_ranges      = ["0.0.0.0/0"]
  target_service_accounts = [for account in google_service_account.node : account.email]
  allow {
    protocol = "udp"
    ports    = ["53", "123"]
  }
}

resource "google_compute_firewall" "deny_other_out" {
  name                    = "${var.project}-${var.environment}-deny-other-out"
  network                 = google_compute_network.fleet.name
  direction               = "EGRESS"
  priority                = 65000
  destination_ranges      = ["0.0.0.0/0"]
  target_service_accounts = [for account in google_service_account.node : account.email]
  deny { protocol = "all" }
}

resource "google_compute_instance" "node" {
  for_each = var.nodes

  name                = "${each.key}-${substr(each.value.release_digest, 7, 8)}"
  machine_type        = each.value.machine_type
  zone                = each.value.zone
  can_ip_forward      = false
  deletion_protection = false
  tags                = ["onionroute", each.value.role]

  boot_disk {
    auto_delete = true
    initialize_params {
      image = each.value.image_id
      size  = 16
      type  = "pd-balanced"
    }
    kms_key_self_link = google_kms_crypto_key.node_disk[each.key].id
  }

  network_interface {
    subnetwork = google_compute_subnetwork.private.id
    # No access_config: the instance never receives a public address.
  }

  service_account {
    email  = google_service_account.node[each.key].email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    block-project-ssh-keys     = "true"
    enable-oslogin             = "false"
    onionroute-node-id         = each.key
    onionroute-role            = each.value.role
    onionroute-vault-addr      = var.vault_addr
    onionroute-vault-auth-role = each.value.vault_auth_role
    onionroute-secret-scope    = each.value.secret_scope
    onionroute-release-digest  = each.value.release_digest
    onionroute-release-pubkey  = var.release_signing_public_key
  }

  labels = {
    role         = each.value.role
    admin_domain = substr(replace(lower(each.value.admin_domain), "_", "-"), 0, 63)
    data_class   = "no-user-data"
  }

  lifecycle {
    create_before_destroy = true
    precondition {
      condition     = can(regex("^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/global/images/[a-z][a-z0-9-]{0,62}$", each.value.image_id))
      error_message = "GCP image_id must be a pinned fully-qualified image resource."
    }
    precondition {
      condition     = startswith(each.value.zone, "${var.region}-")
      error_message = "GCP node zone must belong to the configured fleet region."
    }
  }

  depends_on = [google_kms_crypto_key_iam_member.compute_agent]
}

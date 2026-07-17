packer {
  required_version = "= 1.11.2"
  required_plugins {
    amazon = {
      source  = "github.com/hashicorp/amazon"
      version = "= 1.3.9"
    }
    googlecompute = {
      source  = "github.com/hashicorp/googlecompute"
      version = "= 1.2.1"
    }
    ansible = {
      source  = "github.com/hashicorp/ansible"
      version = "= 1.1.3"
    }
  }
}

variable "node_role" { type = string }
variable "release_version" { type = string }
variable "release_digest" { type = string }
variable "release_bundle" { type = string }
variable "release_bundle_signature" { type = string }
variable "release_public_key" { type = string }
variable "admin_ssh_ca_public_key" { type = string }
variable "debian_snapshot" { type = string }
variable "vault_version" { type = string }
variable "vault_sha256" { type = string }
variable "cosign_version" { type = string }
variable "cosign_sha256" { type = string }
variable "dependency_v4" { type = list(string) }
variable "next_hop_v4" { type = list(string) }
variable "management_v4" { type = list(string) }
variable "dns_v4" { type = list(string) }
variable "ntp_v4" { type = list(string) }
variable "next_hop_port" { type = number }
variable "skip_ansible_version_check" {
  type        = bool
  default     = false
  description = "Validation-only escape hatch; production builds must keep the Ansible preflight enabled."
}

variable "aws_region" { type = string }
variable "aws_source_ami" { type = string }
variable "aws_subnet_id" { type = string }
variable "aws_builder_instance_profile" { type = string }
variable "aws_builder_security_group_id" { type = string }
variable "aws_builder_kms_key_id" { type = string }
variable "aws_instance_type" {
  type    = string
  default = "t3.medium"
}

variable "gcp_project_id" { type = string }
variable "gcp_zone" { type = string }
variable "gcp_source_image" { type = string }
variable "gcp_subnetwork" { type = string }
variable "gcp_builder_service_account" { type = string }
variable "gcp_machine_type" {
  type    = string
  default = "e2-standard-2"
}

locals {
  image_name = substr("onionroute-${var.node_role}-${replace(replace(var.release_version, ".", "-"), "_", "-")}", 0, 63)
}

source "amazon-ebs" "onionroute" {
  ami_name                    = local.image_name
  region                      = var.aws_region
  source_ami                  = var.aws_source_ami
  instance_type               = var.aws_instance_type
  ssh_username                = "admin"
  ssh_interface               = "session_manager"
  iam_instance_profile        = var.aws_builder_instance_profile
  security_group_id           = var.aws_builder_security_group_id
  subnet_id                   = var.aws_subnet_id
  associate_public_ip_address = false
  encrypt_boot                = true
  kms_key_id                  = var.aws_builder_kms_key_id
  imds_support                = "v2.0"
  deprecate_at                = timeadd(timestamp(), "2160h")

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags = {
    Project       = "onionroute"
    Role          = var.node_role
    ReleaseDigest = var.release_digest
    Immutable     = "true"
  }
}

source "googlecompute" "onionroute" {
  image_name                  = local.image_name
  image_description           = "Immutable OnionRoute ${var.node_role} ${var.release_digest}"
  project_id                  = var.gcp_project_id
  source_image                = var.gcp_source_image
  zone                        = var.gcp_zone
  machine_type                = var.gcp_machine_type
  subnetwork                  = var.gcp_subnetwork
  service_account_email       = var.gcp_builder_service_account
  ssh_username                = "packer"
  use_iap                     = true
  omit_external_ip            = true
  use_internal_ip             = true
  enable_secure_boot          = true
  enable_vtpm                 = true
  enable_integrity_monitoring = true

  image_labels = {
    role           = var.node_role
    immutable      = "true"
    release_digest = substr(var.release_digest, 7, 32)
  }
}

build {
  name = "onionroute-${var.node_role}"
  sources = [
    "source.amazon-ebs.onionroute",
    "source.googlecompute.onionroute"
  ]

  provisioner "file" {
    source      = var.release_bundle
    destination = "/tmp/onionroute-release.tar.gz"
  }

  provisioner "file" {
    source      = var.release_bundle_signature
    destination = "/tmp/onionroute-release.tar.gz.sig"
  }

  provisioner "file" {
    source      = var.release_public_key
    destination = "/tmp/release-signing.pub"
  }

  provisioner "file" {
    source      = var.admin_ssh_ca_public_key
    destination = "/tmp/admin-ssh-ca.pub"
  }

  provisioner "shell" {
    script = "scripts/prepare-image.sh"
    environment_vars = [
      "DEBIAN_SNAPSHOT=${var.debian_snapshot}",
      "VAULT_VERSION=${var.vault_version}",
      "VAULT_SHA256=${var.vault_sha256}",
      "COSIGN_VERSION=${var.cosign_version}",
      "COSIGN_SHA256=${var.cosign_sha256}",
      "RELEASE_VERSION=${var.release_version}",
      "RELEASE_DIGEST=${var.release_digest}"
    ]
  }

  provisioner "ansible" {
    playbook_file      = "../ansible/site.yml"
    skip_version_check = var.skip_ansible_version_check
    extra_arguments = [
      "--become",
      "--extra-vars", "onionroute_node_role=${var.node_role}",
      "--extra-vars", "onionroute_release_version=${var.release_version}",
      "--extra-vars", "onionroute_release_digest=${var.release_digest}",
      "--extra-vars", "onionroute_dependency_v4=${jsonencode(var.dependency_v4)}",
      "--extra-vars", "onionroute_next_hop_v4=${jsonencode(var.next_hop_v4)}",
      "--extra-vars", "onionroute_management_v4=${jsonencode(var.management_v4)}",
      "--extra-vars", "onionroute_dns_v4=${jsonencode(var.dns_v4)}",
      "--extra-vars", "onionroute_ntp_v4=${jsonencode(var.ntp_v4)}",
      "--extra-vars", "onionroute_next_hop_port=${var.next_hop_port}"
    ]
  }

  provisioner "shell" {
    script = "scripts/validate-image.sh"
  }

  post-processor "manifest" {
    output     = "artifacts/packer-manifest.json"
    strip_path = true
    custom_data = {
      node_role      = var.node_role
      release_digest = var.release_digest
    }
  }
}

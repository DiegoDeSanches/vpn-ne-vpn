variable "project" {
  type    = string
  default = "onionroute"
}

variable "environment" {
  type    = string
  default = "production"
  validation {
    condition     = contains(["staging", "production"], var.environment)
    error_message = "environment must be staging or production"
  }
}

variable "aws_region" { type = string }
variable "gcp_region" { type = string }
variable "gcp_project_id" { type = string }

variable "aws_network_cidr" {
  type    = string
  default = "10.81.0.0/16"
}

variable "gcp_network_cidr" {
  type    = string
  default = "10.82.0.0/20"
}

variable "vault_addr" {
  description = "Non-secret HTTPS or authenticated onion endpoint for Vault."
  type        = string
  validation {
    condition     = startswith(var.vault_addr, "https://")
    error_message = "Vault transport must use HTTPS."
  }
}

variable "release_signing_public_key" {
  description = "Public cosign key baked into node metadata; never a private key."
  type        = string
  default     = "/usr/share/onionroute/trust/release-signing.pub"
}

variable "aws_nodes" {
  description = "AWS nodes. Values are inventory metadata and immutable image references only."
  type = map(object({
    role                    = string
    image_id                = string
    instance_type           = string
    zone_index              = number
    subnet_index            = number
    asn                     = number
    admin_domain            = string
    management_trust_domain = string
    vault_auth_role         = string
    secret_scope            = string
    release_digest          = string
  }))
  default = {}

  validation {
    condition = alltrue([
      for node in values(var.aws_nodes) : contains([
        "entry", "exit", "relay", "directory", "token", "health-collector",
        "signing", "monitoring", "management"
      ], node.role)
    ])
    error_message = "Unsupported node role."
  }
  validation {
    condition     = alltrue([for name, node in var.aws_nodes : can(regex("^[a-z][a-z0-9-]{0,39}$", name)) && node.subnet_index >= 10 && node.subnet_index <= 250 && node.zone_index >= 0 && node.zone_index <= 15])
    error_message = "AWS node names and stable subnet_index values are invalid."
  }
  validation {
    condition     = alltrue([for node in values(var.aws_nodes) : can(regex("^sha256:[0-9a-f]{64}$", node.release_digest))])
    error_message = "Every release_digest must be a sha256 OCI digest."
  }
  validation {
    condition     = length(values(var.aws_nodes)) == length(toset([for node in values(var.aws_nodes) : node.subnet_index]))
    error_message = "AWS subnet_index values must be unique and stable."
  }
  validation {
    condition = alltrue([
      for name, node in var.aws_nodes :
      node.secret_scope == "kv/data/nodes/${name}" &&
      node.vault_auth_role == name &&
      can(regex("^[a-z][a-z0-9-]{0,63}$", node.admin_domain)) &&
      can(regex("^[a-z][a-z0-9-]{0,63}$", node.management_trust_domain)) &&
      node.asn > 0 && node.asn <= 4294967295
    ])
    error_message = "AWS trust metadata, ASN, auth role or node-bound secret scope is invalid."
  }
}

variable "gcp_nodes" {
  description = "GCP nodes. Values are inventory metadata and immutable image references only."
  type = map(object({
    role                    = string
    image_id                = string
    machine_type            = string
    zone                    = string
    asn                     = number
    admin_domain            = string
    management_trust_domain = string
    vault_auth_role         = string
    secret_scope            = string
    release_digest          = string
  }))
  default = {}

  validation {
    condition = alltrue([
      for node in values(var.gcp_nodes) : contains([
        "entry", "exit", "relay", "directory", "token", "health-collector",
        "signing", "monitoring", "management"
      ], node.role)
    ])
    error_message = "Unsupported node role."
  }
  validation {
    condition     = alltrue([for node in values(var.gcp_nodes) : can(regex("^sha256:[0-9a-f]{64}$", node.release_digest))])
    error_message = "Every release_digest must be a sha256 OCI digest."
  }
  validation {
    condition     = alltrue([for name in keys(var.gcp_nodes) : can(regex("^[a-z][a-z0-9-]{0,39}$", name))])
    error_message = "GCP node names must be stable lowercase identifiers up to 40 characters."
  }
  validation {
    condition = alltrue([
      for name, node in var.gcp_nodes :
      node.secret_scope == "kv/data/nodes/${name}" &&
      node.vault_auth_role == name &&
      can(regex("^[a-z][a-z0-9-]{0,63}$", node.admin_domain)) &&
      can(regex("^[a-z][a-z0-9-]{0,63}$", node.management_trust_domain)) &&
      node.asn > 0 && node.asn <= 4294967295
    ])
    error_message = "GCP trust metadata, ASN, auth role or node-bound secret scope is invalid."
  }
}

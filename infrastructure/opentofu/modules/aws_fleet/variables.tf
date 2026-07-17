variable "project" { type = string }
variable "environment" { type = string }
variable "region" { type = string }
variable "network_cidr" { type = string }
variable "vault_addr" { type = string }
variable "release_signing_public_key" { type = string }
variable "nodes" {
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
}

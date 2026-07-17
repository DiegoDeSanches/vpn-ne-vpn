locals {
  aws_entry = [for node in values(var.aws_nodes) : node if node.role == "entry"]
  aws_exit  = [for node in values(var.aws_nodes) : node if node.role == "exit"]
  gcp_entry = [for node in values(var.gcp_nodes) : node if node.role == "entry"]
  gcp_exit  = [for node in values(var.gcp_nodes) : node if node.role == "exit"]

  entry_providers = toset(concat(length(local.aws_entry) > 0 ? ["aws"] : [], length(local.gcp_entry) > 0 ? ["gcp"] : []))
  exit_providers  = toset(concat(length(local.aws_exit) > 0 ? ["aws"] : [], length(local.gcp_exit) > 0 ? ["gcp"] : []))
  entry_asns      = toset(concat([for n in local.aws_entry : n.asn], [for n in local.gcp_entry : n.asn]))
  exit_asns       = toset(concat([for n in local.aws_exit : n.asn], [for n in local.gcp_exit : n.asn]))
  entry_admin     = toset(concat([for n in local.aws_entry : n.admin_domain], [for n in local.gcp_entry : n.admin_domain]))
  exit_admin      = toset(concat([for n in local.aws_exit : n.admin_domain], [for n in local.gcp_exit : n.admin_domain]))
  entry_mgmt      = toset(concat([for n in local.aws_entry : n.management_trust_domain], [for n in local.gcp_entry : n.management_trust_domain]))
  exit_mgmt       = toset(concat([for n in local.aws_exit : n.management_trust_domain], [for n in local.gcp_exit : n.management_trust_domain]))
  all_scopes      = concat([for n in values(var.aws_nodes) : n.secret_scope], [for n in values(var.gcp_nodes) : n.secret_scope])
  all_vault_roles = concat([for n in values(var.aws_nodes) : n.vault_auth_role], [for n in values(var.gcp_nodes) : n.vault_auth_role])
}

check "entry_exit_separation" {
  assert {
    condition     = length(local.entry_providers) > 0 && length(local.exit_providers) > 0
    error_message = "At least one entry and one exit are required."
  }
  assert {
    condition     = length(setintersection(local.entry_providers, local.exit_providers)) == 0
    error_message = "Entry and exit roles must not share a cloud provider."
  }
  assert {
    condition     = length(setintersection(local.entry_asns, local.exit_asns)) == 0
    error_message = "Entry and exit roles must not share an ASN."
  }
  assert {
    condition     = length(setintersection(local.entry_admin, local.exit_admin)) == 0
    error_message = "Entry and exit roles must not share an administrative project."
  }
  assert {
    condition     = length(setintersection(local.entry_mgmt, local.exit_mgmt)) == 0
    error_message = "Entry and exit roles must use separate management trust domains."
  }
}

check "secret_scope_separation" {
  assert {
    condition     = length(local.all_scopes) == length(toset(local.all_scopes))
    error_message = "Every node must have an independent Vault secret scope."
  }
  assert {
    condition     = length(local.all_vault_roles) == length(toset(local.all_vault_roles))
    error_message = "Every node must have an independent Vault workload auth role."
  }
}

module "aws_fleet" {
  source = "./modules/aws_fleet"

  project                    = var.project
  environment                = var.environment
  region                     = var.aws_region
  network_cidr               = var.aws_network_cidr
  nodes                      = var.aws_nodes
  vault_addr                 = var.vault_addr
  release_signing_public_key = var.release_signing_public_key
}

module "gcp_fleet" {
  source = "./modules/gcp_fleet"

  project                    = var.project
  environment                = var.environment
  region                     = var.gcp_region
  network_cidr               = var.gcp_network_cidr
  nodes                      = var.gcp_nodes
  vault_addr                 = var.vault_addr
  release_signing_public_key = var.release_signing_public_key
}

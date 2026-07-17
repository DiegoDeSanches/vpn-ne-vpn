output "inventory" {
  description = "Non-secret deployment inventory. No public addresses are assigned."
  value = {
    aws = module.aws_fleet.inventory
    gcp = module.gcp_fleet.inventory
  }
}

output "workload_identities" {
  description = "Identity principals to bind to per-role Vault auth roles."
  value = {
    aws = module.aws_fleet.workload_identities
    gcp = module.gcp_fleet.workload_identities
  }
}


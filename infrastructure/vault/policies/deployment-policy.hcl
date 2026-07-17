# The deployment controller can disable one unique node auth role. Node auth tokens
# are non-renewable and expire within two minutes; this policy cannot mint tokens or
# read/revoke secret values. Provider isolation and directory revocation are separate.
path "auth/aws/role/+" {
  capabilities = ["read", "update", "delete"]
}
path "auth/gcp/role/+" {
  capabilities = ["read", "update", "delete"]
}

# Human login to Vault is owned by the SSO policy and must require hardware MFA.
# This policy can only sign a short-lived user certificate; it cannot read host keys.
path "ssh-client-signer/sign/onionroute-admin" {
  capabilities = ["update"]
  allowed_parameters = {
    "cert_type"        = ["user"]
    "valid_principals" = ["onionroute-admin"]
    "ttl"              = ["15m"]
  }
}


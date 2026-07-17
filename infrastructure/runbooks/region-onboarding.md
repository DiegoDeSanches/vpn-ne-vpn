# Region onboarding runbook

1. Record provider legal entity, cloud account/project, observed ASN, jurisdiction,
   abuse process and failure domain. Entry and exit must differ in provider, ASN,
   project, KMS administration and management IdP group. A second operator verifies
   public BGP ownership; do not trust an inventory string alone.
2. Allocate non-overlapping private CIDRs, dedicated state prefix/lock, builder
   subnet, NAT egress and per-role quotas. Nodes receive no public address/ingress.
3. Create separate image-builder identity and disk KMS key. Pin Debian base image ID,
   snapshot timestamp, Vault/cosign versions and checksums.
4. Create exact Vault node scopes and paired app/onion auth roles from OpenTofu
   workload identity outputs. Add data and management onion keys independently.
5. Build each required role image. Verify SBOM/provenance/signatures and run
   systemd/AppArmor/nft tests. Populate dependency/next-hop nft sets through reviewed
   region variables; no host is edited after creation.
6. Add the region as a capacity-zero canary. Test Tor bootstrap, management client
   auth, DNS/IPv6/UDP/metadata/private-range leaks, clock, draining and emergency
   revoke. Confirm monitoring targets contain only node ID/role/region/onion endpoint.
7. Publish the signed directory entry at low weight. Increase capacity only after a
   full observation window and cross-provider path test.

Do not onboard a region when provider/ASN separation is ambiguous, Vault cannot use
workload identity, or emergency revocation exceeds five minutes.


# Rollback runbook

The previous signed image/tfvars stay retained until the full observation window and
one directory TTL have elapsed. Database contract migrations are not rolled back;
expand-only schema remains compatible with the old binary.

Automatic rollback revokes changed nodes from the directory, applies
`rollback_tfvars`, waits for protected health, then republishes the previous nodes.
Run the same path manually only after automatic rollback reports success or failure:

```text
python3 infrastructure/deploy/onionroute_deploy.py \
  --config /secure/change/exit-2026-07-17.json rollback
```

Never relax nftables, enable clearnet fallback, reuse the failed node secret scope,
or restore a directory with a lower sequence. If both deploy and rollback fail:

1. Keep affected nodes revoked and cloud-isolated.
2. Preserve capacity on untouched providers/regions; do not re-enable unhealthy
   gateways to meet capacity.
3. Verify the previous image signature and instantiate a fresh node identity/scope.
4. Publish only after onion and TLS identities match the reviewed directory change.
5. Record the tested recovery time and create an incident review.

Quarterly rollback tests deploy a non-production canary, inject readiness failure,
assert automatic restoration and compare directory sequence monotonicity. Test
evidence is retained as administrative audit, not application telemetry.


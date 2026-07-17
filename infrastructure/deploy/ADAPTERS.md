# Deployment adapter contract v1

The controller never edits the protected directory or token formats. It invokes
small, separately reviewed argv-based adapters; no command is passed through a
shell. All endpoints are provider APIs or authenticated onion services, so neither
deployment nor rollback requires public SSH.

- `directory-adapter v1 drain|activate|revoke NODE` updates inventory and publishes
  a newly signed directory with monotonic sequence/expiry. `drain` rejects new
  sessions; `revoke` removes the node immediately.
- `health-adapter v1 health NODE` returns exactly the eight fields accepted by
  `Health.parse`. It must query the authenticated management onion endpoint and
  must not return addresses, destinations, session IDs or free-form labels.
  Stream error rate and five-minute egress failures are both bounded deployment
  gates; a controller configuration must never silently omit either threshold.
- `lifecycle-adapter v1 drain|restart NODE` invokes the node's authenticated
  management path. `drain` reloads `onionroute-role.service`, whose `ExecReload`
  sends `SIGUSR1`; `restart` clears the irreversible in-process drain state during
  rollback, including when an image plan made no change. Both actions are idempotent
  and must never use public SSH. Directory drain is published first so both catalog
  and local admission close before bucket-zero waiting.
- `cloud-isolate v1 isolate NODE` stops the instance and denies its workload
  identity using provider APIs. It must be idempotent.
- `vault-revoke v1 CLOUD revoke NODE` deletes the exact `NODE` and `NODE-onion`
  workload auth roles. Existing batch tokens have a hard two-minute max TTL. The
  adapter must not mint tokens or read secret values.
- A control-plane migration adapter takes no arguments and returns only
  `{"safe":true,"expand_only":true,"schema_version":N}`. Contracting/destructive
  migrations are a later release after every old binary is gone.

Adapters must bound request/response sizes, use short-lived operator identity, and
emit only administrative audit events. Their production implementations are owned
by the directory, Vault and provider integrations; unavailable adapters fail the
deployment before traffic is changed.

All relative filesystem paths in a deployment JSON are resolved against that JSON's
directory, never against the operator's current working directory.

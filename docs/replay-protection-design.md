# Capability-token replay protection

## Options compared

| Option | Strength | Availability/privacy cost | MVP disposition |
|---|---|---|---|
| Strict one-time token | Simple exact spent bit; smallest replay window | Every new session consumes a token; large batches; every store fault blocks; spent set grows | Not the primary model |
| Short-lived session token | Bounds theft and outage exposure; supports reconnect | Requires atomic active-session accounting across gateways | Selected |
| Proof of possession | Stolen token alone is unusable; binds redemption to challenge/gateway | Client must protect an ephemeral private key; does not stop an authorized client exceeding limits alone | Required with session tokens |
| Rotating token batches | Separates issuance from use and tolerates brief control outage | Client cache and over-issuance controls; timing still leaks if batch is used immediately | Selected, 1..8 identical-policy credentials |
| Bloom filter | Compact membership test | False positives deny legitimate users; cannot atomically count sessions or delete reliably | Cache/telemetry only, never authority |
| Distributed exact spent/session store | Fleet-wide atomic replay/limit control | Data-plane dependency and cross-region consistency cost | Required production authority |

## MVP selection

Use 15-minute role-scoped session tokens with mandatory Ed25519 PoP, rotating
batches, and an exact shared `TokenStore`. A token may hold only its canonical
plan number of active sessions. An identical redemption tuple is rejected even
when the count is below the limit.

PoP input is:

```text
"onionroute-pop-v1\0"
|| random_token_id
|| gateway_binding
|| fresh_32_byte_gateway_challenge
```

The store's session key is a domain-separated SHA-256 digest of the same public
values. It contains no account/device/payment value. PoP is checked before
reservation so a party that stole only the public token cannot poison the
token's session quota.

## Multi-gateway store contract

Production `reserve(token_id, session_id, now, expires_at, max_sessions)` must:

- be linearizable for a token ID across all eligible gateways;
- atomically reject an existing session ID and a count at/above the signed
  canonical limit;
- never accept an expiry later than the signed token expiry;
- expire state no earlier than `expires_at + maximum_clock_skew`;
- reject on timeout, split brain, lost quorum or uncertain commit;
- expose only low-cardinality aggregate metrics and never raw keys in logs;
- isolate role/region namespaces operationally without weakening global
  per-token correctness.

A deterministic shard derived from the random token ID can route operations to
a replicated quorum. The store is part of the anonymous data plane and has no
network route or database credential for account/billing systems.

`InMemoryTokenStore` implements the atomic semantics for one process and tests;
it is not a multi-gateway production backend.

## Failure behavior

- Control plane unavailable: cached credentials continue until their signed
  expiry; no renewal is possible.
- Replay store unavailable: deny new sessions. Already admitted sessions may
  continue only to credential expiry.
- Revocation snapshot stale: deny new sessions. A snapshot is normally valid
  for 60 minutes and refreshed every five minutes.
- Client loses connectivity: gateway releases the active lease; an unclean
  loss remains counted until bounded store expiry.
- Exact replay: reject, do not return whether the token otherwise remains
  valid, and emit only a coarse aggregate error counter.

## Residual replay risks

An attacker holding both token and PoP private key can establish sessions until
the signed active-session limit or token expiry. A compromised store can ignore
limits. A partitioned store cannot safely choose availability and must fail
closed. Per-flow connection-rate and bandwidth enforcement remains local to a
gateway grant; cross-gateway active sessions are the distributed invariant.

# onionroute-circuit-manager

Owns route leases, complete Tor isolation tuples, Direct Tor stream allocation and identity
rotation. It implements the stable `onionroute_common_types::contracts::v1::CircuitManager` trait,
so client-core is independent of C Tor and Arti.

## Isolation tuple

`IsolationScope` includes:

- session epoch (owned by `IsolationManager`/backend);
- local application;
- anonymity profile;
- selected first gateway;
- destination group;
- optional browser container.

The tuple remains local. `IsolationManager` requests a random context from the backend, verifies that
the returned epoch matches, and rejects reuse of one key by two different tuples after eight bounded
attempts. Soft-rotation entries remain registered until their routes drain; hard rotation clears all
ownership.

## Route lifecycle

```text
Prepared -> Active -> Draining -> retired
```

Retirement is idempotent. Route count and lease TTL are bounded. `prepare_rotation` creates and opens
the replacement before touching the current route; failure retires only the candidate. Role order is
strict:

- Standard: `Exit`;
- Enhanced: `Entry -> Exit`;
- Maximum: `Entry -> Relay -> Exit`;
- Direct Tor: no private gateway hops.

Direct Tor has a separate explicit `open_direct_stream` API. It is not a recovery fallback.

## Identity transitions

Soft rotation changes the epoch and leaves active TCP streams untouched.

Hard rotation is serialized and rate-limited, then performs:

1. `RotationObserver::hard_rotation_started` notification to client-core;
2. `close_active_streams`;
3. backend hard rotation and isolation cancellation;
4. route/isolation ownership cleanup;
5. allocation of the new epoch root context.

Identity Reset runs hard rotation, then `flush_dns_state`,
`revoke_temporary_gateway_session`, and `clear_transient_state`. Cleanup callbacks are attempted even
if an earlier cleanup callback fails; the first error is returned after bounded cleanup.

`RotationScheduler` selects uniformly across the entire profile window, which provides jitter:

- Standard / Direct Tor: 15–30 minutes;
- Enhanced: 10–20 minutes;
- Maximum: 5–15 minutes.

Its sliding-window gate adds minimum local spacing and a maximum number of rotations per window to
avoid a multi-context stampede. `CircuitManager::run_automatic_rotation` executes this policy as an
explicitly cancellable task. A backend error terminates the task and is returned to client-core;
there is no hidden or unbounded retry loop.

## Test commands

```powershell
cargo test --manifest-path crates/circuit-manager/Cargo.toml --all-features
cargo clippy --manifest-path crates/circuit-manager/Cargo.toml --all-features --all-targets -- -D warnings
```

## Open questions

1. Which component owns policy for destination-group classification shared by browsers and apps?
2. What bounded drain deadline is approved for long-lived TCP streams before route retirement?
3. Should scheduled rotation remain soft for all profiles, or should Maximum periodically request a
   hard rotation with explicit UX impact?

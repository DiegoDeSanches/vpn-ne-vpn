# Reference gateway selection

The implementation is `crates/directory-client/src/selection.rs` and operates only
on an already verified, unexpired directory.

Required role plans are exit for Standard, entry+exit for Enhanced, and
entry+relay+exit for Maximum. Direct Tor returns no private gateways. The selected
country constrains the exit and must be enabled for the requested profile.

Candidates are removed before scoring when any of these are true:

- active gateway revocation;
- wrong role or selected exit country;
- descriptor outside its validity window;
- unknown/unhealthy health, saturated load, draining/maintenance, or abuse block;
- protocol/capability mismatch;
- client below `minimum_client_version`;
- gateway already used by another route role.

Remaining candidates receive lower-is-better scores for load, degraded health,
capacity class, and recent local failures. Provider-group and AS collisions receive
large penalties, so diverse routes are selected whenever compatible alternatives
exist. A cryptographic hash of an ephemeral per-attempt seed and public gateway ID
provides small tie-breaking jitter.

The seed is generated locally for each route attempt, is not persisted, and is not
sent to the control plane. Recent failures remain local and expire from scoring
after 30 minutes. The algorithm takes no user, account, device, installation, or
persistent anonymous fingerprint.


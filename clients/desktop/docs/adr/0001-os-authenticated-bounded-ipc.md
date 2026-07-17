# ADR-DESKTOP-0001: OS-authenticated bounded local IPC

Status: accepted for the experimental desktop shell.

## Context

The unprivileged UI must control a privileged, reboot-persistent protection host
without receiving data-plane secrets or network authority. A portable shared
secret would need provisioning, rotation and exposure to the UI process.

## Decision

Use a desktop-local protobuf v1 schema with a 64 KiB length prefix and mandatory
OS peer authentication before decode. Named Pipe token/ACL + SCM identity,
Network Extension audit/code-signing identity, and Unix `SO_PEERCRED` + ACL form
the platform trust roots. Protocol nonces are ephemeral freshness values, not
authentication secrets. Critical operations use bounded, random, single-use
confirmation identifiers scoped to an already authenticated session.

The schema is located inside `clients/desktop`, not protected root `proto/`, until
its ownership and release process are approved. It imports no gateway/control
schema and contains only UI-safe projections.

## Consequences

- UI compromise can request only the closed command set and cannot access raw
  core/Tor/gateway secrets.
- OS-specific peer verification needs dedicated clean-VM integration tests.
- A future cross-user control UI requires a new authorization model and protocol
  revision; broadening the ACL is forbidden as a compatibility shortcut.
- Swift/C# generated sources must be pinned to the canonical schema descriptor.

## Rejected alternatives

- Loopback HTTP: larger parser surface and weaker process identity binding.
- Shared bearer token in UI storage: secret exposure and rotation problems.
- Direct Rust core FFI from UI: grants network lifecycle ownership to the UI and
  breaks kill-switch persistence when the window exits.


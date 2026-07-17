# Open questions

1. Which legal code-signing publishers, Apple Team ID and Linux package signing
   keys become production peer-identity roots?
2. Is Wintun distributed as a pinned signed DLL from upstream, or packaged under
   a separately reviewed driver update channel?
3. Does the Windows threat model require boot-start WFP callout enforcement, or
   are persistent base filters plus an automatic early service sufficient?
4. Which macOS system-extension/Network Extension entitlement has been approved
   by Apple for the shipping bundle identifiers?
5. Which Linux distributions and nftables/systemd/Secret Service versions define
   the first supported matrix? Headless installations need a secure-storage
   policy separate from a logged-in Secret Service session.
6. Which OS-native application identity formats are stable enough for split
   tunneling across upgrades and renames?
7. Should scheduled rotation remain soft for Maximum mode, pending the circuit
   manager product decision already recorded by that component?
8. What diagnostics retention default is approved by privacy policy (the contract
   permits 1..168 hours and exports no arbitrary logs)?
9. Who owns versioned generation/release of SwiftProtobuf and C# IPC bindings?
10. When CP-0006 is accepted, should the desktop nested workspace be flattened
    into the root workspace or remain an isolated platform workspace?


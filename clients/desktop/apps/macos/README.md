# macOS shell build

Generate SwiftProtobuf bindings from the canonical desktop IPC schema, build the
reviewed Rust core/daemon FFI as a signed universal static library, then generate
the Xcode project with XcodeGen. The release pipeline must replace Team ID and
bundle IDs, sign both targets with the approved designated requirement, archive,
notarize and staple before distribution.

`TunnelController` communicates only through `NETunnelProviderSession` typed
provider messages. The SwiftUI process never links `RustBridge.h`. Only the
Network Extension links the Rust core and owns packet flow, DNS route settings,
Keychain/App Group recovery state and lifecycle.


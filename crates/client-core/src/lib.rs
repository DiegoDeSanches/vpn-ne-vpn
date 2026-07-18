#![forbid(unsafe_code)]
//! Runtime-neutral OnionRoute client network core.
//!
//! The core coordinates packet parsing, policy, synthetic DNS, protected gateway
//! streams, local diagnostics, sleep/resume and shutdown. It has no UI dependency
//! and no direct socket or system-DNS API.

mod core;
mod dispatcher;
mod factory;
mod packet_io;
mod shutdown;

pub use core::{ActiveRoute, ClientCore, CoreOutput, LocalDiagnostic};
pub use dispatcher::{ConnectionDispatcher, DispatcherCancellation, DispatcherConfig};
pub use factory::{
    ClientRuntimeConfig, ClientRuntimeFactory, PreparedClientRuntime,
    ProductionClientRuntimeFactory,
};
pub use packet_io::{PacketReader, PacketWriter, TunnelPacketIo};
pub use shutdown::{ShutdownCoordinator, ShutdownPhase};

#[cfg(feature = "test-utils")]
/// Deterministic common contract mocks for component and integration tests.
pub mod test_support {
    pub use onionroute_common_types::mocks::{
        MemoryPacketTunnel, MemoryTransport, MockGatewayConnector, MockTorBackend,
    };
}

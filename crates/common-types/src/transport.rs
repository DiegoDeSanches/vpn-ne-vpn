//! Runtime-neutral async byte and packet transport boundaries.

use std::future::Future;
use std::pin::Pin;

use crate::OnionResult;
use crate::version::VersionedContract;

/// Sendable boxed future used without selecting an async runtime.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Asynchronous ordered byte stream.
pub trait ByteTransport: Send + VersionedContract {
    /// Reads bytes, returning zero only after an orderly remote close.
    fn read<'a>(&'a mut self, buffer: &'a mut [u8]) -> BoxFuture<'a, OnionResult<usize>>;

    /// Writes some bytes while respecting transport backpressure.
    fn write<'a>(&'a mut self, buffer: &'a [u8]) -> BoxFuture<'a, OnionResult<usize>>;

    /// Flushes buffered bytes.
    fn flush(&mut self) -> BoxFuture<'_, OnionResult<()>>;

    /// Performs an orderly close.
    fn close(&mut self) -> BoxFuture<'_, OnionResult<()>>;
}

/// Owned runtime-neutral byte stream.
pub type BoxTransport = Box<dyn ByteTransport>;

/// System packet-tunnel adapter supplied by a platform-specific client shell.
pub trait PacketTunnel: Send + VersionedContract {
    /// Receives the next IP packet into `buffer`.
    fn receive<'a>(&'a mut self, buffer: &'a mut [u8]) -> BoxFuture<'a, OnionResult<usize>>;

    /// Sends one IP packet back to the system tunnel.
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, OnionResult<()>>;

    /// Closes the platform packet tunnel.
    fn close(&mut self) -> BoxFuture<'_, OnionResult<()>>;
}

/// Owned platform packet-tunnel adapter.
pub type BoxPacketTunnel = Box<dyn PacketTunnel>;

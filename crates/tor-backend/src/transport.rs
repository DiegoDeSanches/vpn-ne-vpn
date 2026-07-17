use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use onionroute_common_types::error::{ErrorCode, RetryClass, SafetyImpact, Severity};
use onionroute_common_types::transport::{BoxFuture, ByteTransport};
use onionroute_common_types::version::{ContractVersion, VersionedContract, CONTRACT_V1};
use onionroute_common_types::OnionResult;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::tor_error;

pub(crate) struct ManagedTorStream {
    stream: TcpStream,
    cancellation: CancellationToken,
    active: Arc<AtomicUsize>,
}

impl ManagedTorStream {
    pub(crate) fn new(
        stream: TcpStream,
        cancellation: CancellationToken,
        active: Arc<AtomicUsize>,
    ) -> Self {
        active.fetch_add(1, Ordering::AcqRel);
        Self {
            stream,
            cancellation,
            active,
        }
    }
}

impl Drop for ManagedTorStream {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

impl VersionedContract for ManagedTorStream {
    fn contract_version(&self) -> ContractVersion {
        CONTRACT_V1
    }
}

impl ByteTransport for ManagedTorStream {
    fn read<'a>(&'a mut self, buffer: &'a mut [u8]) -> BoxFuture<'a, OnionResult<usize>> {
        Box::pin(async move {
            if self.cancellation.is_cancelled() {
                return Err(cancelled_error());
            }
            tokio::select! {
                _ = self.cancellation.cancelled() => Err(cancelled_error()),
                result = self.stream.read(buffer) => result.map_err(|_| io_error()),
            }
        })
    }

    fn write<'a>(&'a mut self, buffer: &'a [u8]) -> BoxFuture<'a, OnionResult<usize>> {
        Box::pin(async move {
            if self.cancellation.is_cancelled() {
                return Err(cancelled_error());
            }
            tokio::select! {
                _ = self.cancellation.cancelled() => Err(cancelled_error()),
                result = self.stream.write(buffer) => result.map_err(|_| io_error()),
            }
        })
    }

    fn flush(&mut self) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async move {
            if self.cancellation.is_cancelled() {
                return Err(cancelled_error());
            }
            tokio::select! {
                _ = self.cancellation.cancelled() => Err(cancelled_error()),
                result = self.stream.flush() => result.map_err(|_| io_error()),
            }
        })
    }

    fn close(&mut self) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async move { self.stream.shutdown().await.map_err(|_| io_error()) })
    }
}

fn cancelled_error() -> onionroute_common_types::OnionError {
    tor_error(
        ErrorCode::ProtectedPathLost,
        Severity::Error,
        RetryClass::Backoff,
        SafetyImpact::Protected,
        "Tor stream was closed by hard rotation",
    )
}

fn io_error() -> onionroute_common_types::OnionError {
    tor_error(
        ErrorCode::TorStreamFailed,
        Severity::Error,
        RetryClass::Backoff,
        SafetyImpact::Protected,
        "Tor stream I/O failed",
    )
}

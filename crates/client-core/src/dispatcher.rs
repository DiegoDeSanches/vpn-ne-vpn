//! The only data-plane egress boundary used by client-core.

use std::collections::{HashMap, HashSet};
use std::future::{poll_fn, Future};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Waker;

use onionroute_common_types::contracts::v1::{DnsEngine, GatewayConnector};
use onionroute_common_types::error::{ErrorCode, ErrorDomain, RetryClass, SafetyImpact, Severity};
use onionroute_common_types::transport::BoxTransport;
use onionroute_common_types::types::{
    DnsQuery, DnsResponse, FlowId, GatewaySession, GatewaySessionState, TcpFlowRequest,
};
use onionroute_common_types::{OnionError, OnionResult};

/// Dispatcher hard limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatcherConfig {
    /// Maximum protected streams retained by client-core.
    pub max_streams: usize,
    /// Maximum single write/read chunk.
    pub stream_chunk_bytes: usize,
}

#[derive(Default)]
struct CancellationState {
    cancelled: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

/// Cloneable cooperative cancellation signal for pending gateway operations.
///
/// The outer runtime may retain this handle before starting the core loop and
/// cancel it from a shutdown/deadline task without acquiring `ClientCore`.
#[derive(Clone, Default)]
pub struct DispatcherCancellation {
    state: Arc<CancellationState>,
}

impl DispatcherCancellation {
    /// Cancels the current dispatcher generation and wakes its pending operation.
    pub fn cancel(&self) {
        self.state.cancelled.store(true, Ordering::Release);
        if let Some(waker) = self
            .state
            .waker
            .lock()
            .expect("dispatcher cancellation mutex poisoned")
            .take()
        {
            waker.wake();
        }
    }

    /// Returns whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }

    async fn run<F, T>(&self, future: F) -> OnionResult<T>
    where
        F: Future<Output = OnionResult<T>>,
    {
        let mut future = std::pin::pin!(future);
        poll_fn(|context| {
            if self.is_cancelled() {
                return std::task::Poll::Ready(Err(cancelled_error()));
            }
            {
                let mut slot = self
                    .state
                    .waker
                    .lock()
                    .expect("dispatcher cancellation mutex poisoned");
                let replace = match slot.as_ref() {
                    Some(registered) => !registered.will_wake(context.waker()),
                    None => true,
                };
                if replace {
                    *slot = Some(context.waker().clone());
                }
            }
            if self.is_cancelled() {
                return std::task::Poll::Ready(Err(cancelled_error()));
            }
            future.as_mut().poll(context)
        })
        .await
    }
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            max_streams: 4_096,
            stream_chunk_bytes: 64 * 1024,
        }
    }
}

/// Owns gateway streams. It cannot create direct clearnet connections.
pub struct ConnectionDispatcher {
    config: DispatcherConfig,
    gateway: Arc<dyn GatewayConnector>,
    session: GatewaySession,
    streams: HashMap<FlowId, BoxTransport>,
    local_write_closed: HashSet<FlowId>,
    accepting: bool,
    cancellation: DispatcherCancellation,
}

impl ConnectionDispatcher {
    /// Creates a dispatcher for one already-established anonymous gateway session.
    pub fn new(
        config: DispatcherConfig,
        gateway: Arc<dyn GatewayConnector>,
        session: GatewaySession,
    ) -> Option<Self> {
        (config.max_streams > 0 && config.stream_chunk_bytes > 0).then(|| Self {
            config,
            gateway,
            session,
            streams: HashMap::with_capacity(config.max_streams.min(1_024)),
            local_write_closed: HashSet::new(),
            accepting: true,
            cancellation: DispatcherCancellation::default(),
        })
    }

    /// Returns the immutable active session descriptor.
    pub const fn session(&self) -> &GatewaySession {
        &self.session
    }

    /// Returns the number of retained protected streams.
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Returns a handle that can interrupt the current generation's pending I/O.
    pub fn cancellation_handle(&self) -> DispatcherCancellation {
        self.cancellation.clone()
    }

    /// Opens a stream exclusively with `GatewayConnector::open_tcp`.
    pub async fn open(&mut self, request: &TcpFlowRequest) -> OnionResult<()> {
        if !self.accepting || self.streams.len() >= self.config.max_streams {
            return Err(dispatch_error(
                ErrorCode::Backpressure,
                RetryClass::Backoff,
                "protected stream table is full",
            ));
        }
        if self.streams.contains_key(&request.flow_id) {
            return Err(dispatch_error(
                ErrorCode::InvariantViolation,
                RetryClass::Never,
                "flow already has a protected stream",
            ));
        }
        if self.streams.len() >= self.session.max_concurrent_streams as usize {
            return Err(dispatch_error(
                ErrorCode::Backpressure,
                RetryClass::Backoff,
                "gateway session stream limit is reached",
            ));
        }
        let state = self
            .cancellation
            .run(self.gateway.session_state(&self.session))
            .await?;
        if state != GatewaySessionState::Active {
            return Err(dispatch_error(
                ErrorCode::ProtectedPathLost,
                RetryClass::Backoff,
                "gateway session is not active",
            ));
        }
        let stream = self
            .cancellation
            .run(self.gateway.open_tcp(&self.session, request))
            .await?;
        self.streams.insert(request.flow_id, stream);
        Ok(())
    }

    /// Writes a bounded payload completely while honoring downstream backpressure.
    pub async fn write_all(&mut self, flow_id: FlowId, payload: &[u8]) -> OnionResult<()> {
        if payload.len() > self.config.stream_chunk_bytes {
            return Err(dispatch_error(
                ErrorCode::MessageTooLarge,
                RetryClass::Never,
                "protected stream payload exceeds chunk limit",
            ));
        }
        if self.local_write_closed.contains(&flow_id) {
            return Err(dispatch_error(
                ErrorCode::ProtocolViolation,
                RetryClass::Never,
                "write attempted after local FIN",
            ));
        }
        let stream = self.streams.get_mut(&flow_id).ok_or_else(|| {
            dispatch_error(
                ErrorCode::ProtectedPathLost,
                RetryClass::Backoff,
                "protected stream is missing",
            )
        })?;
        let mut offset = 0usize;
        while offset < payload.len() {
            let written = self
                .cancellation
                .run(stream.write(&payload[offset..]))
                .await?;
            if written == 0 || written > payload.len() - offset {
                return Err(dispatch_error(
                    ErrorCode::ProtectedPathLost,
                    RetryClass::Backoff,
                    "protected stream made invalid write progress",
                ));
            }
            offset += written;
        }
        self.cancellation.run(stream.flush()).await
    }

    /// Reads at most one bounded protected-stream chunk.
    pub async fn read_once(&mut self, flow_id: FlowId) -> OnionResult<Option<Vec<u8>>> {
        self.read_once_limited(flow_id, self.config.stream_chunk_bytes)
            .await
    }

    /// Reads at most `limit` bytes without exceeding the dispatcher hard bound.
    pub async fn read_once_limited(
        &mut self,
        flow_id: FlowId,
        limit: usize,
    ) -> OnionResult<Option<Vec<u8>>> {
        if limit == 0 {
            return Err(dispatch_error(
                ErrorCode::Backpressure,
                RetryClass::Immediate,
                "protected read has no available flow credit",
            ));
        }
        let stream = self.streams.get_mut(&flow_id).ok_or_else(|| {
            dispatch_error(
                ErrorCode::ProtectedPathLost,
                RetryClass::Backoff,
                "protected stream is missing",
            )
        })?;
        let mut buffer = vec![0u8; limit.min(self.config.stream_chunk_bytes)];
        let read = self.cancellation.run(stream.read(&mut buffer)).await?;
        if read > buffer.len() {
            return Err(dispatch_error(
                ErrorCode::InvariantViolation,
                RetryClass::Never,
                "protected stream returned an invalid read length",
            ));
        }
        if read == 0 {
            return Ok(None);
        }
        buffer.truncate(read);
        Ok(Some(buffer))
    }

    /// Records a local FIN. Full transport half-close awaits CP-0002.
    ///
    /// Reads continue, later writes fail, and the stream is fully closed only after
    /// remote EOF, RST, timeout, cancellation, or shutdown.
    pub fn mark_write_closed(&mut self, flow_id: FlowId) -> OnionResult<()> {
        if !self.streams.contains_key(&flow_id) {
            return Err(dispatch_error(
                ErrorCode::ProtectedPathLost,
                RetryClass::Backoff,
                "protected stream is missing",
            ));
        }
        self.local_write_closed.insert(flow_id);
        Ok(())
    }

    /// Closes and removes one stream idempotently.
    pub async fn close(&mut self, flow_id: FlowId) -> OnionResult<()> {
        self.local_write_closed.remove(&flow_id);
        if let Some(mut stream) = self.streams.remove(&flow_id) {
            stream.close().await?;
        }
        Ok(())
    }

    /// Resolves DNS only through the supplied DNS engine and this gateway session.
    pub async fn resolve_dns(
        &self,
        dns: &dyn DnsEngine,
        query: &DnsQuery,
    ) -> OnionResult<DnsResponse> {
        self.cancellation
            .run(dns.resolve(query, &self.session, self.gateway.as_ref()))
            .await
    }

    /// Drains and closes every stream before replacing a failed/reconnected session.
    pub async fn replace_session(&mut self, session: GatewaySession) -> OnionResult<()> {
        self.close_all().await?;
        self.session = session;
        self.cancellation = DispatcherCancellation::default();
        self.accepting = true;
        Ok(())
    }

    /// Stops new streams and closes all currently retained transports.
    pub async fn close_all(&mut self) -> OnionResult<()> {
        self.accepting = false;
        self.cancellation.cancel();
        let ids: Vec<FlowId> = self.streams.keys().copied().collect();
        let mut first_error = None;
        for flow_id in ids {
            if let Err(error) = self.close(flow_id).await {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(())
        }
    }
}

fn cancelled_error() -> OnionError {
    dispatch_error(
        ErrorCode::ProtectedPathLost,
        RetryClass::Backoff,
        "dispatcher operation was cancelled",
    )
}

fn dispatch_error(code: ErrorCode, retry: RetryClass, message: &'static str) -> OnionError {
    OnionError::new(
        ErrorDomain::Gateway,
        code,
        Severity::Error,
        retry,
        SafetyImpact::MustBlock,
        message,
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::Duration;

    use onionroute_common_types::error::ErrorCode;
    use onionroute_common_types::OnionResult;

    use super::DispatcherCancellation;

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        struct NoopWake;
        impl Wake for NoopWake {
            fn wake(self: Arc<Self>) {}
        }
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        let mut future = std::pin::pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn pending_operation_is_cancelled_without_core_lock() {
        let cancellation = DispatcherCancellation::default();
        let signal = cancellation.clone();
        let thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(5));
            signal.cancel();
        });
        let result = block_on(cancellation.run(std::future::pending::<OnionResult<()>>()));
        thread.join().expect("cancellation thread");
        assert_eq!(
            result.expect_err("operation must cancel").code,
            ErrorCode::ProtectedPathLost
        );
    }
}

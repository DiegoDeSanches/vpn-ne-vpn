//! Fault-injectable fake backend for component integration tests only.

use std::collections::VecDeque;
use std::sync::Mutex;

use onionroute_common_types::contracts::v1::TorBackend;
use onionroute_common_types::error::{ErrorCode, RetryClass, SafetyImpact, Severity};
use onionroute_common_types::mocks::MemoryTransport;
use onionroute_common_types::transport::{BoxFuture, BoxTransport};
use onionroute_common_types::types::{
    IsolationKey, OnionEndpoint, TcpFlowRequest, TorBootstrapConfig, TorStatus,
};
use onionroute_common_types::version::{ContractVersion, VersionedContract, CONTRACT_V1};
use onionroute_common_types::OnionResult;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::{
    tor_error, BackendHealth, BackendLifecycle, BridgeConfig, IsolationContext, IsolationScope,
    ProxyConfig, RotationOutcome, TorBackendExt,
};

/// One deterministic fault consumed by the fake backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FakeFault {
    /// Fails the next bootstrap call.
    BootstrapFailure,
    /// Marks the process crashed during the next status call.
    ProcessCrash,
    /// Fails the next stream open.
    StreamFailure,
    /// Reports gateway unavailability on the next stream open.
    GatewayUnavailable,
}

#[derive(Default)]
struct FakeState {
    running: bool,
    ready: bool,
    crashed: bool,
    epoch: u64,
    soft_rotations: usize,
    hard_rotations: usize,
    fixed_isolation_key: Option<[u8; 32]>,
    faults: VecDeque<FakeFault>,
}

/// In-memory managed Tor backend for component tests.
#[derive(Default)]
pub struct FakeTorBackend {
    state: Mutex<FakeState>,
}

impl FakeTorBackend {
    /// Queues one fault in call order.
    pub fn inject(&self, fault: FakeFault) {
        self.state
            .lock()
            .expect("fake state poisoned")
            .faults
            .push_back(fault);
    }

    /// Returns `(soft, hard)` rotation call counts.
    pub fn rotation_counts(&self) -> (usize, usize) {
        let state = self.state.lock().expect("fake state poisoned");
        (state.soft_rotations, state.hard_rotations)
    }

    /// Forces allocations to collide, or restores random test allocation.
    pub fn set_fixed_isolation_key(&self, key: Option<[u8; 32]>) {
        self.state
            .lock()
            .expect("fake state poisoned")
            .fixed_isolation_key = key;
    }

    fn consume(&self, expected: FakeFault) -> bool {
        let mut state = self.state.lock().expect("fake state poisoned");
        if state.faults.front() == Some(&expected) {
            state.faults.pop_front();
            true
        } else {
            false
        }
    }

    fn stream(&self) -> OnionResult<BoxTransport> {
        if self.consume(FakeFault::GatewayUnavailable) {
            return Err(tor_error(
                ErrorCode::GatewayUnavailable,
                Severity::Error,
                RetryClass::AfterDirectoryRefresh,
                SafetyImpact::Protected,
                "fake gateway is unavailable",
            ));
        }
        if self.consume(FakeFault::StreamFailure) {
            return Err(fake_unavailable("fake Tor stream failed"));
        }
        let state = self.state.lock().expect("fake state poisoned");
        if !state.running || !state.ready || state.crashed {
            return Err(fake_unavailable("fake Tor is unavailable"));
        }
        Ok(Box::new(MemoryTransport::default()))
    }
}

impl VersionedContract for FakeTorBackend {
    fn contract_version(&self) -> ContractVersion {
        CONTRACT_V1
    }
}

impl TorBackend for FakeTorBackend {
    fn bootstrap<'a>(
        &'a self,
        _config: &'a TorBootstrapConfig,
    ) -> BoxFuture<'a, OnionResult<TorStatus>> {
        Box::pin(async move {
            if self.consume(FakeFault::BootstrapFailure) {
                return Err(tor_error(
                    ErrorCode::TorBootstrapTimeout,
                    Severity::Error,
                    RetryClass::Backoff,
                    SafetyImpact::Protected,
                    "fake Tor bootstrap failed",
                ));
            }
            let mut state = self.state.lock().expect("fake state poisoned");
            state.running = true;
            state.ready = true;
            Ok(TorStatus {
                bootstrap_percent: 100,
                ready: true,
            })
        })
    }

    fn open_onion_stream<'a>(
        &'a self,
        _endpoint: &'a OnionEndpoint,
        _isolation: &'a IsolationKey,
    ) -> BoxFuture<'a, OnionResult<BoxTransport>> {
        Box::pin(async move { self.stream() })
    }

    fn open_direct_stream<'a>(
        &'a self,
        _request: &'a TcpFlowRequest,
        _isolation: &'a IsolationKey,
    ) -> BoxFuture<'a, OnionResult<BoxTransport>> {
        Box::pin(async move { self.stream() })
    }

    fn status(&self) -> BoxFuture<'_, OnionResult<TorStatus>> {
        Box::pin(async move {
            if self.consume(FakeFault::ProcessCrash) {
                let mut state = self.state.lock().expect("fake state poisoned");
                state.crashed = true;
                state.ready = false;
            }
            let state = self.state.lock().expect("fake state poisoned");
            if state.crashed || !state.running {
                return Err(fake_unavailable("fake Tor process crashed"));
            }
            Ok(TorStatus {
                bootstrap_percent: if state.ready { 100 } else { 0 },
                ready: state.ready,
            })
        })
    }

    fn shutdown(&self) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async move {
            let mut state = self.state.lock().expect("fake state poisoned");
            state.running = false;
            state.ready = false;
            Ok(())
        })
    }
}

impl TorBackendExt for FakeTorBackend {
    fn start(&self) -> BoxFuture<'_, OnionResult<TorStatus>> {
        Box::pin(async move {
            let mut state = self.state.lock().expect("fake state poisoned");
            state.running = true;
            Ok(TorStatus {
                bootstrap_percent: 0,
                ready: false,
            })
        })
    }

    fn stop(&self) -> BoxFuture<'_, OnionResult<()>> {
        self.shutdown()
    }

    fn bootstrap_progress(&self) -> BoxFuture<'_, OnionResult<u8>> {
        Box::pin(async move { Ok(self.status().await?.bootstrap_percent) })
    }

    fn allocate_isolation_context<'a>(
        &'a self,
        scope: &'a IsolationScope,
    ) -> BoxFuture<'a, OnionResult<IsolationContext>> {
        Box::pin(async move {
            scope.validate()?;
            let state = self.state.lock().expect("fake state poisoned");
            let epoch = state.epoch;
            let mut key = [0_u8; 32];
            if let Some(fixed) = state.fixed_isolation_key {
                key = fixed;
            } else {
                OsRng.fill_bytes(&mut key);
            }
            Ok(IsolationContext {
                session_epoch: epoch,
                key: IsolationKey(key),
            })
        })
    }

    fn release_isolation_context<'a>(
        &'a self,
        _context: &'a IsolationContext,
    ) -> BoxFuture<'a, OnionResult<()>> {
        Box::pin(async { Ok(()) })
    }

    fn request_soft_rotation(&self) -> BoxFuture<'_, OnionResult<RotationOutcome>> {
        Box::pin(async move {
            let mut state = self.state.lock().expect("fake state poisoned");
            state.epoch += 1;
            state.soft_rotations += 1;
            Ok(RotationOutcome {
                new_epoch: state.epoch,
                closed_streams: 0,
            })
        })
    }

    fn request_hard_rotation(&self) -> BoxFuture<'_, OnionResult<RotationOutcome>> {
        Box::pin(async move {
            let mut state = self.state.lock().expect("fake state poisoned");
            state.epoch += 1;
            state.hard_rotations += 1;
            Ok(RotationOutcome {
                new_epoch: state.epoch,
                closed_streams: 1,
            })
        })
    }

    fn health_status(&self) -> BoxFuture<'_, OnionResult<BackendHealth>> {
        Box::pin(async move {
            let status = self.status().await;
            Ok(match status {
                Ok(status) => BackendHealth {
                    lifecycle: if status.ready {
                        BackendLifecycle::Ready
                    } else {
                        BackendLifecycle::Bootstrapping
                    },
                    bootstrap_percent: status.bootstrap_percent,
                    accepting_streams: status.ready,
                    active_streams: 0,
                    fail_closed: !status.ready,
                },
                Err(_) => BackendHealth {
                    lifecycle: BackendLifecycle::FailedClosed,
                    bootstrap_percent: 0,
                    accepting_streams: false,
                    active_streams: 0,
                    fail_closed: true,
                },
            })
        })
    }

    fn configure_bridges<'a>(&'a self, config: BridgeConfig) -> BoxFuture<'a, OnionResult<()>> {
        Box::pin(async move { config.validate() })
    }

    fn configure_proxy(&self, _config: Option<ProxyConfig>) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async { Ok(()) })
    }

    fn network_changed(&self) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async move {
            let mut state = self.state.lock().expect("fake state poisoned");
            state.ready = false;
            Ok(())
        })
    }
}

fn fake_unavailable(message: &'static str) -> onionroute_common_types::OnionError {
    tor_error(
        ErrorCode::TorUnavailable,
        Severity::Error,
        RetryClass::Backoff,
        SafetyImpact::Protected,
        message,
    )
}

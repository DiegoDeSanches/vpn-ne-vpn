//! Deterministic contract mocks for parallel component development.
//!
//! Enable the `test-utils` feature outside this crate. These mocks model
//! interface behavior only and are not security or performance substitutes.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use crate::contracts::v1::{
    CircuitManager, DnsEngine, GatewayConnector, GatewayDirectoryProvider, HealthReporter,
    KillSwitch, PacketEngine, PolicyEngine, SecureStorage, TokenProvider, TorBackend,
};
use crate::error::{
    ErrorCode, ErrorDomain, RetryClass, SafetyImpact, Severity,
};
use crate::transport::{
    BoxFuture, BoxPacketTunnel, BoxTransport, ByteTransport, PacketTunnel,
};
use crate::types::*;
use crate::version::{ContractVersion, VersionedContract, CONTRACT_V1};
use crate::{OnionError, OnionResult};

fn ready<'a, T: Send + 'a>(value: T) -> BoxFuture<'a, T> {
    Box::pin(async move { value })
}

fn mock_error(domain: ErrorDomain, code: ErrorCode, message: &'static str) -> OnionError {
    OnionError::new(
        domain,
        code,
        Severity::Error,
        RetryClass::Backoff,
        SafetyImpact::Protected,
        message,
    )
}

/// In-memory byte stream that records writes and serves queued read bytes.
#[derive(Default)]
pub struct MemoryTransport {
    reads: VecDeque<u8>,
    writes: Arc<Mutex<Vec<u8>>>,
    closed: bool,
}

impl MemoryTransport {
    /// Creates a stream preloaded with readable bytes.
    pub fn with_read_data(bytes: impl IntoIterator<Item = u8>) -> Self {
        Self {
            reads: bytes.into_iter().collect(),
            writes: Arc::new(Mutex::new(Vec::new())),
            closed: false,
        }
    }

    /// Returns shared access to bytes written by the caller.
    pub fn written_bytes(&self) -> Arc<Mutex<Vec<u8>>> {
        Arc::clone(&self.writes)
    }
}

impl ByteTransport for MemoryTransport {
    fn read<'a>(&'a mut self, buffer: &'a mut [u8]) -> BoxFuture<'a, OnionResult<usize>> {
        let count = buffer.len().min(self.reads.len());
        for output in &mut buffer[..count] {
            *output = self.reads.pop_front().expect("count is bounded by queue length");
        }
        ready(Ok(count))
    }

    fn write<'a>(&'a mut self, buffer: &'a [u8]) -> BoxFuture<'a, OnionResult<usize>> {
        if self.closed {
            return ready(Err(mock_error(
                ErrorDomain::Gateway,
                ErrorCode::ProtectedPathLost,
                "mock transport is closed",
            )));
        }
        self.writes
            .lock()
            .expect("mock write mutex poisoned")
            .extend_from_slice(buffer);
        ready(Ok(buffer.len()))
    }

    fn flush(&mut self) -> BoxFuture<'_, OnionResult<()>> {
        ready(Ok(()))
    }

    fn close(&mut self) -> BoxFuture<'_, OnionResult<()>> {
        self.closed = true;
        ready(Ok(()))
    }
}

impl VersionedContract for MemoryTransport {
    fn contract_version(&self) -> ContractVersion {
        CONTRACT_V1
    }
}

/// In-memory packet-tunnel adapter for packet-engine contract tests.
#[derive(Default)]
pub struct MemoryPacketTunnel {
    incoming: VecDeque<Vec<u8>>,
    outgoing: Arc<Mutex<Vec<Vec<u8>>>>,
    closed: bool,
}

impl MemoryPacketTunnel {
    /// Creates a tunnel with packets waiting for `receive`.
    pub fn with_incoming(packets: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self {
            incoming: packets.into_iter().collect(),
            outgoing: Arc::new(Mutex::new(Vec::new())),
            closed: false,
        }
    }

    /// Returns shared access to packets sent back to the platform.
    pub fn outgoing_packets(&self) -> Arc<Mutex<Vec<Vec<u8>>>> {
        Arc::clone(&self.outgoing)
    }
}

impl PacketTunnel for MemoryPacketTunnel {
    fn receive<'a>(&'a mut self, buffer: &'a mut [u8]) -> BoxFuture<'a, OnionResult<usize>> {
        let Some(packet) = self.incoming.pop_front() else {
            return ready(Ok(0));
        };
        if packet.len() > buffer.len() {
            return ready(Err(mock_error(
                ErrorDomain::Packet,
                ErrorCode::MessageTooLarge,
                "mock packet exceeds receive buffer",
            )));
        }
        buffer[..packet.len()].copy_from_slice(&packet);
        ready(Ok(packet.len()))
    }

    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, OnionResult<()>> {
        if self.closed {
            return ready(Err(mock_error(
                ErrorDomain::Packet,
                ErrorCode::ProtectedPathLost,
                "mock packet tunnel is closed",
            )));
        }
        self.outgoing
            .lock()
            .expect("mock packet mutex poisoned")
            .push(packet.to_vec());
        ready(Ok(()))
    }

    fn close(&mut self) -> BoxFuture<'_, OnionResult<()>> {
        self.closed = true;
        ready(Ok(()))
    }
}

impl VersionedContract for MemoryPacketTunnel {
    fn contract_version(&self) -> ContractVersion {
        CONTRACT_V1
    }
}

/// Tor backend mock that is immediately ready and returns memory streams.
#[derive(Default)]
pub struct MockTorBackend;

impl VersionedContract for MockTorBackend {
    fn contract_version(&self) -> ContractVersion {
        CONTRACT_V1
    }
}

impl TorBackend for MockTorBackend {
    fn bootstrap<'a>(
        &'a self,
        _config: &'a TorBootstrapConfig,
    ) -> BoxFuture<'a, OnionResult<TorStatus>> {
        ready(Ok(TorStatus {
            bootstrap_percent: 100,
            ready: true,
        }))
    }

    fn open_onion_stream<'a>(
        &'a self,
        _endpoint: &'a OnionEndpoint,
        _isolation: &'a IsolationKey,
    ) -> BoxFuture<'a, OnionResult<BoxTransport>> {
        ready(Ok(Box::new(MemoryTransport::default()) as BoxTransport))
    }

    fn open_direct_stream<'a>(
        &'a self,
        _request: &'a TcpFlowRequest,
        _isolation: &'a IsolationKey,
    ) -> BoxFuture<'a, OnionResult<BoxTransport>> {
        ready(Ok(Box::new(MemoryTransport::default()) as BoxTransport))
    }

    fn status(&self) -> BoxFuture<'_, OnionResult<TorStatus>> {
        ready(Ok(TorStatus {
            bootstrap_percent: 100,
            ready: true,
        }))
    }

    fn shutdown(&self) -> BoxFuture<'_, OnionResult<()>> {
        ready(Ok(()))
    }
}

/// Circuit-manager mock with deterministic route identifiers.
#[derive(Default)]
pub struct MockCircuitManager;

impl VersionedContract for MockCircuitManager {
    fn contract_version(&self) -> ContractVersion {
        CONTRACT_V1
    }
}

impl CircuitManager for MockCircuitManager {
    fn prepare_route<'a>(
        &'a self,
        plan: &'a GatewayPlan,
        _reason: RotationReason,
    ) -> BoxFuture<'a, OnionResult<RouteLease>> {
        ready(Ok(RouteLease {
            route_id: RouteId([1; 16]),
            plan: plan.clone(),
            isolation_key: IsolationKey([2; 32]),
            expires_at_unix: i64::MAX,
        }))
    }

    fn open_first_hop<'a>(
        &'a self,
        _route: &'a RouteLease,
    ) -> BoxFuture<'a, OnionResult<BoxTransport>> {
        ready(Ok(Box::new(MemoryTransport::default()) as BoxTransport))
    }

    fn prepare_rotation<'a>(
        &'a self,
        _current: &'a RouteLease,
        replacement: &'a GatewayPlan,
        _reason: RotationReason,
    ) -> BoxFuture<'a, OnionResult<RotationCandidate>> {
        ready(Ok(RotationCandidate {
            route: RouteLease {
                route_id: RouteId([3; 16]),
                plan: replacement.clone(),
                isolation_key: IsolationKey([4; 32]),
                expires_at_unix: i64::MAX,
            },
            transport: Box::new(MemoryTransport::default()),
        }))
    }

    fn retire_route<'a>(&'a self, _route: &'a RouteLease) -> BoxFuture<'a, OnionResult<()>> {
        ready(Ok(()))
    }
}

/// Gateway mock that authenticates any non-empty bounded token.
#[derive(Default)]
pub struct MockGatewayConnector;

impl VersionedContract for MockGatewayConnector {
    fn contract_version(&self) -> ContractVersion {
        CONTRACT_V1
    }
}

impl GatewayConnector for MockGatewayConnector {
    fn exchange_dns<'a>(
        &'a self,
        _session: &'a GatewaySession,
        query: &'a DnsQuery,
    ) -> BoxFuture<'a, OnionResult<DnsResponse>> {
        ready(Ok(DnsResponse {
            query_id: query.query_id,
            wire: query.wire.clone(),
        }))
    }

    fn connect<'a>(
        &'a self,
        _transport: BoxTransport,
        request: &'a GatewayDialRequest,
        credentials: GatewayCredentials,
    ) -> BoxFuture<'a, OnionResult<GatewaySession>> {
        if request.plan.hops.is_empty()
            || credentials.len() != request.plan.hops.len()
        {
            return ready(Err(mock_error(
                ErrorDomain::Gateway,
                ErrorCode::ProtocolViolation,
                "credential count does not match gateway plan",
            )));
        }
        ready(Ok(GatewaySession {
            session_id: SessionId([5; 16]),
            gateway_id: request
                .plan
                .hops
                .last()
                .expect("credential count requires at least one mock hop")
                .gateway_id
                .clone(),
            role: request
                .plan
                .hops
                .last()
                .expect("credential count requires at least one mock hop")
                .role,
            protocol_version: request.supported_versions.maximum,
            state: GatewaySessionState::Active,
            expires_at_unix: i64::MAX,
            max_concurrent_streams: 128,
        }))
    }

    fn open_tcp<'a>(
        &'a self,
        _session: &'a GatewaySession,
        _request: &'a TcpFlowRequest,
    ) -> BoxFuture<'a, OnionResult<BoxTransport>> {
        ready(Ok(Box::new(MemoryTransport::default()) as BoxTransport))
    }

    fn session_state<'a>(
        &'a self,
        session: &'a GatewaySession,
    ) -> BoxFuture<'a, OnionResult<GatewaySessionState>> {
        ready(Ok(session.state))
    }

    fn begin_draining<'a>(
        &'a self,
        _session: &'a GatewaySession,
    ) -> BoxFuture<'a, OnionResult<()>> {
        ready(Ok(()))
    }

    fn close<'a>(&'a self, _session: &'a GatewaySession) -> BoxFuture<'a, OnionResult<()>> {
        ready(Ok(()))
    }
}

/// Packet-engine mock driven by an explicit event queue.
#[derive(Default)]
pub struct MockPacketEngine {
    events: Mutex<VecDeque<PacketEvent>>,
    running: Mutex<bool>,
}

impl MockPacketEngine {
    /// Appends an event that will be returned by `next_event`.
    pub fn push_event(&self, event: PacketEvent) {
        self.events
            .lock()
            .expect("mock event mutex poisoned")
            .push_back(event);
    }
}

impl VersionedContract for MockPacketEngine {
    fn contract_version(&self) -> ContractVersion {
        CONTRACT_V1
    }
}

impl PacketEngine for MockPacketEngine {
    fn start(
        &self,
        _tunnel: BoxPacketTunnel,
        _config: PacketEngineConfig,
    ) -> BoxFuture<'_, OnionResult<()>> {
        *self.running.lock().expect("mock running mutex poisoned") = true;
        ready(Ok(()))
    }

    fn next_event(&self) -> BoxFuture<'_, OnionResult<PacketEvent>> {
        let event = self
            .events
            .lock()
            .expect("mock event mutex poisoned")
            .pop_front()
            .ok_or_else(|| {
                mock_error(
                    ErrorDomain::Packet,
                    ErrorCode::Backpressure,
                    "mock event queue is empty",
                )
            });
        ready(event)
    }

    fn bind_tcp(
        &self,
        _flow: FlowId,
        _stream: BoxTransport,
    ) -> BoxFuture<'_, OnionResult<()>> {
        ready(Ok(()))
    }

    fn reject_flow(
        &self,
        _flow: FlowId,
        _error: OnionError,
    ) -> BoxFuture<'_, OnionResult<()>> {
        ready(Ok(()))
    }

    fn complete_dns(&self, _response: DnsResponse) -> BoxFuture<'_, OnionResult<()>> {
        ready(Ok(()))
    }

    fn status(&self) -> BoxFuture<'_, OnionResult<PacketEngineStatus>> {
        let running = *self.running.lock().expect("mock running mutex poisoned");
        let queued_events = self
            .events
            .lock()
            .expect("mock event mutex poisoned")
            .len();
        ready(Ok(PacketEngineStatus {
            running,
            active_flows: 0,
            queued_events,
        }))
    }

    fn stop(&self) -> BoxFuture<'_, OnionResult<()>> {
        *self.running.lock().expect("mock running mutex poisoned") = false;
        ready(Ok(()))
    }
}

/// DNS mock that delegates to the explicitly supplied protected upstream.
#[derive(Default)]
pub struct MockDnsEngine;

impl VersionedContract for MockDnsEngine {
    fn contract_version(&self) -> ContractVersion {
        CONTRACT_V1
    }
}

impl DnsEngine for MockDnsEngine {
    fn resolve<'a>(
        &'a self,
        query: &'a DnsQuery,
        session: &'a GatewaySession,
        gateway: &'a dyn GatewayConnector,
    ) -> BoxFuture<'a, OnionResult<DnsResponse>> {
        gateway.exchange_dns(session, query)
    }

    fn flush_cache(&self) -> BoxFuture<'_, OnionResult<()>> {
        ready(Ok(()))
    }
}

/// Policy mock that enforces core MVP denies and selects gateways by role.
#[derive(Default)]
pub struct MockPolicyEngine;

impl VersionedContract for MockPolicyEngine {
    fn contract_version(&self) -> ContractVersion {
        CONTRACT_V1
    }
}

impl PolicyEngine for MockPolicyEngine {
    fn evaluate_tcp<'a>(
        &'a self,
        request: &'a TcpFlowRequest,
    ) -> BoxFuture<'a, OnionResult<PolicyDecision>> {
        let decision = if request.port == 25 {
            PolicyDecision {
                action: PolicyAction::Block,
                rule_id: "mvp.block.smtp25.v1".to_owned(),
            }
        } else {
            PolicyDecision {
                action: PolicyAction::Tunnel,
                rule_id: "default.tunnel.v1".to_owned(),
            }
        };
        ready(Ok(decision))
    }

    fn evaluate_dns<'a>(
        &'a self,
        _context: &'a DnsPolicyContext,
    ) -> BoxFuture<'a, OnionResult<PolicyDecision>> {
        ready(Ok(PolicyDecision {
            action: PolicyAction::Tunnel,
            rule_id: "dns.protected.v1".to_owned(),
        }))
    }

    fn select_gateway_plan<'a>(
        &'a self,
        directory: &'a VerifiedGatewayDirectory,
        constraints: &'a RouteConstraints,
    ) -> BoxFuture<'a, OnionResult<GatewayPlan>> {
        let required: &[GatewayRole] = match constraints.mode {
            AnonymityMode::Standard => &[GatewayRole::Exit],
            AnonymityMode::Enhanced => &[GatewayRole::Entry, GatewayRole::Exit],
            AnonymityMode::Maximum => {
                &[GatewayRole::Entry, GatewayRole::Relay, GatewayRole::Exit]
            }
            AnonymityMode::DirectTor => &[],
        };
        let mut hops = Vec::with_capacity(required.len());
        for role in required {
            let descriptor = directory
                .gateways
                .iter()
                .find(|gateway| {
                    gateway.roles.contains(role)
                        && constraints
                            .exit_country
                            .map(|country| *role != GatewayRole::Exit || gateway.country == country)
                            .unwrap_or(true)
                })
                .ok_or_else(|| {
                    mock_error(
                        ErrorDomain::Directory,
                        ErrorCode::GatewayUnavailable,
                        "mock directory has no gateway for required role",
                    )
                });
            let descriptor = match descriptor {
                Ok(value) => value,
                Err(error) => return ready(Err(error)),
            };
            hops.push(GatewayHop {
                gateway_id: descriptor.gateway_id.clone(),
                role: *role,
                onion_endpoint: descriptor.endpoint.clone(),
                tls_spki_sha256: descriptor.tls_spki_sha256,
            });
        }
        ready(Ok(GatewayPlan {
            mode: constraints.mode,
            hops,
        }))
    }
}

/// Kill-switch mock that tracks an engaged generation.
#[derive(Default)]
pub struct MockKillSwitch {
    generation: Mutex<Option<u64>>,
}

impl VersionedContract for MockKillSwitch {
    fn contract_version(&self) -> ContractVersion {
        CONTRACT_V1
    }
}

impl KillSwitch for MockKillSwitch {
    fn engage<'a>(
        &'a self,
        _policy: &'a KillSwitchPolicy,
    ) -> BoxFuture<'a, OnionResult<KillSwitchLease>> {
        let mut generation = self
            .generation
            .lock()
            .expect("mock kill-switch mutex poisoned");
        let next = generation.unwrap_or(0) + 1;
        *generation = Some(next);
        ready(Ok(KillSwitchLease { generation: next }))
    }

    fn verify<'a>(
        &'a self,
        lease: &'a KillSwitchLease,
    ) -> BoxFuture<'a, OnionResult<KillSwitchStatus>> {
        let current = *self
            .generation
            .lock()
            .expect("mock kill-switch mutex poisoned");
        ready(Ok(KillSwitchStatus {
            engaged: current.is_some(),
            verified: current == Some(lease.generation),
            generation: current,
        }))
    }

    fn emergency_block(&self) -> BoxFuture<'_, OnionResult<KillSwitchLease>> {
        let mut generation = self
            .generation
            .lock()
            .expect("mock kill-switch mutex poisoned");
        let next = generation.unwrap_or(0) + 1;
        *generation = Some(next);
        ready(Ok(KillSwitchLease { generation: next }))
    }

    fn disengage<'a>(
        &'a self,
        lease: &'a KillSwitchLease,
    ) -> BoxFuture<'a, OnionResult<()>> {
        let mut generation = self
            .generation
            .lock()
            .expect("mock kill-switch mutex poisoned");
        if *generation == Some(lease.generation) {
            *generation = None;
            ready(Ok(()))
        } else {
            ready(Err(mock_error(
                ErrorDomain::KillSwitch,
                ErrorCode::KillSwitchVerificationFailed,
                "mock kill-switch lease is stale",
            )))
        }
    }

    fn recover(&self) -> BoxFuture<'_, OnionResult<KillSwitchStatus>> {
        let current = *self
            .generation
            .lock()
            .expect("mock kill-switch mutex poisoned");
        ready(Ok(KillSwitchStatus {
            engaged: current.is_some(),
            verified: current.is_some(),
            generation: current,
        }))
    }
}

/// In-memory secure-storage mock with redacting values.
#[derive(Default)]
pub struct MockSecureStorage {
    values: Mutex<HashMap<StorageKey, SecretValue>>,
}

impl VersionedContract for MockSecureStorage {
    fn contract_version(&self) -> ContractVersion {
        CONTRACT_V1
    }
}

impl SecureStorage for MockSecureStorage {
    fn load(&self, key: StorageKey) -> BoxFuture<'_, OnionResult<Option<SecretValue>>> {
        let value = self
            .values
            .lock()
            .expect("mock storage mutex poisoned")
            .get(&key)
            .cloned();
        ready(Ok(value))
    }

    fn store(
        &self,
        key: StorageKey,
        value: SecretValue,
    ) -> BoxFuture<'_, OnionResult<()>> {
        self.values
            .lock()
            .expect("mock storage mutex poisoned")
            .insert(key, value);
        ready(Ok(()))
    }

    fn delete(&self, key: StorageKey) -> BoxFuture<'_, OnionResult<()>> {
        self.values
            .lock()
            .expect("mock storage mutex poisoned")
            .remove(&key);
        ready(Ok(()))
    }
}

/// Directory-provider mock backed by one pre-verified directory.
#[derive(Default)]
pub struct MockGatewayDirectoryProvider {
    directory: Mutex<Option<VerifiedGatewayDirectory>>,
}

impl MockGatewayDirectoryProvider {
    /// Creates a provider that returns `directory` from cache and refresh calls.
    pub fn new(directory: VerifiedGatewayDirectory) -> Self {
        Self {
            directory: Mutex::new(Some(directory)),
        }
    }
}

impl VersionedContract for MockGatewayDirectoryProvider {
    fn contract_version(&self) -> ContractVersion {
        CONTRACT_V1
    }
}

impl GatewayDirectoryProvider for MockGatewayDirectoryProvider {
    fn load_cached(&self) -> BoxFuture<'_, OnionResult<Option<VerifiedGatewayDirectory>>> {
        let directory = self
            .directory
            .lock()
            .expect("mock directory mutex poisoned")
            .clone();
        ready(Ok(directory))
    }

    fn refresh(
        &self,
        _reason: DirectoryRefreshReason,
    ) -> BoxFuture<'_, OnionResult<VerifiedGatewayDirectory>> {
        let result = self
            .directory
            .lock()
            .expect("mock directory mutex poisoned")
            .clone()
            .ok_or_else(|| {
                mock_error(
                    ErrorDomain::Directory,
                    ErrorCode::DirectoryUnavailable,
                    "mock directory is empty",
                )
            });
        ready(result)
    }

    fn verify<'a>(
        &'a self,
        _envelope: &'a SignedDirectoryEnvelope,
    ) -> BoxFuture<'a, OnionResult<VerifiedGatewayDirectory>> {
        self.refresh(DirectoryRefreshReason::UserRequested)
    }
}

/// Token-provider mock that returns a fresh fixed-size anonymous token.
#[derive(Default)]
pub struct MockTokenProvider;

impl VersionedContract for MockTokenProvider {
    fn contract_version(&self) -> ContractVersion {
        CONTRACT_V1
    }
}

impl TokenProvider for MockTokenProvider {
    fn acquire<'a>(
        &'a self,
        _request: &'a TokenRequest,
    ) -> BoxFuture<'a, OnionResult<CapabilityToken>> {
        ready(Ok(CapabilityToken::new(vec![7; 32])
            .expect("fixed mock token is within limits")))
    }

    fn invalidate(&self) -> BoxFuture<'_, OnionResult<()>> {
        ready(Ok(()))
    }
}

/// Health-reporter mock that retains only closed-schema events.
#[derive(Default)]
pub struct MockHealthReporter {
    events: Mutex<Vec<HealthEvent>>,
}

impl MockHealthReporter {
    /// Returns a snapshot of recorded events.
    pub fn events(&self) -> Vec<HealthEvent> {
        self.events
            .lock()
            .expect("mock health mutex poisoned")
            .clone()
    }
}

impl VersionedContract for MockHealthReporter {
    fn contract_version(&self) -> ContractVersion {
        CONTRACT_V1
    }
}

impl HealthReporter for MockHealthReporter {
    fn record(&self, event: HealthEvent) -> BoxFuture<'_, OnionResult<()>> {
        self.events
            .lock()
            .expect("mock health mutex poisoned")
            .push(event);
        ready(Ok(()))
    }

    fn flush(&self) -> BoxFuture<'_, OnionResult<()>> {
        ready(Ok(()))
    }

    fn purge(&self) -> BoxFuture<'_, OnionResult<()>> {
        self.events
            .lock()
            .expect("mock health mutex poisoned")
            .clear();
        ready(Ok(()))
    }
}

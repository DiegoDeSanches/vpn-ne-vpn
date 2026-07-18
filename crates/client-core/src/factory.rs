//! Production assembly of one bounded protected client runtime.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use onionroute_common_types::contracts::v1::{
    CircuitManager, GatewayConnector, GatewayDirectoryProvider, PolicyEngine, TokenProvider,
    TorBackend,
};
use onionroute_common_types::error::{ErrorCode, ErrorDomain, RetryClass, SafetyImpact, Severity};
use onionroute_common_types::transport::BoxFuture;
use onionroute_common_types::types::{
    AnonymityMode, GatewayCredentials, GatewayDialRequest, GatewaySession, GatewaySessionState,
    ProtocolVersionRange, RotationReason, RouteConstraints, RouteLease, TokenRequest,
    TorBootstrapConfig,
};
use onionroute_common_types::version::{ContractVersion, VersionedContract, CONTRACT_V1};
use onionroute_common_types::{OnionError, OnionResult};
use onionroute_dns_engine::{SyntheticDnsConfig, SyntheticDnsEngine};
use onionroute_packet_engine::{EngineConfig, NoopMetrics, PacketProcessor};

use crate::{ActiveRoute, ClientCore, ConnectionDispatcher, DispatcherConfig};

const MAX_FACTORY_FEATURES: usize = 32;
const MAX_FACTORY_FEATURE_BYTES: usize = 64;
const MAX_TOKEN_VALIDITY: Duration = Duration::from_secs(60 * 60);

/// Verified, bounded inputs used to assemble one protected mobile runtime.
#[derive(Clone, Debug)]
pub struct ClientRuntimeConfig {
    /// Route mode, country and required directory capabilities.
    pub route: RouteConstraints,
    /// Finite C Tor bootstrap policy.
    pub tor: TorBootstrapConfig,
    /// Gateway protocol versions accepted by this client.
    pub gateway_versions: ProtocolVersionRange,
    /// Explicit gateway protocol features requested during negotiation.
    pub gateway_features: Vec<String>,
    /// Minimum remaining lifetime for every independently issued hop token.
    pub token_minimum_validity: Duration,
    /// Packet and flow hard limits.
    pub packet: EngineConfig,
    /// Synthetic DNS cache hard limits.
    pub dns: SyntheticDnsConfig,
    /// Protected stream table and chunk hard limits.
    pub dispatcher: DispatcherConfig,
}

impl ClientRuntimeConfig {
    fn validate(&self) -> OnionResult<()> {
        if self.route.mode == AnonymityMode::DirectTor {
            return Err(factory_error(
                ErrorCode::InvalidConfiguration,
                RetryClass::Never,
                "private gateway runtime cannot construct Direct Tor mode",
            ));
        }
        if self.gateway_versions.minimum.major != self.gateway_versions.maximum.major
            || self.gateway_versions.minimum > self.gateway_versions.maximum
            || self.gateway_features.is_empty()
            || self.gateway_features.len() > MAX_FACTORY_FEATURES
            || self.gateway_features.iter().any(|feature| {
                feature.is_empty()
                    || feature.len() > MAX_FACTORY_FEATURE_BYTES
                    || !feature.is_ascii()
                    || feature.contains(['\r', '\n', '\0'])
            })
            || self.token_minimum_validity.is_zero()
            || self.token_minimum_validity > MAX_TOKEN_VALIDITY
        {
            return Err(factory_error(
                ErrorCode::InvalidConfiguration,
                RetryClass::Never,
                "client runtime configuration is invalid",
            ));
        }
        Ok(())
    }
}

/// Object-safe public factory accepted by CP-0006.
pub trait ClientRuntimeFactory: Send + Sync + VersionedContract {
    /// Builds a fully authenticated runtime. A returned value is ready to accept
    /// packets; partial Tor or gateway paths are never returned.
    fn create<'a>(
        &'a self,
        config: &'a ClientRuntimeConfig,
    ) -> BoxFuture<'a, OnionResult<PreparedClientRuntime>>;
}

/// A ready `ClientCore` plus the resources required for deterministic shutdown.
pub struct PreparedClientRuntime {
    core: ClientCore,
    tor: Arc<dyn TorBackend>,
    circuits: Arc<dyn CircuitManager>,
    gateway: Arc<dyn GatewayConnector>,
    route: RouteLease,
    session: GatewaySession,
    stopped: bool,
}

impl PreparedClientRuntime {
    /// Returns the packet core while retaining lifecycle ownership.
    pub fn core_mut(&mut self) -> &mut ClientCore {
        &mut self.core
    }

    /// Returns the independently verified active session descriptor.
    pub const fn session(&self) -> &GatewaySession {
        &self.session
    }

    /// Rechecks both Tor and the authenticated gateway session. The caller must
    /// stop packet intake immediately when this returns false.
    pub async fn protected_path_healthy(&self) -> bool {
        let tor_ready = self
            .tor
            .status()
            .await
            .map(|status| status.ready && status.bootstrap_percent == 100)
            .unwrap_or(false);
        let gateway_ready = self
            .gateway
            .session_state(&self.session)
            .await
            .map(|state| state == GatewaySessionState::Active)
            .unwrap_or(false);
        let unexpired = unix_now()
            .map(|now| self.session.expires_at_unix > now && self.route.expires_at_unix > now)
            .unwrap_or(false);
        tor_ready && gateway_ready && unexpired
    }

    /// Shuts down packet flows, gateway session, route and Tor in safe order.
    pub async fn shutdown(&mut self, monotonic_ms: u64) -> OnionResult<()> {
        if self.stopped {
            return Ok(());
        }
        self.stopped = true;
        let _ = self.core.shutdown(monotonic_ms).await;
        let mut first_error = None;
        if let Err(error) = self.gateway.begin_draining(&self.session).await {
            first_error.get_or_insert(error);
        }
        if let Err(error) = self.gateway.close(&self.session).await {
            first_error.get_or_insert(error);
        }
        if let Err(error) = self.circuits.retire_route(&self.route).await {
            first_error.get_or_insert(error);
        }
        if let Err(error) = self.tor.shutdown().await {
            first_error.get_or_insert(error);
        }
        first_error.map_or(Ok(()), Err)
    }
}

/// Production orchestration over injected, versioned component contracts.
pub struct ProductionClientRuntimeFactory {
    tor: Arc<dyn TorBackend>,
    circuits: Arc<dyn CircuitManager>,
    gateway: Arc<dyn GatewayConnector>,
    directory: Arc<dyn GatewayDirectoryProvider>,
    tokens: Arc<dyn TokenProvider>,
    policy: Arc<dyn PolicyEngine>,
}

impl ProductionClientRuntimeFactory {
    /// Creates a factory. Concrete components remain injected so mobile shells
    /// cannot silently replace production dependencies with direct sockets.
    pub fn new(
        tor: Arc<dyn TorBackend>,
        circuits: Arc<dyn CircuitManager>,
        gateway: Arc<dyn GatewayConnector>,
        directory: Arc<dyn GatewayDirectoryProvider>,
        tokens: Arc<dyn TokenProvider>,
        policy: Arc<dyn PolicyEngine>,
    ) -> Self {
        Self {
            tor,
            circuits,
            gateway,
            directory,
            tokens,
            policy,
        }
    }

    async fn create_inner(
        &self,
        config: &ClientRuntimeConfig,
    ) -> OnionResult<PreparedClientRuntime> {
        config.validate()?;
        let tor_status = self.tor.bootstrap(&config.tor).await?;
        if !tor_status.ready || tor_status.bootstrap_percent != 100 {
            let _ = self.tor.shutdown().await;
            return Err(factory_error(
                ErrorCode::TorUnavailable,
                RetryClass::Backoff,
                "Tor did not provide an independently ready path",
            ));
        }

        let result = self.create_after_tor(config).await;
        if result.is_err() {
            let _ = self.tor.shutdown().await;
        }
        result
    }

    async fn create_after_tor(
        &self,
        config: &ClientRuntimeConfig,
    ) -> OnionResult<PreparedClientRuntime> {
        let now = unix_now()?;
        let directory = match self.directory.load_cached().await? {
            Some(directory)
                if directory.issued_at_unix <= now && directory.valid_until_unix > now =>
            {
                directory
            }
            _ => {
                self.directory
                    .refresh(onionroute_common_types::types::DirectoryRefreshReason::Initial)
                    .await?
            }
        };
        if directory.issued_at_unix > now || directory.valid_until_unix <= now {
            return Err(factory_error(
                ErrorCode::DirectoryExpired,
                RetryClass::AfterDirectoryRefresh,
                "verified gateway directory is outside its validity window",
            ));
        }

        let plan = self
            .policy
            .select_gateway_plan(&directory, &config.route)
            .await?;
        if plan.mode != config.route.mode || plan.hops.is_empty() {
            return Err(factory_error(
                ErrorCode::GatewayUnavailable,
                RetryClass::AfterDirectoryRefresh,
                "gateway policy returned an invalid private route",
            ));
        }

        let mut per_hop = Vec::with_capacity(plan.hops.len());
        for _ in &plan.hops {
            per_hop.push(
                self.tokens
                    .acquire(&TokenRequest {
                        capabilities: config.gateway_features.clone(),
                        mode: plan.mode,
                        minimum_validity: config.token_minimum_validity,
                    })
                    .await?,
            );
        }
        let credentials = GatewayCredentials::new(per_hop).ok_or_else(|| {
            factory_error(
                ErrorCode::TokenUnavailable,
                RetryClass::AfterTokenRefresh,
                "gateway credentials do not match the selected route",
            )
        })?;

        let route = self
            .circuits
            .prepare_route(&plan, RotationReason::Scheduled)
            .await?;
        if route.plan != plan || route.expires_at_unix <= now {
            let _ = self.circuits.retire_route(&route).await;
            return Err(factory_error(
                ErrorCode::TorUnavailable,
                RetryClass::Backoff,
                "circuit manager returned an invalid route lease",
            ));
        }
        let transport = match self.circuits.open_first_hop(&route).await {
            Ok(transport) => transport,
            Err(error) => {
                let _ = self.circuits.retire_route(&route).await;
                return Err(error);
            }
        };

        let dial = GatewayDialRequest {
            plan: plan.clone(),
            supported_versions: config.gateway_versions,
            requested_features: config.gateway_features.clone(),
        };
        let session = match self.gateway.connect(transport, &dial, credentials).await {
            Ok(session) => session,
            Err(error) => {
                let _ = self.circuits.retire_route(&route).await;
                return Err(error);
            }
        };
        let session_state = self.gateway.session_state(&session).await;
        let terminal = plan
            .hops
            .last()
            .expect("private route was checked non-empty");
        let session_valid = session_state.as_ref() == Ok(&GatewaySessionState::Active)
            && session.state == GatewaySessionState::Active
            && session.gateway_id == terminal.gateway_id
            && session.role == terminal.role
            && session.expires_at_unix > now
            && session.max_concurrent_streams > 0
            && config.gateway_versions.negotiate(ProtocolVersionRange {
                minimum: session.protocol_version,
                maximum: session.protocol_version,
            }) == Some(session.protocol_version);
        if !session_valid {
            let _ = self.gateway.close(&session).await;
            let _ = self.circuits.retire_route(&route).await;
            return Err(session_state.err().unwrap_or_else(|| {
                factory_error(
                    ErrorCode::GatewayIdentityMismatch,
                    RetryClass::AfterDirectoryRefresh,
                    "gateway session does not match the verified route",
                )
            }));
        }

        let packet = match PacketProcessor::new(config.packet, Arc::new(NoopMetrics)) {
            Some(packet) => packet,
            None => {
                let _ = self.gateway.close(&session).await;
                let _ = self.circuits.retire_route(&route).await;
                return Err(factory_error(
                    ErrorCode::InvalidConfiguration,
                    RetryClass::Never,
                    "packet engine limits are invalid",
                ));
            }
        };
        let dns = match SyntheticDnsEngine::new(config.dns) {
            Some(dns) => Arc::new(dns),
            None => {
                let _ = self.gateway.close(&session).await;
                let _ = self.circuits.retire_route(&route).await;
                return Err(factory_error(
                    ErrorCode::InvalidConfiguration,
                    RetryClass::Never,
                    "DNS engine limits are invalid",
                ));
            }
        };
        let dispatcher = match ConnectionDispatcher::new(
            config.dispatcher,
            self.gateway.clone(),
            session.clone(),
        ) {
            Some(dispatcher) => dispatcher,
            None => {
                let _ = self.gateway.close(&session).await;
                let _ = self.circuits.retire_route(&route).await;
                return Err(factory_error(
                    ErrorCode::InvalidConfiguration,
                    RetryClass::Never,
                    "dispatcher limits are invalid",
                ));
            }
        };
        let core = ClientCore::new(
            packet,
            dns,
            self.policy.clone(),
            dispatcher,
            ActiveRoute {
                isolation_key: route.isolation_key.clone(),
                anonymity_profile: plan.mode,
                gateway_id: Some(terminal.gateway_id.clone()),
            },
        );
        Ok(PreparedClientRuntime {
            core,
            tor: self.tor.clone(),
            circuits: self.circuits.clone(),
            gateway: self.gateway.clone(),
            route,
            session,
            stopped: false,
        })
    }
}

impl VersionedContract for ProductionClientRuntimeFactory {
    fn contract_version(&self) -> ContractVersion {
        CONTRACT_V1
    }
}

impl ClientRuntimeFactory for ProductionClientRuntimeFactory {
    fn create<'a>(
        &'a self,
        config: &'a ClientRuntimeConfig,
    ) -> BoxFuture<'a, OnionResult<PreparedClientRuntime>> {
        Box::pin(async move { self.create_inner(config).await })
    }
}

fn unix_now() -> OnionResult<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            factory_error(
                ErrorCode::InvalidConfiguration,
                RetryClass::Never,
                "system clock is before the Unix epoch",
            )
        })?
        .as_secs();
    i64::try_from(seconds).map_err(|_| {
        factory_error(
            ErrorCode::InvalidConfiguration,
            RetryClass::Never,
            "system clock exceeds supported range",
        )
    })
}

fn factory_error(code: ErrorCode, retry: RetryClass, message: &'static str) -> OnionError {
    OnionError::new(
        ErrorDomain::Configuration,
        code,
        Severity::Error,
        retry,
        SafetyImpact::MustBlock,
        message,
    )
}

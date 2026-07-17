use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use onionroute_common_types::contracts::v1::CircuitManager as CircuitManagerContract;
use onionroute_common_types::error::{ErrorCode, RetryClass, SafetyImpact, Severity};
use onionroute_common_types::transport::{BoxFuture, BoxTransport};
use onionroute_common_types::types::{
    AnonymityMode, GatewayPlan, GatewayRole, RotationCandidate, RotationReason, RouteId,
    RouteLease, TcpFlowRequest,
};
use onionroute_common_types::version::{ContractVersion, VersionedContract, CONTRACT_V1};
use onionroute_common_types::{OnionError, OnionResult};
use onionroute_tor_backend::{IsolationContext, IsolationScope, RotationOutcome, TorBackendExt};
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

use crate::{circuit_error, IsolationManager, RotationObserver, RotationScheduler};

const ROUTE_ID_ATTEMPTS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Locally owned route lifecycle.
pub enum RouteState {
    /// Isolation and lease exist, but no first-hop stream has opened.
    Prepared,
    /// At least one protected first-hop stream opened successfully.
    Active,
    /// No new work should attach while existing flows drain.
    Draining,
}

#[derive(Clone, Debug)]
/// Bounded route and disruptive-rotation limits.
pub struct CircuitManagerConfig {
    /// Maximum simultaneously owned route leases.
    pub maximum_routes: usize,
    /// Absolute lifetime assigned to each new route lease.
    pub route_ttl: Duration,
    /// Minimum time between disruptive hard rotations.
    pub hard_rotation_minimum_interval: Duration,
}

impl Default for CircuitManagerConfig {
    fn default() -> Self {
        Self {
            maximum_routes: 128,
            route_ttl: Duration::from_secs(45 * 60),
            hard_rotation_minimum_interval: Duration::from_secs(10),
        }
    }
}

impl CircuitManagerConfig {
    fn validate(&self) -> OnionResult<()> {
        if self.maximum_routes == 0
            || self.maximum_routes > 4_096
            || self.route_ttl < Duration::from_secs(60)
            || self.route_ttl > Duration::from_secs(24 * 60 * 60)
            || self.hard_rotation_minimum_interval < Duration::from_secs(10)
            || self.hard_rotation_minimum_interval > Duration::from_secs(5 * 60)
        {
            return Err(circuit_error(
                ErrorCode::InvalidConfiguration,
                Severity::Error,
                RetryClass::Never,
                SafetyImpact::NotApplicable,
                "invalid circuit manager configuration",
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
struct RouteRecord {
    lease: RouteLease,
    context: IsolationContext,
    state: RouteState,
}

#[derive(Clone, Debug)]
/// New root context and disruption count returned by hard/identity reset.
pub struct IdentityResetResult {
    /// First context allocated in the new identity epoch.
    pub context: IsolationContext,
    /// Backend-reported streams cancelled by hard rotation.
    pub closed_streams: usize,
}

/// Concrete owner of Tor routes and identity transitions.
pub struct CircuitManager {
    backend: Arc<dyn TorBackendExt>,
    isolation: IsolationManager,
    observer: Arc<dyn RotationObserver>,
    config: CircuitManagerConfig,
    routes: Mutex<HashMap<RouteId, RouteRecord>>,
    rotation_lock: AsyncMutex<()>,
    hard_rotation_gate: AsyncMutex<Option<Instant>>,
}

impl CircuitManager {
    /// Creates a manager over an implementation-neutral backend and client callbacks.
    pub fn new(
        backend: Arc<dyn TorBackendExt>,
        observer: Arc<dyn RotationObserver>,
        config: CircuitManagerConfig,
    ) -> OnionResult<Self> {
        config.validate()?;
        Ok(Self {
            isolation: IsolationManager::new(Arc::clone(&backend)),
            backend,
            observer,
            config,
            routes: Mutex::new(HashMap::new()),
            rotation_lock: AsyncMutex::new(()),
            hard_rotation_gate: AsyncMutex::new(None),
        })
    }

    /// Returns the owned isolation manager for orchestration and diagnostics.
    pub fn isolation_manager(&self) -> &IsolationManager {
        &self.isolation
    }

    /// Returns the bounded number of live route records.
    pub fn route_count(&self) -> OnionResult<usize> {
        Ok(self.routes.lock().map_err(|_| route_invariant())?.len())
    }

    /// Returns the local lifecycle of an opaque route identifier.
    pub fn route_state(&self, route: RouteId) -> OnionResult<Option<RouteState>> {
        Ok(self
            .routes
            .lock()
            .map_err(|_| route_invariant())?
            .get(&route)
            .map(|record| record.state))
    }

    async fn prepare_route_impl(&self, plan: &GatewayPlan) -> OnionResult<RouteLease> {
        validate_plan(plan)?;
        if self.routes.lock().map_err(|_| route_invariant())?.len() >= self.config.maximum_routes {
            return Err(route_capacity_error());
        }
        let scope = IsolationScope {
            application: None,
            anonymity_profile: plan.mode,
            gateway: plan.hops.first().map(|hop| hop.gateway_id.0.clone()),
            destination_group: if plan.mode == AnonymityMode::DirectTor {
                "direct-tor-route".to_owned()
            } else {
                "private-gateway-first-hop".to_owned()
            },
            browser_container: None,
        };
        let context = self.isolation.allocate(scope).await?;
        let route_id = {
            let routes = self.routes.lock().map_err(|_| route_invariant())?;
            random_route_id(&routes)?
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| route_invariant())?
            .as_secs();
        let expires = now
            .saturating_add(self.config.route_ttl.as_secs())
            .min(i64::MAX as u64) as i64;
        let lease = RouteLease {
            route_id,
            plan: plan.clone(),
            isolation_key: context.key.clone(),
            expires_at_unix: expires,
        };
        let inserted = {
            let mut routes = self.routes.lock().map_err(|_| route_invariant())?;
            if routes.len() >= self.config.maximum_routes || routes.contains_key(&route_id) {
                false
            } else {
                routes.insert(
                    route_id,
                    RouteRecord {
                        lease: lease.clone(),
                        context: context.clone(),
                        state: RouteState::Prepared,
                    },
                );
                true
            }
        };
        if !inserted {
            self.isolation.release(&context).await?;
            return Err(route_capacity_error());
        }
        Ok(lease)
    }

    async fn open_first_hop_impl(&self, route: &RouteLease) -> OnionResult<BoxTransport> {
        let (endpoint, isolation) = {
            let routes = self.routes.lock().map_err(|_| route_invariant())?;
            let record = routes
                .get(&route.route_id)
                .filter(|record| record.lease == *route)
                .ok_or_else(route_invariant)?;
            if route.plan.mode == AnonymityMode::DirectTor {
                return Err(circuit_error(
                    ErrorCode::InvalidConfiguration,
                    Severity::Error,
                    RetryClass::Never,
                    SafetyImpact::Protected,
                    "Direct Tor requires the explicit direct stream API",
                ));
            }
            if route_is_expired(route) {
                return Err(circuit_error(
                    ErrorCode::SessionExpired,
                    Severity::Error,
                    RetryClass::Never,
                    SafetyImpact::Protected,
                    "Tor route lease expired",
                ));
            }
            let endpoint = route
                .plan
                .hops
                .first()
                .ok_or_else(route_invariant)?
                .onion_endpoint
                .clone();
            (endpoint, record.context.key.clone())
        };
        let mut stream = self
            .backend
            .open_onion_stream(&endpoint, &isolation)
            .await?;
        let still_owned = {
            let mut routes = self.routes.lock().map_err(|_| route_invariant())?;
            if let Some(record) = routes.get_mut(&route.route_id) {
                if record.lease == *route {
                    record.state = RouteState::Active;
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };
        if !still_owned {
            let _ = stream.close().await;
            return Err(route_invariant());
        }
        Ok(stream)
    }

    /// Explicit Direct Tor path. It cannot be reached as fallback from a private route.
    pub async fn open_direct_stream(
        &self,
        request: &TcpFlowRequest,
        destination_group: String,
        browser_container: Option<String>,
    ) -> OnionResult<BoxTransport> {
        let scope = IsolationScope {
            application: request
                .application
                .as_ref()
                .map(|application| application.0.clone()),
            anonymity_profile: AnonymityMode::DirectTor,
            gateway: None,
            destination_group,
            browser_container,
        };
        let context = self.isolation.allocate(scope).await?;
        self.backend.open_direct_stream(request, &context.key).await
    }

    /// Changes only the default epoch. Existing transports and route records remain live.
    pub async fn soft_rotate(&self) -> OnionResult<RotationOutcome> {
        let _rotation = self.rotation_lock.lock().await;
        let outcome = self.backend.request_soft_rotation().await?;
        if outcome.closed_streams != 0 {
            return Err(route_invariant());
        }
        self.isolation.install_soft_epoch(outcome.new_epoch)?;
        Ok(outcome)
    }

    /// Runs one scheduled soft-rotation tick when the shared anti-stampede gate permits it.
    ///
    /// A denied tick is intentionally skipped instead of retried immediately. Every context
    /// therefore draws a new full-window delay before its next attempt.
    pub async fn automatic_rotation_tick(
        &self,
        scheduler: &RotationScheduler,
        now: Instant,
    ) -> OnionResult<bool> {
        if !scheduler.try_acquire(now)? {
            return Ok(false);
        }
        self.soft_rotate().await?;
        Ok(true)
    }

    /// Runs automatic soft rotation until explicit cancellation or the first rotation error.
    ///
    /// The loop has no internal retry path: a backend failure is returned to client-core so it
    /// can keep the tunnel fail-closed and apply its bounded recovery policy.
    pub async fn run_automatic_rotation(
        &self,
        profile: AnonymityMode,
        scheduler: &RotationScheduler,
        cancellation: CancellationToken,
    ) -> OnionResult<()> {
        loop {
            let delay = scheduler.next_delay(profile)?;
            tokio::select! {
                _ = cancellation.cancelled() => return Ok(()),
                _ = tokio::time::sleep(delay) => {}
            }
            self.automatic_rotation_tick(scheduler, Instant::now())
                .await?;
        }
    }

    /// Notifies client-core, closes active streams, clears isolation ownership,
    /// and allocates the first context of a new epoch.
    pub async fn hard_rotate(
        &self,
        profile: AnonymityMode,
        reason: RotationReason,
    ) -> OnionResult<IdentityResetResult> {
        let _rotation = self.rotation_lock.lock().await;
        let mut gate = self.hard_rotation_gate.lock().await;
        if gate
            .map(|last| last.elapsed() < self.config.hard_rotation_minimum_interval)
            .unwrap_or(false)
        {
            return Err(circuit_error(
                ErrorCode::RotationDeferred,
                Severity::Warning,
                RetryClass::Backoff,
                SafetyImpact::Protected,
                "hard rotation is rate limited",
            ));
        }

        let mut first_error: Option<OnionError> = None;
        capture_error(
            &mut first_error,
            self.observer.hard_rotation_started(reason).await,
        );
        capture_error(&mut first_error, self.observer.close_active_streams().await);
        let outcome = match self.backend.request_hard_rotation().await {
            Ok(outcome) => outcome,
            Err(error) => {
                first_error.get_or_insert(error);
                return Err(match first_error {
                    Some(error) => error,
                    None => route_invariant(),
                });
            }
        };
        *gate = Some(Instant::now());
        drop(gate);

        if let Err(error) = self.isolation.install_hard_epoch(outcome.new_epoch) {
            first_error.get_or_insert(error);
        }
        match self.routes.lock() {
            Ok(mut routes) => routes.clear(),
            Err(_) => {
                first_error.get_or_insert_with(route_invariant);
            }
        }
        let context = self
            .isolation
            .allocate(IsolationScope {
                application: None,
                anonymity_profile: profile,
                gateway: None,
                destination_group: "identity-epoch-root".to_owned(),
                browser_container: None,
            })
            .await;
        let context = match context {
            Ok(context) => context,
            Err(error) => {
                first_error.get_or_insert(error);
                return Err(match first_error {
                    Some(error) => error,
                    None => route_invariant(),
                });
            }
        };
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(IdentityResetResult {
            context,
            closed_streams: outcome.closed_streams,
        })
    }

    /// Performs hard rotation followed by DNS, gateway-session and transient-state cleanup.
    pub async fn identity_reset(&self, profile: AnonymityMode) -> OnionResult<IdentityResetResult> {
        let result = self
            .hard_rotate(profile, RotationReason::UserRequested)
            .await;
        if matches!(&result, Err(error) if error.code == ErrorCode::RotationDeferred) {
            return result;
        }
        let mut first_error = result.as_ref().err().cloned();
        capture_error(&mut first_error, self.observer.flush_dns_state().await);
        capture_error(
            &mut first_error,
            self.observer.revoke_temporary_gateway_session().await,
        );
        capture_error(
            &mut first_error,
            self.observer.clear_transient_state().await,
        );
        if let Some(error) = first_error {
            return Err(error);
        }
        result
    }

    /// Stops assigning new work to an existing route.
    pub async fn begin_draining(&self, route: RouteId) -> OnionResult<()> {
        let mut routes = self.routes.lock().map_err(|_| route_invariant())?;
        let record = routes.get_mut(&route).ok_or_else(route_invariant)?;
        record.state = RouteState::Draining;
        Ok(())
    }

    async fn retire_route_impl(&self, route: &RouteLease) -> OnionResult<()> {
        let record = {
            let mut routes = self.routes.lock().map_err(|_| route_invariant())?;
            if let Some(record) = routes.get(&route.route_id) {
                if record.lease != *route {
                    return Err(route_invariant());
                }
            }
            routes.remove(&route.route_id)
        };
        if let Some(record) = record {
            self.isolation.release(&record.context).await?;
        }
        Ok(())
    }
}

impl VersionedContract for CircuitManager {
    fn contract_version(&self) -> ContractVersion {
        CONTRACT_V1
    }
}

impl CircuitManagerContract for CircuitManager {
    fn prepare_route<'a>(
        &'a self,
        plan: &'a GatewayPlan,
        _reason: RotationReason,
    ) -> BoxFuture<'a, OnionResult<RouteLease>> {
        Box::pin(async move { self.prepare_route_impl(plan).await })
    }

    fn open_first_hop<'a>(
        &'a self,
        route: &'a RouteLease,
    ) -> BoxFuture<'a, OnionResult<BoxTransport>> {
        Box::pin(async move { self.open_first_hop_impl(route).await })
    }

    fn prepare_rotation<'a>(
        &'a self,
        current: &'a RouteLease,
        replacement: &'a GatewayPlan,
        _reason: RotationReason,
    ) -> BoxFuture<'a, OnionResult<RotationCandidate>> {
        Box::pin(async move {
            {
                let routes = self.routes.lock().map_err(|_| route_invariant())?;
                if !routes
                    .get(&current.route_id)
                    .map(|record| record.lease == *current)
                    .unwrap_or(false)
                {
                    return Err(route_invariant());
                }
            }
            let route = self.prepare_route_impl(replacement).await?;
            match self.open_first_hop_impl(&route).await {
                Ok(mut transport) => {
                    let current_still_owned = self
                        .routes
                        .lock()
                        .map_err(|_| route_invariant())?
                        .get(&current.route_id)
                        .map(|record| record.lease == *current)
                        .unwrap_or(false);
                    if !current_still_owned {
                        let _ = transport.close().await;
                        let _ = self.retire_route_impl(&route).await;
                        return Err(route_invariant());
                    }
                    Ok(RotationCandidate { route, transport })
                }
                Err(error) => {
                    let _ = self.retire_route_impl(&route).await;
                    Err(error)
                }
            }
        })
    }

    fn retire_route<'a>(&'a self, route: &'a RouteLease) -> BoxFuture<'a, OnionResult<()>> {
        Box::pin(async move { self.retire_route_impl(route).await })
    }
}

fn validate_plan(plan: &GatewayPlan) -> OnionResult<()> {
    let roles: Vec<_> = plan.hops.iter().map(|hop| hop.role).collect();
    let valid = match plan.mode {
        AnonymityMode::Standard => roles == [GatewayRole::Exit],
        AnonymityMode::Enhanced => roles == [GatewayRole::Entry, GatewayRole::Exit],
        AnonymityMode::Maximum => {
            roles == [GatewayRole::Entry, GatewayRole::Relay, GatewayRole::Exit]
        }
        AnonymityMode::DirectTor => roles.is_empty(),
    };
    if !valid {
        return Err(circuit_error(
            ErrorCode::InvalidConfiguration,
            Severity::Error,
            RetryClass::Never,
            SafetyImpact::Protected,
            "gateway plan roles do not match anonymity profile",
        ));
    }
    Ok(())
}

fn random_route_id(routes: &HashMap<RouteId, RouteRecord>) -> OnionResult<RouteId> {
    for _ in 0..ROUTE_ID_ATTEMPTS {
        let mut bytes = [0_u8; 16];
        OsRng.fill_bytes(&mut bytes);
        let id = RouteId(bytes);
        if !routes.contains_key(&id) {
            return Ok(id);
        }
    }
    Err(route_invariant())
}

fn route_is_expired(route: &RouteLease) -> bool {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|now| now.as_secs() > route.expires_at_unix.max(0) as u64)
        .unwrap_or(true)
}

fn capture_error(first: &mut Option<OnionError>, result: OnionResult<()>) {
    if let Err(error) = result {
        first.get_or_insert(error);
    }
}

fn route_capacity_error() -> OnionError {
    circuit_error(
        ErrorCode::Backpressure,
        Severity::Error,
        RetryClass::Backoff,
        SafetyImpact::Protected,
        "Tor route capacity is exhausted",
    )
}

fn route_invariant() -> OnionError {
    circuit_error(
        ErrorCode::InvariantViolation,
        Severity::Fatal,
        RetryClass::Never,
        SafetyImpact::MustBlock,
        "Tor route ownership invariant failed",
    )
}

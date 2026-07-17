use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use onionroute_common_types::contracts::v1::TorBackend;
use onionroute_common_types::error::{ErrorCode, RetryClass, SafetyImpact, Severity};
use onionroute_common_types::transport::{BoxFuture, BoxTransport};
use onionroute_common_types::types::{
    IsolationKey, OnionEndpoint, TcpFlowRequest, TorBootstrapConfig, TorStatus,
};
use onionroute_common_types::version::{ContractVersion, VersionedContract, CONTRACT_V1};
use onionroute_common_types::OnionResult;
use rand::rngs::OsRng;
use rand::RngCore;
use tempfile::TempDir;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::backoff::{BoundedBackoff, RetryPolicy};
use crate::control::{ControlClient, ControlEndpoint};
use crate::socks;
use crate::transport::ManagedTorStream;
use crate::types::{
    configuration_error, tor_error, BackendHealth, BackendLifecycle, BridgeConfig,
    ClientTransportPlugin, IsolationContext, IsolationScope, ProxyConfig, RotationOutcome,
    TorBackendExt,
};

const MAX_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MIN_NEWNYM_INTERVAL: Duration = Duration::from_secs(10);
const CONTEXT_COLLISION_ATTEMPTS: usize = 8;

/// C Tor process configuration. Sensitive destinations never enter this type.
#[derive(Clone, Debug)]
pub struct CTorConfig {
    /// C Tor executable name or absolute path.
    pub tor_binary: PathBuf,
    /// Parent for a unique, deleted-on-stop data directory.
    pub state_parent: Option<PathBuf>,
    /// Deadline for process, control endpoint and authentication startup.
    pub startup_timeout: Duration,
    /// Deadline for graceful or forced process shutdown.
    pub shutdown_timeout: Duration,
    /// Deadline for a complete SOCKS connection handshake.
    pub stream_timeout: Duration,
    /// Interval used by the independent child-process watcher.
    pub health_poll_interval: Duration,
    /// Maximum simultaneous isolation keys retained by this process.
    pub max_isolation_contexts: usize,
    /// Finite full-jitter policy for startup and bootstrap polling.
    pub retry_policy: RetryPolicy,
    /// Enables C Tor's seccomp sandbox where the platform supports it.
    pub enable_platform_sandbox: bool,
    /// Initial bridge and pluggable-transport configuration.
    pub bridges: BridgeConfig,
    /// Optional initial upstream proxy for Tor OR connections.
    pub proxy: Option<ProxyConfig>,
}

impl Default for CTorConfig {
    fn default() -> Self {
        Self {
            tor_binary: PathBuf::from("tor"),
            state_parent: None,
            startup_timeout: Duration::from_secs(15),
            shutdown_timeout: Duration::from_secs(10),
            stream_timeout: Duration::from_secs(60),
            health_poll_interval: Duration::from_millis(500),
            max_isolation_contexts: 4_096,
            retry_policy: RetryPolicy::default(),
            enable_platform_sandbox: cfg!(target_os = "linux"),
            bridges: BridgeConfig::default(),
            proxy: None,
        }
    }
}

impl CTorConfig {
    fn validate(&self) -> OnionResult<()> {
        if self.tor_binary.as_os_str().is_empty()
            || self.startup_timeout.is_zero()
            || self.startup_timeout > Duration::from_secs(120)
            || self.shutdown_timeout.is_zero()
            || self.shutdown_timeout > Duration::from_secs(60)
            || self.stream_timeout.is_zero()
            || self.stream_timeout > Duration::from_secs(5 * 60)
            || self.health_poll_interval < Duration::from_millis(100)
            || self.health_poll_interval > Duration::from_secs(30)
            || self.max_isolation_contexts == 0
            || self.max_isolation_contexts > 65_536
        {
            return Err(configuration_error("invalid C Tor backend configuration"));
        }
        if let Some(parent) = &self.state_parent {
            if !parent.is_dir() {
                return Err(configuration_error("Tor state parent is not a directory"));
            }
        }
        self.retry_policy.validate()?;
        self.bridges.validate()?;
        Ok(())
    }
}

#[derive(Clone)]
struct RuntimeOptions {
    bridges: BridgeConfig,
    proxy: Option<ProxyConfig>,
}

struct RuntimeState {
    generation: u64,
    process: Child,
    control: ControlClient,
    socks_address: SocketAddr,
    #[allow(dead_code)]
    data_directory: TempDir,
}

struct ContextRecord {
    epoch: u64,
    scope: Option<IsolationScope>,
    cancellation: CancellationToken,
}

#[derive(Clone, Copy)]
struct StateSnapshot {
    lifecycle: BackendLifecycle,
    progress: u8,
}

struct Inner {
    config: CTorConfig,
    options: RwLock<RuntimeOptions>,
    state: RwLock<StateSnapshot>,
    runtime: Mutex<Option<RuntimeState>>,
    start_guard: Mutex<()>,
    contexts: Mutex<HashMap<[u8; 32], ContextRecord>>,
    epoch: AtomicU64,
    active_streams: Arc<AtomicUsize>,
    generation: AtomicU64,
    last_newnym: Mutex<Option<Instant>>,
}

/// Managed C Tor backend.
///
/// Each instance owns one child process, one private data directory and many
/// independently isolated SOCKS contexts. Clone only clones the process handle;
/// it does not start another Tor process.
#[derive(Clone)]
pub struct CTorBackend {
    inner: Arc<Inner>,
}

impl CTorBackend {
    /// Validates configuration and constructs a stopped managed backend.
    pub fn new(config: CTorConfig) -> OnionResult<Self> {
        config.validate()?;
        Ok(Self {
            inner: Arc::new(Inner {
                options: RwLock::new(RuntimeOptions {
                    bridges: config.bridges.clone(),
                    proxy: config.proxy,
                }),
                config,
                state: RwLock::new(StateSnapshot {
                    lifecycle: BackendLifecycle::Stopped,
                    progress: 0,
                }),
                runtime: Mutex::new(None),
                start_guard: Mutex::new(()),
                contexts: Mutex::new(HashMap::new()),
                epoch: AtomicU64::new(0),
                active_streams: Arc::new(AtomicUsize::new(0)),
                generation: AtomicU64::new(0),
                last_newnym: Mutex::new(None),
            }),
        })
    }

    /// Abruptly terminates the child process for fault-injection tests.
    #[cfg(feature = "test-utils")]
    pub async fn terminate_process_for_test(&self) -> OnionResult<()> {
        let mut runtime = self.inner.runtime.lock().await;
        let runtime = runtime
            .as_mut()
            .ok_or_else(|| unavailable_error("Tor process is not running"))?;
        runtime
            .process
            .kill()
            .await
            .map_err(|_| unavailable_error("Tor test process termination failed"))
    }

    async fn start_impl(&self) -> OnionResult<TorStatus> {
        let _start_guard = self.inner.start_guard.lock().await;
        {
            let mut runtime = self.inner.runtime.lock().await;
            if let Some(running) = runtime.as_mut() {
                if running.process.try_wait().ok().flatten().is_none() {
                    let state = self.state();
                    return Ok(TorStatus {
                        bootstrap_percent: state.progress,
                        ready: state.lifecycle == BackendLifecycle::Ready,
                    });
                }
                runtime.take();
            }
        }
        self.set_state(BackendLifecycle::Starting, 0);

        let parent = self
            .inner
            .config
            .state_parent
            .clone()
            .unwrap_or_else(std::env::temp_dir);
        let data_directory = tempfile::Builder::new()
            .prefix("onionroute-tor-")
            .tempdir_in(parent)
            .map_err(|_| startup_error("could not create private Tor data directory"))?;
        secure_directory(data_directory.path())?;

        let options = self
            .inner
            .options
            .read()
            .map_err(|_| invariant_error())?
            .clone();
        let paths = TorPaths::new(data_directory.path());
        let torrc = render_torrc(&paths, &options, self.inner.config.enable_platform_sandbox)?;
        write_private_file(&paths.torrc, torrc.as_bytes())?;

        let mut command = Command::new(&self.inner.config.tor_binary);
        command
            .arg("-f")
            .arg(&paths.torrc)
            .arg("--ignore-missing-torrc")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut process = command
            .spawn()
            .map_err(|_| startup_error("could not start C Tor process"))?;

        let control_endpoint = match self.wait_for_control_endpoint(&mut process, &paths).await {
            Ok(endpoint) => endpoint,
            Err(error) => {
                let _ = process.kill().await;
                self.set_state(BackendLifecycle::FailedClosed, 0);
                return Err(error);
            }
        };
        let mut control = match ControlClient::connect_and_authenticate(
            &control_endpoint,
            &paths.cookie,
            self.inner.config.startup_timeout,
        )
        .await
        {
            Ok(control) => control,
            Err(error) => {
                let _ = process.kill().await;
                self.set_state(BackendLifecycle::FailedClosed, 0);
                return Err(error);
            }
        };
        let socks_address = match read_socks_listener(&mut control).await {
            Ok(address) => address,
            Err(error) => {
                let _ = control.command("SIGNAL SHUTDOWN").await;
                let _ = process.kill().await;
                self.set_state(BackendLifecycle::FailedClosed, 0);
                return Err(error);
            }
        };

        let generation = self.inner.generation.fetch_add(1, Ordering::AcqRel) + 1;
        *self.inner.runtime.lock().await = Some(RuntimeState {
            generation,
            process,
            control,
            socks_address,
            data_directory,
        });
        self.set_state(BackendLifecycle::Bootstrapping, 0);
        self.spawn_process_monitor(generation);
        Ok(TorStatus {
            bootstrap_percent: 0,
            ready: false,
        })
    }

    async fn wait_for_control_endpoint(
        &self,
        process: &mut Child,
        paths: &TorPaths,
    ) -> OnionResult<ControlEndpoint> {
        #[cfg(unix)]
        let expected = ControlEndpoint::Unix(paths.control_socket.clone());

        let deadline = Instant::now() + self.inner.config.startup_timeout;
        let mut backoff = BoundedBackoff::new(self.inner.config.retry_policy, OsRng)?;
        loop {
            if process
                .try_wait()
                .map_err(|_| startup_error("could not inspect C Tor process"))?
                .is_some()
            {
                return Err(startup_error("C Tor exited during startup"));
            }
            #[cfg(unix)]
            if paths.control_socket.exists() {
                return Ok(expected);
            }
            #[cfg(not(unix))]
            if let Ok(contents) = std::fs::read_to_string(&paths.control_port_file) {
                if let Some(address) = parse_control_port_file(&contents) {
                    return Ok(ControlEndpoint::Tcp(address));
                }
            }
            if Instant::now() >= deadline {
                return Err(startup_error("C Tor control endpoint startup timed out"));
            }
            let Some(delay) = backoff.next_delay() else {
                return Err(startup_error(
                    "C Tor control endpoint retry budget exhausted",
                ));
            };
            tokio::time::sleep(delay.min(deadline.saturating_duration_since(Instant::now()))).await;
        }
    }

    async fn bootstrap_impl(&self, config: &TorBootstrapConfig) -> OnionResult<TorStatus> {
        if config.timeout.is_zero() || config.timeout > MAX_BOOTSTRAP_TIMEOUT {
            return Err(configuration_error("invalid Tor bootstrap deadline"));
        }
        let options = self
            .inner
            .options
            .read()
            .map_err(|_| invariant_error())?
            .clone();
        if (config.bridges_required || options.bridges.required)
            && options.bridges.bridges.is_empty()
        {
            return Err(configuration_error(
                "bridges are required but not configured",
            ));
        }
        self.start_impl().await?;
        let deadline = Instant::now() + config.timeout;
        let mut backoff = BoundedBackoff::new(self.inner.config.retry_policy, OsRng)?;
        loop {
            match self.probe_status().await {
                Ok(status) if status.ready => return Ok(status),
                Ok(_) => {}
                Err(error) if error.code == ErrorCode::TorUnavailable => return Err(error),
                Err(error) => return Err(error),
            }
            if Instant::now() >= deadline {
                self.set_state(BackendLifecycle::Degraded, self.state().progress);
                return Err(tor_error(
                    ErrorCode::TorBootstrapTimeout,
                    Severity::Error,
                    RetryClass::Backoff,
                    SafetyImpact::Protected,
                    "Tor bootstrap deadline expired",
                ));
            }
            let Some(delay) = backoff.next_delay() else {
                self.set_state(BackendLifecycle::Degraded, self.state().progress);
                return Err(tor_error(
                    ErrorCode::TorBootstrapTimeout,
                    Severity::Error,
                    RetryClass::Backoff,
                    SafetyImpact::Protected,
                    "Tor bootstrap retry budget exhausted",
                ));
            };
            tokio::time::sleep(delay.min(deadline.saturating_duration_since(Instant::now()))).await;
        }
    }

    async fn probe_status(&self) -> OnionResult<TorStatus> {
        let response = {
            let mut runtime_guard = self.inner.runtime.lock().await;
            let runtime = runtime_guard
                .as_mut()
                .ok_or_else(|| unavailable_error("Tor process is not running"))?;
            if runtime
                .process
                .try_wait()
                .map_err(|_| unavailable_error("Tor process status failed"))?
                .is_some()
            {
                drop(runtime_guard);
                self.fail_closed().await;
                return Err(unavailable_error("Tor process terminated"));
            }
            runtime
                .control
                .command("GETINFO status/bootstrap-phase")
                .await?
        };
        let progress = parse_bootstrap_progress(&response).ok_or_else(|| {
            tor_error(
                ErrorCode::TorUnavailable,
                Severity::Error,
                RetryClass::Backoff,
                SafetyImpact::Protected,
                "Tor bootstrap status is malformed",
            )
        })?;
        let lifecycle = if progress == 100 {
            BackendLifecycle::Ready
        } else {
            BackendLifecycle::Bootstrapping
        };
        self.set_state(lifecycle, progress);
        Ok(TorStatus {
            bootstrap_percent: progress,
            ready: progress == 100,
        })
    }

    async fn stop_impl(&self) -> OnionResult<()> {
        let _start_guard = self.inner.start_guard.lock().await;
        self.set_state(BackendLifecycle::Stopping, self.state().progress);
        self.cancel_and_clear_contexts().await;
        let runtime = self.inner.runtime.lock().await.take();
        let Some(mut runtime) = runtime else {
            self.set_state(BackendLifecycle::Stopped, 0);
            return Ok(());
        };

        let graceful_command = runtime.control.command("SIGNAL SHUTDOWN").await;
        let graceful_exit =
            tokio::time::timeout(self.inner.config.shutdown_timeout, runtime.process.wait()).await;
        let forced = graceful_command.is_err() || graceful_exit.is_err();
        if forced {
            let _ = runtime.process.kill().await;
            let _ =
                tokio::time::timeout(self.inner.config.shutdown_timeout, runtime.process.wait())
                    .await;
        }
        self.set_state(BackendLifecycle::Stopped, 0);
        if forced {
            return Err(tor_error(
                ErrorCode::ShutdownTimeout,
                Severity::Error,
                RetryClass::Never,
                SafetyImpact::MustBlock,
                "C Tor required forced shutdown",
            ));
        }
        Ok(())
    }

    async fn open_stream(
        &self,
        host: onionroute_common_types::types::TcpHost,
        port: u16,
        isolation: &IsolationKey,
    ) -> OnionResult<BoxTransport> {
        if self.state().lifecycle != BackendLifecycle::Ready {
            return Err(unavailable_error("Tor is not ready for streams"));
        }
        let socks_address = {
            let mut runtime = self.inner.runtime.lock().await;
            let runtime = runtime
                .as_mut()
                .ok_or_else(|| unavailable_error("Tor process is not running"))?;
            if runtime
                .process
                .try_wait()
                .map_err(|_| unavailable_error("Tor process status failed"))?
                .is_some()
            {
                None
            } else {
                Some(runtime.socks_address)
            }
        };
        let Some(socks_address) = socks_address else {
            self.fail_closed().await;
            return Err(unavailable_error("Tor process terminated"));
        };
        let cancellation = self.context_cancellation(isolation).await?;
        let stream = socks::connect(
            socks_address,
            &host,
            port,
            isolation,
            self.inner.config.stream_timeout,
        )
        .await?;
        Ok(Box::new(ManagedTorStream::new(
            stream,
            cancellation,
            Arc::clone(&self.inner.active_streams),
        )))
    }

    async fn context_cancellation(
        &self,
        isolation: &IsolationKey,
    ) -> OnionResult<CancellationToken> {
        let mut contexts = self.inner.contexts.lock().await;
        if let Some(record) = contexts.get(&isolation.0) {
            return Ok(record.cancellation.clone());
        }
        if contexts.len() >= self.inner.config.max_isolation_contexts {
            return Err(tor_error(
                ErrorCode::Backpressure,
                Severity::Error,
                RetryClass::Backoff,
                SafetyImpact::Protected,
                "Tor isolation context capacity is exhausted",
            ));
        }
        let cancellation = CancellationToken::new();
        contexts.insert(
            isolation.0,
            ContextRecord {
                epoch: self.inner.epoch.load(Ordering::Acquire),
                scope: None,
                cancellation: cancellation.clone(),
            },
        );
        Ok(cancellation)
    }

    async fn allocate_context(&self, scope: &IsolationScope) -> OnionResult<IsolationContext> {
        scope.validate()?;
        let epoch = self.inner.epoch.load(Ordering::Acquire);
        let mut contexts = self.inner.contexts.lock().await;
        if let Some((key, _)) = contexts
            .iter()
            .find(|(_, record)| record.epoch == epoch && record.scope.as_ref() == Some(scope))
        {
            return Ok(IsolationContext {
                session_epoch: epoch,
                key: IsolationKey(*key),
            });
        }
        if contexts.len() >= self.inner.config.max_isolation_contexts {
            return Err(tor_error(
                ErrorCode::Backpressure,
                Severity::Error,
                RetryClass::Backoff,
                SafetyImpact::Protected,
                "Tor isolation context capacity is exhausted",
            ));
        }
        for _ in 0..CONTEXT_COLLISION_ATTEMPTS {
            let mut key = [0_u8; 32];
            OsRng.fill_bytes(&mut key);
            if contexts.contains_key(&key) {
                continue;
            }
            contexts.insert(
                key,
                ContextRecord {
                    epoch,
                    scope: Some(scope.clone()),
                    cancellation: CancellationToken::new(),
                },
            );
            return Ok(IsolationContext {
                session_epoch: epoch,
                key: IsolationKey(key),
            });
        }
        Err(invariant_error())
    }

    async fn cancel_and_clear_contexts(&self) -> usize {
        let mut contexts = self.inner.contexts.lock().await;
        for record in contexts.values() {
            record.cancellation.cancel();
        }
        let count = self.inner.active_streams.load(Ordering::Acquire);
        contexts.clear();
        count
    }

    async fn fail_closed(&self) {
        self.set_state(BackendLifecycle::FailedClosed, self.state().progress);
        self.cancel_and_clear_contexts().await;
    }

    fn spawn_process_monitor(&self, generation: u64) {
        let backend = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(backend.inner.config.health_poll_interval).await;
                let exited = {
                    let mut runtime = backend.inner.runtime.lock().await;
                    let Some(runtime) = runtime.as_mut() else {
                        return;
                    };
                    if runtime.generation != generation {
                        return;
                    }
                    match runtime.process.try_wait() {
                        Ok(Some(_)) | Err(_) => true,
                        Ok(None) => false,
                    }
                };
                if exited {
                    backend.fail_closed().await;
                    return;
                }
            }
        });
    }

    fn state(&self) -> StateSnapshot {
        self.inner
            .state
            .read()
            .map(|state| *state)
            .unwrap_or(StateSnapshot {
                lifecycle: BackendLifecycle::FailedClosed,
                progress: 0,
            })
    }

    fn set_state(&self, lifecycle: BackendLifecycle, progress: u8) {
        if let Ok(mut state) = self.inner.state.write() {
            state.lifecycle = lifecycle;
            state.progress = progress.min(100);
        }
    }

    async fn configure_options(
        &self,
        bridges: Option<BridgeConfig>,
        proxy: Option<Option<ProxyConfig>>,
    ) -> OnionResult<()> {
        if self.inner.runtime.lock().await.is_some() {
            return Err(configuration_error(
                "Tor options can only change while stopped",
            ));
        }
        let mut options = self.inner.options.write().map_err(|_| invariant_error())?;
        if let Some(bridges) = bridges {
            bridges.validate()?;
            options.bridges = bridges;
        }
        if let Some(proxy) = proxy {
            options.proxy = proxy;
        }
        Ok(())
    }
}

impl VersionedContract for CTorBackend {
    fn contract_version(&self) -> ContractVersion {
        CONTRACT_V1
    }
}

impl TorBackend for CTorBackend {
    fn bootstrap<'a>(
        &'a self,
        config: &'a TorBootstrapConfig,
    ) -> BoxFuture<'a, OnionResult<TorStatus>> {
        Box::pin(async move { self.bootstrap_impl(config).await })
    }

    fn open_onion_stream<'a>(
        &'a self,
        endpoint: &'a OnionEndpoint,
        isolation: &'a IsolationKey,
    ) -> BoxFuture<'a, OnionResult<BoxTransport>> {
        Box::pin(async move {
            let host = socks::onion_host(&endpoint.service_id)?;
            self.open_stream(host, endpoint.port, isolation).await
        })
    }

    fn open_direct_stream<'a>(
        &'a self,
        request: &'a TcpFlowRequest,
        isolation: &'a IsolationKey,
    ) -> BoxFuture<'a, OnionResult<BoxTransport>> {
        Box::pin(async move {
            self.open_stream(request.host.clone(), request.port, isolation)
                .await
        })
    }

    fn status(&self) -> BoxFuture<'_, OnionResult<TorStatus>> {
        Box::pin(async move { self.probe_status().await })
    }

    fn shutdown(&self) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async move { self.stop_impl().await })
    }
}

impl TorBackendExt for CTorBackend {
    fn start(&self) -> BoxFuture<'_, OnionResult<TorStatus>> {
        Box::pin(async move { self.start_impl().await })
    }

    fn stop(&self) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async move { self.stop_impl().await })
    }

    fn bootstrap_progress(&self) -> BoxFuture<'_, OnionResult<u8>> {
        Box::pin(async move { Ok(self.probe_status().await?.bootstrap_percent) })
    }

    fn allocate_isolation_context<'a>(
        &'a self,
        scope: &'a IsolationScope,
    ) -> BoxFuture<'a, OnionResult<IsolationContext>> {
        Box::pin(async move { self.allocate_context(scope).await })
    }

    fn release_isolation_context<'a>(
        &'a self,
        context: &'a IsolationContext,
    ) -> BoxFuture<'a, OnionResult<()>> {
        Box::pin(async move {
            if let Some(record) = self.inner.contexts.lock().await.remove(&context.key.0) {
                record.cancellation.cancel();
            }
            Ok(())
        })
    }

    fn request_soft_rotation(&self) -> BoxFuture<'_, OnionResult<RotationOutcome>> {
        Box::pin(async move {
            let new_epoch = self.inner.epoch.fetch_add(1, Ordering::AcqRel) + 1;
            Ok(RotationOutcome {
                new_epoch,
                closed_streams: 0,
            })
        })
    }

    fn request_hard_rotation(&self) -> BoxFuture<'_, OnionResult<RotationOutcome>> {
        Box::pin(async move {
            let mut last_newnym = self.inner.last_newnym.lock().await;
            if last_newnym
                .map(|last| last.elapsed() < MIN_NEWNYM_INTERVAL)
                .unwrap_or(false)
            {
                return Err(tor_error(
                    ErrorCode::RotationDeferred,
                    Severity::Warning,
                    RetryClass::Backoff,
                    SafetyImpact::Protected,
                    "Tor hard rotation is rate limited",
                ));
            }
            {
                let mut runtime = self.inner.runtime.lock().await;
                let runtime = runtime
                    .as_mut()
                    .ok_or_else(|| unavailable_error("Tor process is not running"))?;
                runtime.control.command("SIGNAL NEWNYM").await?;
            }
            *last_newnym = Some(Instant::now());
            drop(last_newnym);
            let closed_streams = self.cancel_and_clear_contexts().await;
            let new_epoch = self.inner.epoch.fetch_add(1, Ordering::AcqRel) + 1;
            Ok(RotationOutcome {
                new_epoch,
                closed_streams,
            })
        })
    }

    fn health_status(&self) -> BoxFuture<'_, OnionResult<BackendHealth>> {
        Box::pin(async move {
            let _ = self.probe_status().await?;
            let state = self.state();
            Ok(BackendHealth {
                lifecycle: state.lifecycle,
                bootstrap_percent: state.progress,
                accepting_streams: state.lifecycle == BackendLifecycle::Ready,
                active_streams: self.inner.active_streams.load(Ordering::Acquire),
                fail_closed: state.lifecycle != BackendLifecycle::Ready,
            })
        })
    }

    fn configure_bridges<'a>(&'a self, config: BridgeConfig) -> BoxFuture<'a, OnionResult<()>> {
        Box::pin(async move { self.configure_options(Some(config), None).await })
    }

    fn configure_proxy(&self, config: Option<ProxyConfig>) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async move { self.configure_options(None, Some(config)).await })
    }

    fn network_changed(&self) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async move {
            self.set_state(BackendLifecycle::Degraded, self.state().progress);
            self.inner.epoch.fetch_add(1, Ordering::AcqRel);
            let mut runtime = self.inner.runtime.lock().await;
            let runtime = runtime
                .as_mut()
                .ok_or_else(|| unavailable_error("Tor process is not running"))?;
            runtime.control.command("SIGNAL ACTIVE").await?;
            Ok(())
        })
    }
}

struct TorPaths {
    torrc: PathBuf,
    cookie: PathBuf,
    #[cfg(not(unix))]
    control_port_file: PathBuf,
    #[cfg(unix)]
    control_socket: PathBuf,
    data: PathBuf,
    cache: PathBuf,
}

impl TorPaths {
    fn new(root: &Path) -> Self {
        Self {
            torrc: root.join("torrc"),
            cookie: root.join("control.authcookie"),
            #[cfg(not(unix))]
            control_port_file: root.join("control.port"),
            #[cfg(unix)]
            control_socket: root.join("control.sock"),
            data: root.join("data"),
            cache: root.join("cache"),
        }
    }
}

fn render_torrc(paths: &TorPaths, options: &RuntimeOptions, sandbox: bool) -> OnionResult<String> {
    options.bridges.validate()?;
    let mut lines = vec![
        format!("DataDirectory {}", quote_path(&paths.data)?),
        format!("CacheDirectory {}", quote_path(&paths.cache)?),
        "DataDirectoryGroupReadable 0".to_owned(),
        "ClientOnly 1".to_owned(),
        "SafeSocks 1".to_owned(),
        "TestSocks 0".to_owned(),
        "SocksPort auto IsolateSOCKSAuth KeepAliveIsolateSOCKSAuth".to_owned(),
        "CookieAuthentication 1".to_owned(),
        format!("CookieAuthFile {}", quote_path(&paths.cookie)?),
        "CookieAuthFileGroupReadable 0".to_owned(),
        "ControlPortFileGroupReadable 0".to_owned(),
        "Log notice stdout".to_owned(),
        "AvoidDiskWrites 1".to_owned(),
        "DormantOnFirstStartup 0".to_owned(),
    ];
    #[cfg(unix)]
    {
        lines.push(format!(
            "ControlPort unix:{}",
            quote_path(&paths.control_socket)?
        ));
        lines.push("ControlSocketsGroupWritable 0".to_owned());
    }
    #[cfg(not(unix))]
    {
        lines.push("ControlPort auto".to_owned());
        lines.push(format!(
            "ControlPortWriteToFile {}",
            quote_path(&paths.control_port_file)?
        ));
    }
    if cfg!(target_os = "linux") && sandbox {
        lines.push("Sandbox 1".to_owned());
    }
    if !options.bridges.bridges.is_empty() {
        lines.push("UseBridges 1".to_owned());
    }
    for transport in &options.bridges.transports {
        match transport {
            ClientTransportPlugin::Socks5 { name, endpoint } => {
                lines.push(format!("ClientTransportPlugin {name} socks5 {endpoint}"))
            }
            ClientTransportPlugin::Executable {
                name,
                path,
                arguments,
            } => {
                let mut line = format!("ClientTransportPlugin {name} exec {}", quote_path(path)?);
                for argument in arguments {
                    line.push(' ');
                    line.push_str(&quote_value(argument)?);
                }
                lines.push(line);
            }
        }
    }
    for bridge in &options.bridges.bridges {
        let mut line = "Bridge".to_owned();
        if let Some(transport) = &bridge.transport {
            line.push(' ');
            line.push_str(transport);
        }
        line.push(' ');
        line.push_str(&bridge.address.to_string());
        if let Some(fingerprint) = &bridge.fingerprint {
            line.push(' ');
            line.push_str(fingerprint);
        }
        for (key, value) in &bridge.parameters {
            line.push(' ');
            line.push_str(key);
            line.push('=');
            line.push_str(value);
        }
        lines.push(line);
    }
    match options.proxy {
        Some(ProxyConfig::Socks5(endpoint)) => lines.push(format!("Socks5Proxy {endpoint}")),
        Some(ProxyConfig::Https(endpoint)) => lines.push(format!("HTTPSProxy {endpoint}")),
        None => {}
    }
    lines.push(String::new());
    Ok(lines.join("\n"))
}

fn quote_path(path: &Path) -> OnionResult<String> {
    quote_value(
        path.to_str()
            .ok_or_else(|| configuration_error("Tor path is not valid UTF-8"))?,
    )
}

fn quote_value(value: &str) -> OnionResult<String> {
    if value.is_empty() || value.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n')) {
        return Err(configuration_error("invalid Tor configuration value"));
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn write_private_file(path: &Path, bytes: &[u8]) -> OnionResult<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| startup_error("could not create private Tor configuration"))?;
    file.write_all(bytes)
        .map_err(|_| startup_error("could not write private Tor configuration"))?;
    file.sync_all()
        .map_err(|_| startup_error("could not sync private Tor configuration"))
}

#[cfg(unix)]
fn secure_directory(path: &Path) -> OnionResult<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| startup_error("could not restrict Tor data directory"))?;
    let mode = std::fs::metadata(path)
        .map_err(|_| startup_error("could not inspect Tor data directory"))?
        .mode();
    if mode & 0o077 != 0 {
        return Err(startup_error("Tor data directory permissions are unsafe"));
    }
    Ok(())
}

#[cfg(windows)]
fn secure_directory(path: &Path) -> OnionResult<()> {
    let username = std::env::var("USERNAME")
        .map_err(|_| startup_error("could not identify Tor data directory owner"))?;
    let domain = std::env::var("USERDOMAIN").unwrap_or_default();
    let account = if domain.is_empty() {
        username
    } else {
        format!("{domain}\\{username}")
    };
    let grant = format!("{account}:(OI)(CI)F");
    let status = std::process::Command::new("icacls.exe")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(grant)
        .arg("/grant:r")
        .arg("*S-1-5-18:(OI)(CI)F")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| startup_error("could not restrict Tor data directory ACL"))?;
    if !status.success() {
        return Err(startup_error("Tor data directory ACL is unsafe"));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn secure_directory(_path: &Path) -> OnionResult<()> {
    Err(configuration_error(
        "secure Tor data directories are unsupported",
    ))
}

#[cfg(not(unix))]
fn parse_control_port_file(contents: &str) -> Option<SocketAddr> {
    let line = contents.lines().find(|line| line.starts_with("PORT="))?;
    line.strip_prefix("PORT=")?.parse().ok()
}

async fn read_socks_listener(control: &mut ControlClient) -> OnionResult<SocketAddr> {
    let lines = control.command("GETINFO net/listeners/socks").await?;
    for line in lines {
        let Some(value) = line.split_once('=').map(|(_, value)| value) else {
            continue;
        };
        for candidate in value.split_whitespace() {
            let candidate = candidate.trim_matches('"');
            if let Ok(address) = candidate.parse::<SocketAddr>() {
                if address.ip().is_loopback() {
                    return Ok(address);
                }
            }
        }
    }
    Err(startup_error("Tor SOCKS listener is unavailable"))
}

fn parse_bootstrap_progress(lines: &[String]) -> Option<u8> {
    lines.iter().find_map(|line| {
        line.split_ascii_whitespace().find_map(|part| {
            part.strip_prefix("PROGRESS=")
                .and_then(|value| value.trim_matches('"').parse::<u8>().ok())
                .filter(|value| *value <= 100)
        })
    })
}

fn startup_error(message: &'static str) -> onionroute_common_types::OnionError {
    tor_error(
        ErrorCode::TorUnavailable,
        Severity::Error,
        RetryClass::Backoff,
        SafetyImpact::Protected,
        message,
    )
}

fn unavailable_error(message: &'static str) -> onionroute_common_types::OnionError {
    tor_error(
        ErrorCode::TorUnavailable,
        Severity::Error,
        RetryClass::Backoff,
        SafetyImpact::Protected,
        message,
    )
}

fn invariant_error() -> onionroute_common_types::OnionError {
    tor_error(
        ErrorCode::InvariantViolation,
        Severity::Fatal,
        RetryClass::Never,
        SafetyImpact::MustBlock,
        "Tor backend invariant failed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_parser_is_bounded() {
        assert_eq!(
            parse_bootstrap_progress(&[
                "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=73 TAG=x".into()
            ]),
            Some(73)
        );
        assert_eq!(parse_bootstrap_progress(&["250 PROGRESS=101".into()]), None);
    }

    #[test]
    fn torrc_has_private_control_and_socks_isolation() {
        let directory = tempfile::tempdir().unwrap();
        let paths = TorPaths::new(directory.path());
        let text = render_torrc(
            &paths,
            &RuntimeOptions {
                bridges: BridgeConfig::default(),
                proxy: None,
            },
            false,
        )
        .unwrap();
        assert!(text.contains("CookieAuthentication 1"));
        assert!(text.contains("CookieAuthFileGroupReadable 0"));
        assert!(text.contains("IsolateSOCKSAuth"));
        assert!(!text.contains("ControlPort 0.0.0.0"));
    }
}

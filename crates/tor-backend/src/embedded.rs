//! In-process C Tor backend for iOS Network Extensions.

use std::collections::HashMap;
use std::ffi::CString;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use onionroute_common_types::contracts::v1::TorBackend;
use onionroute_common_types::error::{ErrorCode, RetryClass, SafetyImpact, Severity};
use onionroute_common_types::transport::{BoxFuture, BoxTransport};
use onionroute_common_types::types::{
    IsolationKey, OnionEndpoint, TcpFlowRequest, TorBootstrapConfig, TorStatus,
};
use onionroute_common_types::version::{ContractVersion, VersionedContract, CONTRACT_V1};
use onionroute_common_types::OnionResult;
use onionroute_embedded_ctor_sys::EmbeddedTorError;
use rand::rngs::OsRng;
use rand::RngCore;
use tempfile::TempDir;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::control::{ControlClient, ControlEndpoint};
use crate::ctor::{
    parse_bootstrap_progress, read_socks_listener, render_torrc, secure_directory,
    write_private_file, RuntimeOptions, TorPaths,
};
use crate::socks;
use crate::transport::ManagedTorStream;
use crate::types::{
    configuration_error, tor_error, BackendHealth, BackendLifecycle, BridgeConfig,
    ClientTransportPlugin, IsolationContext, IsolationScope, ProxyConfig, RotationOutcome,
    TorBackendExt,
};

const MAX_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MIN_NEWNYM_INTERVAL: Duration = Duration::from_secs(10);

/// Bounded configuration for the one in-process C Tor instance.
#[derive(Clone, Debug)]
pub struct EmbeddedCTorConfig {
    /// Existing App Group directory under which an owner-only runtime directory is created.
    pub state_parent: PathBuf,
    /// Deadline for the control socket and SAFECOOKIE authentication.
    pub startup_timeout: Duration,
    /// Deadline for graceful thread exit after `SIGNAL SHUTDOWN`.
    pub shutdown_timeout: Duration,
    /// Deadline for a complete isolated SOCKS handshake.
    pub stream_timeout: Duration,
    /// Maximum retained isolation scopes.
    pub max_isolation_contexts: usize,
    /// Initial bridge configuration. Child executable transports are forbidden on iOS.
    pub bridges: BridgeConfig,
    /// Optional upstream proxy used only by Tor OR connections.
    pub proxy: Option<ProxyConfig>,
}

impl EmbeddedCTorConfig {
    fn validate(&self) -> OnionResult<()> {
        if !self.state_parent.is_dir()
            || self.startup_timeout.is_zero()
            || self.startup_timeout > Duration::from_secs(120)
            || self.shutdown_timeout.is_zero()
            || self.shutdown_timeout > Duration::from_secs(60)
            || self.stream_timeout.is_zero()
            || self.stream_timeout > Duration::from_secs(5 * 60)
            || self.max_isolation_contexts == 0
            || self.max_isolation_contexts > 65_536
        {
            return Err(configuration_error(
                "invalid embedded C Tor backend configuration",
            ));
        }
        self.bridges.validate()?;
        if self
            .bridges
            .transports
            .iter()
            .any(|transport| matches!(transport, ClientTransportPlugin::Executable { .. }))
        {
            return Err(configuration_error(
                "iOS embedded Tor cannot launch transport executables",
            ));
        }
        Ok(())
    }
}

struct RuntimeState {
    control: ControlClient,
    socks_address: SocketAddr,
    thread: Option<JoinHandle<Result<i32, EmbeddedTorError>>>,
    cancellation: CancellationToken,
    #[allow(dead_code)]
    data_directory: TempDir,
}

#[derive(Clone, Copy)]
struct StateSnapshot {
    lifecycle: BackendLifecycle,
    progress: u8,
}

struct Inner {
    config: EmbeddedCTorConfig,
    options: RwLock<RuntimeOptions>,
    state: RwLock<StateSnapshot>,
    runtime: Mutex<Option<RuntimeState>>,
    start_guard: Mutex<()>,
    contexts: Mutex<HashMap<IsolationScope, IsolationContext>>,
    epoch: AtomicU64,
    active_streams: Arc<AtomicUsize>,
    last_newnym: Mutex<Option<Instant>>,
}

/// Embedded C Tor backend selected for the iOS MVP by ADR-0019.
#[derive(Clone)]
pub struct EmbeddedCTorBackend {
    inner: Arc<Inner>,
}

impl EmbeddedCTorBackend {
    /// Validates all paths and limits without starting native code.
    pub fn new(config: EmbeddedCTorConfig) -> OnionResult<Self> {
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
                last_newnym: Mutex::new(None),
            }),
        })
    }

    async fn start_impl(&self) -> OnionResult<TorStatus> {
        let _guard = self.inner.start_guard.lock().await;
        if self.inner.runtime.lock().await.is_some() {
            let state = self.state();
            return Ok(TorStatus {
                bootstrap_percent: state.progress,
                ready: state.lifecycle == BackendLifecycle::Ready,
            });
        }
        self.set_state(BackendLifecycle::Starting, 0);
        let data_directory = tempfile::Builder::new()
            .prefix("onionroute-ios-tor-")
            .tempdir_in(&self.inner.config.state_parent)
            .map_err(|_| startup_error("could not create embedded Tor data directory"))?;
        secure_directory(data_directory.path())?;
        let paths = TorPaths::new(data_directory.path());
        let options = self
            .inner
            .options
            .read()
            .map_err(|_| invariant_error())?
            .clone();
        let torrc = render_torrc(&paths, &options, false)?;
        write_private_file(&paths.torrc, torrc.as_bytes())?;
        let torrc_path = paths
            .torrc
            .to_str()
            .ok_or_else(|| configuration_error("embedded Tor path is not UTF-8"))?;
        let arguments = vec![
            CString::new("tor").expect("static Tor argument"),
            CString::new("-f").expect("static Tor argument"),
            CString::new(torrc_path)
                .map_err(|_| configuration_error("embedded Tor path contains NUL"))?,
            CString::new("--ignore-missing-torrc").expect("static Tor argument"),
        ];
        let thread = std::thread::Builder::new()
            .name("onionroute-embedded-tor".to_owned())
            .spawn(move || onionroute_embedded_ctor_sys::run(&arguments))
            .map_err(|_| startup_error("could not create embedded Tor thread"))?;

        #[cfg(unix)]
        let endpoint = ControlEndpoint::Unix(paths.control_socket.clone());
        #[cfg(not(unix))]
        compile_error!("embedded C Tor currently requires a Unix control socket");

        let deadline = Instant::now() + self.inner.config.startup_timeout;
        while !paths.control_socket.exists() {
            if thread.is_finished() {
                self.set_state(BackendLifecycle::FailedClosed, 0);
                let _ = thread.join();
                return Err(startup_error("embedded C Tor exited during startup"));
            }
            if Instant::now() >= deadline {
                self.set_state(BackendLifecycle::FailedClosed, 0);
                return Err(startup_error(
                    "embedded C Tor control endpoint startup timed out",
                ));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let mut control = ControlClient::connect_and_authenticate(
            &endpoint,
            &paths.cookie,
            deadline.saturating_duration_since(Instant::now()),
        )
        .await?;
        let socks_address = read_socks_listener(&mut control).await?;
        let cancellation = CancellationToken::new();
        *self.inner.runtime.lock().await = Some(RuntimeState {
            control,
            socks_address,
            thread: Some(thread),
            cancellation,
            data_directory,
        });
        self.set_state(BackendLifecycle::Bootstrapping, 0);
        Ok(TorStatus {
            bootstrap_percent: 0,
            ready: false,
        })
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
        loop {
            let status = self.probe_status().await?;
            if status.ready {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                self.set_state(BackendLifecycle::Degraded, status.bootstrap_percent);
                return Err(tor_error(
                    ErrorCode::TorBootstrapTimeout,
                    Severity::Error,
                    RetryClass::Backoff,
                    SafetyImpact::MustBlock,
                    "embedded Tor bootstrap deadline expired",
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn probe_status(&self) -> OnionResult<TorStatus> {
        let response = {
            let mut runtime = self.inner.runtime.lock().await;
            let runtime = runtime
                .as_mut()
                .ok_or_else(|| unavailable_error("embedded Tor is not running"))?;
            if runtime
                .thread
                .as_ref()
                .is_some_and(std::thread::JoinHandle::is_finished)
            {
                self.set_state(BackendLifecycle::FailedClosed, 0);
                return Err(unavailable_error("embedded Tor terminated"));
            }
            runtime
                .control
                .command("GETINFO status/bootstrap-phase")
                .await?
        };
        let progress = parse_bootstrap_progress(&response)
            .ok_or_else(|| unavailable_error("embedded Tor bootstrap status is malformed"))?;
        self.set_state(
            if progress == 100 {
                BackendLifecycle::Ready
            } else {
                BackendLifecycle::Bootstrapping
            },
            progress,
        );
        Ok(TorStatus {
            bootstrap_percent: progress,
            ready: progress == 100,
        })
    }

    async fn stop_impl(&self) -> OnionResult<()> {
        let _guard = self.inner.start_guard.lock().await;
        self.set_state(BackendLifecycle::Stopping, self.state().progress);
        self.inner.contexts.lock().await.clear();
        let Some(runtime) = self.inner.runtime.lock().await.take() else {
            self.set_state(BackendLifecycle::Stopped, 0);
            return Ok(());
        };
        runtime.cancellation.cancel();
        let RuntimeState {
            mut control,
            thread,
            data_directory,
            ..
        } = runtime;
        let control_result = control.command("SIGNAL SHUTDOWN").await;
        drop(control);
        let joined = if let Some(thread) = thread {
            tokio::time::timeout(
                self.inner.config.shutdown_timeout,
                tokio::task::spawn_blocking(move || thread.join()),
            )
            .await
            .is_ok()
        } else {
            true
        };
        drop(data_directory);
        self.set_state(BackendLifecycle::Stopped, 0);
        if control_result.is_err() || !joined {
            return Err(tor_error(
                ErrorCode::ShutdownTimeout,
                Severity::Fatal,
                RetryClass::Never,
                SafetyImpact::MustBlock,
                "embedded Tor did not stop cleanly",
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
            return Err(unavailable_error("embedded Tor is not ready for streams"));
        }
        let (address, cancellation) = {
            let runtime = self.inner.runtime.lock().await;
            let runtime = runtime
                .as_ref()
                .ok_or_else(|| unavailable_error("embedded Tor is not running"))?;
            (runtime.socks_address, runtime.cancellation.clone())
        };
        let stream = socks::connect(
            address,
            &host,
            port,
            isolation,
            self.inner.config.stream_timeout,
        )
        .await?;
        Ok(Box::new(ManagedTorStream::new(
            stream,
            cancellation,
            self.inner.active_streams.clone(),
        )))
    }

    fn state(&self) -> StateSnapshot {
        *self
            .inner
            .state
            .read()
            .expect("embedded Tor state lock poisoned")
    }

    fn set_state(&self, lifecycle: BackendLifecycle, progress: u8) {
        if let Ok(mut state) = self.inner.state.write() {
            state.lifecycle = lifecycle;
            state.progress = progress.min(100);
        }
    }
}

impl VersionedContract for EmbeddedCTorBackend {
    fn contract_version(&self) -> ContractVersion {
        CONTRACT_V1
    }
}

impl TorBackend for EmbeddedCTorBackend {
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

impl TorBackendExt for EmbeddedCTorBackend {
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
        Box::pin(async move {
            scope.validate()?;
            let mut contexts = self.inner.contexts.lock().await;
            if let Some(existing) = contexts.get(scope) {
                return Ok(existing.clone());
            }
            if contexts.len() >= self.inner.config.max_isolation_contexts {
                return Err(tor_error(
                    ErrorCode::Backpressure,
                    Severity::Error,
                    RetryClass::Backoff,
                    SafetyImpact::Protected,
                    "embedded Tor isolation context limit reached",
                ));
            }
            let mut key = [0_u8; 32];
            OsRng.fill_bytes(&mut key);
            let context = IsolationContext {
                session_epoch: self.inner.epoch.load(Ordering::Acquire),
                key: IsolationKey(key),
            };
            contexts.insert(scope.clone(), context.clone());
            Ok(context)
        })
    }

    fn release_isolation_context<'a>(
        &'a self,
        context: &'a IsolationContext,
    ) -> BoxFuture<'a, OnionResult<()>> {
        Box::pin(async move {
            self.inner
                .contexts
                .lock()
                .await
                .retain(|_, candidate| candidate != context);
            Ok(())
        })
    }

    fn request_soft_rotation(&self) -> BoxFuture<'_, OnionResult<RotationOutcome>> {
        Box::pin(async move {
            let epoch = self.inner.epoch.fetch_add(1, Ordering::AcqRel) + 1;
            self.inner.contexts.lock().await.clear();
            Ok(RotationOutcome {
                new_epoch: epoch,
                closed_streams: 0,
            })
        })
    }

    fn request_hard_rotation(&self) -> BoxFuture<'_, OnionResult<RotationOutcome>> {
        Box::pin(async move {
            let mut last = self.inner.last_newnym.lock().await;
            if last.is_some_and(|value| value.elapsed() < MIN_NEWNYM_INTERVAL) {
                return Err(tor_error(
                    ErrorCode::RotationDeferred,
                    Severity::Warning,
                    RetryClass::Backoff,
                    SafetyImpact::Protected,
                    "embedded Tor hard rotation is rate limited",
                ));
            }
            let closed = self.inner.active_streams.load(Ordering::Acquire);
            let mut runtime_guard = self.inner.runtime.lock().await;
            let runtime = runtime_guard
                .as_mut()
                .ok_or_else(|| unavailable_error("embedded Tor is not running"))?;
            runtime.control.command("SIGNAL NEWNYM").await?;
            runtime.cancellation.cancel();
            runtime.cancellation = CancellationToken::new();
            *last = Some(Instant::now());
            drop(runtime_guard);
            drop(last);
            self.inner.contexts.lock().await.clear();
            let epoch = self.inner.epoch.fetch_add(1, Ordering::AcqRel) + 1;
            Ok(RotationOutcome {
                new_epoch: epoch,
                closed_streams: closed,
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
        Box::pin(async move {
            config.validate()?;
            if config
                .transports
                .iter()
                .any(|transport| matches!(transport, ClientTransportPlugin::Executable { .. }))
            {
                return Err(configuration_error(
                    "iOS embedded Tor cannot launch transport executables",
                ));
            }
            if self.inner.runtime.lock().await.is_some() {
                return Err(configuration_error(
                    "embedded Tor bridges can change only while stopped",
                ));
            }
            self.inner
                .options
                .write()
                .map_err(|_| invariant_error())?
                .bridges = config;
            Ok(())
        })
    }

    fn configure_proxy(&self, config: Option<ProxyConfig>) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async move {
            if self.inner.runtime.lock().await.is_some() {
                return Err(configuration_error(
                    "embedded Tor proxy can change only while stopped",
                ));
            }
            self.inner
                .options
                .write()
                .map_err(|_| invariant_error())?
                .proxy = config;
            Ok(())
        })
    }

    fn network_changed(&self) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async move {
            self.set_state(BackendLifecycle::Degraded, self.state().progress);
            let mut runtime = self.inner.runtime.lock().await;
            runtime
                .as_mut()
                .ok_or_else(|| unavailable_error("embedded Tor is not running"))?
                .control
                .command("SIGNAL ACTIVE")
                .await?;
            Ok(())
        })
    }
}

fn startup_error(message: &'static str) -> onionroute_common_types::OnionError {
    tor_error(
        ErrorCode::TorUnavailable,
        Severity::Error,
        RetryClass::Backoff,
        SafetyImpact::MustBlock,
        message,
    )
}

fn unavailable_error(message: &'static str) -> onionroute_common_types::OnionError {
    tor_error(
        ErrorCode::TorUnavailable,
        Severity::Error,
        RetryClass::Backoff,
        SafetyImpact::MustBlock,
        message,
    )
}

fn invariant_error() -> onionroute_common_types::OnionError {
    tor_error(
        ErrorCode::InvariantViolation,
        Severity::Fatal,
        RetryClass::Never,
        SafetyImpact::MustBlock,
        "embedded Tor backend invariant failed",
    )
}

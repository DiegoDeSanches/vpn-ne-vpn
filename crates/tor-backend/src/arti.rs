use std::sync::RwLock;

use onionroute_common_types::contracts::v1::TorBackend;
use onionroute_common_types::error::{ErrorCode, RetryClass, SafetyImpact, Severity};
use onionroute_common_types::transport::{BoxFuture, BoxTransport};
use onionroute_common_types::types::{
    IsolationKey, OnionEndpoint, TcpFlowRequest, TorBootstrapConfig, TorStatus,
};
use onionroute_common_types::version::{ContractVersion, VersionedContract, CONTRACT_V1};
use onionroute_common_types::OnionResult;

use crate::types::{
    tor_error, BackendHealth, BackendLifecycle, BridgeConfig, IsolationContext, IsolationScope,
    ProxyConfig, RotationOutcome, TorBackendExt,
};

/// Experimental Arti scaffold.
///
/// It deliberately fails closed until the blockers in `docs/arti-migration.md`
/// are resolved. No request can accidentally fall back to clearnet.
pub struct ArtiBackend {
    options: RwLock<(BridgeConfig, Option<ProxyConfig>)>,
}

impl Default for ArtiBackend {
    fn default() -> Self {
        Self {
            options: RwLock::new((BridgeConfig::default(), None)),
        }
    }
}

impl VersionedContract for ArtiBackend {
    fn contract_version(&self) -> ContractVersion {
        CONTRACT_V1
    }
}

impl TorBackend for ArtiBackend {
    fn bootstrap<'a>(
        &'a self,
        _config: &'a TorBootstrapConfig,
    ) -> BoxFuture<'a, OnionResult<TorStatus>> {
        unsupported()
    }

    fn open_onion_stream<'a>(
        &'a self,
        _endpoint: &'a OnionEndpoint,
        _isolation: &'a IsolationKey,
    ) -> BoxFuture<'a, OnionResult<BoxTransport>> {
        unsupported()
    }

    fn open_direct_stream<'a>(
        &'a self,
        _request: &'a TcpFlowRequest,
        _isolation: &'a IsolationKey,
    ) -> BoxFuture<'a, OnionResult<BoxTransport>> {
        unsupported()
    }

    fn status(&self) -> BoxFuture<'_, OnionResult<TorStatus>> {
        unsupported()
    }

    fn shutdown(&self) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl TorBackendExt for ArtiBackend {
    fn start(&self) -> BoxFuture<'_, OnionResult<TorStatus>> {
        unsupported()
    }

    fn stop(&self) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async { Ok(()) })
    }

    fn bootstrap_progress(&self) -> BoxFuture<'_, OnionResult<u8>> {
        unsupported()
    }

    fn allocate_isolation_context<'a>(
        &'a self,
        _scope: &'a IsolationScope,
    ) -> BoxFuture<'a, OnionResult<IsolationContext>> {
        unsupported()
    }

    fn release_isolation_context<'a>(
        &'a self,
        _context: &'a IsolationContext,
    ) -> BoxFuture<'a, OnionResult<()>> {
        Box::pin(async { Ok(()) })
    }

    fn request_soft_rotation(&self) -> BoxFuture<'_, OnionResult<RotationOutcome>> {
        unsupported()
    }

    fn request_hard_rotation(&self) -> BoxFuture<'_, OnionResult<RotationOutcome>> {
        unsupported()
    }

    fn health_status(&self) -> BoxFuture<'_, OnionResult<BackendHealth>> {
        Box::pin(async {
            Ok(BackendHealth {
                lifecycle: BackendLifecycle::FailedClosed,
                bootstrap_percent: 0,
                accepting_streams: false,
                active_streams: 0,
                fail_closed: true,
            })
        })
    }

    fn configure_bridges<'a>(&'a self, config: BridgeConfig) -> BoxFuture<'a, OnionResult<()>> {
        Box::pin(async move {
            config.validate()?;
            self.options.write().map_err(|_| arti_error())?.0 = config;
            Ok(())
        })
    }

    fn configure_proxy(&self, config: Option<ProxyConfig>) -> BoxFuture<'_, OnionResult<()>> {
        Box::pin(async move {
            self.options.write().map_err(|_| arti_error())?.1 = config;
            Ok(())
        })
    }

    fn network_changed(&self) -> BoxFuture<'_, OnionResult<()>> {
        unsupported()
    }
}

fn unsupported<'a, T: Send + 'a>() -> BoxFuture<'a, OnionResult<T>> {
    Box::pin(async { Err(arti_error()) })
}

fn arti_error() -> onionroute_common_types::OnionError {
    tor_error(
        ErrorCode::PlatformUnsupported,
        Severity::Error,
        RetryClass::UserAction,
        SafetyImpact::MustBlock,
        "experimental Arti backend is not production-ready",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scaffold_always_fails_closed() {
        let backend = ArtiBackend::default();
        assert!(backend.status().await.unwrap_err().requires_blocking());
        assert!(backend.health_status().await.unwrap().fail_closed);
    }
}

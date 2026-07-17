//! Short-lived, role-scoped data-plane identities and pin/trust rotation.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use crate::route::GatewayRole;
use crate::{ErrorCode, Result};

pub const MAX_LEAF_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
pub const DEFAULT_ROTATION_LEAD: Duration = Duration::from_secs(2 * 60 * 60);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IdentityPurpose {
    InterGatewayDataPlane,
    ExitTerminal,
    Management,
}

/// Metadata authenticated by the signed trust bundle and pinned to the exact
/// leaf certificate digest. This is a service identity, never a user identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerIdentity {
    pub service_id: String,
    pub role: GatewayRole,
    pub purpose: IdentityPurpose,
    pub certificate_sha256: [u8; 32],
    pub valid_from: SystemTime,
    pub valid_until: SystemTime,
}

impl PeerIdentity {
    pub fn validate(&self, now: SystemTime) -> Result<()> {
        if self.service_id.is_empty()
            || self.service_id.len() > 128
            || !self.service_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
            || self.valid_from > now
            || self.valid_until <= now
            || self
                .valid_until
                .duration_since(self.valid_from)
                .map_err(|_| ErrorCode::InvalidIdentity)?
                > MAX_LEAF_LIFETIME
        {
            return Err(ErrorCode::InvalidIdentity.into());
        }
        Ok(())
    }
}

/// In-memory identity material supplied by Vault/cloud KMS adapters. Private
/// keys are never formatted, logged, or exposed by a public accessor.
pub struct IdentityMaterial {
    descriptor: PeerIdentity,
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

impl IdentityMaterial {
    pub fn new(
        descriptor: PeerIdentity,
        certificate_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
        now: SystemTime,
    ) -> Result<Self> {
        descriptor.validate(now)?;
        let leaf = certificate_chain
            .first()
            .ok_or(ErrorCode::InvalidIdentity)?;
        if certificate_fingerprint(leaf) != descriptor.certificate_sha256 {
            return Err(ErrorCode::InvalidIdentity.into());
        }
        Ok(Self {
            descriptor,
            certificate_chain,
            private_key,
        })
    }

    pub fn descriptor(&self) -> &PeerIdentity {
        &self.descriptor
    }

    pub(crate) fn certificate_chain(&self) -> Vec<CertificateDer<'static>> {
        self.certificate_chain.clone()
    }

    pub(crate) fn private_key(&self) -> PrivateKeyDer<'static> {
        self.private_key.clone_key()
    }
}

#[derive(Clone)]
pub struct IdentityStore {
    expected_role: GatewayRole,
    expected_purpose: IdentityPurpose,
    current: Arc<RwLock<Arc<IdentityMaterial>>>,
}

impl IdentityStore {
    pub fn new(material: IdentityMaterial) -> Result<Self> {
        let expected_role = material.descriptor.role;
        let expected_purpose = material.descriptor.purpose;
        if expected_purpose == IdentityPurpose::Management {
            return Err(ErrorCode::InvalidIdentity.into());
        }
        Ok(Self {
            expected_role,
            expected_purpose,
            current: Arc::new(RwLock::new(Arc::new(material))),
        })
    }

    pub fn snapshot(&self, now: SystemTime) -> Result<Arc<IdentityMaterial>> {
        let material = self
            .current
            .read()
            .map_err(|_| ErrorCode::Internal)?
            .clone();
        material.descriptor.validate(now)?;
        Ok(material)
    }

    pub fn install(&self, material: IdentityMaterial, now: SystemTime) -> Result<()> {
        material.descriptor.validate(now)?;
        if material.descriptor.role != self.expected_role
            || material.descriptor.purpose != self.expected_purpose
        {
            return Err(ErrorCode::WrongRole.into());
        }
        *self.current.write().map_err(|_| ErrorCode::Internal)? = Arc::new(material);
        Ok(())
    }

    pub fn expires_within(&self, lead: Duration, now: SystemTime) -> Result<bool> {
        let current = self.snapshot(now)?;
        Ok(current
            .descriptor
            .valid_until
            .duration_since(now)
            .map(|remaining| remaining <= lead)
            .unwrap_or(true))
    }
}

/// Role-specific roots plus exact short-lived leaf pins. Rotation is performed
/// by installing an overlapping bundle containing both current and next leaves.
#[derive(Clone)]
pub struct TrustBundle {
    roots: Arc<Vec<CertificateDer<'static>>>,
    peers: Arc<RwLock<HashMap<[u8; 32], PeerIdentity>>>,
    revoked_services: Arc<RwLock<HashSet<String>>>,
    revoked_certificates: Arc<RwLock<HashSet<[u8; 32]>>>,
}

impl TrustBundle {
    pub fn new(
        roots: Vec<CertificateDer<'static>>,
        peers: Vec<PeerIdentity>,
        now: SystemTime,
    ) -> Result<Self> {
        if roots.is_empty() || roots.len() > 16 || peers.is_empty() || peers.len() > 4096 {
            return Err(ErrorCode::InvalidConfiguration.into());
        }
        let mut mapped = HashMap::with_capacity(peers.len());
        for peer in peers {
            peer.validate(now)?;
            if mapped.insert(peer.certificate_sha256, peer).is_some() {
                return Err(ErrorCode::InvalidConfiguration.into());
            }
        }
        Ok(Self {
            roots: Arc::new(roots),
            peers: Arc::new(RwLock::new(mapped)),
            revoked_services: Arc::new(RwLock::new(HashSet::new())),
            revoked_certificates: Arc::new(RwLock::new(HashSet::new())),
        })
    }

    pub(crate) fn roots(&self) -> &[CertificateDer<'static>] {
        self.roots.as_slice()
    }

    pub fn replace_peers(&self, peers: Vec<PeerIdentity>, now: SystemTime) -> Result<()> {
        if peers.is_empty() || peers.len() > 4096 {
            return Err(ErrorCode::InvalidConfiguration.into());
        }
        let mut next = HashMap::with_capacity(peers.len());
        for peer in peers {
            peer.validate(now)?;
            if next.insert(peer.certificate_sha256, peer).is_some() {
                return Err(ErrorCode::InvalidConfiguration.into());
            }
        }
        *self.peers.write().map_err(|_| ErrorCode::Internal)? = next;
        Ok(())
    }

    pub fn emergency_revoke_service(&self, service_id: &str) -> Result<()> {
        if service_id.is_empty() || service_id.len() > 128 {
            return Err(ErrorCode::InvalidIdentity.into());
        }
        self.revoked_services
            .write()
            .map_err(|_| ErrorCode::Internal)?
            .insert(service_id.to_owned());
        Ok(())
    }

    pub fn emergency_revoke_certificate(&self, digest: [u8; 32]) -> Result<()> {
        self.revoked_certificates
            .write()
            .map_err(|_| ErrorCode::Internal)?
            .insert(digest);
        Ok(())
    }

    pub fn authorize_leaf(
        &self,
        leaf: &CertificateDer<'_>,
        expected_role: GatewayRole,
        expected_purpose: IdentityPurpose,
        expected_service_id: Option<&str>,
        now: SystemTime,
    ) -> Result<PeerIdentity> {
        let digest = certificate_fingerprint(leaf);
        if self
            .revoked_certificates
            .read()
            .map_err(|_| ErrorCode::Internal)?
            .contains(&digest)
        {
            return Err(ErrorCode::Revoked.into());
        }
        let peer = self
            .peers
            .read()
            .map_err(|_| ErrorCode::Internal)?
            .get(&digest)
            .cloned()
            .ok_or(ErrorCode::InvalidIdentity)?;
        peer.validate(now)?;
        if peer.role != expected_role || peer.purpose != expected_purpose {
            return Err(ErrorCode::WrongRole.into());
        }
        if expected_service_id.map_or(false, |expected| expected != peer.service_id) {
            return Err(ErrorCode::InvalidIdentity.into());
        }
        if self
            .revoked_services
            .read()
            .map_err(|_| ErrorCode::Internal)?
            .contains(&peer.service_id)
        {
            return Err(ErrorCode::Revoked.into());
        }
        Ok(peer)
    }

    pub fn ensure_active(&self, peer: &PeerIdentity, now: SystemTime) -> Result<()> {
        peer.validate(now)?;
        if self
            .revoked_certificates
            .read()
            .map_err(|_| ErrorCode::Internal)?
            .contains(&peer.certificate_sha256)
            || self
                .revoked_services
                .read()
                .map_err(|_| ErrorCode::Internal)?
                .contains(&peer.service_id)
        {
            return Err(ErrorCode::Revoked.into());
        }
        Ok(())
    }
}

pub fn certificate_fingerprint(certificate: &CertificateDer<'_>) -> [u8; 32] {
    Sha256::digest(certificate.as_ref()).into()
}

#[async_trait]
pub trait RotationSource: Send + Sync + 'static {
    async fn load_next(&self) -> Result<IdentityMaterial>;
}

/// Polls a Vault/KMS-backed source before expiry. A failed refresh leaves the
/// current identity installed; once it expires, new TLS handshakes fail closed.
pub async fn run_automatic_rotation<S>(
    store: IdentityStore,
    source: Arc<S>,
    poll_interval: Duration,
    lead: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()>
where
    S: RotationSource,
{
    if poll_interval.is_zero() || lead.is_zero() || lead >= MAX_LEAF_LIFETIME {
        return Err(ErrorCode::InvalidConfiguration.into());
    }
    let mut interval = tokio::time::interval(poll_interval);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let now = SystemTime::now();
                if store.expires_within(lead, now)? {
                    if let Ok(next) = source.load_next().await {
                        store.install(next, SystemTime::now())?;
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
        }
    }
}

/// Keeps boxed futures out of identity structures and simplifies adapters that
/// obtain new credentials from a local agent.
pub type RotationFuture = std::pin::Pin<Box<dyn Future<Output = Result<IdentityMaterial>> + Send>>;

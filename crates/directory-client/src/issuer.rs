//! Reference issuer helpers. The offline-root helper belongs in an isolated ceremony,
//! never in the online signing service.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use thiserror::Error;

use crate::format::{DirectoryDocument, RootTrustBundle, SignedDirectory, SignedTrustBundle};
use crate::{DIRECTORY_SIGNATURE_DOMAIN, TRUST_BUNDLE_SIGNATURE_DOMAIN};

/// Failure while producing a canonical signed artifact.
#[derive(Debug, Error)]
pub enum IssueError {
    /// Canonical JSON serialization failed.
    #[error("canonical document serialization failed")]
    CanonicalSerialization,
    /// The online key is not authorized by the supplied trust bundle.
    #[error("online signing key is not authorized by the trust bundle")]
    UnauthorizedSigningKey,
}

/// Creates a trust bundle during an offline-root ceremony.
///
/// This function does not perform key storage. Production callers must provide a
/// non-exportable root operation backed by an offline HSM or equivalent ceremony.
pub fn sign_trust_bundle(
    root_key: &SigningKey,
    bundle: RootTrustBundle,
) -> Result<SignedTrustBundle, IssueError> {
    let canonical = serde_jcs::to_vec(&bundle).map_err(|_| IssueError::CanonicalSerialization)?;
    let message = domain_message(TRUST_BUNDLE_SIGNATURE_DOMAIN, &canonical);
    let signature = root_key.sign(&message);
    Ok(SignedTrustBundle {
        bundle,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

/// Signs a short-lived directory with a root-authorized online intermediate key.
pub fn sign_directory(
    online_key: &SigningKey,
    signing_key_id: &str,
    trust_bundle: SignedTrustBundle,
    document: &DirectoryDocument,
) -> Result<SignedDirectory, IssueError> {
    let encoded_public_key = URL_SAFE_NO_PAD.encode(online_key.verifying_key().to_bytes());
    let authorized = trust_bundle.bundle.signing_keys.iter().any(|certificate| {
        certificate.key_id == signing_key_id
            && certificate.algorithm == "ed25519"
            && certificate.public_key == encoded_public_key
            && !trust_bundle
                .bundle
                .revoked_signing_key_ids
                .iter()
                .any(|revoked| revoked == signing_key_id)
    });
    if !authorized {
        return Err(IssueError::UnauthorizedSigningKey);
    }

    let payload = serde_jcs::to_vec(document).map_err(|_| IssueError::CanonicalSerialization)?;
    let message = domain_message(DIRECTORY_SIGNATURE_DOMAIN, &payload);
    let signature = online_key.sign(&message);
    Ok(SignedDirectory {
        envelope_version: 1,
        signing_key_id: signing_key_id.to_owned(),
        trust_bundle,
        payload: URL_SAFE_NO_PAD.encode(payload),
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

pub(crate) fn domain_message(domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + bytes.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(bytes);
    message
}

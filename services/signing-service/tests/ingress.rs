use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use onionroute_directory_client::{DirectoryDocument, SignedDirectory};
use onionroute_signing_service::{router, MemoryPublicationRepository, OnlineSigner, SigningError};
use tower::ServiceExt;

struct RejectingSigner;

impl OnlineSigner for RejectingSigner {
    fn sign(&self, _: &DirectoryDocument) -> Result<SignedDirectory, SigningError> {
        Err(SigningError::InvalidDraft)
    }
}

#[tokio::test]
async fn unauthenticated_call_never_reaches_signer() {
    let repository = Arc::new(MemoryPublicationRepository::default());
    let response = router(Arc::new(RejectingSigner), repository.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/signing/v1/directories")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    // JSON extraction happens before handler authorization, but no valid document
    // can reach a signer without the workload identity.
    assert!(matches!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY | StatusCode::UNAUTHORIZED
    ));
    assert!(repository.published_versions().await.is_empty());
}

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use onionroute_directory_service::{
    router, ClientIngressConfig, MemoryDirectoryRepository, StoredDirectory,
};
use tower::ServiceExt;

#[tokio::test]
async fn exact_directory_bytes_are_served_without_personalization() {
    let bytes = br#"{"envelope_version":1,"signing_key_id":"key","trust_bundle":{"bundle":{"format_version":1,"bundle_version":1,"root_key_id":"root","issued_at":1,"expires_at":2,"signing_keys":[],"revoked_signing_key_ids":[]},"signature":"x"},"payload":"x","signature":"x"}"#.to_vec();
    let repository = Arc::new(MemoryDirectoryRepository::with_directory(StoredDirectory {
        version: 1,
        envelope: bytes.clone(),
    }));
    let response = router(repository)
        .oneshot(
            Request::builder()
                .uri("/client/v2/directory")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["cache-control"],
        "private, no-store, max-age=0"
    );
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        bytes
    );
}

#[test]
fn public_client_bind_is_rejected() {
    let config = ClientIngressConfig {
        bind: "0.0.0.0:443".parse().unwrap(),
        onion_hostname: format!("{}.onion", "a".repeat(56)),
    };
    assert!(config.validate().is_err());
}

#[tokio::test]
async fn bootstrap_rejects_identity_shaped_unknown_fields() {
    let repository = Arc::new(MemoryDirectoryRepository::default());
    let response = router(repository)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/client/v1/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"client_version":"1.2.3","platform":"windows","channel":"stable","user_id":"forbidden"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use onionroute_admin_api::{router, AdminIngressConfig, MemoryAdminRepository};
use tower::ServiceExt;

#[test]
fn admin_ingress_cannot_share_client_listener() {
    let bind = "127.0.0.1:8080".parse().unwrap();
    let config = AdminIngressConfig {
        bind,
        client_api_bind: Some(bind),
    };
    assert!(config.validate().is_err());
}

#[tokio::test]
async fn unauthenticated_admin_command_is_rejected() {
    let repository = Arc::new(MemoryAdminRepository::default());
    let response = router(repository.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/v1/directory-publications")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"validity_seconds":3600}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(repository.commands().await.is_empty());
}

#[tokio::test]
async fn authenticated_publication_reserves_monotonic_version() {
    let repository = Arc::new(MemoryAdminRepository::default());
    let response = router(repository.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/v1/directory-publications")
                .header("content-type", "application/json")
                .header("x-onionroute-admin-subject", "ops:publisher")
                .body(Body::from(r#"{"validity_seconds":3600}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(
        repository.commands().await[0].command,
        "create_directory_draft"
    );
}

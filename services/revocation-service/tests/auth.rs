use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use onionroute_revocation_service::{router, MemoryRevocationRepository};
use tower::ServiceExt;

#[tokio::test]
async fn active_revocations_are_workload_authenticated() {
    let repository = Arc::new(MemoryRevocationRepository::default());
    let unauthorized = router(repository.clone())
        .oneshot(
            Request::builder()
                .uri("/revocation/v1/gateways")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let authorized = router(repository)
        .oneshot(
            Request::builder()
                .uri("/revocation/v1/gateways")
                .header("x-onionroute-workload-subject", "directory-publisher")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::OK);
}

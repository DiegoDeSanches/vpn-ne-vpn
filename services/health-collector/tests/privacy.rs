use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use onionroute_directory_client::{CapacityBucket, HealthState, LoadBucket};
use onionroute_health_collector::{router, HealthCheck, HealthReport, MemoryHealthRepository};
use tower::ServiceExt;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn report() -> HealthReport {
    HealthReport {
        gateway_id: "gateway-de-1".to_owned(),
        sequence: 1,
        observed_at: now(),
        health: HealthState::Healthy,
        load_bucket: LoadBucket::Low,
        capacity_bucket: CapacityBucket::Medium,
        checks: vec![HealthCheck {
            name: "onion_reachable".to_owned(),
            ok: true,
            latency_bucket: "normal".to_owned(),
        }],
    }
}

#[tokio::test]
async fn authenticated_sample_contains_no_user_or_source_ip() {
    let repository = Arc::new(MemoryHealthRepository::default());
    let response = router(repository.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/gateway-health/v1/samples")
                .header("content-type", "application/json")
                .header("x-onionroute-gateway-id", "gateway-de-1")
                .body(Body::from(serde_json::to_vec(&report()).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(repository.reports().await, vec![report()]);
}

#[tokio::test]
async fn source_ip_field_is_rejected_instead_of_logged_or_stored() {
    let repository = Arc::new(MemoryHealthRepository::default());
    let mut value = serde_json::to_value(report()).unwrap();
    value["source_ip"] = serde_json::json!("203.0.113.7");
    let response = router(repository.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/gateway-health/v1/samples")
                .header("content-type", "application/json")
                .header("x-onionroute-gateway-id", "gateway-de-1")
                .body(Body::from(serde_json::to_vec(&value).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(repository.reports().await.is_empty());
}

#[tokio::test]
async fn m_tls_identity_must_match_body() {
    let repository = Arc::new(MemoryHealthRepository::default());
    let response = router(repository)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/gateway-health/v1/samples")
                .header("content-type", "application/json")
                .header("x-onionroute-gateway-id", "gateway-other")
                .body(Body::from(serde_json::to_vec(&report()).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

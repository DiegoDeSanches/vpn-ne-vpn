use onionroute_admin_api::AdminIngressConfig;
use onionroute_directory_service::ClientIngressConfig;
use onionroute_health_collector::HealthIngressConfig;
use onionroute_revocation_service::RevocationIngressConfig;
use onionroute_signing_service::SigningIngressConfig;

#[test]
fn every_api_class_has_a_distinct_fail_closed_listener() {
    let client_bind = "127.0.0.1:18080".parse().unwrap();
    let admin_bind = "127.0.0.1:18082".parse().unwrap();
    let signing_bind = "127.0.0.1:18083".parse().unwrap();
    let revocation_bind = "127.0.0.1:18084".parse().unwrap();

    ClientIngressConfig {
        bind: client_bind,
        onion_hostname: format!("{}.onion", "a".repeat(56)),
    }
    .validate()
    .unwrap();
    HealthIngressConfig {
        bind: "127.0.0.1:18081".parse().unwrap(),
    }
    .validate()
    .unwrap();
    AdminIngressConfig {
        bind: admin_bind,
        client_api_bind: Some(client_bind),
    }
    .validate()
    .unwrap();
    SigningIngressConfig {
        bind: signing_bind,
        admin_api_bind: Some(admin_bind),
    }
    .validate()
    .unwrap();
    RevocationIngressConfig {
        bind: revocation_bind,
        forbidden_shared_binds: vec![client_bind, admin_bind, signing_bind],
    }
    .validate()
    .unwrap();

    assert!(AdminIngressConfig {
        bind: client_bind,
        client_api_bind: Some(client_bind),
    }
    .validate()
    .is_err());
}

#[test]
fn database_contains_required_tables_and_public_allowlist() {
    let migration = include_str!("../../../../services/migrations/0001_control_plane.sql");
    for table in [
        "gateways",
        "gateway_roles",
        "countries",
        "health_samples",
        "directory_versions",
        "signing_keys",
        "revocations",
        "client_version_rules",
        "incidents",
        "feature_flags",
    ] {
        assert!(
            migration.contains(&format!("CREATE TABLE {table}")),
            "missing {table}"
        );
    }

    let projection = migration
        .split("CREATE VIEW directory_gateway_projection AS")
        .nth(1)
        .unwrap()
        .split("CREATE OR REPLACE FUNCTION")
        .next()
        .unwrap();
    for forbidden in [
        "management_ip",
        "internal_topology",
        "cloud_account",
        "exact_capacity",
        "updated_by",
        "created_by",
    ] {
        assert!(
            !projection.contains(forbidden),
            "public projection leaks {forbidden}"
        );
    }
}

#[test]
fn administrator_openapi_is_private_m_tls_only() {
    let openapi = include_str!("../../../../services/admin-api/openapi/admin-v1.yaml");
    assert!(openapi.contains("type: mutualTLS"));
    assert!(openapi.contains("https://admin.control.internal"));
    assert!(!openapi.contains("/client/v1/bootstrap"));
    assert!(!openapi.contains("/client/v2/directory"));
}

#[test]
fn gateway_schema_contains_no_account_or_billing_identity() {
    let schema = [
        include_str!("../../../proto/gateway/v1/gateway.proto"),
        include_str!("../../../proto/gateway/v1/handshake.proto"),
        include_str!("../../../proto/gateway/v1/stream.proto"),
        include_str!("../../../proto/gateway/v1/types.proto"),
    ]
    .join("\n")
    .to_ascii_lowercase();

    for forbidden in [
        "account_id",
        "user_id",
        "device_id",
        "payment_id",
        "billing_id",
        "client_ip",
    ] {
        assert!(
            !schema.contains(forbidden),
            "forbidden identity field: {forbidden}"
        );
    }
}

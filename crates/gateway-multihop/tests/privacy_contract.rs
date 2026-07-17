use onionroute_gateway_multihop::protocol::{
    inter_gateway_frame, InterGatewayFrame, OpenSession, WireVersion,
};
use prost::Message;

#[test]
fn inter_gateway_wire_has_no_account_or_source_ip_field() {
    let source = include_str!("../src/protocol.rs");
    assert!(!source.contains("account_id"));
    assert!(!source.contains("client_ip"));
    assert!(!source.contains("source_ip"));

    let frame = InterGatewayFrame {
        sequence: 3,
        version: Some(WireVersion { major: 1, minor: 0 }),
        connection_id: vec![7; 16],
        body: Some(inter_gateway_frame::Body::OpenSession(OpenSession {
            session_id: 1,
            terminal_protocol_version: Some(WireVersion { major: 1, minor: 0 }),
            initial_receive_window: 65_536,
            expires_at_unix_seconds: 1_900_000_000,
        })),
    };
    assert!(frame.encoded_len() < 128);
}

#[test]
fn entry_api_cannot_receive_a_socket_address() {
    let source = include_str!("../src/entry.rs");
    assert!(!source.contains("use std::net"));
    assert!(!source.contains("pub source_address"));
    assert!(!source.contains("pub peer_address"));
}

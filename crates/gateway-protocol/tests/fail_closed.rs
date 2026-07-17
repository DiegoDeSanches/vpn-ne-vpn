use onionroute_gateway_protocol::framing::write_frame;
use onionroute_gateway_protocol::limits::{ProtocolLimits, ABSOLUTE_MAX_FRAME_SIZE};
use onionroute_gateway_protocol::negotiation::version;
use onionroute_gateway_protocol::proto::gateway_frame::Body;
use onionroute_gateway_protocol::proto::{GatewayFrame, Ping};
use onionroute_gateway_protocol::session::{Session, SessionPhase};
use onionroute_gateway_protocol::ProtocolError;

#[tokio::test]
async fn inbound_protocol_error_permanently_closes_session() {
    let (client_io, mut peer_io) = tokio::io::duplex(4096);
    let mut session =
        Session::new_client(client_io, ProtocolLimits::default(), version(1, 0)).unwrap();
    let invalid_for_phase = GatewayFrame {
        sequence: 1,
        version: Some(version(1, 0)),
        critical_extension_ids: Vec::new(),
        session_id: Vec::new(),
        body: Some(Body::Ping(Ping { nonce: vec![0; 8] })),
    };
    write_frame(&mut peer_io, &invalid_for_phase, ABSOLUTE_MAX_FRAME_SIZE)
        .await
        .unwrap();

    assert!(matches!(
        session.receive().await,
        Err(ProtocolError::InvalidSession)
    ));
    assert_eq!(session.phase(), SessionPhase::Closed);
    assert!(matches!(
        session.receive().await,
        Err(ProtocolError::Closed)
    ));
}

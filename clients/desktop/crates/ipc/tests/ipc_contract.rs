use onionroute_desktop_ipc::{
    decode_frame, encode_frame,
    v1::{envelope, ClientHello, Envelope, EventTopic, ProtocolVersion, ProtocolVersionRange},
    FrameError, IPC_V1, MAX_FRAME_BYTES,
};

fn hello() -> Envelope {
    Envelope {
        version: Some(IPC_V1),
        request_id: vec![7; 16],
        sequence: 1,
        body: Some(envelope::Body::ClientHello(ClientHello {
            supported_versions: Some(ProtocolVersionRange {
                minimum: Some(ProtocolVersion { major: 1, minor: 0 }),
                maximum: Some(ProtocolVersion { major: 1, minor: 0 }),
            }),
            process_nonce: vec![9; 32],
            requested_topics: vec![EventTopic::TunnelState as i32],
            event_window: 32,
        })),
    }
}

#[test]
fn frame_round_trip_is_exact_and_bounded() {
    let source = hello();
    let bytes = encode_frame(&source).unwrap();
    assert_eq!(decode_frame(&bytes).unwrap(), source);
}

#[test]
fn oversized_length_is_rejected_before_decode() {
    let mut bytes = Vec::from(((MAX_FRAME_BYTES + 1) as u32).to_be_bytes());
    bytes.extend_from_slice(&[0; 4]);
    assert_eq!(decode_frame(&bytes), Err(FrameError::TooLarge));
}

#[test]
fn trailing_frames_are_not_silently_accepted() {
    let mut bytes = encode_frame(&hello()).unwrap();
    bytes.push(0);
    assert_eq!(decode_frame(&bytes), Err(FrameError::TrailingBytes));
}

#[test]
fn unknown_or_duplicate_topics_fail_closed() {
    let mut envelope = hello();
    if let Some(envelope::Body::ClientHello(hello)) = envelope.body.as_mut() {
        hello.requested_topics = vec![1, 1];
    }
    assert!(encode_frame(&envelope).is_err());
    if let Some(envelope::Body::ClientHello(hello)) = envelope.body.as_mut() {
        hello.requested_topics = vec![99];
    }
    assert!(encode_frame(&envelope).is_err());
}

#[test]
fn peer_debug_output_redacts_binding() {
    use onionroute_desktop_ipc::{AuthenticatedPeer, PeerRole};
    let peer = AuthenticatedPeer::new(PeerRole::UnprivilegedUi, [0xAB; 32]);
    let debug = format!("{peer:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("171"));
}

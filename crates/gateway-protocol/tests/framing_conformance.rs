use std::collections::BTreeSet;

use onionroute_gateway_protocol::debug::FrameSummary;
use onionroute_gateway_protocol::framing::{decode_frame_bytes, encode_frame, FrameDecoder};
use onionroute_gateway_protocol::limits::ABSOLUTE_MAX_FRAME_SIZE;
use onionroute_gateway_protocol::negotiation::{
    select_version, verify_server_selection, version, version_range,
};
use onionroute_gateway_protocol::proto::destination::Value;
use onionroute_gateway_protocol::proto::gateway_frame::Body;
use onionroute_gateway_protocol::proto::{Data, Destination, GatewayFrame, OpenTcpStream, Ping};
use onionroute_gateway_protocol::validation::validate_frame;
use onionroute_gateway_protocol::wire::onionroute::common::v1::ProtocolVersion;
use onionroute_gateway_protocol::ProtocolError;
use proptest::prelude::*;

fn ping_frame() -> GatewayFrame {
    GatewayFrame {
        sequence: 1,
        version: Some(ProtocolVersion { major: 1, minor: 0 }),
        critical_extension_ids: Vec::new(),
        session_id: Vec::new(),
        body: Some(Body::Ping(Ping {
            nonce: (0u8..8).collect(),
        })),
    }
}

#[test]
fn golden_ping_frame_is_stable() {
    let encoded = encode_frame(&ping_frame(), ABSOLUTE_MAX_FRAME_SIZE).unwrap();
    let expected = [
        0x13, 0x08, 0x01, 0x12, 0x02, 0x08, 0x01, 0xca, 0x01, 0x0a, 0x0a, 0x08, 0x00, 0x01, 0x02,
        0x03, 0x04, 0x05, 0x06, 0x07,
    ];
    assert_eq!(encoded, expected);
}

#[test]
fn incremental_decoder_accepts_every_chunk_boundary() {
    let encoded = encode_frame(&ping_frame(), ABSOLUTE_MAX_FRAME_SIZE).unwrap();
    for boundary in 0..=encoded.len() {
        let mut decoder = FrameDecoder::new(ABSOLUTE_MAX_FRAME_SIZE).unwrap();
        let first = decoder.push(&encoded[..boundary]).unwrap();
        assert_eq!(first.consumed, boundary);
        let decoded = if let Some(frame) = first.frame {
            frame
        } else {
            decoder
                .push(&encoded[boundary..])
                .unwrap()
                .frame
                .expect("complete second chunk")
        };
        assert_eq!(decoded.sequence, 1);
    }
}

#[test]
fn unknown_message_tag_and_duplicate_fields_are_rejected() {
    // sequence=1, version={major=1}, unknown length-delimited message tag 29.
    let unknown = [0x08, 0x01, 0x12, 0x02, 0x08, 0x01, 0xea, 0x01, 0x00];
    assert!(matches!(
        decode_frame_bytes(&unknown),
        Err(ProtocolError::UnknownMessageTag(29))
    ));

    let duplicate_sequence = [
        0x08, 0x01, 0x08, 0x02, 0x12, 0x02, 0x08, 0x01, 0xca, 0x01, 0x0a, 0x0a, 0x08, 0x00, 0x01,
        0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    ];
    assert!(matches!(
        decode_frame_bytes(&duplicate_sequence),
        Err(ProtocolError::DuplicateField(1))
    ));
}

#[test]
fn length_prefix_is_canonical_and_bounded_before_allocation() {
    let mut decoder = FrameDecoder::new(1024).unwrap();
    assert!(matches!(
        decoder.push(&[0x80, 0x00]),
        Err(ProtocolError::NonCanonicalVarint)
    ));
    let encoded = encode_frame(&ping_frame(), 1024).unwrap();
    assert!(decoder.push(&encoded).unwrap().frame.is_some());

    let mut decoder = FrameDecoder::new(1024).unwrap();
    // 1025 encoded as unsigned varint.
    assert!(matches!(
        decoder.push(&[0x81, 0x08]),
        Err(ProtocolError::FrameTooLarge { .. })
    ));
    assert_eq!(decoder.buffered_bytes(), 0);
}

#[test]
fn version_selection_is_maximal_and_detects_downgrade() {
    let client = version_range(1, 1, 5);
    let server = version_range(1, 0, 3);
    assert_eq!(select_version(&client, &server).unwrap(), version(1, 3));
    assert!(matches!(
        verify_server_selection(&client, &server, &version(1, 2)),
        Err(ProtocolError::SilentDowngrade)
    ));
}

#[test]
fn unknown_critical_extension_is_rejected() {
    let mut frame = ping_frame();
    frame.critical_extension_ids.push(77);
    assert!(validate_frame(&frame, &BTreeSet::new()).is_err());
}

#[test]
fn debug_summary_redacts_payload_and_destination() {
    let secret_hostname = "private.example";
    let frame = GatewayFrame {
        sequence: 9,
        version: Some(version(1, 0)),
        critical_extension_ids: Vec::new(),
        session_id: vec![0; 16],
        body: Some(Body::OpenTcpStream(OpenTcpStream {
            stream_id: 1,
            destination: Some(Destination {
                value: Some(Value::Hostname(secret_hostname.to_owned())),
            }),
            destination_port: 443,
            timeout_ms: 10_000,
            policy_flags: 0,
            initial_receive_window: 1024,
        })),
    };
    let rendered = format!(
        "{:?} {}",
        FrameSummary::from_frame(&frame),
        FrameSummary::from_frame(&frame)
    );
    assert!(!rendered.contains(secret_hostname));

    let payload = b"do-not-log-this".to_vec();
    let data = GatewayFrame {
        body: Some(Body::Data(Data {
            stream_id: 1,
            payload: payload.clone(),
        })),
        ..frame
    };
    let rendered = format!("{:?}", FrameSummary::from_frame(&data));
    assert!(!rendered.contains(std::str::from_utf8(&payload).unwrap()));
    assert!(rendered.contains("payload-redacted"));
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_exceed_decoder_memory(input in prop::collection::vec(any::<u8>(), 0..200_000)) {
        let mut decoder = FrameDecoder::new(ABSOLUTE_MAX_FRAME_SIZE).unwrap();
        let mut offset = 0usize;
        while offset < input.len() {
            match decoder.push(&input[offset..]) {
                Ok(progress) => {
                    prop_assert!(decoder.buffered_bytes() <= ABSOLUTE_MAX_FRAME_SIZE + 5);
                    if progress.consumed == 0 {
                        break;
                    }
                    offset += progress.consumed;
                }
                Err(_) => break,
            }
        }
    }
}

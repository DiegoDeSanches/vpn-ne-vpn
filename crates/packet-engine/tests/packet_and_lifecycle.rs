use std::net::Ipv4Addr;
use std::sync::Arc;

use onionroute_common_types::state::ClientConnectionState;
use onionroute_common_types::types::{
    AnonymityMode, FlowId, GatewayId, IsolationKey, PolicyAction, PolicyDecision,
};
use onionroute_packet_engine::{
    build_tcp_packet, build_udp_packet, classify, BlockReason, BufferLimits, ClassifiedPacket,
    CloseDirection, EngineAction, EngineConfig, NoopMetrics, PacketEngineInput, PacketProcessor,
    PlatformMetadata, ProtectedRoute, TcpFlags, TcpFlowState,
};

const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const SERVER: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
const CLIENT_PORT: u16 = 49_152;
const SERVER_PORT: u16 = 443;

fn engine() -> PacketProcessor {
    PacketProcessor::new(EngineConfig::default(), Arc::new(NoopMetrics))
        .expect("default config is valid")
}

fn route(action: PolicyAction) -> ProtectedRoute {
    ProtectedRoute {
        decision: PolicyDecision {
            action,
            rule_id: "test.rule.v1".to_owned(),
        },
        hostname: Some("example.com".to_owned()),
        isolation_key: IsolationKey([7; 32]),
        anonymity_profile: AnonymityMode::Standard,
        gateway_id: Some(GatewayId("gateway-test".to_owned())),
    }
}

fn packet(seq: u32, ack: u32, flags: TcpFlags, payload: &[u8]) -> Vec<u8> {
    build_tcp_packet(
        CLIENT,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        seq,
        ack,
        flags,
        32_768,
        payload,
    )
}

fn process(
    engine: &mut PacketProcessor,
    packet: &[u8],
    route: Option<ProtectedRoute>,
    now: u64,
) -> Vec<EngineAction> {
    engine.process(PacketEngineInput {
        packet,
        platform: PlatformMetadata {
            application: None,
            monotonic_ms: now,
        },
        route,
        connection_state: ClientConnectionState::Connected,
    })
}

#[test]
fn checked_parser_reads_ipv4_tcp() {
    let bytes = packet(
        100,
        0,
        TcpFlags {
            syn: true,
            ..TcpFlags::default()
        },
        b"",
    );
    let ClassifiedPacket::Tcp(segment) = classify(&bytes).expect("valid segment") else {
        panic!("expected TCP");
    };
    assert_eq!(segment.source, CLIENT);
    assert_eq!(segment.destination, SERVER);
    assert_eq!(segment.source_port, CLIENT_PORT);
    assert_eq!(segment.destination_port, SERVER_PORT);
    assert_eq!(segment.sequence, 100);
    assert!(segment.flags.syn);
}

#[test]
fn malformed_lengths_and_checksums_fail_without_flow() {
    let mut bad_length = packet(
        100,
        0,
        TcpFlags {
            syn: true,
            ..TcpFlags::default()
        },
        b"",
    );
    bad_length[2..4].copy_from_slice(&10u16.to_be_bytes());
    assert!(classify(&bad_length).is_err());

    let mut bad_checksum = packet(
        100,
        0,
        TcpFlags {
            syn: true,
            ..TcpFlags::default()
        },
        b"",
    );
    bad_checksum[10] ^= 0xff;
    assert!(classify(&bad_checksum).is_err());

    let mut engine = engine();
    let actions = process(&mut engine, &[0x45, 0], None, 1);
    assert!(matches!(
        actions.first(),
        Some(EngineAction::BlockFlow {
            reason: BlockReason::MalformedPacket,
            ..
        })
    ));
    assert_eq!(engine.active_flows(), 0);

    let invalid_syn = packet(
        100,
        0,
        TcpFlags {
            syn: true,
            fin: true,
            ..TcpFlags::default()
        },
        b"fast-open-is-unsupported",
    );
    let actions = process(
        &mut engine,
        &invalid_syn,
        Some(route(PolicyAction::Tunnel)),
        2,
    );
    assert!(actions.iter().any(|action| matches!(
        action,
        EngineAction::BlockFlow {
            reason: BlockReason::MalformedPacket,
            ..
        }
    )));
    assert_eq!(engine.active_flows(), 0);
}

#[test]
fn tcp_syn_ack_payload_retransmission_fin_and_remote_fin() {
    let mut engine = engine();
    let syn = packet(
        100,
        0,
        TcpFlags {
            syn: true,
            ..TcpFlags::default()
        },
        b"",
    );
    let actions = process(&mut engine, &syn, Some(route(PolicyAction::Tunnel)), 1);
    let flow_id = actions
        .iter()
        .find_map(|action| match action {
            EngineAction::OpenProtectedStream { request, .. } => Some(request.flow_id),
            _ => None,
        })
        .expect("protected open action");
    assert_eq!(
        engine.flow(flow_id).expect("flow").state,
        TcpFlowState::Connecting
    );

    let opened = engine.protected_stream_opened(flow_id, 2);
    let syn_ack = opened
        .iter()
        .find_map(|action| match action {
            EngineAction::SendSyntheticResponse { packet } => Some(packet),
            _ => None,
        })
        .expect("SYN-ACK packet");
    let ClassifiedPacket::Tcp(syn_ack_segment) = classify(syn_ack).expect("valid SYN-ACK") else {
        panic!("expected TCP");
    };
    assert!(syn_ack_segment.flags.syn && syn_ack_segment.flags.ack);
    assert_eq!(syn_ack_segment.acknowledgement, 101);
    let server_next = syn_ack_segment.sequence.wrapping_add(1);

    let ack = packet(101, server_next, TcpFlags::ack(), b"");
    process(&mut engine, &ack, None, 3);
    assert_eq!(
        engine.flow(flow_id).expect("flow").state,
        TcpFlowState::Established
    );

    let data = packet(
        101,
        server_next,
        TcpFlags {
            psh: true,
            ..TcpFlags::ack()
        },
        b"hello",
    );
    let data_actions = process(&mut engine, &data, None, 4);
    assert_eq!(
        data_actions
            .iter()
            .filter(|action| matches!(action, EngineAction::ForwardPayload { .. }))
            .count(),
        1
    );
    engine.acknowledge_forwarded(flow_id, 5, 4);

    let retransmit = process(&mut engine, &data, None, 5);
    assert!(!retransmit
        .iter()
        .any(|action| matches!(action, EngineAction::ForwardPayload { .. })));
    assert!(retransmit
        .iter()
        .any(|action| matches!(action, EngineAction::RecordDiagnostic { .. })));

    let remote = engine.protected_payload(flow_id, b"world", 6);
    let remote_packet = remote
        .iter()
        .find_map(|action| match action {
            EngineAction::SendSyntheticResponse { packet } => Some(packet),
            _ => None,
        })
        .expect("protected payload packet");
    let ClassifiedPacket::Tcp(remote_segment) = classify(remote_packet).expect("valid data") else {
        panic!("expected TCP");
    };
    let remote_next = remote_segment
        .sequence
        .wrapping_add(remote_segment.payload.len() as u32);

    let fin = packet(106, remote_next, TcpFlags::fin_ack(), b"");
    let fin_actions = process(&mut engine, &fin, None, 7);
    assert!(fin_actions.iter().any(|action| matches!(
        action,
        EngineAction::CloseProtectedStream {
            direction: CloseDirection::Write,
            ..
        }
    )));
    assert_eq!(
        engine.flow(flow_id).expect("flow").state,
        TcpFlowState::HalfClosedLocal
    );

    let remote_fin = engine.protected_stream_closed(flow_id, 8);
    assert!(remote_fin
        .iter()
        .any(|action| matches!(action, EngineAction::SendSyntheticResponse { .. })));
    assert_eq!(
        engine.flow(flow_id).expect("flow").state,
        TcpFlowState::Closing
    );
}

#[test]
fn payload_ack_is_deferred_until_protected_write_succeeds() {
    let mut engine = engine();
    let syn = packet(
        1,
        0,
        TcpFlags {
            syn: true,
            ..TcpFlags::default()
        },
        b"",
    );
    let actions = process(&mut engine, &syn, Some(route(PolicyAction::Tunnel)), 1);
    let flow_id = actions
        .iter()
        .find_map(|action| match action {
            EngineAction::OpenProtectedStream { request, .. } => Some(request.flow_id),
            _ => None,
        })
        .expect("flow");
    let opened = engine.protected_stream_opened(flow_id, 2);
    let syn_ack = opened
        .iter()
        .find_map(|action| match action {
            EngineAction::SendSyntheticResponse { packet } => Some(packet),
            _ => None,
        })
        .expect("SYN-ACK");
    let ClassifiedPacket::Tcp(syn_ack) = classify(syn_ack).expect("valid") else {
        panic!()
    };
    let server_next = syn_ack.sequence.wrapping_add(1);
    process(
        &mut engine,
        &packet(2, server_next, TcpFlags::ack(), b""),
        None,
        3,
    );

    let actions = process(
        &mut engine,
        &packet(
            2,
            server_next,
            TcpFlags {
                psh: true,
                ..TcpFlags::ack()
            },
            b"hello",
        ),
        None,
        4,
    );
    assert!(actions
        .iter()
        .any(|action| matches!(action, EngineAction::ForwardPayload { .. })));
    assert!(!actions
        .iter()
        .any(|action| matches!(action, EngineAction::SendSyntheticResponse { .. })));

    let committed = engine.acknowledge_forwarded(flow_id, 5, 5);
    assert!(committed
        .iter()
        .any(|action| matches!(action, EngineAction::SendSyntheticResponse { .. })));
}

#[test]
fn protected_payload_is_bounded_retransmitted_and_released_by_ack() {
    let config = EngineConfig {
        retransmit_interval_ms: 5,
        max_retransmissions: 2,
        ..EngineConfig::default()
    };
    let mut engine = PacketProcessor::new(config, Arc::new(NoopMetrics)).expect("valid config");
    let syn = packet(
        10,
        0,
        TcpFlags {
            syn: true,
            ..TcpFlags::default()
        },
        b"",
    );
    let actions = process(&mut engine, &syn, Some(route(PolicyAction::Tunnel)), 1);
    let flow_id = actions
        .iter()
        .find_map(|action| match action {
            EngineAction::OpenProtectedStream { request, .. } => Some(request.flow_id),
            _ => None,
        })
        .expect("flow");
    let opened = engine.protected_stream_opened(flow_id, 2);
    let syn_ack = opened
        .iter()
        .find_map(|action| match action {
            EngineAction::SendSyntheticResponse { packet } => Some(packet),
            _ => None,
        })
        .expect("SYN-ACK");
    let ClassifiedPacket::Tcp(syn_ack) = classify(syn_ack).expect("valid") else {
        panic!()
    };
    let server_next = syn_ack.sequence.wrapping_add(1);
    process(
        &mut engine,
        &packet(11, server_next, TcpFlags::ack(), b""),
        None,
        3,
    );

    let outbound = engine.protected_payload(flow_id, b"reply", 4);
    let packet_out = outbound
        .iter()
        .find_map(|action| match action {
            EngineAction::SendSyntheticResponse { packet } => Some(packet),
            _ => None,
        })
        .expect("outbound packet");
    let ClassifiedPacket::Tcp(outbound) = classify(packet_out).expect("valid") else {
        panic!()
    };
    assert_eq!(engine.protected_read_capacity(flow_id), 0);
    let retransmit = engine.tick(9);
    assert!(retransmit.iter().any(|action| matches!(
        action,
        EngineAction::RecordDiagnostic {
            code: onionroute_packet_engine::DiagnosticCode::Retransmission,
            ..
        }
    )));

    let acknowledged = packet(
        11,
        outbound
            .sequence
            .wrapping_add(outbound.payload.len() as u32),
        TcpFlags::ack(),
        b"",
    );
    process(&mut engine, &acknowledged, None, 10);
    assert_eq!(
        engine.protected_read_capacity(flow_id),
        EngineConfig::default().buffers.to_application_bytes
    );
    assert_eq!(engine.flow(flow_id).expect("flow").queued_to_application, 0);
}

#[test]
fn remote_first_fin_preserves_local_write_half_until_application_fin() {
    let mut engine = engine();
    let syn = packet(
        100,
        0,
        TcpFlags {
            syn: true,
            ..TcpFlags::default()
        },
        b"",
    );
    let actions = process(&mut engine, &syn, Some(route(PolicyAction::Tunnel)), 1);
    let flow_id = actions
        .iter()
        .find_map(|action| match action {
            EngineAction::OpenProtectedStream { request, .. } => Some(request.flow_id),
            _ => None,
        })
        .expect("flow");
    let opened = engine.protected_stream_opened(flow_id, 2);
    let syn_ack = opened
        .iter()
        .find_map(|action| match action {
            EngineAction::SendSyntheticResponse { packet } => Some(packet),
            _ => None,
        })
        .expect("SYN-ACK");
    let ClassifiedPacket::Tcp(syn_ack) = classify(syn_ack).expect("valid") else {
        panic!()
    };
    let server_next = syn_ack.sequence.wrapping_add(1);
    process(
        &mut engine,
        &packet(101, server_next, TcpFlags::ack(), b""),
        None,
        3,
    );

    let remote_fin = engine.protected_stream_closed(flow_id, 4);
    let fin_packet = remote_fin
        .iter()
        .find_map(|action| match action {
            EngineAction::SendSyntheticResponse { packet } => Some(packet),
            _ => None,
        })
        .expect("remote FIN");
    let ClassifiedPacket::Tcp(fin) = classify(fin_packet).expect("valid FIN") else {
        panic!()
    };
    let after_fin = fin.sequence.wrapping_add(1);
    process(
        &mut engine,
        &packet(101, after_fin, TcpFlags::ack(), b""),
        None,
        5,
    );
    assert_eq!(
        engine.flow(flow_id).expect("half-open flow").state,
        TcpFlowState::HalfClosedRemote
    );

    let local_tail = process(
        &mut engine,
        &packet(
            101,
            after_fin,
            TcpFlags {
                psh: true,
                ..TcpFlags::ack()
            },
            b"tail",
        ),
        None,
        6,
    );
    assert!(local_tail
        .iter()
        .any(|action| matches!(action, EngineAction::ForwardPayload { .. })));
    engine.acknowledge_forwarded(flow_id, 4, 7);

    let local_fin = process(
        &mut engine,
        &packet(105, after_fin, TcpFlags::fin_ack(), b""),
        None,
        8,
    );
    assert!(local_fin.iter().any(|action| matches!(
        action,
        EngineAction::CloseProtectedStream {
            direction: CloseDirection::Both,
            ..
        }
    )));
    assert!(local_fin
        .iter()
        .any(|action| matches!(action, EngineAction::SendSyntheticResponse { .. })));
    assert!(engine.flow(flow_id).is_none());
}

#[test]
fn dns_is_blocked_when_protected_path_is_not_active() {
    let mut engine = engine();
    let dns = build_udp_packet(CLIENT, Ipv4Addr::new(8, 8, 8, 8), CLIENT_PORT, 53, &[0; 12]);
    let actions = engine.process(PacketEngineInput {
        packet: &dns,
        platform: PlatformMetadata {
            application: None,
            monotonic_ms: 1,
        },
        route: None,
        connection_state: ClientConnectionState::Reconnecting,
    });
    assert!(actions.iter().any(|action| matches!(
        action,
        EngineAction::BlockFlow {
            reason: BlockReason::ProtectedPathUnavailable,
            ..
        }
    )));
    assert_eq!(engine.pending_dns(), 0);
}

#[test]
fn rst_releases_flow_without_fallback() {
    let mut engine = engine();
    let syn = packet(
        10,
        0,
        TcpFlags {
            syn: true,
            ..TcpFlags::default()
        },
        b"",
    );
    let actions = process(&mut engine, &syn, Some(route(PolicyAction::Tunnel)), 1);
    let flow_id = actions
        .iter()
        .find_map(|action| match action {
            EngineAction::OpenProtectedStream { request, .. } => Some(request.flow_id),
            _ => None,
        })
        .expect("flow ID");
    let rst = packet(
        11,
        0,
        TcpFlags {
            rst: true,
            ..TcpFlags::default()
        },
        b"",
    );
    let actions = process(&mut engine, &rst, None, 2);
    assert!(actions
        .iter()
        .any(|action| matches!(action, EngineAction::CloseProtectedStream { .. })));
    assert!(engine.flow(flow_id).is_none());
}

#[test]
fn bounded_buffer_exhaustion_resets_flow() {
    let config = EngineConfig {
        buffers: BufferLimits {
            to_gateway_bytes: 4,
            to_application_bytes: 4,
        },
        receive_window: 4,
        ..EngineConfig::default()
    };
    let mut engine = PacketProcessor::new(config, Arc::new(NoopMetrics)).expect("valid config");
    let syn = packet(
        1,
        0,
        TcpFlags {
            syn: true,
            ..TcpFlags::default()
        },
        b"",
    );
    let actions = process(&mut engine, &syn, Some(route(PolicyAction::Tunnel)), 1);
    let flow_id = actions
        .iter()
        .find_map(|action| match action {
            EngineAction::OpenProtectedStream { request, .. } => Some(request.flow_id),
            _ => None,
        })
        .expect("flow ID");
    let opened = engine.protected_stream_opened(flow_id, 2);
    let syn_ack = opened
        .iter()
        .find_map(|action| match action {
            EngineAction::SendSyntheticResponse { packet } => Some(packet),
            _ => None,
        })
        .expect("SYN-ACK");
    let ClassifiedPacket::Tcp(segment) = classify(syn_ack).expect("valid") else {
        panic!()
    };
    let server_next = segment.sequence.wrapping_add(1);
    process(
        &mut engine,
        &packet(2, server_next, TcpFlags::ack(), b""),
        None,
        3,
    );
    let actions = process(
        &mut engine,
        &packet(
            2,
            server_next,
            TcpFlags {
                psh: true,
                ..TcpFlags::ack()
            },
            b"12345",
        ),
        None,
        4,
    );
    assert!(actions.iter().any(|action| matches!(
        action,
        EngineAction::BlockFlow {
            reason: BlockReason::Backpressure,
            ..
        }
    )));
    assert!(engine.flow(flow_id).is_none());
}

#[test]
fn connect_idle_shutdown_and_resume_are_fail_closed() {
    let config = EngineConfig {
        connection_timeout_ms: 10,
        idle_timeout_ms: 20,
        ..EngineConfig::default()
    };
    let mut engine = PacketProcessor::new(config, Arc::new(NoopMetrics)).expect("valid config");
    let syn = packet(
        1,
        0,
        TcpFlags {
            syn: true,
            ..TcpFlags::default()
        },
        b"",
    );
    process(&mut engine, &syn, Some(route(PolicyAction::Tunnel)), 1);
    let timeout = engine.tick(11);
    assert!(timeout.iter().any(|action| matches!(
        action,
        EngineAction::BlockFlow {
            reason: BlockReason::ConnectionTimeout,
            ..
        }
    )));

    process(&mut engine, &syn, Some(route(PolicyAction::Tunnel)), 20);
    engine.suspend(21);
    assert!(engine.tick(10_000).is_empty());
    let resume = engine.resume(10_000, false);
    assert!(resume.iter().any(|action| matches!(
        action,
        EngineAction::BlockFlow {
            reason: BlockReason::ProtectedPathUnavailable,
            ..
        }
    )));
    assert_eq!(engine.active_flows(), 0);

    let stopped = engine.shutdown();
    assert!(stopped
        .iter()
        .any(|action| matches!(action, EngineAction::RecordDiagnostic { .. })));
    let denied = process(&mut engine, &syn, Some(route(PolicyAction::Tunnel)), 30);
    assert!(denied.iter().any(|action| matches!(
        action,
        EngineAction::BlockFlow {
            reason: BlockReason::Shutdown,
            ..
        }
    )));
}

#[test]
fn final_handshake_ack_remains_under_connection_deadline() {
    let config = EngineConfig {
        connection_timeout_ms: 10,
        ..EngineConfig::default()
    };
    let mut engine = PacketProcessor::new(config, Arc::new(NoopMetrics)).expect("valid config");
    let syn = packet(
        1,
        0,
        TcpFlags {
            syn: true,
            ..TcpFlags::default()
        },
        b"",
    );
    let opened = process(&mut engine, &syn, Some(route(PolicyAction::Tunnel)), 1);
    let flow_id = opened
        .iter()
        .find_map(|action| match action {
            EngineAction::OpenProtectedStream { request, .. } => Some(request.flow_id),
            _ => None,
        })
        .expect("flow");
    engine.protected_stream_opened(flow_id, 2);
    let expired = engine.tick(11);
    assert!(expired.iter().any(|action| matches!(
        action,
        EngineAction::BlockFlow {
            reason: BlockReason::ConnectionTimeout,
            ..
        }
    )));
    assert!(engine.flow(flow_id).is_none());
}

#[test]
fn dns_udp_is_intercepted_while_ipv6_quic_and_bypass_are_blocked() {
    let mut engine = engine();
    let dns = build_udp_packet(CLIENT, Ipv4Addr::new(8, 8, 8, 8), CLIENT_PORT, 53, &[0; 12]);
    let dns_actions = process(&mut engine, &dns, None, 1);
    assert!(dns_actions
        .iter()
        .any(|action| matches!(action, EngineAction::ResolveDns { .. })));

    let quic = build_udp_packet(CLIENT, SERVER, CLIENT_PORT, 443, b"quic");
    let quic_actions = process(&mut engine, &quic, None, 2);
    assert!(quic_actions.iter().any(|action| matches!(
        action,
        EngineAction::BlockFlow {
            reason: BlockReason::QuicBlocked,
            ..
        }
    )));

    let mut ipv6 = [0u8; 40];
    ipv6[0] = 0x60;
    let ipv6_actions = process(&mut engine, &ipv6, None, 3);
    assert!(ipv6_actions.iter().any(|action| matches!(
        action,
        EngineAction::BlockFlow {
            reason: BlockReason::Ipv6Blocked,
            ..
        }
    )));

    let syn = packet(
        5,
        0,
        TcpFlags {
            syn: true,
            ..TcpFlags::default()
        },
        b"",
    );
    let bypass = process(&mut engine, &syn, Some(route(PolicyAction::Bypass)), 4);
    assert!(bypass.iter().any(|action| matches!(
        action,
        EngineAction::BlockFlow {
            reason: BlockReason::DirectFallbackForbidden,
            ..
        }
    )));
}

#[test]
fn protected_path_state_is_required_for_new_flow() {
    let mut engine = engine();
    let syn = packet(
        1,
        0,
        TcpFlags {
            syn: true,
            ..TcpFlags::default()
        },
        b"",
    );
    let actions = engine.process(PacketEngineInput {
        packet: &syn,
        platform: PlatformMetadata {
            application: None,
            monotonic_ms: 1,
        },
        route: Some(route(PolicyAction::Tunnel)),
        connection_state: ClientConnectionState::Reconnecting,
    });
    assert!(actions.iter().any(|action| matches!(
        action,
        EngineAction::BlockFlow {
            reason: BlockReason::ProtectedPathUnavailable,
            ..
        }
    )));
    assert_eq!(engine.active_flows(), 0);
}

#[test]
fn flow_id_is_process_local_and_allocated_once_per_syn() {
    let mut engine = engine();
    let syn = packet(
        1,
        0,
        TcpFlags {
            syn: true,
            ..TcpFlags::default()
        },
        b"",
    );
    let first = process(&mut engine, &syn, Some(route(PolicyAction::Tunnel)), 1);
    let second = process(&mut engine, &syn, Some(route(PolicyAction::Tunnel)), 2);
    assert_eq!(
        first
            .iter()
            .filter(|action| matches!(action, EngineAction::OpenProtectedStream { .. }))
            .count(),
        1
    );
    assert_eq!(
        second
            .iter()
            .filter(|action| matches!(action, EngineAction::OpenProtectedStream { .. }))
            .count(),
        0
    );
    assert_eq!(engine.flow_ids(), vec![FlowId(1)]);
}

#[test]
fn tcp_dns_is_locally_terminated_and_length_framed() {
    let mut engine = engine();
    let dns_packet = |seq, ack, flags: TcpFlags, payload: &[u8]| {
        build_tcp_packet(
            CLIENT,
            SERVER,
            CLIENT_PORT,
            53,
            seq,
            ack,
            flags,
            32_768,
            payload,
        )
    };
    let syn = dns_packet(
        100,
        0,
        TcpFlags {
            syn: true,
            ..TcpFlags::default()
        },
        &[],
    );
    let opened = process(&mut engine, &syn, None, 1);
    let syn_ack = opened
        .iter()
        .find_map(|action| match action {
            EngineAction::SendSyntheticResponse { packet } => Some(packet),
            _ => None,
        })
        .expect("local DNS SYN-ACK");
    let ClassifiedPacket::Tcp(syn_ack) = classify(syn_ack).expect("valid SYN-ACK") else {
        panic!()
    };
    let server_next = syn_ack.sequence.wrapping_add(1);
    process(
        &mut engine,
        &dns_packet(101, server_next, TcpFlags::ack(), &[]),
        None,
        2,
    );

    let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend_from_slice(&[7]);
    query.extend_from_slice(b"example");
    query.extend_from_slice(&[3]);
    query.extend_from_slice(b"com");
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(&query);
    let actions = process(
        &mut engine,
        &dns_packet(
            101,
            server_next,
            TcpFlags {
                psh: true,
                ..TcpFlags::ack()
            },
            &framed,
        ),
        None,
        3,
    );
    let query_id = actions
        .iter()
        .find_map(|action| match action {
            EngineAction::ResolveDns { query, .. } => Some(query.query_id),
            _ => None,
        })
        .expect("protected/local DNS action");
    let response_actions = engine.complete_dns(query_id, &query, 4);
    let response = response_actions
        .iter()
        .find_map(|action| match action {
            EngineAction::SendSyntheticResponse { packet } => Some(packet),
            _ => None,
        })
        .expect("TCP DNS response");
    let ClassifiedPacket::Tcp(response) = classify(response).expect("valid response") else {
        panic!()
    };
    assert_eq!(
        usize::from(u16::from_be_bytes([
            response.payload[0],
            response.payload[1]
        ])),
        query.len()
    );
    assert_eq!(&response.payload[2..], query.as_slice());
}

#[test]
fn payload_fin_is_forwarded_before_write_half_close() {
    let mut engine = engine();
    let syn = packet(
        1,
        0,
        TcpFlags {
            syn: true,
            ..TcpFlags::default()
        },
        b"",
    );
    let actions = process(&mut engine, &syn, Some(route(PolicyAction::Tunnel)), 1);
    let flow_id = actions
        .iter()
        .find_map(|action| match action {
            EngineAction::OpenProtectedStream { request, .. } => Some(request.flow_id),
            _ => None,
        })
        .expect("flow");
    let opened = engine.protected_stream_opened(flow_id, 2);
    let syn_ack = opened
        .iter()
        .find_map(|action| match action {
            EngineAction::SendSyntheticResponse { packet } => Some(packet),
            _ => None,
        })
        .expect("SYN-ACK");
    let ClassifiedPacket::Tcp(segment) = classify(syn_ack).expect("valid") else {
        panic!()
    };
    let actions = process(
        &mut engine,
        &packet(
            2,
            segment.sequence.wrapping_add(1),
            TcpFlags {
                fin: true,
                psh: true,
                ..TcpFlags::ack()
            },
            b"last",
        ),
        None,
        3,
    );
    let forward = actions
        .iter()
        .position(|action| matches!(action, EngineAction::ForwardPayload { .. }))
        .expect("forward");
    let close = actions
        .iter()
        .position(|action| {
            matches!(
                action,
                EngineAction::CloseProtectedStream {
                    direction: CloseDirection::Write,
                    ..
                }
            )
        })
        .expect("half close");
    assert!(forward < close);
}

#[test]
fn oversized_packet_writer_fails_without_allocation_or_panic() {
    let payload = vec![0u8; usize::from(u16::MAX)];
    assert!(build_tcp_packet(
        CLIENT,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        1,
        0,
        TcpFlags::ack(),
        1,
        &payload
    )
    .is_empty());
    assert!(build_udp_packet(CLIENT, SERVER, CLIENT_PORT, 53, &payload).is_empty());
}

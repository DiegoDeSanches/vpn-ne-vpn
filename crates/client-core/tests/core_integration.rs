use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use onionroute_client_core::{
    ActiveRoute, ClientCore, ConnectionDispatcher, DispatcherConfig, PacketReader, PacketWriter,
    ShutdownCoordinator, ShutdownPhase, TunnelPacketIo,
};
use onionroute_common_types::mocks::{MemoryPacketTunnel, MockGatewayConnector};
use onionroute_common_types::state::ClientConnectionState;
use onionroute_common_types::types::{
    AnonymityMode, FlowId, GatewayId, GatewayRole, GatewaySession, GatewaySessionState,
    IsolationKey, ProtocolVersion,
};
use onionroute_dns_engine::{SyntheticDnsConfig, SyntheticDnsEngine};
use onionroute_packet_engine::{
    build_tcp_packet, build_udp_packet, classify, BlockReason, ClassifiedPacket, EngineConfig,
    NoopMetrics, PacketProcessor, PlatformMetadata, TcpFlags,
};
use onionroute_policy_engine::MvpPolicyEngine;

const CLIENT: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 0, 0, 2);
const SERVER: std::net::Ipv4Addr = std::net::Ipv4Addr::new(93, 184, 216, 34);

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    struct NoopWake;
    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn session(marker: u8) -> GatewaySession {
    GatewaySession {
        session_id: onionroute_common_types::types::SessionId([marker; 16]),
        gateway_id: GatewayId(format!("gateway-{marker}")),
        role: GatewayRole::Exit,
        protocol_version: ProtocolVersion::new(1, 0),
        state: GatewaySessionState::Active,
        expires_at_unix: i64::MAX,
        max_concurrent_streams: 64,
    }
}

fn route(marker: u8) -> ActiveRoute {
    ActiveRoute {
        isolation_key: IsolationKey([marker; 32]),
        anonymity_profile: AnonymityMode::Standard,
        gateway_id: Some(GatewayId(format!("gateway-{marker}"))),
    }
}

fn core() -> ClientCore {
    let packet = PacketProcessor::new(EngineConfig::default(), Arc::new(NoopMetrics))
        .expect("valid packet config");
    let dns =
        Arc::new(SyntheticDnsEngine::new(SyntheticDnsConfig::default()).expect("valid DNS config"));
    let policy = Arc::new(MvpPolicyEngine::default());
    let gateway = Arc::new(MockGatewayConnector);
    let dispatcher = ConnectionDispatcher::new(DispatcherConfig::default(), gateway, session(1))
        .expect("valid dispatcher config");
    ClientCore::new(packet, dns, policy, dispatcher, route(1))
}

fn syn(source_port: u16, sequence: u32) -> Vec<u8> {
    build_tcp_packet(
        CLIENT,
        SERVER,
        source_port,
        443,
        sequence,
        0,
        TcpFlags {
            syn: true,
            ..TcpFlags::default()
        },
        32_768,
        &[],
    )
}

fn dns_query(name: &str) -> Vec<u8> {
    let mut wire = vec![0xaa, 0x55, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        wire.push(label.len() as u8);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
    wire.extend_from_slice(&1u16.to_be_bytes());
    wire.extend_from_slice(&1u16.to_be_bytes());
    wire
}

fn metadata(now: u64) -> PlatformMetadata {
    PlatformMetadata {
        application: None,
        monotonic_ms: now,
    }
}

#[test]
fn mock_gateway_stream_opens_and_path_loss_fails_closed() {
    let mut core = core();
    let output = block_on(core.handle_packet(
        &syn(49_152, 100),
        metadata(1),
        ClientConnectionState::Connected,
    ));
    assert_eq!(core.active_flows(), 1);
    assert_eq!(output.packets.len(), 1);
    let ClassifiedPacket::Tcp(segment) = classify(&output.packets[0]).expect("valid SYN-ACK")
    else {
        panic!("expected TCP");
    };
    assert!(segment.flags.syn && segment.flags.ack);

    let lost = block_on(core.protected_path_lost(2));
    assert_eq!(core.active_flows(), 0);
    assert!(lost
        .blocked
        .iter()
        .any(|(_, reason)| *reason == BlockReason::ProtectedPathUnavailable));
}

#[test]
fn reconnect_uses_new_mock_session_without_reusing_flows() {
    let mut core = core();
    block_on(core.handle_packet(
        &syn(49_152, 1),
        metadata(1),
        ClientConnectionState::Connected,
    ));
    let closed = block_on(core.reconnect(session(2), route(2), 2)).expect("reconnect");
    assert!(!closed.blocked.is_empty());
    assert_eq!(core.active_flows(), 0);

    let reopened = block_on(core.handle_packet(
        &syn(49_153, 10),
        metadata(3),
        ClientConnectionState::Connected,
    ));
    assert_eq!(core.active_flows(), 1);
    assert_eq!(reopened.packets.len(), 1);
}

#[test]
fn dns_is_intercepted_and_synthesized_inside_core() {
    let mut core = core();
    let packet = build_udp_packet(
        CLIENT,
        "8.8.8.8".parse().expect("resolver fixture"),
        53_000,
        53,
        &dns_query("example.com"),
    );
    let output =
        block_on(core.handle_packet(&packet, metadata(1), ClientConnectionState::Connected));
    assert_eq!(output.packets.len(), 1);
    let ClassifiedPacket::Udp(response) =
        classify(&output.packets[0]).expect("valid DNS response packet")
    else {
        panic!("expected UDP");
    };
    assert_eq!(response.source_port, 53);
    assert_eq!(response.destination_port, 53_000);
    assert_eq!(
        u16::from_be_bytes([response.payload[6], response.payload[7]]),
        1
    );
}

#[test]
fn quic_ipv6_and_reconnecting_state_never_open_streams() {
    let mut core = core();
    let quic = build_udp_packet(CLIENT, SERVER, 50_000, 443, b"quic");
    let output = block_on(core.handle_packet(&quic, metadata(1), ClientConnectionState::Connected));
    assert!(output
        .blocked
        .iter()
        .any(|(_, reason)| *reason == BlockReason::QuicBlocked));

    let mut ipv6 = [0u8; 40];
    ipv6[0] = 0x60;
    let output = block_on(core.handle_packet(&ipv6, metadata(2), ClientConnectionState::Connected));
    assert!(output
        .blocked
        .iter()
        .any(|(_, reason)| *reason == BlockReason::Ipv6Blocked));

    let output = block_on(core.handle_packet(
        &syn(49_154, 1),
        metadata(3),
        ClientConnectionState::Reconnecting,
    ));
    assert!(output
        .blocked
        .iter()
        .any(|(_, reason)| *reason == BlockReason::ProtectedPathUnavailable));
    assert_eq!(core.active_flows(), 0);
}

#[test]
fn shutdown_rejects_later_flows() {
    let mut core = core();
    block_on(core.handle_packet(
        &syn(49_152, 1),
        metadata(1),
        ClientConnectionState::Connected,
    ));
    let shutdown = block_on(core.shutdown(2));
    assert!(!shutdown.diagnostics.is_empty());
    assert_eq!(core.active_flows(), 0);
    let denied = block_on(core.handle_packet(
        &syn(49_153, 1),
        metadata(3),
        ClientConnectionState::Connected,
    ));
    assert!(denied
        .blocked
        .iter()
        .any(|(_, reason)| *reason == BlockReason::Shutdown));
}

#[test]
fn remote_eof_keeps_protected_write_half_open_until_local_fin() {
    let mut core = core();
    let opened = block_on(core.handle_packet(
        &syn(49_152, 100),
        metadata(1),
        ClientConnectionState::Connected,
    ));
    let ClassifiedPacket::Tcp(syn_ack) = classify(&opened.packets[0]).expect("valid SYN-ACK")
    else {
        panic!("expected TCP");
    };
    let server_next = syn_ack.sequence.wrapping_add(1);
    let acknowledged = build_tcp_packet(
        CLIENT,
        SERVER,
        49_152,
        443,
        101,
        server_next,
        TcpFlags::ack(),
        32_768,
        &[],
    );
    block_on(core.handle_packet(&acknowledged, metadata(2), ClientConnectionState::Connected));

    let eof = block_on(core.pump_flow(FlowId(1), 3));
    let fin_packet = eof.packets.first().expect("remote FIN packet");
    let ClassifiedPacket::Tcp(fin) = classify(fin_packet).expect("valid remote FIN") else {
        panic!("expected TCP");
    };
    let after_fin = fin.sequence.wrapping_add(1);
    let tail = build_tcp_packet(
        CLIENT,
        SERVER,
        49_152,
        443,
        101,
        after_fin,
        TcpFlags {
            psh: true,
            ..TcpFlags::ack()
        },
        32_768,
        b"tail",
    );
    let forwarded =
        block_on(core.handle_packet(&tail, metadata(4), ClientConnectionState::Connected));
    assert_eq!(forwarded.packets.len(), 1);
    assert_eq!(core.active_flows(), 1);

    let local_fin = build_tcp_packet(
        CLIENT,
        SERVER,
        49_152,
        443,
        105,
        after_fin,
        TcpFlags::fin_ack(),
        32_768,
        &[],
    );
    let closed =
        block_on(core.handle_packet(&local_fin, metadata(5), ClientConnectionState::Connected));
    assert_eq!(closed.packets.len(), 1);
    assert_eq!(core.active_flows(), 0);
}

#[test]
fn packet_io_and_shutdown_coordinator_remain_bounded() {
    let tunnel = MemoryPacketTunnel::with_incoming([vec![0x45, 1, 2, 3]]);
    let outgoing = tunnel.outgoing_packets();
    let mut io = TunnelPacketIo::new(Box::new(tunnel), 1_500).expect("bounded packet adapter");
    let received = block_on(io.read_packet())
        .expect("packet read")
        .expect("one packet");
    assert_eq!(received, vec![0x45, 1, 2, 3]);
    block_on(io.write_packet(&received)).expect("packet write");
    assert_eq!(
        outgoing.lock().expect("outgoing packet lock").as_slice(),
        &[received]
    );
    assert!(block_on(io.write_packet(&vec![0; 1_501])).is_err());
    block_on(io.close()).expect("packet tunnel close");

    let mut shutdown = ShutdownCoordinator::default();
    assert_eq!(shutdown.phase(), ShutdownPhase::Running);
    shutdown.begin(100);
    assert_eq!(shutdown.phase(), ShutdownPhase::Draining);
    assert!(shutdown.cancelled(50));
    shutdown.complete();
    assert_eq!(shutdown.phase(), ShutdownPhase::Complete);
}

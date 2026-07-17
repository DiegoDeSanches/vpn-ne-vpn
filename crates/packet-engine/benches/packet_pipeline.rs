use std::sync::Arc;
use std::time::Instant;

use onionroute_packet_engine::{
    build_tcp_packet, classify, EngineConfig, NoopMetrics, PacketProcessor, TcpFlags,
};

fn main() {
    let packet = build_tcp_packet(
        "10.0.0.2".parse().expect("fixture address"),
        "93.184.216.34".parse().expect("fixture address"),
        49_152,
        443,
        1,
        0,
        TcpFlags {
            syn: true,
            ..TcpFlags::default()
        },
        32_768,
        &[],
    );
    let _engine = PacketProcessor::new(EngineConfig::default(), Arc::new(NoopMetrics))
        .expect("valid benchmark config");
    let start = Instant::now();
    for _ in 0..1_000_000 {
        std::hint::black_box(classify(std::hint::black_box(&packet))).expect("valid packet");
    }
    eprintln!(
        "packet-classify: 1000000 iterations in {:?}",
        start.elapsed()
    );
}

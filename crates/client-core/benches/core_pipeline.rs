use std::time::Instant;

use onionroute_dns_engine::SyntheticDnsEngine;
use onionroute_packet_engine::{build_tcp_packet, classify, TcpFlags};

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
    let mut dns = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    dns.extend_from_slice(&[7]);
    dns.extend_from_slice(b"example");
    dns.extend_from_slice(&[3]);
    dns.extend_from_slice(b"com");
    dns.extend_from_slice(&[0, 0, 1, 0, 1]);
    let started = Instant::now();
    for _ in 0..500_000 {
        std::hint::black_box(classify(std::hint::black_box(&packet))).expect("valid packet");
        std::hint::black_box(SyntheticDnsEngine::parse_query(std::hint::black_box(&dns)))
            .expect("valid DNS query");
    }
    eprintln!(
        "core-parse: 500000 packet+DNS iterations in {:?}",
        started.elapsed()
    );
}

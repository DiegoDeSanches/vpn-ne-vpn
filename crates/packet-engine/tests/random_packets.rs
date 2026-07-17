use onionroute_packet_engine::classify;

#[test]
fn randomized_packets_never_panic() {
    let mut state = 0x4d59_5df4_d0f3_3173u64;
    for case in 0..20_000usize {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let length = (state as usize ^ case) % 2_048;
        let mut bytes = vec![0u8; length];
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        let result = std::panic::catch_unwind(|| classify(&bytes));
        assert!(result.is_ok(), "parser panicked on randomized case {case}");
    }
}

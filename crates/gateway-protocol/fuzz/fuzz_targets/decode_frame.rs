#![no_main]

use libfuzzer_sys::fuzz_target;
use onionroute_gateway_protocol::framing::FrameDecoder;
use onionroute_gateway_protocol::limits::ABSOLUTE_MAX_FRAME_SIZE;

fuzz_target!(|input: &[u8]| {
    let mut decoder = FrameDecoder::new(ABSOLUTE_MAX_FRAME_SIZE).expect("valid hard limit");
    let mut offset = 0usize;
    while offset < input.len() {
        match decoder.push(&input[offset..]) {
            Ok(progress) => {
                assert!(decoder.buffered_bytes() <= ABSOLUTE_MAX_FRAME_SIZE + 5);
                if progress.consumed == 0 {
                    break;
                }
                offset += progress.consumed;
            }
            Err(_) => break,
        }
    }
});

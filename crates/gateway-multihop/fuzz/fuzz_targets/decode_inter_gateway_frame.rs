#![no_main]

use libfuzzer_sys::fuzz_target;
use onionroute_gateway_multihop::protocol::decode_frame_bytes;

fuzz_target!(|data: &[u8]| {
    let _ = decode_frame_bytes(data, 64 * 1024);
});


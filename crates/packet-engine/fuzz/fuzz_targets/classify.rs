#![no_main]

use libfuzzer_sys::fuzz_target;
use onionroute_packet_engine::classify;

fuzz_target!(|packet: &[u8]| {
    let _ = classify(packet);
});

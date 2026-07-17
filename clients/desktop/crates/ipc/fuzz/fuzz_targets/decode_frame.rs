#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = onionroute_desktop_ipc::decode_frame(data);
});


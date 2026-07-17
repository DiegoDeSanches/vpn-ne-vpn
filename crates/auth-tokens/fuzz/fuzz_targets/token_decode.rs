#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = onionroute_auth_tokens::validate_wire_format(data);
});

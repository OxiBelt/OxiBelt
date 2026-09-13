#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    oxibelt::proxy_protocol::fuzz_parse_v2_payload(data);
});

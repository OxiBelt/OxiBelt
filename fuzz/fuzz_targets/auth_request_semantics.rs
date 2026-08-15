#![no_main]

use libfuzzer_sys::fuzz_target;

const MAX_TEXT_BYTES: usize = 512;
const FALLBACK: &[u8] = b" /%?=;,_-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

fn text(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(MAX_TEXT_BYTES)
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b" /%?=;,_-".contains(byte) {
                char::from(*byte)
            } else {
                char::from(FALLBACK[usize::from(*byte) % FALLBACK.len()])
            }
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    // Split the remaining bytes evenly into bounded fields. This mapping is
    // total, so every corpus seed exercises the authorization assertions.
    let outcome = data.first().copied().unwrap_or_default();
    let fail_open = data.get(1).copied().unwrap_or_default() & 1 == 1;
    let payload = data.get(2..).unwrap_or_default();
    let boundary = |part: usize| payload.len().saturating_mul(part) / 5;
    let authorization = text(&payload[boundary(0)..boundary(1)]);
    let duplicate_authorization = text(&payload[boundary(1)..boundary(2)]);
    let identity = text(&payload[boundary(2)..boundary(3)]);
    let trailer_authorization = text(&payload[boundary(3)..boundary(4)]);
    let route_path = text(&payload[boundary(4)..boundary(5)]);

    oxibelt::fuzzing::exercise_auth_request_semantics(
        &authorization,
        &duplicate_authorization,
        &identity,
        &trailer_authorization,
        outcome,
        fail_open,
        &route_path,
    );
});

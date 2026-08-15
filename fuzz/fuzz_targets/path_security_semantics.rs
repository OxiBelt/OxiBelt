#![no_main]

use libfuzzer_sys::fuzz_target;

const MAX_COMPONENT_BYTES: usize = 512;
const FALLBACK: &[u8] = b"/%.?=&\\abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
const UNICODE_PATH_CONFUSABLES: &[char] = &['∕', '⁄', '／', '．', '․', '＼'];

fn component(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(MAX_COMPONENT_BYTES)
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"/%.?=&\\_-".contains(byte) {
                char::from(*byte)
            } else if *byte >= 0xf0 {
                UNICODE_PATH_CONFUSABLES[usize::from(*byte) % UNICODE_PATH_CONFUSABLES.len()]
            } else {
                char::from(FALLBACK[usize::from(*byte) % FALLBACK.len()])
            }
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    // Use a total projection instead of a fallible length-prefixed decoder so
    // every corpus entry and mutation reaches the security-property facade.
    let prefix = data.first().copied().unwrap_or_default();
    let replacement = data.get(1).copied().unwrap_or_default();
    let absolute_form = data.get(2).copied().unwrap_or_default() & 1 == 1;
    let payload = data.get(3..).unwrap_or_default();
    let split = payload.len() / 2;
    let path = component(&payload[..split]);
    let query = component(&payload[split..]);

    let route_prefix = match prefix % 4 {
        0 => "/",
        1 => "/safe",
        2 => "/app",
        _ => "/api/v1",
    };
    let replacement = match replacement % 4 {
        0 => None,
        1 => Some("/"),
        2 => Some("/edge"),
        _ => Some("/internal/v1"),
    };
    oxibelt::fuzzing::exercise_path_security_semantics(
        &path,
        &query,
        route_prefix,
        replacement,
        absolute_form,
    );
});

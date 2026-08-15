#![no_main]

use libfuzzer_sys::fuzz_target;

const MAX_TEXT_BYTES: usize = 1024;
const MAX_BODY_BYTES: usize = 8192;
const ATTACK: &str = "oxibelt_fuzz_attack";
const FALLBACK: &[u8] = b"/%?=&; _-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

fn text(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(MAX_TEXT_BYTES)
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"/%?=&; _-".contains(byte) {
                char::from(*byte)
            } else {
                char::from(FALLBACK[usize::from(*byte) % FALLBACK.len()])
            }
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    // A total projection keeps malformed inputs bounded while ensuring no
    // seed is silently discarded by a structured-input length prefix.
    let transform = data.first().copied().unwrap_or_default();
    let protocol = data.get(1).copied().unwrap_or_default();
    let body_coding = data.get(2).copied().unwrap_or_default();
    let malicious_seed = data.get(3).copied().unwrap_or_default() & 1 == 1;
    let payload = data.get(4..).unwrap_or_default();
    let first = payload.len() / 3;
    let second = first.saturating_mul(2);
    let mut path = text(&payload[..first]);
    let mut header = text(&payload[first..second]);
    let mut body = payload[second..]
        .iter()
        .copied()
        .take(MAX_BODY_BYTES)
        .collect::<Vec<_>>();

    // This is the only metamorphic assertion class: the facade knows these
    // seeds carry the fixed malicious semantic marker. Arbitrary malformed
    // requests exercise only robustness and deterministic decision handling.
    if malicious_seed {
        match transform % 3 {
            0 => path = format!("/protected/{ATTACK}"),
            1 => body = ATTACK.as_bytes().to_vec(),
            _ => header = ATTACK.to_string(),
        }
    }
    oxibelt::fuzzing::exercise_waf_request_evaluation(
        &path,
        &body,
        &header,
        transform,
        protocol,
        body_coding,
    );
});

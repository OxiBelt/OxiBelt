#![no_main]

use std::borrow::Cow;

use libfuzzer_sys::arbitrary::{Arbitrary, Error, Unstructured};
use libfuzzer_sys::fuzz_target;

const LIMIT_SELECTOR_COUNT: usize = 9;
const MAX_FRAGMENT_SIZES: usize = 32;
const REVIEWED_SEED_PREFIX: &[u8] = b"OBH1:";

#[derive(Debug)]
struct CompioH1ResponseInput<'a> {
    limit_selectors: [u8; LIMIT_SELECTOR_COUNT],
    fragment_sizes: Vec<u8>,
    response: &'a [u8],
}

impl<'a> Arbitrary<'a> for CompioH1ResponseInput<'a> {
    fn arbitrary(raw: &mut Unstructured<'a>) -> Result<Self, Error> {
        let limit_selectors = <[u8; LIMIT_SELECTOR_COUNT]>::arbitrary(raw)?;
        let fragment_count = usize::from(u8::arbitrary(raw)?) % (MAX_FRAGMENT_SIZES + 1);
        let fragment_sizes = raw.bytes(fragment_count)?.to_vec();
        let response = raw.bytes(raw.len())?;
        Ok(Self {
            limit_selectors,
            fragment_sizes,
            response,
        })
    }
}

fn decode_reviewed_seed(response: &[u8]) -> Cow<'_, [u8]> {
    let Some(encoded) = response.strip_prefix(REVIEWED_SEED_PREFIX) else {
        return Cow::Borrowed(response);
    };
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut cursor = 0;
    while cursor < encoded.len() {
        if encoded[cursor] == b'\\' && cursor + 1 < encoded.len() {
            match encoded[cursor + 1] {
                b'r' => decoded.push(b'\r'),
                b'n' => decoded.push(b'\n'),
                b'\\' => decoded.push(b'\\'),
                _ => {
                    decoded.push(encoded[cursor]);
                    decoded.push(encoded[cursor + 1]);
                }
            }
            cursor += 2;
        } else {
            decoded.push(encoded[cursor]);
            cursor += 1;
        }
    }
    Cow::Owned(decoded)
}

fuzz_target!(|input: CompioH1ResponseInput<'_>| {
    let response = decode_reviewed_seed(input.response);
    oxibelt::fuzzing::exercise_compio_h1_response(
        response.as_ref(),
        &input.fragment_sizes,
        input.limit_selectors,
    );
});

//! Bounded RFC 9842 inputs in the existing HTTP body-coding campaign.
use crate::compression_dictionary::{codec, fields};
use sha2::{Digest, Sha256};
use std::{
  sync::Arc,
  time::{Duration, Instant},
};

pub(super) fn exercise(data: &[u8]) {
  let data = &data[..data.len().min(16 * 1024)];
  let mut headers = http::HeaderMap::new();
  if let Ok(value) = http::HeaderValue::from_bytes(data) {
    for name in ["available-dictionary", "dictionary-id", "use-as-dictionary"] {
      headers.insert(name, value.clone());
    }
    let _ = fields::parse_available_dictionary(&headers);
    if let Ok(url) = url::Url::parse("https://example.test/dictionary") {
      let _ = fields::parse_use_as_dictionary(data, &url);
    }
  }
  let dictionary: Arc<[u8]> = Arc::from(&b"bounded dictionary fuzz prefix"[..]);
  let hash = Sha256::digest(&dictionary);
  let coding = if data.first().copied().unwrap_or(0) & 1 == 0 {
    codec::DictionaryCoding::Dcb
  } else {
    codec::DictionaryCoding::Dcz
  };
  let mut encoded = match coding {
    codec::DictionaryCoding::Dcb => b"\xffDCB".to_vec(),
    codec::DictionaryCoding::Dcz => b"^*M\x18 \0\0\0".to_vec(),
  };
  encoded.extend_from_slice(&hash);
  encoded.extend_from_slice(data.get(1..).unwrap_or_default());
  let mut limits = codec::DecodeLimits::new(64 * 1024, 16);
  limits.deadline = Some(Instant::now() + Duration::from_millis(25));
  if let Ok(decoded) = codec::decode_bounded(coding, dictionary, &encoded, &limits) {
    assert!(decoded.len() <= 64 * 1024);
  }
}

#[cfg(test)]
mod tests {
  #[test]
  fn bounded_dictionary_mutations() {
    for seed in 0_u8..=255 {
      let mut input = vec![seed; usize::from(seed) + 1];
      for (index, byte) in input.iter_mut().enumerate() {
        *byte = byte.wrapping_add((index as u8).wrapping_mul(31));
      }
      super::exercise(&input);
    }
  }
}

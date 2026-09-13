//! Opaque PROXY TLS cache identity, separate from locally verified certificates.

#[derive(Clone, Eq, PartialEq)]
pub struct CacheProxyProtocolIdentity(String);

impl CacheProxyProtocolIdentity {
  pub(crate) fn new(source: &str, encoded_header: &[u8]) -> Self {
    let mut value = Vec::with_capacity(source.len() + encoded_header.len() + 32);
    value.extend_from_slice(b"oxibelt-proxy-tls-cache-v1\0");
    value.extend_from_slice(source.as_bytes());
    value.push(0);
    value.extend_from_slice(encoded_header);
    let hash = crate::crypto::sha256(&value);
    let mut digest = String::with_capacity(64);
    for byte in hash {
      use std::fmt::Write as _;
      // Writing to a String is infallible.
      let _ = write!(digest, "{byte:02x}");
    }
    Self(digest)
  }

  pub(super) fn partition(&self, base_key: String) -> String {
    format!(
      "\0oxibelt-cache-proxy-tls-v1\0base:{}:{}identity:{}",
      base_key.len(),
      base_key,
      self.0
    )
  }
}

impl std::fmt::Debug for CacheProxyProtocolIdentity {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("CacheProxyProtocolIdentity { redacted }")
  }
}

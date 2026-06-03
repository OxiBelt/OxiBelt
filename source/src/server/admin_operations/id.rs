//! Admin operation identifier validation.
//! IDs stay constrained so operation lookups cannot become path or log injection surfaces.

use anyhow::bail;
use ring::rand::{SecureRandom, SystemRandom};

const OPERATION_ID_PREFIX: &str = "op_";

pub(super) fn new_operation_id() -> String {
  let mut bytes = [0_u8; 16];
  SystemRandom::new()
    .fill(&mut bytes)
    .expect("system random generator should produce admin operation IDs");
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  format!(
    "op_{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
    bytes[0],
    bytes[1],
    bytes[2],
    bytes[3],
    bytes[4],
    bytes[5],
    bytes[6],
    bytes[7],
    bytes[8],
    bytes[9],
    bytes[10],
    bytes[11],
    bytes[12],
    bytes[13],
    bytes[14],
    bytes[15]
  )
}

pub(in crate::server) fn parse_operation_id(raw: &str) -> anyhow::Result<&str> {
  let Some(uuid) = raw.strip_prefix(OPERATION_ID_PREFIX) else {
    bail!("operation id must start with op_");
  };
  if uuid.len() != 36 {
    bail!("operation id must contain a canonical UUIDv4");
  }
  for (index, byte) in uuid.bytes().enumerate() {
    let hyphen = matches!(index, 8 | 13 | 18 | 23);
    if hyphen {
      if byte != b'-' {
        bail!("operation id must contain a canonical UUIDv4");
      }
      continue;
    }
    if !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase() {
      bail!("operation id must contain a lowercase canonical UUIDv4");
    }
  }
  if uuid.as_bytes()[14] != b'4' {
    bail!("operation id must contain a UUIDv4");
  }
  if !matches!(uuid.as_bytes()[19], b'8' | b'9' | b'a' | b'b') {
    bail!("operation id must contain an RFC 4122 UUID variant");
  }
  Ok(raw)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn generated_operation_ids_are_prefixed_uuid_v4() {
    for _ in 0..16 {
      let id = new_operation_id();
      parse_operation_id(&id).expect("generated ID should parse");
      assert!(id.starts_with("op_"));
      assert_eq!(id.len(), 39);
    }
  }

  #[test]
  fn parser_rejects_non_canonical_ids() {
    assert!(parse_operation_id("550e8400-e29b-41d4-a716-446655440000").is_err());
    assert!(parse_operation_id("op_550E8400-e29b-41d4-a716-446655440000").is_err());
    assert!(parse_operation_id("op_550e8400-e29b-31d4-a716-446655440000").is_err());
    assert!(parse_operation_id("op_550e8400-e29b-41d4-c716-446655440000").is_err());
  }
}

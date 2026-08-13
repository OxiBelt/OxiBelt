use std::collections::BTreeSet;

use anyhow::bail;

pub(crate) fn normalize_fingerprint_pins(raw: &[String]) -> anyhow::Result<BTreeSet<String>> {
  raw
    .iter()
    .map(|fingerprint| normalize_fingerprint_pin(fingerprint))
    .collect()
}

fn normalize_fingerprint_pin(raw: &str) -> anyhow::Result<String> {
  let normalized = raw
    .chars()
    .filter(|character| !matches!(character, ' ' | '\t' | '\n' | '\r' | ':'))
    .flat_map(char::to_lowercase)
    .collect::<String>();
  if !matches!(normalized.len(), 40 | 64)
    || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit())
  {
    bail!("--rulepack-openpgp-fingerprint requires a full 40- or 64-character hex fingerprint");
  }
  Ok(normalized)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn fingerprint_pins_must_be_full_hex() {
    assert!(normalize_fingerprint_pin("AA BB:cc").is_err());
    let fp = "0123456789abcdef0123456789abcdef01234567";
    assert_eq!(
      normalize_fingerprint_pin(fp).expect("fingerprint"),
      fp.to_string()
    );
  }
}

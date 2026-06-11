use anyhow::bail;

use super::RulepackSourceProvenance;

pub(super) fn validate_source_text(source: &str, field: &str, value: &str) -> anyhow::Result<()> {
  validate_non_empty(source, field, value)?;
  if value.len() > 2048 {
    bail!("{source} {field} exceeds 2048 bytes");
  }
  Ok(())
}

pub(super) fn validate_source_sha256(source: &str, field: &str, value: &str) -> anyhow::Result<()> {
  validate_non_empty(source, field, value)?;
  if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
    bail!("{source} {field} must be a 64-character hex SHA-256 digest");
  }
  Ok(())
}

pub(super) fn validate_source_fingerprint(
  source: &str,
  field: &str,
  value: &str,
) -> anyhow::Result<()> {
  validate_non_empty(source, field, value)?;
  if !matches!(value.len(), 40 | 64) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
    bail!("{source} {field} must be a full 40- or 64-character hex OpenPGP fingerprint");
  }
  Ok(())
}

pub(super) fn set_rulepack_provenance(
  value: &mut toml::Value,
  provenance: RulepackSourceProvenance,
) -> anyhow::Result<()> {
  let Some(table) = value
    .get_mut("rulepack")
    .and_then(toml::Value::as_table_mut)
  else {
    bail!("rulepack manifest is missing [rulepack]");
  };
  for key in [
    "source_url",
    "source_sha256",
    "source_openpgp_signature_url",
    "source_openpgp_signer_fingerprint",
  ] {
    table.remove(key);
  }
  table.insert(
    "source_url".to_string(),
    toml::Value::String(provenance.source_url),
  );
  table.insert(
    "source_sha256".to_string(),
    toml::Value::String(provenance.source_sha256),
  );
  if let Some(value) = provenance.source_openpgp_signature_url {
    table.insert(
      "source_openpgp_signature_url".to_string(),
      toml::Value::String(value),
    );
  }
  if let Some(value) = provenance.source_openpgp_signer_fingerprint {
    table.insert(
      "source_openpgp_signer_fingerprint".to_string(),
      toml::Value::String(value),
    );
  }
  Ok(())
}

fn validate_non_empty(source: &str, field: &str, value: &str) -> anyhow::Result<()> {
  if value.trim().is_empty() {
    bail!("{source} {field} must not be empty");
  }
  Ok(())
}

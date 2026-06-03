//! DNS upstream discovery configuration and resolver helpers.
//! DNS results are treated as dynamic candidates, not permanent configuration.

use anyhow::bail;

pub(super) fn canonical_dns_name(name: &str) -> anyhow::Result<String> {
  let trimmed = name.trim_end_matches('.');
  if trimmed.is_empty() {
    bail!("DNS name must not be empty");
  }
  for label in trimmed.split('.') {
    if label.is_empty() || label.len() > 63 {
      bail!("DNS name contains an invalid label");
    }
  }
  Ok(trimmed.to_ascii_lowercase())
}

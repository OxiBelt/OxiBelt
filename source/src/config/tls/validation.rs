use std::collections::HashSet;

use anyhow::bail;

use super::{Tls12CipherSuite, Tls13CipherSuite, TlsConfig, TlsKeyExchangeGroup, TlsVersion};

pub(in crate::config) fn validate_tls_negotiation(tls: &TlsConfig) -> anyhow::Result<()> {
  validate_tls_key_exchange_groups(
    "tls.1_3.key_exchange_groups",
    &tls.tls13.key_exchange_groups,
    TlsVersion::Tls13,
  )?;
  validate_tls13_cipher_suites("tls.1_3.ciphers", &tls.tls13.ciphers)?;
  validate_tls12_cipher_suites("tls.1_2.groups", &tls.tls12.groups)
}

pub(in crate::config) fn validate_tls_key_exchange_groups(
  field_name: &str,
  groups: &[TlsKeyExchangeGroup],
  version: TlsVersion,
) -> anyhow::Result<()> {
  if groups.is_empty() {
    bail!("{field_name} must include at least one group");
  }
  let mut seen = HashSet::new();
  for group in groups {
    if version == TlsVersion::Tls12 && *group == TlsKeyExchangeGroup::X25519MlKem768 {
      bail!("{field_name} cannot include x25519mlkem768 for tls1.2");
    }
    if !seen.insert(*group) {
      bail!("{field_name} contains duplicate {}", group.as_str());
    }
  }
  Ok(())
}

pub(in crate::config) fn validate_tls13_cipher_suites(
  field_name: &str,
  ciphers: &[Tls13CipherSuite],
) -> anyhow::Result<()> {
  if ciphers.is_empty() {
    bail!("{field_name} must include at least one cipher suite");
  }
  let mut seen = HashSet::new();
  for cipher in ciphers {
    if !seen.insert(*cipher) {
      bail!("{field_name} contains duplicate {}", cipher.as_str());
    }
  }
  Ok(())
}

pub(in crate::config) fn validate_tls12_cipher_suites(
  field_name: &str,
  ciphers: &[Tls12CipherSuite],
) -> anyhow::Result<()> {
  if ciphers.is_empty() {
    bail!("{field_name} must include at least one cipher suite");
  }
  let mut seen = HashSet::new();
  for cipher in ciphers {
    if !seen.insert(*cipher) {
      bail!("{field_name} contains duplicate {}", cipher.as_str());
    }
  }
  Ok(())
}

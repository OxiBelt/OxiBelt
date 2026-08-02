//! Upstream TLS authentication-name and trust-store configuration.
//! Exact CA digests bind generated paths to the bytes validated at configuration load.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{
  OutboundTlsRevocationConfig, UpstreamEchConfig, UpstreamEchMode, UpstreamTlsResumptionConfig,
  UpstreamTlsResumptionMode, resolve_existing_local_config_file_path_with_logical,
};

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct UpstreamTlsConfig {
  #[serde(default)]
  pub server_name: Option<String>,
  #[serde(default)]
  pub subject_alt_names: Vec<UpstreamTlsSubjectAltName>,
  #[serde(default)]
  pub trust: UpstreamTlsTrust,
  #[serde(default)]
  pub trusted_ca_certs: Vec<PathBuf>,
  #[serde(default)]
  pub trusted_ca_sha256: Vec<String>,
  #[serde(default)]
  pub ech: UpstreamEchConfig,
  #[serde(default)]
  pub resumption: UpstreamTlsResumptionConfig,
  #[serde(default)]
  pub upstream_revocation: Option<OutboundTlsRevocationConfig>,
}

impl UpstreamTlsConfig {
  pub(in crate::config) fn resolve_relative_paths(
    &mut self,
    base_dir: &Path,
  ) -> anyhow::Result<Vec<PathBuf>> {
    let mut source_paths = Vec::new();
    self.trusted_ca_certs = self
      .trusted_ca_certs
      .iter()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "upstream TLS trusted_ca_certs",
          base_dir,
          path,
        )?;
        source_paths.push(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .collect::<anyhow::Result<_>>()?;
    self.ech.config_list_file = self
      .ech
      .config_list_file
      .take()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "upstreams.tls.ech.config_list_file",
          base_dir,
          &path,
        )?;
        source_paths.push(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .transpose()?;
    Ok(source_paths)
  }

  pub(in crate::config) fn validate(&self, upstream_name: &str) -> anyhow::Result<()> {
    if let Some(server_name) = self.server_name.as_deref() {
      let server_name = server_name.trim();
      if server_name.is_empty() || server_name != self.server_name.as_deref().unwrap_or_default() {
        bail!("upstream {upstream_name} tls.server_name must be a non-empty exact value");
      }
      rustls::pki_types::ServerName::try_from(server_name.to_string()).with_context(|| {
        format!("upstream {upstream_name} tls.server_name is not a valid DNS name or IP address")
      })?;
    }
    validate_subject_alt_names(upstream_name, &self.subject_alt_names)?;
    match self.trust {
      UpstreamTlsTrust::System if !self.trusted_ca_certs.is_empty() => bail!(
        "upstream {upstream_name} tls.trusted_ca_certs must be empty when tls.trust = \"system\""
      ),
      UpstreamTlsTrust::Exclusive if self.trusted_ca_certs.is_empty() => bail!(
        "upstream {upstream_name} tls.trusted_ca_certs must not be empty when tls.trust = \"exclusive\""
      ),
      _ => {}
    }
    if self.trusted_ca_certs.len() != self.trusted_ca_sha256.len() {
      bail!(
        "upstream {upstream_name} tls.trusted_ca_sha256 must contain one digest for each trusted_ca_certs entry"
      );
    }
    for (path, expected) in self.trusted_ca_certs.iter().zip(&self.trusted_ca_sha256) {
      validate_ca_digest(upstream_name, path, expected)?;
    }
    if self.resumption.mode == UpstreamTlsResumptionMode::Enabled
      && self.resumption.session_cache_size == 0
    {
      bail!(
        "upstream {} tls.resumption.session_cache_size must be greater than 0 when resumption is enabled",
        upstream_name
      );
    }
    match self.ech.mode {
      UpstreamEchMode::Disabled | UpstreamEchMode::Grease => {
        if self.ech.config_list_file.is_some() {
          bail!(
            "upstream {} tls.ech.config_list_file is only valid when tls.ech.mode = \"config_list\"",
            upstream_name
          );
        }
      }
      UpstreamEchMode::ConfigList => {
        if self.ech.config_list_file.is_none() {
          bail!(
            "upstream {} tls.ech.config_list_file is required when tls.ech.mode = \"config_list\"",
            upstream_name
          );
        }
      }
    }
    if let Some(revocation) = &self.upstream_revocation {
      revocation.validate(&format!("upstream {upstream_name} tls.upstream_revocation"))?;
    }
    Ok(())
  }
}

/// An explicit certificate authentication identity for an upstream TLS peer.
///
/// When this list is non-empty, `UpstreamTlsConfig::server_name` remains the
/// TLS SNI but is not an authentication identity unless it also appears here.
#[derive(Debug, Clone, Deserialize, Eq, Hash, PartialEq)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum UpstreamTlsSubjectAltName {
  Dns(String),
  Uri(String),
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamTlsTrust {
  #[default]
  Inherit,
  System,
  Exclusive,
}

const MAX_UPSTREAM_TLS_SUBJECT_ALT_NAMES: usize = 5;
const MAX_UPSTREAM_TLS_SUBJECT_ALT_NAME_BYTES: usize = 253;

fn validate_subject_alt_names(
  upstream_name: &str,
  subject_alt_names: &[UpstreamTlsSubjectAltName],
) -> anyhow::Result<()> {
  if subject_alt_names.len() > MAX_UPSTREAM_TLS_SUBJECT_ALT_NAMES {
    bail!(
      "upstream {upstream_name} tls.subject_alt_names supports at most {MAX_UPSTREAM_TLS_SUBJECT_ALT_NAMES} entries"
    );
  }
  let mut unique = HashSet::new();
  for subject_alt_name in subject_alt_names {
    match subject_alt_name {
      UpstreamTlsSubjectAltName::Dns(value) => {
        validate_dns_subject_alt_name(upstream_name, value)?;
        if !unique.insert(("dns", value.as_str())) {
          bail!("upstream {upstream_name} tls.subject_alt_names entries must be unique");
        }
      }
      UpstreamTlsSubjectAltName::Uri(value) => {
        validate_uri_subject_alt_name(upstream_name, value)?;
        if !unique.insert(("uri", value.as_str())) {
          bail!("upstream {upstream_name} tls.subject_alt_names entries must be unique");
        }
      }
    }
  }
  Ok(())
}

fn validate_dns_subject_alt_name(upstream_name: &str, value: &str) -> anyhow::Result<()> {
  if value.is_empty()
    || value.len() > MAX_UPSTREAM_TLS_SUBJECT_ALT_NAME_BYTES
    || !value.is_ascii()
    || value != value.to_ascii_lowercase()
    || value.contains('*')
    || value.parse::<std::net::IpAddr>().is_ok()
  {
    bail!(
      "upstream {upstream_name} tls.subject_alt_names DNS values must be lowercase exact DNS names of at most {MAX_UPSTREAM_TLS_SUBJECT_ALT_NAME_BYTES} bytes without wildcards or IP addresses"
    );
  }
  for label in value.split('.') {
    if label.is_empty()
      || label.len() > 63
      || label.starts_with('-')
      || label.ends_with('-')
      || !label
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
      bail!(
        "upstream {upstream_name} tls.subject_alt_names DNS values must be lowercase exact DNS names of at most {MAX_UPSTREAM_TLS_SUBJECT_ALT_NAME_BYTES} bytes without wildcards or IP addresses"
      );
    }
  }
  Ok(())
}

fn validate_uri_subject_alt_name(upstream_name: &str, value: &str) -> anyhow::Result<()> {
  let absolute_parts = value.split_once(':');
  if value.is_empty()
    || value.len() > MAX_UPSTREAM_TLS_SUBJECT_ALT_NAME_BYTES
    || !value.is_ascii()
    || value.trim() != value
    || value.bytes().any(|byte| byte.is_ascii_control())
    || absolute_parts
      .is_none_or(|(scheme, remainder)| !valid_uri_scheme(scheme) || remainder.is_empty())
    || !value.bytes().all(is_rfc3986_uri_byte)
    || !has_valid_percent_encoding(value)
    || url::Url::parse(value).is_err()
  {
    bail!(
      "upstream {upstream_name} tls.subject_alt_names URI values must be exact absolute URIs of at most {MAX_UPSTREAM_TLS_SUBJECT_ALT_NAME_BYTES} bytes"
    );
  }
  Ok(())
}

fn valid_uri_scheme(value: &str) -> bool {
  let mut bytes = value.bytes();
  bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
    && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

fn is_rfc3986_uri_byte(byte: u8) -> bool {
  byte.is_ascii_alphanumeric()
    || matches!(
      byte,
      b'-'
        | b'.'
        | b'_'
        | b'~'
        | b':'
        | b'/'
        | b'?'
        | b'#'
        | b'['
        | b']'
        | b'@'
        | b'!'
        | b'$'
        | b'&'
        | b'\''
        | b'('
        | b')'
        | b'*'
        | b'+'
        | b','
        | b';'
        | b'='
        | b'%'
    )
}

fn has_valid_percent_encoding(value: &str) -> bool {
  let mut remaining = value.as_bytes();
  while let Some((&byte, rest)) = remaining.split_first() {
    if byte != b'%' {
      remaining = rest;
      continue;
    }
    let Some((&high, rest)) = rest.split_first() else {
      return false;
    };
    let Some((&low, rest)) = rest.split_first() else {
      return false;
    };
    if !high.is_ascii_hexdigit() || !low.is_ascii_hexdigit() {
      return false;
    }
    remaining = rest;
  }
  true
}

fn validate_ca_digest(upstream_name: &str, path: &Path, expected: &str) -> anyhow::Result<()> {
  if expected.len() != 64
    || !expected
      .bytes()
      .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
  {
    bail!("upstream {upstream_name} tls.trusted_ca_sha256 values must be lowercase SHA-256 hex");
  }
  let bytes = std::fs::read(path).with_context(|| {
    format!(
      "failed to read upstream {upstream_name} trusted CA file {} for digest verification",
      path.display()
    )
  })?;
  let actual = hex_lower(&Sha256::digest(bytes));
  if actual != expected {
    bail!(
      "upstream {upstream_name} trusted CA digest mismatch for {}",
      path.display()
    );
  }
  Ok(())
}

pub(super) fn hex_lower(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut output = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    output.push(HEX[(byte >> 4) as usize] as char);
    output.push(HEX[(byte & 0x0f) as usize] as char);
  }
  output
}

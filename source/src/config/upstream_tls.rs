//! Upstream TLS authentication-name and trust-store configuration.
//! Exact CA digests bind generated paths to the bytes validated at configuration load.

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

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamTlsTrust {
  #[default]
  Inherit,
  System,
  Exclusive,
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

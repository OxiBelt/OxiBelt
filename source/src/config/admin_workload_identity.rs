//! Opt-in Admin mTLS workload identity configuration and validation.

use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, bail};
use serde::Deserialize;
use url::Url;

use super::{AdminTransportMode, Config, IpmTrustSource, TlsClientAuthMode};

/// Controls binding a verified Admin mTLS workload identity to IPM authorization.
///
/// The feature is intentionally opt-in: existing bearer and break-glass flows retain
/// their behavior until operators enable this section and provide mTLS trust mappings.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AdminWorkloadIdentityConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub bearer_mode: AdminWorkloadIdentityBearerMode,
  #[serde(default)]
  pub revoked_certificate_fingerprints_sha256: Vec<String>,
}

impl Default for AdminWorkloadIdentityConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      bearer_mode: AdminWorkloadIdentityBearerMode::Required,
      revoked_certificate_fingerprints_sha256: Vec::new(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AdminWorkloadIdentityBearerMode {
  #[default]
  Required,
  Optional,
}

impl Config {
  pub(super) fn validate_admin_workload_identity(&self) -> anyhow::Result<()> {
    let workload_identity = &self.admin.workload_identity;
    if !workload_identity.enabled {
      return Ok(());
    }
    if self.admin.transport != AdminTransportMode::Tls {
      bail!("admin.workload_identity.enabled requires admin.transport = \"tls\"");
    }
    if !self.admin.tls.enabled {
      bail!("admin.workload_identity.enabled requires admin.tls.enabled = true");
    }
    if self.admin.tls.client_auth.mode != TlsClientAuthMode::Require {
      bail!("admin.workload_identity.enabled requires admin.tls.client_auth.mode = \"require\"");
    }
    if !self.ipm.enabled {
      bail!("admin.workload_identity.enabled requires ipm.enabled = true");
    }
    if !self.admin.audit.enabled {
      bail!("admin.workload_identity.enabled requires admin.audit.enabled = true");
    }
    if workload_identity.bearer_mode == AdminWorkloadIdentityBearerMode::Required
      && self.ipm.credentials.is_empty()
    {
      bail!(
        "admin.workload_identity.bearer_mode = \"required\" requires at least one [[ipm.credentials]] entry"
      );
    }

    let mut fingerprints = HashSet::new();
    for fingerprint in &workload_identity.revoked_certificate_fingerprints_sha256 {
      if fingerprint.len() != 64
        || !fingerprint
          .bytes()
          .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
      {
        bail!(
          "admin.workload_identity.revoked_certificate_fingerprints_sha256 entries must be 64 lowercase hexadecimal characters"
        );
      }
      if !fingerprints.insert(fingerprint.as_str()) {
        bail!(
          "duplicate admin.workload_identity.revoked_certificate_fingerprints_sha256 entry {fingerprint}"
        );
      }
    }

    let mut mappings = HashMap::new();
    for trust in self
      .ipm
      .trust
      .iter()
      .filter(|trust| trust.source == IpmTrustSource::Mtls)
    {
      let Some(principal) = trust.principal.as_deref() else {
        bail!(
          "admin.workload_identity.enabled requires each mTLS ipm.trust mapping to target a principal"
        );
      };
      if trust.group.is_some() {
        bail!(
          "admin.workload_identity.enabled does not allow mTLS ipm.trust mappings that target a group"
        );
      }
      match trust.claim.as_str() {
        "spiffe_id" => validate_admin_workload_spiffe_id(&trust.value)?,
        "san_uri" => validate_admin_workload_san_uri(&trust.value)?,
        "san_dns" => validate_admin_workload_san_dns(&trust.value)?,
        _ => bail!(
          "admin.workload_identity.enabled supports mTLS ipm.trust claims spiffe_id, san_uri, or san_dns"
        ),
      }
      match mappings.entry((trust.claim.as_str(), trust.value.as_str())) {
        std::collections::hash_map::Entry::Vacant(entry) => {
          entry.insert(principal);
        }
        std::collections::hash_map::Entry::Occupied(entry) if *entry.get() != principal => {
          bail!(
            "mTLS ipm.trust mapping {} = {} targets multiple principals",
            trust.claim,
            trust.value
          );
        }
        std::collections::hash_map::Entry::Occupied(_) => {}
      }
    }
    if mappings.is_empty() {
      bail!(
        "admin.workload_identity.enabled requires at least one mTLS [[ipm.trust]] mapping to a principal"
      );
    }
    Ok(())
  }
}

fn validate_admin_workload_spiffe_id(value: &str) -> anyhow::Result<()> {
  const PREFIX: &str = "spiffe://";
  if value.len() > 2048 || !value.is_ascii() || !value.starts_with(PREFIX) || value.contains('%') {
    bail!("mTLS ipm.trust spiffe_id must be a canonical SPIFFE ID");
  }
  let parsed = Url::parse(value)
    .map_err(|_| anyhow!("mTLS ipm.trust spiffe_id must be a canonical SPIFFE ID"))?;
  if parsed.scheme() != "spiffe"
    || parsed.username() != ""
    || parsed.password().is_some()
    || parsed.port().is_some()
    || parsed.query().is_some()
    || parsed.fragment().is_some()
  {
    bail!("mTLS ipm.trust spiffe_id must be a canonical SPIFFE ID");
  }
  let Some(trust_domain) = parsed.host_str() else {
    bail!("mTLS ipm.trust spiffe_id must include a trust domain");
  };
  if trust_domain != trust_domain.to_ascii_lowercase()
    || trust_domain.is_empty()
    || !trust_domain.bytes().all(|byte| {
      byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    })
  {
    bail!("mTLS ipm.trust spiffe_id has an invalid trust domain");
  }
  let path = parsed.path();
  if path == "/" || !path.starts_with('/') || path.ends_with('/') {
    bail!("mTLS ipm.trust spiffe_id must include a canonical workload path");
  }
  for segment in path[1..].split('/') {
    if segment.is_empty()
      || matches!(segment, "." | "..")
      || !segment
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
      bail!("mTLS ipm.trust spiffe_id has an invalid workload path");
    }
  }
  Ok(())
}

fn validate_admin_workload_san_uri(value: &str) -> anyhow::Result<()> {
  let parsed =
    Url::parse(value).map_err(|_| anyhow!("mTLS ipm.trust san_uri must be an absolute URI"))?;
  if parsed.scheme() == "spiffe" {
    bail!("mTLS ipm.trust san_uri must not use the spiffe scheme; use spiffe_id instead");
  }
  if parsed.scheme().is_empty() || value.contains('\n') || value.contains('\r') {
    bail!("mTLS ipm.trust san_uri must be an absolute URI");
  }
  Ok(())
}

fn validate_admin_workload_san_dns(value: &str) -> anyhow::Result<()> {
  if value.is_empty()
    || value.len() > 253
    || value != value.to_ascii_lowercase()
    || value.contains('*')
  {
    bail!("mTLS ipm.trust san_dns must be a lowercase exact DNS name without wildcards");
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
      bail!("mTLS ipm.trust san_dns must be a lowercase exact DNS name without wildcards");
    }
  }
  Ok(())
}

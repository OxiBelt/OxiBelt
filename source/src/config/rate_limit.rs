use std::collections::HashSet;

use anyhow::bail;
use serde::Deserialize;

use super::LimitMode;
use crate::waf::PersonProofTokenBinding;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RateLimitConfig {
  pub name: String,
  #[serde(default)]
  pub key: RateLimitKey,
  #[serde(default = "crate::limits::default_rate_limit_ipv4_prefix_bits")]
  pub ipv4_prefix_bits: u8,
  #[serde(default = "crate::limits::default_rate_limit_ipv6_prefix_bits")]
  pub ipv6_prefix_bits: u8,
  #[serde(default)]
  pub identity_parts: Vec<RateLimitIdentityPart>,
  #[serde(default)]
  pub token_bindings: Vec<PersonProofTokenBinding>,
  #[serde(default)]
  pub routes: Vec<String>,
  #[serde(default)]
  pub token_header: Option<String>,
  pub rate: String,
  #[serde(default)]
  pub burst: u32,
  #[serde(default = "crate::limits::default_rate_limit_max_buckets")]
  pub max_buckets: usize,
  #[serde(default)]
  pub mode: LimitMode,
  #[serde(default = "default_rate_limit_status")]
  pub status: u16,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKey {
  Global,
  Route,
  #[default]
  #[serde(alias = "client-ip")]
  ClientIp,
  #[serde(alias = "client-ip-route")]
  ClientIpRoute,
  #[serde(alias = "client-ip-path")]
  ClientIpPath,
  #[serde(alias = "access-token")]
  AccessToken,
  #[serde(alias = "access-token-route")]
  AccessTokenRoute,
  #[serde(alias = "access-token-path")]
  AccessTokenPath,
  #[serde(alias = "client-ip-prefix")]
  ClientIpPrefix,
  #[serde(alias = "client-ip-prefix-route")]
  ClientIpPrefixRoute,
  #[serde(alias = "client-ip-prefix-path")]
  ClientIpPrefixPath,
  #[serde(alias = "tls-fingerprint")]
  TlsFingerprint,
  #[serde(alias = "tls-fingerprint-route")]
  TlsFingerprintRoute,
  #[serde(alias = "token-binding-hash")]
  TokenBindingHash,
  #[serde(alias = "token-binding-hash-route")]
  TokenBindingHashRoute,
  #[serde(alias = "person-proof-clearance")]
  PersonProofClearance,
  #[serde(alias = "person-proof-clearance-route")]
  PersonProofClearanceRoute,
  #[serde(alias = "composite-client")]
  CompositeClient,
  #[serde(alias = "composite-client-route")]
  CompositeClientRoute,
  Asn,
  AsnRoute,
}

impl RateLimitKey {
  pub fn uses_access_token(self) -> bool {
    matches!(
      self,
      Self::AccessToken | Self::AccessTokenRoute | Self::AccessTokenPath
    )
  }

  pub fn uses_ip_prefix(self) -> bool {
    matches!(
      self,
      Self::ClientIpPrefix
        | Self::ClientIpPrefixRoute
        | Self::ClientIpPrefixPath
        | Self::CompositeClient
        | Self::CompositeClientRoute
    )
  }

  pub fn uses_token_bindings(self) -> bool {
    matches!(self, Self::TokenBindingHash | Self::TokenBindingHashRoute)
  }

  pub fn uses_person_proof_clearance(self) -> bool {
    matches!(
      self,
      Self::PersonProofClearance | Self::PersonProofClearanceRoute
    )
  }

  pub fn supports_top_level(self) -> bool {
    !self.uses_token_bindings() && !self.uses_person_proof_clearance()
  }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitIdentityPart {
  ClientIpPrefix,
  UserAgent,
  TlsFingerprint,
  Asn,
}

pub(crate) struct RateLimitIdentityValidation<'a> {
  pub(crate) label: &'a str,
  pub(crate) name: &'a str,
  pub(crate) key: RateLimitKey,
  pub(crate) ipv4_prefix_bits: u8,
  pub(crate) ipv6_prefix_bits: u8,
  pub(crate) identity_parts: &'a [RateLimitIdentityPart],
  pub(crate) token_bindings: &'a [PersonProofTokenBinding],
  pub(crate) waf_context: bool,
}

pub(crate) fn validate_rate_limit_identity_config(
  request: RateLimitIdentityValidation<'_>,
) -> anyhow::Result<()> {
  let RateLimitIdentityValidation {
    label,
    name,
    key,
    ipv4_prefix_bits,
    ipv6_prefix_bits,
    identity_parts,
    token_bindings,
    waf_context,
  } = request;
  if !waf_context && !key.supports_top_level() {
    bail!("{label} {name} key {key:?} is only valid in WAF rate_limit actions");
  }
  if ipv4_prefix_bits > 32 {
    bail!("{label} {name} ipv4_prefix_bits must be between 0 and 32");
  }
  if ipv6_prefix_bits > 128 {
    bail!("{label} {name} ipv6_prefix_bits must be between 0 and 128");
  }
  let default_ipv4_prefix_bits = crate::limits::default_rate_limit_ipv4_prefix_bits();
  let default_ipv6_prefix_bits = crate::limits::default_rate_limit_ipv6_prefix_bits();
  if !key.uses_ip_prefix()
    && (ipv4_prefix_bits != default_ipv4_prefix_bits
      || ipv6_prefix_bits != default_ipv6_prefix_bits)
  {
    bail!("{label} {name} prefix bits require a client_ip_prefix or composite_client key");
  }

  if !matches!(
    key,
    RateLimitKey::CompositeClient | RateLimitKey::CompositeClientRoute
  ) {
    if !identity_parts.is_empty() {
      bail!("{label} {name} identity_parts requires a composite_client key");
    }
  } else {
    if identity_parts.is_empty() {
      bail!("{label} {name} identity_parts must not be empty for composite_client keys");
    }
    let mut seen_parts = HashSet::new();
    for part in identity_parts {
      if !seen_parts.insert(*part) {
        bail!("{label} {name} identity_parts contains duplicate {part:?}");
      }
    }
  }

  if !key.uses_token_bindings() {
    if !token_bindings.is_empty() {
      bail!("{label} {name} token_bindings requires a token_binding_hash key");
    }
  } else {
    if token_bindings.is_empty() {
      bail!("{label} {name} token_bindings must not be empty for token_binding_hash keys");
    }
    let mut seen_bindings = HashSet::new();
    for binding in token_bindings {
      if *binding == PersonProofTokenBinding::TcpMaxHop {
        bail!("{label} {name} token_bindings does not support tcp_max_hop");
      }
      if !seen_bindings.insert(*binding) {
        bail!(
          "{label} {name} token_bindings contains duplicate {}",
          binding.as_str()
        );
      }
    }
  }
  Ok(())
}

fn default_rate_limit_status() -> u16 {
  429
}

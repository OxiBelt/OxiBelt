//! External authorization configuration validation.
//! Request projection settings are constrained before traffic can depend on them.

use std::collections::HashSet;

use anyhow::{Context, bail};
use serde::Deserialize;
use url::Url;

use super::{Config, validate_optional_non_empty, validate_runtime_identifier};

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ExternalAuthConfig {
  pub name: String,
  #[serde(default)]
  pub provider: ExternalAuthProvider,
  pub endpoint: Url,
  #[serde(default = "default_external_auth_timeout_ms")]
  pub timeout_ms: u64,
  #[serde(default)]
  pub fail_policy: ExternalAuthFailPolicy,
  #[serde(default = "default_external_auth_forward_headers")]
  pub forward_headers: Vec<String>,
  #[serde(default = "default_external_auth_identity_headers")]
  pub identity_headers: Vec<String>,
  #[serde(default = "default_external_auth_terminal_response_headers")]
  pub terminal_response_headers: Vec<String>,
  #[serde(default = "default_external_auth_max_response_body_bytes")]
  pub max_response_body_bytes: usize,
  #[serde(default)]
  pub client_id_env: Option<String>,
  #[serde(default)]
  pub client_secret_env: Option<String>,
  #[serde(default)]
  pub required_scopes: Vec<String>,
  #[serde(default)]
  pub required_claims: Vec<ExternalAuthClaimRequirement>,
  #[serde(default = "default_external_auth_claim_headers")]
  pub claim_headers: Vec<ExternalAuthClaimHeader>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExternalAuthProvider {
  #[default]
  Authelia,
  OAuth2,
  Oidc,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExternalAuthFailPolicy {
  Open,
  #[default]
  Closed,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ExternalAuthClaimRequirement {
  pub name: String,
  pub value: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ExternalAuthClaimHeader {
  pub claim: String,
  pub header: String,
}

impl Config {
  pub(super) fn validate_external_auth(&self) -> anyhow::Result<()> {
    let mut names = HashSet::new();
    for auth in &self.external_auth {
      validate_runtime_identifier("external_auth name", &auth.name)?;
      if !names.insert(auth.name.as_str()) {
        bail!("duplicate external_auth name: {}", auth.name);
      }
      if auth.endpoint.scheme() != "http" && auth.endpoint.scheme() != "https" {
        bail!(
          "external_auth {} endpoint must use http:// or https://",
          auth.name
        );
      }
      if auth.timeout_ms == 0 {
        bail!(
          "external_auth {} timeout_ms must be greater than 0",
          auth.name
        );
      }
      if auth.max_response_body_bytes == 0 {
        bail!(
          "external_auth {} max_response_body_bytes must be greater than 0",
          auth.name
        );
      }
      validate_header_names(
        &format!("external_auth {} forward_headers", auth.name),
        &auth.forward_headers,
        true,
      )?;
      validate_header_names(
        &format!("external_auth {} identity_headers", auth.name),
        &auth.identity_headers,
        true,
      )?;
      validate_header_names(
        &format!("external_auth {} terminal_response_headers", auth.name),
        &auth.terminal_response_headers,
        true,
      )?;
      validate_optional_non_empty(
        &format!("external_auth {} client_id_env", auth.name),
        auth.client_id_env.as_deref(),
      )?;
      validate_optional_non_empty(
        &format!("external_auth {} client_secret_env", auth.name),
        auth.client_secret_env.as_deref(),
      )?;
      if auth.client_id_env.is_some() != auth.client_secret_env.is_some() {
        bail!(
          "external_auth {} must set client_id_env and client_secret_env together",
          auth.name
        );
      }
      validate_string_list(
        &format!("external_auth {} required_scopes", auth.name),
        &auth.required_scopes,
      )?;
      let mut claims = HashSet::new();
      for claim in &auth.required_claims {
        validate_optional_non_empty(
          &format!("external_auth {} required_claims.name", auth.name),
          Some(&claim.name),
        )?;
        validate_optional_non_empty(
          &format!("external_auth {} required_claims.value", auth.name),
          Some(&claim.value),
        )?;
        if !claims.insert(claim.name.as_str()) {
          bail!(
            "external_auth {} contains duplicate required_claims name {}",
            auth.name,
            claim.name
          );
        }
      }
      let mut claim_headers = HashSet::new();
      for mapping in &auth.claim_headers {
        validate_optional_non_empty(
          &format!("external_auth {} claim_headers.claim", auth.name),
          Some(&mapping.claim),
        )?;
        validate_header_names(
          &format!("external_auth {} claim_headers.header", auth.name),
          std::slice::from_ref(&mapping.header),
          false,
        )?;
        let normalized = http::HeaderName::from_bytes(mapping.header.as_bytes())
          .expect("validated header name")
          .as_str()
          .to_ascii_lowercase();
        if !claim_headers.insert(normalized.clone()) {
          bail!(
            "external_auth {} maps duplicate claim header {}",
            auth.name,
            normalized
          );
        }
      }
    }
    Ok(())
  }
}

fn validate_header_names(
  field_name: &str,
  headers: &[String],
  allow_empty: bool,
) -> anyhow::Result<()> {
  if headers.is_empty() && !allow_empty {
    bail!("{field_name} must include at least one header");
  }
  let mut names = HashSet::new();
  for header in headers {
    if header.trim() != header || header.is_empty() {
      bail!("{field_name} contains an empty or padded header name");
    }
    let name = http::HeaderName::from_bytes(header.as_bytes())
      .with_context(|| format!("{field_name} contains invalid header name {header}"))?;
    let normalized = name.as_str().to_ascii_lowercase();
    if !names.insert(normalized.clone()) {
      bail!("{field_name} contains duplicate header {normalized}");
    }
  }
  Ok(())
}

fn validate_string_list(field_name: &str, values: &[String]) -> anyhow::Result<()> {
  let mut names = HashSet::new();
  for value in values {
    validate_optional_non_empty(field_name, Some(value))?;
    if !names.insert(value.as_str()) {
      bail!("{field_name} contains duplicate value {value}");
    }
  }
  Ok(())
}

fn default_external_auth_timeout_ms() -> u64 {
  2_000
}

fn default_external_auth_max_response_body_bytes() -> usize {
  65_536
}

fn default_external_auth_forward_headers() -> Vec<String> {
  ["authorization", "cookie"]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_external_auth_identity_headers() -> Vec<String> {
  [
    "remote-user",
    "remote-groups",
    "remote-email",
    "remote-name",
  ]
  .into_iter()
  .map(str::to_string)
  .collect()
}

fn default_external_auth_terminal_response_headers() -> Vec<String> {
  ["location", "www-authenticate", "set-cookie"]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_external_auth_claim_headers() -> Vec<ExternalAuthClaimHeader> {
  [
    ("sub", "remote-user"),
    ("email", "remote-email"),
    ("groups", "remote-groups"),
  ]
  .into_iter()
  .map(|(claim, header)| ExternalAuthClaimHeader {
    claim: claim.to_string(),
    header: header.to_string(),
  })
  .collect()
}

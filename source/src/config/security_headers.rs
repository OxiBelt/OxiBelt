use std::collections::HashSet;

use anyhow::bail;
use serde::Deserialize;

use super::{Config, default_true};

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct SecurityConfig {
  #[serde(default)]
  pub headers: SecurityHeadersConfig,
  #[serde(default)]
  pub header_policies: Vec<SecurityHeaderPolicyConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct SecurityHeaderPolicyConfig {
  pub name: String,
  #[serde(flatten)]
  pub headers: SecurityHeadersConfig,
}

impl SecurityConfig {
  pub(crate) fn effective_headers_for_route(
    &self,
    route_security_headers: Option<&str>,
  ) -> Option<&SecurityHeadersConfig> {
    match route_security_headers {
      Some("off") => None,
      Some("default") | None => Some(&self.headers),
      Some(name) => self
        .header_policies
        .iter()
        .find(|policy| policy.name == name)
        .map(|policy| &policy.headers),
    }
  }

  pub(crate) fn response_headers_enabled_for_route(
    &self,
    route_security_headers: Option<&str>,
  ) -> bool {
    self
      .effective_headers_for_route(route_security_headers)
      .is_some_and(SecurityHeadersConfig::enabled)
  }

  pub(crate) fn any_response_headers_enabled(&self) -> bool {
    self.headers.enabled()
      || self
        .header_policies
        .iter()
        .any(|policy| policy.headers.enabled())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct SecurityHeadersConfig {
  #[serde(default)]
  pub hsts: bool,
  #[serde(default = "default_hsts_max_age_seconds")]
  pub hsts_max_age_seconds: u64,
  #[serde(default = "default_true")]
  pub hsts_include_subdomains: bool,
  #[serde(default)]
  pub hsts_preload: bool,
  #[serde(default)]
  pub x_content_type_options: Option<String>,
  #[serde(default)]
  pub referrer_policy: Option<String>,
  #[serde(default)]
  pub permissions_policy: Option<String>,
}

impl Default for SecurityHeadersConfig {
  fn default() -> Self {
    Self {
      hsts: false,
      hsts_max_age_seconds: default_hsts_max_age_seconds(),
      hsts_include_subdomains: true,
      hsts_preload: false,
      x_content_type_options: None,
      referrer_policy: None,
      permissions_policy: None,
    }
  }
}

impl SecurityHeadersConfig {
  pub(crate) fn enabled(&self) -> bool {
    self.hsts
      || self.x_content_type_options.is_some()
      || self.referrer_policy.is_some()
      || self.permissions_policy.is_some()
  }
}

pub(super) fn validate_security_headers(config: &Config) -> anyhow::Result<()> {
  validate_security_header_values("security.headers", &config.security.headers)?;
  let mut names = HashSet::new();
  for policy in &config.security.header_policies {
    if policy.name.trim().is_empty() {
      bail!("security header policy name must not be empty");
    }
    if matches!(policy.name.as_str(), "default" | "off") {
      bail!("security header policy name {} is reserved", policy.name);
    }
    if !names.insert(policy.name.as_str()) {
      bail!("duplicate security header policy name {}", policy.name);
    }
    validate_security_header_values(
      &format!("security header policy {}", policy.name),
      &policy.headers,
    )?;
  }
  Ok(())
}

fn validate_security_header_values(
  field_prefix: &str,
  headers: &SecurityHeadersConfig,
) -> anyhow::Result<()> {
  for (field, value) in [
    (
      "x_content_type_options",
      headers.x_content_type_options.as_deref(),
    ),
    ("referrer_policy", headers.referrer_policy.as_deref()),
    ("permissions_policy", headers.permissions_policy.as_deref()),
  ] {
    if let Some(value) = value {
      if value.trim().is_empty() {
        bail!("{field_prefix}.{field} must not be empty");
      }
      if http::HeaderValue::from_str(value).is_err() {
        bail!("{field_prefix}.{field} is not a valid header value");
      }
    }
  }
  Ok(())
}

fn default_hsts_max_age_seconds() -> u64 {
  31_536_000
}

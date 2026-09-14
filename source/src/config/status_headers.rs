//! Proxy status-header configuration and route-level resolution.

use anyhow::bail;
use serde::Deserialize;

use super::RouteConfig;

/// Controls handling of status headers received from an upstream response.
#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StatusHeaderUpstream {
  /// Retain received status headers after OxiBelt has applied its own policy.
  #[default]
  Preserve,
  /// Remove received status headers before downstream delivery.
  Strip,
}

/// Global status-header policy.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct StatusHeadersConfig {
  #[serde(default = "super::default_true")]
  pub proxy_status: bool,
  #[serde(default = "super::default_true")]
  pub cache_status: bool,
  #[serde(default)]
  pub upstream: StatusHeaderUpstream,
  #[serde(default)]
  pub identifier: Option<String>,
}

impl Default for StatusHeadersConfig {
  fn default() -> Self {
    Self {
      proxy_status: true,
      cache_status: true,
      upstream: StatusHeaderUpstream::Preserve,
      identifier: None,
    }
  }
}

impl StatusHeadersConfig {
  /// Resolves the global policy with optional sparse route overrides.
  pub fn for_route(&self, route: Option<&RouteConfig>) -> Self {
    let Some(route) = route else {
      return self.clone();
    };
    let overrides = &route.status_headers;
    Self {
      proxy_status: overrides.proxy_status.unwrap_or(self.proxy_status),
      cache_status: overrides.cache_status.unwrap_or(self.cache_status),
      upstream: overrides.upstream.unwrap_or(self.upstream),
      identifier: overrides
        .identifier
        .clone()
        .or_else(|| self.identifier.clone()),
    }
  }

  pub(super) fn validate(&self, field_prefix: &str) -> anyhow::Result<()> {
    if let Some(identifier) = &self.identifier {
      validate_identifier(&format!("{field_prefix}.identifier"), identifier)?;
    }
    Ok(())
  }
}

/// Sparse route-level overrides for [`StatusHeadersConfig`].
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteStatusHeadersConfig {
  #[serde(default)]
  pub proxy_status: Option<bool>,
  #[serde(default)]
  pub cache_status: Option<bool>,
  #[serde(default)]
  pub upstream: Option<StatusHeaderUpstream>,
  #[serde(default)]
  pub identifier: Option<String>,
}

impl RouteStatusHeadersConfig {
  pub(super) fn validate(&self, field_prefix: &str) -> anyhow::Result<()> {
    if let Some(identifier) = &self.identifier {
      validate_identifier(&format!("{field_prefix}.identifier"), identifier)?;
    }
    Ok(())
  }
}

fn validate_identifier(field_name: &str, value: &str) -> anyhow::Result<()> {
  if !(1..=128).contains(&value.len())
    || value.bytes().any(|byte| !(b' '..=b'~').contains(&byte))
    || value.bytes().all(|byte| byte == b' ')
  {
    bail!("{field_name} must be 1 through 128 printable ASCII characters and not whitespace-only");
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn identifier_accepts_printable_ascii_without_requiring_trimmed_text() {
    validate_identifier("identifier", " edge status ")
      .expect("printable non-whitespace identifier should validate");
  }

  #[test]
  fn identifier_rejects_invalid_values() {
    for identifier in ["", " ", "\t", "status\n", "status🦀"] {
      assert!(validate_identifier("identifier", identifier).is_err());
    }
    assert!(validate_identifier("identifier", &"x".repeat(129)).is_err());
  }
}

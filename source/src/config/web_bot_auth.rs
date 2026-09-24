//! Opt-in Web Bot Auth configuration.

use anyhow::{Context, bail};
use serde::Deserialize;
use url::Url;

pub(crate) const WEB_BOT_AUTH_CONFIG_KEYS: &[&str] = &[
  "enabled",
  "max_signature_age_seconds",
  "max_body_digest_bytes",
  "discovery_timeout_ms",
  "stale_if_error_seconds",
  "nonstandard_port_origins",
];

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct WebBotAuthConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_max_signature_age_seconds")]
  pub max_signature_age_seconds: u64,
  #[serde(default = "default_max_body_digest_bytes")]
  pub max_body_digest_bytes: usize,
  #[serde(default = "default_discovery_timeout_ms")]
  pub discovery_timeout_ms: u64,
  #[serde(default = "default_stale_if_error_seconds")]
  pub stale_if_error_seconds: u64,
  #[serde(default)]
  pub nonstandard_port_origins: Vec<String>,
}

impl Default for WebBotAuthConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      max_signature_age_seconds: default_max_signature_age_seconds(),
      max_body_digest_bytes: default_max_body_digest_bytes(),
      discovery_timeout_ms: default_discovery_timeout_ms(),
      stale_if_error_seconds: default_stale_if_error_seconds(),
      nonstandard_port_origins: Vec::new(),
    }
  }
}

impl WebBotAuthConfig {
  pub(crate) fn validate(&self, max_memory_body_bytes: usize) -> anyhow::Result<()> {
    if !(1..=86_400).contains(&self.max_signature_age_seconds) {
      bail!("web_bot_auth.max_signature_age_seconds must be between 1 and 86400");
    }
    if self.max_body_digest_bytes == 0
      || (self.enabled && self.max_body_digest_bytes > max_memory_body_bytes)
    {
      bail!(
        "web_bot_auth.max_body_digest_bytes must be greater than 0 and not exceed proxy.buffering.max_memory_body_bytes"
      );
    }
    if !(1..=3_000).contains(&self.discovery_timeout_ms) {
      bail!("web_bot_auth.discovery_timeout_ms must be between 1 and 3000");
    }
    if self.stale_if_error_seconds > 300 {
      bail!("web_bot_auth.stale_if_error_seconds must not exceed 300");
    }
    let mut seen = std::collections::HashSet::new();
    for origin in &self.nonstandard_port_origins {
      let url = Url::parse(origin).with_context(|| {
        format!("invalid web_bot_auth.nonstandard_port_origins origin {origin}")
      })?;
      if url.scheme() != "https"
        || url.port().is_none_or(|port| port == 443)
        || url.host_str().is_none()
        || url.origin().ascii_serialization() != *origin
      {
        bail!(
          "web_bot_auth.nonstandard_port_origins entries must be canonical HTTPS origins with explicit nonstandard ports: {origin}"
        );
      }
      if !seen.insert(origin) {
        bail!("duplicate web_bot_auth.nonstandard_port_origins entry: {origin}");
      }
    }
    Ok(())
  }
}

const fn default_max_signature_age_seconds() -> u64 {
  86_400
}

const fn default_max_body_digest_bytes() -> usize {
  1_048_576
}

const fn default_discovery_timeout_ms() -> u64 {
  3_000
}

const fn default_stale_if_error_seconds() -> u64 {
  300
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn defaults_are_disabled_and_bounded() {
    let config = WebBotAuthConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.max_signature_age_seconds, 86_400);
    assert_eq!(config.max_body_digest_bytes, 1_048_576);
    assert_eq!(config.discovery_timeout_ms, 3_000);
    assert_eq!(config.stale_if_error_seconds, 300);
    assert!(config.nonstandard_port_origins.is_empty());
    config.validate(1_048_576).unwrap();
  }

  #[test]
  fn rejects_invalid_limits_when_enabled() {
    let mut config = WebBotAuthConfig {
      enabled: true,
      max_body_digest_bytes: 1_048_577,
      ..Default::default()
    };
    assert!(config.validate(1_048_576).is_err());
    config.max_body_digest_bytes = 1;
    config.discovery_timeout_ms = 0;
    assert!(config.validate(1_048_576).is_err());
    config.discovery_timeout_ms = 3_000;
    config.max_signature_age_seconds = 0;
    assert!(config.validate(1_048_576).is_err());
    config.max_signature_age_seconds = 86_400;
    config.stale_if_error_seconds = 301;
    assert!(config.validate(1_048_576).is_err());
  }

  #[test]
  fn requires_canonical_https_origins_with_nonstandard_ports() {
    for invalid in [
      "http://example.com:8443",
      "https://example.com",
      "https://example.com:443",
      "https://example.com:8443/path",
      "https://user@example.com:8443",
      "https://example.com:8443?x=1",
    ] {
      let config = WebBotAuthConfig {
        nonstandard_port_origins: vec![invalid.to_string()],
        ..WebBotAuthConfig::default()
      };
      assert!(config.validate(1_048_576).is_err(), "accepted {invalid}");
    }
    let config = WebBotAuthConfig {
      nonstandard_port_origins: vec!["https://example.com:8443".to_string()],
      ..WebBotAuthConfig::default()
    };
    config.validate(1_048_576).unwrap();
  }

  #[test]
  fn absent_section_preserves_smaller_existing_proxy_buffer_cap() {
    WebBotAuthConfig::default().validate(65_536).unwrap();
  }

  #[test]
  fn config_shape_rejects_unknown_fields() {
    let value: toml::Value =
      toml::from_str("[web_bot_auth]\nenabled = false\nunknown = true\n").unwrap();
    assert!(super::super::shape::validate_merged_toml_shape(&value).is_err());
  }
}

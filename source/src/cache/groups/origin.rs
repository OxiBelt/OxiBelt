//! Canonical RFC 9110 origins used to scope RFC 9875 cache groups.

use std::str::FromStr;

use anyhow::{Result, bail};
use http::Uri;
use http::uri::Authority;
use serde::{Deserialize, Serialize};

/// A canonical HTTP origin, including its effective port.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct CacheGroupOrigin {
  pub scheme: String,
  pub host: String,
  pub port: u16,
}

impl CacheGroupOrigin {
  /// Builds an origin from a validated HTTP scheme and authority.
  pub fn new(scheme: &str, authority: &str) -> Result<Self> {
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
      "http" => 80,
      "https" => 443,
      _ => bail!("cache group origin scheme must be http or https"),
    };
    if authority.is_empty() || authority.trim() != authority || authority.contains('@') {
      bail!("cache group origin authority must not contain credentials");
    }
    let authority = Authority::from_str(authority)?;
    let host = authority
      .host()
      .strip_prefix('[')
      .and_then(|host| host.strip_suffix(']'))
      .unwrap_or_else(|| authority.host());
    if host.is_empty() {
      bail!("cache group origin authority must include a host");
    }
    let port = match explicit_port(authority.as_str()) {
      Some(port) => port
        .parse::<u16>()
        .map_err(|_| anyhow::anyhow!("cache group origin authority has an invalid port"))?,
      None => default_port,
    };
    Ok(Self {
      scheme,
      // RFC 9110 compares host names case-insensitively. Do not apply the
      // routing host normalizer here: a trailing dot remains part of this key.
      host: host.to_ascii_lowercase(),
      port,
    })
  }

  /// Parses an absolute origin URI without a resource path, query, fragment,
  /// or credentials.
  pub fn parse_origin(value: &str) -> Result<Self> {
    if value.contains('#') {
      bail!("cache group origin must not contain a fragment");
    }
    let uri = Uri::from_str(value)?;
    let scheme = uri
      .scheme_str()
      .ok_or_else(|| anyhow::anyhow!("cache group origin must be absolute"))?;
    let authority = uri
      .authority()
      .ok_or_else(|| anyhow::anyhow!("cache group origin must include an authority"))?;
    if uri.path() != "/" && !uri.path().is_empty() {
      bail!("cache group origin must not include a path");
    }
    if uri.query().is_some() {
      bail!("cache group origin must not include a query");
    }
    Self::new(scheme, authority.as_str())
  }

  /// Returns the canonical authority, omitting the default port.
  pub fn authority(&self) -> String {
    let host = if self.host.contains(':') {
      format!("[{}]", self.host)
    } else {
      self.host.clone()
    };
    if self.port == default_port(&self.scheme) {
      host
    } else {
      format!("{host}:{}", self.port)
    }
  }

  /// Returns the canonical serialized origin.
  pub fn as_origin(&self) -> String {
    format!("{}://{}", self.scheme, self.authority())
  }
}

fn default_port(scheme: &str) -> u16 {
  match scheme {
    "http" => 80,
    "https" => 443,
    // Construction only permits the two schemes, but retain a safe value for
    // deserialized values that callers may choose to validate separately.
    _ => 0,
  }
}

fn explicit_port(authority: &str) -> Option<&str> {
  if authority.starts_with('[') {
    return authority
      .find(']')
      .and_then(|end| authority.strip_prefix(&format!("{}:", &authority[..=end])));
  }
  authority
    .rsplit_once(':')
    .filter(|(host, _)| !host.contains(':'))
    .map(|(_, port)| port)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn canonicalizes_scheme_host_and_default_ports_without_routing_normalization() {
    let origin = CacheGroupOrigin::new("HTTPS", "EXAMPLE.Test.:443").unwrap();
    assert_eq!(origin.scheme, "https");
    assert_eq!(origin.host, "example.test.");
    assert_eq!(origin.port, 443);
    assert_eq!(origin.authority(), "example.test.");
    assert_eq!(origin.as_origin(), "https://example.test.");

    let explicit = CacheGroupOrigin::new("http", "example.test:8080").unwrap();
    assert_eq!(explicit.authority(), "example.test:8080");
  }

  #[test]
  fn formats_ipv6_and_parses_only_absolute_origins() {
    let origin = CacheGroupOrigin::parse_origin("https://[2001:DB8::1]:8443/").unwrap();
    assert_eq!(origin.host, "2001:db8::1");
    assert_eq!(origin.authority(), "[2001:db8::1]:8443");
    assert_eq!(origin.as_origin(), "https://[2001:db8::1]:8443");

    for invalid in [
      "example.test",
      "https://example.test/path",
      "https://example.test/?query",
      "https://user@example.test/",
      "ftp://example.test/",
      "https://example.test/#fragment",
    ] {
      assert!(
        CacheGroupOrigin::parse_origin(invalid).is_err(),
        "{invalid}"
      );
    }
  }

  #[test]
  fn rejects_credentials_and_malformed_ports() {
    assert!(CacheGroupOrigin::new("https", "user@example.test").is_err());
    assert!(CacheGroupOrigin::new("https", "example.test:65536").is_err());
    assert!(CacheGroupOrigin::new("https", "example.test:").is_err());
  }
}

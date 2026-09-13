//! Route configuration for forwarding verified downstream client certificates.

use anyhow::{Context, bail};
use http::HeaderName;
use serde::Deserialize;

use super::RouteConfig;

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct ClientCertificateForwardingConfig {
  pub header: String,
  #[serde(default)]
  pub format: ClientCertificateForwardingFormat,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ClientCertificateForwardingFormat {
  #[default]
  UrlEncodedPem,
  Rfc9440,
}

impl ClientCertificateForwardingFormat {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::UrlEncodedPem => "url_encoded_pem",
      Self::Rfc9440 => "rfc9440",
    }
  }
}

pub(super) fn validate_client_certificate_forwarding(
  route: &RouteConfig,
  max_header_name_bytes: usize,
) -> anyhow::Result<Option<HeaderName>> {
  let Some(forwarding) = &route.client_certificate_forwarding else {
    return Ok(None);
  };
  let field_name = "client_certificate_forwarding.header";
  if forwarding.header.trim() != forwarding.header || forwarding.header.is_empty() {
    bail!(
      "route {} {field_name} must not be empty or padded",
      route.name
    );
  }
  let name = super::normalize_route_action_header_name(&forwarding.header).with_context(|| {
    format!(
      "route {} {field_name} contains invalid header name {}",
      route.name, forwarding.header
    )
  })?;
  if name.len() > max_header_name_bytes {
    bail!(
      "route {} {field_name} exceeds limits.max_header_name_bytes",
      route.name
    );
  }
  if oxibelt_control_protocol::is_reserved_client_certificate_forwarding_header(&name) {
    bail!(
      "route {} {field_name} cannot use reserved header {name}",
      route.name
    );
  }
  if name == "client-cert-chain" {
    bail!(
      "route {} {field_name} cannot use client-cert-chain",
      route.name
    );
  }
  if name == "client-cert" && forwarding.format != ClientCertificateForwardingFormat::Rfc9440 {
    bail!(
      "route {} {field_name} client-cert requires format rfc9440",
      route.name
    );
  }
  HeaderName::from_bytes(name.as_bytes())
    .with_context(|| {
      format!(
        "route {} {field_name} contains invalid normalized header name {name}",
        route.name
      )
    })
    .map(Some)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn route(header: &str, format: Option<&str>) -> RouteConfig {
    let format = format
      .map(|format| format!(", format = \"{format}\""))
      .unwrap_or_default();
    toml::from_str(&format!(
      "name = \"forward-client-cert\"\nclient_certificate_forwarding = {{ header = \"{header}\"{format} }}"
    ))
    .expect("route configuration should deserialize")
  }

  #[test]
  fn allows_private_header_with_default_url_encoded_pem() {
    let route = route("X-Verified-Client-Certificate", None);
    let header = validate_client_certificate_forwarding(&route, 128)
      .expect("private forwarding header should validate")
      .expect("forwarding is configured");

    assert_eq!(
      header,
      HeaderName::from_static("x-verified-client-certificate")
    );
    assert_eq!(
      route.client_certificate_forwarding.unwrap().format,
      ClientCertificateForwardingFormat::UrlEncodedPem
    );
  }

  #[test]
  fn protects_rfc9440_names_and_header_budget() {
    let client_cert = route("client-cert", None);
    assert!(
      validate_client_certificate_forwarding(&client_cert, 128)
        .expect_err("client-cert requires its RFC 9440 representation")
        .to_string()
        .contains("requires format rfc9440")
    );

    let client_cert = route("client-cert", Some("rfc9440"));
    validate_client_certificate_forwarding(&client_cert, 128)
      .expect("RFC 9440 client-cert should validate");

    for header in [
      "client-cert-chain",
      "forwarded",
      "authorization",
      "accept-encoding",
      "early-data",
      "traceparent",
      "tracestate",
      "priority",
    ] {
      let route = route(header, Some("rfc9440"));
      assert!(validate_client_certificate_forwarding(&route, 128).is_err());
    }

    let route = route("x-long", None);
    assert!(validate_client_certificate_forwarding(&route, 5).is_err());
  }
}

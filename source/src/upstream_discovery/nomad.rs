//! Nomad upstream discovery provider.
//! Service records are validated before pool membership changes.

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use http::Request;
use serde::Deserialize;

use crate::config::{
  UpstreamPoolDiscoveryConfig, UpstreamPoolServerConfig, UpstreamPoolServerSource,
  UpstreamPoolServerState,
};
use crate::control_http::{ControlHttpClient, empty_body, uri_from_url};
use crate::upstream_control;

const NOMAD_MAX_BODY_BYTES: usize = 1_048_576;

pub(super) struct NomadDiscoveryResult {
  pub servers: Vec<UpstreamPoolServerConfig>,
  pub delay: Duration,
  pub index: Option<String>,
}

pub(super) async fn discover_nomad_servers(
  client: &ControlHttpClient,
  discovery: &UpstreamPoolDiscoveryConfig,
  blocking_index: Option<&str>,
) -> anyhow::Result<NomadDiscoveryResult> {
  let service = discovery
    .service
    .as_deref()
    .ok_or_else(|| anyhow!("Nomad discovery requires service"))?;
  let url = build_nomad_service_url(discovery, service, blocking_index)?;
  let mut builder = Request::builder()
    .method(http::Method::GET)
    .uri(uri_from_url(&url)?)
    .header(http::header::ACCEPT, "application/json");
  add_nomad_token_header(&mut builder, discovery.token_env.as_deref())?;
  let timeout = if discovery.watch {
    Duration::from_secs(discovery.watch_timeout_seconds)
      .saturating_add(Duration::from_millis(discovery.refresh_interval_ms))
  } else {
    Duration::from_millis(discovery.refresh_interval_ms)
  };
  let response = client
    .request(builder.body(empty_body())?, timeout, NOMAD_MAX_BODY_BYTES)
    .await?;
  if !response.status.is_success() {
    bail!("Nomad discovery returned HTTP status {}", response.status);
  }
  let index = response
    .headers
    .get("x-nomad-index")
    .and_then(|value| value.to_str().ok())
    .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
    .map(str::to_string);
  let entries: Vec<NomadServiceEntry> =
    serde_json::from_slice(&response.body).context("failed to parse Nomad service JSON")?;
  let mut servers = entries
    .into_iter()
    .map(|entry| nomad_service_entry_to_server(discovery, service, entry))
    .collect::<anyhow::Result<Vec<_>>>()?;
  sort_discovered_servers(&mut servers);
  Ok(NomadDiscoveryResult {
    servers,
    delay: Duration::from_millis(discovery.refresh_interval_ms),
    index,
  })
}

fn build_nomad_service_url(
  discovery: &UpstreamPoolDiscoveryConfig,
  service: &str,
  blocking_index: Option<&str>,
) -> anyhow::Result<url::Url> {
  let mut url = discovery
    .endpoint
    .clone()
    .ok_or_else(|| anyhow!("Nomad discovery requires endpoint"))?;
  url
    .path_segments_mut()
    .map_err(|_| anyhow!("Nomad discovery endpoint cannot be a base URL"))?
    .clear()
    .extend(["v1", "service", service]);
  {
    let mut query = url.query_pairs_mut();
    if let Some(namespace) = discovery.namespace.as_deref() {
      query.append_pair("namespace", namespace);
    }
    if let Some(filter) = discovery.filter.as_deref() {
      query.append_pair("filter", filter);
    }
    if discovery.watch {
      query.append_pair("wait", &format!("{}s", discovery.watch_timeout_seconds));
      if let Some(index) = blocking_index.filter(|index| !index.is_empty()) {
        query.append_pair("index", index);
      }
    }
  }
  Ok(url)
}

#[derive(Debug, Deserialize)]
struct NomadServiceEntry {
  #[serde(rename = "Address")]
  address: String,
  #[serde(rename = "ID")]
  id: String,
  #[serde(rename = "Namespace")]
  namespace: Option<String>,
  #[serde(rename = "Port")]
  port: u16,
  #[serde(rename = "ServiceName")]
  service_name: String,
}

fn nomad_service_entry_to_server(
  discovery: &UpstreamPoolDiscoveryConfig,
  expected_service: &str,
  entry: NomadServiceEntry,
) -> anyhow::Result<UpstreamPoolServerConfig> {
  if entry.id.trim().is_empty() {
    bail!("Nomad discovery service entry ID must not be empty");
  }
  if entry.service_name != expected_service {
    bail!("Nomad discovery returned an entry for an unexpected service");
  }
  if entry.port == 0 {
    bail!("Nomad discovery service entry port must be greater than 0");
  }
  let host = validated_nomad_host(&entry.address)?;
  let origin = format!("{}://{}:{}/", discovery.scheme.as_str(), host, entry.port)
    .parse()
    .context("failed to build discovered Nomad upstream origin")?;
  let namespace = entry
    .namespace
    .as_deref()
    .or(discovery.namespace.as_deref())
    .unwrap_or("default");
  Ok(UpstreamPoolServerConfig {
    id: Some(upstream_control::stable_generated_server_id(&[
      "nomad",
      namespace,
      expected_service,
      &entry.id,
      &entry.address,
      &entry.port.to_string(),
    ])),
    origin,
    weight: 1,
    max_conns: 0,
    backup: false,
    state: UpstreamPoolServerState::Ready,
    tls: Default::default(),
    source: UpstreamPoolServerSource::Nomad,
    discovery_instance_id: None,
    discovered_weight: None,
  })
}

fn validated_nomad_host(host: &str) -> anyhow::Result<String> {
  let host = host.trim();
  if host.is_empty() {
    bail!("Nomad discovery service entry address must not be empty");
  }
  if let Ok(ip) = host.parse::<IpAddr>() {
    return Ok(match ip {
      IpAddr::V4(ip) => ip.to_string(),
      IpAddr::V6(ip) => format!("[{ip}]"),
    });
  }
  if host
    .bytes()
    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
  {
    return Ok(host.to_string());
  }
  bail!("Nomad discovery service entry address contains unsupported characters")
}

fn add_nomad_token_header(
  builder: &mut http::request::Builder,
  token_env: Option<&str>,
) -> anyhow::Result<()> {
  let Some(token_env) = token_env else {
    return Ok(());
  };
  let token = std::env::var(token_env)
    .with_context(|| format!("failed to read discovery token_env {token_env}"))?;
  if token.trim().is_empty() {
    bail!("discovery token_env {token_env} resolved to an empty value");
  }
  let headers = builder
    .headers_mut()
    .ok_or_else(|| anyhow!("failed to build discovery request headers"))?;
  headers.insert(
    http::HeaderName::from_static("x-nomad-token"),
    http::HeaderValue::from_str(token.trim())
      .context("Nomad discovery token is not a valid header value")?,
  );
  Ok(())
}

fn sort_discovered_servers(servers: &mut Vec<UpstreamPoolServerConfig>) {
  servers.sort_by(|left, right| {
    left
      .id
      .as_deref()
      .unwrap_or_default()
      .cmp(right.id.as_deref().unwrap_or_default())
  });
  servers.dedup_by(|left, right| left.id == right.id);
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::DiscoveryUpstreamScheme;

  fn discovery() -> UpstreamPoolDiscoveryConfig {
    UpstreamPoolDiscoveryConfig {
      provider: crate::config::UpstreamDiscoveryProvider::Nomad,
      id: None,
      weight_multiplier: 1,
      name: None,
      endpoint: Some("http://nomad.service:4646".parse().unwrap()),
      namespace: Some("default".to_string()),
      service: Some("app".to_string()),
      port_name: None,
      key_prefix: None,
      token_env: None,
      token_file: None,
      filter: None,
      datacenter: None,
      file: None,
      record_type: crate::config::DnsDiscoveryRecordType::AAndAaaa,
      scheme: DiscoveryUpstreamScheme::Http,
      port: None,
      kubernetes_resource: crate::config::KubernetesDiscoveryResource::Endpoints,
      watch: false,
      watch_timeout_seconds: 300,
      update_debounce_ms: 250,
      refresh_interval_ms: 30_000,
      min_ttl_ms: 1_000,
      tls: Default::default(),
    }
  }

  #[test]
  fn converts_valid_nomad_service_entry_to_server() {
    let server = nomad_service_entry_to_server(
      &discovery(),
      "app",
      NomadServiceEntry {
        address: "2001:db8::1".to_string(),
        id: "alloc-service".to_string(),
        namespace: Some("default".to_string()),
        port: 8080,
        service_name: "app".to_string(),
      },
    )
    .expect("valid Nomad service should convert");

    assert_eq!(server.source, UpstreamPoolServerSource::Nomad);
    assert_eq!(server.origin.as_str(), "http://[2001:db8::1]:8080/");
    assert!(
      server
        .id
        .unwrap()
        .contains("nomad-default-app-alloc-service")
    );
  }

  #[test]
  fn builds_nomad_query_with_namespace_filter_and_blocking_index() {
    let mut discovery = discovery();
    discovery.filter = Some(r#"Tags contains "blue""#.to_string());
    discovery.watch = true;
    discovery.watch_timeout_seconds = 45;

    let url = build_nomad_service_url(&discovery, "app", Some("12345")).unwrap();

    assert_eq!(
      url.as_str(),
      "http://nomad.service:4646/v1/service/app?namespace=default&filter=Tags+contains+%22blue%22&wait=45s&index=12345"
    );
  }

  #[test]
  fn rejects_invalid_nomad_service_entry_address() {
    let error = nomad_service_entry_to_server(
      &discovery(),
      "app",
      NomadServiceEntry {
        address: "bad/host".to_string(),
        id: "alloc-service".to_string(),
        namespace: None,
        port: 8080,
        service_name: "app".to_string(),
      },
    )
    .expect_err("invalid host should be rejected");

    assert!(error.to_string().contains("unsupported characters"));
  }

  #[test]
  fn rejects_empty_nomad_service_id_and_zero_port() {
    let error = nomad_service_entry_to_server(
      &discovery(),
      "app",
      NomadServiceEntry {
        address: "127.0.0.1".to_string(),
        id: " ".to_string(),
        namespace: None,
        port: 8080,
        service_name: "app".to_string(),
      },
    )
    .expect_err("empty IDs should be rejected");
    assert!(error.to_string().contains("ID must not be empty"));

    let error = nomad_service_entry_to_server(
      &discovery(),
      "app",
      NomadServiceEntry {
        address: "127.0.0.1".to_string(),
        id: "alloc-service".to_string(),
        namespace: None,
        port: 0,
        service_name: "app".to_string(),
      },
    )
    .expect_err("zero ports should be rejected");
    assert!(error.to_string().contains("port must be greater than 0"));
  }
}

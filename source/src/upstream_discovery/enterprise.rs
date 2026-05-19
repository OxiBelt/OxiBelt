use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use base64::Engine;
use bytes::Bytes;
use http::Request;
use serde::Deserialize;
use serde_json::json;

use crate::config::{
  DiscoveryUpstreamScheme, UpstreamPoolDiscoveryConfig, UpstreamPoolServerConfig,
  UpstreamPoolServerSource, UpstreamPoolServerState,
};
use crate::control_http::{ControlHttpClient, empty_body, full_body, uri_from_url};
use crate::upstream_control;

pub(super) async fn discover_kubernetes_servers(
  client: &ControlHttpClient,
  discovery: &UpstreamPoolDiscoveryConfig,
) -> anyhow::Result<(Vec<UpstreamPoolServerConfig>, Duration)> {
  let namespace = discovery
    .namespace
    .as_deref()
    .ok_or_else(|| anyhow!("Kubernetes discovery requires namespace"))?;
  let service = discovery
    .service
    .as_deref()
    .ok_or_else(|| anyhow!("Kubernetes discovery requires service"))?;
  let mut url = discovery
    .endpoint
    .clone()
    .ok_or_else(|| anyhow!("Kubernetes discovery requires endpoint"))?;
  url
    .path_segments_mut()
    .map_err(|_| anyhow!("Kubernetes discovery endpoint cannot be a base URL"))?
    .clear()
    .extend(["api", "v1", "namespaces", namespace, "endpoints", service]);
  url.set_query(None);
  let mut builder = Request::builder()
    .method(http::Method::GET)
    .uri(uri_from_url(&url)?)
    .header(http::header::ACCEPT, "application/json");
  add_bearer_env_header(
    &mut builder,
    discovery.token_env.as_deref(),
    http::header::AUTHORIZATION,
  )?;
  let response = client
    .request(
      builder.body(empty_body())?,
      Duration::from_millis(discovery.refresh_interval_ms),
      1_048_576,
    )
    .await?;
  if !response.status.is_success() {
    bail!(
      "Kubernetes discovery returned HTTP status {}",
      response.status
    );
  }
  let endpoints: KubernetesEndpoints =
    serde_json::from_slice(&response.body).context("failed to parse Kubernetes endpoints JSON")?;
  let mut servers = Vec::new();
  for subset in endpoints.subsets {
    let port = match (&discovery.port_name, discovery.port) {
      (Some(name), None) => subset
        .ports
        .iter()
        .find(|port| port.name.as_deref() == Some(name.as_str()))
        .map(|port| port.port),
      (None, Some(port)) => Some(port),
      _ => None,
    };
    let Some(port) = port else {
      continue;
    };
    for address in subset.addresses {
      servers.push(discovered_ip_server(
        UpstreamPoolServerSource::Kubernetes,
        discovery.scheme,
        "kubernetes",
        &[namespace, service, &address.ip, &port.to_string()],
        &address.ip,
        port,
      )?);
    }
  }
  sort_discovered_servers(&mut servers);
  Ok((
    servers,
    Duration::from_millis(discovery.refresh_interval_ms),
  ))
}

pub(super) async fn discover_consul_servers(
  client: &ControlHttpClient,
  discovery: &UpstreamPoolDiscoveryConfig,
) -> anyhow::Result<(Vec<UpstreamPoolServerConfig>, Duration)> {
  let service = discovery
    .service
    .as_deref()
    .ok_or_else(|| anyhow!("Consul discovery requires service"))?;
  let mut url = discovery
    .endpoint
    .clone()
    .ok_or_else(|| anyhow!("Consul discovery requires endpoint"))?;
  url
    .path_segments_mut()
    .map_err(|_| anyhow!("Consul discovery endpoint cannot be a base URL"))?
    .clear()
    .extend(["v1", "health", "service", service]);
  {
    let mut query = url.query_pairs_mut();
    query.append_pair("passing", "true");
    if let Some(namespace) = discovery.namespace.as_deref() {
      query.append_pair("ns", namespace);
    }
    if let Some(datacenter) = discovery.datacenter.as_deref() {
      query.append_pair("dc", datacenter);
    }
    if let Some(filter) = discovery.filter.as_deref() {
      query.append_pair("filter", filter);
    }
  }
  let mut builder = Request::builder()
    .method(http::Method::GET)
    .uri(uri_from_url(&url)?)
    .header(http::header::ACCEPT, "application/json");
  add_bearer_env_header(
    &mut builder,
    discovery.token_env.as_deref(),
    http::HeaderName::from_static("x-consul-token"),
  )?;
  let response = client
    .request(
      builder.body(empty_body())?,
      Duration::from_millis(discovery.refresh_interval_ms),
      1_048_576,
    )
    .await?;
  if !response.status.is_success() {
    bail!("Consul discovery returned HTTP status {}", response.status);
  }
  let entries: Vec<ConsulServiceEntry> =
    serde_json::from_slice(&response.body).context("failed to parse Consul service JSON")?;
  let mut servers = Vec::new();
  for entry in entries {
    let host = if entry.service.address.is_empty() {
      entry.node.address
    } else {
      entry.service.address
    };
    servers.push(discovered_host_server(
      UpstreamPoolServerSource::Consul,
      discovery.scheme,
      "consul",
      &[
        service,
        &entry.service.id,
        &host,
        &entry.service.port.to_string(),
      ],
      &host,
      entry.service.port,
    )?);
  }
  sort_discovered_servers(&mut servers);
  Ok((
    servers,
    Duration::from_millis(discovery.refresh_interval_ms),
  ))
}

pub(super) async fn discover_etcd_servers(
  client: &ControlHttpClient,
  discovery: &UpstreamPoolDiscoveryConfig,
) -> anyhow::Result<(Vec<UpstreamPoolServerConfig>, Duration)> {
  let key_prefix = discovery
    .key_prefix
    .as_deref()
    .ok_or_else(|| anyhow!("etcd discovery requires key_prefix"))?;
  let mut url = discovery
    .endpoint
    .clone()
    .ok_or_else(|| anyhow!("etcd discovery requires endpoint"))?;
  url
    .path_segments_mut()
    .map_err(|_| anyhow!("etcd discovery endpoint cannot be a base URL"))?
    .clear()
    .extend(["v3", "kv", "range"]);
  let key = base64::engine::general_purpose::STANDARD.encode(key_prefix.as_bytes());
  let range_end =
    base64::engine::general_purpose::STANDARD.encode(prefix_range_end(key_prefix.as_bytes()));
  let body = Bytes::from(json!({ "key": key, "range_end": range_end }).to_string());
  let mut builder = Request::builder()
    .method(http::Method::POST)
    .uri(uri_from_url(&url)?)
    .header(http::header::ACCEPT, "application/json")
    .header(http::header::CONTENT_TYPE, "application/json");
  add_bearer_env_header(
    &mut builder,
    discovery.token_env.as_deref(),
    http::header::AUTHORIZATION,
  )?;
  let response = client
    .request(
      builder.body(full_body(body))?,
      Duration::from_millis(discovery.refresh_interval_ms),
      1_048_576,
    )
    .await?;
  if !response.status.is_success() {
    bail!("etcd discovery returned HTTP status {}", response.status);
  }
  let document: EtcdRangeResponse =
    serde_json::from_slice(&response.body).context("failed to parse etcd range JSON")?;
  let mut servers = Vec::new();
  for kv in document.kvs {
    let value = base64::engine::general_purpose::STANDARD
      .decode(kv.value.as_bytes())
      .context("failed to decode etcd discovery value")?;
    servers.push(parse_etcd_server(discovery, &value)?);
  }
  sort_discovered_servers(&mut servers);
  Ok((
    servers,
    Duration::from_millis(discovery.refresh_interval_ms),
  ))
}

#[derive(Debug, Deserialize)]
struct KubernetesEndpoints {
  #[serde(default)]
  subsets: Vec<KubernetesEndpointSubset>,
}

#[derive(Debug, Deserialize)]
struct KubernetesEndpointSubset {
  #[serde(default)]
  addresses: Vec<KubernetesEndpointAddress>,
  #[serde(default)]
  ports: Vec<KubernetesEndpointPort>,
}

#[derive(Debug, Deserialize)]
struct KubernetesEndpointAddress {
  ip: String,
}

#[derive(Debug, Deserialize)]
struct KubernetesEndpointPort {
  #[serde(default)]
  name: Option<String>,
  port: u16,
}

#[derive(Debug, Deserialize)]
struct ConsulServiceEntry {
  #[serde(rename = "Node")]
  node: ConsulNode,
  #[serde(rename = "Service")]
  service: ConsulService,
}

#[derive(Debug, Deserialize)]
struct ConsulNode {
  #[serde(rename = "Address")]
  address: String,
}

#[derive(Debug, Deserialize)]
struct ConsulService {
  #[serde(rename = "ID")]
  id: String,
  #[serde(rename = "Address")]
  address: String,
  #[serde(rename = "Port")]
  port: u16,
}

#[derive(Debug, Deserialize)]
struct EtcdRangeResponse {
  #[serde(default)]
  kvs: Vec<EtcdKeyValue>,
}

#[derive(Debug, Deserialize)]
struct EtcdKeyValue {
  value: String,
}

#[derive(Debug, Deserialize)]
struct EtcdDiscoveryServer {
  #[serde(default)]
  id: Option<String>,
  #[serde(default)]
  origin: Option<url::Url>,
  #[serde(default = "super::default_discovered_weight")]
  weight: u32,
  #[serde(default)]
  max_conns: usize,
  #[serde(default)]
  backup: bool,
  #[serde(default)]
  state: UpstreamPoolServerState,
}

fn parse_etcd_server(
  discovery: &UpstreamPoolDiscoveryConfig,
  value: &[u8],
) -> anyhow::Result<UpstreamPoolServerConfig> {
  if let Ok(raw) = std::str::from_utf8(value)
    && let Ok(url) = raw.parse::<url::Url>()
  {
    return Ok(UpstreamPoolServerConfig {
      id: Some(upstream_control::stable_generated_server_id(&[
        "etcd",
        discovery.key_prefix.as_deref().unwrap_or_default(),
        url.as_str(),
      ])),
      origin: url,
      weight: 1,
      max_conns: 0,
      backup: false,
      state: UpstreamPoolServerState::Ready,
      source: UpstreamPoolServerSource::Etcd,
    });
  }
  let server: EtcdDiscoveryServer =
    serde_json::from_slice(value).context("failed to parse etcd discovery server")?;
  if server.weight == 0 {
    bail!("etcd discovery server weight must be greater than 0");
  }
  let origin = server
    .origin
    .ok_or_else(|| anyhow!("etcd discovery server requires origin"))?;
  let id = server.id.unwrap_or_else(|| {
    upstream_control::stable_generated_server_id(&[
      "etcd",
      discovery.key_prefix.as_deref().unwrap_or_default(),
      origin.as_str(),
    ])
  });
  Ok(UpstreamPoolServerConfig {
    id: Some(id),
    origin,
    weight: server.weight,
    max_conns: server.max_conns,
    backup: server.backup,
    state: server.state,
    source: UpstreamPoolServerSource::Etcd,
  })
}

fn discovered_ip_server(
  source: UpstreamPoolServerSource,
  scheme: DiscoveryUpstreamScheme,
  provider: &str,
  id_parts: &[&str],
  host: &str,
  port: u16,
) -> anyhow::Result<UpstreamPoolServerConfig> {
  let parsed = host.parse::<IpAddr>().context("discovered IP is invalid")?;
  let host = match parsed {
    IpAddr::V4(ip) => ip.to_string(),
    IpAddr::V6(ip) => format!("[{ip}]"),
  };
  discovered_host_server(source, scheme, provider, id_parts, &host, port)
}

fn discovered_host_server(
  source: UpstreamPoolServerSource,
  scheme: DiscoveryUpstreamScheme,
  provider: &str,
  id_parts: &[&str],
  host: &str,
  port: u16,
) -> anyhow::Result<UpstreamPoolServerConfig> {
  let host_for_url = match host.parse::<IpAddr>() {
    Ok(IpAddr::V4(ip)) => ip.to_string(),
    Ok(IpAddr::V6(ip)) => format!("[{ip}]"),
    Err(_) => host.to_string(),
  };
  let origin = format!("{}://{}:{}/", scheme.as_str(), host_for_url, port)
    .parse()
    .context("failed to build discovered upstream origin")?;
  let mut parts = Vec::with_capacity(id_parts.len() + 1);
  parts.push(provider);
  parts.extend_from_slice(id_parts);
  Ok(UpstreamPoolServerConfig {
    id: Some(upstream_control::stable_generated_server_id(&parts)),
    origin,
    weight: 1,
    max_conns: 0,
    backup: false,
    state: UpstreamPoolServerState::Ready,
    source,
  })
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

fn prefix_range_end(prefix: &[u8]) -> Vec<u8> {
  let mut end = prefix.to_vec();
  for index in (0..end.len()).rev() {
    if end[index] != 0xff {
      end[index] += 1;
      end.truncate(index + 1);
      return end;
    }
  }
  vec![0]
}

fn add_bearer_env_header(
  builder: &mut http::request::Builder,
  token_env: Option<&str>,
  header_name: http::HeaderName,
) -> anyhow::Result<()> {
  let Some(token_env) = token_env else {
    return Ok(());
  };
  let token = std::env::var(token_env)
    .with_context(|| format!("failed to read discovery token_env {token_env}"))?;
  if token.trim().is_empty() {
    bail!("discovery token_env {token_env} resolved to an empty value");
  }
  if header_name == http::header::AUTHORIZATION {
    builder.headers_mut().expect("headers available").insert(
      header_name,
      http::HeaderValue::from_str(&format!("Bearer {}", token.trim()))
        .context("discovery bearer token is not a valid header value")?,
    );
  } else {
    builder.headers_mut().expect("headers available").insert(
      header_name,
      http::HeaderValue::from_str(token.trim())
        .context("discovery token is not a valid header value")?,
    );
  }
  Ok(())
}

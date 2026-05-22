use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use http::Request;
use serde::Deserialize;

use crate::config::{
  DiscoveryUpstreamScheme, KubernetesDiscoveryResource, UpstreamPoolDiscoveryConfig,
  UpstreamPoolServerConfig, UpstreamPoolServerSource, UpstreamPoolServerState,
};
use crate::control_http::{ControlHttpClient, empty_body, uri_from_url};
use crate::upstream_control;

const KUBERNETES_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

mod watch;
pub(super) use watch::run_kubernetes_endpoint_slice_watch;

#[cfg(test)]
mod tests;

pub(super) async fn discover_kubernetes_servers(
  client: &ControlHttpClient,
  discovery: &UpstreamPoolDiscoveryConfig,
) -> anyhow::Result<(Vec<UpstreamPoolServerConfig>, Duration)> {
  match discovery.kubernetes_resource {
    KubernetesDiscoveryResource::Endpoints => discover_endpoints_servers(client, discovery).await,
    KubernetesDiscoveryResource::EndpointSlice => {
      discover_endpoint_slice_servers(client, discovery).await
    }
  }
}

async fn discover_endpoints_servers(
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
      KUBERNETES_MAX_BODY_BYTES,
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

async fn discover_endpoint_slice_servers(
  client: &ControlHttpClient,
  discovery: &UpstreamPoolDiscoveryConfig,
) -> anyhow::Result<(Vec<UpstreamPoolServerConfig>, Duration)> {
  let list = list_endpoint_slices(client, discovery).await?;
  let cache = EndpointSliceCache::from_list(discovery, list)?;
  Ok((
    cache.servers(discovery)?,
    Duration::from_millis(discovery.refresh_interval_ms),
  ))
}

async fn list_endpoint_slices(
  client: &ControlHttpClient,
  discovery: &UpstreamPoolDiscoveryConfig,
) -> anyhow::Result<KubernetesEndpointSliceList> {
  let namespace = discovery
    .namespace
    .as_deref()
    .ok_or_else(|| anyhow!("Kubernetes discovery requires namespace"))?;
  let service = discovery
    .service
    .as_deref()
    .ok_or_else(|| anyhow!("Kubernetes discovery requires service"))?;
  let mut url = endpoint_slice_url(discovery, namespace)?;
  {
    let mut query = url.query_pairs_mut();
    query.append_pair(
      "labelSelector",
      &format!("kubernetes.io/service-name={service}"),
    );
  }
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
      KUBERNETES_MAX_BODY_BYTES,
    )
    .await?;
  if !response.status.is_success() {
    bail!(
      "Kubernetes EndpointSlice discovery returned HTTP status {}",
      response.status
    );
  }
  serde_json::from_slice(&response.body).context("failed to parse Kubernetes EndpointSlice list")
}

fn endpoint_slice_url(
  discovery: &UpstreamPoolDiscoveryConfig,
  namespace: &str,
) -> anyhow::Result<url::Url> {
  let mut url = discovery
    .endpoint
    .clone()
    .ok_or_else(|| anyhow!("Kubernetes discovery requires endpoint"))?;
  url
    .path_segments_mut()
    .map_err(|_| anyhow!("Kubernetes discovery endpoint cannot be a base URL"))?
    .clear()
    .extend([
      "apis",
      "discovery.k8s.io",
      "v1",
      "namespaces",
      namespace,
      "endpointslices",
    ]);
  url.set_query(None);
  Ok(url)
}

#[derive(Default)]
struct EndpointSliceCache {
  slices: HashMap<String, KubernetesEndpointSlice>,
}

impl EndpointSliceCache {
  fn from_list(
    discovery: &UpstreamPoolDiscoveryConfig,
    list: KubernetesEndpointSliceList,
  ) -> anyhow::Result<Self> {
    let mut cache = Self::default();
    for slice in list.items {
      if slice.metadata.name.is_empty() {
        bail!("Kubernetes EndpointSlice is missing metadata.name");
      }
      if endpoint_slice_matches_service(&slice, discovery) {
        cache.slices.insert(slice.metadata.name.clone(), slice);
      }
    }
    Ok(cache)
  }

  fn servers(
    &self,
    discovery: &UpstreamPoolDiscoveryConfig,
  ) -> anyhow::Result<Vec<UpstreamPoolServerConfig>> {
    let namespace = discovery
      .namespace
      .as_deref()
      .ok_or_else(|| anyhow!("Kubernetes discovery requires namespace"))?;
    let service = discovery
      .service
      .as_deref()
      .ok_or_else(|| anyhow!("Kubernetes discovery requires service"))?;
    let mut servers = Vec::new();
    for slice in self.slices.values() {
      servers.extend(endpoint_slice_servers(
        namespace, service, discovery, slice,
      )?);
    }
    sort_discovered_servers(&mut servers);
    Ok(servers)
  }
}

fn endpoint_slice_servers(
  namespace: &str,
  service: &str,
  discovery: &UpstreamPoolDiscoveryConfig,
  slice: &KubernetesEndpointSlice,
) -> anyhow::Result<Vec<UpstreamPoolServerConfig>> {
  if matches!(slice.address_type.as_deref(), Some("FQDN")) {
    return Ok(Vec::new());
  }
  let Some(port) = selected_endpoint_slice_port(slice, discovery) else {
    return Ok(Vec::new());
  };
  let mut servers = Vec::new();
  for endpoint in &slice.endpoints {
    if !endpoint_is_ready(endpoint) {
      continue;
    }
    for address in &endpoint.addresses {
      servers.push(discovered_ip_server(
        UpstreamPoolServerSource::Kubernetes,
        discovery.scheme,
        "kubernetes",
        &[namespace, service, address, &port.to_string()],
        address,
        port,
      )?);
    }
  }
  Ok(servers)
}

fn selected_endpoint_slice_port(
  slice: &KubernetesEndpointSlice,
  discovery: &UpstreamPoolDiscoveryConfig,
) -> Option<u16> {
  match (&discovery.port_name, discovery.port) {
    (Some(name), None) => slice
      .ports
      .iter()
      .find(|port| port.name.as_deref() == Some(name.as_str()) && port.is_tcp())
      .and_then(|port| port.port),
    (None, Some(configured_port)) => {
      if slice.ports.is_empty()
        || slice
          .ports
          .iter()
          .any(|port| port.port == Some(configured_port) && port.is_tcp())
      {
        Some(configured_port)
      } else {
        None
      }
    }
    _ => None,
  }
}

fn endpoint_is_ready(endpoint: &KubernetesEndpointSliceEndpoint) -> bool {
  endpoint.conditions.ready == Some(true) && endpoint.conditions.terminating != Some(true)
}

fn endpoint_slice_matches_service(
  slice: &KubernetesEndpointSlice,
  discovery: &UpstreamPoolDiscoveryConfig,
) -> bool {
  let Some(service) = discovery.service.as_deref() else {
    return false;
  };
  slice
    .metadata
    .labels
    .get("kubernetes.io/service-name")
    .is_some_and(|value| value == service)
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
struct KubernetesEndpointSliceList {
  #[serde(default)]
  metadata: KubernetesListMeta,
  #[serde(default)]
  items: Vec<KubernetesEndpointSlice>,
}

#[derive(Debug, Default, Deserialize)]
struct KubernetesListMeta {
  #[serde(default, rename = "resourceVersion")]
  resource_version: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct KubernetesEndpointSlice {
  metadata: KubernetesObjectMeta,
  #[serde(default, rename = "addressType")]
  address_type: Option<String>,
  #[serde(default)]
  ports: Vec<KubernetesEndpointSlicePort>,
  #[serde(default)]
  endpoints: Vec<KubernetesEndpointSliceEndpoint>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct KubernetesObjectMeta {
  #[serde(default)]
  name: String,
  #[serde(default, rename = "resourceVersion")]
  resource_version: Option<String>,
  #[serde(default)]
  labels: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
struct KubernetesEndpointSlicePort {
  #[serde(default)]
  name: Option<String>,
  #[serde(default)]
  port: Option<u16>,
  #[serde(default)]
  protocol: Option<String>,
}

impl KubernetesEndpointSlicePort {
  fn is_tcp(&self) -> bool {
    self
      .protocol
      .as_deref()
      .is_none_or(|protocol| protocol.eq_ignore_ascii_case("TCP"))
  }
}

#[derive(Clone, Debug, Deserialize)]
struct KubernetesEndpointSliceEndpoint {
  #[serde(default)]
  addresses: Vec<String>,
  #[serde(default)]
  conditions: KubernetesEndpointSliceConditions,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct KubernetesEndpointSliceConditions {
  #[serde(default)]
  ready: Option<bool>,
  #[serde(default)]
  terminating: Option<bool>,
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
  let origin = format!("{}://{}:{}/", scheme.as_str(), host, port)
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
  let headers = builder
    .headers_mut()
    .ok_or_else(|| anyhow!("failed to build discovery request headers"))?;
  headers.insert(
    header_name,
    http::HeaderValue::from_str(&format!("Bearer {}", token.trim()))
      .context("discovery bearer token is not a valid header value")?,
  );
  Ok(())
}

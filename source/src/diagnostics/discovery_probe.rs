//! Upstream-discovery probe orchestration.
//! Probes observe configured discovery sources without mutating runtime membership.

use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use http::Request;

use crate::config::{Config, KubernetesDiscoveryResource, UpstreamDiscoveryProvider};
use crate::control_http::{ControlHttpClient, empty_body, uri_from_url};

use super::{DiagnosticReport, DiagnosticSeverity, DoctorOptions};

pub(super) async fn probe_discovery(
  config: &Config,
  options: &DoctorOptions,
  report: &mut DiagnosticReport,
) {
  let metrics = crate::metrics::Metrics::new();
  let revocation = match crate::tls::OutboundRevocationRuntime::new(config, metrics).await {
    Ok(runtime) => runtime,
    Err(error) => {
      report.push(
        DiagnosticSeverity::Error,
        "probe.discovery_revocation_failed",
        "probe",
        "upstream_pools.discovery",
        format!("failed to build discovery revocation runtime: {error:#}"),
        "Fix proxy.upstream_revocation before running discovery probes.",
      );
      return;
    }
  };
  let client = match ControlHttpClient::new_with_crypto_and_revocation(
    &config.proxy.trusted_ca_certs,
    &config.crypto,
    &revocation,
    revocation.default_policy(),
  ) {
    Ok(client) => client,
    Err(error) => {
      report.push(
        DiagnosticSeverity::Error,
        "probe.discovery_client_failed",
        "probe",
        "upstream_pools.discovery",
        format!("failed to build discovery HTTP client: {error:#}"),
        "Fix proxy.trusted_ca_certs or discovery TLS settings before running discovery probes.",
      );
      return;
    }
  };
  for pool in &config.upstream_pools {
    for (index, discovery) in pool.discovery.iter().enumerate() {
      let target = format!("{}.discovery{index}.{:?}", pool.name, discovery.provider);
      if discovery.token_env.is_some() && !options.allow_secret_env_probes {
        report.probe(
          "upstream",
          &target,
          "skipped",
          "discovery probe requires token_env and is disabled for candidate diagnostics",
        );
        continue;
      }
      match crate::upstream_discovery::discover_servers(&client, discovery).await {
        Ok((servers, _)) => report.probe(
          "upstream",
          &target,
          "ok",
          format!(
            "{:?} discovery succeeded with {} server(s)",
            discovery.provider,
            servers.len()
          ),
        ),
        Err(error) => push_discovery_error(report, &target, error),
      }
      if discovery.provider == UpstreamDiscoveryProvider::Kubernetes
        && discovery.kubernetes_resource == KubernetesDiscoveryResource::EndpointSlice
        && discovery.watch
      {
        match probe_kubernetes_endpoint_slice_watch(&client, discovery).await {
          Ok(()) => report.probe(
            "upstream",
            format!("{target}.watch"),
            "ok",
            "Kubernetes EndpointSlice watch opened successfully",
          ),
          Err(error) => push_discovery_error(report, &format!("{target}.watch"), error),
        }
      }
    }
  }
}

async fn probe_kubernetes_endpoint_slice_watch(
  client: &ControlHttpClient,
  discovery: &crate::config::UpstreamPoolDiscoveryConfig,
) -> anyhow::Result<()> {
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
    .extend([
      "apis",
      "discovery.k8s.io",
      "v1",
      "namespaces",
      namespace,
      "endpointslices",
    ]);
  {
    let mut query = url.query_pairs_mut();
    query.append_pair(
      "labelSelector",
      &format!("kubernetes.io/service-name={service}"),
    );
    query.append_pair("watch", "true");
    query.append_pair("allowWatchBookmarks", "true");
    query.append_pair("timeoutSeconds", "1");
  }
  let mut builder = Request::builder()
    .method(http::Method::GET)
    .uri(uri_from_url(&url)?)
    .header(http::header::ACCEPT, "application/json");
  add_bearer_env_header(&mut builder, discovery.token_env.as_deref())?;
  let response = client
    .request_stream(
      builder.body(empty_body())?,
      Duration::from_millis(discovery.refresh_interval_ms.min(1_000)),
    )
    .await?;
  if response.status == http::StatusCode::GONE {
    return Ok(());
  }
  if !response.status.is_success() {
    bail!(
      "Kubernetes EndpointSlice watch returned HTTP status {}",
      response.status
    );
  }
  Ok(())
}

fn add_bearer_env_header(
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
  builder
    .headers_mut()
    .ok_or_else(|| anyhow::anyhow!("discovery request builder rejected headers"))?
    .insert(
      http::header::AUTHORIZATION,
      http::HeaderValue::from_str(&format!("Bearer {}", token.trim()))
        .context("discovery bearer token is not a valid header value")?,
    );
  Ok(())
}

fn push_discovery_error(report: &mut DiagnosticReport, target: &str, error: anyhow::Error) {
  let message = error.to_string();
  report.probe("upstream", target, "error", &message);
  report.push(
    DiagnosticSeverity::Error,
    "probe.upstream_discovery_failed",
    "probe",
    target,
    format!("upstream discovery probe failed: {message}"),
    "Fix discovery endpoint, credentials, permissions, network policy, or disable upstream external probes for offline validation.",
  );
}

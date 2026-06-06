//! Upstream probe execution.
//! Probes reuse runtime clients where possible while keeping failures diagnostic-only.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use bytes::Bytes;
use futures_util::future::poll_fn;
use http::Request;
use tokio::net::TcpStream;

use crate::config::{Config, HealthCheckProtocol, HttpVersion, UpstreamConfig, UpstreamPoolConfig};
use crate::control_http::{ControlHttpClient, empty_body, uri_from_url};

use super::{DiagnosticReport, DiagnosticSeverity};

pub(super) async fn probe_upstreams(config: &Config, report: &mut DiagnosticReport) {
  let metrics = crate::metrics::Metrics::new();
  let revocation = match crate::tls::OutboundRevocationRuntime::new(config, metrics).await {
    Ok(runtime) => runtime,
    Err(error) => {
      report.push(
        DiagnosticSeverity::Error,
        "probe.upstream_revocation_failed",
        "probe",
        "upstream",
        format!("failed to build upstream revocation runtime: {error:#}"),
        "Fix proxy.upstream_revocation before running upstream probes.",
      );
      return;
    }
  };
  let http_client = match ControlHttpClient::new_with_revocation(
    &config.proxy.trusted_ca_certs,
    &revocation,
    revocation.default_policy(),
  ) {
    Ok(client) => client,
    Err(error) => {
      report.push(
        DiagnosticSeverity::Error,
        "probe.upstream_client_failed",
        "probe",
        "upstream",
        format!("failed to build upstream probe HTTP client: {error:#}"),
        "Fix proxy.trusted_ca_certs before running upstream probes.",
      );
      return;
    }
  };

  for upstream in &config.upstreams {
    probe_direct_upstream(config, &http_client, &revocation, upstream, report).await;
  }
  for pool in &config.upstream_pools {
    probe_pool(config, &http_client, &revocation, pool, report).await;
  }
}

async fn probe_direct_upstream(
  config: &Config,
  client: &ControlHttpClient,
  revocation: &crate::tls::OutboundRevocationRuntime,
  upstream: &UpstreamConfig,
  report: &mut DiagnosticReport,
) {
  if upstream.max_http_version == HttpVersion::H3 {
    match probe_h3_get(config, revocation, upstream, upstream.connect_timeout_ms).await {
      Ok(status) if status.is_success() => report.probe(
        "upstream",
        &upstream.name,
        "ok",
        format!("HTTP/3 GET /healthz returned {status}"),
      ),
      Ok(status) => push_probe_error(
        report,
        &upstream.name,
        anyhow!("HTTP/3 GET /healthz returned unexpected status {status}"),
      ),
      Err(error) => push_probe_error(report, &upstream.name, error),
    }
    return;
  }

  let mut url = upstream.origin.clone();
  url.set_path("/healthz");
  url.set_query(None);
  url.set_fragment(None);
  let upstream_client;
  let client = if upstream.origin.scheme() == "https" {
    match ControlHttpClient::new_with_revocation(
      &config.proxy.trusted_ca_certs,
      revocation,
      revocation.policy_for_upstream(upstream),
    ) {
      Ok(client) => {
        upstream_client = client;
        &upstream_client
      }
      Err(error) => {
        push_probe_error(
          report,
          &upstream.name,
          error.context("failed to build upstream-specific probe client"),
        );
        return;
      }
    }
  } else {
    client
  };
  match probe_http_get(
    client,
    &url,
    Duration::from_millis(upstream.connect_timeout_ms),
  )
  .await
  {
    Ok(status) if status.is_success() => report.probe(
      "upstream",
      &upstream.name,
      "ok",
      format!("GET /healthz returned {status}"),
    ),
    Ok(status) => push_probe_error(
      report,
      &upstream.name,
      anyhow!("GET /healthz returned unexpected status {status}"),
    ),
    Err(error) => push_probe_error(report, &upstream.name, error),
  }
}

async fn probe_pool(
  config: &Config,
  client: &ControlHttpClient,
  revocation: &crate::tls::OutboundRevocationRuntime,
  pool: &UpstreamPoolConfig,
  report: &mut DiagnosticReport,
) {
  for (index, server) in pool.servers.iter().enumerate() {
    let target = server
      .id
      .as_deref()
      .map(|id| format!("{}.{}", pool.name, id))
      .unwrap_or_else(|| format!("{}.server{index}", pool.name));
    if pool.health_check.enabled {
      if pool.health_check.protocol == HealthCheckProtocol::Grpc {
        report.probe(
          "upstream",
          &target,
          "skipped",
          "gRPC health probes are performed by runtime health checks and are not duplicated by doctor",
        );
        continue;
      }
      let mut url = server.origin.clone();
      url.set_path(&pool.health_check.path);
      url.set_query(None);
      url.set_fragment(None);
      match probe_http_get(
        client,
        &url,
        Duration::from_millis(pool.health_check.timeout_ms),
      )
      .await
      {
        Ok(status)
          if pool
            .health_check
            .expected_status
            .iter()
            .any(|expected| *expected == status.as_u16()) =>
        {
          report.probe(
            "upstream",
            &target,
            "ok",
            format!(
              "health_check GET {} returned {status}",
              pool.health_check.path
            ),
          );
        }
        Ok(status) => push_probe_error(
          report,
          &target,
          anyhow!(
            "health_check GET {} returned unexpected status {status}",
            pool.health_check.path
          ),
        ),
        Err(error) => push_probe_error(report, &target, error),
      }
    } else if let Err(error) =
      probe_connect(config, revocation, &server.origin, Duration::from_secs(3)).await
    {
      push_probe_error(report, &target, error);
    } else {
      report.probe(
        "upstream",
        &target,
        "ok",
        "upstream TCP/TLS connect succeeded",
      );
    }
  }
}

async fn probe_http_get(
  client: &ControlHttpClient,
  url: &url::Url,
  timeout: Duration,
) -> anyhow::Result<http::StatusCode> {
  let request = Request::builder()
    .method(http::Method::GET)
    .uri(uri_from_url(url)?)
    .body(empty_body())?;
  Ok(client.request(request, timeout, 64 * 1024).await?.status)
}

async fn probe_connect(
  config: &Config,
  revocation: &crate::tls::OutboundRevocationRuntime,
  url: &url::Url,
  timeout: Duration,
) -> anyhow::Result<()> {
  let remote = resolve_url_addr(url).await?;
  let stream = tokio::time::timeout(timeout, TcpStream::connect(remote))
    .await
    .context("upstream connect timed out")??;
  if url.scheme() == "https" {
    let tls_config = crate::tls::build_upstream_client_config_with_resumption_and_revocation(
      &config.proxy.trusted_ca_certs,
      &crate::config::UpstreamEchConfig::default(),
      &crate::config::UpstreamTlsResumptionConfig::default(),
      None,
      "diagnostics-probe",
      Some((revocation, revocation.default_policy())),
    )?;
    let host = url
      .host_str()
      .ok_or_else(|| anyhow!("upstream origin has no host: {url}"))?
      .to_string();
    let server_name = rustls::pki_types::ServerName::try_from(host)
      .map_err(|error| anyhow!("invalid upstream TLS server name: {error}"))?;
    tokio::time::timeout(
      timeout,
      tokio_rustls::TlsConnector::from(Arc::new(tls_config)).connect(server_name, stream),
    )
    .await
    .context("upstream TLS handshake timed out")?
    .context("upstream TLS handshake failed")?;
  }
  Ok(())
}

async fn probe_h3_get(
  config: &Config,
  revocation: &crate::tls::OutboundRevocationRuntime,
  upstream: &UpstreamConfig,
  timeout_ms: u64,
) -> anyhow::Result<http::StatusCode> {
  let url = &upstream.origin;
  let remote = resolve_url_addr(url).await?;
  let quic_config = crate::tls::build_upstream_quic_client_config_with_resumption_and_revocation(
    &config.proxy.trusted_ca_certs,
    &upstream.tls.ech,
    &config.quic,
    &upstream.tls.resumption,
    None,
    &upstream.name,
    Some((revocation, revocation.policy_for_upstream(upstream))),
  )?;
  let endpoint = crate::quic::bind_client_endpoint(
    remote,
    &config.quic,
    config.source_paths.cert_dir.as_deref(),
  )?;
  let host = url
    .host_str()
    .ok_or_else(|| anyhow!("upstream origin has no host: {url}"))?
    .to_string();
  let timeout = Duration::from_millis(timeout_ms);
  let quinn_connection = tokio::time::timeout(
    timeout,
    endpoint
      .connect_with(quic_config, remote, &host)
      .with_context(|| format!("failed to start upstream HTTP/3 connection to {host}"))?,
  )
  .await
  .context("upstream HTTP/3 connect timed out")?
  .with_context(|| format!("failed to connect upstream HTTP/3 to {host}"))?;
  let h3_connection = h3_quinn::Connection::new(quinn_connection);
  let (mut driver, mut send_request): (_, h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>) =
    h3::client::builder()
      .build(h3_connection)
      .await
      .with_context(|| {
        format!(
          "failed to establish upstream HTTP/3 connection for {}",
          upstream.name
        )
      })?;
  let driver_task = tokio::spawn(async move {
    let _ = poll_fn(|cx| driver.poll_close(cx)).await;
  });

  let mut probe_url = url.clone();
  probe_url.set_path("/healthz");
  probe_url.set_query(None);
  probe_url.set_fragment(None);
  let request = Request::builder()
    .method(http::Method::GET)
    .uri(uri_from_url(&probe_url)?)
    .body(())?;
  let mut stream = send_request.send_request(request).await?;
  stream.finish().await?;
  let response = tokio::time::timeout(timeout, stream.recv_response())
    .await
    .context("upstream HTTP/3 first byte timed out")??;
  driver_task.abort();
  Ok(response.status())
}

async fn resolve_url_addr(url: &url::Url) -> anyhow::Result<std::net::SocketAddr> {
  let port = url
    .port_or_known_default()
    .ok_or_else(|| anyhow!("upstream origin has no port: {url}"))?;
  let host = url
    .host_str()
    .ok_or_else(|| anyhow!("upstream origin has no host: {url}"))?;
  tokio::net::lookup_host((host, port))
    .await
    .with_context(|| format!("failed to resolve upstream host {host}:{port}"))?
    .next()
    .ok_or_else(|| anyhow!("upstream host resolved no addresses: {host}:{port}"))
}

fn push_probe_error(report: &mut DiagnosticReport, target: &str, error: anyhow::Error) {
  let message = error.to_string();
  report.probe("upstream", target, "error", &message);
  report.push(
    DiagnosticSeverity::Error,
    "probe.upstream_failed",
    "probe",
    target,
    format!("upstream probe failed: {message}"),
    "Fix upstream DNS, network policy, TLS trust, health path/status, or disable upstream external probes for offline validation.",
  );
}

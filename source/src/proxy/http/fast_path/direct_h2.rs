//! Direct upstream HTTP/2 transport for the plain-proxy fast path.
//! It is limited to direct empty-body safe requests and falls back for all broader semantics.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use bytes::Bytes;
use http::{Method, Request, Response, Uri};
use http_body_util::{BodyExt, Empty};
use hyper::body::{Body, Incoming};
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};
use url::Url;

use crate::config::{HttpVersion, ProxyHttp2Config, ProxyProtocolEgressMode, UpstreamConfig};
use crate::metrics::Metrics;
use crate::proxy::http::EffectiveTimeouts;
use crate::proxy::http::body::{BoxError, ProxyBody};
use crate::tls::{OutboundRevocationRuntime, TlsResumptionState};

#[derive(Clone, Default)]
pub(crate) struct DirectH2Pools {
  pools: Vec<Option<Arc<DirectH2Pool>>>,
}

impl DirectH2Pools {
  pub(crate) fn new(
    upstreams: &[UpstreamConfig],
    extra_root_certs: &[PathBuf],
    tls_resumption: &TlsResumptionState,
    http2_config: &ProxyHttp2Config,
    outbound_revocation: &OutboundRevocationRuntime,
  ) -> anyhow::Result<Self> {
    let mut pools = Vec::with_capacity(upstreams.len());
    for upstream in upstreams {
      pools.push(
        DirectH2Pool::new(
          upstream,
          extra_root_certs,
          tls_resumption,
          http2_config,
          outbound_revocation,
        )
        .transpose()
        .with_context(|| format!("failed to build direct H2 pool for {}", upstream.name))?
        .map(Arc::new),
      );
    }
    Ok(Self { pools })
  }

  fn for_upstream_index(&self, upstream_index: usize) -> Option<Arc<DirectH2Pool>> {
    self
      .pools
      .get(upstream_index)
      .and_then(|pool| pool.as_ref())
      .cloned()
  }
}

struct DirectH2Pool {
  origin: DirectH2Origin,
  connect_timeout: Duration,
  idle_timeout: Duration,
  http2_config: ProxyHttp2Config,
  tls_config: Option<Arc<rustls::ClientConfig>>,
  entry: tokio::sync::Mutex<Option<Arc<DirectH2Connection>>>,
}

struct DirectH2Connection {
  sender: SendRequest<ProxyBody>,
  last_used: Mutex<Instant>,
}

impl DirectH2Connection {
  fn usable(&self, idle_timeout: Duration) -> bool {
    self
      .last_used
      .lock()
      .expect("direct H2 last-used lock poisoned")
      .elapsed()
      <= idle_timeout
  }

  fn mark_used(&self) {
    *self
      .last_used
      .lock()
      .expect("direct H2 last-used lock poisoned") = Instant::now();
  }
}

struct DirectH2Origin {
  scheme: &'static str,
  host: String,
  port: u16,
}

impl DirectH2Origin {
  fn from_url(origin: &Url) -> Option<Self> {
    let scheme = match origin.scheme() {
      "http" => "http",
      "https" => "https",
      _ => return None,
    };
    Some(Self {
      scheme,
      host: origin.host_str()?.to_owned(),
      port: origin.port_or_known_default()?,
    })
  }
}

pub(super) enum DirectH2SendResult {
  Fallback(Request<ProxyBody>),
  Sent(Result<Response<Incoming>, anyhow::Error>),
}

impl DirectH2Pool {
  fn new(
    upstream: &UpstreamConfig,
    extra_root_certs: &[PathBuf],
    tls_resumption: &TlsResumptionState,
    http2_config: &ProxyHttp2Config,
    outbound_revocation: &OutboundRevocationRuntime,
  ) -> Option<anyhow::Result<Self>> {
    let origin = DirectH2Origin::from_url(&upstream.origin)?;
    let tls_config = if origin.scheme == "https" {
      Some(build_h2_tls_config(
        upstream,
        extra_root_certs,
        tls_resumption,
        outbound_revocation,
      ))
    } else {
      None
    };
    Some(tls_config.transpose().map(|tls_config| Self {
      origin,
      connect_timeout: Duration::from_millis(upstream.connect_timeout_ms),
      idle_timeout: Duration::from_millis(upstream.idle_timeout_ms),
      http2_config: *http2_config,
      tls_config,
      entry: tokio::sync::Mutex::new(None),
    }))
  }

  async fn sender(&self, metrics: &Arc<Metrics>) -> anyhow::Result<(SendRequest<ProxyBody>, bool)> {
    let mut entry = self.entry.lock().await;
    if let Some(connection) = entry.as_ref() {
      if connection.usable(self.idle_timeout) {
        connection.mark_used();
        return Ok((connection.sender.clone(), true));
      }
      *entry = None;
    }

    metrics.record_http_upstream_client_pool_miss(
      self.metric_version(),
      self.origin.scheme,
      "primary",
    );
    let sender = self.connect_sender(metrics).await?;
    *entry = Some(Arc::new(DirectH2Connection {
      sender: sender.clone(),
      last_used: Mutex::new(Instant::now()),
    }));
    Ok((sender, false))
  }

  async fn clear_sender(&self) {
    *self.entry.lock().await = None;
  }

  async fn connect_sender(&self, metrics: &Arc<Metrics>) -> anyhow::Result<SendRequest<ProxyBody>> {
    let stream = tokio::time::timeout(
      self.connect_timeout,
      TcpStream::connect((self.origin.host.as_str(), self.origin.port)),
    )
    .await
    .context("direct H2 upstream connect timed out")?
    .with_context(|| {
      format!(
        "failed to connect direct H2 upstream {}:{}",
        self.origin.host, self.origin.port
      )
    })?;
    stream
      .set_nodelay(true)
      .context("failed to enable TCP_NODELAY for direct H2 upstream")?;

    let sender = if let Some(tls_config) = &self.tls_config {
      let server_name = rustls::pki_types::ServerName::try_from(self.origin.host.clone())
        .map_err(|error| anyhow::anyhow!("invalid upstream TLS server name: {error}"))?;
      let tls = tokio::time::timeout(
        self.connect_timeout,
        TlsConnector::from(tls_config.clone()).connect(server_name, stream),
      )
      .await
      .context("direct H2 upstream TLS handshake timed out")?
      .context("direct H2 upstream TLS handshake failed")?;
      h2_handshake(tls, &self.http2_config).await?
    } else {
      h2_handshake(stream, &self.http2_config).await?
    };

    metrics.record_http_upstream_client_connection_created(
      self.metric_version(),
      self.origin.scheme,
      "primary",
    );
    Ok(sender)
  }

  fn metric_version(&self) -> &'static str {
    if self.origin.scheme == "http" {
      "h2c"
    } else {
      "h2"
    }
  }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn try_send_direct_h2(
  pools: &DirectH2Pools,
  metrics: &Arc<Metrics>,
  upstream_index: usize,
  upstream: &UpstreamConfig,
  upstream_version: HttpVersion,
  request_version: http::Version,
  direct_selection_used: bool,
  request_body_proven_empty: bool,
  outbound: Request<ProxyBody>,
  timeouts: EffectiveTimeouts,
) -> DirectH2SendResult {
  let protocol = fast_path_metric_protocol(request_version);
  if let Some(reason) = direct_h2_guard_miss(
    upstream,
    upstream_version,
    request_version,
    direct_selection_used,
    request_body_proven_empty,
    &outbound,
  ) {
    metrics.record_direct_h2_transport_miss(protocol, reason);
    return DirectH2SendResult::Fallback(outbound);
  }

  let Some(pool) = pools.for_upstream_index(upstream_index) else {
    metrics.record_direct_h2_transport_miss(protocol, "unsupported_upstream");
    return DirectH2SendResult::Fallback(outbound);
  };

  let prepared = match PreparedDirectH2Request::from_request(outbound) {
    Ok(prepared) => prepared,
    Err(error) => {
      metrics.record_direct_h2_transport_miss(protocol, "unsupported_request");
      return DirectH2SendResult::Sent(Err(error));
    }
  };

  let result = send_prepared_request(pool, metrics, prepared, timeouts).await;
  match &result {
    Ok(_) => metrics.record_direct_h2_transport_hit(protocol),
    Err(error) if error.to_string().contains("timed out") => {
      metrics.record_direct_h2_transport_miss(protocol, "connect_error");
    }
    Err(_) => {
      metrics.record_direct_h2_transport_miss(protocol, "send_error");
    }
  }
  DirectH2SendResult::Sent(result)
}

fn direct_h2_guard_miss(
  upstream: &UpstreamConfig,
  upstream_version: HttpVersion,
  request_version: http::Version,
  direct_selection_used: bool,
  request_body_proven_empty: bool,
  outbound: &Request<ProxyBody>,
) -> Option<&'static str> {
  if !matches!(
    request_version,
    http::Version::HTTP_11 | http::Version::HTTP_2 | http::Version::HTTP_3
  ) || !direct_selection_used
    || !matches!(outbound.method(), &Method::GET | &Method::HEAD)
  {
    return Some("unsupported_request");
  }
  if upstream_version != HttpVersion::H2
    || !matches!(upstream.origin.scheme(), "http" | "https")
    || upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
  {
    return Some("unsupported_upstream");
  }
  if !request_body_proven_empty || !outbound.body().is_end_stream() {
    return Some("request_body");
  }
  None
}

async fn send_prepared_request(
  pool: Arc<DirectH2Pool>,
  metrics: &Arc<Metrics>,
  prepared: PreparedDirectH2Request,
  timeouts: EffectiveTimeouts,
) -> anyhow::Result<Response<Incoming>> {
  metrics.record_http_upstream_client_request(pool.metric_version(), pool.origin.scheme, "primary");

  let (mut sender, reused) = pool.sender(metrics).await?;
  let mut retry = reused.then(|| prepared.retry_request());
  match tokio::time::timeout(
    timeouts.upstream_first_byte,
    sender.send_request(prepared.into_request()),
  )
  .await
  {
    Ok(Ok(response)) => Ok(response),
    Ok(Err(error)) if reused => {
      debug!(error = %error, "direct H2 upstream sender failed; reconnecting once");
      pool.clear_sender().await;
      let (mut sender, _) = pool.sender(metrics).await?;
      let retry = retry
        .take()
        .expect("reused direct H2 sends should retain one retry request");
      tokio::time::timeout(
        timeouts.upstream_first_byte,
        sender.send_request(retry.into_request()),
      )
      .await
      .context("direct H2 upstream first-byte timeout")?
      .context("direct H2 upstream retry request failed")
    }
    Ok(Err(error)) => {
      pool.clear_sender().await;
      Err(error.into())
    }
    Err(_) => anyhow::bail!("direct H2 upstream first-byte timed out"),
  }
}

async fn h2_handshake<I>(
  io: I,
  http2_config: &ProxyHttp2Config,
) -> anyhow::Result<SendRequest<ProxyBody>>
where
  I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
  crate::h2_tuning::apply_client_conn_defaults(&mut builder, http2_config);
  let (sender, connection) = builder
    .handshake(TokioIo::new(io))
    .await
    .context("failed to establish direct HTTP/2 upstream connection")?;
  tokio::spawn(async move {
    if let Err(error) = connection.await {
      warn!(error = %error, "direct HTTP/2 upstream connection closed with error");
    }
  });
  Ok(sender)
}

struct PreparedDirectH2Request {
  request: Request<ProxyBody>,
}

struct RetryDirectH2Request {
  method: Method,
  uri: Uri,
  headers: http::HeaderMap,
}

impl PreparedDirectH2Request {
  fn from_request(mut request: Request<ProxyBody>) -> anyhow::Result<Self> {
    if request.uri().scheme().is_none() || request.uri().authority().is_none() {
      anyhow::bail!("direct H2 request URI must be absolute-form");
    }
    *request.version_mut() = http::Version::HTTP_2;
    Ok(Self { request })
  }

  fn retry_request(&self) -> RetryDirectH2Request {
    RetryDirectH2Request {
      method: self.request.method().clone(),
      uri: self.request.uri().clone(),
      headers: self.request.headers().clone(),
    }
  }

  fn into_request(self) -> Request<ProxyBody> {
    self.request
  }
}

impl RetryDirectH2Request {
  fn into_request(self) -> Request<ProxyBody> {
    let mut request = Request::builder()
      .method(self.method)
      .version(http::Version::HTTP_2)
      .uri(self.uri)
      .body(empty_body())
      .expect("direct H2 retry request parts should be valid");
    *request.headers_mut() = self.headers;
    request
  }
}

fn build_h2_tls_config(
  upstream: &UpstreamConfig,
  extra_root_certs: &[PathBuf],
  tls_resumption: &TlsResumptionState,
  outbound_revocation: &OutboundRevocationRuntime,
) -> anyhow::Result<Arc<rustls::ClientConfig>> {
  let root_certs;
  let extra_root_certs = if upstream.extra_trusted_ca_certs.is_empty() {
    extra_root_certs
  } else {
    root_certs = extra_root_certs
      .iter()
      .chain(upstream.extra_trusted_ca_certs.iter())
      .cloned()
      .collect::<Vec<PathBuf>>();
    &root_certs
  };
  let revocation_policy = outbound_revocation.policy_for_upstream(upstream);
  let mut tls_config = crate::tls::build_upstream_client_config_with_resumption_and_revocation(
    extra_root_certs,
    &upstream.tls.ech,
    &upstream.tls.resumption,
    Some(tls_resumption),
    &upstream.name,
    Some((outbound_revocation, revocation_policy)),
  )?;
  tls_config.alpn_protocols = vec![b"h2".to_vec()];
  Ok(Arc::new(tls_config))
}

fn empty_body() -> ProxyBody {
  Empty::<Bytes>::new()
    .map_err(|never| -> BoxError { match never {} })
    .boxed()
}

fn fast_path_metric_protocol(version: http::Version) -> &'static str {
  match version {
    http::Version::HTTP_10 | http::Version::HTTP_11 => "h1",
    http::Version::HTTP_2 => "h2",
    http::Version::HTTP_3 => "h3",
    _ => "other",
  }
}

#[cfg(test)]
mod tests;

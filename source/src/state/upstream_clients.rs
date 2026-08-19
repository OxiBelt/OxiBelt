use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Context as AnyhowContext;
use bytes::Bytes;
use http::Uri;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::rt::{Read as HyperRead, ReadBufCursor, Write as HyperWrite};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tower_service::Service;

use crate::circuit_breakers::{AdmissionLease, CircuitBreakerRuntime};
use crate::config::{
  CryptoConfig, HttpVersion, ProxyHttp2Config, UpstreamConfig, UpstreamPoolConfig,
  upstream_pool_server_id,
};
use crate::metrics::Metrics;
use crate::pools::synthetic_upstream_name_for_id;
use crate::tls;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type UpstreamBody = BoxBody<Bytes, BoxError>;
type HyperConnector = InstrumentedConnector<HappyEyeballsHttpConnector>;
type H2cConnector = InstrumentedConnector<HappyEyeballsHttpConnector>;
type HyperClient = Client<HyperConnector, UpstreamBody>;
type H2cClient = Client<H2cConnector, UpstreamBody>;

trait ReadyHyperIo: HyperRead + HyperWrite + Send + Unpin {}

impl<T> ReadyHyperIo for T where T: HyperRead + HyperWrite + Send + Unpin {}

pub(crate) struct ReadyHttpTransport {
  io: Box<dyn ReadyHyperIo>,
  negotiated_h2: bool,
}

impl Connection for ReadyHttpTransport {
  fn connected(&self) -> Connected {
    if self.negotiated_h2 {
      Connected::new().negotiated_h2()
    } else {
      Connected::new()
    }
  }
}

impl HyperRead for ReadyHttpTransport {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: ReadBufCursor<'_>,
  ) -> Poll<std::io::Result<()>> {
    Pin::new(&mut *self.io).poll_read(cx, buf)
  }
}

impl HyperWrite for ReadyHttpTransport {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    Pin::new(&mut *self.io).poll_write(cx, buf)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut *self.io).poll_flush(cx)
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut *self.io).poll_shutdown(cx)
  }

  fn is_write_vectored(&self) -> bool {
    self.io.is_write_vectored()
  }

  fn poll_write_vectored(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &[std::io::IoSlice<'_>],
  ) -> Poll<std::io::Result<usize>> {
    Pin::new(&mut *self.io).poll_write_vectored(cx, bufs)
  }
}

#[derive(Clone, Copy)]
enum FixedHttpProtocol {
  H1,
  H2,
}

impl FixedHttpProtocol {
  fn is_h2(self) -> bool {
    matches!(self, Self::H2)
  }

  fn accepts_negotiated_alpn(self, negotiated: Option<&[u8]>) -> bool {
    match self {
      Self::H1 => negotiated.is_none_or(|alpn| alpn == b"http/1.1"),
      Self::H2 => negotiated == Some(b"h2"),
    }
  }
}

#[derive(Clone)]
pub(crate) struct HappyEyeballsHttpConnector {
  host: Arc<str>,
  port: u16,
  discovery_id: Arc<str>,
  connect_timeout: Duration,
  resolution_policy: crate::upstream_resolution::ResolutionPolicy,
  scheduler_policy: crate::upstream_resolution::CandidateSchedulerConfig,
  protocol: FixedHttpProtocol,
  svcb_enabled: bool,
  allowed_svcb_ports: Arc<[u16]>,
  tls_config: Option<Arc<rustls::ClientConfig>>,
  server_name: Option<rustls::pki_types::ServerName<'static>>,
}

impl Service<Uri> for HappyEyeballsHttpConnector {
  type Response = ReadyHttpTransport;
  type Error = BoxError;
  type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

  fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
    Poll::Ready(Ok(()))
  }

  fn call(&mut self, _requested: Uri) -> Self::Future {
    let connector = self.clone();
    Box::pin(async move { connector.connect().await })
  }
}

impl HappyEyeballsHttpConnector {
  async fn connect(self) -> Result<ReadyHttpTransport, BoxError> {
    let deadline = tokio::time::Instant::now()
      .checked_add(self.connect_timeout)
      .ok_or_else(|| -> BoxError {
        anyhow::anyhow!("upstream connection deadline overflowed").into()
      })?;
    let mut updates = crate::upstream_resolution::resolve_http_candidate_updates(
      &self.host,
      self.port,
      &self.discovery_id,
      self.resolution_policy,
      match self.protocol {
        FixedHttpProtocol::H1 => crate::upstream_resolution::HttpTransportProtocol::H1,
        FixedHttpProtocol::H2 => crate::upstream_resolution::HttpTransportProtocol::H2,
      },
      self.tls_config.is_some(),
      self.svcb_enabled,
      &self.allowed_svcb_ports,
      deadline,
    )
    .map_err(|error| -> BoxError { error.into() })?;
    let protocol = self.protocol;
    let tls_config = self.tls_config;
    let server_name = self.server_name;
    crate::upstream_resolution::race_happy_eyeballs_candidates(
      &mut updates,
      self.scheduler_policy,
      deadline,
      move |candidate, _| {
        let tls_config = tls_config.clone();
        let server_name = server_name.clone();
        async move {
          let address = candidate.into_value();
          let stream = tokio::time::timeout_at(deadline, TcpStream::connect(address))
            .await
            .map_err(|_| {
              crate::upstream_resolution::CandidateAttemptError::Endpoint(anyhow::anyhow!(
                "upstream TCP candidate {address} timed out"
              ))
            })?
            .map_err(|error| {
              crate::upstream_resolution::CandidateAttemptError::Endpoint(anyhow::Error::new(error))
            })?;
          stream.set_nodelay(true).map_err(|error| {
            crate::upstream_resolution::CandidateAttemptError::Endpoint(anyhow::Error::new(error))
          })?;
          let io: Box<dyn ReadyHyperIo> = match (tls_config, server_name) {
            (Some(tls_config), Some(server_name)) => {
              let tls = tokio::time::timeout_at(
                deadline,
                TlsConnector::from(tls_config).connect(server_name, stream),
              )
              .await
              .map_err(|_| {
                crate::upstream_resolution::CandidateAttemptError::Endpoint(anyhow::anyhow!(
                  "upstream TLS handshake timed out"
                ))
              })?
              .map_err(|error| {
                crate::upstream_resolution::CandidateAttemptError::Endpoint(anyhow::Error::new(
                  error,
                ))
              })?;
              if !protocol.accepts_negotiated_alpn(tls.get_ref().1.alpn_protocol()) {
                return Err(crate::upstream_resolution::CandidateAttemptError::Endpoint(
                  anyhow::anyhow!("upstream TLS negotiated an unexpected ALPN protocol"),
                ));
              }
              Box::new(TokioIo::new(tls))
            }
            (None, None) => Box::new(TokioIo::new(stream)),
            _ => {
              return Err(crate::upstream_resolution::CandidateAttemptError::Endpoint(
                anyhow::anyhow!("upstream TLS connector has incomplete identity state"),
              ));
            }
          };
          Ok(ReadyHttpTransport {
            io,
            negotiated_h2: protocol.is_h2(),
          })
        }
      },
    )
    .await
    .map_err(|error| -> BoxError { Box::new(HttpCandidateRaceFailure(error)) })
  }
}

#[derive(Debug)]
struct HttpCandidateRaceFailure(crate::upstream_resolution::CandidateRaceError<anyhow::Error>);

impl std::fmt::Display for HttpCandidateRaceFailure {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match &self.0 {
      crate::upstream_resolution::CandidateRaceError::Deadline => {
        formatter.write_str("upstream connection deadline elapsed")
      }
      crate::upstream_resolution::CandidateRaceError::NoCandidates => {
        formatter.write_str("upstream resolver returned no candidates")
      }
      crate::upstream_resolution::CandidateRaceError::Exhausted { .. } => {
        formatter.write_str("upstream connection candidates were exhausted")
      }
    }
  }
}

impl std::error::Error for HttpCandidateRaceFailure {}

#[derive(Clone)]
pub(super) struct ClientPool {
  h1_only: HyperClient,
  negotiated: HyperClient,
  h2c: H2cClient,
  metrics: Arc<Metrics>,
  pool_label: &'static str,
}

impl ClientPool {
  fn for_version(
    &self,
    origin_scheme: &str,
    version: HttpVersion,
  ) -> Option<UpstreamClientRef<'_>> {
    match version {
      HttpVersion::H1 => Some(UpstreamClientRef::Hyper {
        client: &self.h1_only,
        metrics: &self.metrics,
        version: "h1",
        pool: self.pool_label,
      }),
      HttpVersion::H2 if origin_scheme == "http" => Some(UpstreamClientRef::H2c {
        client: &self.h2c,
        metrics: &self.metrics,
        version: "h2c",
        pool: self.pool_label,
      }),
      HttpVersion::H2 => Some(UpstreamClientRef::Hyper {
        client: &self.negotiated,
        metrics: &self.metrics,
        version: "h2",
        pool: self.pool_label,
      }),
      HttpVersion::H3 => None,
    }
  }
}

#[derive(Clone, Copy)]
pub(crate) enum UpstreamClientRef<'a> {
  Hyper {
    client: &'a HyperClient,
    metrics: &'a Arc<Metrics>,
    version: &'static str,
    pool: &'static str,
  },
  H2c {
    client: &'a H2cClient,
    metrics: &'a Arc<Metrics>,
    version: &'static str,
    pool: &'static str,
  },
}

impl UpstreamClientRef<'_> {
  pub(crate) async fn request(
    &self,
    request: http::Request<UpstreamBody>,
  ) -> Result<http::Response<Incoming>, hyper_util::client::legacy::Error> {
    let scheme = metric_scheme(request.uri());
    match self {
      Self::Hyper {
        client,
        metrics,
        version,
        pool,
      } => {
        metrics.record_http_upstream_client_request(version, scheme, pool);
        client.request(request).await
      }
      Self::H2c {
        client,
        metrics,
        version,
        pool,
      } => {
        metrics.record_http_upstream_client_request(version, scheme, pool);
        client.request(request).await
      }
    }
  }
}

/// Per-upstream HTTP client pools keyed by validated upstream configuration.
#[derive(Clone)]
pub struct UpstreamClientPools {
  pub(super) by_upstream: HashMap<String, usize>,
  pub(super) pools: Vec<ClientPool>,
}

impl UpstreamClientPools {
  pub(crate) fn for_upstream_index(
    &self,
    upstream_index: usize,
    origin_scheme: &str,
    version: HttpVersion,
  ) -> Option<UpstreamClientRef<'_>> {
    self
      .pools
      .get(upstream_index)
      .and_then(|pool| pool.for_version(origin_scheme, version))
  }

  pub(crate) fn upstream_index(&self, upstream_name: &str) -> Option<usize> {
    self.by_upstream.get(upstream_name).copied()
  }

  pub(crate) fn for_upstream_version(
    &self,
    upstream_name: &str,
    origin_scheme: &str,
    version: HttpVersion,
  ) -> Option<UpstreamClientRef<'_>> {
    self
      .by_upstream
      .get(upstream_name)
      .and_then(|&index| self.for_upstream_index(index, origin_scheme, version))
  }
}

#[derive(Clone)]
pub(crate) struct InstrumentedConnector<C> {
  inner: C,
  metrics: Arc<Metrics>,
  version: &'static str,
  pool: &'static str,
  circuit_breakers: Option<Arc<CircuitBreakerRuntime>>,
  circuit_pool: Option<Arc<str>>,
}

impl<C> InstrumentedConnector<C> {
  fn new(
    inner: C,
    metrics: Arc<Metrics>,
    version: &'static str,
    pool: &'static str,
    circuit_breakers: Option<Arc<CircuitBreakerRuntime>>,
    circuit_pool: Option<Arc<str>>,
  ) -> Self {
    Self {
      inner,
      metrics,
      version,
      pool,
      circuit_breakers,
      circuit_pool,
    }
  }
}

/// Holds a connection admission for the lifetime of a pooled transport.
pub(crate) struct AdmissionConnection<C> {
  inner: C,
  _lease: Option<AdmissionLease>,
}

impl<C> Connection for AdmissionConnection<C>
where
  C: Connection,
{
  fn connected(&self) -> Connected {
    self.inner.connected()
  }
}

impl<C> HyperRead for AdmissionConnection<C>
where
  C: HyperRead + Unpin,
{
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: ReadBufCursor<'_>,
  ) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
  }
}

impl<C> HyperWrite for AdmissionConnection<C>
where
  C: HyperWrite + Unpin,
{
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.get_mut().inner).poll_flush(cx)
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
  }

  fn is_write_vectored(&self) -> bool {
    self.inner.is_write_vectored()
  }

  fn poll_write_vectored(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &[std::io::IoSlice<'_>],
  ) -> Poll<std::io::Result<usize>> {
    Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
  }
}

impl<C> Service<Uri> for InstrumentedConnector<C>
where
  C: Service<Uri> + Send + 'static,
  C::Future: Send + 'static,
  C::Response: HyperRead + HyperWrite + Connection + Send + Unpin + 'static,
  C::Error: Into<BoxError>,
{
  type Response = AdmissionConnection<C::Response>;
  type Error = BoxError;
  type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

  fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
    match self.inner.poll_ready(cx) {
      Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
      Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
      Poll::Pending => Poll::Pending,
    }
  }

  fn call(&mut self, dst: Uri) -> Self::Future {
    let scheme = metric_scheme(&dst);
    self
      .metrics
      .record_http_upstream_client_pool_miss(self.version, scheme, self.pool);
    let metrics = self.metrics.clone();
    let version = self.version;
    let pool = self.pool;
    let circuit_breakers = self.circuit_breakers.clone();
    let circuit_pool = self.circuit_pool.clone();
    let future = self.inner.call(dst);
    Box::pin(async move {
      let lease = match circuit_breakers {
        Some(runtime) => Some(
          runtime
            .admit_upstream_connection(circuit_pool.as_deref(), None)
            .await
            .map_err(|error| -> BoxError { Box::new(error) })?,
        ),
        None => None,
      };
      let result: Result<C::Response, BoxError> = future.await.map_err(Into::into);
      if result.is_ok() {
        metrics.record_http_upstream_client_connection_created(version, scheme, pool);
      }
      result.map(|inner| AdmissionConnection {
        inner,
        _lease: lease,
      })
    })
  }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_clients(
  upstreams: &[UpstreamConfig],
  extra_root_certs: &[std::path::PathBuf],
  crypto: &CryptoConfig,
  tls_resumption: &tls::TlsResumptionState,
  http2_config: &ProxyHttp2Config,
  outbound_revocation: &tls::OutboundRevocationRuntime,
  metrics: Arc<Metrics>,
  pool_label: &'static str,
  circuit_breakers: Option<Arc<CircuitBreakerRuntime>>,
  circuit_pools: &[UpstreamPoolConfig],
  resolution_config: &crate::config::UpstreamResolutionConfig,
) -> anyhow::Result<UpstreamClientPools> {
  let mut by_upstream = HashMap::new();
  let mut pools = Vec::with_capacity(upstreams.len());

  for upstream in upstreams {
    let index = pools.len();
    let circuit_pool = circuit_pool_for_upstream(&upstream.name, circuit_pools);
    let pool = build_client_pool(
      upstream,
      extra_root_certs,
      crypto,
      tls_resumption,
      http2_config,
      outbound_revocation,
      metrics.clone(),
      pool_label,
      circuit_breakers.clone(),
      circuit_pool,
      resolution_config,
    )
    .with_context(|| format!("failed to build clients for upstream {}", upstream.name))?;
    by_upstream.insert(upstream.name.clone(), index);
    pools.push(pool);
  }

  Ok(UpstreamClientPools { by_upstream, pools })
}

#[allow(clippy::too_many_arguments)]
fn build_client_pool(
  upstream: &UpstreamConfig,
  extra_root_certs: &[std::path::PathBuf],
  crypto: &CryptoConfig,
  tls_resumption: &tls::TlsResumptionState,
  http2_config: &ProxyHttp2Config,
  outbound_revocation: &tls::OutboundRevocationRuntime,
  metrics: Arc<Metrics>,
  pool_label: &'static str,
  circuit_breakers: Option<Arc<CircuitBreakerRuntime>>,
  circuit_pool: Option<Arc<str>>,
  resolution_config: &crate::config::UpstreamResolutionConfig,
) -> anyhow::Result<ClientPool> {
  let revocation_policy = outbound_revocation.policy_for_upstream(upstream);
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
  let mut h1_tls_config = tls::build_upstream_client_config_with_policy(
    crypto,
    extra_root_certs,
    &upstream.tls,
    Some(tls_resumption),
    &upstream.name,
    Some((outbound_revocation, revocation_policy.clone())),
  )
  .context("failed to build HTTP/1.1 upstream TLS client")?;
  h1_tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
  let mut negotiated_tls_config = tls::build_upstream_client_config_with_policy(
    crypto,
    extra_root_certs,
    &upstream.tls,
    Some(tls_resumption),
    &upstream.name,
    Some((outbound_revocation, revocation_policy)),
  )
  .context("failed to build negotiated upstream TLS client")?;
  negotiated_tls_config.alpn_protocols = vec![b"h2".to_vec()];
  let (resolution_policy, scheduler_policy) =
    crate::upstream_resolution::http_upstream_policies(resolution_config, upstream)?;
  let host = upstream
    .origin
    .host_str()
    .with_context(|| format!("upstream {} origin has no host", upstream.name))?;
  let port = upstream
    .origin
    .port_or_known_default()
    .with_context(|| format!("upstream {} origin has no port", upstream.name))?;
  let server_name = upstream
    .tls
    .server_name
    .as_deref()
    .unwrap_or(host)
    .to_string();
  let server_name = rustls::pki_types::ServerName::try_from(server_name)
    .with_context(|| format!("invalid TLS server name for upstream {}", upstream.name))?;
  let tls_enabled = upstream.origin.scheme() == "https";
  let svcb_enabled = resolution_config.happy_eyeballs.svcb
    == crate::config::UpstreamResolutionDnsMode::Auto
    && scheduler_policy.mode() == crate::upstream_resolution::CandidateSchedulerMode::Enabled;
  let allowed_svcb_ports = Arc::<[u16]>::from(upstream.svcb_allowed_ports.clone());
  let connector = |protocol, tls_config| HappyEyeballsHttpConnector {
    host: Arc::from(host.to_string()),
    port,
    discovery_id: Arc::from(format!("hyper:{}:{host}:{port}", upstream.name)),
    connect_timeout: Duration::from_millis(upstream.connect_timeout_ms),
    resolution_policy,
    scheduler_policy,
    protocol,
    svcb_enabled,
    allowed_svcb_ports: allowed_svcb_ports.clone(),
    tls_config: tls_enabled.then(|| Arc::new(tls_config)),
    server_name: tls_enabled.then(|| server_name.clone()),
  };
  let h1_connector = connector(FixedHttpProtocol::H1, h1_tls_config);
  let h1_connector = InstrumentedConnector::new(
    h1_connector,
    metrics.clone(),
    "h1",
    pool_label,
    circuit_breakers.clone(),
    circuit_pool.clone(),
  );
  let mut h1_builder = Client::builder(TokioExecutor::new());
  // Keep every retry visible to OxiBelt's deadline, retry budget, and circuit
  // accounting. Hyper-util otherwise retries a cancelled reused connection
  // before the request reaches our retry policy.
  h1_builder.retry_canceled_requests(false);
  apply_client_pool_defaults(&mut h1_builder, upstream);
  let h1_only = h1_builder.build(h1_connector);

  let negotiated_connector = connector(FixedHttpProtocol::H2, negotiated_tls_config);
  let negotiated_connector = InstrumentedConnector::new(
    negotiated_connector,
    metrics.clone(),
    "h2",
    pool_label,
    circuit_breakers.clone(),
    circuit_pool.clone(),
  );
  let mut negotiated_builder = Client::builder(TokioExecutor::new());
  negotiated_builder.retry_canceled_requests(false);
  crate::h2_tuning::apply_legacy_client_defaults(&mut negotiated_builder, http2_config);
  apply_client_pool_defaults(&mut negotiated_builder, upstream);
  let negotiated = negotiated_builder.build(negotiated_connector);

  let mut h2c_builder = Client::builder(TokioExecutor::new());
  h2c_builder.retry_canceled_requests(false);
  h2c_builder.http2_only(true);
  crate::h2_tuning::apply_legacy_client_defaults(&mut h2c_builder, http2_config);
  apply_client_pool_defaults(&mut h2c_builder, upstream);
  let h2c_http = HappyEyeballsHttpConnector {
    host: Arc::from(host.to_string()),
    port,
    discovery_id: Arc::from(format!("hyper-h2c:{}:{host}:{port}", upstream.name)),
    connect_timeout: Duration::from_millis(upstream.connect_timeout_ms),
    resolution_policy,
    scheduler_policy,
    protocol: FixedHttpProtocol::H2,
    svcb_enabled,
    allowed_svcb_ports,
    tls_config: None,
    server_name: None,
  };
  let h2c_http = InstrumentedConnector::new(
    h2c_http,
    metrics.clone(),
    "h2c",
    pool_label,
    circuit_breakers,
    circuit_pool,
  );
  let h2c = h2c_builder.build(h2c_http);

  Ok(ClientPool {
    h1_only,
    negotiated,
    h2c,
    metrics,
    pool_label,
  })
}

fn circuit_pool_for_upstream(
  upstream_name: &str,
  pools: &[UpstreamPoolConfig],
) -> Option<Arc<str>> {
  pools
    .iter()
    .find(|pool| {
      pool.servers.iter().enumerate().any(|(index, server)| {
        synthetic_upstream_name_for_id(&pool.name, &upstream_pool_server_id(index, server))
          == upstream_name
      })
    })
    .map(|pool| Arc::<str>::from(pool.name.as_str()))
}

fn apply_client_pool_defaults(
  builder: &mut hyper_util::client::legacy::Builder,
  upstream: &UpstreamConfig,
) {
  builder.pool_timer(TokioTimer::new());
  builder.pool_idle_timeout(Duration::from_millis(upstream.idle_timeout_ms));
  builder.pool_max_idle_per_host(upstream.pool_max_idle_per_host);
}

fn metric_scheme(uri: &Uri) -> &'static str {
  match uri.scheme_str() {
    Some("http") => "http",
    Some("https") => "https",
    _ => "other",
  }
}

#[cfg(test)]
mod tests {
  use std::future::{Ready, ready};

  use hyper::rt::{Read as HyperRead, ReadBufCursor, Write as HyperWrite};
  use hyper_util::client::legacy::connect::{Connected, Connection};

  use super::*;

  #[test]
  fn fixed_protocol_alpn_acceptance_preserves_h1_fallback_and_requires_h2() {
    assert!(FixedHttpProtocol::H1.accepts_negotiated_alpn(None));
    assert!(FixedHttpProtocol::H1.accepts_negotiated_alpn(Some(b"http/1.1")));
    assert!(!FixedHttpProtocol::H1.accepts_negotiated_alpn(Some(b"h2")));
    assert!(!FixedHttpProtocol::H2.accepts_negotiated_alpn(None));
    assert!(FixedHttpProtocol::H2.accepts_negotiated_alpn(Some(b"h2")));
    assert!(!FixedHttpProtocol::H2.accepts_negotiated_alpn(Some(b"http/1.1")));
  }
  use crate::config::{CapacitySetting, Config};

  #[derive(Clone)]
  struct FakeConnector;

  impl Service<Uri> for FakeConnector {
    type Response = FakeIo;
    type Error = std::io::Error;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
      Poll::Ready(Ok(()))
    }

    fn call(&mut self, _dst: Uri) -> Self::Future {
      ready(Ok(FakeIo))
    }
  }

  struct FakeIo;

  impl Connection for FakeIo {
    fn connected(&self) -> Connected {
      Connected::new()
    }
  }

  impl HyperRead for FakeIo {
    fn poll_read(
      self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
      _buf: ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
      Poll::Ready(Ok(()))
    }
  }

  impl HyperWrite for FakeIo {
    fn poll_write(
      self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
      _buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
      Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
      Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
      Poll::Ready(Ok(()))
    }
  }

  #[tokio::test]
  async fn connector_records_pool_miss_and_created_connection() {
    let metrics = Metrics::new();
    let mut connector =
      InstrumentedConnector::new(FakeConnector, metrics.clone(), "h1", "primary", None, None);
    connector
      .call("http://example.test/".parse().expect("URI should parse"))
      .await
      .expect("connector should succeed");

    let body = metrics.prometheus(
      &crate::config::MetricsConfig::default(),
      crate::cache::CacheStats::default(),
      crate::tls::TlsServerSessionStorageStats::default(),
    );
    assert!(body.contains(
      "oxibelt_http_upstream_client_pool_misses_total{version=\"h1\",scheme=\"http\",pool=\"primary\"} 1"
    ));
    assert!(body.contains(
      "oxibelt_http_upstream_client_connections_created_total{version=\"h1\",scheme=\"http\",pool=\"primary\"} 1"
    ));
  }

  #[tokio::test]
  async fn connector_holds_connection_admission_for_transport_lifetime() {
    let mut config: Config =
      toml::from_str(include_str!("../../config/oxibelt.toml")).expect("example config parses");
    config.circuit_breakers.global.max_connections = CapacitySetting::Fixed(1);
    config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(0);
    let runtime = CircuitBreakerRuntime::new(&config);
    let metrics = Metrics::new();
    let mut connector =
      InstrumentedConnector::new(FakeConnector, metrics, "h1", "primary", Some(runtime), None);
    let uri: Uri = "http://example.test/".parse().expect("URI should parse");
    let first = connector
      .call(uri.clone())
      .await
      .expect("first connection should be admitted");
    assert!(connector.call(uri.clone()).await.is_err());
    drop(first);
    assert!(connector.call(uri).await.is_ok());
  }
}

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
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::{TokioExecutor, TokioTimer};
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
type HyperConnector = InstrumentedConnector<hyper_rustls::HttpsConnector<HttpConnector>>;
type H2cConnector = InstrumentedConnector<HttpConnector>;
type HyperClient = Client<HyperConnector, UpstreamBody>;
type H2cClient = Client<H2cConnector, UpstreamBody>;

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
  let h1_tls_config = tls::build_upstream_client_config_with_crypto_resumption_and_revocation(
    crypto,
    extra_root_certs,
    &upstream.tls.ech,
    &upstream.tls.resumption,
    Some(tls_resumption),
    &upstream.name,
    Some((outbound_revocation, revocation_policy.clone())),
  )
  .context("failed to build HTTP/1.1 upstream TLS client")?;
  let negotiated_tls_config =
    tls::build_upstream_client_config_with_crypto_resumption_and_revocation(
      crypto,
      extra_root_certs,
      &upstream.tls.ech,
      &upstream.tls.resumption,
      Some(tls_resumption),
      &upstream.name,
      Some((outbound_revocation, revocation_policy)),
    )
    .context("failed to build negotiated upstream TLS client")?;

  let mut h1_http = HttpConnector::new();
  h1_http.enforce_http(false);
  h1_http.set_connect_timeout(Some(Duration::from_millis(upstream.connect_timeout_ms)));
  h1_http.set_nodelay(true);
  let h1_connector = HttpsConnectorBuilder::new()
    .with_tls_config(h1_tls_config)
    .https_or_http()
    .enable_http1()
    .wrap_connector(h1_http);
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

  let mut negotiated_http = HttpConnector::new();
  negotiated_http.enforce_http(false);
  negotiated_http.set_connect_timeout(Some(Duration::from_millis(upstream.connect_timeout_ms)));
  negotiated_http.set_nodelay(true);
  let negotiated_connector = HttpsConnectorBuilder::new()
    .with_tls_config(negotiated_tls_config)
    .https_or_http()
    .enable_http1()
    .enable_http2()
    .wrap_connector(negotiated_http);
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
  let mut h2c_http = HttpConnector::new();
  h2c_http.set_connect_timeout(Some(Duration::from_millis(upstream.connect_timeout_ms)));
  h2c_http.set_nodelay(true);
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

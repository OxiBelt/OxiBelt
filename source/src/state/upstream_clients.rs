use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Context as AnyhowContext;
use http::Uri;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use tower_service::Service;

use crate::config::{ProxyHttp2Config, UpstreamConfig};
use crate::metrics::Metrics;
use crate::tls;

use super::{ClientPool, UpstreamClientPools};

#[derive(Clone)]
pub(crate) struct InstrumentedConnector<C> {
  inner: C,
  metrics: Arc<Metrics>,
  version: &'static str,
  pool: &'static str,
}

impl<C> InstrumentedConnector<C> {
  fn new(inner: C, metrics: Arc<Metrics>, version: &'static str, pool: &'static str) -> Self {
    Self {
      inner,
      metrics,
      version,
      pool,
    }
  }
}

impl<C> Service<Uri> for InstrumentedConnector<C>
where
  C: Service<Uri> + Send + 'static,
  C::Future: Send + 'static,
{
  type Response = C::Response;
  type Error = C::Error;
  type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

  fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
    self.inner.poll_ready(cx)
  }

  fn call(&mut self, dst: Uri) -> Self::Future {
    let scheme = metric_scheme(&dst);
    self
      .metrics
      .record_http_upstream_client_pool_miss(self.version, scheme, self.pool);
    let metrics = self.metrics.clone();
    let version = self.version;
    let pool = self.pool;
    let future = self.inner.call(dst);
    Box::pin(async move {
      let result = future.await;
      if result.is_ok() {
        metrics.record_http_upstream_client_connection_created(version, scheme, pool);
      }
      result
    })
  }
}

pub(super) fn build_clients(
  upstreams: &[UpstreamConfig],
  extra_root_certs: &[std::path::PathBuf],
  tls_resumption: &tls::TlsResumptionState,
  http2_config: &ProxyHttp2Config,
  outbound_revocation: &tls::OutboundRevocationRuntime,
  metrics: Arc<Metrics>,
  pool_label: &'static str,
) -> anyhow::Result<UpstreamClientPools> {
  let mut by_upstream = HashMap::new();
  let mut pools = Vec::with_capacity(upstreams.len());

  for upstream in upstreams {
    let index = pools.len();
    let pool = build_client_pool(
      upstream,
      extra_root_certs,
      tls_resumption,
      http2_config,
      outbound_revocation,
      metrics.clone(),
      pool_label,
    )
    .with_context(|| format!("failed to build clients for upstream {}", upstream.name))?;
    by_upstream.insert(upstream.name.clone(), index);
    pools.push(pool);
  }

  Ok(UpstreamClientPools { by_upstream, pools })
}

fn build_client_pool(
  upstream: &UpstreamConfig,
  extra_root_certs: &[std::path::PathBuf],
  tls_resumption: &tls::TlsResumptionState,
  http2_config: &ProxyHttp2Config,
  outbound_revocation: &tls::OutboundRevocationRuntime,
  metrics: Arc<Metrics>,
  pool_label: &'static str,
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
  let h1_tls_config = tls::build_upstream_client_config_with_resumption_and_revocation(
    extra_root_certs,
    &upstream.tls.ech,
    &upstream.tls.resumption,
    Some(tls_resumption),
    &upstream.name,
    Some((outbound_revocation, revocation_policy.clone())),
  )
  .context("failed to build HTTP/1.1 upstream TLS client")?;
  let negotiated_tls_config = tls::build_upstream_client_config_with_resumption_and_revocation(
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
  let h1_connector = InstrumentedConnector::new(h1_connector, metrics.clone(), "h1", pool_label);
  let mut h1_builder = Client::builder(TokioExecutor::new());
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
  let negotiated_connector =
    InstrumentedConnector::new(negotiated_connector, metrics.clone(), "h2", pool_label);
  let mut negotiated_builder = Client::builder(TokioExecutor::new());
  crate::h2_tuning::apply_legacy_client_defaults(&mut negotiated_builder, http2_config);
  apply_client_pool_defaults(&mut negotiated_builder, upstream);
  let negotiated = negotiated_builder.build(negotiated_connector);

  let mut h2c_builder = Client::builder(TokioExecutor::new());
  h2c_builder.http2_only(true);
  crate::h2_tuning::apply_legacy_client_defaults(&mut h2c_builder, http2_config);
  apply_client_pool_defaults(&mut h2c_builder, upstream);
  let mut h2c_http = HttpConnector::new();
  h2c_http.set_connect_timeout(Some(Duration::from_millis(upstream.connect_timeout_ms)));
  h2c_http.set_nodelay(true);
  let h2c_http = InstrumentedConnector::new(h2c_http, metrics.clone(), "h2c", pool_label);
  let h2c = h2c_builder.build(h2c_http);

  Ok(ClientPool {
    h1_only,
    negotiated,
    h2c,
    metrics,
    pool_label,
  })
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

  use hyper_util::client::legacy::connect::{Connected, Connection};
  use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

  use super::*;

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

  impl AsyncRead for FakeIo {
    fn poll_read(
      self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
      _buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
      Poll::Pending
    }
  }

  impl AsyncWrite for FakeIo {
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
    let mut connector = InstrumentedConnector::new(FakeConnector, metrics.clone(), "h1", "primary");
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
}

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use anyhow::Context;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::time::Duration;

use crate::access_log::AccessLogSinks;
use crate::cache::ResponseCache;
use crate::config::{Config, HttpVersion, UpstreamConfig};
use crate::limits::LimitState;
use crate::metrics::Metrics;
use crate::pools::PoolState;
use crate::routes::RouteTable;
use crate::tls;
use crate::waf::WafEngine;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type UpstreamBody = BoxBody<Bytes, BoxError>;
type HyperClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, UpstreamBody>;
type H2cClient = Client<HttpConnector, UpstreamBody>;

#[derive(Clone)]
struct ClientPool {
  h1_only: HyperClient,
  negotiated: HyperClient,
  h2c: H2cClient,
}

impl ClientPool {
  fn for_version(&self, origin_scheme: &str, version: HttpVersion) -> UpstreamClientRef<'_> {
    match version {
      HttpVersion::H1 => UpstreamClientRef::Hyper(&self.h1_only),
      HttpVersion::H2 if origin_scheme == "http" => UpstreamClientRef::H2c(&self.h2c),
      HttpVersion::H2 | HttpVersion::H3 => UpstreamClientRef::Hyper(&self.negotiated),
    }
  }
}

#[derive(Clone, Copy)]
pub(crate) enum UpstreamClientRef<'a> {
  Hyper(&'a HyperClient),
  H2c(&'a H2cClient),
}

impl UpstreamClientRef<'_> {
  pub(crate) async fn request(
    &self,
    request: http::Request<UpstreamBody>,
  ) -> Result<http::Response<Incoming>, hyper_util::client::legacy::Error> {
    match self {
      Self::Hyper(client) => client.request(request).await,
      Self::H2c(client) => client.request(request).await,
    }
  }
}

#[derive(Clone)]
pub struct UpstreamClientPools {
  by_upstream: HashMap<String, ClientPool>,
}

impl UpstreamClientPools {
  pub(crate) fn for_upstream_version(
    &self,
    upstream_name: &str,
    origin_scheme: &str,
    version: HttpVersion,
  ) -> Option<UpstreamClientRef<'_>> {
    self
      .by_upstream
      .get(upstream_name)
      .map(|pool| pool.for_version(origin_scheme, version))
  }
}

#[derive(Clone)]
pub struct AppHandle {
  current: Arc<RwLock<Arc<AppSnapshot>>>,
}

impl AppHandle {
  pub fn new(snapshot: AppSnapshot) -> Self {
    Self {
      current: Arc::new(RwLock::new(Arc::new(snapshot))),
    }
  }

  pub fn snapshot(&self) -> Arc<AppSnapshot> {
    self
      .current
      .read()
      .expect("app snapshot lock poisoned")
      .clone()
  }

  pub fn replace(&self, snapshot: AppSnapshot) {
    *self.current.write().expect("app snapshot lock poisoned") = Arc::new(snapshot);
  }
}

pub struct AppSnapshot {
  pub config: Config,
  pub route_table: RouteTable,
  pub upstreams: Vec<UpstreamConfig>,
  pub clients: UpstreamClientPools,
  pub limits: Arc<LimitState>,
  pub pools: Arc<PoolState>,
  pub cache: Arc<ResponseCache>,
  pub metrics: Arc<Metrics>,
  pub tls_server_config: Arc<rustls::ServerConfig>,
  pub quic_server_config: Option<h3_quinn::quinn::ServerConfig>,
  pub waf: WafEngine,
  pub access_logs: AccessLogSinks,
}

impl AppSnapshot {
  pub async fn new(config: Config) -> anyhow::Result<Self> {
    Self::new_with_previous(config, None).await
  }

  pub async fn new_with_previous(
    config: Config,
    previous: Option<&AppSnapshot>,
  ) -> anyhow::Result<Self> {
    let route_table = RouteTable::new(config.routes.clone());
    let mut upstreams = config.upstreams.clone();
    upstreams.extend(PoolState::synthetic_upstreams(&config.upstream_pools));
    let clients = build_clients(&upstreams, &config.proxy.trusted_ca_certs)
      .context("failed to build upstream HTTP clients")?;
    let limits = LimitState::new();
    let pools = PoolState::new(&config.upstream_pools);
    let cache = ResponseCache::new(&config.cache).context("failed to build response cache")?;
    let metrics = Metrics::new();
    let tls_server_config = tls::build_server_config(&config.tls, &config.listeners)
      .context("failed to build downstream TLS config")?;
    let quic_server_config = if config.listeners.http3 {
      Some(tls::build_quic_server_config(&config.tls).context("failed to build QUIC TLS config")?)
    } else {
      None
    };
    let waf = WafEngine::new_with_previous(&config, previous.map(|snapshot| &snapshot.waf))
      .context("failed to build WAF engine")?;
    let access_logs = AccessLogSinks::new(&config.database.access_log)
      .await
      .context("failed to build access log sinks")?;

    Ok(Self {
      config,
      route_table,
      upstreams,
      clients,
      limits,
      pools,
      cache,
      metrics,
      tls_server_config,
      quic_server_config,
      waf,
      access_logs,
    })
  }
}

fn build_clients(
  upstreams: &[UpstreamConfig],
  extra_root_certs: &[std::path::PathBuf],
) -> anyhow::Result<UpstreamClientPools> {
  let mut by_upstream = HashMap::new();

  for upstream in upstreams {
    let pool = build_client_pool(upstream, extra_root_certs)
      .with_context(|| format!("failed to build clients for upstream {}", upstream.name))?;
    by_upstream.insert(upstream.name.clone(), pool);
  }

  Ok(UpstreamClientPools { by_upstream })
}

fn build_client_pool(
  upstream: &UpstreamConfig,
  extra_root_certs: &[std::path::PathBuf],
) -> anyhow::Result<ClientPool> {
  let h1_tls_config = tls::build_upstream_client_config(extra_root_certs, &upstream.tls.ech)
    .context("failed to build HTTP/1.1 upstream TLS client")?;
  let negotiated_tls_config =
    tls::build_upstream_client_config(extra_root_certs, &upstream.tls.ech)
      .context("failed to build negotiated upstream TLS client")?;

  let mut h1_http = HttpConnector::new();
  h1_http.set_connect_timeout(Some(Duration::from_millis(upstream.connect_timeout_ms)));
  let h1_connector = HttpsConnectorBuilder::new()
    .with_tls_config(h1_tls_config)
    .https_or_http()
    .enable_http1()
    .wrap_connector(h1_http);
  let mut h1_builder = Client::builder(TokioExecutor::new());
  h1_builder.pool_idle_timeout(Duration::from_millis(upstream.idle_timeout_ms));
  let h1_only = h1_builder.build(h1_connector);

  let mut negotiated_http = HttpConnector::new();
  negotiated_http.set_connect_timeout(Some(Duration::from_millis(upstream.connect_timeout_ms)));
  let negotiated_connector = HttpsConnectorBuilder::new()
    .with_tls_config(negotiated_tls_config)
    .https_or_http()
    .enable_http1()
    .enable_http2()
    .wrap_connector(negotiated_http);
  let mut negotiated_builder = Client::builder(TokioExecutor::new());
  negotiated_builder.pool_idle_timeout(Duration::from_millis(upstream.idle_timeout_ms));
  let negotiated = negotiated_builder.build(negotiated_connector);

  let mut h2c_builder = Client::builder(TokioExecutor::new());
  h2c_builder.http2_only(true);
  h2c_builder.pool_idle_timeout(Duration::from_millis(upstream.idle_timeout_ms));
  let mut h2c_http = HttpConnector::new();
  h2c_http.set_connect_timeout(Some(Duration::from_millis(upstream.connect_timeout_ms)));
  let h2c = h2c_builder.build(h2c_http);

  Ok(ClientPool {
    h1_only,
    negotiated,
    h2c,
  })
}

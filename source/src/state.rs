use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use anyhow::Context;
use bytes::Bytes;
use http::HeaderValue;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::time::Duration;
use tokio::sync::watch;

use crate::access_log::{AccessLogSinks, SystemAccessLog};
use crate::cache::ResponseCache;
use crate::config::{Config, HttpVersion, UpstreamConfig};
use crate::dynamic_policy::DynamicPolicyRuntime;
use crate::lifecycle::LifecycleState;
use crate::limits::LimitState;
use crate::metrics::Metrics;
use crate::pools::PoolState;
use crate::proxy::http::buffering;
use crate::proxy::http::compression::CompressionState;
use crate::proxy::http::uri::UpstreamUriParts;
use crate::proxy::http3::UpstreamH3Pools;
use crate::routes::RouteTable;
use crate::shared_state::SharedState;
use crate::tls;
use crate::turn::TurnPoolState;
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
  fn for_version(
    &self,
    origin_scheme: &str,
    version: HttpVersion,
  ) -> Option<UpstreamClientRef<'_>> {
    match version {
      HttpVersion::H1 => Some(UpstreamClientRef::Hyper(&self.h1_only)),
      HttpVersion::H2 if origin_scheme == "http" => Some(UpstreamClientRef::H2c(&self.h2c)),
      HttpVersion::H2 => Some(UpstreamClientRef::Hyper(&self.negotiated)),
      HttpVersion::H3 => None,
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
  by_upstream: HashMap<String, usize>,
  pools: Vec<ClientPool>,
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
pub struct AppHandle {
  current: Arc<RwLock<AppGeneration>>,
}

struct AppGeneration {
  snapshot: Arc<AppSnapshot>,
  data_plane_drain: watch::Sender<bool>,
}

pub(crate) struct AppConnectionSnapshot {
  pub(crate) snapshot: Arc<AppSnapshot>,
  pub(crate) data_plane_drain: watch::Receiver<bool>,
}

impl AppHandle {
  pub fn new(snapshot: AppSnapshot) -> Self {
    let (data_plane_drain, _) = watch::channel(false);
    Self {
      current: Arc::new(RwLock::new(AppGeneration {
        snapshot: Arc::new(snapshot),
        data_plane_drain,
      })),
    }
  }

  pub fn snapshot(&self) -> Arc<AppSnapshot> {
    self
      .current
      .read()
      .expect("app snapshot lock poisoned")
      .snapshot
      .clone()
  }

  pub(crate) fn connection_snapshot(&self) -> AppConnectionSnapshot {
    let current = self.current.read().expect("app snapshot lock poisoned");
    AppConnectionSnapshot {
      snapshot: current.snapshot.clone(),
      data_plane_drain: current.data_plane_drain.subscribe(),
    }
  }

  pub fn replace(&self, snapshot: AppSnapshot) {
    let (data_plane_drain, _) = watch::channel(false);
    let previous = {
      let mut current = self.current.write().expect("app snapshot lock poisoned");
      std::mem::replace(
        &mut *current,
        AppGeneration {
          snapshot: Arc::new(snapshot),
          data_plane_drain,
        },
      )
    };
    let _ = previous.data_plane_drain.send(true);
  }
}

pub struct AppSnapshot {
  pub config: Config,
  pub route_table: RouteTable,
  pub upstreams: Vec<UpstreamConfig>,
  pub(crate) upstream_uri_parts: HashMap<String, UpstreamUriParts>,
  pub clients: UpstreamClientPools,
  pub(crate) h3_clients: UpstreamH3Pools,
  pub limits: Arc<LimitState>,
  pub pools: Arc<PoolState>,
  pub turn_pools: Arc<TurnPoolState>,
  pub cache: Arc<ResponseCache>,
  pub(crate) compression: Arc<CompressionState>,
  pub metrics: Arc<Metrics>,
  pub dynamic_policy: DynamicPolicyRuntime,
  pub lifecycle: Arc<LifecycleState>,
  pub shared_state: Option<Arc<SharedState>>,
  pub tls_server_config: Arc<rustls::ServerConfig>,
  pub admin_tls_server_config: Option<Arc<rustls::ServerConfig>>,
  pub quic_server_config: Option<h3_quinn::quinn::ServerConfig>,
  pub(crate) tls_resumption: tls::TlsResumptionState,
  pub waf: WafEngine,
  pub access_logs: AccessLogSinks,
  pub system_access_log: SystemAccessLog,
  pub(crate) alt_svc_header_value: Option<HeaderValue>,
}

impl AppSnapshot {
  pub async fn new(config: Config) -> anyhow::Result<Self> {
    Self::new_with_previous(config, None).await
  }

  pub async fn new_with_previous(
    config: Config,
    previous: Option<&AppSnapshot>,
  ) -> anyhow::Result<Self> {
    let mut upstreams = config.upstreams.clone();
    upstreams.extend(PoolState::synthetic_upstreams(&config.upstream_pools));
    let upstream_uri_parts = build_upstream_uri_parts(&upstreams)?;
    let tls_resumption = previous
      .map(|snapshot| snapshot.tls_resumption.clone())
      .unwrap_or_default();
    let clients = build_clients(&upstreams, &config.proxy.trusted_ca_certs, &tls_resumption)
      .context("failed to build upstream HTTP clients")?;
    let h3_clients = UpstreamH3Pools::new(&upstreams, &config, &tls_resumption)
      .context("failed to build upstream HTTP/3 pools")?;
    let shared_state = SharedState::new(&config)
      .await
      .context("failed to build shared state")?;
    if previous.is_none()
      && let Some(temp_dir) = config.proxy.buffering.temp_dir.as_deref()
    {
      buffering::cleanup_stale_temp_files(temp_dir);
    }
    let limits = LimitState::new(shared_state.clone());
    let pools = PoolState::new(&config.upstream_pools, shared_state.clone());
    let turn_pools = TurnPoolState::new(&config.turn_upstream_pools);
    let cache = ResponseCache::new(&config.cache, shared_state.clone())
      .context("failed to build response cache")?;
    let metrics = previous
      .map(|snapshot| snapshot.metrics.clone())
      .unwrap_or_default();
    let compression = CompressionState::new(&config.compression);
    let dynamic_policy = DynamicPolicyRuntime::new(&config, metrics.clone())
      .await
      .context("failed to build dynamic policy runtime")?;
    let lifecycle = previous
      .map(|snapshot| snapshot.lifecycle.clone())
      .unwrap_or_default();
    let tls_server_config = tls::build_server_config_with_resumption(
      &config.tls,
      &config.listeners,
      Some(&tls_resumption),
    )
    .context("failed to build downstream TLS config")?;
    let admin_tls_server_config = if config.admin.enabled && config.admin.tls.enabled {
      Some(
        tls::build_admin_server_config_with_resumption(&config.admin.tls, Some(&tls_resumption))
          .context("failed to build admin TLS config")?,
      )
    } else {
      None
    };
    let quic_server_config = if config.listeners.http3 {
      Some(
        tls::build_quic_server_config_with_resumption(
          &config.tls,
          &config.quic,
          config.source_paths.cert_dir.as_deref(),
          Some(&tls_resumption),
        )
        .context("failed to build QUIC TLS config")?,
      )
    } else {
      None
    };
    let waf = WafEngine::new_with_previous_and_limits(
      &config,
      previous.map(|snapshot| &snapshot.waf),
      shared_state.clone(),
      Some(limits.clone()),
    )
    .context("failed to build WAF engine")?;
    let route_table = RouteTable::new_with_waf(&config, &waf);
    let access_logs = AccessLogSinks::new(&config.database.access_log)
      .await
      .context("failed to build access log sinks")?;
    let system_access_log = SystemAccessLog::new(&config.logging.access_log)
      .await
      .context("failed to build system access log")?;
    let alt_svc_header_value = build_alt_svc_header_value(&config)
      .context("failed to build precomputed Alt-Svc header value")?;

    Ok(Self {
      config,
      route_table,
      upstreams,
      upstream_uri_parts,
      clients,
      h3_clients,
      limits,
      pools,
      turn_pools,
      cache,
      compression,
      metrics,
      dynamic_policy,
      lifecycle,
      shared_state,
      tls_server_config,
      admin_tls_server_config,
      quic_server_config,
      tls_resumption,
      waf,
      access_logs,
      system_access_log,
      alt_svc_header_value,
    })
  }

  pub async fn new_with_updated_upstream_pools(
    config: Config,
    previous: &AppSnapshot,
  ) -> anyhow::Result<Self> {
    let mut upstreams = config.upstreams.clone();
    upstreams.extend(PoolState::synthetic_upstreams(&config.upstream_pools));
    let route_table = RouteTable::new_with_waf(&config, &previous.waf);
    let upstream_uri_parts = build_upstream_uri_parts(&upstreams)?;
    let clients = build_clients(
      &upstreams,
      &config.proxy.trusted_ca_certs,
      &previous.tls_resumption,
    )
    .context("failed to build upstream HTTP clients")?;
    let h3_clients = UpstreamH3Pools::new(&upstreams, &config, &previous.tls_resumption)
      .context("failed to build upstream HTTP/3 pools")?;
    let pools = PoolState::new(&config.upstream_pools, previous.shared_state.clone());
    let turn_pools = TurnPoolState::new(&config.turn_upstream_pools);
    let alt_svc_header_value = build_alt_svc_header_value(&config)
      .context("failed to build precomputed Alt-Svc header value")?;

    Ok(Self {
      config,
      route_table,
      upstreams,
      upstream_uri_parts,
      clients,
      h3_clients,
      limits: previous.limits.clone(),
      pools,
      turn_pools,
      cache: previous.cache.clone(),
      compression: previous.compression.clone(),
      metrics: previous.metrics.clone(),
      dynamic_policy: previous.dynamic_policy.clone(),
      lifecycle: previous.lifecycle.clone(),
      shared_state: previous.shared_state.clone(),
      tls_server_config: previous.tls_server_config.clone(),
      admin_tls_server_config: previous.admin_tls_server_config.clone(),
      quic_server_config: previous.quic_server_config.clone(),
      tls_resumption: previous.tls_resumption.clone(),
      waf: previous.waf.clone(),
      access_logs: previous.access_logs.clone(),
      system_access_log: previous.system_access_log.clone(),
      alt_svc_header_value,
    })
  }
}

fn build_upstream_uri_parts(
  upstreams: &[UpstreamConfig],
) -> anyhow::Result<HashMap<String, UpstreamUriParts>> {
  upstreams
    .iter()
    .map(|upstream| {
      Ok((
        upstream.name.clone(),
        UpstreamUriParts::from_url(&upstream.origin)
          .with_context(|| format!("failed to precompute URI parts for {}", upstream.name))?,
      ))
    })
    .collect()
}

fn build_alt_svc_header_value(config: &Config) -> anyhow::Result<Option<HeaderValue>> {
  if !config.listeners.http3 || !config.quic.alt_svc.enabled {
    return Ok(None);
  }

  let mut value = format!(
    "h3=\":{}\"; ma={}",
    config.listeners.https_bind.port(),
    config.quic.alt_svc.max_age_seconds
  );
  if config.quic.alt_svc.persist {
    value.push_str("; persist=1");
  }
  HeaderValue::from_str(&value)
    .map(Some)
    .context("invalid Alt-Svc header value")
}

fn build_clients(
  upstreams: &[UpstreamConfig],
  extra_root_certs: &[std::path::PathBuf],
  tls_resumption: &tls::TlsResumptionState,
) -> anyhow::Result<UpstreamClientPools> {
  let mut by_upstream = HashMap::new();
  let mut pools = Vec::with_capacity(upstreams.len());

  for upstream in upstreams {
    let index = pools.len();
    let pool = build_client_pool(upstream, extra_root_certs, tls_resumption)
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
) -> anyhow::Result<ClientPool> {
  let h1_tls_config = tls::build_upstream_client_config_with_resumption(
    extra_root_certs,
    &upstream.tls.ech,
    &upstream.tls.resumption,
    Some(tls_resumption),
    &upstream.name,
  )
  .context("failed to build HTTP/1.1 upstream TLS client")?;
  let negotiated_tls_config = tls::build_upstream_client_config_with_resumption(
    extra_root_certs,
    &upstream.tls.ech,
    &upstream.tls.resumption,
    Some(tls_resumption),
    &upstream.name,
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
  let mut h1_builder = Client::builder(TokioExecutor::new());
  h1_builder.pool_idle_timeout(Duration::from_millis(upstream.idle_timeout_ms));
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
  let mut negotiated_builder = Client::builder(TokioExecutor::new());
  crate::h2_tuning::apply_legacy_client_defaults(&mut negotiated_builder);
  negotiated_builder.pool_idle_timeout(Duration::from_millis(upstream.idle_timeout_ms));
  let negotiated = negotiated_builder.build(negotiated_connector);

  let mut h2c_builder = Client::builder(TokioExecutor::new());
  h2c_builder.http2_only(true);
  crate::h2_tuning::apply_legacy_client_defaults(&mut h2c_builder);
  h2c_builder.pool_idle_timeout(Duration::from_millis(upstream.idle_timeout_ms));
  let mut h2c_http = HttpConnector::new();
  h2c_http.set_connect_timeout(Some(Duration::from_millis(upstream.connect_timeout_ms)));
  h2c_http.set_nodelay(true);
  let h2c = h2c_builder.build(h2c_http);

  Ok(ClientPool {
    h1_only,
    negotiated,
    h2c,
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  fn parse_config(raw: &str) -> Config {
    let config: Config = toml::from_str(raw).expect("config should parse");
    config.validate().expect("config should validate");
    config
  }

  #[tokio::test]
  async fn replace_signals_old_data_plane_generation_and_installs_fresh_one() {
    let temp_dir = common::TempDir::new("app-generation-drain");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "app-generation-drain");
    let initial = common::minimal_config_toml(&cert_path, &key_path);
    let reloaded = initial.replace(
      "[compression]\nenabled = true",
      "[compression]\nenabled = false",
    );
    let handle = AppHandle::new(
      AppSnapshot::new(parse_config(&initial))
        .await
        .expect("initial snapshot should initialize"),
    );
    let old_connection = handle.connection_snapshot();
    assert!(old_connection.snapshot.config.compression.enabled);
    assert!(!*old_connection.data_plane_drain.borrow());

    handle.replace(
      AppSnapshot::new(parse_config(&reloaded))
        .await
        .expect("replacement snapshot should initialize"),
    );

    assert!(*old_connection.data_plane_drain.borrow());
    let new_connection = handle.connection_snapshot();
    assert!(!new_connection.snapshot.config.compression.enabled);
    assert!(!*new_connection.data_plane_drain.borrow());
  }
}

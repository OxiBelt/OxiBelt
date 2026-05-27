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
use hyper_util::rt::{TokioExecutor, TokioTimer};
use std::time::Duration;
use tokio::sync::watch;

use crate::access_log::{AccessLogSinks, SystemAccessLog};
use crate::admin_audit::AdminAuditRuntime;
use crate::cache::ResponseCache;
use crate::config::{Config, HttpVersion, ProxyHttp2Config, UpstreamConfig};
use crate::control_http::ControlHttpClient;
use crate::dynamic_policy::DynamicPolicyRuntime;
use crate::external_auth::ExternalAuthRuntime;
use crate::ipm::IpmRuntime;
use crate::lifecycle::LifecycleState;
use crate::limits::LimitState;
use crate::metrics::Metrics;
use crate::mitigation::MitigationSink;
use crate::pools::PoolState;
use crate::proxy::http::buffering;
use crate::proxy::http::compression::CompressionState;
use crate::proxy::http::static_files::StaticFilesRuntime;
use crate::proxy::http::uri::UpstreamUriParts;
use crate::proxy::http3::UpstreamH3Pools;
use crate::routes::RouteTable;
use crate::runtime_introspection::RuntimeIntrospectionState;
use crate::shared_state::SharedState;
use crate::sni_forward::SniForwardTable;
use crate::telemetry::TelemetryRuntime;
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

#[derive(Clone)]
pub struct AppSnapshot {
  pub config: Config,
  pub route_table: RouteTable,
  pub(crate) sni_forward: SniForwardTable,
  pub upstreams: Vec<UpstreamConfig>,
  pub(crate) upstream_uri_parts: HashMap<String, UpstreamUriParts>,
  pub clients: UpstreamClientPools,
  pub(crate) control_http: ControlHttpClient,
  pub(crate) h3_clients: UpstreamH3Pools,
  pub limits: Arc<LimitState>,
  pub pools: Arc<PoolState>,
  pub turn_pools: Arc<TurnPoolState>,
  pub cache: Arc<ResponseCache>,
  pub(crate) compression: Arc<CompressionState>,
  pub(crate) static_files: Arc<StaticFilesRuntime>,
  pub metrics: Arc<Metrics>,
  pub telemetry: TelemetryRuntime,
  pub ipm: IpmRuntime,
  pub dynamic_policy: DynamicPolicyRuntime,
  pub external_auth: ExternalAuthRuntime,
  pub runtime_introspection: Arc<RuntimeIntrospectionState>,
  pub lifecycle: Arc<LifecycleState>,
  pub admin_audit: AdminAuditRuntime,
  pub shared_state: Option<Arc<SharedState>>,
  pub tls_server_config: Arc<rustls::ServerConfig>,
  pub admin_tls_server_config: Option<Arc<rustls::ServerConfig>>,
  pub quic_server_config: Option<h3_quinn::quinn::ServerConfig>,
  pub(crate) tls_resumption: tls::TlsResumptionState,
  pub waf: WafEngine,
  pub mitigation: MitigationSink,
  pub access_logs: AccessLogSinks,
  pub system_access_log: SystemAccessLog,
  pub(crate) alt_svc_header_value: Option<HeaderValue>,
}

impl AppSnapshot {
  pub async fn new(config: Config) -> anyhow::Result<Self> {
    Self::new_with_previous(config, None).await
  }

  pub async fn new_with_telemetry(
    config: Config,
    telemetry: TelemetryRuntime,
  ) -> anyhow::Result<Self> {
    Self::new_with_previous_and_telemetry(config, None, Some(telemetry)).await
  }

  pub async fn new_with_previous(
    config: Config,
    previous: Option<&AppSnapshot>,
  ) -> anyhow::Result<Self> {
    Self::new_with_previous_and_telemetry(config, previous, None).await
  }

  async fn new_with_previous_and_telemetry(
    config: Config,
    previous: Option<&AppSnapshot>,
    initial_telemetry: Option<TelemetryRuntime>,
  ) -> anyhow::Result<Self> {
    let mut upstreams = config.upstreams.clone();
    upstreams.extend(PoolState::synthetic_upstreams(&config.upstream_pools));
    let upstream_uri_parts = build_upstream_uri_parts(&upstreams)?;
    let tls_resumption = previous
      .map(|snapshot| snapshot.tls_resumption.clone())
      .unwrap_or_default();
    let clients = build_clients(
      &upstreams,
      &config.proxy.trusted_ca_certs,
      &tls_resumption,
      &config.proxy.http2,
    )
    .context("failed to build upstream HTTP clients")?;
    let h3_clients = UpstreamH3Pools::new(&upstreams, &config, &tls_resumption)
      .context("failed to build upstream HTTP/3 pools")?;
    let control_http = ControlHttpClient::new(&config.proxy.trusted_ca_certs)
      .context("failed to build control-plane HTTP client")?;
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
    let telemetry = match previous {
      Some(_) => TelemetryRuntime::new(&config.telemetry.tracing)
        .context("failed to build telemetry runtime")?,
      None => match initial_telemetry {
        Some(telemetry) => telemetry,
        None => TelemetryRuntime::new(&config.telemetry.tracing)
          .context("failed to build telemetry runtime")?,
      },
    };
    let compression = CompressionState::new(&config.compression);
    let static_files =
      StaticFilesRuntime::new(&config).context("failed to build static files runtime")?;
    let ipm = IpmRuntime::new(&config)
      .await
      .context("failed to build IPM runtime")?;
    let dynamic_policy = DynamicPolicyRuntime::new(&config, metrics.clone())
      .await
      .context("failed to build dynamic policy runtime")?;
    let external_auth = ExternalAuthRuntime::new(&config, control_http.clone(), metrics.clone())
      .context("failed to build external auth runtime")?;
    let runtime_introspection = previous
      .map(|snapshot| snapshot.runtime_introspection.clone())
      .unwrap_or_default();
    let mitigation = MitigationSink::new(&config, metrics.clone())
      .await
      .context("failed to build mitigation sink")?;
    let lifecycle = previous
      .map(|snapshot| snapshot.lifecycle.clone())
      .unwrap_or_default();
    let admin_audit = AdminAuditRuntime::new(&config)
      .await
      .context("failed to build admin audit runtime")?;
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
    let waf = WafEngine::new_with_previous_limits_and_mitigation(
      &config,
      previous.map(|snapshot| &snapshot.waf),
      shared_state.clone(),
      Some(limits.clone()),
      mitigation.clone(),
    )
    .context("failed to build WAF engine")?;
    let route_table = RouteTable::new_with_waf(&config, &waf);
    let sni_forward =
      SniForwardTable::new(&config).context("failed to build SNI forwarding table")?;
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
      sni_forward,
      upstreams,
      upstream_uri_parts,
      clients,
      control_http,
      h3_clients,
      limits,
      pools,
      turn_pools,
      cache,
      compression,
      static_files: Arc::new(static_files),
      metrics,
      telemetry,
      ipm,
      dynamic_policy,
      external_auth,
      runtime_introspection,
      lifecycle,
      admin_audit,
      shared_state,
      tls_server_config,
      admin_tls_server_config,
      quic_server_config,
      tls_resumption,
      waf,
      mitigation,
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
    let sni_forward =
      SniForwardTable::new(&config).context("failed to build SNI forwarding table")?;
    let upstream_uri_parts = build_upstream_uri_parts(&upstreams)?;
    let clients = build_clients(
      &upstreams,
      &config.proxy.trusted_ca_certs,
      &previous.tls_resumption,
      &config.proxy.http2,
    )
    .context("failed to build upstream HTTP clients")?;
    let h3_clients = UpstreamH3Pools::new(&upstreams, &config, &previous.tls_resumption)
      .context("failed to build upstream HTTP/3 pools")?;
    let control_http = ControlHttpClient::new(&config.proxy.trusted_ca_certs)
      .context("failed to build control-plane HTTP client")?;
    let pools = PoolState::new(&config.upstream_pools, previous.shared_state.clone());
    let turn_pools = TurnPoolState::new(&config.turn_upstream_pools);
    let alt_svc_header_value = build_alt_svc_header_value(&config)
      .context("failed to build precomputed Alt-Svc header value")?;
    let static_files =
      StaticFilesRuntime::new(&config).context("failed to build static files runtime")?;
    let external_auth =
      ExternalAuthRuntime::new(&config, control_http.clone(), previous.metrics.clone())
        .context("failed to build external auth runtime")?;
    let ipm = IpmRuntime::new(&config)
      .await
      .context("failed to build IPM runtime")?;

    Ok(Self {
      config,
      route_table,
      sni_forward,
      upstreams,
      upstream_uri_parts,
      clients,
      control_http: control_http.clone(),
      h3_clients,
      limits: previous.limits.clone(),
      pools,
      turn_pools,
      cache: previous.cache.clone(),
      compression: previous.compression.clone(),
      static_files: Arc::new(static_files),
      metrics: previous.metrics.clone(),
      telemetry: previous.telemetry.clone(),
      ipm,
      dynamic_policy: previous.dynamic_policy.clone(),
      external_auth,
      runtime_introspection: previous.runtime_introspection.clone(),
      lifecycle: previous.lifecycle.clone(),
      admin_audit: previous.admin_audit.clone(),
      shared_state: previous.shared_state.clone(),
      tls_server_config: previous.tls_server_config.clone(),
      admin_tls_server_config: previous.admin_tls_server_config.clone(),
      quic_server_config: previous.quic_server_config.clone(),
      tls_resumption: previous.tls_resumption.clone(),
      waf: previous.waf.clone(),
      mitigation: previous.mitigation.clone(),
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
  http2_config: &ProxyHttp2Config,
) -> anyhow::Result<UpstreamClientPools> {
  let mut by_upstream = HashMap::new();
  let mut pools = Vec::with_capacity(upstreams.len());

  for upstream in upstreams {
    let index = pools.len();
    let pool = build_client_pool(upstream, extra_root_certs, tls_resumption, http2_config)
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
  let h2c = h2c_builder.build(h2c_http);

  Ok(ClientPool {
    h1_only,
    negotiated,
    h2c,
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

  #[tokio::test]
  async fn full_reload_rebuilds_telemetry_runtime_from_new_config() {
    let temp_dir = common::TempDir::new("telemetry-full-reload");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "telemetry-full-reload");
    let base_raw = common::minimal_config_toml(&cert_path, &key_path);
    let initial_raw = base_raw.clone()
      + r#"

[telemetry.tracing]
enabled = true
endpoint = "http://127.0.0.1:4318/v1/traces"
service_name = "oxibelt-test"
sample_ratio = 1.0
export_timeout_ms = 1
propagate_trace_context = true
"#;
    let disabled_raw = base_raw
      + r#"

[telemetry.tracing]
enabled = false
endpoint = "http://127.0.0.1:4319/v1/traces"
service_name = "oxibelt-test-disabled"
sample_ratio = 0.0
export_timeout_ms = 1
propagate_trace_context = false
"#;

    let initial = AppSnapshot::new(parse_config(&initial_raw))
      .await
      .expect("initial telemetry snapshot should initialize");
    let initial_context = initial
      .telemetry
      .context_from_headers(&http::HeaderMap::new());
    let mut initial_headers = http::HeaderMap::new();
    initial
      .telemetry
      .inject_trace_context(&mut initial_headers, initial_context);
    assert!(initial.telemetry.enabled());
    assert!(initial_headers.contains_key("traceparent"));

    let reloaded = AppSnapshot::new_with_previous(parse_config(&disabled_raw), Some(&initial))
      .await
      .expect("reloaded telemetry snapshot should initialize");
    let mut reloaded_headers = http::HeaderMap::new();
    reloaded
      .telemetry
      .inject_trace_context(&mut reloaded_headers, initial_context);

    assert!(!reloaded.config.telemetry.tracing.enabled);
    assert!(!reloaded.telemetry.enabled());
    assert!(
      reloaded
        .telemetry
        .context_from_headers(&http::HeaderMap::new())
        .is_none()
    );
    assert!(!reloaded_headers.contains_key("traceparent"));
    assert!(initial.telemetry.enabled());
  }
}

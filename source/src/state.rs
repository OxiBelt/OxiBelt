//! Immutable runtime snapshots and shared client pools used by request handlers.
//! Reloads swap snapshots so in-flight work can finish against a consistent view.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;
use http::HeaderValue;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;

use crate::access_log::{AccessLogSinks, SystemAccessLog};
use crate::admin_audit::AdminAuditRuntime;
use crate::cache::ResponseCache;
use crate::client_identity::ClientIdentityRuntime;
use crate::config::{Config, HttpVersion, UpstreamConfig};
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
use crate::proxy::http::waf_body_coding::WafBodyCodingState;
use crate::proxy::http3::UpstreamH3Pools;
use crate::routes::RouteTable;
use crate::runtime_introspection::RuntimeIntrospectionState;
use crate::shared_state::SharedState;
use crate::sni_forward::SniForwardTable;
use crate::stream::pools::StreamPoolState;
use crate::telemetry::TelemetryRuntime;
use crate::tls;
use crate::turn::TurnPoolState;
use crate::waf::WafEngine;
use crate::webtransport_admin::WebTransportAdminRegistry;

pub(crate) mod handle;
mod http1_upgrade;
mod request_path_features;
mod stream_pool_update;
mod upstream_clients;

pub use handle::AppHandle;
pub(crate) use request_path_features::RequestPathFeaturePlan;
use upstream_clients::build_clients;

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

/// Per-upstream HTTP client pools keyed by validated upstream configuration.
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

/// Immutable snapshot of runtime configuration and derived state.
#[derive(Clone)]
pub struct AppSnapshot {
  pub config: Config,
  pub route_table: RouteTable,
  pub(crate) sni_forward: SniForwardTable,
  pub upstreams: Vec<UpstreamConfig>,
  pub(crate) upstream_uri_parts: HashMap<String, UpstreamUriParts>,
  pub(crate) upstream_uri_parts_by_index: Vec<UpstreamUriParts>,
  pub clients: UpstreamClientPools,
  pub health_check_clients: UpstreamClientPools,
  pub(crate) control_http: ControlHttpClient,
  pub(crate) h3_clients: UpstreamH3Pools,
  pub(crate) outbound_revocation: tls::OutboundRevocationRuntime,
  pub upstream_pool_generation: u64,
  pub stream_pool_generation: u64,
  pub limits: Arc<LimitState>,
  pub pools: Arc<PoolState>,
  pub stream_pools: Arc<StreamPoolState>,
  pub turn_pools: Arc<TurnPoolState>,
  pub cache: Arc<ResponseCache>,
  pub(crate) compression: Arc<CompressionState>,
  pub(crate) waf_body_coding: Arc<WafBodyCodingState>,
  pub(crate) static_files: Arc<StaticFilesRuntime>,
  pub metrics: Arc<Metrics>,
  pub telemetry: TelemetryRuntime,
  pub ipm: IpmRuntime,
  pub dynamic_policy: DynamicPolicyRuntime,
  pub external_auth: ExternalAuthRuntime,
  pub client_identity: ClientIdentityRuntime,
  pub runtime_introspection: Arc<RuntimeIntrospectionState>,
  pub webtransport_admin: Arc<WebTransportAdminRegistry>,
  pub lifecycle: Arc<LifecycleState>,
  pub admin_audit: AdminAuditRuntime,
  pub shared_state: Option<Arc<SharedState>>,
  pub(crate) crlite: tls::CrliteRuntime,
  pub(crate) ocsp_staple: tls::OcspStapleRuntime,
  pub tls_server_config: Arc<rustls::ServerConfig>,
  pub admin_tls_server_config: Option<Arc<rustls::ServerConfig>>,
  pub quic_server_config: Option<h3_quinn::quinn::ServerConfig>,
  pub admin_quic_server_config: Option<h3_quinn::quinn::ServerConfig>,
  pub(crate) tls_resumption: tls::TlsResumptionState,
  pub waf: WafEngine,
  pub mitigation: MitigationSink,
  pub access_logs: AccessLogSinks,
  pub system_access_log: SystemAccessLog,
  pub(crate) request_path_features: RequestPathFeaturePlan,
  pub(crate) alt_svc_header_value: Option<HeaderValue>,
  pub(crate) http1_upgrades_possible: bool,
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
    let (upstream_uri_parts, upstream_uri_parts_by_index) = build_upstream_uri_parts(&upstreams)?;
    let tls_resumption = previous
      .map(|snapshot| snapshot.tls_resumption.clone())
      .unwrap_or_default();
    let metrics = previous
      .map(|snapshot| snapshot.metrics.clone())
      .unwrap_or_default();
    let outbound_revocation = tls::OutboundRevocationRuntime::new(&config, metrics.clone())
      .await
      .context("failed to build outbound TLS revocation runtime")?;
    let clients = build_clients(
      &upstreams,
      &config.proxy.trusted_ca_certs,
      &tls_resumption,
      &config.proxy.http2,
      &outbound_revocation,
    )
    .context("failed to build upstream HTTP clients")?;
    let health_check_upstreams = PoolState::health_check_upstreams(&config.upstream_pools);
    let health_check_clients = build_clients(
      &health_check_upstreams,
      &config.proxy.trusted_ca_certs,
      &tls_resumption,
      &config.proxy.http2,
      &outbound_revocation,
    )
    .context("failed to build upstream health-check HTTP clients")?;
    let h3_clients =
      UpstreamH3Pools::new(&upstreams, &config, &tls_resumption, &outbound_revocation)
        .context("failed to build upstream HTTP/3 pools")?;
    let control_http = ControlHttpClient::new_with_revocation(
      &config.proxy.trusted_ca_certs,
      &outbound_revocation,
      outbound_revocation.default_policy(),
    )
    .context("failed to build control-plane HTTP client")?;
    let bootstrap_control_http = ControlHttpClient::new(&config.proxy.trusted_ca_certs)
      .context("failed to build revocation bootstrap HTTP client")?;
    let shared_state = SharedState::new(&config)
      .await
      .context("failed to build shared state")?;
    if previous.is_none()
      && let Some(temp_dir) = config.proxy.buffering.temp_dir.as_deref()
    {
      buffering::cleanup_stale_temp_files(temp_dir);
    }
    let limits = LimitState::new(shared_state.clone());
    let pools = PoolState::new_with_previous_and_metrics(
      &config.upstream_pools,
      shared_state.clone(),
      previous.map(|snapshot| snapshot.pools.as_ref()),
      Some(metrics.clone()),
    );
    publish_upstream_pool_server_metrics(&pools);
    let stream_pools = StreamPoolState::new(&config.stream_upstream_pools);
    let turn_pools = TurnPoolState::new(&config.turn_upstream_pools);
    let cache = ResponseCache::new(&config.cache, shared_state.clone())
      .context("failed to build response cache")?;
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
    let waf_body_coding = WafBodyCodingState::new(&config.waf.http_body_compression);
    let static_files =
      StaticFilesRuntime::new(&config).context("failed to build static files runtime")?;
    let ipm = IpmRuntime::new(&config)
      .await
      .context("failed to build IPM runtime")?;
    let dynamic_policy = DynamicPolicyRuntime::new(&config, metrics.clone())
      .await
      .context("failed to build dynamic policy runtime")?;
    let client_identity = ClientIdentityRuntime::new(&config, &control_http)
      .await
      .context("failed to build client identity runtime")?;
    let external_auth = ExternalAuthRuntime::new(&config, control_http.clone(), metrics.clone())
      .context("failed to build external auth runtime")?;
    let runtime_introspection = previous
      .map(|snapshot| snapshot.runtime_introspection.clone())
      .unwrap_or_default();
    let webtransport_admin = previous
      .map(|snapshot| snapshot.webtransport_admin.clone())
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
    let crlite = tls::CrliteRuntime::new(&config.tls, metrics.clone())
      .await
      .context("failed to build CRLite runtime")?;
    let ocsp_staple =
      tls::OcspStapleRuntime::new(&config.tls, &bootstrap_control_http, metrics.clone())
        .await
        .context("failed to build OCSP staple runtime")?;
    let tls_server_config = tls::build_server_config_with_resumption_and_ocsp(
      &config.tls,
      &config.listeners,
      Some(&tls_resumption),
      Some(&ocsp_staple),
      Some(&crlite),
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
        tls::build_quic_server_config_with_resumption_and_ocsp(
          &config.tls,
          &config.quic,
          config.source_paths.cert_dir.as_deref(),
          Some(&tls_resumption),
          Some(&ocsp_staple),
          Some(&crlite),
        )
        .context("failed to build QUIC TLS config")?,
      )
    } else {
      None
    };
    let admin_quic_server_config = if config.admin.enabled && config.admin.http3.enabled {
      Some(
        tls::build_admin_quic_server_config_with_resumption(
          &config.admin.tls,
          &config.quic,
          config.source_paths.cert_dir.as_deref(),
          Some(&tls_resumption),
        )
        .context("failed to build admin QUIC TLS config")?,
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
    let request_path_features = RequestPathFeaturePlan::new(
      &config,
      cache.enabled(),
      dynamic_policy.enabled(),
      telemetry.enabled(),
      system_access_log.enabled(),
      waf.has_person_proof_api_paths(),
    );
    let alt_svc_header_value = build_alt_svc_header_value(&config)
      .context("failed to build precomputed Alt-Svc header value")?;
    let http1_upgrades_possible = http1_upgrade::http1_upgrades_possible(&config, &upstreams);
    let upstream_pool_generation = next_upstream_pool_generation(&config, previous);
    let stream_pool_generation = next_stream_pool_generation(&config, previous);

    Ok(Self {
      config,
      route_table,
      sni_forward,
      upstreams,
      upstream_uri_parts,
      upstream_uri_parts_by_index,
      clients,
      health_check_clients,
      control_http,
      h3_clients,
      outbound_revocation,
      upstream_pool_generation,
      stream_pool_generation,
      limits,
      pools,
      stream_pools,
      turn_pools,
      cache,
      compression,
      waf_body_coding,
      static_files: Arc::new(static_files),
      metrics,
      telemetry,
      ipm,
      dynamic_policy,
      external_auth,
      client_identity,
      runtime_introspection,
      webtransport_admin,
      lifecycle,
      admin_audit,
      shared_state,
      crlite,
      ocsp_staple,
      tls_server_config,
      admin_tls_server_config,
      quic_server_config,
      admin_quic_server_config,
      tls_resumption,
      waf,
      mitigation,
      access_logs,
      system_access_log,
      request_path_features,
      alt_svc_header_value,
      http1_upgrades_possible,
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
    let (upstream_uri_parts, upstream_uri_parts_by_index) = build_upstream_uri_parts(&upstreams)?;
    let clients = build_clients(
      &upstreams,
      &config.proxy.trusted_ca_certs,
      &previous.tls_resumption,
      &config.proxy.http2,
      &previous.outbound_revocation,
    )
    .context("failed to build upstream HTTP clients")?;
    let health_check_upstreams = PoolState::health_check_upstreams(&config.upstream_pools);
    let health_check_clients = build_clients(
      &health_check_upstreams,
      &config.proxy.trusted_ca_certs,
      &previous.tls_resumption,
      &config.proxy.http2,
      &previous.outbound_revocation,
    )
    .context("failed to build upstream health-check HTTP clients")?;
    let h3_clients = UpstreamH3Pools::new(
      &upstreams,
      &config,
      &previous.tls_resumption,
      &previous.outbound_revocation,
    )
    .context("failed to build upstream HTTP/3 pools")?;
    let control_http = ControlHttpClient::new_with_revocation(
      &config.proxy.trusted_ca_certs,
      &previous.outbound_revocation,
      previous.outbound_revocation.default_policy(),
    )
    .context("failed to build control-plane HTTP client")?;
    let metrics = previous.metrics.clone();
    let pools = PoolState::new_with_previous_and_metrics(
      &config.upstream_pools,
      previous.shared_state.clone(),
      Some(previous.pools.as_ref()),
      Some(metrics.clone()),
    );
    publish_upstream_pool_server_metrics(&pools);
    let stream_pools = StreamPoolState::new(&config.stream_upstream_pools);
    let turn_pools = TurnPoolState::new(&config.turn_upstream_pools);
    let alt_svc_header_value = build_alt_svc_header_value(&config)
      .context("failed to build precomputed Alt-Svc header value")?;
    let static_files =
      StaticFilesRuntime::new(&config).context("failed to build static files runtime")?;
    let waf_body_coding = WafBodyCodingState::new(&config.waf.http_body_compression);
    let client_identity = ClientIdentityRuntime::new(&config, &control_http)
      .await
      .context("failed to build client identity runtime")?;
    let external_auth = ExternalAuthRuntime::new(&config, control_http.clone(), metrics.clone())
      .context("failed to build external auth runtime")?;
    let ipm = IpmRuntime::new(&config)
      .await
      .context("failed to build IPM runtime")?;
    let upstream_pool_generation = next_upstream_pool_generation(&config, Some(previous));
    let stream_pool_generation = next_stream_pool_generation(&config, Some(previous));
    let http1_upgrades_possible = http1_upgrade::http1_upgrades_possible(&config, &upstreams);
    let request_path_features = RequestPathFeaturePlan::new(
      &config,
      previous.cache.enabled(),
      previous.dynamic_policy.enabled(),
      previous.telemetry.enabled(),
      previous.system_access_log.enabled(),
      previous.waf.has_person_proof_api_paths(),
    );

    Ok(Self {
      config,
      route_table,
      sni_forward,
      upstreams,
      upstream_uri_parts,
      upstream_uri_parts_by_index,
      clients,
      health_check_clients,
      control_http: control_http.clone(),
      h3_clients,
      outbound_revocation: previous.outbound_revocation.clone(),
      upstream_pool_generation,
      stream_pool_generation,
      limits: previous.limits.clone(),
      pools,
      stream_pools,
      turn_pools,
      cache: previous.cache.clone(),
      compression: previous.compression.clone(),
      waf_body_coding,
      static_files: Arc::new(static_files),
      metrics,
      telemetry: previous.telemetry.clone(),
      ipm,
      dynamic_policy: previous.dynamic_policy.clone(),
      external_auth,
      client_identity,
      runtime_introspection: previous.runtime_introspection.clone(),
      webtransport_admin: previous.webtransport_admin.clone(),
      lifecycle: previous.lifecycle.clone(),
      admin_audit: previous.admin_audit.clone(),
      shared_state: previous.shared_state.clone(),
      crlite: previous.crlite.clone(),
      ocsp_staple: previous.ocsp_staple.clone(),
      tls_server_config: previous.tls_server_config.clone(),
      admin_tls_server_config: previous.admin_tls_server_config.clone(),
      quic_server_config: previous.quic_server_config.clone(),
      admin_quic_server_config: previous.admin_quic_server_config.clone(),
      tls_resumption: previous.tls_resumption.clone(),
      waf: previous.waf.clone(),
      mitigation: previous.mitigation.clone(),
      access_logs: previous.access_logs.clone(),
      system_access_log: previous.system_access_log.clone(),
      request_path_features,
      alt_svc_header_value,
      http1_upgrades_possible,
    })
  }
}

fn next_upstream_pool_generation(config: &Config, previous: Option<&AppSnapshot>) -> u64 {
  let Some(previous) = previous else {
    return 0;
  };
  if config.upstream_pools == previous.config.upstream_pools {
    previous.upstream_pool_generation
  } else {
    previous.upstream_pool_generation.saturating_add(1)
  }
}

fn next_stream_pool_generation(config: &Config, previous: Option<&AppSnapshot>) -> u64 {
  let Some(previous) = previous else {
    return 0;
  };
  if config.stream_upstream_pools == previous.config.stream_upstream_pools {
    previous.stream_pool_generation
  } else {
    previous.stream_pool_generation.saturating_add(1)
  }
}

fn publish_upstream_pool_server_metrics(pools: &Arc<PoolState>) {
  pools.publish_server_count_metrics();
}

fn build_upstream_uri_parts(
  upstreams: &[UpstreamConfig],
) -> anyhow::Result<(HashMap<String, UpstreamUriParts>, Vec<UpstreamUriParts>)> {
  let mut by_name = HashMap::with_capacity(upstreams.len());
  let mut by_index = Vec::with_capacity(upstreams.len());
  for upstream in upstreams {
    let parts = UpstreamUriParts::from_url(&upstream.origin)
      .with_context(|| format!("failed to precompute URI parts for {}", upstream.name))?;
    by_name.insert(upstream.name.clone(), parts.clone());
    by_index.push(parts);
  }
  Ok((by_name, by_index))
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

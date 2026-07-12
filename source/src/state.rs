//! Immutable runtime snapshots and shared client pools; reloads swap snapshots so in-flight work can finish against a consistent view.
use crate::access_log::{AccessLogRuntime, AccessLogSinks, AccessLogSource, SystemAccessLog};
use crate::admin_audit::AdminAuditRuntime;
use crate::cache::ResponseCache;
use crate::client_identity::ClientIdentityRuntime;
use crate::config::{Config, RuntimeDirectH1IoMode, RuntimeMainRuntimeMode, UpstreamConfig};
use crate::control_http::ControlHttpClient;
use crate::dynamic_policy::DynamicPolicyRuntime;
use crate::external_auth::ExternalAuthRuntime;
use crate::ipm::IpmRuntime;
use crate::lifecycle::LifecycleState;
use crate::limits::LimitState;
use crate::metrics::Metrics;
use crate::mitigation::MitigationSink;
use crate::overload::OverloadRuntime;
use crate::pools::PoolState;
use crate::proxy::http::buffering;
use crate::proxy::http::compression::CompressionState;
use crate::proxy::http::fast_path::{
  CompiledRouteFastPathActions, DirectH1Pools, DirectH2Pools, build_compiled_fast_path_actions,
};
use crate::proxy::http::static_files::StaticFilesRuntime;
use crate::proxy::http::uri::UpstreamUriParts;
use crate::proxy::http::waf_body_coding::WafBodyCodingState;
use crate::proxy::http3::UpstreamH3Pools;
use crate::routes::RouteTable;
use crate::runtime::backend::{
  RuntimeBackendSnapshot, TOKIO_HYPER_RUNTIME_NAME, runtime_backend_snapshot,
};
use crate::runtime_introspection::{
  RuntimeCounterGuard, RuntimeIntrospectionCounter, RuntimeIntrospectionState,
};
use crate::shared_state::SharedState;
use crate::sni_forward::SniForwardTable;
use crate::stream::pools::StreamPoolState;
use crate::turn::TurnPoolState;
use crate::waf::WafEngine;
use crate::webtransport_admin::WebTransportAdminRegistry;
use crate::{telemetry::TelemetryRuntime, tls};
use anyhow::Context;
use http::StatusCode;
use std::collections::HashMap;
use std::sync::Arc;

mod alt_svc;
pub(crate) mod handle;
mod http1_upgrade;
mod request_path_features;
mod stream_pool_update;
mod upstream_clients;

pub(crate) use alt_svc::{AltSvcHeaderValues, build_alt_svc_header_values};
pub use handle::AppHandle;
pub(crate) use request_path_features::RequestPathFeaturePlan;
use stream_pool_update::next_stream_pool_generation;
pub use upstream_clients::UpstreamBody;
use upstream_clients::build_clients;
pub(crate) use upstream_clients::{UpstreamClientPools, UpstreamClientRef};

/// Immutable snapshot of runtime configuration and derived state.
#[derive(Clone)]
pub struct AppSnapshot {
  pub config: Config,
  pub(crate) effective_direct_h1_io: RuntimeDirectH1IoMode,
  pub route_table: RouteTable,
  pub(crate) sni_forward: SniForwardTable,
  pub upstreams: Vec<UpstreamConfig>,
  pub(crate) upstream_uri_parts: HashMap<String, UpstreamUriParts>,
  pub(crate) upstream_uri_parts_by_index: Vec<UpstreamUriParts>,
  pub(crate) compiled_fast_path_actions: Arc<Vec<CompiledRouteFastPathActions>>,
  pub clients: UpstreamClientPools,
  pub(crate) direct_h1_pools: DirectH1Pools,
  pub(crate) direct_h2_pools: DirectH2Pools,
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
  pub overload: Arc<OverloadRuntime>,
  pub circuit_breakers: Arc<crate::circuit_breakers::CircuitBreakerRuntime>,
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
  pub tls_server_config: tls::DownstreamTlsServerConfig,
  pub admin_tls_server_config: Option<Arc<rustls::ServerConfig>>,
  pub quic_server_config: Option<tls::DownstreamQuicServerConfig>,
  pub admin_quic_server_config: Option<h3_quinn::quinn::ServerConfig>,
  pub(crate) tls_resumption: tls::TlsResumptionState,
  pub waf: WafEngine,
  pub mitigation: MitigationSink,
  pub access_logs: AccessLogSinks,
  pub system_access_log: SystemAccessLog,
  pub(crate) request_path_features: RequestPathFeaturePlan,
  pub(crate) alt_svc_header_values: AltSvcHeaderValues,
  pub(crate) http1_upgrades_possible: bool,
}

impl AppSnapshot {
  #[inline]
  pub(crate) fn record_hot_path_request(&self) {
    if self.request_path_features.hot_path_metrics {
      self.metrics.record_request();
    }
  }

  #[inline]
  pub(crate) fn record_hot_path_response(&self, status: StatusCode) {
    if self.request_path_features.hot_path_metrics {
      self.metrics.record_response(status);
    }
  }

  pub(crate) fn compiled_fast_path_actions(
    &self,
    route_index: usize,
  ) -> Option<&CompiledRouteFastPathActions> {
    self.compiled_fast_path_actions.get(route_index)
  }

  #[inline]
  pub(crate) fn runtime_introspection_guard(
    &self,
    counter: RuntimeIntrospectionCounter,
  ) -> Option<RuntimeCounterGuard> {
    if self.request_path_features.runtime_introspection {
      Some(self.runtime_introspection.guard(counter))
    } else {
      None
    }
  }

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
    mut config: Config,
    previous: Option<&AppSnapshot>,
    initial_telemetry: Option<TelemetryRuntime>,
  ) -> anyhow::Result<Self> {
    if config.rollout.is_immutable() {
      config
        .validate()
        .context("failed to validate immutable rollout configuration")?;
    }
    crate::crypto::configure_runtime(&config.crypto);
    let mut upstreams = config.upstreams.clone();
    upstreams.extend(PoolState::synthetic_upstreams(&config.upstream_pools));
    let (upstream_uri_parts, upstream_uri_parts_by_index) = build_upstream_uri_parts(&upstreams)?;
    let tls_resumption = previous
      .map(|snapshot| snapshot.tls_resumption.clone())
      .unwrap_or_default();
    let metrics = previous
      .map(|snapshot| snapshot.metrics.clone())
      .unwrap_or_default();
    let lifecycle = previous
      .map(|snapshot| snapshot.lifecycle.clone())
      .unwrap_or_default();
    let overload = previous
      .map(|snapshot| snapshot.overload.clone())
      .unwrap_or_else(|| OverloadRuntime::new(&config.overload));
    if config.overload.enabled {
      overload.bootstrap_validate()?;
    }
    let circuit_breakers = previous
      .map(|snapshot| snapshot.circuit_breakers.clone())
      .unwrap_or_else(|| crate::circuit_breakers::CircuitBreakerRuntime::new(&config));
    circuit_breakers.configure(&config);
    let outbound_revocation = tls::OutboundRevocationRuntime::new(&config, metrics.clone())
      .await
      .context("failed to build outbound TLS revocation runtime")?;
    let clients = build_clients(
      &upstreams,
      &config.proxy.trusted_ca_certs,
      &config.crypto,
      &tls_resumption,
      &config.proxy.http2,
      &outbound_revocation,
      metrics.clone(),
      "primary",
      Some(circuit_breakers.clone()),
      &config.upstream_pools,
    )
    .context("failed to build upstream HTTP clients")?;
    let direct_h1_pools = DirectH1Pools::new(&upstreams);
    let direct_h2_pools = DirectH2Pools::new(
      &upstreams,
      &config.proxy.trusted_ca_certs,
      &config.crypto,
      &tls_resumption,
      &config.proxy.http2,
      &outbound_revocation,
    )
    .context("failed to build direct HTTP/2 pools")?;
    let health_check_upstreams = PoolState::health_check_upstreams(&config.upstream_pools);
    let health_check_clients = build_clients(
      &health_check_upstreams,
      &config.proxy.trusted_ca_certs,
      &config.crypto,
      &tls_resumption,
      &config.proxy.http2,
      &outbound_revocation,
      metrics.clone(),
      "health",
      Some(circuit_breakers.clone()),
      &config.upstream_pools,
    )
    .context("failed to build upstream health-check HTTP clients")?;
    let h3_clients = UpstreamH3Pools::new(
      &upstreams,
      &config,
      &tls_resumption,
      &outbound_revocation,
      circuit_breakers.clone(),
    )
    .context("failed to build upstream HTTP/3 pools")?;
    let control_http = ControlHttpClient::new_with_crypto_and_revocation(
      &config.proxy.trusted_ca_certs,
      &config.crypto,
      &outbound_revocation,
      outbound_revocation.default_policy(),
    )
    .context("failed to build control-plane HTTP client")?;
    let bootstrap_control_http =
      ControlHttpClient::new_with_crypto(&config.proxy.trusted_ca_certs, &config.crypto)
        .context("failed to build revocation bootstrap HTTP client")?;
    let shared_state = SharedState::new_with_previous(
      &config,
      metrics.clone(),
      previous.and_then(|snapshot| snapshot.shared_state.as_deref()),
    )
    .await
    .context("failed to build shared state")?;
    if previous.is_none()
      && let Some(temp_dir) = config.proxy.buffering.temp_dir.as_deref()
    {
      buffering::cleanup_stale_temp_files(temp_dir);
    }
    let limits = LimitState::new(shared_state.clone());
    let pools = PoolState::new_with_previous_and_metrics_async(
      &config.upstream_pools,
      shared_state.clone(),
      previous.map(|snapshot| snapshot.pools.as_ref()),
      Some(metrics.clone()),
    )
    .await;
    pools.publish_server_count_metrics();
    let stream_pools = StreamPoolState::new(&config.stream_upstream_pools);
    let turn_pools = TurnPoolState::new(&config.turn_upstream_pools);
    let external_cache = crate::cache::ExternalCacheRuntime::new(&config, metrics.clone())
      .context("failed to build external cache handlers")?;
    let cache =
      ResponseCache::new_with_external(&config.cache, shared_state.clone(), external_cache)
        .context("failed to build response cache")?;
    cache.set_overload_runtime(overload.clone());
    let telemetry = match previous {
      Some(_) => TelemetryRuntime::new(&config.telemetry.tracing)
        .context("failed to build telemetry runtime")?,
      None => match initial_telemetry {
        Some(telemetry) => telemetry,
        None => TelemetryRuntime::new(&config.telemetry.tracing)
          .context("failed to build telemetry runtime")?,
      },
    };
    let compression = CompressionState::new_with_runtime(&config.compression, overload.clone());
    let waf_body_coding =
      WafBodyCodingState::new_with_runtime(&config.waf.http_body_compression, overload.clone());
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
    runtime_introspection.set_enabled(config.admin.enabled);
    let webtransport_admin = previous
      .map(|snapshot| snapshot.webtransport_admin.clone())
      .unwrap_or_default();
    let mitigation = MitigationSink::new(&config, metrics.clone())
      .await
      .context("failed to build mitigation sink")?;
    let access_log_runtime = AccessLogRuntime::new(&config.access_log, &config.crypto)
      .await
      .context("failed to build access log runtime")?;
    let admin_audit = AdminAuditRuntime::new(
      &config,
      AccessLogSinks::new(access_log_runtime.clone(), AccessLogSource::Admin),
      metrics.clone(),
    )
    .await
    .context("failed to build admin audit runtime")?;
    let crlite = tls::CrliteRuntime::new(&config.tls, metrics.clone())
      .await
      .context("failed to build CRLite runtime")?;
    let ocsp_staple = tls::OcspStapleRuntime::new(
      &config.crypto,
      &config.tls,
      &bootstrap_control_http,
      metrics.clone(),
    )
    .await
    .context("failed to build OCSP staple runtime")?;
    let tls_server_config = tls::build_downstream_tls_server_config_with_resumption_and_ocsp(
      &config.crypto,
      &config.tls,
      &config.listeners,
      &config.routes,
      if config.downstream_tcp_early_data_enabled() {
        config.downstream_tcp_early_data_max_bytes()
      } else {
        0
      },
      Some(&tls_resumption),
      Some(&ocsp_staple),
      Some(&crlite),
    )
    .context("failed to build downstream TLS config")?;
    let admin_tls_server_config = if config.admin.enabled && config.admin.tls.enabled {
      Some(
        tls::build_admin_server_config_with_crypto_and_resumption(
          &config.crypto,
          &config.admin.tls,
          Some(&tls_resumption),
        )
        .context("failed to build admin TLS config")?,
      )
    } else {
      None
    };
    let quic_server_config = if config.listeners.http3 {
      Some(
        tls::build_downstream_quic_server_config_with_resumption_and_ocsp(
          &config.crypto,
          &config.tls,
          &config.quic,
          config.source_paths.cert_dir.as_deref(),
          &config.routes,
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
        tls::build_admin_quic_server_config_with_crypto_and_resumption(
          &config.crypto,
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
    let waf = WafEngine::new_with_previous_limits_and_mitigation_async(
      &config,
      previous.map(|snapshot| &snapshot.waf),
      shared_state.clone(),
      Some(limits.clone()),
      mitigation.clone(),
    )
    .await
    .context("failed to build WAF engine")?;
    let route_table = RouteTable::new_with_waf(&config, &waf);
    let sni_forward =
      SniForwardTable::new(&config).context("failed to build SNI forwarding table")?;
    let access_logs = AccessLogSinks::new(access_log_runtime.clone(), AccessLogSource::Waf);
    let system_access_log = SystemAccessLog::new(
      &config.logging.access_log,
      access_log_runtime,
      config.access_log.system.enabled || config.logging.access_log.enabled,
    )
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
    let alt_svc_header_values = build_alt_svc_header_values(&config)
      .context("failed to build precomputed Alt-Svc header values")?;
    let http1_upgrades_possible = http1_upgrade::http1_upgrades_possible(&config, &upstreams);
    let upstream_pool_generation = next_upstream_pool_generation(&config, previous);
    let stream_pool_generation = next_stream_pool_generation(&config, previous);
    let effective_direct_h1_io =
      effective_direct_h1_io_for_backend(&config, runtime_backend_snapshot());
    let compiled_fast_path_actions = build_compiled_fast_path_actions(
      &config,
      &route_table,
      &upstreams,
      &upstream_uri_parts_by_index,
    );

    config.rollout.mark_applied();

    Ok(Self {
      config,
      effective_direct_h1_io,
      route_table,
      sni_forward,
      upstreams,
      upstream_uri_parts,
      upstream_uri_parts_by_index,
      compiled_fast_path_actions,
      clients,
      direct_h1_pools,
      direct_h2_pools,
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
      overload,
      circuit_breakers,
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
      alt_svc_header_values,
      http1_upgrades_possible,
    })
  }

  pub async fn new_with_updated_upstream_pools(
    config: Config,
    previous: &AppSnapshot,
  ) -> anyhow::Result<Self> {
    crate::crypto::configure_runtime(&config.crypto);
    let mut upstreams = config.upstreams.clone();
    upstreams.extend(PoolState::synthetic_upstreams(&config.upstream_pools));
    let route_table = RouteTable::new_with_waf(&config, &previous.waf);
    let sni_forward =
      SniForwardTable::new(&config).context("failed to build SNI forwarding table")?;
    let (upstream_uri_parts, upstream_uri_parts_by_index) = build_upstream_uri_parts(&upstreams)?;
    let circuit_breakers = previous.circuit_breakers.clone();
    circuit_breakers.configure(&config);
    let clients = build_clients(
      &upstreams,
      &config.proxy.trusted_ca_certs,
      &config.crypto,
      &previous.tls_resumption,
      &config.proxy.http2,
      &previous.outbound_revocation,
      previous.metrics.clone(),
      "primary",
      Some(circuit_breakers.clone()),
      &config.upstream_pools,
    )
    .context("failed to build upstream HTTP clients")?;
    let direct_h1_pools = DirectH1Pools::new(&upstreams);
    let direct_h2_pools = DirectH2Pools::new(
      &upstreams,
      &config.proxy.trusted_ca_certs,
      &config.crypto,
      &previous.tls_resumption,
      &config.proxy.http2,
      &previous.outbound_revocation,
    )
    .context("failed to build direct HTTP/2 pools")?;
    let health_check_upstreams = PoolState::health_check_upstreams(&config.upstream_pools);
    let health_check_clients = build_clients(
      &health_check_upstreams,
      &config.proxy.trusted_ca_certs,
      &config.crypto,
      &previous.tls_resumption,
      &config.proxy.http2,
      &previous.outbound_revocation,
      previous.metrics.clone(),
      "health",
      Some(circuit_breakers.clone()),
      &config.upstream_pools,
    )
    .context("failed to build upstream health-check HTTP clients")?;
    let h3_clients = UpstreamH3Pools::new(
      &upstreams,
      &config,
      &previous.tls_resumption,
      &previous.outbound_revocation,
      circuit_breakers.clone(),
    )
    .context("failed to build upstream HTTP/3 pools")?;
    let control_http = ControlHttpClient::new_with_crypto_and_revocation(
      &config.proxy.trusted_ca_certs,
      &config.crypto,
      &previous.outbound_revocation,
      previous.outbound_revocation.default_policy(),
    )
    .context("failed to build control-plane HTTP client")?;
    let metrics = previous.metrics.clone();
    previous
      .runtime_introspection
      .set_enabled(config.admin.enabled);
    let pools = PoolState::new_with_previous_and_metrics_async(
      &config.upstream_pools,
      previous.shared_state.clone(),
      Some(previous.pools.as_ref()),
      Some(metrics.clone()),
    )
    .await;
    pools.publish_server_count_metrics();
    let stream_pools = StreamPoolState::new(&config.stream_upstream_pools);
    let turn_pools = TurnPoolState::new(&config.turn_upstream_pools);
    let alt_svc_header_values = build_alt_svc_header_values(&config)
      .context("failed to build precomputed Alt-Svc header values")?;
    let static_files =
      StaticFilesRuntime::new(&config).context("failed to build static files runtime")?;
    let waf_body_coding = WafBodyCodingState::new_with_runtime(
      &config.waf.http_body_compression,
      previous.overload.clone(),
    );
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
    let effective_direct_h1_io =
      effective_direct_h1_io_for_backend(&config, runtime_backend_snapshot());
    let request_path_features = RequestPathFeaturePlan::new(
      &config,
      previous.cache.enabled(),
      previous.dynamic_policy.enabled(),
      previous.telemetry.enabled(),
      previous.system_access_log.enabled(),
      previous.waf.has_person_proof_api_paths(),
    );
    let compiled_fast_path_actions = build_compiled_fast_path_actions(
      &config,
      &route_table,
      &upstreams,
      &upstream_uri_parts_by_index,
    );

    Ok(Self {
      config,
      effective_direct_h1_io,
      route_table,
      sni_forward,
      upstreams,
      upstream_uri_parts,
      upstream_uri_parts_by_index,
      compiled_fast_path_actions,
      clients,
      direct_h1_pools,
      direct_h2_pools,
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
      overload: previous.overload.clone(),
      circuit_breakers,
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
      alt_svc_header_values,
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

fn effective_direct_h1_io_for_backend(
  config: &Config,
  runtime_backend: RuntimeBackendSnapshot,
) -> RuntimeDirectH1IoMode {
  if config.runtime.direct_h1_io != RuntimeDirectH1IoMode::Compio {
    return config.runtime.direct_h1_io;
  }
  if config.runtime.main_runtime == RuntimeMainRuntimeMode::TokioHyper
    || runtime_backend.active_runtime == TOKIO_HYPER_RUNTIME_NAME
  {
    tracing::warn!(
      configured_direct_h1_io = "compio",
      active_runtime = runtime_backend.active_runtime,
      "runtime.direct_h1_io = \"compio\" requires an active Compio main runtime; using Tokio/Hyper direct-H1 IO"
    );
    return RuntimeDirectH1IoMode::TokioHyper;
  }
  RuntimeDirectH1IoMode::Compio
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

#[cfg(test)]
mod tests;

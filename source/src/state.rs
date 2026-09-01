//! Immutable runtime snapshots and shared client pools; reloads swap snapshots so in-flight work can finish against a consistent view.
use crate::access_log::{AccessLogRuntime, AccessLogSinks, AccessLogSource, SystemAccessLog};
#[cfg(feature = "admin-runtime")]
use crate::admin_audit::AdminAuditRuntime;
#[cfg(feature = "admin-runtime")]
use crate::admin_mutation::AdminMutationRuntime;
use crate::cache::ResponseCache;
use crate::client_identity::ClientIdentityRuntime;
#[cfg(feature = "admin-runtime")]
use crate::config::AdminAuditExportSink;
use crate::config::{AccessLogConfig, Config, RuntimeDirectH1IoMode, UpstreamConfig};
use crate::control_http::ControlHttpClient;
use crate::ct_runtime::CtRuntime;
use crate::dynamic_policy::DynamicPolicyRuntime;
use crate::external_auth::ExternalAuthRuntime;
use crate::filesystem_access::FilesystemAccessManifest;
use crate::hardening::{
  LandlockEnforcementState, RuntimeHardeningOutcome, RuntimeHardeningSnapshot,
  observe_runtime_hardening,
};
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
use crate::runtime::topology::RuntimeTopologySnapshot;
use crate::runtime_health::{RuntimeHealth, RuntimeSubsystem, RuntimeSubsystemState};
use crate::runtime_introspection::{
  RuntimeCounterGuard, RuntimeIntrospectionCounter, RuntimeIntrospectionState,
};
use crate::secret_activation::SecretReferenceRuntime;
use crate::shared_state::SharedState;
use crate::sni_forward::SniForwardTable;
use crate::stream::pools::StreamPoolState;
use crate::turn::TurnPoolState;
use crate::waf::WafEngine;
#[cfg(feature = "admin-runtime")]
use crate::webtransport_admin::WebTransportAdminRegistry;
use crate::{telemetry::TelemetryRuntime, tls};
use anyhow::Context;
use http::StatusCode;
use std::collections::HashMap;
use std::sync::Arc;
mod alt_svc;
mod compio_direct_h1;
mod generation;
pub(crate) mod handle;
mod http1_upgrade;
mod request_path_features;
mod runtime_services;
mod runtime_topology;
mod secret_references;
mod stream_pool_update;
mod upstream_clients;
mod upstream_precompute;
pub(crate) use alt_svc::{AltSvcHeaderValues, build_alt_svc_header_values};
use generation::{next_direct_h1_plan_generation, next_upstream_pool_generation};
pub use handle::AppHandle;
pub(crate) use request_path_features::RequestPathFeaturePlan;
use stream_pool_update::next_stream_pool_generation;
pub use upstream_clients::UpstreamBody;
use upstream_clients::build_clients;
pub(crate) use upstream_clients::{UpstreamClientPools, UpstreamClientRef};
use upstream_precompute::build_upstream_uri_parts;
/// Immutable snapshot of runtime configuration and derived state.
#[derive(Clone)]
pub struct AppSnapshot {
  pub config: Config,
  pub runtime_topology: RuntimeTopologySnapshot,
  pub hardening: RuntimeHardeningSnapshot,
  pub(crate) secret_references: SecretReferenceRuntime,
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
  pub(crate) compio_direct_h1_budget: Option<crate::circuit_breakers::CompioDirectH1Budget>,
  pub(crate) compio_direct_h1_overlap_budget: Arc<compio_direct_h1::CompioDirectH1OverlapBudget>,
  pub(crate) direct_h1_plan_generation: u64,
  pub(crate) compio_direct_h1_service:
    Option<Arc<crate::proxy::http::fast_path::direct_h1::CompioDirectH1Service>>,
  pub(crate) staged_compio_direct_h1_service:
    Option<crate::proxy::http::fast_path::direct_h1::CompioDirectH1Staged>,
  pub(crate) compio_direct_h1_fleet_reservation:
    Option<Arc<compio_direct_h1::CompioDirectH1FleetReservation>>,
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
  pub(crate) certificate_transparency: CtRuntime,
  pub metrics: Arc<Metrics>,
  pub(crate) runtime_health: Arc<RuntimeHealth>,
  pub(crate) runtime_generation: u64,
  pub overload: Arc<OverloadRuntime>,
  pub circuit_breakers: Arc<crate::circuit_breakers::CircuitBreakerRuntime>,
  pub telemetry: TelemetryRuntime,
  pub ipm: IpmRuntime,
  pub dynamic_policy: DynamicPolicyRuntime,
  pub external_auth: ExternalAuthRuntime,
  pub client_identity: ClientIdentityRuntime,
  pub runtime_introspection: Arc<RuntimeIntrospectionState>,
  #[cfg(feature = "admin-runtime")]
  pub webtransport_admin: Arc<WebTransportAdminRegistry>,
  pub lifecycle: Arc<LifecycleState>,
  #[cfg(feature = "admin-runtime")]
  pub admin_audit: AdminAuditRuntime,
  #[cfg(feature = "admin-runtime")]
  pub(crate) admin_mutations: AdminMutationRuntime,
  pub shared_state: Option<Arc<SharedState>>,
  pub(crate) crlite: tls::CrliteRuntime,
  pub(crate) downstream_ct: tls::DownstreamCtRuntime,
  pub(crate) ocsp_staple: tls::OcspStapleRuntime,
  pub tls_server_config: tls::DownstreamTlsServerConfig,
  #[cfg(feature = "admin-runtime")]
  pub admin_tls_server_config: Option<Arc<rustls::ServerConfig>>,
  pub quic_server_config: Option<tls::DownstreamQuicServerConfig>,
  #[cfg(feature = "admin-runtime")]
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

fn effective_access_log_config(
  config: &AccessLogConfig,
  legacy_system_enabled: bool,
) -> AccessLogConfig {
  let mut effective = config.clone();
  effective.system.enabled |= legacy_system_enabled;
  effective
}

impl AppSnapshot {
  pub(crate) fn admitted_reload_hardening(
    &self,
    candidate: &Config,
  ) -> anyhow::Result<RuntimeHardeningSnapshot> {
    let candidate_manifest = FilesystemAccessManifest::from_config(candidate)
      .context("failed to generate candidate filesystem-access manifest")?;
    let projection = candidate_manifest.landlock_projection();
    if self.hardening.landlock.enforcement == LandlockEnforcementState::Active {
      if !projection.parent_scope_representable {
        anyhow::bail!(
          "manifest_landlock_parent_scope_unrepresentable: candidate write roots must be pre-created before reload"
        );
      }
      let installed_authority = self
        .hardening
        .landlock
        .installed_authority
        .as_ref()
        .context(
          "installed_landlock_authority_unavailable: active Landlock rules cannot be reconstructed safely; restart required",
        )?;
      if !installed_authority.has_valid_policy_evidence() {
        anyhow::bail!(
          "installed_landlock_authority_invalid: active Landlock evidence is incomplete; restart required"
        );
      }
      let explicit_rules = crate::hardening::project_explicit_landlock_additions(
        &candidate.runtime.hardening.landlock,
      )
      .context("failed to project candidate explicit Landlock additions")?;
      let expansion_count = installed_authority
        .uncovered_rule_count(&projection)
        .saturating_add(
          explicit_rules
            .iter()
            .filter(|rule| !installed_authority.covers_rule(rule))
            .count(),
        );
      if expansion_count != 0 {
        anyhow::bail!(
          "filesystem_access_expansion: candidate manifest requires {} path policies outside active Landlock rules; restart required",
          expansion_count
        );
      }
    }
    let (filesystem_manifest, filesystem_blocking_reasons) =
      crate::hardening::assess_filesystem_manifest_expectation(
        &candidate.runtime.hardening,
        Some(&projection),
      );
    let hardening = self.hardening.with_current_manifest(
      candidate_manifest.digest().to_string(),
      projection.read_only_rootfs,
      filesystem_manifest,
      filesystem_blocking_reasons,
    );
    Ok(hardening)
  }

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
    Self::new_with_previous_and_telemetry(config, None, Some(telemetry), None, None).await
  }

  pub async fn new_with_telemetry_and_hardening(
    config: Config,
    telemetry: TelemetryRuntime,
    hardening: RuntimeHardeningSnapshot,
  ) -> anyhow::Result<Self> {
    Self::new_with_previous_and_telemetry(config, None, Some(telemetry), None, Some(hardening))
      .await
  }

  pub async fn new_with_telemetry_and_topology(
    config: Config,
    telemetry: TelemetryRuntime,
    topology: RuntimeTopologySnapshot,
  ) -> anyhow::Result<Self> {
    Self::new_with_previous_and_telemetry(config, None, Some(telemetry), Some(topology), None).await
  }

  pub async fn new_with_telemetry_and_topology_and_hardening(
    config: Config,
    telemetry: TelemetryRuntime,
    topology: RuntimeTopologySnapshot,
    hardening: RuntimeHardeningSnapshot,
  ) -> anyhow::Result<Self> {
    Self::new_with_previous_and_telemetry(
      config,
      None,
      Some(telemetry),
      Some(topology),
      Some(hardening),
    )
    .await
  }

  pub async fn new_with_previous(
    config: Config,
    previous: Option<&AppSnapshot>,
  ) -> anyhow::Result<Self> {
    Self::new_with_previous_and_telemetry(config, previous, None, None, None).await
  }

  async fn new_with_previous_and_telemetry(
    mut config: Config,
    previous: Option<&AppSnapshot>,
    initial_telemetry: Option<TelemetryRuntime>,
    supplied_topology: Option<RuntimeTopologySnapshot>,
    supplied_hardening: Option<RuntimeHardeningSnapshot>,
  ) -> anyhow::Result<Self> {
    if config.rollout.is_immutable() {
      config
        .validate()
        .context("failed to validate immutable rollout configuration")?;
    }
    let runtime_topology =
      runtime_topology::for_snapshot_build(&config, supplied_topology, previous)?;
    let filesystem_manifest = FilesystemAccessManifest::from_config(&config)
      .context("failed to generate filesystem-access manifest")?;
    let manifest_projection = filesystem_manifest.landlock_projection();
    let hardening = match (previous, supplied_hardening) {
      (Some(previous), None) => previous.admitted_reload_hardening(&config)?,
      (_, Some(hardening)) => hardening,
      (None, None) => {
        observe_runtime_hardening(&config.runtime.hardening, Some(&manifest_projection))
      }
    };
    let mut upstreams = config.upstreams.clone();
    upstreams.extend(PoolState::synthetic_upstreams(&config.upstream_pools));
    let (upstream_uri_parts, upstream_uri_parts_by_index) = build_upstream_uri_parts(&upstreams)?;
    let tls_resumption = previous
      .map(|snapshot| snapshot.tls_resumption.clone())
      .unwrap_or_default();
    let metrics = previous
      .map(|snapshot| snapshot.metrics.clone())
      .unwrap_or_default();
    let certificate_transparency =
      CtRuntime::new(&config.certificate_transparency, metrics.clone())
        .await
        .context("failed to build Certificate Transparency runtime")?;
    let (runtime_health, runtime_generation, overload, circuit_breakers) =
      runtime_services::build(&config, previous)?;
    let (hardening_state, readiness_critical) = match hardening.outcome {
      RuntimeHardeningOutcome::Satisfied => (RuntimeSubsystemState::Healthy, false),
      RuntimeHardeningOutcome::Degraded => (RuntimeSubsystemState::Degraded, false),
      RuntimeHardeningOutcome::Blocked => (RuntimeSubsystemState::Failed, true),
    };
    runtime_health.set_subsystem_state(
      runtime_generation,
      RuntimeSubsystem::Hardening,
      hardening_state,
      readiness_critical,
    );
    let lifecycle = previous
      .map(|snapshot| snapshot.lifecycle.clone())
      .unwrap_or_default();
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
      &config.proxy.upstream_resolution,
    )
    .context("failed to build upstream HTTP clients")?;
    let direct_h1_pools = DirectH1Pools::new(
      &upstreams,
      circuit_breakers.clone(),
      &config.upstream_pools,
      &config.proxy.upstream_resolution,
    )
    .context("failed to build direct HTTP/1 pools")?;
    let direct_h2_pools = DirectH2Pools::new(
      &upstreams,
      &config.proxy.trusted_ca_certs,
      &config.crypto,
      &tls_resumption,
      &config.proxy.http2,
      &outbound_revocation,
      circuit_breakers.clone(),
      &config.upstream_pools,
      &config.proxy.upstream_resolution,
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
      &config.proxy.upstream_resolution,
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
    let limits = LimitState::new_with_health(shared_state.clone(), runtime_health.clone());
    let pools = PoolState::new_with_previous_and_metrics_async(
      &config.upstream_pools,
      shared_state.clone(),
      previous.map(|snapshot| snapshot.pools.as_ref()),
      Some(metrics.clone()),
    )
    .await;
    pools.publish_server_count_metrics();
    let stream_pools = StreamPoolState::new(&config.stream_upstream_pools);
    let turn_pools = TurnPoolState::new_with_previous(
      &config.turn_upstream_pools,
      previous.map(|snapshot| snapshot.turn_pools.as_ref()),
    );
    let external_cache = crate::cache::ExternalCacheRuntime::new(&config, metrics.clone())
      .context("failed to build external cache handlers")?;
    let cache = ResponseCache::new_with_external_and_health(
      &config.cache,
      shared_state.clone(),
      external_cache,
      runtime_health.clone(),
    )
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
    let static_files = StaticFilesRuntime::new_with_health(&config, runtime_health.clone())
      .context("failed to build static files runtime")?;
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
    #[cfg(feature = "admin-runtime")]
    let webtransport_admin = previous
      .map(|snapshot| snapshot.webtransport_admin.clone())
      .unwrap_or_default();
    let mitigation = MitigationSink::new(&config, metrics.clone())
      .await
      .context("failed to build mitigation sink")?;
    let effective_access_log =
      effective_access_log_config(&config.access_log, config.logging.access_log.enabled);
    let system_access_log_enabled = effective_access_log.system.enabled;
    let access_log_runtime = AccessLogRuntime::new(&effective_access_log, &config.crypto)
      .await
      .context("failed to build access log runtime")?;
    #[cfg(feature = "admin-runtime")]
    let admin_access_logs = AccessLogSinks::new(access_log_runtime.clone(), AccessLogSource::Admin);
    #[cfg(feature = "admin-runtime")]
    let reusable_admin_audit = previous.filter(|previous| {
      config.admin.enabled == previous.config.admin.enabled
        && config.admin.audit == previous.config.admin.audit
        && config.shared_state.namespace == previous.config.shared_state.namespace
        && config.shared_state.instance_id_env == previous.config.shared_state.instance_id_env
        && (!config.admin.audit.store.enabled
          || config.shared_state.backends == previous.config.shared_state.backends)
    });
    #[cfg(feature = "admin-runtime")]
    let admin_audit = if let Some(previous) = reusable_admin_audit {
      let export = (config.admin.enabled
        && config.admin.audit.enabled
        && config.admin.audit.export.enabled
        && config
          .admin
          .audit
          .export
          .sinks
          .contains(&AdminAuditExportSink::AccessLog))
      .then_some(admin_access_logs);
      previous.admin_audit.clone_with_export(export)
    } else {
      AdminAuditRuntime::new(
        &config,
        admin_access_logs,
        metrics.clone(),
        runtime_health.clone(),
      )
      .await
      .context("failed to build admin audit runtime")?
    };
    #[cfg(feature = "admin-runtime")]
    let prior_admin_mutations = previous.map(|value| (&value.config, &value.admin_mutations));
    #[cfg(feature = "admin-runtime")]
    let admin_mutations =
      AdminMutationRuntime::new_or_reuse(&config, &admin_audit, prior_admin_mutations)
        .await
        .context("failed to build Admin mutation runtime")?;
    let crlite = tls::CrliteRuntime::new(&config.tls, metrics.clone())
      .await
      .context("failed to build CRLite runtime")?;
    let downstream_ct = tls::DownstreamCtRuntime::new(&config.tls, metrics.clone())
      .await
      .context("failed to build downstream CT runtime")?;
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
      Some(&downstream_ct),
    )
    .context("failed to build downstream TLS config")?;
    #[cfg(feature = "admin-runtime")]
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
          Some(&downstream_ct),
        )
        .context("failed to build QUIC TLS config")?,
      )
    } else {
      None
    };
    #[cfg(feature = "admin-runtime")]
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
    let route_table = RouteTable::new_with_waf_and_previous(
      &config,
      &waf,
      previous.map(|snapshot| &snapshot.route_table),
    );
    let sni_forward =
      SniForwardTable::new(&config).context("failed to build SNI forwarding table")?;
    let access_logs = AccessLogSinks::new(access_log_runtime.clone(), AccessLogSource::Waf);
    let system_access_log = SystemAccessLog::new(
      &config.logging.access_log,
      access_log_runtime,
      system_access_log_enabled,
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
      runtime_topology::effective_direct_h1_io(&config, &runtime_topology);
    let compio_direct_h1_budget = (effective_direct_h1_io == RuntimeDirectH1IoMode::Compio)
      .then(|| crate::circuit_breakers::compio_direct_h1_budget(&config))
      .transpose()?;
    let direct_h1_plan_generation = next_direct_h1_plan_generation(
      &config,
      effective_direct_h1_io,
      compio_direct_h1_budget,
      previous,
    );
    let (
      compio_direct_h1_overlap_budget,
      compio_direct_h1_service,
      staged_compio_direct_h1_service,
      compio_direct_h1_fleet_reservation,
    ) = compio_direct_h1::stage_service(
      effective_direct_h1_io,
      compio_direct_h1_budget,
      direct_h1_plan_generation,
      metrics.clone(),
      runtime_health.clone(),
      previous,
    )?;
    let compiled_fast_path_actions = build_compiled_fast_path_actions(
      &config,
      &route_table,
      &upstreams,
      &upstream_uri_parts_by_index,
    );

    let secret_references = secret_references::build(&config, previous)?;
    config.rollout.mark_applied();
    Ok(Self {
      config,
      runtime_topology,
      hardening,
      secret_references,
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
      compio_direct_h1_budget,
      compio_direct_h1_overlap_budget,
      direct_h1_plan_generation,
      compio_direct_h1_service,
      staged_compio_direct_h1_service,
      compio_direct_h1_fleet_reservation,
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
      certificate_transparency,
      metrics,
      runtime_health,
      runtime_generation,
      overload,
      circuit_breakers,
      telemetry,
      ipm,
      dynamic_policy,
      external_auth,
      client_identity,
      runtime_introspection,
      #[cfg(feature = "admin-runtime")]
      webtransport_admin,
      lifecycle,
      #[cfg(feature = "admin-runtime")]
      admin_audit,
      #[cfg(feature = "admin-runtime")]
      admin_mutations,
      shared_state,
      crlite,
      downstream_ct,
      ocsp_staple,
      tls_server_config,
      #[cfg(feature = "admin-runtime")]
      admin_tls_server_config,
      quic_server_config,
      #[cfg(feature = "admin-runtime")]
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
    let hardening = previous.admitted_reload_hardening(&config)?;
    let mut upstreams = config.upstreams.clone();
    upstreams.extend(PoolState::synthetic_upstreams(&config.upstream_pools));
    let route_table =
      RouteTable::new_with_waf_and_previous(&config, &previous.waf, Some(&previous.route_table));
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
      &config.proxy.upstream_resolution,
    )
    .context("failed to build upstream HTTP clients")?;
    let direct_h1_pools = DirectH1Pools::new(
      &upstreams,
      circuit_breakers.clone(),
      &config.upstream_pools,
      &config.proxy.upstream_resolution,
    )
    .context("failed to build direct HTTP/1 pools")?;
    let direct_h2_pools = DirectH2Pools::new(
      &upstreams,
      &config.proxy.trusted_ca_certs,
      &config.crypto,
      &previous.tls_resumption,
      &config.proxy.http2,
      &previous.outbound_revocation,
      circuit_breakers.clone(),
      &config.upstream_pools,
      &config.proxy.upstream_resolution,
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
      &config.proxy.upstream_resolution,
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
    let runtime_health = previous.runtime_health.clone();
    let runtime_generation = runtime_health.allocate_generation();
    let (hardening_state, readiness_critical) = match hardening.outcome {
      RuntimeHardeningOutcome::Satisfied => (RuntimeSubsystemState::Healthy, false),
      RuntimeHardeningOutcome::Degraded => (RuntimeSubsystemState::Degraded, false),
      RuntimeHardeningOutcome::Blocked => (RuntimeSubsystemState::Failed, true),
    };
    runtime_health.set_subsystem_state(
      runtime_generation,
      RuntimeSubsystem::Hardening,
      hardening_state,
      readiness_critical,
    );
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
    let turn_pools = TurnPoolState::new_with_previous(
      &config.turn_upstream_pools,
      Some(previous.turn_pools.as_ref()),
    );
    let alt_svc_header_values = build_alt_svc_header_values(&config)
      .context("failed to build precomputed Alt-Svc header values")?;
    let static_files = StaticFilesRuntime::new_with_health(&config, runtime_health.clone())
      .context("failed to build static files runtime")?;
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
    let runtime_topology = runtime_topology::for_snapshot_build(&config, None, Some(previous))?;
    let effective_direct_h1_io =
      runtime_topology::effective_direct_h1_io(&config, &runtime_topology);
    let compio_direct_h1_budget = (effective_direct_h1_io == RuntimeDirectH1IoMode::Compio)
      .then(|| crate::circuit_breakers::compio_direct_h1_budget(&config))
      .transpose()?;
    let direct_h1_plan_generation = next_direct_h1_plan_generation(
      &config,
      effective_direct_h1_io,
      compio_direct_h1_budget,
      Some(previous),
    );
    let (
      compio_direct_h1_overlap_budget,
      compio_direct_h1_service,
      staged_compio_direct_h1_service,
      compio_direct_h1_fleet_reservation,
    ) = compio_direct_h1::stage_service(
      effective_direct_h1_io,
      compio_direct_h1_budget,
      direct_h1_plan_generation,
      metrics.clone(),
      runtime_health.clone(),
      Some(previous),
    )?;
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

    let secret_references = secret_references::build(&config, Some(previous))?;
    Ok(Self {
      config,
      runtime_topology,
      hardening,
      secret_references,
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
      compio_direct_h1_budget,
      compio_direct_h1_overlap_budget,
      direct_h1_plan_generation,
      compio_direct_h1_service,
      staged_compio_direct_h1_service,
      compio_direct_h1_fleet_reservation,
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
      certificate_transparency: previous.certificate_transparency.clone(),
      metrics,
      runtime_health,
      runtime_generation,
      overload: previous.overload.clone(),
      circuit_breakers,
      telemetry: previous.telemetry.clone(),
      ipm,
      dynamic_policy: previous.dynamic_policy.clone(),
      external_auth,
      client_identity,
      runtime_introspection: previous.runtime_introspection.clone(),
      #[cfg(feature = "admin-runtime")]
      webtransport_admin: previous.webtransport_admin.clone(),
      lifecycle: previous.lifecycle.clone(),
      #[cfg(feature = "admin-runtime")]
      admin_audit: previous.admin_audit.clone(),
      #[cfg(feature = "admin-runtime")]
      admin_mutations: previous.admin_mutations.clone(),
      shared_state: previous.shared_state.clone(),
      crlite: previous.crlite.clone(),
      downstream_ct: previous.downstream_ct.clone(),
      ocsp_staple: previous.ocsp_staple.clone(),
      tls_server_config: previous.tls_server_config.clone(),
      #[cfg(feature = "admin-runtime")]
      admin_tls_server_config: previous.admin_tls_server_config.clone(),
      quic_server_config: previous.quic_server_config.clone(),
      #[cfg(feature = "admin-runtime")]
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

  pub(super) fn restage_direct_h2_pools_for_publication(&mut self) -> anyhow::Result<()> {
    if !self.direct_h2_pools.needs_restage() {
      return Ok(());
    }
    self.direct_h2_pools = DirectH2Pools::new(
      &self.upstreams,
      &self.config.proxy.trusted_ca_certs,
      &self.config.crypto,
      &self.tls_resumption,
      &self.config.proxy.http2,
      &self.outbound_revocation,
      self.circuit_breakers.clone(),
      &self.config.upstream_pools,
      &self.config.proxy.upstream_resolution,
    )
    .context("failed to restage direct HTTP/2 pools for snapshot publication")?;
    Ok(())
  }
}

#[cfg(test)]
mod access_log_tests;
#[cfg(test)]
mod tests;

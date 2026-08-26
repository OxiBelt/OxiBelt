//! Hot-reload loading and validation.
//! New snapshots are built fully before replacing the active runtime state.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, bail};
use tracing::{info, warn};

use crate::config::{Config, HotReloadMode, RuntimeOverrides, TlsConfig};
use crate::proxy::http::fast_path::build_compiled_fast_path_actions;
use crate::routes::RouteTable;
#[cfg(test)]
use crate::runtime::topology::RuntimeTopologyChangePlan;
use crate::server::ListenerSupervisor;
use crate::state::{AppHandle, AppSnapshot, RequestPathFeaturePlan};
use crate::tls;
use crate::waf::WafEngine;

#[cfg(feature = "admin-runtime")]
#[path = "reload/audit.rs"]
mod audit;

#[derive(Debug, Clone, Copy)]
pub(crate) enum ReloadTrigger {
  Poll,
  Signal,
}

pub(crate) struct ReloadManager {
  config_path: PathBuf,
  runtime_overrides: RuntimeOverrides,
  mode: HotReloadMode,
  poll_interval: Duration,
  last_fingerprints: Vec<FileFingerprint>,
}

impl ReloadManager {
  pub(crate) fn new(
    config_path: PathBuf,
    runtime_overrides: RuntimeOverrides,
    snapshot: &AppSnapshot,
  ) -> anyhow::Result<Self> {
    let mode = snapshot.config.runtime.hot_reload.mode;
    let poll_interval = Duration::from_millis(snapshot.config.runtime.hot_reload.poll_interval_ms);
    let last_fingerprints = fingerprint_files(relevant_files(mode, &snapshot.config));
    Ok(Self {
      config_path,
      runtime_overrides,
      mode,
      poll_interval,
      last_fingerprints,
    })
  }

  pub(crate) fn poll_interval(&self) -> Duration {
    self.poll_interval
  }

  pub(crate) async fn reload_if_changed(
    &mut self,
    trigger: ReloadTrigger,
    state: &AppHandle,
    listeners: &mut ListenerSupervisor,
  ) {
    let active = state.snapshot();
    self.mode = active.config.runtime.hot_reload.mode;
    self.poll_interval = Duration::from_millis(active.config.runtime.hot_reload.poll_interval_ms);
    if !self.mode.enabled() {
      return;
    }

    let result = match self.mode {
      HotReloadMode::Off => Ok(false),
      HotReloadMode::OxiRule => self.reload_oxirule(trigger, state).await,
      HotReloadMode::Full => self.reload_full(trigger, state, listeners).await,
      HotReloadMode::DownstreamTls => self.reload_downstream_tls(trigger, state, listeners).await,
    };

    match result {
      Ok(true) => info!(mode = %self.mode, "hot reload applied"),
      Ok(false) => {}
      Err(error) => {
        warn!(mode = %self.mode, error = %error, "hot reload failed; keeping previous active state");
      }
    }
  }

  async fn reload_oxirule(
    &mut self,
    trigger: ReloadTrigger,
    state: &AppHandle,
  ) -> anyhow::Result<bool> {
    let config = self.load_config()?;
    let fingerprints = fingerprint_files(config.source_paths.oxirule_reload_files());
    if matches!(trigger, ReloadTrigger::Poll) && fingerprints == self.last_fingerprints {
      return Ok(false);
    }

    let active = state.snapshot();
    if !active.config.non_waf_equivalent(&config) {
      bail!("OxiRule hot reload rejected because non-WAF OxiBelt configuration changed");
    }
    if active.config.waf_equivalent(&config) {
      self.last_fingerprints = fingerprints;
      return Ok(false);
    }
    let hardening = active.admitted_reload_hardening(&config)?;

    let waf = WafEngine::new_with_previous_limits_and_mitigation(
      &config,
      Some(&active.waf),
      active.shared_state.clone(),
      Some(active.limits.clone()),
      active.mitigation.clone(),
    )
    .context("failed to rebuild WAF engine")?;
    let route_table = RouteTable::new_with_waf(&config, &waf);
    let compiled_fast_path_actions = build_compiled_fast_path_actions(
      &config,
      &route_table,
      &active.upstreams,
      &active.upstream_uri_parts_by_index,
    );
    let ipm = crate::ipm::IpmRuntime::new(&config)
      .await
      .context("failed to build IPM runtime")?;
    let request_path_features = RequestPathFeaturePlan::new(
      &config,
      active.cache.enabled(),
      active.dynamic_policy.enabled(),
      active.telemetry.enabled(),
      active.system_access_log.enabled(),
      waf.has_person_proof_api_paths(),
    );
    let upstream_pool_generation = if config.upstream_pools == active.config.upstream_pools {
      active.upstream_pool_generation
    } else {
      active.upstream_pool_generation.saturating_add(1)
    };
    let stream_pool_generation =
      if config.stream_upstream_pools == active.config.stream_upstream_pools {
        active.stream_pool_generation
      } else {
        active.stream_pool_generation.saturating_add(1)
      };
    let waf_body_coding = crate::proxy::http::waf_body_coding::WafBodyCodingState::new_with_runtime(
      &config.waf.http_body_compression,
      active.overload.clone(),
    );
    let alt_svc_header_values = crate::state::build_alt_svc_header_values(&config)
      .context("failed to build precomputed Alt-Svc header values")?;
    let snapshot = AppSnapshot {
      runtime_topology: active.runtime_topology.clone(),
      hardening,
      route_table,
      sni_forward: active.sni_forward.clone(),
      upstreams: active.upstreams.clone(),
      upstream_uri_parts: active.upstream_uri_parts.clone(),
      upstream_uri_parts_by_index: active.upstream_uri_parts_by_index.clone(),
      compiled_fast_path_actions,
      config,
      secret_references: active.secret_references.clone(),
      effective_direct_h1_io: active.effective_direct_h1_io,
      clients: active.clients.clone(),
      direct_h1_pools: active.direct_h1_pools.clone(),
      direct_h2_pools: active.direct_h2_pools.clone(),
      health_check_clients: active.health_check_clients.clone(),
      control_http: active.control_http.clone(),
      h3_clients: active.h3_clients.clone(),
      outbound_revocation: active.outbound_revocation.clone(),
      compio_direct_h1_budget: active.compio_direct_h1_budget,
      compio_direct_h1_overlap_budget: active.compio_direct_h1_overlap_budget.clone(),
      direct_h1_plan_generation: active.direct_h1_plan_generation,
      compio_direct_h1_service: active.compio_direct_h1_service.clone(),
      staged_compio_direct_h1_service: None,
      compio_direct_h1_fleet_reservation: active.compio_direct_h1_fleet_reservation.clone(),
      upstream_pool_generation,
      stream_pool_generation,
      limits: active.limits.clone(),
      pools: active.pools.clone(),
      stream_pools: active.stream_pools.clone(),
      turn_pools: active.turn_pools.clone(),
      cache: active.cache.clone(),
      compression: active.compression.clone(),
      waf_body_coding,
      static_files: active.static_files.clone(),
      certificate_transparency: active.certificate_transparency.clone(),
      metrics: active.metrics.clone(),
      runtime_health: active.runtime_health.clone(),
      runtime_generation: active.runtime_generation,
      overload: active.overload.clone(),
      circuit_breakers: active.circuit_breakers.clone(),
      telemetry: active.telemetry.clone(),
      ipm,
      dynamic_policy: active.dynamic_policy.clone(),
      external_auth: active.external_auth.clone(),
      client_identity: active.client_identity.clone(),
      runtime_introspection: active.runtime_introspection.clone(),
      #[cfg(feature = "admin-runtime")]
      webtransport_admin: active.webtransport_admin.clone(),
      lifecycle: active.lifecycle.clone(),
      #[cfg(feature = "admin-runtime")]
      admin_audit: active.admin_audit.clone(),
      #[cfg(feature = "admin-runtime")]
      admin_mutations: active.admin_mutations.clone(),
      shared_state: active.shared_state.clone(),
      crlite: active.crlite.clone(),
      downstream_ct: active.downstream_ct.clone(),
      ocsp_staple: active.ocsp_staple.clone(),
      tls_server_config: active.tls_server_config.clone(),
      #[cfg(feature = "admin-runtime")]
      admin_tls_server_config: active.admin_tls_server_config.clone(),
      quic_server_config: active.quic_server_config.clone(),
      #[cfg(feature = "admin-runtime")]
      admin_quic_server_config: active.admin_quic_server_config.clone(),
      tls_resumption: active.tls_resumption.clone(),
      waf,
      mitigation: active.mitigation.clone(),
      access_logs: active.access_logs.clone(),
      system_access_log: active.system_access_log.clone(),
      request_path_features,
      alt_svc_header_values,
      http1_upgrades_possible: active.http1_upgrades_possible,
    };
    state.replace(snapshot);
    self.last_fingerprints = fingerprints;
    Ok(true)
  }

  async fn reload_full(
    &mut self,
    trigger: ReloadTrigger,
    state: &AppHandle,
    listeners: &mut ListenerSupervisor,
  ) -> anyhow::Result<bool> {
    let config = self.load_config()?;
    let fingerprints = fingerprint_files(config.source_paths.all_reload_files());
    let active = state.snapshot();
    if matches!(trigger, ReloadTrigger::Poll)
      && fingerprints == self.last_fingerprints
      && config == active.config
    {
      return Ok(false);
    }
    validate_full_reload_runtime_compatibility(&active.config, &config)?;

    let snapshot = AppSnapshot::new_with_previous(config, Some(active.as_ref())).await?;
    let pending = listeners.prepare(&snapshot).await?;
    state.replace(snapshot);
    let active = state.snapshot();
    listeners.commit(pending, active.as_ref(), state.clone());
    self.mode = active.config.runtime.hot_reload.mode;
    self.poll_interval = Duration::from_millis(active.config.runtime.hot_reload.poll_interval_ms);
    self.last_fingerprints = fingerprints;
    Ok(true)
  }

  async fn reload_downstream_tls(
    &mut self,
    trigger: ReloadTrigger,
    state: &AppHandle,
    listeners: &mut ListenerSupervisor,
  ) -> anyhow::Result<bool> {
    let active = state.snapshot();
    let fingerprints = fingerprint_files(active.config.source_paths.downstream_tls_reload_files());
    if matches!(trigger, ReloadTrigger::Poll) && fingerprints == self.last_fingerprints {
      return Ok(false);
    }

    let mut config = active.config.clone();
    reload_downstream_tls_paths(&mut config)?;
    let hardening = active.admitted_reload_hardening(&config)?;
    let crlite = tls::CrliteRuntime::new(&config.tls, active.metrics.clone())
      .await
      .context("failed to build CRLite runtime")?;
    let downstream_ct = tls::DownstreamCtRuntime::new(&config.tls, active.metrics.clone())
      .await
      .context("failed to build downstream CT runtime")?;
    let ocsp_staple = tls::OcspStapleRuntime::new(
      &config.crypto,
      &config.tls,
      &active.control_http,
      active.metrics.clone(),
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
      Some(&active.tls_resumption),
      Some(&ocsp_staple),
      Some(&crlite),
      Some(&downstream_ct),
    )
    .context("failed to rebuild downstream TLS config")?;
    let quic_server_config = if config.listeners.http3 {
      Some(
        tls::build_downstream_quic_server_config_with_resumption_and_ocsp(
          &config.crypto,
          &config.tls,
          &config.quic,
          config.source_paths.cert_dir.as_deref(),
          &config.routes,
          Some(&active.tls_resumption),
          Some(&ocsp_staple),
          Some(&crlite),
          Some(&downstream_ct),
        )
        .context("failed to rebuild QUIC TLS config")?,
      )
    } else {
      None
    };
    #[cfg(feature = "admin-runtime")]
    let admin_quic_server_config = active.admin_quic_server_config.clone();
    let ipm = crate::ipm::IpmRuntime::new(&config)
      .await
      .context("failed to build IPM runtime")?;
    let request_path_features = RequestPathFeaturePlan::new(
      &config,
      active.cache.enabled(),
      active.dynamic_policy.enabled(),
      active.telemetry.enabled(),
      active.system_access_log.enabled(),
      active.waf.has_person_proof_api_paths(),
    );
    let upstream_pool_generation = if config.upstream_pools == active.config.upstream_pools {
      active.upstream_pool_generation
    } else {
      active.upstream_pool_generation.saturating_add(1)
    };
    let stream_pool_generation =
      if config.stream_upstream_pools == active.config.stream_upstream_pools {
        active.stream_pool_generation
      } else {
        active.stream_pool_generation.saturating_add(1)
      };
    let waf_body_coding = crate::proxy::http::waf_body_coding::WafBodyCodingState::new_with_runtime(
      &config.waf.http_body_compression,
      active.overload.clone(),
    );
    let alt_svc_header_values = crate::state::build_alt_svc_header_values(&config)
      .context("failed to build precomputed Alt-Svc header values")?;
    let snapshot = AppSnapshot {
      runtime_topology: active.runtime_topology.clone(),
      hardening,
      route_table: active.route_table.clone(),
      sni_forward: active.sni_forward.clone(),
      upstreams: active.upstreams.clone(),
      upstream_uri_parts: active.upstream_uri_parts.clone(),
      upstream_uri_parts_by_index: active.upstream_uri_parts_by_index.clone(),
      compiled_fast_path_actions: active.compiled_fast_path_actions.clone(),
      config,
      secret_references: active.secret_references.clone(),
      effective_direct_h1_io: active.effective_direct_h1_io,
      clients: active.clients.clone(),
      direct_h1_pools: active.direct_h1_pools.clone(),
      direct_h2_pools: active.direct_h2_pools.clone(),
      health_check_clients: active.health_check_clients.clone(),
      control_http: active.control_http.clone(),
      h3_clients: active.h3_clients.clone(),
      outbound_revocation: active.outbound_revocation.clone(),
      compio_direct_h1_budget: active.compio_direct_h1_budget,
      compio_direct_h1_overlap_budget: active.compio_direct_h1_overlap_budget.clone(),
      direct_h1_plan_generation: active.direct_h1_plan_generation,
      compio_direct_h1_service: active.compio_direct_h1_service.clone(),
      staged_compio_direct_h1_service: None,
      compio_direct_h1_fleet_reservation: active.compio_direct_h1_fleet_reservation.clone(),
      upstream_pool_generation,
      stream_pool_generation,
      limits: active.limits.clone(),
      pools: active.pools.clone(),
      stream_pools: active.stream_pools.clone(),
      turn_pools: active.turn_pools.clone(),
      cache: active.cache.clone(),
      compression: active.compression.clone(),
      waf_body_coding,
      static_files: active.static_files.clone(),
      certificate_transparency: active.certificate_transparency.clone(),
      metrics: active.metrics.clone(),
      runtime_health: active.runtime_health.clone(),
      runtime_generation: active.runtime_generation,
      overload: active.overload.clone(),
      circuit_breakers: active.circuit_breakers.clone(),
      telemetry: active.telemetry.clone(),
      ipm,
      dynamic_policy: active.dynamic_policy.clone(),
      external_auth: active.external_auth.clone(),
      client_identity: active.client_identity.clone(),
      runtime_introspection: active.runtime_introspection.clone(),
      #[cfg(feature = "admin-runtime")]
      webtransport_admin: active.webtransport_admin.clone(),
      lifecycle: active.lifecycle.clone(),
      #[cfg(feature = "admin-runtime")]
      admin_audit: active.admin_audit.clone(),
      #[cfg(feature = "admin-runtime")]
      admin_mutations: active.admin_mutations.clone(),
      shared_state: active.shared_state.clone(),
      crlite,
      downstream_ct,
      ocsp_staple,
      tls_server_config,
      #[cfg(feature = "admin-runtime")]
      admin_tls_server_config: active.admin_tls_server_config.clone(),
      quic_server_config,
      #[cfg(feature = "admin-runtime")]
      admin_quic_server_config,
      tls_resumption: active.tls_resumption.clone(),
      waf: active.waf.clone(),
      mitigation: active.mitigation.clone(),
      access_logs: active.access_logs.clone(),
      system_access_log: active.system_access_log.clone(),
      request_path_features,
      alt_svc_header_values,
      http1_upgrades_possible: active.http1_upgrades_possible,
    };
    let pending = listeners.prepare(&snapshot).await?;
    state.replace(snapshot);
    let active = state.snapshot();
    listeners.commit(pending, active.as_ref(), state.clone());
    self.last_fingerprints = fingerprints;
    Ok(true)
  }

  fn load_config(&self) -> anyhow::Result<Config> {
    let mut config = Config::load(&self.config_path)
      .with_context(|| format!("failed to load {}", self.config_path.display()))?;
    for warning in config.apply_runtime_overrides(&self.runtime_overrides) {
      warn!("{warning}");
    }
    config.validate()?;
    Ok(config)
  }
}

pub(crate) fn validate_full_reload_runtime_compatibility(
  active: &Config,
  replacement: &Config,
) -> anyhow::Result<()> {
  if let FullReloadCompatibility::RestartRequired(reason) =
    classify_full_reload_runtime_compatibility(active, replacement)
  {
    bail!(reason.message(active, replacement));
  }
  Ok(())
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum FullReloadCompatibility {
  InProcess,
  RestartRequired(FullReloadRestartReason),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum FullReloadRestartReason {
  MainRuntime,
  TokioWorkers,
  RuntimeHardening,
  HotReloadManager,
  NetportSwitcher,
  CryptoProvider,
  LoggingLevel,
  MetricsListener,
  HealthListener,
  #[cfg(feature = "admin-runtime")]
  AdminMutations,
  #[cfg(feature = "admin-runtime")]
  AdminAudit,
  #[cfg(feature = "admin-runtime")]
  AdminOperations,
  #[cfg(feature = "admin-runtime")]
  AdminStorageAuthority,
}

impl FullReloadRestartReason {
  fn message(self, active: &Config, replacement: &Config) -> String {
    match self {
      Self::MainRuntime => format!(
        "full hot reload rejected because runtime.main_runtime would change the active main topology from {} to {}; restart OxiBelt to replace the main runtime",
        active.runtime.main_runtime.canonical().as_str(),
        replacement.runtime.main_runtime.canonical().as_str()
      ),
      Self::TokioWorkers => format!(
        "full hot reload rejected because runtime.workers.tokio changed from {} to {}; restart OxiBelt to resize the Tokio executor",
        active.runtime.workers.tokio, replacement.runtime.workers.tokio
      ),
      Self::RuntimeHardening => {
        "full hot reload rejected because runtime.hardening is an irreversible startup boundary"
          .to_string()
      }
      Self::HotReloadManager => {
        "full hot reload rejected because runtime.hot_reload manager ownership is restart-only"
          .to_string()
      }
      Self::NetportSwitcher => {
        "full hot reload rejected because runtime.netport_switcher process state is restart-only"
          .to_string()
      }
      Self::CryptoProvider => {
        "full hot reload rejected because crypto provider selection is process-global"
          .to_string()
      }
      Self::LoggingLevel => {
        "full hot reload rejected because logging.level is installed before the runtime starts"
          .to_string()
      }
      Self::MetricsListener => {
        "full hot reload rejected because metrics listener ownership is restart-only".to_string()
      }
      Self::HealthListener => {
        "full hot reload rejected because health listener ownership is restart-only".to_string()
      }
      #[cfg(feature = "admin-runtime")]
      Self::AdminMutations => {
        "full hot reload rejected because admin.mutations is a restart-only control-plane trust root"
          .to_string()
      }
      #[cfg(feature = "admin-runtime")]
      Self::AdminAudit => {
        "full hot reload rejected because admin.audit persistence, storage, or integrity authority is restart-only"
          .to_string()
      }
      #[cfg(feature = "admin-runtime")]
      Self::AdminOperations => {
        "full hot reload rejected because admin.operations runtime ownership is restart-only"
          .to_string()
      }
      #[cfg(feature = "admin-runtime")]
      Self::AdminStorageAuthority => {
        "full hot reload rejected because active Admin mutation audit, storage, and namespace authority are restart-only"
          .to_string()
      }
    }
  }
}

pub(crate) fn classify_full_reload_runtime_compatibility(
  active: &Config,
  replacement: &Config,
) -> FullReloadCompatibility {
  if replacement.runtime.main_runtime.canonical() != active.runtime.main_runtime.canonical() {
    return FullReloadCompatibility::RestartRequired(FullReloadRestartReason::MainRuntime);
  }
  if replacement.runtime.workers.tokio != active.runtime.workers.tokio {
    return FullReloadCompatibility::RestartRequired(FullReloadRestartReason::TokioWorkers);
  }
  if replacement.runtime.hardening != active.runtime.hardening {
    return FullReloadCompatibility::RestartRequired(FullReloadRestartReason::RuntimeHardening);
  }
  if replacement.runtime.hot_reload != active.runtime.hot_reload {
    return FullReloadCompatibility::RestartRequired(FullReloadRestartReason::HotReloadManager);
  }
  if replacement.runtime.netport_switcher != active.runtime.netport_switcher
    || replacement.runtime.unprivileged_mode != active.runtime.unprivileged_mode
  {
    return FullReloadCompatibility::RestartRequired(FullReloadRestartReason::NetportSwitcher);
  }
  if replacement.crypto != active.crypto {
    return FullReloadCompatibility::RestartRequired(FullReloadRestartReason::CryptoProvider);
  }
  if replacement.logging.level != active.logging.level {
    return FullReloadCompatibility::RestartRequired(FullReloadRestartReason::LoggingLevel);
  }
  if replacement.metrics.enabled != active.metrics.enabled
    || replacement.metrics.bind != active.metrics.bind
  {
    return FullReloadCompatibility::RestartRequired(FullReloadRestartReason::MetricsListener);
  }
  if replacement.health.enabled != active.health.enabled
    || replacement.health.bind != active.health.bind
  {
    return FullReloadCompatibility::RestartRequired(FullReloadRestartReason::HealthListener);
  }
  #[cfg(feature = "admin-runtime")]
  if replacement.admin.mutations != active.admin.mutations {
    return FullReloadCompatibility::RestartRequired(FullReloadRestartReason::AdminMutations);
  }
  #[cfg(feature = "admin-runtime")]
  if audit::validate_runtime_compatibility(active, replacement).is_err() {
    return FullReloadCompatibility::RestartRequired(FullReloadRestartReason::AdminAudit);
  }
  #[cfg(feature = "admin-runtime")]
  if replacement.admin.operations != active.admin.operations {
    return FullReloadCompatibility::RestartRequired(FullReloadRestartReason::AdminOperations);
  }
  #[cfg(feature = "admin-runtime")]
  if active.admin.mutations.mode.enabled()
    && (replacement.shared_state != active.shared_state
      || replacement.ipm.backend != active.ipm.backend
      || replacement.ipm.namespace != active.ipm.namespace)
  {
    return FullReloadCompatibility::RestartRequired(
      FullReloadRestartReason::AdminStorageAuthority,
    );
  }
  FullReloadCompatibility::InProcess
}

#[cfg(test)]
pub(crate) fn classify_runtime_topology_change(
  active: &Config,
  replacement: &Config,
) -> RuntimeTopologyChangePlan {
  if replacement.runtime.main_runtime.canonical() != active.runtime.main_runtime.canonical()
    || replacement.runtime.workers.tokio != active.runtime.workers.tokio
  {
    RuntimeTopologyChangePlan::RestartRequired
  } else {
    RuntimeTopologyChangePlan::InProcess
  }
}

pub(crate) fn reload_downstream_tls_paths(config: &mut Config) -> anyhow::Result<()> {
  let cert_dir = config
    .source_paths
    .cert_dir
    .as_ref()
    .ok_or_else(|| anyhow::anyhow!("missing TLS certificate directory for downstream reload"))?;
  let cert_chain = config
    .source_paths
    .downstream_tls_cert_chain
    .as_ref()
    .ok_or_else(|| anyhow::anyhow!("missing configured tls.cert_chain path"))?;
  let private_key = config.source_paths.downstream_tls_private_key.as_ref();

  let ocsp = config
    .source_paths
    .downstream_tls_ocsp_response_file
    .as_ref()
    .map(|path| canonicalize_under_base("tls.ocsp.response_file", cert_dir, path))
    .transpose()?;
  let crlite_filter = config
    .source_paths
    .downstream_tls_crlite_filter_file
    .as_ref()
    .map(|path| canonicalize_under_base("tls.crlite.filter_file", cert_dir, path))
    .transpose()?;
  let ct_log_list_file = config
    .source_paths
    .downstream_tls_ct_log_list_file
    .as_ref()
    .map(|path| canonicalize_under_base("tls.ct.log_list.file", cert_dir, path))
    .transpose()?;
  let ct_log_list_signature_file = config
    .source_paths
    .downstream_tls_ct_log_list_signature_file
    .as_ref()
    .map(|path| canonicalize_under_base("tls.ct.log_list.signature_file", cert_dir, path))
    .transpose()?;
  let quic_host_key_file = config
    .source_paths
    .quic_host_key_file
    .as_ref()
    .map(|path| canonicalize_under_base("quic.host_key_file", cert_dir, path))
    .transpose()?;
  let remote_signer_token_file = config
    .source_paths
    .downstream_tls_remote_signer_token_file
    .as_ref()
    .map(|path| canonicalize_under_base("tls.remote_signer.token_file", cert_dir, path))
    .transpose()?;

  let old_tls = config.tls.clone();
  let mut remote_signer = old_tls.remote_signer.clone();
  remote_signer.token_file = remote_signer_token_file;
  remote_signer.token_file_reload_path = config
    .source_paths
    .downstream_tls_remote_signer_token_file
    .clone();
  remote_signer.token_file_reload_base_dir = remote_signer
    .token_file_reload_path
    .as_ref()
    .map(|_| cert_dir.clone());
  let mut old_quic = config.quic.clone();
  old_quic.host_key_file = quic_host_key_file;
  if old_tls.certificates.len() != config.source_paths.downstream_tls_certificates.len() {
    anyhow::bail!("configured tls.certificates path metadata is incomplete");
  }
  let certificates = old_tls
    .certificates
    .into_iter()
    .zip(config.source_paths.downstream_tls_certificates.iter())
    .enumerate()
    .map(|(index, (mut certificate, paths))| {
      certificate.cert_chain = canonicalize_under_base(
        &format!("tls.certificates[{index}].cert_chain"),
        cert_dir,
        &paths.cert_chain,
      )?;
      certificate.private_key = paths
        .private_key
        .as_ref()
        .map(|path| {
          canonicalize_under_base(
            &format!("tls.certificates[{index}].private_key"),
            cert_dir,
            path,
          )
        })
        .transpose()?;
      certificate.ocsp.response_file = paths
        .ocsp_response_file
        .as_ref()
        .map(|path| {
          canonicalize_under_base(
            &format!("tls.certificates[{index}].ocsp.response_file"),
            cert_dir,
            path,
          )
        })
        .transpose()?;
      Ok::<_, anyhow::Error>(certificate)
    })
    .collect::<anyhow::Result<Vec<_>>>()?;
  config.tls = TlsConfig {
    server_names: old_tls.server_names,
    cert_chain: canonicalize_under_base("tls.cert_chain", cert_dir, cert_chain)?,
    private_key: private_key
      .map(|path| canonicalize_under_base("tls.private_key", cert_dir, path))
      .transpose()?,
    remote_signer,
    require_sni: old_tls.require_sni,
    reject_unknown_sni: old_tls.reject_unknown_sni,
    ssl_early_data: old_tls.ssl_early_data,
    certificates,
    min_version: old_tls.min_version,
    max_version: old_tls.max_version,
    tls12: old_tls.tls12,
    tls13: old_tls.tls13,
    key_exchange_groups: old_tls.key_exchange_groups,
    session_tickets: old_tls.session_tickets,
    session_ticket_rotation_seconds: old_tls.session_ticket_rotation_seconds,
    resumption: old_tls.resumption,
    client_auth: old_tls.client_auth,
    ocsp: crate::config::OcspConfig {
      mode: old_tls.ocsp.mode,
      response_file: ocsp,
      responder_url: old_tls.ocsp.responder_url,
      request_timeout_ms: old_tls.ocsp.request_timeout_ms,
      max_response_bytes: old_tls.ocsp.max_response_bytes,
      refresh_jitter_pct: old_tls.ocsp.refresh_jitter_pct,
      clock_skew_seconds: old_tls.ocsp.clock_skew_seconds,
    },
    crlite: crate::config::CrliteConfig {
      mode: old_tls.crlite.mode,
      filter_file: crlite_filter,
      filter_sha256: old_tls.crlite.filter_sha256,
      max_filter_bytes: old_tls.crlite.max_filter_bytes,
      max_filter_age_seconds: old_tls.crlite.max_filter_age_seconds,
      failure_policy: old_tls.crlite.failure_policy,
      coverage_policy: old_tls.crlite.coverage_policy,
      managed: old_tls.crlite.managed,
    },
    ct: crate::config::DownstreamCtConfig {
      log_list: crate::config::DownstreamCtLogListConfig {
        file: ct_log_list_file,
        signature_file: ct_log_list_signature_file,
        ..old_tls.ct.log_list
      },
      mode: old_tls.ct.mode,
      policy: old_tls.ct.policy,
      failure_policy: old_tls.ct.failure_policy,
    },
  };
  config.quic = old_quic;
  Ok(())
}

fn canonicalize_under_base(
  field_name: &str,
  base_dir: &Path,
  path: &Path,
) -> anyhow::Result<PathBuf> {
  let canonical_base = base_dir.canonicalize().with_context(|| {
    format!(
      "failed to resolve configured directory {}",
      base_dir.display()
    )
  })?;
  let canonical_path = path
    .canonicalize()
    .with_context(|| format!("failed to resolve {field_name} {}", path.display()))?;
  if !canonical_path.starts_with(&canonical_base) {
    bail!("{field_name} must stay within the configured directory");
  }
  let metadata = canonical_path.metadata().with_context(|| {
    format!(
      "failed to inspect {field_name} {}",
      canonical_path.display()
    )
  })?;
  if !metadata.is_file() {
    bail!("{field_name} must point to a regular file");
  }
  Ok(canonical_path)
}

fn relevant_files(mode: HotReloadMode, config: &Config) -> Vec<PathBuf> {
  match mode {
    HotReloadMode::Off => Vec::new(),
    HotReloadMode::OxiRule => config.source_paths.oxirule_reload_files(),
    HotReloadMode::Full => config.source_paths.all_reload_files(),
    HotReloadMode::DownstreamTls => config.source_paths.downstream_tls_reload_files(),
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct FileFingerprint {
  path: PathBuf,
  exists: bool,
  len: u64,
  modified: Option<SystemTime>,
  canonical: Option<PathBuf>,
}

fn fingerprint_files(mut paths: Vec<PathBuf>) -> Vec<FileFingerprint> {
  paths.sort();
  paths.dedup();
  paths.into_iter().map(fingerprint_file).collect()
}

fn fingerprint_file(path: PathBuf) -> FileFingerprint {
  match fs::metadata(&path) {
    Ok(metadata) => FileFingerprint {
      canonical: path.canonicalize().ok(),
      path,
      exists: true,
      len: metadata.len(),
      modified: metadata.modified().ok(),
    },
    Err(_) => FileFingerprint {
      path,
      exists: false,
      len: 0,
      modified: None,
      canonical: None,
    },
  }
}

#[cfg(test)]
mod tests;

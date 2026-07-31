//! Configuration loading, effective rendering, overrides, and equivalence.

use super::*;

impl Config {
  pub fn load(path: &Path) -> anyhow::Result<Self> {
    let path_roots = config_path_roots(path)?;
    let mut loaded = load_toml_with_includes(path)?;
    normalize_merged_lb_policy_compat(&mut loaded.value)?;
    validate_merged_toml_shape(&loaded.value)?;
    let mut config: Self = loaded
      .value
      .try_into()
      .with_context(|| format!("failed to decode merged TOML from {}", path.display()))?;
    config.source_paths.config_entry = Some(absolute_config_path(path)?);
    config.source_paths.config_files = loaded.files;
    config.source_paths.field_origins = loaded.origins;
    config.resolve_relative_paths(&path_roots)?;
    config.load_external_waf_rules()?;
    config.normalize_loaded_waf_lb_policy_compat()?;
    config.collect_loaded_waf_rule_paths();
    config.resolve_rollout_identity_from_environment()?;
    Ok(config)
  }

  pub(crate) fn load_with_config_file_overrides(
    path: &Path,
    overrides: &HashMap<PathBuf, Option<String>>,
  ) -> anyhow::Result<Self> {
    let path_roots = config_path_roots(path)?;
    let mut loaded = load_toml_with_includes_and_overrides(path, overrides)?;
    normalize_merged_lb_policy_compat(&mut loaded.value)?;
    validate_merged_toml_shape(&loaded.value)?;
    let mut config: Self = loaded
      .value
      .try_into()
      .with_context(|| format!("failed to decode merged TOML from {}", path.display()))?;
    config.source_paths.config_entry = Some(absolute_config_path(path)?);
    config.source_paths.config_files = loaded.files;
    config.source_paths.field_origins = loaded.origins;
    config.resolve_relative_paths(&path_roots)?;
    config.load_external_waf_rules()?;
    config.normalize_loaded_waf_lb_policy_compat()?;
    config.collect_loaded_waf_rule_paths();
    config.resolve_rollout_identity_from_environment()?;
    Ok(config)
  }

  pub fn load_effective_toml_redacted(path: &Path) -> anyhow::Result<toml::Value> {
    Ok(Self::redact_effective_toml_value(
      &Self::load_effective_toml_for_activation(path)?,
    ))
  }

  pub(crate) fn redact_effective_toml_value(value: &toml::Value) -> toml::Value {
    let mut redacted = value.clone();
    redact_effective_toml(&mut redacted);
    redacted
  }

  pub(crate) fn load_effective_toml_for_activation(path: &Path) -> anyhow::Result<toml::Value> {
    let loaded = load_toml_with_includes(path)?;
    let mut value = loaded.value;
    operational_profile::apply_to_toml(&mut value)?;
    normalize_merged_lb_policy_compat(&mut value)?;
    validate_merged_toml_shape(&value)?;
    let config = Self::load(path)?;
    config.validate()?;
    config.write_resolved_workers_to_toml(&mut value)?;
    Ok(value)
  }

  pub fn load_lb_policy_compat_report(
    path: &Path,
    profile: LbPolicyCompatProfile,
  ) -> anyhow::Result<LbPolicyCompatReport> {
    let loaded = load_toml_with_includes(path)?;
    let mut value = loaded.value;
    operational_profile::apply_to_toml(&mut value)?;
    let diagnostics = lb_policy_compat::normalize_toml_with_profile(&mut value, profile);
    let converted_toml = toml::to_string_pretty(&value)
      .with_context(|| format!("failed to render converted TOML from {}", path.display()))?;
    Ok(LbPolicyCompatReport {
      profile: profile.as_str(),
      converted_toml,
      diagnostics,
    })
  }

  pub fn log_worker_resolution(&self) {
    let resolution = self.runtime.worker_resolution;
    if let Some(error) = resolution.fallback_error {
      tracing::warn!(
        error,
        fallback_parallelism = resolution.available_parallelism,
        "worker auto-scaling fell back to one available thread"
      );
    }
    tracing::info!(
      available_parallelism = resolution.available_parallelism,
      runtime_multiplier = resolution.runtime_multiplier,
      tokio_multiplier = resolution.tokio_multiplier,
      compio_direct_h1_multiplier = resolution.compio_direct_h1_multiplier,
      accept_multiplier = resolution.accept_multiplier,
      quic_socket_multiplier = resolution.quic_socket_multiplier,
      runtime_worker_threads = self.runtime.worker_threads,
      tokio_workers = self.runtime.workers.tokio,
      compio_direct_h1_workers = self.runtime.workers.compio_direct_h1,
      accept_workers = self.runtime.accept.workers,
      quic_socket_workers = self.quic.socket.workers,
      "resolved worker auto-scaling"
    );
  }

  pub fn downstream_tcp_early_data_enabled(&self) -> bool {
    self
      .tls
      .ssl_early_data
      .is_some_and(TlsEarlyDataMode::is_enabled)
      || self.routes.iter().any(|route| {
        route
          .tls
          .ssl_early_data
          .is_some_and(TlsEarlyDataMode::is_enabled)
      })
  }

  pub(super) fn downstream_tls12_allowed(&self) -> bool {
    self.tls.min_version <= TlsVersion::Tls12
      || self.routes.iter().any(|route| {
        self
          .tls
          .effective_route_negotiation_policy(&route.tls)
          .allows_tls12()
      })
  }

  pub fn downstream_tcp_early_data_max_bytes(&self) -> u32 {
    let header_budget = self.limits.max_total_header_bytes.max(8192) as u64;
    let body_budget = self.limits.max_request_body_bytes;
    header_budget
      .saturating_add(body_budget)
      .min(u32::MAX as u64) as u32
  }

  pub fn apply_runtime_overrides(&mut self, overrides: &RuntimeOverrides) -> Vec<String> {
    let mut warnings = Vec::new();
    if let Some(mode) = overrides.hot_reload_mode {
      if self.runtime.hot_reload.mode != mode {
        warnings.push(format!(
          "CLI --hot-reload-mode={mode} overrides runtime.hot_reload.mode={}",
          self.runtime.hot_reload.mode
        ));
      }
      self.runtime.hot_reload.mode = mode;
    }
    if let Some(poll_interval_ms) = overrides.hot_reload_poll_interval_ms {
      if self.runtime.hot_reload.poll_interval_ms != poll_interval_ms {
        warnings.push(format!(
          "CLI --hot-reload-poll-interval-ms={poll_interval_ms} overrides runtime.hot_reload.poll_interval_ms={}",
          self.runtime.hot_reload.poll_interval_ms
        ));
      }
      self.runtime.hot_reload.poll_interval_ms = poll_interval_ms;
    }
    warnings
  }

  pub(super) fn write_resolved_workers_to_toml(
    &self,
    value: &mut toml::Value,
  ) -> anyhow::Result<()> {
    set_toml_value_path(
      value,
      &["runtime", "main_runtime"],
      toml::Value::String(self.runtime.main_runtime.as_str().to_string()),
    )?;
    set_toml_value_path(
      value,
      &["runtime", "topology_policy"],
      toml::Value::String(self.runtime.topology_policy.as_str().to_string()),
    )?;
    set_toml_integer_path(
      value,
      &["runtime", "worker_threads"],
      self.runtime.worker_threads,
    )?;
    set_toml_integer_path(
      value,
      &["runtime", "workers", "tokio"],
      self.runtime.workers.tokio,
    )?;
    set_toml_integer_path(
      value,
      &["runtime", "workers", "compio_direct_h1"],
      self.runtime.workers.compio_direct_h1,
    )?;
    set_toml_float_path(
      value,
      &["runtime", "worker_multipliers", "runtime"],
      self.runtime.worker_multipliers.runtime,
    )?;
    set_toml_float_path(
      value,
      &["runtime", "worker_multipliers", "tokio"],
      self.runtime.worker_multipliers.tokio,
    )?;
    set_toml_float_path(
      value,
      &["runtime", "worker_multipliers", "compio_direct_h1"],
      self.runtime.worker_multipliers.compio_direct_h1,
    )?;
    set_toml_float_path(
      value,
      &["runtime", "worker_multipliers", "accept"],
      self.runtime.worker_multipliers.accept,
    )?;
    set_toml_float_path(
      value,
      &["runtime", "worker_multipliers", "quic_socket"],
      self.runtime.worker_multipliers.quic_socket,
    )?;
    set_toml_integer_path(
      value,
      &["runtime", "accept", "workers"],
      self.runtime.accept.workers,
    )?;
    set_toml_integer_path(
      value,
      &["quic", "socket", "workers"],
      self.quic.socket.workers,
    )
  }

  pub fn non_waf_equivalent(&self, other: &Self) -> bool {
    self.logging == other.logging
      && self.config == other.config
      && self.operational_profile == other.operational_profile
      && self.runtime == other.runtime
      && self.rollout == other.rollout
      && self.crypto == other.crypto
      && self.listeners == other.listeners
      && self.tls == other.tls
      && self.quic == other.quic
      && self.proxy == other.proxy
      && self.limits == other.limits
      && self.rate_limits == other.rate_limits
      && self.connection_limits == other.connection_limits
      && self.client_identity == other.client_identity
      && self.compression == other.compression
      && self.cache == other.cache
      && self.ipm == other.ipm
      && self.admin == other.admin
      && self.metrics == other.metrics
      && self.telemetry == other.telemetry
      && self.health == other.health
      && self.overload == other.overload
      && self.circuit_breakers == other.circuit_breakers
      && self.security == other.security
      && self.database == other.database
      && self.shared_state == other.shared_state
      && self.dynamic_policy == other.dynamic_policy
      && self.external_auth == other.external_auth
      && self.upstreams == other.upstreams
      && self.upstream_pools == other.upstream_pools
      && self.turn_upstream_pools == other.turn_upstream_pools
      && self.stream_upstream_pools == other.stream_upstream_pools
      && self.sni_forward == other.sni_forward
      && self.stream_listeners == other.stream_listeners
      && self.webrtc_turn_listeners == other.webrtc_turn_listeners
      && routes_without_waf_are_equivalent(&self.routes, &other.routes)
  }

  pub fn waf_equivalent(&self, other: &Self) -> bool {
    self.waf == other.waf && route_waf_configs_are_equivalent(&self.routes, &other.routes)
  }
}

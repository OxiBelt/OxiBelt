//! Configuration parsing and validation for every runtime boundary.
//! This module keeps defaults explicit before listeners, proxying, WAF, and admin code consume them.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, anyhow, bail};
use base64::Engine;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::waf::WafConfig;

mod access_log;
mod admin_audit;
mod admin_legacy;
mod admin_runtime;
mod allowed_keys;
mod cache_external;
mod cache_sections;
mod circuit_breakers;
mod client_identity;
mod compression;
mod crlite;
mod crypto;
mod database;
mod dynamic_policy;
mod external_auth;
mod http2;
mod http3;
mod ipm;
mod lb_policy_compat;
mod limits;
mod listener;
mod loader;
mod logging;
mod outbound_revocation;
mod overload;
mod quic;
mod rate_limit;
mod retry;
mod rollout_identity;
mod route;
mod route_actions;
mod route_header_policy;
mod route_static_files;
mod route_tls_policy;
mod runtime_hardening;
mod security_headers;
mod shared_state;
mod sni_forward;
mod source_paths;
mod static_files;
mod stream;
mod telemetry;
mod tls;
mod turn;
mod turn_queue;
mod upstream_pool;
mod workers;
pub use access_log::*;
pub use admin_audit::*;
use admin_legacy::{LegacyAdminRbacConfig, LegacyAdminTokenStoreConfig};
pub use cache_external::{
  ExternalCacheHandlerConfig, ExternalCacheHandlerFailPolicy, ExternalCacheHandlerKind,
};
pub use cache_sections::{
  CacheAdmissionConfig, CachePolicyRuleConfig, CacheStaleIfErrorConfig, CacheSurrogateConfig,
};
pub use circuit_breakers::*;
pub use client_identity::*;
pub use compression::*;
pub use crlite::*;
pub use crypto::*;
pub use database::*;
pub use dynamic_policy::*;
pub use external_auth::*;
pub use http2::*;
pub use http3::*;
pub use ipm::*;
pub use lb_policy_compat::*;
use limits::{
  default_max_connections, default_max_connections_per_ip, default_max_requests_per_connection,
  default_max_webtransport_sessions_per_connection,
};
pub use listener::{HttpListenerMode, ListenerConfig, ProxyProtocolConfig, ProxyProtocolVersion};
use listener::{RawListenerConfig, validate_bind_list, validate_bind_lists_do_not_overlap};
use loader::{
  absolute_config_path, load_toml_with_includes, load_toml_with_includes_and_overrides,
};
pub use logging::*;
pub use outbound_revocation::*;
pub use overload::*;
pub(crate) use quic::RawQuicTransportConfig;
pub use quic::*;
pub use rate_limit::*;
pub use retry::*;
pub use rollout_identity::{ConfigRolloutApplyState, ConfigRolloutIdentity, ConfigRolloutMode};
pub use route::*;
pub use route_actions::*;
pub use route_header_policy::*;
pub use route_static_files::*;
pub use runtime_hardening::*;
pub use security_headers::*;
pub use shared_state::{
  BackendFailureMode, RedisAuthConfig, RedisPlaintextPolicy, RedisPoolConfig, RedisTlsConfig,
  RedisTrustStore, SharedStateBackendConfig, SharedStateBackendKind, SharedStateConfig,
  SharedStateFailurePolicies,
};
pub(crate) use shared_state::{
  RedisPoolSettings, default_shared_state_namespace, validate_redis_connection_url,
};
pub use sni_forward::*;
pub use source_paths::{ConfigSourcePaths, DownstreamTlsCertificateSourcePaths};
pub use static_files::*;
pub use stream::*;
pub use telemetry::*;
pub use tls::*;
use turn::RawWebRtcTurnListenerConfig;
pub use turn::*;
pub use upstream_pool::*;
pub use workers::*;

/// Fully validated runtime configuration consumed by listeners, proxying, WAF, and admin code.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
  pub access_log: AccessLogConfig,
  pub config: ConfigBehaviorConfig,
  pub logging: LoggingConfig,
  pub runtime: RuntimeConfig,
  pub crypto: CryptoConfig,
  pub listeners: ListenerConfig,
  pub tls: TlsConfig,
  pub quic: QuicConfig,
  pub proxy: ProxyConfig,
  pub limits: LimitsConfig,
  pub rate_limits: Vec<RateLimitConfig>,
  pub connection_limits: Vec<ConnectionLimitConfig>,
  pub client_identity: ClientIdentityConfig,
  pub compression: CompressionConfig,
  pub cache: CacheConfig,
  pub ipm: IpmConfig,
  pub admin: AdminConfig,
  pub metrics: MetricsConfig,
  pub telemetry: TelemetryConfig,
  pub health: HealthConfig,
  pub overload: OverloadConfig,
  pub circuit_breakers: CircuitBreakersConfig,
  pub security: SecurityConfig,
  pub database: DatabaseConfig,
  pub shared_state: SharedStateConfig,
  pub dynamic_policy: DynamicPolicyConfig,
  pub external_auth: Vec<ExternalAuthConfig>,
  pub upstreams: Vec<UpstreamConfig>,
  pub upstream_pools: Vec<UpstreamPoolConfig>,
  pub turn_upstream_pools: Vec<TurnUpstreamPoolConfig>,
  pub stream_upstream_pools: Vec<StreamUpstreamPoolConfig>,
  pub sni_forward: SniForwardConfig,
  pub stream_listeners: Vec<StreamListenerConfig>,
  pub webrtc_turn_listeners: Vec<WebRtcTurnListenerConfig>,
  pub routes: Vec<RouteConfig>,
  pub waf: WafConfig,
  pub source_paths: ConfigSourcePaths,
  pub rollout: ConfigRolloutIdentity,
}

#[derive(Debug, Deserialize)]
struct RawConfig {
  #[serde(default)]
  access_log: AccessLogConfig,
  #[serde(default)]
  config: ConfigBehaviorConfig,
  #[serde(default)]
  logging: LoggingConfig,
  #[serde(default)]
  runtime: RawRuntimeConfig,
  #[serde(default)]
  crypto: CryptoConfig,
  listeners: RawListenerConfig,
  tls: TlsConfig,
  #[serde(default)]
  quic: RawQuicConfig,
  #[serde(default)]
  proxy: ProxyConfig,
  #[serde(default)]
  limits: LimitsConfig,
  #[serde(default)]
  rate_limits: Vec<RateLimitConfig>,
  #[serde(default)]
  connection_limits: Vec<ConnectionLimitConfig>,
  #[serde(default)]
  client_identity: ClientIdentityConfig,
  #[serde(default)]
  compression: CompressionConfig,
  #[serde(default)]
  cache: CacheConfig,
  #[serde(default)]
  ipm: IpmConfig,
  #[serde(default)]
  admin: AdminConfig,
  #[serde(default)]
  metrics: MetricsConfig,
  #[serde(default)]
  telemetry: TelemetryConfig,
  #[serde(default)]
  health: HealthConfig,
  #[serde(default)]
  overload: OverloadConfig,
  #[serde(default)]
  circuit_breakers: CircuitBreakersConfig,
  #[serde(default)]
  security: SecurityConfig,
  #[serde(default)]
  database: DatabaseConfig,
  #[serde(default)]
  shared_state: SharedStateConfig,
  #[serde(default)]
  dynamic_policy: DynamicPolicyConfig,
  #[serde(default)]
  external_auth: Vec<ExternalAuthConfig>,
  #[serde(default)]
  upstreams: Vec<UpstreamConfig>,
  #[serde(default)]
  upstream_pools: Vec<UpstreamPoolConfig>,
  #[serde(default)]
  turn_upstream_pools: Vec<TurnUpstreamPoolConfig>,
  #[serde(default)]
  stream_upstream_pools: Vec<StreamUpstreamPoolConfig>,
  #[serde(default)]
  sni_forward: SniForwardConfig,
  #[serde(default)]
  stream_listeners: Vec<StreamListenerConfig>,
  #[serde(default)]
  webrtc_turn_listeners: Vec<RawWebRtcTurnListenerConfig>,
  #[serde(default)]
  routes: Vec<RouteConfig>,
  #[serde(default)]
  waf: WafConfig,
}

impl TryFrom<RawConfig> for Config {
  type Error = anyhow::Error;

  fn try_from(raw: RawConfig) -> Result<Self, Self::Error> {
    let parallelism = WorkerParallelism::detect();
    let runtime = RuntimeConfig::resolve(raw.runtime, parallelism)?;
    let quic = QuicConfig::resolve(raw.quic, runtime.worker_multipliers, parallelism)?;
    let webrtc_turn_listeners = raw
      .webrtc_turn_listeners
      .into_iter()
      .map(|listener| listener.resolve(parallelism.available))
      .collect::<anyhow::Result<Vec<_>>>()?;
    let listeners = raw.listeners.resolve()?;
    Ok(Self {
      access_log: raw.access_log,
      config: raw.config,
      logging: raw.logging,
      runtime,
      crypto: raw.crypto,
      listeners,
      tls: raw.tls,
      quic,
      proxy: raw.proxy,
      limits: raw.limits,
      rate_limits: raw.rate_limits,
      connection_limits: raw.connection_limits,
      client_identity: raw.client_identity,
      compression: raw.compression,
      cache: raw.cache,
      ipm: raw.ipm,
      admin: raw.admin,
      metrics: raw.metrics,
      telemetry: raw.telemetry,
      health: raw.health,
      overload: raw.overload,
      circuit_breakers: raw.circuit_breakers,
      security: raw.security,
      database: raw.database,
      shared_state: raw.shared_state,
      dynamic_policy: raw.dynamic_policy,
      external_auth: raw.external_auth,
      upstreams: raw.upstreams,
      upstream_pools: raw.upstream_pools,
      turn_upstream_pools: raw.turn_upstream_pools,
      stream_upstream_pools: raw.stream_upstream_pools,
      sni_forward: raw.sni_forward,
      stream_listeners: raw.stream_listeners,
      webrtc_turn_listeners,
      routes: raw.routes,
      waf: raw.waf,
      source_paths: ConfigSourcePaths::default(),
      rollout: ConfigRolloutIdentity::default(),
    })
  }
}

impl<'de> Deserialize<'de> for Config {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    let mut value = toml::Value::deserialize(deserializer)?;
    let diagnostics =
      lb_policy_compat::normalize_toml_from_config(&mut value).map_err(serde::de::Error::custom)?;
    lb_policy_compat::ensure_supported(&diagnostics).map_err(serde::de::Error::custom)?;
    reject_removed_access_log_config(&value).map_err(serde::de::Error::custom)?;
    RawConfig::deserialize(value)
      .map_err(serde::de::Error::custom)?
      .try_into()
      .map_err(serde::de::Error::custom)
  }
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeOverrides {
  pub hot_reload_mode: Option<HotReloadMode>,
  pub hot_reload_poll_interval_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ConfigBehaviorConfig {
  #[serde(default = "default_true")]
  pub strict_unknown_fields: bool,
  #[serde(default = "default_true")]
  pub warn_on_deprecated_fields: bool,
  #[serde(default)]
  pub lb_policy_compat_profile: LbPolicyCompatProfile,
}

impl Default for ConfigBehaviorConfig {
  fn default() -> Self {
    Self {
      strict_unknown_fields: true,
      warn_on_deprecated_fields: true,
      lb_policy_compat_profile: LbPolicyCompatProfile::Strict,
    }
  }
}

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
    config.resolve_relative_paths(&path_roots)?;
    config.load_external_waf_rules()?;
    config.normalize_loaded_waf_lb_policy_compat()?;
    config.collect_loaded_waf_rule_paths();
    config.resolve_rollout_identity_from_environment()?;
    Ok(config)
  }

  pub fn load_effective_toml_redacted(path: &Path) -> anyhow::Result<toml::Value> {
    let loaded = load_toml_with_includes(path)?;
    let mut value = loaded.value;
    normalize_merged_lb_policy_compat(&mut value)?;
    validate_merged_toml_shape(&value)?;
    let config = Self::load(path)?;
    config.validate()?;
    config.write_resolved_workers_to_toml(&mut value)?;
    redact_effective_toml(&mut value);
    Ok(value)
  }

  pub fn load_lb_policy_compat_report(
    path: &Path,
    profile: LbPolicyCompatProfile,
  ) -> anyhow::Result<LbPolicyCompatReport> {
    let loaded = load_toml_with_includes(path)?;
    let mut value = loaded.value;
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
      accept_multiplier = resolution.accept_multiplier,
      quic_socket_multiplier = resolution.quic_socket_multiplier,
      runtime_worker_threads = self.runtime.worker_threads,
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

  fn downstream_tls12_allowed(&self) -> bool {
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

  fn write_resolved_workers_to_toml(&self, value: &mut toml::Value) -> anyhow::Result<()> {
    set_toml_integer_path(
      value,
      &["runtime", "worker_threads"],
      self.runtime.worker_threads,
    )?;
    set_toml_float_path(
      value,
      &["runtime", "worker_multipliers", "runtime"],
      self.runtime.worker_multipliers.runtime,
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

  fn resolve_relative_paths(&mut self, path_roots: &ConfigPathRoots) -> anyhow::Result<()> {
    self.source_paths.config_dir = Some(path_roots.config_dir.clone());
    self.source_paths.cert_dir = Some(path_roots.cert_dir.clone());
    self.source_paths.oxirule_dir = Some(path_roots.oxirule_dir.clone());
    let (tls_cert_chain, tls_cert_chain_logical) =
      resolve_existing_local_config_file_path_with_logical(
        "tls.cert_chain",
        &path_roots.cert_dir,
        &self.tls.cert_chain,
      )?;
    self.tls.cert_chain = tls_cert_chain;
    self
      .source_paths
      .remember_runtime_file(tls_cert_chain_logical.clone());
    self
      .source_paths
      .remember_downstream_tls_file(tls_cert_chain_logical.clone());
    self.source_paths.downstream_tls_cert_chain = Some(tls_cert_chain_logical);

    if let Some(private_key) = self.tls.private_key.take() {
      let (tls_private_key, tls_private_key_logical) =
        resolve_existing_local_config_file_path_with_logical(
          "tls.private_key",
          &path_roots.cert_dir,
          &private_key,
        )?;
      self.tls.private_key = Some(tls_private_key);
      self
        .source_paths
        .remember_runtime_file(tls_private_key_logical.clone());
      self
        .source_paths
        .remember_downstream_tls_file(tls_private_key_logical.clone());
      self.source_paths.downstream_tls_private_key = Some(tls_private_key_logical);
    }

    self.source_paths.downstream_tls_certificates.clear();
    for (index, certificate) in self.tls.certificates.iter_mut().enumerate() {
      let (cert_chain, cert_logical) = resolve_existing_local_config_file_path_with_logical(
        &format!("tls.certificates[{index}].cert_chain"),
        &path_roots.cert_dir,
        &certificate.cert_chain,
      )?;
      certificate.cert_chain = cert_chain;
      self
        .source_paths
        .remember_runtime_file(cert_logical.clone());
      self
        .source_paths
        .remember_downstream_tls_file(cert_logical.clone());

      let private_key_logical = certificate
        .private_key
        .take()
        .map(|private_key| {
          let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
            &format!("tls.certificates[{index}].private_key"),
            &path_roots.cert_dir,
            &private_key,
          )?;
          certificate.private_key = Some(resolved);
          self.source_paths.remember_runtime_file(logical.clone());
          self
            .source_paths
            .remember_downstream_tls_file(logical.clone());
          Ok::<PathBuf, anyhow::Error>(logical)
        })
        .transpose()?;

      let ocsp_response_logical = certificate
        .ocsp
        .response_file
        .take()
        .map(|response_file| {
          let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
            &format!("tls.certificates[{index}].ocsp.response_file"),
            &path_roots.cert_dir,
            &response_file,
          )?;
          certificate.ocsp.response_file = Some(resolved);
          self.source_paths.remember_runtime_file(logical.clone());
          self
            .source_paths
            .remember_downstream_tls_file(logical.clone());
          Ok::<PathBuf, anyhow::Error>(logical)
        })
        .transpose()?;

      self
        .source_paths
        .downstream_tls_certificates
        .push(DownstreamTlsCertificateSourcePaths {
          cert_chain: cert_logical,
          private_key: private_key_logical,
          ocsp_response_file: ocsp_response_logical,
        });
    }

    self.tls.remote_signer.token_file = self
      .tls
      .remote_signer
      .token_file
      .take()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "tls.remote_signer.token_file",
          &path_roots.cert_dir,
          &path,
        )?;
        self.tls.remote_signer.token_file_reload_path = Some(logical.clone());
        self.tls.remote_signer.token_file_reload_base_dir = Some(path_roots.cert_dir.clone());
        self.source_paths.remember_runtime_file(logical.clone());
        self
          .source_paths
          .remember_downstream_tls_file(logical.clone());
        self.source_paths.downstream_tls_remote_signer_token_file = Some(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .transpose()?;

    self.tls.ocsp.response_file = self
      .tls
      .ocsp
      .response_file
      .take()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "tls.ocsp.response_file",
          &path_roots.cert_dir,
          &path,
        )?;
        self.source_paths.remember_runtime_file(logical.clone());
        self
          .source_paths
          .remember_downstream_tls_file(logical.clone());
        self.source_paths.downstream_tls_ocsp_response_file = Some(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .transpose()?;
    crlite::resolve_filter_file(
      &mut self.tls.crlite,
      &mut self.source_paths,
      &path_roots.cert_dir,
    )?;
    client_identity::resolve_asn_database_file(
      &mut self.client_identity.asn,
      &mut self.source_paths,
      &path_roots.config_dir,
    )?;
    self.tls.client_auth.ca_certs = self
      .tls
      .client_auth
      .ca_certs
      .iter()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "tls.client_auth.ca_certs",
          &path_roots.cert_dir,
          path,
        )?;
        self.source_paths.remember_runtime_file(logical.clone());
        self.source_paths.remember_downstream_tls_file(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .collect::<anyhow::Result<_>>()?;
    self.proxy.trusted_ca_certs = self
      .proxy
      .trusted_ca_certs
      .iter()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "proxy.trusted_ca_certs",
          &path_roots.cert_dir,
          path,
        )?;
        self.source_paths.remember_runtime_file(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .collect::<anyhow::Result<_>>()?;
    self.access_log.otlp.trusted_ca_certs = self
      .access_log
      .otlp
      .trusted_ca_certs
      .iter()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "access_log.otlp.trusted_ca_certs",
          &path_roots.cert_dir,
          path,
        )?;
        self.source_paths.remember_runtime_file(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .collect::<anyhow::Result<_>>()?;
    outbound_revocation::resolve_outbound_crlite_filter_file(
      &mut self.proxy.upstream_revocation,
      &mut self.source_paths,
      &path_roots.cert_dir,
      "proxy.upstream_revocation.crlite.filter_file",
    )?;
    self.quic.host_key_file = self
      .quic
      .host_key_file
      .take()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "quic.host_key_file",
          &path_roots.cert_dir,
          &path,
        )?;
        self.source_paths.remember_runtime_file(logical.clone());
        self
          .source_paths
          .remember_downstream_tls_file(logical.clone());
        self.source_paths.quic_host_key_file = Some(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .transpose()?;
    for upstream in &mut self.upstreams {
      for path in upstream.tls.resolve_relative_paths(&path_roots.cert_dir)? {
        self.source_paths.remember_runtime_file(path);
      }
      if let Some(revocation) = &mut upstream.tls.upstream_revocation {
        outbound_revocation::resolve_outbound_crlite_filter_file(
          revocation,
          &mut self.source_paths,
          &path_roots.cert_dir,
          "upstreams.tls.upstream_revocation.crlite.filter_file",
        )?;
      }
    }
    for path in self
      .database
      .mitigation
      .tls
      .resolve_relative_paths("database.mitigation.tls", &path_roots.cert_dir)?
    {
      self.source_paths.remember_runtime_file(path);
    }
    for backend in &mut self.shared_state.backends {
      for path in backend.tls.resolve_relative_paths(
        &format!("shared_state.backends.{}.tls", backend.name),
        &path_roots.cert_dir,
      )? {
        self.source_paths.remember_runtime_file(path);
      }
      for path in backend.redis_tls.resolve_relative_paths(
        &format!("shared_state.backends.{}.redis_tls", backend.name),
        &path_roots.cert_dir,
      )? {
        self.source_paths.remember_runtime_file(path);
      }
      for path in backend.redis_auth.resolve_relative_paths(
        &format!("shared_state.backends.{}.redis_auth", backend.name),
        &path_roots.cert_dir,
      )? {
        self.source_paths.remember_runtime_file(path);
      }
    }
    for pool in &mut self.upstream_pools {
      for path in pool.resolve_discovery_paths(&path_roots.config_dir)? {
        self.source_paths.remember_discovery_file(path);
      }
      pool.resolve_health_check_paths(&path_roots.cert_dir, &mut self.source_paths)?;
    }
    for listener in &mut self.webrtc_turn_listeners {
      for path in listener.tls.resolve_relative_paths(&path_roots.cert_dir)? {
        self.source_paths.remember_runtime_file(path.clone());
        self.source_paths.remember_downstream_tls_file(path);
      }
    }
    for path in self
      .admin
      .tls
      .resolve_relative_paths(&path_roots.cert_dir)?
    {
      self.source_paths.remember_runtime_file(path);
    }
    self.waf.resolve_relative_paths(&path_roots.oxirule_dir)?;
    for route in &mut self.routes {
      if let Some(static_root) = route.static_root.as_ref() {
        let resolved = if static_root.is_absolute() {
          static_root.clone()
        } else {
          validate_relative_path("routes.static_root", static_root)?;
          path_roots.config_dir.join(static_root)
        };
        route.static_root = Some(crate::proxy::http::static_files::validate_static_root(
          &resolved,
        )?);
      }
      route.waf.resolve_relative_paths(&path_roots.oxirule_dir)?;
    }
    Ok(())
  }

  fn load_external_waf_rules(&mut self) -> anyhow::Result<()> {
    self.waf.load_external_rules()?;
    for route in &mut self.routes {
      route.waf.load_external_rules()?;
    }
    Ok(())
  }

  fn normalize_loaded_waf_lb_policy_compat(&mut self) -> anyhow::Result<()> {
    let profile = self.config.lb_policy_compat_profile;
    let mut diagnostics = self
      .waf
      .normalize_lb_policy_compat(profile, "waf".to_string());
    for (route_index, route) in self.routes.iter_mut().enumerate() {
      diagnostics.extend(
        route
          .waf
          .normalize_lb_policy_compat(profile, format!("routes[{route_index}].waf")),
      );
    }
    lb_policy_compat::ensure_supported(&diagnostics)
  }

  fn collect_loaded_waf_rule_paths(&mut self) {
    for path in self.waf.loaded_rule_paths() {
      self.source_paths.remember_oxirule_file(path);
    }
    for route in &self.routes {
      for path in route.waf.loaded_rule_paths() {
        self.source_paths.remember_oxirule_file(path);
      }
    }
  }

  pub fn validate(&self) -> anyhow::Result<()> {
    if !self.listeners.http1
      && !self.listeners.http2
      && !self.listeners.http3
      && !self.sni_forward.has_any_protocol()
    {
      bail!("at least one downstream HTTP version or SNI forwarding protocol must be enabled");
    }

    self.validate_listener_binds()?;
    if self.listeners.http_mode != HttpListenerMode::Off && self.listeners.http_binds.is_empty() {
      bail!("listeners.http_binds is required when listeners.http_mode is not \"off\"");
    }
    if self.listeners.proxy_protocol.enabled {
      for cidr in &self.listeners.proxy_protocol.trusted_sources {
        crate::identity::Cidr::parse(cidr).with_context(|| {
          format!("invalid listeners.proxy_protocol.trusted_sources entry {cidr}")
        })?;
      }
    }

    self.runtime.validate()?;
    self
      .rollout
      .validate(&self.source_paths, self.runtime.hot_reload.mode)?;
    self.validate_limits()?;
    self.validate_proxy()?;
    self.validate_compression()?;
    self.validate_cache()?;
    self.validate_ipm()?;
    self.validate_admin()?;
    self.validate_metrics_and_health()?;
    self.overload.validate()?;
    self.circuit_breakers.validate()?;
    self.telemetry.validate()?;
    security_headers::validate_security_headers(self)?;
    crypto::validate_crypto(self)?;
    self.validate_tls()?;
    self.quic.validate(self.listeners.http3)?;
    self.validate_http3_alt_svc_binds()?;
    self.validate_sni_forward()?;
    self.access_log.validate()?;
    self.logging.validate()?;

    if self.runtime.linux_only && !cfg!(target_os = "linux") {
      bail!("this build is configured for Linux only");
    }

    if self.routes.is_empty()
      && self.stream_listeners.is_empty()
      && self.webrtc_turn_listeners.is_empty()
      && !self.sni_forward.has_any_target()
    {
      bail!(
        "at least one route, SNI forwarding rule/default target, stream listener, or WebRTC TURN listener must be configured"
      );
    }

    self.database.validate()?;
    self.shared_state.validate()?;
    self.validate_external_auth()?;
    self.validate_mitigation_database()?;

    let mut upstream_names = HashSet::new();
    for upstream in &self.upstreams {
      if upstream.name.trim().is_empty() {
        bail!("upstream name must not be empty");
      }
      if !upstream_names.insert(upstream.name.clone()) {
        bail!("duplicate upstream name: {}", upstream.name);
      }

      if upstream.origin.scheme() != "http" && upstream.origin.scheme() != "https" {
        bail!(
          "upstream {} must use http:// or https:// origin, got {}",
          upstream.name,
          upstream.origin
        );
      }

      if upstream.max_http_version == HttpVersion::H3 && upstream.origin.scheme() != "https" {
        bail!(
          "upstream {} must use https:// origin when max_http_version = \"h3\"",
          upstream.name
        );
      }
      if upstream.max_http_version == HttpVersion::H3
        && upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
      {
        bail!(
          "upstream {} cannot enable proxy_protocol_egress with max_http_version = \"h3\"",
          upstream.name
        );
      }

      upstream.tls.validate(&upstream.name)?;
      if upstream.connect_timeout_ms == 0
        || upstream.request_timeout_ms == 0
        || upstream.first_byte_timeout_ms == 0
        || upstream.read_timeout_ms == 0
        || upstream.send_timeout_ms == 0
        || upstream.idle_timeout_ms == 0
      {
        bail!(
          "upstream {} timeout values must be greater than 0",
          upstream.name
        );
      }
    }

    let mut pool_names = HashSet::new();
    for pool in &self.upstream_pools {
      if pool.name.trim().is_empty() {
        bail!("upstream pool name must not be empty");
      }
      if !pool_names.insert(pool.name.clone()) {
        bail!("duplicate upstream pool name: {}", pool.name);
      }
      if pool.algorithm == LoadBalancingAlgorithm::StickyCookie {
        upstream_pool::validate_sticky_cookie_pool(pool)?;
      }
      if pool.servers.is_empty() && pool.discovery.is_empty() {
        bail!(
          "upstream pool {} must define at least one server or discovery provider",
          pool.name
        );
      }
      if pool.keepalive.idle_timeout_ms == 0 || pool.keepalive.max_lifetime_ms == 0 {
        bail!(
          "upstream pool {} keepalive timeout values must be greater than 0",
          pool.name
        );
      }
      upstream_pool::validate_pool_policy(pool)?;
      if let Some(circuit_breaker) = &pool.circuit_breaker {
        circuit_breaker.validate(&format!("upstream_pools {} circuit_breaker", pool.name))?;
      }
      let mut server_ids = HashSet::new();
      for (index, server) in pool.servers.iter().enumerate() {
        let server_id = upstream_pool_server_id(index, server);
        validate_runtime_identifier(
          &format!("upstream pool {} server id", pool.name),
          &server_id,
        )?;
        if !server_ids.insert(server_id.clone()) {
          bail!(
            "upstream pool {} has duplicate server id {server_id}",
            pool.name
          );
        }
        if server.origin.scheme() != "http" && server.origin.scheme() != "https" {
          bail!(
            "upstream pool {} server origin must use http:// or https://, got {}",
            pool.name,
            server.origin
          );
        }
        if server.weight == 0 {
          bail!(
            "upstream pool {} server weight must be greater than 0",
            pool.name
          );
        }
      }
      upstream_pool::validate_pool_discovery(pool)?;
      upstream_pool::validate_pool_health_check(pool)?;
    }

    let turn_pool_names = self.validate_turn_forwarding()?;

    let compression_policy_names = self
      .compression
      .policies
      .iter()
      .map(|policy| policy.name.as_str())
      .collect::<HashSet<_>>();
    let security_header_policy_names = self
      .security
      .header_policies
      .iter()
      .map(|policy| policy.name.as_str())
      .collect::<HashSet<_>>();

    let mut route_names = HashSet::new();
    for route in &self.routes {
      if route.name.trim().is_empty() {
        bail!("route name must not be empty");
      }
      if !route_names.insert(route.name.clone()) {
        bail!("duplicate route name: {}", route.name);
      }
      if route.hosts.is_empty() {
        bail!("route {} must have at least one host match", route.name);
      }
      route::validate_route_path_value(&route.name, "path_prefix", &route.path_prefix)?;
      route::validate_route_match_config(route)?;
      if let Some(replacement) = &route.replace_prefix_with {
        route::validate_route_path_value(&route.name, "replace_prefix_with", replacement)?;
      }
      route_actions::validate_route_actions_config(route)?;
      route_static_files::validate_route_static_files_config(&route.name, &route.static_files)?;
      let target_count = usize::from(route.upstream.is_some())
        + usize::from(route.upstream_pool.is_some())
        + usize::from(route.static_root.is_some())
        + usize::from(route.actions.redirect.is_some());
      if target_count != 1 {
        bail!(
          "route {} must set exactly one of upstream, upstream_pool, static_root, or actions.redirect",
          route.name
        );
      }
      route_actions::validate_route_action_target_compatibility(route)?;
      route_actions::validate_route_action_pool_references(route, &pool_names)?;
      match (
        &route.upstream,
        &route.upstream_pool,
        &route.static_root,
        &route.actions.redirect,
      ) {
        (Some(upstream), None, None, None) if !upstream_names.contains(upstream) => {
          bail!(
            "route {} references unknown upstream {}",
            route.name,
            upstream
          );
        }
        (None, Some(pool), None, None) if !pool_names.contains(pool) => {
          bail!(
            "route {} references unknown upstream_pool {}",
            route.name,
            pool
          );
        }
        (Some(_), None, None, None) | (None, Some(_), None, None) => {}
        (None, None, Some(static_root), None) => {
          crate::proxy::http::static_files::validate_static_root(static_root)
            .with_context(|| format!("route {} static_root is invalid", route.name))?;
          if route.replace_prefix_with.is_some() {
            bail!(
              "route {} cannot set replace_prefix_with when static_root is configured",
              route.name
            );
          }
          if route.cache.is_some() {
            bail!(
              "route {} cannot set cache when static_root is configured",
              route.name
            );
          }
          if route.upstream_http_version.is_some() {
            bail!(
              "route {} cannot set upstream_http_version when static_root is configured",
              route.name
            );
          }
          if route.generic_http_upgrade || route.connect_tunneling || route.grpc_web {
            bail!(
              "route {} cannot enable upstream-only route features when static_root is configured",
              route.name
            );
          }
        }
        (None, None, None, Some(_)) => {}
        _ => {}
      }
      if route.static_root.is_none() && route.static_files.has_convenience_options() {
        bail!(
          "route {} cannot set static_files options without static_root",
          route.name
        );
      }
      if let Some(cache) = &route.cache
        && cache != "default"
        && !self
          .cache
          .policies
          .iter()
          .any(|policy| policy.name == *cache)
      {
        bail!("route {} references unknown cache {}", route.name, cache);
      }
      if let Some(compression) = &route.compression
        && compression != "default"
        && compression != "off"
        && !compression_policy_names.contains(compression.as_str())
      {
        bail!(
          "route {} references unknown compression policy {}",
          route.name,
          compression
        );
      }
      if let Some(security_headers) = &route.security_headers
        && security_headers != "default"
        && security_headers != "off"
        && !security_header_policy_names.contains(security_headers.as_str())
      {
        bail!(
          "route {} references unknown security header policy {}",
          route.name,
          security_headers
        );
      }
      if let Some(external_auth) = &route.external_auth {
        let Some(auth_config) = self
          .external_auth
          .iter()
          .find(|config| config.name == *external_auth)
        else {
          bail!(
            "route {} references unknown external_auth {}",
            route.name,
            external_auth
          );
        };
        route_actions::validate_route_external_auth_identity_header_conflicts(
          route,
          &auth_config.identity_headers,
        )?;
      }
      if route.grpc_web && !self.proxy.grpc_web.enabled {
        bail!(
          "route {} enables grpc_web but proxy.grpc_web.enabled is false",
          route.name
        );
      }
      if route.generic_http_upgrade && !self.proxy.upgrades.generic_http_upgrade {
        bail!(
          "route {} enables generic_http_upgrade but proxy.upgrades.generic_http_upgrade is false",
          route.name
        );
      }
      if route.connect_tunneling && !self.proxy.upgrades.connect_tunneling {
        bail!(
          "route {} enables connect_tunneling but proxy.upgrades.connect_tunneling is false",
          route.name
        );
      }
      if let Some(route_version) = route.upstream_http_version {
        match (&route.upstream, &route.upstream_pool) {
          (Some(upstream_name), None) => {
            let upstream = self
              .upstreams
              .iter()
              .find(|item| item.name == *upstream_name)
              .expect("validated route upstream");
            if route_version > upstream.max_http_version {
              bail!(
                "route {} upstream_http_version cannot exceed upstream {} max_http_version",
                route.name,
                upstream.name
              );
            }
            if route_version == HttpVersion::H3
              && upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
            {
              bail!(
                "route {} cannot select HTTP/3 when upstream {} has proxy_protocol_egress enabled",
                route.name,
                upstream.name
              );
            }
          }
          (None, Some(_)) if route_version == HttpVersion::H3 => {
            bail!(
              "route {} cannot set upstream_http_version = \"h3\" for upstream_pool routes",
              route.name
            );
          }
          _ => {}
        }
      }
      route.timeouts.validate(&route.name)?;
      route.limits.validate(&route.name)?;
      route.ipm.validate(&route.name)?;
      if let Some(retry) = &route.retry {
        retry.validate(&route.name)?;
        let backoff_base = retry
          .backoff_base_ms
          .unwrap_or(self.proxy.retry.backoff_base_ms);
        let backoff_max = retry
          .backoff_max_ms
          .unwrap_or(self.proxy.retry.backoff_max_ms);
        if backoff_max > 0 && backoff_base > backoff_max {
          bail!(
            "route {} retry.backoff_max_ms must be 0 or greater than or equal to effective retry.backoff_base_ms",
            route.name
          );
        }
      }
      if let Some(circuit_breaker) = &route.circuit_breaker {
        circuit_breaker.validate(&format!("route {} circuit_breaker", route.name))?;
      }
    }
    route::validate_route_match_conflicts(&self.routes)?;

    self.validate_dynamic_policy(&route_names)?;
    self.validate_stream_upstream_pools()?;
    self.validate_stream_listeners()?;
    self.validate_webrtc_turn_listeners(&turn_pool_names)?;

    validate_ocsp_config("tls.ocsp", &self.tls.ocsp)?;
    self.tls.crlite.validate()?;
    self.client_identity.validate()?;
    crate::waf::validate_config(self)?;

    Ok(())
  }

  fn validate_limits(&self) -> anyhow::Result<()> {
    if self.limits.max_connections == 0
      || self.limits.max_connections_per_ip == 0
      || self.limits.max_webtransport_sessions == Some(0)
      || self.limits.max_webtransport_sessions_per_ip == Some(0)
      || self.limits.max_webtransport_sessions_per_connection == 0
      || self.limits.max_requests_per_connection == 0
      || self.limits.client_header_timeout_ms == 0
      || self.limits.client_body_timeout_ms == 0
      || self.limits.client_idle_timeout_ms == 0
      || self.limits.websocket_idle_timeout_ms == 0
      || self.limits.webtransport_idle_timeout_ms == 0
      || self.limits.tls_handshake_timeout_ms == 0
      || self.limits.response_send_timeout_ms == 0
      || self.limits.max_headers == 0
      || self.limits.max_header_name_bytes == 0
      || self.limits.max_header_value_bytes == 0
      || self.limits.max_total_header_bytes == 0
      || self.limits.max_uri_bytes == 0
      || self.limits.max_request_body_bytes == 0
    {
      bail!("limits values must be greater than 0");
    }
    let route_names = self
      .routes
      .iter()
      .map(|route| route.name.as_str())
      .collect::<HashSet<_>>();
    let mut names = HashSet::new();
    for rate_limit in &self.rate_limits {
      if rate_limit.name.trim().is_empty() {
        bail!("rate limit name must not be empty");
      }
      if !names.insert(rate_limit.name.as_str()) {
        bail!("duplicate rate limit name {}", rate_limit.name);
      }
      crate::limits::parse_rate(&rate_limit.rate)
        .with_context(|| format!("invalid rate_limits {} rate", rate_limit.name))?;
      if rate_limit.max_buckets == 0 {
        bail!(
          "rate limit {} max_buckets must be greater than 0",
          rate_limit.name
        );
      }
      http::StatusCode::from_u16(rate_limit.status)
        .with_context(|| format!("rate limit {} has invalid status", rate_limit.name))?;
      if let Some(token_header) = &rate_limit.token_header {
        http::header::HeaderName::from_bytes(token_header.as_bytes())
          .with_context(|| format!("rate limit {} has invalid token_header", rate_limit.name))?;
      }
      validate_rate_limit_identity_config(RateLimitIdentityValidation {
        label: "rate limit",
        name: &rate_limit.name,
        key: rate_limit.key,
        ipv4_prefix_bits: rate_limit.ipv4_prefix_bits,
        ipv6_prefix_bits: rate_limit.ipv6_prefix_bits,
        identity_parts: &rate_limit.identity_parts,
        token_bindings: &rate_limit.token_bindings,
        token_header: rate_limit.token_header.as_deref(),
        access_token_source: rate_limit.access_token_source,
        waf_context: false,
      })?;
      let mut route_filter_names = HashSet::new();
      for route in &rate_limit.routes {
        if !route_filter_names.insert(route.as_str()) {
          bail!(
            "rate limit {} contains duplicate route {}",
            rate_limit.name,
            route
          );
        }
        if !route_names.contains(route.as_str()) {
          bail!(
            "rate limit {} references unknown route {}",
            rate_limit.name,
            route
          );
        }
      }
    }
    names.clear();
    for connection_limit in &self.connection_limits {
      if connection_limit.name.trim().is_empty() {
        bail!("connection limit name must not be empty");
      }
      if !names.insert(connection_limit.name.as_str()) {
        bail!("duplicate connection limit name {}", connection_limit.name);
      }
      if connection_limit.limit == 0 {
        bail!(
          "connection limit {} limit must be greater than 0",
          connection_limit.name
        );
      }
      http::StatusCode::from_u16(connection_limit.status).with_context(|| {
        format!(
          "connection limit {} has invalid status",
          connection_limit.name
        )
      })?;
    }
    Ok(())
  }

  fn validate_dynamic_policy(&self, route_names: &HashSet<String>) -> anyhow::Result<()> {
    let policy = &self.dynamic_policy;
    policy.validate_basic()?;
    validate_optional_non_empty("dynamic_policy.backend", policy.backend.as_deref())?;
    if policy.automation_api.enabled {
      if !policy.enabled {
        bail!("dynamic_policy.automation_api.enabled requires dynamic_policy.enabled = true");
      }
      if !self.admin.enabled {
        bail!("dynamic_policy.automation_api.enabled requires admin.enabled = true");
      }
      policy.automation_api.validate_signature_key_env()?;
    }
    if !policy.enabled {
      return Ok(());
    }
    if !self.shared_state.enabled {
      bail!("dynamic_policy.enabled requires shared_state.enabled = true");
    }
    let Some(backend_name) = self.dynamic_policy_backend_name() else {
      bail!(
        "dynamic_policy.enabled requires dynamic_policy.backend, shared_state.dynamic_policy_backend, shared_state.default_backend, or at least one shared_state backend"
      );
    };
    let Some(backend) = self
      .shared_state
      .backends
      .iter()
      .find(|backend| backend.name == backend_name)
    else {
      bail!("dynamic_policy backend references unknown shared_state backend {backend_name}");
    };
    if backend.kind != SharedStateBackendKind::Postgres {
      bail!("dynamic_policy backend {backend_name} must use kind = \"postgres\"");
    }
    if route_names.is_empty() {
      bail!("dynamic_policy requires at least one named route");
    }
    Ok(())
  }

  fn validate_mitigation_database(&self) -> anyhow::Result<()> {
    let mitigation = &self.database.mitigation;
    let Some(backend_name) = mitigation.backend.as_deref() else {
      return Ok(());
    };
    if !mitigation.enabled {
      return Ok(());
    }
    if !self.shared_state.enabled {
      bail!("database.mitigation.backend requires shared_state.enabled = true");
    }
    let Some(backend) = self
      .shared_state
      .backends
      .iter()
      .find(|backend| backend.name == backend_name)
    else {
      bail!("database.mitigation.backend references unknown shared_state backend {backend_name}");
    };
    if backend.kind != SharedStateBackendKind::Postgres {
      bail!("database.mitigation.backend {backend_name} must use kind = \"postgres\"");
    }
    Ok(())
  }

  pub(crate) fn dynamic_policy_backend_name(&self) -> Option<&str> {
    self
      .dynamic_policy
      .backend
      .as_deref()
      .or(self.shared_state.dynamic_policy_backend.as_deref())
      .or(self.shared_state.default_backend.as_deref())
      .or_else(|| {
        self
          .shared_state
          .backends
          .first()
          .map(|backend| backend.name.as_str())
      })
  }

  fn validate_proxy(&self) -> anyhow::Result<()> {
    if self.proxy.retry.tries == 0 {
      bail!("proxy.retry.tries must be greater than 0");
    }
    if self.proxy.retry.timeout_ms == 0 {
      bail!("proxy.retry.timeout_ms must be greater than 0");
    }
    if self.proxy.retry.total_budget_ms == Some(0) {
      bail!("proxy.retry.total_budget_ms must be greater than 0");
    }
    if self.proxy.retry.per_attempt_timeout_ms == Some(0) {
      bail!("proxy.retry.per_attempt_timeout_ms must be greater than 0");
    }
    if self.proxy.retry.backoff_max_ms > 0
      && self.proxy.retry.backoff_base_ms > self.proxy.retry.backoff_max_ms
    {
      bail!(
        "proxy.retry.backoff_max_ms must be 0 or greater than or equal to proxy.retry.backoff_base_ms"
      );
    }
    if self.proxy.http.direct_h1_small_request_body_max_bytes == 0 {
      bail!("proxy.http.direct_h1_small_request_body_max_bytes must be greater than 0");
    }
    #[cfg(not(target_os = "linux"))]
    if self.runtime.direct_h1_io == RuntimeDirectH1IoMode::Compio {
      bail!("runtime.direct_h1_io = \"compio\" is Linux-only");
    }
    if self.proxy.http2.max_concurrent_streams == 0
      || self.proxy.http2.max_send_buf_size == 0
      || self.proxy.http2.keep_alive_timeout_ms == 0
      || self
        .proxy
        .http2
        .initial_stream_window_bytes
        .is_some_and(|value| value == 0)
      || self
        .proxy
        .http2
        .initial_connection_window_bytes
        .is_some_and(|value| value == 0)
      || self
        .proxy
        .http2
        .max_frame_size_bytes
        .is_some_and(|value| value == 0)
    {
      bail!(
        "proxy.http2 numeric values must be greater than 0, except keep_alive_interval_ms = 0 disables keep-alive pings"
      );
    }
    if self.proxy.http2.adaptive_window
      && (self.proxy.http2.initial_stream_window_bytes.is_some()
        || self.proxy.http2.initial_connection_window_bytes.is_some()
        || self.proxy.http2.max_frame_size_bytes.is_some())
    {
      bail!("proxy.http2 manual window and frame-size values require adaptive_window = false");
    }
    self
      .proxy
      .upstream_revocation
      .validate("proxy.upstream_revocation")?;
    const HTTP2_MAX_WINDOW_BYTES: u32 = (1 << 31) - 1;
    if self
      .proxy
      .http2
      .initial_stream_window_bytes
      .is_some_and(|value| value > HTTP2_MAX_WINDOW_BYTES)
      || self
        .proxy
        .http2
        .initial_connection_window_bytes
        .is_some_and(|value| value > HTTP2_MAX_WINDOW_BYTES)
    {
      bail!("proxy.http2 initial window values must be at most 2147483647 bytes");
    }
    const HTTP2_MIN_MAX_FRAME_SIZE_BYTES: u32 = 16_384;
    const HTTP2_MAX_MAX_FRAME_SIZE_BYTES: u32 = 16_777_215;
    if self.proxy.http2.max_frame_size_bytes.is_some_and(|value| {
      !(HTTP2_MIN_MAX_FRAME_SIZE_BYTES..=HTTP2_MAX_MAX_FRAME_SIZE_BYTES).contains(&value)
    }) {
      bail!("proxy.http2.max_frame_size_bytes must be between 16384 and 16777215 bytes");
    }
    if self.proxy.static_files.open_file_cache_max_entries > 0
      && self.proxy.static_files.open_file_cache_ttl_ms == 0
    {
      bail!(
        "proxy.static_files.open_file_cache_ttl_ms must be greater than 0 when open_file_cache_max_entries is set"
      );
    }
    if self.proxy.static_files.sendfile_chunk_bytes == 0 {
      bail!("proxy.static_files.sendfile_chunk_bytes must be greater than 0");
    }
    if self.proxy.static_files.hot_object_cache_max_bytes > 0 {
      if self.proxy.static_files.open_file_cache_max_entries == 0 {
        bail!(
          "proxy.static_files.hot_object_cache_max_bytes requires open_file_cache_max_entries greater than 0"
        );
      }
      if self.proxy.static_files.hot_object_cache_max_file_bytes == 0 {
        bail!(
          "proxy.static_files.hot_object_cache_max_file_bytes must be greater than 0 when hot_object_cache_max_bytes is set"
        );
      }
    }
    self.validate_buffering()?;
    for cidr in &self.proxy.real_ip.trusted_proxies {
      crate::identity::Cidr::parse(cidr)
        .with_context(|| format!("invalid proxy.real_ip.trusted_proxies entry {cidr}"))?;
    }
    Ok(())
  }

  fn validate_buffering(&self) -> anyhow::Result<()> {
    let mut requires_temp_dir = false;
    validate_effective_buffering(
      "proxy.buffering",
      self.proxy.buffering.request,
      self.proxy.buffering.max_temp_file_bytes,
      &mut requires_temp_dir,
    )?;
    validate_effective_buffering(
      "proxy.buffering",
      self.proxy.buffering.response,
      self.proxy.buffering.max_temp_file_bytes,
      &mut requires_temp_dir,
    )?;

    for route in &self.routes {
      let request = route
        .buffering
        .request
        .unwrap_or(self.proxy.buffering.request);
      let response = route
        .buffering
        .response
        .unwrap_or(self.proxy.buffering.response);
      let max_temp_file_bytes = route
        .buffering
        .max_temp_file_bytes
        .unwrap_or(self.proxy.buffering.max_temp_file_bytes);
      validate_effective_buffering(
        &format!("route {} buffering", route.name),
        request,
        max_temp_file_bytes,
        &mut requires_temp_dir,
      )?;
      validate_effective_buffering(
        &format!("route {} buffering", route.name),
        response,
        max_temp_file_bytes,
        &mut requires_temp_dir,
      )?;
    }

    if requires_temp_dir {
      let dir =
        self.proxy.buffering.temp_dir.as_ref().ok_or_else(|| {
          anyhow!("proxy.buffering.temp_dir is required when buffering uses spool")
        })?;
      crate::cache::validate_disk_dir(dir)?;
    }
    Ok(())
  }

  fn validate_compression(&self) -> anyhow::Result<()> {
    validate_compression_level("compression.level", self.compression.level)?;
    validate_compression_proxied("compression.proxied", &self.compression.proxied)?;
    validate_compression_statuses("compression.statuses", &self.compression.statuses)?;
    validate_compression_mime_types("compression.mime_types", &self.compression.mime_types)?;

    let mut names = HashSet::new();
    for policy in &self.compression.policies {
      if policy.name.trim().is_empty() {
        bail!("compression policy name must not be empty");
      }
      if matches!(policy.name.as_str(), "default" | "off") {
        bail!("compression policy name {} is reserved", policy.name);
      }
      if !names.insert(policy.name.as_str()) {
        bail!("duplicate compression policy name {}", policy.name);
      }
      validate_compression_level(
        &format!("compression policy {} level", policy.name),
        policy.level,
      )?;
      validate_compression_proxied(
        &format!("compression policy {} proxied", policy.name),
        &policy.proxied,
      )?;
      validate_compression_statuses(
        &format!("compression policy {} statuses", policy.name),
        &policy.statuses,
      )?;
      validate_compression_mime_types(
        &format!("compression policy {} mime_types", policy.name),
        &policy.mime_types,
      )?;
    }

    Ok(())
  }

  fn validate_cache(&self) -> anyhow::Result<()> {
    if self.cache.max_size_bytes == 0 {
      bail!("cache.max_size_bytes must be greater than 0");
    }
    if let Some(memory_max_size_bytes) = self.cache.memory_max_size_bytes
      && memory_max_size_bytes == 0
    {
      bail!("cache.memory_max_size_bytes must be greater than 0 when configured");
    }
    if let Some(disk_max_size_bytes) = self.cache.disk_max_size_bytes
      && disk_max_size_bytes == 0
    {
      bail!("cache.disk_max_size_bytes must be greater than 0 when configured");
    }
    if !(0.0..=1.0).contains(&self.cache.memory_auto_fraction)
      || self.cache.memory_auto_fraction == 0.0
    {
      bail!("cache.memory_auto_fraction must be greater than 0.0 and less than or equal to 1.0");
    }
    if self.cache.default_ttl_seconds == 0 {
      bail!("cache.default_ttl_seconds must be greater than 0");
    }
    if self.cache.store == CacheStore::Tmpfs && self.cache.enabled {
      let dir = self
        .cache
        .tmpfs_dir
        .clone()
        .unwrap_or_else(default_cache_tmpfs_dir);
      crate::cache::validate_tmpfs_dir(&dir)?;
    }
    if self.cache.enabled && self.cache.store.uses_disk() {
      let dir = self
        .cache
        .disk_dir
        .as_ref()
        .ok_or_else(|| anyhow!("cache.disk_dir is required when cache.store uses disk"))?;
      crate::cache::validate_disk_dir(dir)?;
      if self.cache.disk_max_size_bytes.is_none() {
        bail!("cache.disk_max_size_bytes is required when cache.store uses disk");
      }
    }
    for status in &self.cache.negative_statuses {
      http::StatusCode::from_u16(*status)
        .with_context(|| format!("cache.negative_statuses contains invalid status {status}"))?;
    }
    if !self.cache.negative_statuses.is_empty() && self.cache.negative_ttl_seconds == 0 {
      bail!("cache.negative_ttl_seconds must be greater than 0 when negative_statuses is set");
    }
    validate_cache_tag_headers("cache.tag_headers", &self.cache.tag_headers)?;
    if self.cache.max_tags_per_entry == 0 {
      bail!("cache.max_tags_per_entry must be greater than 0");
    }
    if self.cache.max_tag_bytes == 0 {
      bail!("cache.max_tag_bytes must be greater than 0");
    }
    if self.cache.max_vary_fields == 0 {
      bail!("cache.max_vary_fields must be greater than 0");
    }
    if self.cache.max_vary_variants_per_key == 0 {
      bail!("cache.max_vary_variants_per_key must be greater than 0");
    }
    validate_cache_bypass_headers(
      "cache.bypass_request_headers",
      &self.cache.bypass_request_headers,
    )?;
    if self.cache.stream_chunk_bytes == 0 {
      bail!("cache.stream_chunk_bytes must be greater than 0");
    }
    if self.cache.background_refresh_max_concurrent == 0 {
      bail!("cache.background_refresh_max_concurrent must be greater than 0");
    }
    if self.cache.lock_wait_timeout_ms == 0 {
      bail!("cache.lock_wait_timeout_ms must be greater than 0");
    }
    #[cfg(not(target_os = "linux"))]
    if self.cache.copy_file_range == CacheCopyFileRangeMode::Required {
      bail!("cache.copy_file_range = \"required\" is Linux-only");
    }
    validate_cache_admission("cache.admission", &self.cache.admission, &self.cache)?;
    validate_cache_stale_if_error("cache.stale_if_error", &self.cache.stale_if_error)?;
    let external_handler_names = cache_external::validate_external_handlers(&self.cache)?;
    cache_external::validate_external_handler_reference(
      "cache.external_handler",
      self.cache.external_handler.as_deref(),
      &external_handler_names,
      false,
    )?;

    let mut names = HashSet::new();
    for policy in &self.cache.policies {
      if policy.name.trim().is_empty() {
        bail!("cache policy name must not be empty");
      }
      if policy.name == "default" {
        bail!("cache policy name default is reserved");
      }
      if !names.insert(policy.name.as_str()) {
        bail!("duplicate cache policy name {}", policy.name);
      }
      if let Some(default_ttl_seconds) = policy.default_ttl_seconds
        && default_ttl_seconds == 0
      {
        bail!(
          "cache policy {} default_ttl_seconds must be greater than 0",
          policy.name
        );
      }
      if let Some(negative_statuses) = &policy.negative_statuses {
        for status in negative_statuses {
          http::StatusCode::from_u16(*status).with_context(|| {
            format!(
              "cache policy {} negative_statuses contains invalid status {status}",
              policy.name
            )
          })?;
        }
        if !negative_statuses.is_empty() && policy.negative_ttl_seconds.unwrap_or(0) == 0 {
          bail!(
            "cache policy {} negative_ttl_seconds must be greater than 0 when negative_statuses is set",
            policy.name
          );
        }
      } else if policy.negative_ttl_seconds.is_some() {
        bail!(
          "cache policy {} negative_ttl_seconds requires negative_statuses",
          policy.name
        );
      }
      if let Some(memory_max_size_bytes) = policy.memory_max_size_bytes
        && memory_max_size_bytes == 0
      {
        bail!(
          "cache policy {} memory_max_size_bytes must be greater than 0",
          policy.name
        );
      }
      if let Some(disk_max_size_bytes) = policy.disk_max_size_bytes
        && disk_max_size_bytes == 0
      {
        bail!(
          "cache policy {} disk_max_size_bytes must be greater than 0",
          policy.name
        );
      }
      if let Some(tag_headers) = &policy.tag_headers {
        validate_cache_tag_headers(
          &format!("cache policy {} tag_headers", policy.name),
          tag_headers,
        )?;
      }
      if policy.max_tags_per_entry == Some(0) {
        bail!(
          "cache policy {} max_tags_per_entry must be greater than 0",
          policy.name
        );
      }
      if policy.max_tag_bytes == Some(0) {
        bail!(
          "cache policy {} max_tag_bytes must be greater than 0",
          policy.name
        );
      }
      if policy.max_vary_fields == Some(0) {
        bail!(
          "cache policy {} max_vary_fields must be greater than 0",
          policy.name
        );
      }
      if policy.max_vary_variants_per_key == Some(0) {
        bail!(
          "cache policy {} max_vary_variants_per_key must be greater than 0",
          policy.name
        );
      }
      if policy.background_refresh_max_concurrent == Some(0) {
        bail!(
          "cache policy {} background_refresh_max_concurrent must be greater than 0",
          policy.name
        );
      }
      if policy.lock_wait_timeout_ms == Some(0) {
        bail!(
          "cache policy {} lock_wait_timeout_ms must be greater than 0",
          policy.name
        );
      }
      if let Some(admission) = &policy.admission {
        validate_cache_admission(
          &format!("cache policy {} admission", policy.name),
          admission,
          &self.cache,
        )?;
      }
      if let Some(stale_if_error) = &policy.stale_if_error {
        validate_cache_stale_if_error(
          &format!("cache policy {} stale_if_error", policy.name),
          stale_if_error,
        )?;
      }
      cache_external::validate_external_handler_reference(
        &format!("cache policy {} external_handler", policy.name),
        policy.external_handler.as_deref(),
        &external_handler_names,
        true,
      )?;
      if policy.store == Some(CacheStore::Tmpfs) && self.cache.enabled {
        let dir = self
          .cache
          .tmpfs_dir
          .clone()
          .unwrap_or_else(default_cache_tmpfs_dir);
        crate::cache::validate_tmpfs_dir(&dir)?;
      }
      if policy.store.is_some_and(CacheStore::uses_disk) {
        let dir = self
          .cache
          .disk_dir
          .as_ref()
          .ok_or_else(|| anyhow!("cache.disk_dir is required when cache policy uses disk"))?;
        if self.cache.enabled {
          crate::cache::validate_disk_dir(dir)?;
        }
        if policy
          .disk_max_size_bytes
          .or(self.cache.disk_max_size_bytes)
          .is_none()
        {
          bail!(
            "cache.disk_max_size_bytes or cache policy {} disk_max_size_bytes is required when policy uses disk",
            policy.name
          );
        }
      }
      for rule in &policy.rules {
        if rule.mime_types.is_empty() {
          bail!(
            "cache policy {} rule must include at least one MIME pattern",
            policy.name
          );
        }
        validate_compression_mime_types(
          &format!("cache policy {} rule mime_types", policy.name),
          &rule.mime_types,
        )?;
        if rule.store.uses_disk() {
          let dir = self.cache.disk_dir.as_ref().ok_or_else(|| {
            anyhow!("cache.disk_dir is required when cache policy rule uses disk")
          })?;
          if self.cache.enabled {
            crate::cache::validate_disk_dir(dir)?;
          }
          if policy
            .disk_max_size_bytes
            .or(self.cache.disk_max_size_bytes)
            .is_none()
          {
            bail!(
              "cache.disk_max_size_bytes or cache policy {} disk_max_size_bytes is required when rule uses disk",
              policy.name
            );
          }
        }
      }
    }
    Ok(())
  }

  fn validate_admin(&self) -> anyhow::Result<()> {
    self.validate_legacy_admin_authorization()?;
    self.validate_admin_audit_config_fields()?;
    if self.admin.audit.queue_capacity == 0 {
      bail!("admin.audit.queue_capacity must be greater than 0");
    }
    if !self.admin.enabled {
      if self.admin.audit.enabled {
        bail!("admin.audit.enabled requires admin.enabled = true");
      }
      if self.admin.http3.enabled {
        bail!("admin.http3.enabled requires admin.enabled = true");
      }
      return Ok(());
    }
    self.validate_admin_privileged_ports()?;
    self.validate_admin_audit_runtime()?;
    if self.admin.operations.max_running == 0 {
      bail!("admin.operations.max_running must be greater than 0");
    }
    if self.admin.operations.max_queued == 0 {
      bail!("admin.operations.max_queued must be greater than 0");
    }
    if self.admin.operations.max_stored == 0 {
      bail!("admin.operations.max_stored must be greater than 0");
    }
    if self.admin.operations.max_stored < self.admin.operations.max_running {
      bail!("admin.operations.max_stored must be at least admin.operations.max_running");
    }
    if self.admin.operations.retention_seconds == 0 {
      bail!("admin.operations.retention_seconds must be greater than 0");
    }
    if self.admin.operations.event_buffer == 0 {
      bail!("admin.operations.event_buffer must be greater than 0");
    }
    if self.admin.operations.result_max_bytes == 0 {
      bail!("admin.operations.result_max_bytes must be greater than 0");
    }
    if self.admin.operations.webtransport_max_sessions == 0 {
      bail!("admin.operations.webtransport_max_sessions must be greater than 0");
    }
    if !self.ipm.enabled {
      if self.admin.bearer_token_env.trim().is_empty() {
        bail!("admin.bearer_token_env must not be empty when admin is enabled");
      }
      if std::env::var(&self.admin.bearer_token_env)
        .ok()
        .is_none_or(|token| token.is_empty())
      {
        bail!(
          "admin bearer token environment variable {} must be set and non-empty",
          self.admin.bearer_token_env
        );
      }
    }
    for cidr in &self.admin.plaintext_allowed_source_cidrs {
      crate::identity::Cidr::parse(cidr)
        .with_context(|| format!("invalid admin.plaintext_allowed_source_cidrs entry {cidr}"))?;
    }
    if self.admin.cache_purge_signing.enabled {
      validate_base64_32_byte_env(
        "admin.cache_purge_signing.key_env",
        &self.admin.cache_purge_signing.key_env,
      )?;
      if self.admin.cache_purge_signing.max_skew_seconds == 0 {
        bail!("admin.cache_purge_signing.max_skew_seconds must be greater than 0");
      }
      if self.admin.cache_purge_signing.nonce_ttl_seconds == 0 {
        bail!("admin.cache_purge_signing.nonce_ttl_seconds must be greater than 0");
      }
    }
    if self.admin.transport == AdminTransportMode::Plaintext && !self.admin.allow_insecure_plaintext
    {
      bail!("admin.allow_insecure_plaintext must be true when admin.transport = \"plaintext\"");
    }
    if matches!(
      self.admin.transport,
      AdminTransportMode::Auto | AdminTransportMode::Tls
    ) && !self.admin.bind.ip().is_loopback()
      && !self.admin.tls.enabled
    {
      bail!(
        "admin.tls.enabled must be true for non-loopback admin.bind when admin.transport requires TLS"
      );
    }
    if self.admin.http3.enabled {
      if !self.admin.tls.enabled {
        bail!("admin.http3.enabled requires admin.tls.enabled = true");
      }
      if self.admin.tls.max_version != TlsVersion::Tls13 {
        bail!("admin.http3.enabled requires admin.tls.max_version to allow tls1.3");
      }
    }
    self.admin.tls.validate()
  }

  fn validate_metrics_and_health(&self) -> anyhow::Result<()> {
    self.validate_ops_privileged_ports()?;
    if self.metrics.histogram_buckets_ms.is_empty() {
      bail!("metrics.histogram_buckets_ms must not be empty");
    }
    let mut previous = 0;
    for bucket in &self.metrics.histogram_buckets_ms {
      if *bucket == 0 {
        bail!("metrics.histogram_buckets_ms values must be greater than 0");
      }
      if *bucket <= previous {
        bail!("metrics.histogram_buckets_ms values must be strictly increasing");
      }
      previous = *bucket;
    }
    if !self.health.ready_path.starts_with('/') || !self.health.live_path.starts_with('/') {
      bail!("health ready_path and live_path must start with '/'");
    }
    Ok(())
  }

  fn validate_listener_binds(&self) -> anyhow::Result<()> {
    validate_bind_list("listeners.https_binds", &self.listeners.https_binds)?;
    if self.listeners.http_mode != HttpListenerMode::Off || !self.listeners.http_binds.is_empty() {
      validate_bind_list("listeners.http_binds", &self.listeners.http_binds)?;
    }
    if self.rejects_privileged_data_plane_ports() {
      for bind in &self.listeners.https_binds {
        if self.rejects_privileged_data_plane_bind(*bind) {
          bail!(
            "listeners.https_binds entry {} requires a privileged port but unprivileged_mode=true",
            bind
          );
        }
      }
      for bind in &self.listeners.http_binds {
        if self.rejects_privileged_data_plane_bind(*bind) {
          bail!(
            "listeners.http_binds entry {} requires a privileged port but unprivileged_mode=true",
            bind
          );
        }
      }
    }
    if self.needs_https_listener() && self.listeners.http_mode != HttpListenerMode::Off {
      validate_bind_lists_do_not_overlap(
        "listeners.https_binds",
        &self.listeners.https_binds,
        "listeners.http_binds",
        &self.listeners.http_binds,
      )?;
    }
    Ok(())
  }

  fn validate_http3_alt_svc_binds(&self) -> anyhow::Result<()> {
    if !self.listeners.http3 || !self.quic.alt_svc.enabled {
      return Ok(());
    }
    let mut override_binds = HashSet::new();
    for port_override in &self.quic.alt_svc.port_overrides {
      if port_override.advertised_port == 0 {
        bail!("quic.alt_svc.port_overrides advertised_port must be greater than 0");
      }
      if !override_binds.insert(port_override.bind) {
        bail!(
          "quic.alt_svc.port_overrides contains duplicate bind {}",
          port_override.bind
        );
      }
      if !self.listeners.https_binds.contains(&port_override.bind) {
        bail!(
          "quic.alt_svc.port_overrides bind {} must match a listeners.https_binds entry",
          port_override.bind
        );
      }
    }
    if !self.quic.alt_svc.port_overrides.is_empty() {
      return Ok(());
    }
    let Some(first) = self.listeners.https_binds.first() else {
      return Ok(());
    };
    let port = first.port();
    if self
      .listeners
      .https_binds
      .iter()
      .any(|bind| bind.port() != port)
    {
      bail!(
        "listeners.https_binds entries must use the same port when listeners.http3 and quic.alt_svc.enabled are true"
      );
    }
    Ok(())
  }

  fn validate_tls(&self) -> anyhow::Result<()> {
    if self.tls.min_version > self.tls.max_version {
      bail!("tls.min_version must be less than or equal to tls.max_version");
    }
    if self.tls.session_ticket_rotation_seconds == 0 {
      bail!("tls.session_ticket_rotation_seconds must be greater than 0");
    }
    tls::validate_tls_negotiation(&self.tls)?;
    route_tls_policy::validate_negotiation_policies(self)?;
    validate_tls_server_resumption("tls.resumption", &self.tls.resumption)?;
    let multi_certificate = !self.tls.certificates.is_empty();
    let multi_certificate_partitioned =
      self.tls.resumption.multi_certificate == TlsMultiCertificateResumptionMode::PartitionBySni;
    let tcp_early_data_enabled = self.downstream_tcp_early_data_enabled();
    if multi_certificate {
      let unsafe_multi_cert_resumption = self.tls.resumption.mode != TlsServerResumptionMode::Off
        || self.quic.zero_rtt != QuicZeroRttMode::Off
        || tcp_early_data_enabled;
      if unsafe_multi_cert_resumption && !multi_certificate_partitioned {
        bail!(
          "tls.resumption.multi_certificate = \"partition_by_sni\" is required when tls.certificates is configured with resumption, quic.zero_rtt, or ssl_early_data"
        );
      }
      if multi_certificate_partitioned && !self.tls.require_sni {
        bail!(
          "tls.require_sni must be true when tls.resumption.multi_certificate = \"partition_by_sni\""
        );
      }
      if multi_certificate_partitioned && !self.tls.reject_unknown_sni {
        bail!(
          "tls.reject_unknown_sni must be true when tls.resumption.multi_certificate = \"partition_by_sni\""
        );
      }
    }
    if tcp_early_data_enabled && self.tls.max_version < TlsVersion::Tls13 {
      bail!("tls.ssl_early_data requires tls.max_version to allow tls1.3");
    }
    if tcp_early_data_enabled && self.tls.resumption.mode != TlsServerResumptionMode::Stateful {
      bail!("tls.ssl_early_data requires tls.resumption.mode = \"stateful\"");
    }
    if self.listeners.http3
      && self.quic.zero_rtt == QuicZeroRttMode::SafeMethods
      && self.tls.resumption.mode == TlsServerResumptionMode::Stateless
    {
      bail!(
        "tls.resumption.mode = \"stateless\" cannot be used with quic.zero_rtt = \"safe_methods\""
      );
    }
    if self.tls.remote_signer.enabled {
      if self.tls.private_key.is_some() {
        bail!("tls.private_key must not be set when tls.remote_signer.enabled = true");
      }
      self.tls.remote_signer.validate("tls.remote_signer")?;
      if self.downstream_tls12_allowed() && !self.tls.remote_signer.allow_tls12_unstructured_signing
      {
        bail!(
          "tls.remote_signer.allow_tls12_unstructured_signing must be true when remote signing is enabled with any downstream TLS policy that allows tls1.2"
        );
      }
    } else if self.tls.private_key.is_none() {
      bail!("tls.private_key is required unless tls.remote_signer.enabled = true");
    }
    let mut server_names = HashSet::new();
    for name in &self.tls.server_names {
      validate_tls_server_name("tls.server_names", name)?;
      if !server_names.insert(name.to_ascii_lowercase()) {
        bail!("duplicate tls server_name {name}");
      }
    }
    for (index, certificate) in self.tls.certificates.iter().enumerate() {
      if certificate.server_names.is_empty() {
        bail!("tls.certificates[{index}].server_names must not be empty");
      }
      for name in &certificate.server_names {
        validate_tls_server_name("tls.certificates.server_names", name)?;
        if !server_names.insert(name.to_ascii_lowercase()) {
          bail!("duplicate tls certificate server_name {name}");
        }
      }
      if self.tls.remote_signer.enabled {
        if certificate.private_key.is_some() {
          bail!(
            "tls.certificates[{index}].private_key must not be set when tls.remote_signer.enabled = true"
          );
        }
        match certificate.remote_signer_key_id.as_deref() {
          Some(key_id) if !key_id.trim().is_empty() => {}
          _ => bail!(
            "tls.certificates[{index}].remote_signer_key_id is required when tls.remote_signer.enabled = true"
          ),
        }
      } else {
        if certificate.remote_signer_key_id.is_some() {
          bail!(
            "tls.certificates[{index}].remote_signer_key_id requires tls.remote_signer.enabled = true"
          );
        }
        if certificate.private_key.is_none() {
          bail!(
            "tls.certificates[{index}].private_key is required unless tls.remote_signer.enabled = true"
          );
        }
      }
      validate_ocsp_config(
        &format!("tls.certificates[{index}].ocsp"),
        &certificate.ocsp,
      )?;
    }
    if self.listeners.http3 && self.tls.min_version != TlsVersion::Tls13 {
      bail!("HTTP/3 requires tls.min_version = \"tls1.3\"");
    }
    self.tls.client_auth.validate("tls.client_auth")?;
    for listener in &self.webrtc_turn_listeners {
      if listener.tls.remote_signer_key_id.is_some() && !self.tls.remote_signer.enabled {
        bail!(
          "WebRTC TURN listener {} tls.remote_signer_key_id requires tls.remote_signer.enabled = true",
          listener.name
        );
      }
      if let Some(resumption) = &listener.tls.resumption {
        validate_tls_server_resumption(
          &format!("webrtc_turn_listeners.{}.tls.resumption", listener.name),
          resumption,
        )?;
      }
    }
    Ok(())
  }
}

fn validate_ocsp_config(prefix: &str, ocsp: &OcspConfig) -> anyhow::Result<()> {
  match ocsp.mode {
    OcspMode::Disabled => {}
    OcspMode::StaticFile => {
      if ocsp.response_file.is_none() {
        bail!("{prefix}.response_file is required when {prefix}.mode = \"static_file\"");
      }
    }
    OcspMode::LiveFetch => {
      if ocsp.response_file.is_some() {
        bail!("{prefix}.response_file cannot be used when {prefix}.mode = \"live_fetch\"");
      }
    }
  }
  ocsp.validate_fetch_settings_with_prefix(prefix)
}

fn validate_tls_server_resumption(
  prefix: &str,
  resumption: &TlsServerResumptionConfig,
) -> anyhow::Result<()> {
  if resumption.session_cache_size == 0 {
    bail!("{prefix}.session_cache_size must be greater than 0");
  }
  if resumption.tls13_ticket_count == 0 {
    bail!("{prefix}.tls13_ticket_count must be greater than 0");
  }
  if resumption.rotation_seconds == 0 {
    bail!("{prefix}.rotation_seconds must be greater than 0");
  }
  Ok(())
}

fn validate_compression_statuses(field_name: &str, statuses: &[u16]) -> anyhow::Result<()> {
  if statuses.is_empty() {
    bail!("{field_name} must include at least one status");
  }
  for status in statuses {
    http::StatusCode::from_u16(*status)
      .with_context(|| format!("{field_name} contains invalid status {status}"))?;
  }
  Ok(())
}

fn validate_compression_level(field_name: &str, level: u8) -> anyhow::Result<()> {
  if !(1..=9).contains(&level) {
    bail!("{field_name} must be between 1 and 9");
  }
  Ok(())
}

fn validate_compression_proxied(
  field_name: &str,
  proxied: &[CompressionProxiedPredicate],
) -> anyhow::Result<()> {
  if proxied.is_empty() {
    bail!("{field_name} must include at least one predicate");
  }
  let mut seen = HashSet::new();
  for predicate in proxied {
    if !seen.insert(*predicate) {
      bail!("{field_name} contains duplicate predicate {predicate:?}");
    }
  }
  let has_off = seen.contains(&CompressionProxiedPredicate::Off);
  let has_any = seen.contains(&CompressionProxiedPredicate::Any);
  if has_off && proxied.len() > 1 {
    bail!("{field_name} predicate off cannot be combined with other predicates");
  }
  if has_any && proxied.len() > 1 {
    bail!("{field_name} predicate any cannot be combined with other predicates");
  }
  Ok(())
}

fn validate_compression_mime_types(field_name: &str, mime_types: &[String]) -> anyhow::Result<()> {
  if mime_types.is_empty() {
    bail!("{field_name} must include at least one MIME pattern");
  }
  for mime_type in mime_types {
    validate_compression_mime_type(field_name, mime_type)?;
  }
  Ok(())
}

fn validate_compression_mime_type(field_name: &str, mime_type: &str) -> anyhow::Result<()> {
  if mime_type.trim() != mime_type || mime_type.is_empty() {
    bail!("{field_name} contains an empty or padded MIME pattern");
  }
  if mime_type.bytes().any(|byte| byte.is_ascii_control()) {
    bail!("{field_name} contains a control character in {mime_type}");
  }
  let Some((type_part, subtype_part)) = mime_type.split_once('/') else {
    bail!("{field_name} MIME pattern {mime_type} must contain '/'");
  };
  if type_part.is_empty() || subtype_part.is_empty() {
    bail!("{field_name} MIME pattern {mime_type} must have type and subtype");
  }
  if type_part.contains('*') && type_part != "*" {
    bail!("{field_name} MIME pattern {mime_type} has invalid wildcard type");
  }
  if type_part == "*" && subtype_part != "*" {
    bail!("{field_name} MIME pattern {mime_type} must use */* for wildcard type");
  }
  if subtype_part.matches('*').count() > 1 {
    bail!("{field_name} MIME pattern {mime_type} has too many wildcards");
  }
  if subtype_part.contains('*') && subtype_part != "*" && !subtype_part.starts_with("*+") {
    bail!("{field_name} MIME pattern {mime_type} has invalid wildcard subtype");
  }
  Ok(())
}

fn validate_cache_tag_headers(field_name: &str, headers: &[String]) -> anyhow::Result<()> {
  if headers.is_empty() {
    bail!("{field_name} must include at least one header name");
  }
  for header in headers {
    if header.trim() != header || header.is_empty() {
      bail!("{field_name} contains an empty or padded header name");
    }
    http::header::HeaderName::from_bytes(header.as_bytes())
      .with_context(|| format!("{field_name} contains invalid header name {header}"))?;
  }
  Ok(())
}

fn validate_cache_bypass_headers(field_name: &str, headers: &[String]) -> anyhow::Result<()> {
  if headers.is_empty() {
    bail!("{field_name} must include at least one header");
  }
  let mut names = HashSet::new();
  for header in headers {
    if header.trim() != header || header.is_empty() {
      bail!("{field_name} contains an empty or padded header name");
    }
    let name = http::header::HeaderName::from_bytes(header.as_bytes())
      .with_context(|| format!("{field_name} contains invalid header name {header}"))?;
    let normalized = name.as_str().to_ascii_lowercase();
    if !names.insert(normalized.clone()) {
      bail!("{field_name} contains duplicate header {normalized}");
    }
  }
  Ok(())
}

fn validate_cache_admission(
  field_name: &str,
  admission: &CacheAdmissionConfig,
  cache: &CacheConfig,
) -> anyhow::Result<()> {
  if admission.statuses.is_empty() && cache.negative_statuses.is_empty() {
    bail!("{field_name}.statuses must include at least one status");
  }
  for status in &admission.statuses {
    http::StatusCode::from_u16(*status)
      .with_context(|| format!("{field_name}.statuses contains invalid status {status}"))?;
  }
  if !admission.content_types.is_empty() {
    validate_compression_mime_types(
      &format!("{field_name}.content_types"),
      &admission.content_types,
    )?;
  }
  if admission.min_hits == 0 {
    bail!("{field_name}.min_hits must be greater than 0");
  }
  if admission.max_tracked_keys == 0 {
    bail!("{field_name}.max_tracked_keys must be greater than 0");
  }
  Ok(())
}

fn validate_cache_stale_if_error(
  field_name: &str,
  stale_if_error: &CacheStaleIfErrorConfig,
) -> anyhow::Result<()> {
  for status in &stale_if_error.statuses {
    http::StatusCode::from_u16(*status)
      .with_context(|| format!("{field_name}.statuses contains invalid status {status}"))?;
  }
  Ok(())
}

fn validate_base64_32_byte_env(field_name: &str, env_name: &str) -> anyhow::Result<()> {
  if env_name.trim().is_empty() {
    bail!("{field_name} must not be empty");
  }
  let raw =
    std::env::var(env_name).with_context(|| format!("failed to read {field_name} {env_name}"))?;
  let bytes = base64::engine::general_purpose::STANDARD
    .decode(raw.trim())
    .with_context(|| format!("{field_name} must contain base64"))?;
  if bytes.len() != 32 {
    bail!("{field_name} must contain exactly 32 bytes");
  }
  Ok(())
}

fn validate_tls_server_name(field_name: &str, name: &str) -> anyhow::Result<()> {
  if name.trim() != name || name.is_empty() {
    bail!("{field_name} must not be empty or padded");
  }
  if name.bytes().any(|byte| byte.is_ascii_control()) {
    bail!("{field_name} {name} contains a control character");
  }
  let name = name.strip_prefix("*.").unwrap_or(name);
  if name.is_empty() || name.contains('*') {
    bail!("{field_name} may only use a leftmost wildcard");
  }
  if name
    .split('.')
    .any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-'))
  {
    bail!("{field_name} {name} is not a valid DNS pattern");
  }
  if !name
    .bytes()
    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
  {
    bail!("{field_name} {name} contains invalid characters");
  }
  Ok(())
}

fn validate_admin_server_name(name: &str) -> anyhow::Result<()> {
  validate_tls_server_name("admin.tls certificate server name", name)
}

pub(crate) fn upstream_pool_server_id(index: usize, server: &UpstreamPoolServerConfig) -> String {
  server.id.clone().unwrap_or_else(|| index.to_string())
}

pub(crate) fn turn_upstream_pool_server_id(
  index: usize,
  server: &TurnUpstreamPoolServerConfig,
) -> String {
  server.id.clone().unwrap_or_else(|| index.to_string())
}

pub(crate) fn validate_runtime_identifier(field_name: &str, value: &str) -> anyhow::Result<()> {
  if value.trim() != value || value.is_empty() {
    bail!("{field_name} must not be empty or padded");
  }
  if !value
    .bytes()
    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
  {
    bail!("{field_name} must contain only ASCII letters, digits, '-', '_' or '.'");
  }
  Ok(())
}

fn routes_without_waf_are_equivalent(left: &[RouteConfig], right: &[RouteConfig]) -> bool {
  left.len() == right.len()
    && left.iter().zip(right).all(|(left, right)| {
      left.name == right.name
        && left.hosts == right.hosts
        && left.path_prefix == right.path_prefix
        && left.r#match == right.r#match
        && left.replace_prefix_with == right.replace_prefix_with
        && left.actions == right.actions
        && left.upstream == right.upstream
        && left.upstream_pool == right.upstream_pool
        && left.static_root == right.static_root
        && left.static_files == right.static_files
        && left.upstream_http_version == right.upstream_http_version
        && left.generic_http_upgrade == right.generic_http_upgrade
        && left.connect_tunneling == right.connect_tunneling
        && left.grpc_web == right.grpc_web
        && left.external_auth == right.external_auth
        && left.cache == right.cache
        && left.compression == right.compression
        && left.buffering == right.buffering
        && left.limits == right.limits
    })
}

fn validate_effective_buffering(
  field_name: &str,
  mode: BufferingMode,
  max_temp_file_bytes: usize,
  requires_temp_dir: &mut bool,
) -> anyhow::Result<()> {
  if mode == BufferingMode::Spool {
    if max_temp_file_bytes == 0 {
      bail!("{field_name}.max_temp_file_bytes must be greater than 0 when buffering uses spool");
    }
    *requires_temp_dir = true;
  }
  Ok(())
}

fn route_waf_configs_are_equivalent(left: &[RouteConfig], right: &[RouteConfig]) -> bool {
  left.len() == right.len()
    && left
      .iter()
      .zip(right)
      .all(|(left, right)| left.name == right.name && left.waf == right.waf)
}

fn normalize_merged_lb_policy_compat(value: &mut toml::Value) -> anyhow::Result<()> {
  let diagnostics = lb_policy_compat::normalize_toml_from_config(value)?;
  lb_policy_compat::ensure_supported(&diagnostics)
}

fn validate_merged_toml_shape(value: &toml::Value) -> anyhow::Result<()> {
  reject_removed_access_log_config(value)?;
  let strict = value
    .get("config")
    .and_then(|config| config.get("strict_unknown_fields"))
    .and_then(toml::Value::as_bool)
    .unwrap_or(true);
  if !strict {
    return Ok(());
  }

  let mut unknown = Vec::new();
  collect_unknown_keys(value, "", &mut unknown);
  if !unknown.is_empty() {
    unknown.sort();
    bail!(
      "configuration contains unknown field(s): {}",
      unknown.join(", ")
    );
  }
  Ok(())
}
fn reject_removed_access_log_config(value: &toml::Value) -> anyhow::Result<()> {
  if value
    .get("database")
    .and_then(|database| database.get("access_log"))
    .is_some()
  {
    bail!(
      "database.access_log PostgreSQL access-log sink has been removed; use access_log.stdout or access_log.otlp with schema = \"ocsf\" or \"ecs\""
    );
  }
  if value
    .get("logging")
    .and_then(|logging| logging.get("access_log"))
    .and_then(|access_log| access_log.get("database"))
    .is_some()
  {
    bail!(
      "logging.access_log.database PostgreSQL access-log sink has been removed; use access_log.stdout or access_log.otlp with schema = \"ocsf\" or \"ecs\""
    );
  }
  Ok(())
}
fn collect_unknown_keys(value: &toml::Value, path: &str, unknown: &mut Vec<String>) {
  if path == "waf" || path.ends_with(".waf") || path.contains(".waf.") {
    return;
  }
  match value {
    toml::Value::Table(table) => {
      let Some(allowed) = allowed_config_keys(path) else {
        return;
      };
      for (key, child) in table {
        let child_path = join_key_path(path, key);
        if allowed.contains(key.as_str()) {
          collect_unknown_keys(child, &child_path, unknown);
        } else {
          unknown.push(child_path);
        }
      }
    }
    toml::Value::Array(items) => {
      for item in items {
        collect_unknown_keys(item, path, unknown);
      }
    }
    _ => {}
  }
}

fn join_key_path(parent: &str, key: &str) -> String {
  if parent.is_empty() {
    key.to_string()
  } else {
    format!("{parent}.{key}")
  }
}

fn allowed_config_keys(path: &str) -> Option<BTreeSet<&'static str>> {
  let keys = match path {
    "" => allowed_keys::ROOT_CONFIG_KEYS,
    "access_log" => &["admin", "otlp", "stdout", "system", "waf"][..],
    "access_log.admin" => &["enabled"][..],
    "access_log.otlp" => &[
      "batch_size",
      "enabled",
      "endpoint",
      "export_timeout_ms",
      "queue_capacity",
      "schema",
      "service_name",
      "trusted_ca_certs",
    ][..],
    "access_log.stdout" => &["enabled", "schema"][..],
    "access_log.system" => &["enabled"][..],
    "access_log.waf" => &["enabled"][..],
    "config" => &[
      "lb_policy_compat_profile",
      "strict_unknown_fields",
      "warn_on_deprecated_fields",
    ][..],
    "logging" => &["access_log", "level"][..],
    "logging.access_log" => &["enabled", "fields", "stdout"][..],
    "logging.access_log.fields" => &["expression", "name", "value"][..],
    "runtime" => &[
      "accept",
      "direct_h1_io",
      "drain",
      "hardening",
      "hot_reload",
      "linux_only",
      "main_runtime",
      "memory_only_state",
      "netport_switcher",
      "read_only_rootfs_compatible",
      "unprivileged_mode",
      "worker_multipliers",
      "worker_threads",
    ][..],
    "runtime.worker_multipliers" => &["accept", "quic_socket", "runtime"][..],
    "runtime.accept" => &[
      "accept_error_backoff_ms",
      "backlog",
      "reuse_port",
      "workers",
    ][..],
    "runtime.drain" => &[
      "graceful_timeout_ms",
      "long_connection_close_delay_ms",
      "shutdown_delay_ms",
    ][..],
    "runtime.hot_reload" => &["mode", "poll_interval_ms"][..],
    "runtime.hardening" => &["close_range", "landlock", "seccomp"][..],
    "runtime.hardening.seccomp" => &["mode"][..],
    "runtime.hardening.landlock" => &["mode", "read_paths", "read_write_paths"][..],
    "runtime.netport_switcher" => workers::NETPORT_SWITCHER_CONFIG_KEYS,
    "listeners" => &[
      "http1",
      "http2",
      "http3",
      "http_bind",
      "http_binds",
      "http_mode",
      "https_bind",
      "https_binds",
      "proxy_protocol",
    ][..],
    "listeners.proxy_protocol" => &["enabled", "trusted_sources", "version"][..],
    "client_identity" => client_identity::CLIENT_IDENTITY_CONFIG_KEYS,
    "client_identity.asn" => client_identity::CLIENT_IDENTITY_ASN_CONFIG_KEYS,
    "client_identity.asn.managed" => client_identity::CLIENT_IDENTITY_ASN_MANAGED_CONFIG_KEYS,
    "client_identity.asn.iana_registry" => {
      client_identity::CLIENT_IDENTITY_ASN_IANA_REGISTRY_CONFIG_KEYS
    }
    "crypto" => crypto::CRYPTO_CONFIG_KEYS,
    "crypto.primitives" => crypto::CRYPTO_PRIMITIVES_CONFIG_KEYS,
    "crypto.primitive_backends" => crypto::CRYPTO_PRIMITIVE_BACKENDS_CONFIG_KEYS,
    "sni_forward" => sni_forward::SNI_FORWARD_CONFIG_KEYS,
    "sni_forward.rules" => sni_forward::SNI_FORWARD_RULE_KEYS,
    "tls" => allowed_keys::TLS_CONFIG_KEYS,
    "tls.1_2" => allowed_keys::TLS12_NEGOTIATION_CONFIG_KEYS,
    "tls.1_3" => allowed_keys::TLS13_NEGOTIATION_CONFIG_KEYS,
    "tls.resumption" => allowed_keys::TLS_RESUMPTION_CONFIG_KEYS,
    "tls.remote_signer" => allowed_keys::TLS_REMOTE_SIGNER_CONFIG_KEYS,
    "tls.ocsp" => tls::OCSP_CONFIG_KEYS,
    "tls.certificates" => &[
      "cert_chain",
      "ocsp",
      "private_key",
      "remote_signer_key_id",
      "server_names",
    ][..],
    "tls.certificates.ocsp" => tls::OCSP_CONFIG_KEYS,
    "tls.crlite" => crlite::CRLITE_CONFIG_KEYS,
    "tls.crlite.managed" => crlite::CRLITE_MANAGED_CONFIG_KEYS,
    "tls.client_auth" => allowed_keys::TLS_CLIENT_AUTH_CONFIG_KEYS,
    "quic" => &[
      "alt_svc",
      "downstream",
      "host_key_file",
      "retry",
      "socket",
      "transport",
      "upstream",
      "upstream_pool",
      "zero_rtt",
    ][..],
    "quic.alt_svc" => &["enabled", "max_age_seconds", "persist", "port_overrides"][..],
    "quic.alt_svc.port_overrides" => &["advertised_port", "bind"][..],
    "quic.transport" => &[
      "datagram_receive_buffer_bytes",
      "datagram_send_buffer_bytes",
      "gso",
      "idle_timeout_ms",
      "initial_mtu",
      "keep_alive_interval_ms",
      "max_concurrent_bidi_streams",
      "max_concurrent_uni_streams",
      "max_udp_payload_size",
      "min_mtu",
      "mtu_discovery",
      "receive_window_bytes",
      "send_fairness",
      "send_window_bytes",
      "stream_receive_window_bytes",
    ][..],
    "quic.transport.mtu_discovery" => &[
      "black_hole_cooldown_ms",
      "enabled",
      "interval_ms",
      "minimum_change",
      "upper_bound",
    ][..],
    "quic.downstream" => &["transport"][..],
    "quic.downstream.transport" => &[
      "datagram_receive_buffer_bytes",
      "datagram_send_buffer_bytes",
      "gso",
      "idle_timeout_ms",
      "initial_mtu",
      "keep_alive_interval_ms",
      "max_concurrent_bidi_streams",
      "max_concurrent_uni_streams",
      "max_udp_payload_size",
      "min_mtu",
      "mtu_discovery",
      "receive_window_bytes",
      "send_fairness",
      "send_window_bytes",
      "stream_receive_window_bytes",
    ][..],
    "quic.downstream.transport.mtu_discovery" => &[
      "black_hole_cooldown_ms",
      "enabled",
      "interval_ms",
      "minimum_change",
      "upper_bound",
    ][..],
    "quic.upstream" => &["transport"][..],
    "quic.upstream.transport" => &[
      "datagram_receive_buffer_bytes",
      "datagram_send_buffer_bytes",
      "gso",
      "idle_timeout_ms",
      "initial_mtu",
      "keep_alive_interval_ms",
      "max_concurrent_bidi_streams",
      "max_concurrent_uni_streams",
      "max_udp_payload_size",
      "min_mtu",
      "mtu_discovery",
      "receive_window_bytes",
      "send_fairness",
      "send_window_bytes",
      "stream_receive_window_bytes",
    ][..],
    "quic.upstream.transport.mtu_discovery" => &[
      "black_hole_cooldown_ms",
      "enabled",
      "interval_ms",
      "minimum_change",
      "upper_bound",
    ][..],
    "quic.socket" => &[
      "receive_buffer_bytes",
      "reuse_port",
      "send_buffer_bytes",
      "workers",
    ][..],
    "quic.upstream_pool" => &["enabled", "max_connections_per_upstream", "max_lifetime_ms"][..],
    "proxy" => &[
      "auto_upgrade",
      "buffering",
      "forwarded_headers",
      "grpc_web",
      "http",
      "http2",
      "http3",
      "real_ip",
      "retry",
      "static_files",
      "trusted_ca_certs",
      "upstream_revocation",
      "upgrades",
    ][..],
    "proxy.upstream_revocation" => outbound_revocation::OUTBOUND_REVOCATION_CONFIG_KEYS,
    "proxy.upstream_revocation.ocsp" => outbound_revocation::OUTBOUND_OCSP_CONFIG_KEYS,
    "proxy.upstream_revocation.crlite" => crlite::CRLITE_CONFIG_KEYS,
    "proxy.upstream_revocation.crlite.managed" => crlite::CRLITE_MANAGED_CONFIG_KEYS,
    "proxy.forwarded_headers" => &["client_ip_source", "mode"][..],
    "proxy.auto_upgrade" => &["enabled", "max_http_version"][..],
    "proxy.real_ip" => &[
      "enabled",
      "fail_on_untrusted_forwarded_headers",
      "header",
      "recursive",
      "trusted_proxies",
    ][..],
    "proxy.upgrades" => &["connect_tunneling", "generic_http_upgrade", "websocket"][..],
    "proxy.grpc_web" => &["enabled"][..],
    "proxy.retry" => &[
      "backoff_base_ms",
      "backoff_max_ms",
      "enabled",
      "exclude_failed_pool_upstreams",
      "jitter",
      "on",
      "per_attempt_timeout_ms",
      "report_passive_health",
      "reselect_pool_on_retry",
      "retry_non_idempotent",
      "timeout_ms",
      "total_budget_ms",
      "tries",
    ][..],
    "proxy.buffering" => &[
      "max_memory_body_bytes",
      "max_temp_file_bytes",
      "request",
      "response",
      "temp_dir",
    ][..],
    "proxy.http" => &[
      "early_hints",
      "trailers",
      "expect_continue",
      "priority",
      "sse_auto_streaming",
      "direct_h1_small_request_body_max_bytes",
      "grpc",
      "errors",
    ][..],
    "proxy.http2" => &[
      "adaptive_window",
      "initial_connection_window_bytes",
      "initial_stream_window_bytes",
      "keep_alive_interval_ms",
      "keep_alive_timeout_ms",
      "keep_alive_while_idle",
      "max_frame_size_bytes",
      "max_concurrent_streams",
      "max_send_buf_size",
    ][..],
    "proxy.http3" => &["inline_bodyless_fast_path"][..],
    "proxy.http.grpc" => &["enabled", "respect_grpc_timeout", "retry"][..],
    "proxy.http.errors" => &["mode"][..],
    "proxy.static_files" => &[
      "hot_object_cache_max_bytes",
      "hot_object_cache_max_file_bytes",
      "inline_max_bytes",
      "open_file_cache_max_entries",
      "open_file_cache_ttl_ms",
      "sendfile",
      "sendfile_chunk_bytes",
      "sendfile_write_strategy",
    ][..],
    "limits" => &[
      "client_body_timeout_ms",
      "client_header_timeout_ms",
      "client_idle_timeout_ms",
      "connection_limit_identity",
      "max_connections",
      "max_connections_per_ip",
      "max_webtransport_sessions",
      "max_webtransport_sessions_per_connection",
      "max_webtransport_sessions_per_ip",
      "max_header_name_bytes",
      "max_header_value_bytes",
      "max_headers",
      "max_request_body_bytes",
      "max_requests_per_connection",
      "max_total_header_bytes",
      "max_uri_bytes",
      "response_send_timeout_ms",
      "tls_handshake_timeout_ms",
      "websocket_idle_timeout_ms",
      "webtransport_idle_timeout_ms",
    ][..],
    "compression" => &[
      "br",
      "deflate",
      "enabled",
      "gzip",
      "level",
      "max_concurrent_responses",
      "mime_types",
      "min_size_bytes",
      "policies",
      "proxied",
      "statuses",
      "upstream_accept_encoding",
      "vary",
      "zstd",
    ][..],
    "compression.policies" => &[
      "br",
      "deflate",
      "enabled",
      "gzip",
      "level",
      "mime_types",
      "min_size_bytes",
      "name",
      "proxied",
      "statuses",
      "upstream_accept_encoding",
      "vary",
      "zstd",
    ][..],
    "cache" => &[
      "admission",
      "background_refresh",
      "background_refresh_max_concurrent",
      "bypass_request_headers",
      "cache_key",
      "cache_methods",
      "default_ttl_seconds",
      "disk_dir",
      "disk_max_size_bytes",
      "enabled",
      "external_handler",
      "external_handlers",
      "lock",
      "lock_wait_timeout_ms",
      "copy_file_range",
      "max_tag_bytes",
      "max_tags_per_entry",
      "max_vary_fields",
      "max_vary_variants_per_key",
      "max_size_bytes",
      "memory_auto_fraction",
      "memory_max_size_bytes",
      "negative_statuses",
      "negative_ttl_seconds",
      "partition_key",
      "policies",
      "respect_cache_control",
      "stale_if_error",
      "stale_if_error_seconds",
      "stale_while_revalidate_seconds",
      "store",
      "stream_chunk_bytes",
      "stream_large_objects",
      "surrogate",
      "tag_headers",
      "tmpfs_dir",
    ][..],
    "cache.admission" => &[
      "content_types",
      "max_body_bytes",
      "max_tracked_keys",
      "min_hits",
      "statuses",
    ][..],
    "cache.surrogate" => &["enabled", "strip_response_header"][..],
    "cache.external_handlers" => &[
      "connect_timeout_ms",
      "endpoint",
      "fail_policy",
      "kind",
      "max_body_bytes",
      "max_inflight_requests",
      "max_metadata_bytes",
      "name",
      "request_timeout_ms",
      "token_env",
    ][..],
    "cache.stale_if_error" => &[
      "connect_error",
      "max_upstream_stale_seconds",
      "read_timeout",
      "statuses",
    ][..],
    "cache.policies" => &[
      "admission",
      "background_refresh",
      "background_refresh_max_concurrent",
      "cache_key",
      "default_ttl_seconds",
      "disk_max_size_bytes",
      "external_handler",
      "lock_wait_timeout_ms",
      "max_tag_bytes",
      "max_tags_per_entry",
      "max_vary_fields",
      "max_vary_variants_per_key",
      "memory_max_size_bytes",
      "name",
      "negative_statuses",
      "negative_ttl_seconds",
      "partition_key",
      "rules",
      "stale_if_error",
      "store",
      "tag_headers",
    ][..],
    "cache.policies.admission" => &[
      "content_types",
      "max_body_bytes",
      "max_tracked_keys",
      "min_hits",
      "statuses",
    ][..],
    "cache.policies.stale_if_error" => &[
      "connect_error",
      "max_upstream_stale_seconds",
      "read_timeout",
      "statuses",
    ][..],
    "cache.policies.rules" => &["mime_types", "store"][..],
    "admin" => &[
      "allow_insecure_plaintext",
      "audit",
      "bearer_token_env",
      "bind",
      "cache_purge_signing",
      "enabled",
      "http3",
      "operations",
      "plaintext_allowed_source_cidrs",
      "rbac",
      "tls",
      "token_store",
      "transport",
    ][..],
    "admin.audit" => &[
      "backend",
      "enabled",
      "export",
      "mode",
      "queue_capacity",
      "store",
    ][..],
    "admin.audit.store" => &["backend", "enabled", "kind"][..],
    "admin.audit.export" => &["enabled", "required_sinks", "sinks"][..],
    "admin.operations" => &[
      "enabled",
      "event_buffer",
      "max_queued",
      "max_running",
      "max_stored",
      "result_max_bytes",
      "retention_seconds",
      "webtransport",
      "webtransport_max_sessions",
      "websocket",
    ][..],
    "admin.http3" => &["bind", "enabled"][..],
    "admin.cache_purge_signing" => &[
      "enabled",
      "key_env",
      "max_skew_seconds",
      "nonce_ttl_seconds",
    ][..],
    "admin.rbac" => &["tokens"][..],
    "admin.rbac.tokens" => &[
      "bearer_token_env",
      "deny_permissions",
      "name",
      "permissions",
      "roles",
    ][..],
    "admin.token_store" => &[
      "audience",
      "backend",
      "enabled",
      "fail_closed",
      "issuer",
      "public_key_env",
      "snapshot_refresh_interval_ms",
      "token_ttl_seconds",
    ][..],
    "ipm" => &[
      "bindings",
      "backend",
      "credentials",
      "enabled",
      "fail_closed",
      "break_glass",
      "namespace",
      "policies",
      "principals",
      "trust",
    ][..],
    "ipm.break_glass" => &["argon2id_memory_mib"][..],
    "ipm.credentials" => &[
      "bearer_token_env",
      "break_glass_access_token_hash",
      "name",
      "principal",
    ][..],
    "ipm.principals" => &["groups", "id", "subject"][..],
    "ipm.policies" => &["name", "statements", "version"][..],
    "ipm.policies.statements" => &["actions", "conditions", "effect", "resources"][..],
    "ipm.policies.statements.conditions" => &["key", "operator", "values"][..],
    "ipm.bindings" => &["group", "policy", "principal"][..],
    "ipm.trust" => &["claim", "group", "principal", "source", "value"][..],
    "admin.tls" => &[
      "certificates",
      "client_auth",
      "enabled",
      "max_version",
      "min_version",
      "reject_unknown_sni",
      "require_sni",
      "resumption",
      "session_ticket_rotation_seconds",
      "session_tickets",
    ][..],
    "admin.tls.resumption" => &[
      "mode",
      "rotation_seconds",
      "session_cache_size",
      "tls13_ticket_count",
    ][..],
    "admin.tls.certificates" => &["cert_chain", "default", "private_key", "server_names"][..],
    "admin.tls.client_auth" => &["ca_certs", "mode", "verify_depth"][..],
    "metrics" => &[
      "bind",
      "detail",
      "enabled",
      "format",
      "histogram_buckets_ms",
    ][..],
    "overload" => &[
      "enabled",
      "sample_interval_ms",
      "sample_interval",
      "soft_enter_samples",
      "recovery_samples",
      "recovery_ratio",
      "signal_stale_timeout_ms",
      "thresholds",
      "actions",
      "reserved_capacity",
    ][..],
    "overload.thresholds" => &[
      "memory_soft_ratio",
      "memory_hard_ratio",
      "fd_soft_ratio",
      "fd_hard_ratio",
      "cpu_soft_ratio",
      "cpu_hard_ratio",
      "event_loop_lag_soft_ms",
      "event_loop_lag_hard_ms",
      "event_loop_lag_soft",
      "event_loop_lag_hard",
      "shared_state_waiters_soft",
      "shared_state_waiters_hard",
      "downstream_connections_soft",
      "downstream_connections_hard",
      "active_requests_soft",
      "active_requests_hard",
      "h2_streams_soft",
      "h2_streams_hard",
      "h3_streams_soft",
      "h3_streams_hard",
      "pending_upstream_requests_soft",
      "pending_upstream_requests_hard",
      "retry_concurrency_soft",
      "retry_concurrency_hard",
      "cache_fill_concurrency_soft",
      "cache_fill_concurrency_hard",
      "waf_body_inspection_concurrency_soft",
      "waf_body_inspection_concurrency_hard",
      "compression_jobs_soft",
      "compression_jobs_hard",
      "decompression_jobs_soft",
      "decompression_jobs_hard",
      "request_body_buffered_bytes_soft",
      "request_body_buffered_bytes_hard",
    ][..],
    "overload.actions" => &["soft", "hard"][..],
    "overload.actions.soft" => &[
      "disable_cache_fill",
      "compression_level_cap",
      "reject_priority_classes",
      "retry_budget_multiplier",
      "waf_body_inspection_concurrency_cap",
      "decompression_concurrency_cap",
      "prefer_cached_or_stale",
    ][..],
    "overload.actions.hard" => &[
      "reject_new_connections",
      "reject_new_streams",
      "reject_new_requests",
      "stop_large_request_bodies",
      "large_request_body_threshold_bytes",
      "disable_cache_fill",
      "disable_compression",
      "disable_retries",
      "disable_request_mirroring",
      "reject_expensive_waf_bodies",
      "enter_recoverable_drain",
      "fail_readiness",
      "response_status",
      "retry_after_seconds",
      "retry_after",
    ][..],
    "overload.reserved_capacity" => &[
      "file_descriptors",
      "admin_connections",
      "admin_requests",
      "health_connections",
      "health_requests",
      "metrics_connections",
      "metrics_requests",
    ][..],
    "circuit_breakers" => &[
      "enabled",
      "response_status",
      "capacity_retry_after_ms",
      "capacity_retry_after",
      "global",
      "route_defaults",
      "pool_defaults",
      "retry_budget",
      "failure",
      "priority",
    ][..],
    "circuit_breakers.global"
    | "circuit_breakers.route_defaults"
    | "circuit_breakers.pool_defaults" => &[
      "max_active_requests",
      "max_pending_requests",
      "pending_queue_timeout_ms",
      "pending_queue_timeout",
      "max_connections",
      "max_streams",
      "max_body_inspection_jobs",
      "max_decompression_jobs",
    ][..],
    "circuit_breakers.retry_budget" => &[
      "percent",
      "min_concurrency",
      "max_concurrency",
      "max_queue",
      "queue_timeout_ms",
      "queue_timeout",
    ][..],
    "circuit_breakers.priority" => &["enabled", "classes"][..],
    "circuit_breakers.priority.classes" => &[
      "name",
      "reserved_requests",
      "max_share",
      "max_pending_requests",
      "pending_queue_timeout_ms",
      "pending_queue_timeout",
      "rejection_policy",
    ][..],
    "circuit_breakers.failure" => &[
      "enabled",
      "on",
      "consecutive_failures",
      "minimum_requests",
      "failure_ratio",
      "window_ms",
      "window",
      "open_timeout_ms",
      "open_timeout",
      "max_open_timeout_ms",
      "max_open_timeout",
      "half_open_max_probes",
      "half_open_successes",
    ][..],
    "telemetry" => &["tracing"][..],
    "telemetry.tracing" => &[
      "enabled",
      "endpoint",
      "export_timeout_ms",
      "propagate_trace_context",
      "sample_ratio",
      "service_name",
    ][..],
    "health" => &["bind", "enabled", "live_path", "ready_path"][..],
    "security" => &["header_policies", "headers"][..],
    "security.headers" => &[
      "hsts",
      "hsts_include_subdomains",
      "hsts_max_age_seconds",
      "hsts_preload",
      "permissions_policy",
      "referrer_policy",
      "x_content_type_options",
    ][..],
    "security.header_policies" => &[
      "hsts",
      "hsts_include_subdomains",
      "hsts_max_age_seconds",
      "hsts_preload",
      "name",
      "permissions_policy",
      "referrer_policy",
      "x_content_type_options",
    ][..],
    "database" => &["mitigation"][..],
    "database.mitigation" => &[
      "backend",
      "connect_timeout_ms",
      "connection_url",
      "connection_url_env",
      "dedupe_window_ms",
      "enabled",
      "failure_policy",
      "max_connections",
      "mode",
      "namespace",
      "queue_capacity",
      "table",
      "tls",
      "ttl_seconds",
    ][..],
    "database.mitigation.tls" => &["ca_cert", "client_cert", "client_key", "mode"][..],
    "dynamic_policy" => &[
      "automation_api",
      "backend",
      "default_body",
      "default_status",
      "enabled",
      "fail_policy",
      "matching",
      "max_policies",
      "refresh_interval_ms",
    ][..],
    "dynamic_policy.automation_api" => &[
      "default_source_quota",
      "enabled",
      "require_ttl",
      "signature_key_env",
      "source_quotas",
    ][..],
    "dynamic_policy.automation_api.source_quotas" => &["max_active_policies", "source"][..],
    "dynamic_policy.matching" => &[
      "composite_identity_parts",
      "ipv4_prefix_bits",
      "ipv6_prefix_bits",
      "normalize_path",
      "token_bindings",
      "trust_route_name",
    ][..],
    "external_auth" => &[
      "claim_headers",
      "client_id_env",
      "client_secret_env",
      "endpoint",
      "fail_policy",
      "forward_headers",
      "identity_headers",
      "max_response_body_bytes",
      "name",
      "provider",
      "required_claims",
      "required_scopes",
      "terminal_response_headers",
      "timeout_ms",
    ][..],
    "external_auth.required_claims" => &["name", "value"][..],
    "external_auth.claim_headers" => &["claim", "header"][..],
    "shared_state" => &[
      "backends",
      "cache_backend",
      "cache_lock_ms",
      "connection_lease_ms",
      "connection_limits_backend",
      "default_backend",
      "dynamic_policy_backend",
      "enabled",
      "enumeration_max_items_per_operation",
      "enumeration_page_size",
      "failure_policies",
      "instance_id_env",
      "namespace",
      "operation_timeout_ms",
      "admin_tokens_backend",
      "person_proof_backend",
      "redis_plaintext_policy",
      "rate_limits_backend",
      "reload_backend",
      "sticky_sessions_backend",
      "upstream_health_backend",
    ][..],
    "shared_state.failure_policies" => &[
      "cache",
      "connection_limits",
      "person_proof",
      "rate_limits",
      "reload",
      "sticky_sessions",
      "upstream_health",
    ][..],
    "shared_state.backends" => &[
      "connect_timeout_ms",
      "connection_url",
      "connection_url_env",
      "kind",
      "max_connections",
      "name",
      "redis_auth",
      "redis_pool",
      "redis_tls",
      "tls",
    ][..],
    "shared_state.backends.redis_pool" => &[
      "circuit_breaker_failure_threshold",
      "circuit_breaker_open_timeout_ms",
      "command_timeout_ms",
      "health_check_interval_ms",
      "idle_timeout_ms",
      "max_waiters",
      "min_idle_connections",
      "pool_wait_timeout_ms",
      "reconnect_max_backoff_ms",
      "reconnect_min_backoff_ms",
    ][..],
    "shared_state.backends.redis_tls" => &[
      "ca_cert",
      "client_cert",
      "client_key",
      "server_name",
      "server_spki_sha256",
      "trust_store",
    ][..],
    "shared_state.backends.redis_auth" => &["password_file", "username_file"][..],
    "shared_state.backends.tls" => &["ca_cert", "client_cert", "client_key", "mode"][..],
    "upstreams" => &[
      "connect_timeout_ms",
      "first_byte_timeout_ms",
      "idle_timeout_ms",
      "max_http_version",
      "name",
      "origin",
      "pool_max_idle_per_host",
      "preserve_host",
      "proxy_protocol_egress",
      "read_timeout_ms",
      "request_timeout_ms",
      "send_timeout_ms",
      "tls",
      "webrtc",
      "websocket",
      "webtransport",
    ][..],
    "upstreams.tls" => &["ech", "resumption", "upstream_revocation"][..],
    "upstreams.tls.ech" => &["config_list_file", "mode"][..],
    "upstreams.tls.resumption" => &["mode", "session_cache_size", "tls12"][..],
    "upstreams.tls.upstream_revocation" => outbound_revocation::OUTBOUND_REVOCATION_CONFIG_KEYS,
    "upstreams.tls.upstream_revocation.ocsp" => outbound_revocation::OUTBOUND_OCSP_CONFIG_KEYS,
    "upstreams.tls.upstream_revocation.crlite" => crlite::CRLITE_CONFIG_KEYS,
    "upstreams.tls.upstream_revocation.crlite.managed" => crlite::CRLITE_MANAGED_CONFIG_KEYS,
    "upstream_pools" => &[
      "algorithm",
      "discovery",
      "hash_key",
      "health_check",
      "keepalive",
      "name",
      "outlier_ejection",
      "servers",
      "slow_start",
      "sticky_cookie",
      "circuit_breaker",
    ][..],
    "upstream_pools.discovery" => &[
      "datacenter",
      "endpoint",
      "file",
      "filter",
      "key_prefix",
      "kubernetes_resource",
      "min_ttl_ms",
      "name",
      "namespace",
      "port",
      "port_name",
      "provider",
      "record_type",
      "refresh_interval_ms",
      "scheme",
      "service",
      "token_env",
      "token_file",
      "update_debounce_ms",
      "watch",
      "watch_timeout_seconds",
    ][..],
    "upstream_pools.sticky_cookie" => &[
      "cookie_name",
      "fallback_algorithm",
      "http_only",
      "path",
      "same_site",
      "secret_env",
      "secure",
      "ttl_seconds",
    ][..],
    "upstream_pools.keepalive" => &["idle_timeout_ms", "max_idle", "max_lifetime_ms"][..],
    "upstream_pools.slow_start" => &["duration_ms", "enabled", "min_weight_percent"][..],
    "upstream_pools.outlier_ejection" => &[
      "base_ejection_ms",
      "consecutive_failures",
      "enabled",
      "max_ejection_ms",
    ][..],
    "upstream_pools.health_check" => &[
      "body",
      "body_match_max_bytes",
      "enabled",
      "expected_body_regex",
      "expected_status",
      "expected_status_ranges",
      "fall",
      "grpc_expected_statuses",
      "grpc_service",
      "health_host",
      "health_port",
      "headers",
      "healthy_threshold",
      "interval_ms",
      "jitter_ms",
      "method",
      "mode",
      "path",
      "protocol",
      "rise",
      "timeout_ms",
      "tls",
      "unhealthy_threshold",
    ][..],
    "upstream_pools.health_check.headers" => &["name", "value"][..],
    "upstream_pools.health_check.expected_status_ranges" => &["end", "start"][..],
    "upstream_pools.health_check.tls" => &["trusted_ca_certs", "upstream_revocation"][..],
    "upstream_pools.health_check.tls.upstream_revocation" => {
      outbound_revocation::OUTBOUND_REVOCATION_CONFIG_KEYS
    }
    "upstream_pools.health_check.tls.upstream_revocation.ocsp" => {
      outbound_revocation::OUTBOUND_OCSP_CONFIG_KEYS
    }
    "upstream_pools.health_check.tls.upstream_revocation.crlite" => crlite::CRLITE_CONFIG_KEYS,
    "upstream_pools.health_check.tls.upstream_revocation.crlite.managed" => {
      crlite::CRLITE_MANAGED_CONFIG_KEYS
    }
    "upstream_pools.servers" => &["backup", "id", "max_conns", "origin", "state", "weight"][..],
    "upstream_pools.circuit_breaker" | "routes.circuit_breaker" => &[
      "max_active_requests",
      "max_pending_requests",
      "pending_queue_timeout_ms",
      "pending_queue_timeout",
      "max_connections",
      "max_streams",
      "max_body_inspection_jobs",
      "max_decompression_jobs",
    ][..],
    "routes" => &[
      "actions",
      "buffering",
      "cache",
      "compression",
      "hosts",
      "match",
      "name",
      "path_prefix",
      "replace_prefix_with",
      "retry",
      "circuit_breaker",
      "security_headers",
      "priority_class",
      "connect_tunneling",
      "generic_http_upgrade",
      "grpc_web",
      "external_auth",
      "ipm",
      "limits",
      "static_root",
      "static_files",
      "tls",
      "upstream",
      "upstream_http_version",
      "upstream_pool",
      "timeouts",
      "waf",
    ][..],
    "routes.actions" => &[
      "cors",
      "redirect",
      "request_headers",
      "request_mirrors",
      "response_headers",
      "rewrite",
    ][..],
    "routes.actions.cors" => &[
      "allow_credentials",
      "allow_headers",
      "allow_methods",
      "allow_origins",
      "expose_headers",
      "max_age_seconds",
    ][..],
    "routes.actions.redirect" => &["location_template", "status"][..],
    "routes.actions.request_headers" => &["add", "remove", "set"][..],
    "routes.actions.request_headers.add" => &["name", "value"][..],
    "routes.actions.request_headers.set" => &["name", "value"][..],
    "routes.actions.request_mirrors" => &["max_body_bytes", "sample_percent", "upstream_pool"][..],
    "routes.actions.response_headers" => &["add", "remove", "set"][..],
    "routes.actions.response_headers.add" => &["name", "value"][..],
    "routes.actions.response_headers.set" => &["name", "value"][..],
    "routes.actions.rewrite" => &["path", "query"][..],
    "routes.static_files" => &[
      "cache_control",
      "cache_control_by_extension",
      "directory_index",
      "error_pages",
      "mime_overrides",
      "precompressed",
      "spa_fallback",
      "try_files",
    ][..],
    "routes.static_files.error_pages" => &["not_found", "server_error"][..],
    "routes.tls" => &["1_2", "1_3", "max_version", "min_version", "ssl_early_data"][..],
    "routes.tls.1_2" => allowed_keys::TLS12_NEGOTIATION_CONFIG_KEYS,
    "routes.tls.1_3" => allowed_keys::TLS13_NEGOTIATION_CONFIG_KEYS,
    "routes.match" => &[
      "headers",
      "methods",
      "path",
      "priority",
      "protocols",
      "queries",
      "source_cidrs",
      "terminal",
      "tls",
    ][..],
    "routes.match.headers" => &[
      "contains", "exact", "name", "prefix", "present", "regex", "suffix",
    ][..],
    "routes.match.queries" => &[
      "contains", "exact", "name", "prefix", "present", "regex", "suffix",
    ][..],
    "routes.match.path" => &["exact", "prefix", "regex"][..],
    "routes.match.tls" => &["client_cert"][..],
    "routes.match.tls.client_cert" => &[
      "fingerprint_sha256",
      "present",
      "san_dns",
      "san_ip",
      "subject_cn",
    ][..],
    "routes.match.tls.client_cert.fingerprint_sha256" => {
      &["contains", "exact", "prefix", "present", "regex", "suffix"][..]
    }
    "routes.match.tls.client_cert.san_dns" => {
      &["contains", "exact", "prefix", "present", "regex", "suffix"][..]
    }
    "routes.match.tls.client_cert.san_ip" => {
      &["contains", "exact", "prefix", "present", "regex", "suffix"][..]
    }
    "routes.match.tls.client_cert.subject_cn" => {
      &["contains", "exact", "prefix", "present", "regex", "suffix"][..]
    }
    "routes.buffering" => &[
      "max_memory_body_bytes",
      "max_temp_file_bytes",
      "request",
      "response",
    ][..],
    "routes.limits" => &["max_request_body_bytes"][..],
    "routes.timeouts" => &[
      "client_body_timeout_ms",
      "response_send_timeout_ms",
      "upstream_connect_timeout_ms",
      "upstream_first_byte_timeout_ms",
      "upstream_read_timeout_ms",
      "upstream_request_timeout_ms",
      "upstream_send_timeout_ms",
      "websocket_idle_timeout_ms",
      "webtransport_idle_timeout_ms",
    ][..],
    "routes.ipm" => &["action", "enabled"][..],
    "routes.retry" => &[
      "backoff_base_ms",
      "backoff_max_ms",
      "enabled",
      "exclude_failed_pool_upstreams",
      "jitter",
      "on",
      "per_attempt_timeout_ms",
      "report_passive_health",
      "reselect_pool_on_retry",
      "retry_non_idempotent",
      "total_budget_ms",
      "tries",
    ][..],
    "stream_listeners" => &[
      "bind",
      "connect_timeout_ms",
      "idle_timeout_ms",
      "max_udp_flows",
      "name",
      "network",
      "proxy_protocol_egress",
      "sni_rules",
      "target",
      "udp_datagram_burst",
      "udp_datagram_rate",
      "udp_batch",
      "udp_batch_size",
      "upstream_pool",
    ][..],
    "stream_listeners.sni_rules" => &[
      "connect_timeout_ms",
      "idle_timeout_ms",
      "name",
      "proxy_protocol_egress",
      "server_names",
      "target",
      "upstream_pool",
    ][..],
    "stream_upstream_pools" => &["algorithm", "hash_key", "name", "servers"][..],
    "stream_upstream_pools.servers" => {
      &["backup", "id", "max_conns", "origin", "state", "weight"][..]
    }
    "turn_upstream_pools" => &["algorithm", "hash_key", "health_check", "name", "servers"][..],
    "turn_upstream_pools.health_check" => &[
      "enabled",
      "healthy_threshold",
      "interval_ms",
      "timeout_ms",
      "unhealthy_threshold",
    ][..],
    "turn_upstream_pools.servers" => {
      &["backup", "id", "max_conns", "origin", "state", "weight"][..]
    }
    "webrtc_turn_listeners" => &[
      "auth",
      "bind_tcp",
      "bind_tls",
      "bind_udp",
      "idle_timeout_ms",
      "limits",
      "mode",
      "name",
      "peer_policy",
      "public_ip",
      "realm",
      "relay_bind_ip",
      "relay_families",
      "relay_port_range",
      "stream_outbound_queue_capacity",
      "tcp_pool",
      "tls",
      "tls_pool",
      "udp_pool",
    ][..],
    "webrtc_turn_listeners.auth" => &[
      "mode",
      "nonce_ttl_seconds",
      "rest_shared_secret",
      "rest_shared_secret_env",
      "static_credentials",
    ][..],
    "webrtc_turn_listeners.auth.static_credentials" => {
      &["password", "password_env", "username"][..]
    }
    "webrtc_turn_listeners.limits" => &[
      "max_allocation_lifetime_seconds",
      "max_allocations_per_client",
      "max_allocations_per_listener",
      "max_channels_per_allocation",
      "max_permissions_per_allocation",
    ][..],
    "webrtc_turn_listeners.peer_policy" => &[
      "allow_link_local_peers",
      "allow_loopback_peers",
      "allow_multicast_peers",
      "allow_private_peers",
      "allow_unspecified_peers",
    ][..],
    "webrtc_turn_listeners.relay_families" => {
      &["family", "public_ip", "relay_bind_ip", "relay_port_range"][..]
    }
    "webrtc_turn_listeners.relay_families.relay_port_range" => &["end", "start"][..],
    "webrtc_turn_listeners.relay_port_range" => &["end", "start"][..],
    "webrtc_turn_listeners.tls" => &[
      "cert_chain",
      "private_key",
      "remote_signer_key_id",
      "resumption",
    ][..],
    "webrtc_turn_listeners.tls.resumption" => &[
      "mode",
      "rotation_seconds",
      "session_cache_size",
      "tls13_ticket_count",
    ][..],
    "rate_limits" => &[
      "access_token_source",
      "burst",
      "identity_parts",
      "ipv4_prefix_bits",
      "ipv6_prefix_bits",
      "key",
      "max_buckets",
      "mode",
      "name",
      "rate",
      "routes",
      "status",
      "token_header",
      "token_bindings",
    ][..],
    "connection_limits" => &["key", "limit", "name", "status"][..],
    _ => return None,
  };
  Some(keys.iter().copied().collect())
}

const REDACTED_TOML_VALUE: &str = "<redacted>";
fn redact_effective_toml(value: &mut toml::Value) {
  redact_toml_path(value, &["database", "access_log", "connection_url"]);
  redact_toml_path(value, &["database", "mitigation", "connection_url"]);
  redact_toml_path(
    value,
    &["logging", "access_log", "database", "connection_url"],
  );
  if let Some(backends) = value
    .get_mut("shared_state")
    .and_then(|shared_state| shared_state.get_mut("backends"))
    .and_then(toml::Value::as_array_mut)
  {
    for backend in backends {
      redact_toml_path(backend, &["connection_url"]);
    }
  }
  if let Some(credentials) = value
    .get_mut("ipm")
    .and_then(|ipm| ipm.get_mut("credentials"))
    .and_then(toml::Value::as_array_mut)
  {
    for credential in credentials {
      redact_toml_path(credential, &["break_glass_access_token_hash"]);
    }
  }
  if let Some(listeners) = value
    .get_mut("webrtc_turn_listeners")
    .and_then(toml::Value::as_array_mut)
  {
    for listener in listeners {
      redact_toml_path(listener, &["auth", "rest_shared_secret"]);
      if let Some(static_credentials) = listener
        .get_mut("auth")
        .and_then(|auth| auth.get_mut("static_credentials"))
        .and_then(toml::Value::as_array_mut)
      {
        for credential in static_credentials {
          redact_toml_path(credential, &["password"]);
        }
      }
    }
  }
  redact_toml_url_sensitive_parts(value, &["tls", "ocsp", "responder_url"]);
  if let Some(upstreams) = value
    .get_mut("upstreams")
    .and_then(toml::Value::as_array_mut)
  {
    for upstream in upstreams {
      redact_toml_url_sensitive_parts(upstream, &["origin"]);
    }
  }
  if let Some(pools) = value
    .get_mut("upstream_pools")
    .and_then(toml::Value::as_array_mut)
  {
    for pool in pools {
      if let Some(servers) = pool.get_mut("servers").and_then(toml::Value::as_array_mut) {
        for server in servers {
          redact_toml_url_sensitive_parts(server, &["origin"]);
        }
      }
    }
  }
  if let Some(pools) = value
    .get_mut("stream_upstream_pools")
    .and_then(toml::Value::as_array_mut)
  {
    for pool in pools {
      if let Some(servers) = pool.get_mut("servers").and_then(toml::Value::as_array_mut) {
        for server in servers {
          redact_toml_url_sensitive_parts(server, &["origin"]);
        }
      }
    }
  }
}

fn redact_toml_path(value: &mut toml::Value, path: &[&str]) {
  let Some((last, parents)) = path.split_last() else {
    return;
  };
  let mut current = value;
  for key in parents {
    let Some(next) = current.get_mut(*key) else {
      return;
    };
    current = next;
  }
  if let Some(secret) = current.get_mut(*last) {
    *secret = toml::Value::String(REDACTED_TOML_VALUE.to_string());
  }
}

fn redact_toml_url_sensitive_parts(value: &mut toml::Value, path: &[&str]) {
  let Some((last, parents)) = path.split_last() else {
    return;
  };
  let mut current = value;
  for key in parents {
    let Some(next) = current.get_mut(*key) else {
      return;
    };
    current = next;
  }
  let Some(origin) = current.get_mut(*last) else {
    return;
  };
  let Some(redacted) = origin.as_str().and_then(redact_url_sensitive_parts) else {
    return;
  };
  *origin = toml::Value::String(redacted);
}

fn redact_url_sensitive_parts(raw: &str) -> Option<String> {
  let Ok(mut url) = Url::parse(raw) else {
    return None;
  };
  if url.username().is_empty()
    && url.password().is_none()
    && url.query().is_none()
    && url.fragment().is_none()
  {
    return None;
  }
  let _ = url.set_username("");
  let _ = url.set_password(None);
  url.set_query(None);
  url.set_fragment(None);
  Some(url.to_string())
}

fn set_toml_integer_path(
  value: &mut toml::Value,
  path: &[&str],
  resolved: usize,
) -> anyhow::Result<()> {
  let resolved = i64::try_from(resolved).context("resolved worker count is too large")?;
  set_toml_value_path(value, path, toml::Value::Integer(resolved))
}

fn set_toml_float_path(
  value: &mut toml::Value,
  path: &[&str],
  resolved: f64,
) -> anyhow::Result<()> {
  set_toml_value_path(value, path, toml::Value::Float(resolved))
}

fn set_toml_value_path(
  value: &mut toml::Value,
  path: &[&str],
  resolved: toml::Value,
) -> anyhow::Result<()> {
  let Some((leaf, parents)) = path.split_last() else {
    return Ok(());
  };
  let mut current = value
    .as_table_mut()
    .ok_or_else(|| anyhow!("effective TOML root must be a table"))?;
  for key in parents {
    let entry = current
      .entry((*key).to_string())
      .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    current = entry
      .as_table_mut()
      .ok_or_else(|| anyhow!("effective TOML path {} must be a table", parents.join(".")))?;
  }
  current.insert((*leaf).to_string(), resolved);
  Ok(())
}

fn config_base_dir(path: &Path) -> anyhow::Result<PathBuf> {
  let absolute_path = absolute_config_path(path)?;

  Ok(
    absolute_path
      .parent()
      .unwrap_or_else(|| Path::new("."))
      .to_path_buf(),
  )
}

struct ConfigPathRoots {
  config_dir: PathBuf,
  cert_dir: PathBuf,
  oxirule_dir: PathBuf,
}

fn config_path_roots(path: &Path) -> anyhow::Result<ConfigPathRoots> {
  let config_dir = config_base_dir(path)?;
  let layout_root = config_dir
    .parent()
    .unwrap_or_else(|| Path::new("."))
    .to_path_buf();

  Ok(ConfigPathRoots {
    config_dir,
    cert_dir: layout_root.join("cert"),
    oxirule_dir: layout_root.join("oxirule"),
  })
}

pub(crate) fn resolve_local_config_file_path(
  field_name: &str,
  base_dir: &Path,
  path: &Path,
) -> anyhow::Result<PathBuf> {
  if path.is_absolute() {
    bail!("{field_name} must be a relative path under the configured directory");
  }

  validate_relative_path(field_name, path)?;
  Ok(base_dir.join(path))
}

pub(crate) fn canonicalize_local_config_file_target(
  field_name: &str,
  path: &Path,
) -> anyhow::Result<PathBuf> {
  match path.canonicalize() {
    Ok(path) => Ok(path),
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      canonicalize_missing_local_config_file_target(field_name, path)
    }
    Err(error) => {
      Err(error).with_context(|| format!("failed to resolve {field_name} {}", path.display()))
    }
  }
}

fn canonicalize_missing_local_config_file_target(
  field_name: &str,
  path: &Path,
) -> anyhow::Result<PathBuf> {
  let mut missing_components = Vec::new();
  let mut current = path;
  loop {
    if current
      .try_exists()
      .with_context(|| format!("failed to inspect {field_name} {}", current.display()))?
    {
      let mut canonical = current
        .canonicalize()
        .with_context(|| format!("failed to resolve {field_name} {}", path.display()))?;
      for component in missing_components.iter().rev() {
        canonical.push(component);
      }
      return Ok(canonical);
    }
    let file_name = current.file_name().ok_or_else(|| {
      anyhow!(
        "failed to resolve {field_name} {} because no existing ancestor was found",
        path.display()
      )
    })?;
    missing_components.push(PathBuf::from(file_name));
    current = current.parent().ok_or_else(|| {
      anyhow!(
        "failed to resolve {field_name} {} because no parent directory was found",
        path.display()
      )
    })?;
  }
}

pub(crate) fn resolve_existing_local_config_file_path_with_logical(
  field_name: &str,
  base_dir: &Path,
  path: &Path,
) -> anyhow::Result<(PathBuf, PathBuf)> {
  let resolved_path = resolve_local_config_file_path(field_name, base_dir, path)?;
  let canonical_base_dir = base_dir.canonicalize().with_context(|| {
    format!(
      "failed to resolve configured directory {}",
      base_dir.display()
    )
  })?;
  let canonical_path = resolved_path
    .canonicalize()
    .with_context(|| format!("failed to resolve {field_name} {}", resolved_path.display()))?;

  if !canonical_path.starts_with(&canonical_base_dir) {
    bail!("{field_name} must stay within the configured directory");
  }
  ensure_regular_file(field_name, &canonical_path)?;

  Ok((canonical_path, resolved_path))
}

pub(crate) fn canonicalize_existing_file(field_name: &str, path: &Path) -> anyhow::Result<PathBuf> {
  let canonical_path = path
    .canonicalize()
    .with_context(|| format!("failed to resolve {field_name} {}", path.display()))?;
  ensure_regular_file(field_name, &canonical_path)?;

  Ok(canonical_path)
}

fn ensure_regular_file(field_name: &str, path: &Path) -> anyhow::Result<()> {
  let metadata = path
    .metadata()
    .with_context(|| format!("failed to inspect {field_name} {}", path.display()))?;

  if !metadata.is_file() {
    bail!("{field_name} must point to a regular file");
  }

  Ok(())
}

fn validate_relative_path(field_name: &str, path: &Path) -> anyhow::Result<()> {
  if path.as_os_str().is_empty() {
    bail!("{field_name} must not be empty");
  }

  for component in path.components() {
    match component {
      Component::Normal(_) => {}
      Component::CurDir | Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
        bail!(
          "{field_name} must not contain absolute, current-directory, or parent-directory components"
        );
      }
    }
  }

  Ok(())
}

fn validate_optional_non_empty(field_name: &str, value: Option<&str>) -> anyhow::Result<()> {
  if matches!(value, Some(value) if value.trim().is_empty()) {
    bail!("{field_name} must not be empty");
  }
  Ok(())
}

pub(crate) fn quote_postgres_identifier_path(
  field_name: &str,
  value: &str,
) -> anyhow::Result<String> {
  validate_postgres_identifier_path(field_name, value)?;

  Ok(
    value
      .split('.')
      .map(|segment| format!("\"{segment}\""))
      .collect::<Vec<_>>()
      .join("."),
  )
}

fn validate_postgres_identifier_path(field_name: &str, value: &str) -> anyhow::Result<()> {
  if value.trim().is_empty() {
    bail!("{field_name} must not be empty");
  }

  let parts = value.split('.').collect::<Vec<_>>();
  if parts.len() > 2 || parts.iter().any(|part| part.is_empty()) {
    bail!("{field_name} must be an unqualified table name or schema-qualified table name");
  }

  for part in parts {
    validate_postgres_identifier(field_name, part)?;
  }

  Ok(())
}

fn validate_postgres_identifier(field_name: &str, value: &str) -> anyhow::Result<()> {
  let mut bytes = value.bytes();
  let Some(first) = bytes.next() else {
    bail!("{field_name} must not contain empty identifier segments");
  };
  if !(first.is_ascii_alphabetic() || first == b'_') {
    bail!("{field_name} identifier segments must start with an ASCII letter or underscore");
  }
  if value.len() > 63 {
    bail!("{field_name} identifier segments must be 63 bytes or shorter");
  }
  if !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
    bail!(
      "{field_name} identifier segments must contain only ASCII letters, digits, or underscores"
    );
  }
  Ok(())
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RuntimeDrainConfig {
  #[serde(default = "default_drain_graceful_timeout_ms")]
  pub graceful_timeout_ms: u64,
  #[serde(default = "default_drain_long_connection_close_delay_ms")]
  pub long_connection_close_delay_ms: u64,
  #[serde(default)]
  pub shutdown_delay_ms: u64,
}

impl Default for RuntimeDrainConfig {
  fn default() -> Self {
    Self {
      graceful_timeout_ms: default_drain_graceful_timeout_ms(),
      long_connection_close_delay_ms: default_drain_long_connection_close_delay_ms(),
      shutdown_delay_ms: 0,
    }
  }
}

impl RuntimeDrainConfig {
  fn validate(&self) -> anyhow::Result<()> {
    if self.graceful_timeout_ms == 0 {
      bail!("runtime.drain.graceful_timeout_ms must be greater than 0");
    }
    if self.long_connection_close_delay_ms == 0 {
      bail!("runtime.drain.long_connection_close_delay_ms must be greater than 0");
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct HotReloadConfig {
  #[serde(default)]
  pub mode: HotReloadMode,
  #[serde(default = "default_hot_reload_poll_interval_ms")]
  pub poll_interval_ms: u64,
}

impl Default for HotReloadConfig {
  fn default() -> Self {
    Self {
      mode: HotReloadMode::Off,
      poll_interval_ms: default_hot_reload_poll_interval_ms(),
    }
  }
}

impl HotReloadConfig {
  fn validate(&self) -> anyhow::Result<()> {
    if self.poll_interval_ms == 0 {
      bail!("runtime.hot_reload.poll_interval_ms must be greater than 0");
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HotReloadMode {
  #[default]
  Off,
  #[serde(rename = "oxirule")]
  OxiRule,
  Full,
  DownstreamTls,
}

impl HotReloadMode {
  pub fn enabled(self) -> bool {
    self != Self::Off
  }
}

impl std::fmt::Display for HotReloadMode {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str(match self {
      Self::Off => "off",
      Self::OxiRule => "oxirule",
      Self::Full => "full",
      Self::DownstreamTls => "downstream_tls",
    })
  }
}

impl FromStr for HotReloadMode {
  type Err = anyhow::Error;

  fn from_str(value: &str) -> Result<Self, Self::Err> {
    match value {
      "off" => Ok(Self::Off),
      "oxirule" => Ok(Self::OxiRule),
      "full" => Ok(Self::Full),
      "downstream_tls" => Ok(Self::DownstreamTls),
      _ => {
        bail!("unsupported hot reload mode {value}; expected off, oxirule, full, or downstream_tls")
      }
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct ProxyConfig {
  #[serde(default)]
  pub auto_upgrade: AutoUpgradeConfig,
  #[serde(default)]
  pub forwarded_headers: ForwardedHeadersConfig,
  #[serde(default)]
  pub real_ip: RealIpConfig,
  #[serde(default)]
  pub upgrades: ProxyUpgradesConfig,
  #[serde(default)]
  pub grpc_web: ProxyGrpcWebConfig,
  #[serde(default)]
  pub retry: ProxyRetryConfig,
  #[serde(default)]
  pub buffering: ProxyBufferingConfig,
  #[serde(default)]
  pub http: ProxyHttpConfig,
  #[serde(default)]
  pub http2: ProxyHttp2Config,
  #[serde(default)]
  pub http3: ProxyHttp3Config,
  #[serde(default)]
  pub static_files: ProxyStaticFilesConfig,
  #[serde(default)]
  pub trusted_ca_certs: Vec<PathBuf>,
  #[serde(default)]
  pub upstream_revocation: OutboundTlsRevocationConfig,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
pub struct ForwardedHeadersConfig {
  #[serde(default)]
  pub mode: ForwardedHeaderMode,
  #[serde(default)]
  pub client_ip_source: ForwardedClientIpSource,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ForwardedHeaderMode {
  #[default]
  Overwrite,
  Append,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ForwardedClientIpSource {
  #[default]
  Resolved,
  DirectPeer,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RealIpConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub trusted_proxies: Vec<String>,
  #[serde(default)]
  pub header: RealIpHeader,
  #[serde(default = "default_true")]
  pub recursive: bool,
  #[serde(default)]
  pub fail_on_untrusted_forwarded_headers: bool,
}

impl Default for RealIpConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      trusted_proxies: Vec::new(),
      header: RealIpHeader::XForwardedFor,
      recursive: true,
      fail_on_untrusted_forwarded_headers: false,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum RealIpHeader {
  #[default]
  XForwardedFor,
  XRealIp,
  Forwarded,
  CfConnectingIp,
}

impl RealIpHeader {
  pub fn header_name(self) -> &'static str {
    match self {
      Self::XForwardedFor => "x-forwarded-for",
      Self::XRealIp => "x-real-ip",
      Self::Forwarded => "forwarded",
      Self::CfConnectingIp => "cf-connecting-ip",
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ProxyUpgradesConfig {
  #[serde(default = "default_true")]
  pub websocket: bool,
  #[serde(default)]
  pub generic_http_upgrade: bool,
  #[serde(default)]
  pub connect_tunneling: bool,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
pub struct ProxyGrpcWebConfig {
  #[serde(default)]
  pub enabled: bool,
}

impl Default for ProxyUpgradesConfig {
  fn default() -> Self {
    Self {
      websocket: true,
      generic_http_upgrade: false,
      connect_tunneling: false,
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ProxyBufferingConfig {
  #[serde(default)]
  pub request: BufferingMode,
  #[serde(default)]
  pub response: BufferingMode,
  #[serde(default = "default_buffering_max_memory_body_bytes")]
  pub max_memory_body_bytes: usize,
  #[serde(default)]
  pub max_temp_file_bytes: usize,
  #[serde(default)]
  pub temp_dir: Option<PathBuf>,
}

impl Default for ProxyBufferingConfig {
  fn default() -> Self {
    Self {
      request: BufferingMode::Streaming,
      response: BufferingMode::Streaming,
      max_memory_body_bytes: default_buffering_max_memory_body_bytes(),
      max_temp_file_bytes: 0,
      temp_dir: None,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BufferingMode {
  #[default]
  Streaming,
  Memory,
  Spool,
  RejectIfTooLarge,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ProxyHttpConfig {
  #[serde(default)]
  pub early_hints: EarlyHintsMode,
  #[serde(default)]
  pub trailers: TrailerMode,
  #[serde(default)]
  pub expect_continue: ExpectContinueMode,
  #[serde(default)]
  pub priority: PriorityMode,
  #[serde(default = "default_true")]
  pub sse_auto_streaming: bool,
  #[serde(default = "default_direct_h1_small_request_body_max_bytes")]
  pub direct_h1_small_request_body_max_bytes: usize,
  #[serde(default)]
  pub grpc: ProxyHttpGrpcConfig,
  #[serde(default)]
  pub errors: ProxyHttpErrorsConfig,
}

impl Default for ProxyHttpConfig {
  fn default() -> Self {
    Self {
      early_hints: EarlyHintsMode::Drop,
      trailers: TrailerMode::Pass,
      expect_continue: ExpectContinueMode::Auto,
      priority: PriorityMode::Pass,
      sse_auto_streaming: true,
      direct_h1_small_request_body_max_bytes: default_direct_h1_small_request_body_max_bytes(),
      grpc: ProxyHttpGrpcConfig::default(),
      errors: ProxyHttpErrorsConfig::default(),
    }
  }
}

pub(crate) fn default_direct_h1_small_request_body_max_bytes() -> usize {
  16 * 1024
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EarlyHintsMode {
  #[default]
  Drop,
  Pass,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TrailerMode {
  #[default]
  Pass,
  Drop,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExpectContinueMode {
  #[default]
  Auto,
  Reject,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PriorityMode {
  #[default]
  Pass,
  Ignore,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ProxyHttpGrpcConfig {
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default = "default_true")]
  pub respect_grpc_timeout: bool,
  #[serde(default)]
  pub retry: GrpcRetryMode,
}

impl Default for ProxyHttpGrpcConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      respect_grpc_timeout: true,
      retry: GrpcRetryMode::Off,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GrpcRetryMode {
  #[default]
  Off,
  SafeUnary,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct ProxyHttpErrorsConfig {
  #[serde(default)]
  pub mode: ErrorResponseMode,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorResponseMode {
  #[default]
  LegacyPlain,
  Plain,
  Json,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AutoUpgradeConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_proxy_max_http_version")]
  pub max_http_version: HttpVersion,
}

impl Default for AutoUpgradeConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      max_http_version: HttpVersion::H2,
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct LimitsConfig {
  #[serde(default = "default_max_connections")]
  pub max_connections: usize,
  #[serde(default = "default_max_connections_per_ip")]
  pub max_connections_per_ip: usize,
  #[serde(default)]
  pub max_webtransport_sessions: Option<usize>,
  #[serde(default)]
  pub max_webtransport_sessions_per_ip: Option<usize>,
  #[serde(default = "default_max_webtransport_sessions_per_connection")]
  pub max_webtransport_sessions_per_connection: usize,
  #[serde(default)]
  pub connection_limit_identity: ConnectionLimitIdentityMode,
  #[serde(default = "default_max_requests_per_connection")]
  pub max_requests_per_connection: usize,
  #[serde(default = "default_client_header_timeout_ms")]
  pub client_header_timeout_ms: u64,
  #[serde(default = "default_client_body_timeout_ms")]
  pub client_body_timeout_ms: u64,
  #[serde(default = "default_client_idle_timeout_ms")]
  pub client_idle_timeout_ms: u64,
  #[serde(default = "default_client_idle_timeout_ms")]
  pub websocket_idle_timeout_ms: u64,
  #[serde(default = "default_client_idle_timeout_ms")]
  pub webtransport_idle_timeout_ms: u64,
  #[serde(default = "default_tls_handshake_timeout_ms")]
  pub tls_handshake_timeout_ms: u64,
  #[serde(default = "default_response_send_timeout_ms")]
  pub response_send_timeout_ms: u64,
  #[serde(default = "default_max_headers")]
  pub max_headers: usize,
  #[serde(default = "default_max_header_name_bytes")]
  pub max_header_name_bytes: usize,
  #[serde(default = "default_max_header_value_bytes")]
  pub max_header_value_bytes: usize,
  #[serde(default = "default_max_total_header_bytes")]
  pub max_total_header_bytes: usize,
  #[serde(default = "default_max_uri_bytes")]
  pub max_uri_bytes: usize,
  #[serde(default = "default_max_request_body_bytes")]
  pub max_request_body_bytes: u64,
}

impl Default for LimitsConfig {
  fn default() -> Self {
    Self {
      max_connections: default_max_connections(),
      max_connections_per_ip: default_max_connections_per_ip(),
      max_webtransport_sessions: None,
      max_webtransport_sessions_per_ip: None,
      max_webtransport_sessions_per_connection: default_max_webtransport_sessions_per_connection(),
      connection_limit_identity: ConnectionLimitIdentityMode::default(),
      max_requests_per_connection: default_max_requests_per_connection(),
      client_header_timeout_ms: default_client_header_timeout_ms(),
      client_body_timeout_ms: default_client_body_timeout_ms(),
      client_idle_timeout_ms: default_client_idle_timeout_ms(),
      websocket_idle_timeout_ms: default_client_idle_timeout_ms(),
      webtransport_idle_timeout_ms: default_client_idle_timeout_ms(),
      tls_handshake_timeout_ms: default_tls_handshake_timeout_ms(),
      response_send_timeout_ms: default_response_send_timeout_ms(),
      max_headers: default_max_headers(),
      max_header_name_bytes: default_max_header_name_bytes(),
      max_header_value_bytes: default_max_header_value_bytes(),
      max_total_header_bytes: default_max_total_header_bytes(),
      max_uri_bytes: default_max_uri_bytes(),
      max_request_body_bytes: default_max_request_body_bytes(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionLimitIdentityMode {
  #[default]
  ProxyProtocol,
  FirstRequestRealIp,
  PerRequestRealIp,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ConnectionLimitConfig {
  pub name: String,
  #[serde(default)]
  pub key: LimitKey,
  pub limit: usize,
  #[serde(default = "default_connection_limit_status")]
  pub status: u16,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LimitKey {
  #[default]
  ClientIp,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LimitMode {
  #[default]
  Enforcing,
  Monitor,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CacheConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub store: CacheStore,
  #[serde(default)]
  pub tmpfs_dir: Option<PathBuf>,
  #[serde(default)]
  pub disk_dir: Option<PathBuf>,
  #[serde(default = "default_cache_max_size_bytes")]
  pub max_size_bytes: usize,
  #[serde(default)]
  pub memory_max_size_bytes: Option<usize>,
  #[serde(default)]
  pub disk_max_size_bytes: Option<usize>,
  #[serde(default = "default_cache_memory_auto_fraction")]
  pub memory_auto_fraction: f64,
  #[serde(default = "default_cache_default_ttl_seconds")]
  pub default_ttl_seconds: u64,
  #[serde(default = "default_cache_methods")]
  pub cache_methods: Vec<String>,
  #[serde(default = "default_cache_key")]
  pub cache_key: String,
  #[serde(default)]
  pub partition_key: String,
  #[serde(default = "default_true")]
  pub respect_cache_control: bool,
  #[serde(default)]
  pub surrogate: CacheSurrogateConfig,
  #[serde(default)]
  pub stale_if_error_seconds: u64,
  #[serde(default = "default_true")]
  pub lock: bool,
  #[serde(default)]
  pub stale_while_revalidate_seconds: u64,
  #[serde(default)]
  pub negative_statuses: Vec<u16>,
  #[serde(default)]
  pub negative_ttl_seconds: u64,
  #[serde(default = "default_cache_tag_headers")]
  pub tag_headers: Vec<String>,
  #[serde(default = "default_cache_max_tags_per_entry")]
  pub max_tags_per_entry: usize,
  #[serde(default = "default_cache_max_tag_bytes")]
  pub max_tag_bytes: usize,
  #[serde(default = "default_cache_max_vary_fields")]
  pub max_vary_fields: usize,
  #[serde(default = "default_cache_max_vary_variants_per_key")]
  pub max_vary_variants_per_key: usize,
  #[serde(default = "default_cache_bypass_request_headers")]
  pub bypass_request_headers: Vec<String>,
  #[serde(default = "default_true")]
  pub stream_large_objects: bool,
  #[serde(default = "default_cache_stream_chunk_bytes")]
  pub stream_chunk_bytes: usize,
  #[serde(default = "default_true")]
  pub background_refresh: bool,
  #[serde(default = "default_cache_background_refresh_max_concurrent")]
  pub background_refresh_max_concurrent: usize,
  #[serde(default = "default_cache_lock_wait_timeout_ms")]
  pub lock_wait_timeout_ms: u64,
  #[serde(default)]
  pub copy_file_range: CacheCopyFileRangeMode,
  #[serde(default)]
  pub admission: CacheAdmissionConfig,
  #[serde(default)]
  pub stale_if_error: CacheStaleIfErrorConfig,
  #[serde(default)]
  pub policies: Vec<CachePolicyConfig>,
  #[serde(default)]
  pub external_handler: Option<String>,
  #[serde(default)]
  pub external_handlers: Vec<ExternalCacheHandlerConfig>,
}

impl Default for CacheConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      store: CacheStore::Memory,
      tmpfs_dir: None,
      disk_dir: None,
      max_size_bytes: default_cache_max_size_bytes(),
      memory_max_size_bytes: None,
      disk_max_size_bytes: None,
      memory_auto_fraction: default_cache_memory_auto_fraction(),
      default_ttl_seconds: default_cache_default_ttl_seconds(),
      cache_methods: default_cache_methods(),
      cache_key: default_cache_key(),
      partition_key: String::new(),
      respect_cache_control: true,
      surrogate: CacheSurrogateConfig::default(),
      stale_if_error_seconds: 0,
      lock: true,
      stale_while_revalidate_seconds: 0,
      negative_statuses: Vec::new(),
      negative_ttl_seconds: 0,
      tag_headers: default_cache_tag_headers(),
      max_tags_per_entry: default_cache_max_tags_per_entry(),
      max_tag_bytes: default_cache_max_tag_bytes(),
      max_vary_fields: default_cache_max_vary_fields(),
      max_vary_variants_per_key: default_cache_max_vary_variants_per_key(),
      bypass_request_headers: default_cache_bypass_request_headers(),
      stream_large_objects: true,
      stream_chunk_bytes: default_cache_stream_chunk_bytes(),
      background_refresh: true,
      background_refresh_max_concurrent: default_cache_background_refresh_max_concurrent(),
      lock_wait_timeout_ms: default_cache_lock_wait_timeout_ms(),
      copy_file_range: CacheCopyFileRangeMode::Auto,
      admission: CacheAdmissionConfig::default(),
      stale_if_error: CacheStaleIfErrorConfig::default(),
      policies: Vec::new(),
      external_handler: None,
      external_handlers: Vec::new(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CacheStore {
  #[default]
  Memory,
  Tmpfs,
  Disk,
  MemoryThenDisk,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CacheCopyFileRangeMode {
  #[default]
  Auto,
  Off,
  Required,
}

impl CacheStore {
  pub fn uses_disk(self) -> bool {
    matches!(self, Self::Disk | Self::MemoryThenDisk)
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CachePolicyConfig {
  pub name: String,
  #[serde(default)]
  pub store: Option<CacheStore>,
  #[serde(default)]
  pub cache_key: Option<String>,
  #[serde(default)]
  pub partition_key: Option<String>,
  #[serde(default)]
  pub default_ttl_seconds: Option<u64>,
  #[serde(default)]
  pub negative_statuses: Option<Vec<u16>>,
  #[serde(default)]
  pub negative_ttl_seconds: Option<u64>,
  #[serde(default)]
  pub memory_max_size_bytes: Option<usize>,
  #[serde(default)]
  pub disk_max_size_bytes: Option<usize>,
  #[serde(default)]
  pub tag_headers: Option<Vec<String>>,
  #[serde(default)]
  pub max_tags_per_entry: Option<usize>,
  #[serde(default)]
  pub max_tag_bytes: Option<usize>,
  #[serde(default)]
  pub max_vary_fields: Option<usize>,
  #[serde(default)]
  pub max_vary_variants_per_key: Option<usize>,
  #[serde(default)]
  pub background_refresh: Option<bool>,
  #[serde(default)]
  pub background_refresh_max_concurrent: Option<usize>,
  #[serde(default)]
  pub lock_wait_timeout_ms: Option<u64>,
  #[serde(default)]
  pub admission: Option<CacheAdmissionConfig>,
  #[serde(default)]
  pub stale_if_error: Option<CacheStaleIfErrorConfig>,
  #[serde(default)]
  pub external_handler: Option<String>,
  #[serde(default)]
  pub rules: Vec<CachePolicyRuleConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AdminConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_admin_bind")]
  pub bind: SocketAddr,
  #[serde(default = "default_admin_bearer_token_env")]
  pub bearer_token_env: String,
  #[serde(default)]
  pub transport: AdminTransportMode,
  #[serde(default)]
  pub allow_insecure_plaintext: bool,
  #[serde(default = "default_admin_plaintext_allowed_source_cidrs")]
  pub plaintext_allowed_source_cidrs: Vec<String>,
  #[serde(default)]
  pub cache_purge_signing: AdminCachePurgeSigningConfig,
  #[serde(default)]
  pub audit: AdminAuditConfig,
  #[serde(default)]
  pub operations: AdminOperationsConfig,
  #[serde(default)]
  pub http3: AdminHttp3Config,
  #[serde(default)]
  pub tls: AdminTlsConfig,
  #[serde(default, rename = "rbac")]
  legacy_rbac: Option<LegacyAdminRbacConfig>,
  #[serde(default, rename = "token_store")]
  legacy_token_store: Option<LegacyAdminTokenStoreConfig>,
}

impl Default for AdminConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      bind: default_admin_bind(),
      bearer_token_env: default_admin_bearer_token_env(),
      transport: AdminTransportMode::Auto,
      allow_insecure_plaintext: false,
      plaintext_allowed_source_cidrs: default_admin_plaintext_allowed_source_cidrs(),
      cache_purge_signing: AdminCachePurgeSigningConfig::default(),
      audit: AdminAuditConfig::default(),
      operations: AdminOperationsConfig::default(),
      http3: AdminHttp3Config::default(),
      tls: AdminTlsConfig::default(),
      legacy_rbac: None,
      legacy_token_store: None,
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AdminOperationsConfig {
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default = "default_admin_operations_max_running")]
  pub max_running: usize,
  #[serde(default = "default_admin_operations_max_queued")]
  pub max_queued: usize,
  #[serde(default = "default_admin_operations_max_stored")]
  pub max_stored: usize,
  #[serde(default = "default_admin_operations_retention_seconds")]
  pub retention_seconds: u64,
  #[serde(default = "default_admin_operations_event_buffer")]
  pub event_buffer: usize,
  #[serde(default = "default_admin_operations_result_max_bytes")]
  pub result_max_bytes: usize,
  #[serde(default = "default_true")]
  pub websocket: bool,
  #[serde(default = "default_true")]
  pub webtransport: bool,
  #[serde(default = "default_admin_operations_webtransport_max_sessions")]
  pub webtransport_max_sessions: usize,
}

impl Default for AdminOperationsConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      max_running: default_admin_operations_max_running(),
      max_queued: default_admin_operations_max_queued(),
      max_stored: default_admin_operations_max_stored(),
      retention_seconds: default_admin_operations_retention_seconds(),
      event_buffer: default_admin_operations_event_buffer(),
      result_max_bytes: default_admin_operations_result_max_bytes(),
      websocket: true,
      webtransport: true,
      webtransport_max_sessions: default_admin_operations_webtransport_max_sessions(),
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct AdminHttp3Config {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub bind: Option<SocketAddr>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AdminCachePurgeSigningConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_cache_purge_signing_key_env")]
  pub key_env: String,
  #[serde(default = "default_cache_purge_signing_max_skew_seconds")]
  pub max_skew_seconds: u64,
  #[serde(default = "default_cache_purge_signing_nonce_ttl_seconds")]
  pub nonce_ttl_seconds: u64,
}

impl Default for AdminCachePurgeSigningConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      key_env: default_cache_purge_signing_key_env(),
      max_skew_seconds: default_cache_purge_signing_max_skew_seconds(),
      nonce_ttl_seconds: default_cache_purge_signing_nonce_ttl_seconds(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AdminTransportMode {
  #[default]
  Auto,
  Tls,
  PlaintextAllowlist,
  Plaintext,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct MetricsConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_metrics_bind")]
  pub bind: SocketAddr,
  #[serde(default)]
  pub format: MetricsFormat,
  #[serde(default)]
  pub detail: MetricsDetail,
  #[serde(default = "default_metrics_histogram_buckets_ms")]
  pub histogram_buckets_ms: Vec<u64>,
}

impl Default for MetricsConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      bind: default_metrics_bind(),
      format: MetricsFormat::Prometheus,
      detail: MetricsDetail::Detailed,
      histogram_buckets_ms: default_metrics_histogram_buckets_ms(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MetricsFormat {
  #[default]
  Prometheus,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MetricsDetail {
  Basic,
  #[default]
  Detailed,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct HealthConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_health_bind")]
  pub bind: SocketAddr,
  #[serde(default = "default_ready_path")]
  pub ready_path: String,
  #[serde(default = "default_live_path")]
  pub live_path: String,
}

impl Default for HealthConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      bind: default_health_bind(),
      ready_path: default_ready_path(),
      live_path: default_live_path(),
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct UpstreamConfig {
  pub name: String,
  pub origin: Url,
  #[serde(default = "default_proxy_max_http_version")]
  pub max_http_version: HttpVersion,
  #[serde(default = "default_connect_timeout_ms")]
  pub connect_timeout_ms: u64,
  #[serde(default = "default_request_timeout_ms")]
  pub request_timeout_ms: u64,
  #[serde(default = "default_request_timeout_ms")]
  pub first_byte_timeout_ms: u64,
  #[serde(default = "default_request_timeout_ms")]
  pub read_timeout_ms: u64,
  #[serde(default = "default_request_timeout_ms")]
  pub send_timeout_ms: u64,
  #[serde(default = "default_client_idle_timeout_ms")]
  pub idle_timeout_ms: u64,
  #[serde(skip, default = "default_pool_keepalive_max_lifetime_ms")]
  pub max_lifetime_ms: u64,
  #[serde(default = "default_upstream_pool_max_idle_per_host")]
  pub pool_max_idle_per_host: usize,
  #[serde(default)]
  pub preserve_host: bool,
  #[serde(default = "default_true")]
  pub websocket: bool,
  #[serde(default = "default_true")]
  pub webrtc: bool,
  #[serde(default = "default_true")]
  pub webtransport: bool,
  #[serde(default)]
  pub proxy_protocol_egress: ProxyProtocolEgressMode,
  #[serde(default)]
  pub tls: UpstreamTlsConfig,
  #[serde(skip)]
  pub extra_trusted_ca_certs: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyProtocolEgressMode {
  #[default]
  Off,
  V1,
  V2,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct UpstreamPoolConfig {
  pub name: String,
  #[serde(default)]
  pub algorithm: LoadBalancingAlgorithm,
  #[serde(default)]
  pub hash_key: Option<String>,
  #[serde(default)]
  pub sticky_cookie: UpstreamPoolStickyCookieConfig,
  #[serde(default)]
  pub keepalive: UpstreamPoolKeepaliveConfig,
  #[serde(default)]
  pub slow_start: UpstreamPoolSlowStartConfig,
  #[serde(default)]
  pub outlier_ejection: UpstreamPoolOutlierEjectionConfig,
  #[serde(default)]
  pub circuit_breaker: Option<CircuitBreakerScopeOverride>,
  #[serde(default)]
  pub servers: Vec<UpstreamPoolServerConfig>,
  #[serde(default)]
  pub discovery: Vec<UpstreamPoolDiscoveryConfig>,
  #[serde(default)]
  pub health_check: UpstreamPoolHealthCheckConfig,
}

impl UpstreamPoolConfig {
  fn resolve_discovery_paths(&mut self, config_dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut resolved_paths = Vec::new();
    for discovery in &mut self.discovery {
      if discovery.provider == UpstreamDiscoveryProvider::File {
        let Some(path) = discovery.file.take() else {
          continue;
        };
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "upstream_pools.discovery.file",
          config_dir,
          &path,
        )?;
        discovery.file = Some(resolved);
        resolved_paths.push(logical);
      }
    }
    Ok(resolved_paths)
  }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamDiscoveryProvider {
  Dns,
  File,
  Kubernetes,
  Consul,
  Etcd,
  Nomad,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DnsDiscoveryRecordType {
  A,
  Aaaa,
  #[default]
  #[serde(rename = "a_aaaa")]
  AAndAaaa,
  Srv,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DiscoveryUpstreamScheme {
  #[default]
  Http,
  Https,
}

impl DiscoveryUpstreamScheme {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Http => "http",
      Self::Https => "https",
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancingAlgorithm {
  #[default]
  PowerOfTwoChoices,
  WeightedLeastConn,
  RendezvousHash,
  RendezvousIpHash,
  Ewma,
  LeastTime,
  StickyCookie,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct UpstreamPoolKeepaliveConfig {
  #[serde(default = "default_pool_keepalive_max_idle")]
  pub max_idle: usize,
  #[serde(default = "default_client_idle_timeout_ms")]
  pub idle_timeout_ms: u64,
  #[serde(default = "default_pool_keepalive_max_lifetime_ms")]
  pub max_lifetime_ms: u64,
}

impl Default for UpstreamPoolKeepaliveConfig {
  fn default() -> Self {
    Self {
      max_idle: default_pool_keepalive_max_idle(),
      idle_timeout_ms: default_client_idle_timeout_ms(),
      max_lifetime_ms: default_pool_keepalive_max_lifetime_ms(),
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct UpstreamPoolServerConfig {
  #[serde(default)]
  pub id: Option<String>,
  pub origin: Url,
  #[serde(default = "default_pool_server_weight")]
  pub weight: u32,
  #[serde(default)]
  pub max_conns: usize,
  #[serde(default)]
  pub backup: bool,
  #[serde(default)]
  pub state: UpstreamPoolServerState,
  #[serde(skip)]
  pub source: UpstreamPoolServerSource,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamPoolServerState {
  #[default]
  Ready,
  Drain,
  Down,
  Maintenance,
}

impl UpstreamPoolServerState {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Ready => "ready",
      Self::Drain => "drain",
      Self::Down => "down",
      Self::Maintenance => "maintenance",
    }
  }

  pub fn accepts_new_requests(self) -> bool {
    self == Self::Ready
  }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum UpstreamPoolServerSource {
  #[default]
  Static,
  Dns,
  File,
  Kubernetes,
  Consul,
  Etcd,
  Nomad,
  Admin,
}

impl UpstreamPoolServerSource {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Static => "static",
      Self::Dns => "dns",
      Self::File => "file",
      Self::Kubernetes => "kubernetes",
      Self::Consul => "consul",
      Self::Etcd => "etcd",
      Self::Nomad => "nomad",
      Self::Admin => "admin",
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct UpstreamTlsConfig {
  #[serde(default)]
  pub ech: UpstreamEchConfig,
  #[serde(default)]
  pub resumption: UpstreamTlsResumptionConfig,
  #[serde(default)]
  pub upstream_revocation: Option<OutboundTlsRevocationConfig>,
}

impl UpstreamTlsConfig {
  fn resolve_relative_paths(&mut self, base_dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut source_paths = Vec::new();
    self.ech.config_list_file = self
      .ech
      .config_list_file
      .take()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "upstreams.tls.ech.config_list_file",
          base_dir,
          &path,
        )?;
        source_paths.push(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .transpose()?;
    Ok(source_paths)
  }

  fn validate(&self, upstream_name: &str) -> anyhow::Result<()> {
    if self.resumption.mode == UpstreamTlsResumptionMode::Enabled
      && self.resumption.session_cache_size == 0
    {
      bail!(
        "upstream {} tls.resumption.session_cache_size must be greater than 0 when resumption is enabled",
        upstream_name
      );
    }
    match self.ech.mode {
      UpstreamEchMode::Disabled | UpstreamEchMode::Grease => {
        if self.ech.config_list_file.is_some() {
          bail!(
            "upstream {} tls.ech.config_list_file is only valid when tls.ech.mode = \"config_list\"",
            upstream_name
          );
        }
      }
      UpstreamEchMode::ConfigList => {
        if self.ech.config_list_file.is_none() {
          bail!(
            "upstream {} tls.ech.config_list_file is required when tls.ech.mode = \"config_list\"",
            upstream_name
          );
        }
      }
    }
    if let Some(revocation) = &self.upstream_revocation {
      revocation.validate(&format!("upstream {upstream_name} tls.upstream_revocation"))?;
    }

    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct UpstreamEchConfig {
  #[serde(default)]
  pub mode: UpstreamEchMode,
  #[serde(default)]
  pub config_list_file: Option<PathBuf>,
}

impl Default for UpstreamEchConfig {
  fn default() -> Self {
    Self {
      mode: UpstreamEchMode::Disabled,
      config_list_file: None,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamEchMode {
  #[default]
  Disabled,
  Grease,
  ConfigList,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
pub enum HttpVersion {
  #[serde(rename = "h1")]
  H1,
  #[serde(rename = "h2")]
  H2,
  #[serde(rename = "h3")]
  H3,
}

impl HttpVersion {
  pub fn as_alpn(self) -> &'static [u8] {
    match self {
      Self::H1 => b"http/1.1",
      Self::H2 => b"h2",
      Self::H3 => b"h3",
    }
  }
}

fn default_true() -> bool {
  true
}

fn default_hot_reload_poll_interval_ms() -> u64 {
  2_000
}

fn default_drain_graceful_timeout_ms() -> u64 {
  30_000
}

fn default_drain_long_connection_close_delay_ms() -> u64 {
  300_000
}

fn default_runtime_accept_backlog() -> u32 {
  1_024
}

fn default_accept_error_backoff_ms() -> u64 {
  50
}

fn default_hosts() -> Vec<String> {
  vec!["*".to_string()]
}

fn default_path_prefix() -> String {
  "/".to_string()
}

fn default_connect_timeout_ms() -> u64 {
  3_000
}

fn default_request_timeout_ms() -> u64 {
  30_000
}

fn default_proxy_max_http_version() -> HttpVersion {
  HttpVersion::H2
}

fn default_client_header_timeout_ms() -> u64 {
  10_000
}

fn default_client_body_timeout_ms() -> u64 {
  30_000
}

fn default_client_idle_timeout_ms() -> u64 {
  75_000
}

fn default_tls_handshake_timeout_ms() -> u64 {
  10_000
}

fn default_response_send_timeout_ms() -> u64 {
  60_000
}

fn default_max_headers() -> usize {
  128
}

fn default_max_header_name_bytes() -> usize {
  128
}

fn default_max_header_value_bytes() -> usize {
  8_192
}

fn default_max_total_header_bytes() -> usize {
  65_536
}

fn default_max_uri_bytes() -> usize {
  8_192
}

fn default_max_request_body_bytes() -> u64 {
  10_485_760
}

fn default_buffering_max_memory_body_bytes() -> usize {
  1_048_576
}

fn default_connection_limit_status() -> u16 {
  429
}

fn default_cache_max_size_bytes() -> usize {
  1_073_741_824
}

fn default_cache_memory_auto_fraction() -> f64 {
  0.5
}

fn default_cache_default_ttl_seconds() -> u64 {
  60
}

fn default_cache_methods() -> Vec<String> {
  vec!["GET".to_string(), "HEAD".to_string()]
}

fn default_cache_key() -> String {
  "{scheme}:{host}:{uri}".to_string()
}

fn default_cache_tag_headers() -> Vec<String> {
  vec!["Surrogate-Key".to_string(), "Cache-Tag".to_string()]
}

fn default_cache_max_tags_per_entry() -> usize {
  32
}

fn default_cache_max_tag_bytes() -> usize {
  128
}

fn default_cache_max_vary_fields() -> usize {
  8
}

fn default_cache_max_vary_variants_per_key() -> usize {
  64
}

fn default_cache_bypass_request_headers() -> Vec<String> {
  vec![
    "Authorization".to_string(),
    "Cookie".to_string(),
    "Proxy-Authorization".to_string(),
  ]
}

fn default_cache_stream_chunk_bytes() -> usize {
  1_048_576
}

fn default_cache_background_refresh_max_concurrent() -> usize {
  16
}

fn default_cache_lock_wait_timeout_ms() -> u64 {
  10_000
}

pub(crate) fn default_cache_tmpfs_dir() -> PathBuf {
  PathBuf::from("/dev/shm/oxibelt-cache")
}

fn default_admin_bind() -> SocketAddr {
  "127.0.0.1:9092".parse().expect("valid admin bind default")
}

fn default_admin_bearer_token_env() -> String {
  "OXIBELT_ADMIN_TOKEN".to_string()
}

fn default_cache_purge_signing_key_env() -> String {
  "OXIBELT_CACHE_PURGE_HMAC_KEY".to_string()
}

fn default_cache_purge_signing_max_skew_seconds() -> u64 {
  300
}

fn default_cache_purge_signing_nonce_ttl_seconds() -> u64 {
  600
}

fn default_admin_plaintext_allowed_source_cidrs() -> Vec<String> {
  vec!["127.0.0.0/8".to_string(), "::1/128".to_string()]
}

fn default_metrics_bind() -> SocketAddr {
  "127.0.0.1:9090"
    .parse()
    .expect("valid metrics bind default")
}

fn default_metrics_histogram_buckets_ms() -> Vec<u64> {
  vec![1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000]
}

fn default_health_bind() -> SocketAddr {
  "127.0.0.1:9091".parse().expect("valid health bind default")
}

fn default_ready_path() -> String {
  "/ready".to_string()
}

fn default_live_path() -> String {
  "/live".to_string()
}

fn default_pool_keepalive_max_idle() -> usize {
  32
}

fn default_upstream_pool_max_idle_per_host() -> usize {
  128
}

fn default_pool_keepalive_max_lifetime_ms() -> u64 {
  3_600_000
}

fn default_pool_server_weight() -> u32 {
  1
}

fn default_discovery_refresh_interval_ms() -> u64 {
  30_000
}

fn default_discovery_min_ttl_ms() -> u64 {
  1_000
}

fn default_database_postgres_max_connections() -> u32 {
  4
}

pub(super) fn default_database_postgres_connect_timeout_ms() -> u64 {
  3_000
}

fn default_admin_audit_queue_capacity() -> usize {
  1024
}

fn default_admin_operations_max_running() -> usize {
  4
}

fn default_admin_operations_max_queued() -> usize {
  64
}

fn default_admin_operations_max_stored() -> usize {
  256
}

fn default_admin_operations_retention_seconds() -> u64 {
  3_600
}

fn default_admin_operations_event_buffer() -> usize {
  256
}

fn default_admin_operations_result_max_bytes() -> usize {
  16 * 1024 * 1024
}

fn default_admin_operations_webtransport_max_sessions() -> usize {
  64
}

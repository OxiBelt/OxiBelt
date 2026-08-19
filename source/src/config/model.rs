//! Effective configuration model and deserialization assembly.

use super::*;

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
  pub operational_profile: Option<OperationalProfile>,
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
      operational_profile: None,
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
    let operational_profile =
      operational_profile::apply_to_toml(&mut value).map_err(serde::de::Error::custom)?;
    let diagnostics =
      lb_policy_compat::normalize_toml_from_config(&mut value).map_err(serde::de::Error::custom)?;
    lb_policy_compat::ensure_supported(&diagnostics).map_err(serde::de::Error::custom)?;
    normalize_merged_upstream_resolution_compat(&mut value).map_err(serde::de::Error::custom)?;
    reject_removed_access_log_config(&value).map_err(serde::de::Error::custom)?;
    let mut config: Self = RawConfig::deserialize(value)
      .map_err(serde::de::Error::custom)?
      .try_into()
      .map_err(serde::de::Error::custom)?;
    config.operational_profile = operational_profile;
    Ok(config)
  }
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeOverrides {
  pub hot_reload_mode: Option<HotReloadMode>,
  pub hot_reload_poll_interval_ms: Option<u64>,
}

/// Compile-time runtime artifact whose structural capabilities constrain configuration.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RuntimeArtifact {
  Standalone,
  StrictDataPlane,
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

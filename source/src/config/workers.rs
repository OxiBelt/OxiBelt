//! Worker-count and CPU-affinity configuration validation.
//! Runtime sizing stays explicit so deployment choices are reproducible.

use std::path::PathBuf;

use anyhow::{Context, bail};
use serde::Deserialize;

use super::{
  HotReloadConfig, QuicAltSvcConfig, QuicEndpointConfig, QuicTransportConfig,
  QuicUpstreamPoolConfig, QuicZeroRttMode, RawQuicTransportConfig, RuntimeDrainConfig,
  default_accept_error_backoff_ms, default_runtime_accept_backlog, default_true,
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) struct WorkerParallelism {
  pub available: usize,
  pub fallback_error: Option<&'static str>,
}

impl WorkerParallelism {
  pub(super) fn detect() -> Self {
    match std::thread::available_parallelism() {
      Ok(value) => Self {
        available: value.get(),
        fallback_error: None,
      },
      Err(_) => Self {
        available: 1,
        fallback_error: Some("std::thread::available_parallelism failed"),
      },
    }
  }
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
enum WorkerCountSetting {
  #[default]
  Auto,
  Fixed(usize),
}

impl<'de> Deserialize<'de> for WorkerCountSetting {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    struct Visitor;

    impl serde::de::Visitor<'_> for Visitor {
      type Value = WorkerCountSetting;

      fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a positive integer or \"auto\"")
      }

      fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
      where
        E: serde::de::Error,
      {
        let value = usize::try_from(value).map_err(|_| E::custom("worker count is too large"))?;
        Ok(WorkerCountSetting::Fixed(value))
      }

      fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
      where
        E: serde::de::Error,
      {
        if value < 0 {
          return Err(E::custom("worker count must be greater than 0"));
        }
        Ok(WorkerCountSetting::Fixed(value as usize))
      }

      fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
      where
        E: serde::de::Error,
      {
        if value == "auto" {
          Ok(WorkerCountSetting::Auto)
        } else {
          Err(E::custom("worker count string must be \"auto\""))
        }
      }
    }

    deserializer.deserialize_any(Visitor)
  }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq)]
pub struct WorkerMultipliersConfig {
  #[serde(default = "default_runtime_worker_multiplier")]
  pub runtime: f64,
  #[serde(default = "default_accept_worker_multiplier")]
  pub accept: f64,
  #[serde(default = "default_quic_socket_worker_multiplier")]
  pub quic_socket: f64,
}

impl Default for WorkerMultipliersConfig {
  fn default() -> Self {
    Self {
      runtime: default_runtime_worker_multiplier(),
      accept: default_accept_worker_multiplier(),
      quic_socket: default_quic_socket_worker_multiplier(),
    }
  }
}

impl WorkerMultipliersConfig {
  fn validate(&self) -> anyhow::Result<()> {
    validate_worker_multiplier("runtime.worker_multipliers.runtime", self.runtime)?;
    validate_worker_multiplier("runtime.worker_multipliers.accept", self.accept)?;
    validate_worker_multiplier("runtime.worker_multipliers.quic_socket", self.quic_socket)
  }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WorkerResolutionConfig {
  pub available_parallelism: usize,
  pub fallback_error: Option<&'static str>,
  pub runtime_multiplier: f64,
  pub accept_multiplier: f64,
  pub quic_socket_multiplier: f64,
}

impl Default for WorkerResolutionConfig {
  fn default() -> Self {
    Self {
      available_parallelism: 1,
      fallback_error: None,
      runtime_multiplier: default_runtime_worker_multiplier(),
      accept_multiplier: default_accept_worker_multiplier(),
      quic_socket_multiplier: default_quic_socket_worker_multiplier(),
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub(super) struct RawRuntimeConfig {
  #[serde(default = "default_true")]
  linux_only: bool,
  #[serde(default = "default_true")]
  read_only_rootfs_compatible: bool,
  #[serde(default = "default_true")]
  memory_only_state: bool,
  #[serde(default = "default_true")]
  unprivileged_mode: bool,
  #[serde(default)]
  worker_threads: WorkerCountSetting,
  #[serde(default)]
  worker_multipliers: WorkerMultipliersConfig,
  #[serde(default)]
  accept: RawRuntimeAcceptConfig,
  #[serde(default)]
  drain: RuntimeDrainConfig,
  #[serde(default)]
  hot_reload: HotReloadConfig,
}

impl Default for RawRuntimeConfig {
  fn default() -> Self {
    Self {
      linux_only: true,
      read_only_rootfs_compatible: true,
      memory_only_state: true,
      unprivileged_mode: true,
      worker_threads: WorkerCountSetting::Auto,
      worker_multipliers: WorkerMultipliersConfig::default(),
      accept: RawRuntimeAcceptConfig::default(),
      drain: RuntimeDrainConfig::default(),
      hot_reload: HotReloadConfig::default(),
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RuntimeConfig {
  pub linux_only: bool,
  pub read_only_rootfs_compatible: bool,
  pub memory_only_state: bool,
  pub unprivileged_mode: bool,
  pub worker_threads: usize,
  pub worker_multipliers: WorkerMultipliersConfig,
  pub accept: RuntimeAcceptConfig,
  pub drain: RuntimeDrainConfig,
  pub hot_reload: HotReloadConfig,
  #[serde(skip)]
  pub worker_resolution: WorkerResolutionConfig,
}

impl Default for RuntimeConfig {
  fn default() -> Self {
    Self {
      linux_only: true,
      read_only_rootfs_compatible: true,
      memory_only_state: true,
      unprivileged_mode: true,
      worker_threads: 1,
      worker_multipliers: WorkerMultipliersConfig::default(),
      accept: RuntimeAcceptConfig::default(),
      drain: RuntimeDrainConfig::default(),
      hot_reload: HotReloadConfig::default(),
      worker_resolution: WorkerResolutionConfig::default(),
    }
  }
}

impl RuntimeConfig {
  pub(super) fn resolve(
    raw: RawRuntimeConfig,
    parallelism: WorkerParallelism,
  ) -> anyhow::Result<Self> {
    raw.worker_multipliers.validate()?;
    let worker_threads = resolve_worker_count(
      "runtime.worker_threads",
      raw.worker_threads,
      raw.worker_multipliers.runtime,
      parallelism.available,
    )?;
    let accept = RuntimeAcceptConfig::resolve(
      raw.accept,
      raw.worker_multipliers.accept,
      parallelism.available,
    )?;
    Ok(Self {
      linux_only: raw.linux_only,
      read_only_rootfs_compatible: raw.read_only_rootfs_compatible,
      memory_only_state: raw.memory_only_state,
      unprivileged_mode: raw.unprivileged_mode,
      worker_threads,
      worker_multipliers: raw.worker_multipliers,
      accept,
      drain: raw.drain,
      hot_reload: raw.hot_reload,
      worker_resolution: WorkerResolutionConfig {
        available_parallelism: parallelism.available,
        fallback_error: parallelism.fallback_error,
        runtime_multiplier: raw.worker_multipliers.runtime,
        accept_multiplier: raw.worker_multipliers.accept,
        quic_socket_multiplier: raw.worker_multipliers.quic_socket,
      },
    })
  }

  pub(super) fn validate(&self) -> anyhow::Result<()> {
    self.worker_multipliers.validate()?;
    if self.worker_threads == 0 {
      bail!("runtime.worker_threads must be greater than 0");
    }
    self.accept.validate()?;
    self.drain.validate()?;
    self.hot_reload.validate()
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct RawRuntimeAcceptConfig {
  #[serde(default)]
  workers: WorkerCountSetting,
  #[serde(default)]
  reuse_port: bool,
  #[serde(default = "default_runtime_accept_backlog")]
  backlog: u32,
  #[serde(default = "default_accept_error_backoff_ms")]
  accept_error_backoff_ms: u64,
}

impl Default for RawRuntimeAcceptConfig {
  fn default() -> Self {
    Self {
      workers: WorkerCountSetting::Auto,
      reuse_port: false,
      backlog: default_runtime_accept_backlog(),
      accept_error_backoff_ms: default_accept_error_backoff_ms(),
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RuntimeAcceptConfig {
  pub workers: usize,
  pub reuse_port: bool,
  pub backlog: u32,
  pub accept_error_backoff_ms: u64,
}

impl Default for RuntimeAcceptConfig {
  fn default() -> Self {
    Self {
      workers: 1,
      reuse_port: false,
      backlog: default_runtime_accept_backlog(),
      accept_error_backoff_ms: default_accept_error_backoff_ms(),
    }
  }
}

impl RuntimeAcceptConfig {
  fn resolve(
    raw: RawRuntimeAcceptConfig,
    multiplier: f64,
    available_parallelism: usize,
  ) -> anyhow::Result<Self> {
    Ok(Self {
      workers: resolve_worker_count(
        "runtime.accept.workers",
        raw.workers,
        multiplier,
        available_parallelism,
      )?,
      reuse_port: raw.reuse_port,
      backlog: raw.backlog,
      accept_error_backoff_ms: raw.accept_error_backoff_ms,
    })
  }

  fn validate(&self) -> anyhow::Result<()> {
    if self.workers == 0 {
      bail!("runtime.accept.workers must be greater than 0");
    }
    if self.workers > 1 && !self.reuse_port {
      bail!("runtime.accept.reuse_port must be true when runtime.accept.workers is greater than 1");
    }
    if self.backlog == 0 {
      bail!("runtime.accept.backlog must be greater than 0");
    }
    if self.accept_error_backoff_ms == 0 {
      bail!("runtime.accept.accept_error_backoff_ms must be greater than 0");
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub(super) struct RawQuicConfig {
  #[serde(default)]
  retry: bool,
  #[serde(default)]
  zero_rtt: QuicZeroRttMode,
  #[serde(default)]
  host_key_file: Option<PathBuf>,
  #[serde(default)]
  alt_svc: QuicAltSvcConfig,
  #[serde(default)]
  transport: QuicTransportConfig,
  #[serde(default)]
  downstream: RawQuicEndpointConfig,
  #[serde(default)]
  upstream: RawQuicEndpointConfig,
  #[serde(default)]
  socket: RawQuicSocketConfig,
  #[serde(default)]
  upstream_pool: QuicUpstreamPoolConfig,
}

impl Default for RawQuicConfig {
  fn default() -> Self {
    Self {
      retry: false,
      zero_rtt: QuicZeroRttMode::Off,
      host_key_file: None,
      alt_svc: QuicAltSvcConfig::default(),
      transport: QuicTransportConfig::default(),
      downstream: RawQuicEndpointConfig::default(),
      upstream: RawQuicEndpointConfig::default(),
      socket: RawQuicSocketConfig::default(),
      upstream_pool: QuicUpstreamPoolConfig::default(),
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct QuicConfig {
  pub retry: bool,
  pub zero_rtt: QuicZeroRttMode,
  pub host_key_file: Option<PathBuf>,
  pub alt_svc: QuicAltSvcConfig,
  pub transport: QuicTransportConfig,
  pub downstream: QuicEndpointConfig,
  pub upstream: QuicEndpointConfig,
  pub socket: QuicSocketConfig,
  pub upstream_pool: QuicUpstreamPoolConfig,
}

impl Default for QuicConfig {
  fn default() -> Self {
    Self {
      retry: false,
      zero_rtt: QuicZeroRttMode::Off,
      host_key_file: None,
      alt_svc: QuicAltSvcConfig::default(),
      transport: QuicTransportConfig::default(),
      downstream: QuicEndpointConfig::default(),
      upstream: QuicEndpointConfig::default(),
      socket: QuicSocketConfig::default(),
      upstream_pool: QuicUpstreamPoolConfig::default(),
    }
  }
}

impl QuicConfig {
  pub(super) fn resolve(
    raw: RawQuicConfig,
    multipliers: WorkerMultipliersConfig,
    parallelism: WorkerParallelism,
  ) -> anyhow::Result<Self> {
    let transport = raw.transport;
    let downstream = raw.downstream.resolve(&transport);
    let upstream = raw.upstream.resolve(&transport);
    Ok(Self {
      retry: raw.retry,
      zero_rtt: raw.zero_rtt,
      host_key_file: raw.host_key_file,
      alt_svc: raw.alt_svc,
      transport,
      downstream,
      upstream,
      socket: QuicSocketConfig::resolve(
        raw.socket,
        multipliers.quic_socket,
        parallelism.available,
      )?,
      upstream_pool: raw.upstream_pool,
    })
  }

  pub(super) fn validate(&self, http3_enabled: bool) -> anyhow::Result<()> {
    if self.alt_svc.max_age_seconds == 0 {
      bail!("quic.alt_svc.max_age_seconds must be greater than 0");
    }
    self.transport.validate("quic.transport")?;
    self
      .downstream
      .transport
      .validate("quic.downstream.transport")?;
    self
      .upstream
      .transport
      .validate("quic.upstream.transport")?;
    if self.upstream_pool.max_connections_per_upstream == 0 {
      bail!("quic.upstream_pool.max_connections_per_upstream must be greater than 0");
    }
    if self.upstream_pool.max_lifetime_ms == 0 {
      bail!("quic.upstream_pool.max_lifetime_ms must be greater than 0");
    }
    self.socket.validate(http3_enabled)?;
    Ok(())
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
struct RawQuicEndpointConfig {
  #[serde(default)]
  transport: RawQuicTransportConfig,
}

impl RawQuicEndpointConfig {
  fn resolve(&self, base_transport: &QuicTransportConfig) -> QuicEndpointConfig {
    QuicEndpointConfig {
      transport: self.transport.resolve(base_transport),
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct RawQuicSocketConfig {
  #[serde(default)]
  receive_buffer_bytes: usize,
  #[serde(default)]
  send_buffer_bytes: usize,
  #[serde(default)]
  workers: WorkerCountSetting,
  #[serde(default)]
  reuse_port: bool,
}

impl Default for RawQuicSocketConfig {
  fn default() -> Self {
    Self {
      receive_buffer_bytes: 0,
      send_buffer_bytes: 0,
      workers: WorkerCountSetting::Auto,
      reuse_port: false,
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct QuicSocketConfig {
  pub receive_buffer_bytes: usize,
  pub send_buffer_bytes: usize,
  pub workers: usize,
  pub reuse_port: bool,
}

impl Default for QuicSocketConfig {
  fn default() -> Self {
    Self {
      receive_buffer_bytes: 0,
      send_buffer_bytes: 0,
      workers: 1,
      reuse_port: false,
    }
  }
}

impl QuicSocketConfig {
  fn resolve(
    raw: RawQuicSocketConfig,
    multiplier: f64,
    available_parallelism: usize,
  ) -> anyhow::Result<Self> {
    Ok(Self {
      receive_buffer_bytes: raw.receive_buffer_bytes,
      send_buffer_bytes: raw.send_buffer_bytes,
      workers: resolve_worker_count(
        "quic.socket.workers",
        raw.workers,
        multiplier,
        available_parallelism,
      )?,
      reuse_port: raw.reuse_port,
    })
  }

  fn validate(&self, http3_enabled: bool) -> anyhow::Result<()> {
    if self.workers == 0 {
      bail!("quic.socket.workers must be greater than 0");
    }
    if http3_enabled && self.workers > 1 && !self.reuse_port {
      bail!("quic.socket.reuse_port must be true when quic.socket.workers is greater than 1");
    }
    Ok(())
  }
}

fn default_runtime_worker_multiplier() -> f64 {
  1.0
}

fn default_accept_worker_multiplier() -> f64 {
  0.5
}

fn default_quic_socket_worker_multiplier() -> f64 {
  1.0
}

fn validate_worker_multiplier(field_name: &str, value: f64) -> anyhow::Result<()> {
  if !value.is_finite() || value <= 0.0 {
    bail!("{field_name} must be a finite number greater than 0");
  }
  Ok(())
}

pub fn resolve_auto_worker_count(
  available_parallelism: usize,
  multiplier: f64,
) -> anyhow::Result<usize> {
  if available_parallelism == 0 {
    bail!("available_parallelism must be greater than 0");
  }
  validate_worker_multiplier("worker multiplier", multiplier)?;
  let resolved = ((available_parallelism as f64) * multiplier).ceil();
  if !resolved.is_finite() || resolved > usize::MAX as f64 {
    bail!("resolved worker count is too large");
  }
  Ok((resolved as usize).max(1))
}

fn resolve_worker_count(
  field_name: &str,
  setting: WorkerCountSetting,
  multiplier: f64,
  available_parallelism: usize,
) -> anyhow::Result<usize> {
  match setting {
    WorkerCountSetting::Auto => resolve_auto_worker_count(available_parallelism, multiplier)
      .with_context(|| format!("failed to resolve {field_name} = \"auto\"")),
    WorkerCountSetting::Fixed(0) => bail!("{field_name} must be greater than 0"),
    WorkerCountSetting::Fixed(value) => Ok(value),
  }
}

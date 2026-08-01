//! QUIC endpoint and socket worker ownership derived from runtime sizing.

use std::path::PathBuf;

use anyhow::bail;
use serde::Deserialize;

use super::{
  QuicAltSvcConfig, QuicEndpointConfig, QuicTransportConfig, QuicUpstreamConfig,
  QuicUpstreamPoolConfig, QuicUpstreamResolutionConfig, QuicZeroRttMode, RawQuicTransportConfig,
  WorkerCountSetting, WorkerMultipliersConfig, WorkerParallelism, resolve_worker_count,
};

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
  upstream: RawQuicUpstreamConfig,
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
      upstream: RawQuicUpstreamConfig::default(),
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
  pub upstream: QuicUpstreamConfig,
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
      upstream: QuicUpstreamConfig::default(),
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
    self.upstream.resolution.validate()?;
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

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
struct RawQuicUpstreamConfig {
  #[serde(default)]
  transport: RawQuicTransportConfig,
  #[serde(default)]
  resolution: QuicUpstreamResolutionConfig,
}

impl RawQuicUpstreamConfig {
  fn resolve(&self, base_transport: &QuicTransportConfig) -> QuicUpstreamConfig {
    QuicUpstreamConfig {
      transport: self.transport.resolve(base_transport),
      resolution: self.resolution.clone(),
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

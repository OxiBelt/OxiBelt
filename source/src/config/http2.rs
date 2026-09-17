//! HTTP/2 tuning configuration.
//! Values are validated before they are applied to downstream or upstream transports.

use serde::Deserialize;

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
pub struct ProxyHttp2Config {
  #[serde(default)]
  pub webtransport: H2WebTransportConfig,
  #[serde(default = "default_true")]
  pub adaptive_window: bool,
  #[serde(default)]
  pub initial_stream_window_bytes: Option<u32>,
  #[serde(default)]
  pub initial_connection_window_bytes: Option<u32>,
  #[serde(default)]
  pub max_frame_size_bytes: Option<u32>,
  #[serde(default = "default_http2_max_concurrent_streams")]
  pub max_concurrent_streams: u32,
  #[serde(default = "default_http2_max_send_buf_size")]
  pub max_send_buf_size: usize,
  #[serde(default)]
  pub keep_alive_interval_ms: u64,
  #[serde(default = "default_http2_keep_alive_timeout_ms")]
  pub keep_alive_timeout_ms: u64,
  #[serde(default)]
  pub keep_alive_while_idle: bool,
}

impl Default for ProxyHttp2Config {
  fn default() -> Self {
    Self {
      webtransport: H2WebTransportConfig::default(),
      adaptive_window: true,
      initial_stream_window_bytes: None,
      initial_connection_window_bytes: None,
      max_frame_size_bytes: None,
      max_concurrent_streams: default_http2_max_concurrent_streams(),
      max_send_buf_size: default_http2_max_send_buf_size(),
      keep_alive_interval_ms: 0,
      keep_alive_timeout_ms: default_http2_keep_alive_timeout_ms(),
      keep_alive_while_idle: false,
    }
  }
}

/// Application buffers for sessions with an HTTP/2 WebTransport leg.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct H2WebTransportConfig {
  pub max_concurrent_uni_streams: u32,
  pub max_concurrent_bidi_streams: u32,
  pub max_stream_buffer_bytes: usize,
  pub max_session_buffer_bytes: usize,
  pub max_total_buffer_bytes: usize,
}

impl Default for H2WebTransportConfig {
  fn default() -> Self {
    Self {
      max_concurrent_uni_streams: 100,
      max_concurrent_bidi_streams: 100,
      max_stream_buffer_bytes: 65_536,
      max_session_buffer_bytes: 1_048_576,
      max_total_buffer_bytes: 67_108_864,
    }
  }
}

impl H2WebTransportConfig {
  /// Conservative memory admission for both endpoints' live stream directions.
  pub(crate) fn session_reservation_bytes(&self) -> Option<usize> {
    let uni = usize::try_from(self.max_concurrent_uni_streams).ok()?;
    let bidi = usize::try_from(self.max_concurrent_bidi_streams).ok()?;
    let staging = uni
      .checked_mul(2)?
      .checked_add(bidi.checked_mul(4)?)?
      .checked_mul(16_384)?;
    let metadata = uni.checked_add(bidi)?.checked_mul(2)?.checked_mul(1024)?;
    self
      .max_session_buffer_bytes
      .checked_mul(2)?
      .checked_add(staging)?
      .checked_add(metadata)?
      .checked_add(196_608)
  }

  pub(crate) fn validate(&self) -> anyhow::Result<()> {
    anyhow::ensure!(
      self.max_concurrent_uni_streams > 0 && self.max_concurrent_bidi_streams > 0,
      "proxy.http2.webtransport stream limits must be positive"
    );
    anyhow::ensure!(
      self.max_stream_buffer_bytes > 0
        && self.max_stream_buffer_bytes <= self.max_session_buffer_bytes
        && self.max_session_buffer_bytes <= self.max_total_buffer_bytes
        && self.max_total_buffer_bytes <= u32::MAX as usize,
      "proxy.http2.webtransport requires 0 < stream <= session <= total buffer bytes <= 4294967295"
    );
    anyhow::ensure!(
      self
        .session_reservation_bytes()
        .is_some_and(|bytes| bytes <= self.max_total_buffer_bytes),
      "proxy.http2.webtransport total budget must hold both session directions, stream staging, and protocol overhead"
    );
    Ok(())
  }
}

fn default_true() -> bool {
  true
}

fn default_http2_max_concurrent_streams() -> u32 {
  1_024
}

fn default_http2_max_send_buf_size() -> usize {
  1024 * 1024
}

fn default_http2_keep_alive_timeout_ms() -> u64 {
  20_000
}

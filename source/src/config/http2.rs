use serde::Deserialize;

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
pub struct ProxyHttp2Config {
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

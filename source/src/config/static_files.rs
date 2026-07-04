//! Static-file proxy configuration and defaults.

use serde::Deserialize;

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
pub struct ProxyStaticFilesConfig {
  #[serde(default)]
  pub sendfile: StaticFilesSendfileMode,
  #[serde(default)]
  pub sendfile_write_strategy: StaticFilesSendfileWriteStrategy,
  #[serde(default = "default_static_files_sendfile_chunk_bytes")]
  pub sendfile_chunk_bytes: usize,
  #[serde(default = "default_static_files_inline_max_bytes")]
  pub inline_max_bytes: usize,
  #[serde(default)]
  pub open_file_cache_max_entries: usize,
  #[serde(default)]
  pub open_file_cache_ttl_ms: u64,
  #[serde(default)]
  pub hot_object_cache_max_bytes: usize,
  #[serde(default = "default_static_files_hot_object_cache_max_file_bytes")]
  pub hot_object_cache_max_file_bytes: usize,
}

impl Default for ProxyStaticFilesConfig {
  fn default() -> Self {
    Self {
      sendfile: StaticFilesSendfileMode::Off,
      sendfile_write_strategy: StaticFilesSendfileWriteStrategy::Auto,
      sendfile_chunk_bytes: default_static_files_sendfile_chunk_bytes(),
      inline_max_bytes: default_static_files_inline_max_bytes(),
      open_file_cache_max_entries: 0,
      open_file_cache_ttl_ms: 0,
      hot_object_cache_max_bytes: 0,
      hot_object_cache_max_file_bytes: default_static_files_hot_object_cache_max_file_bytes(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StaticFilesSendfileMode {
  #[default]
  Off,
  Auto,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StaticFilesSendfileWriteStrategy {
  #[default]
  Auto,
  Split,
  MsgMore,
  TcpCork,
}

fn default_static_files_inline_max_bytes() -> usize {
  16 * 1024
}

fn default_static_files_sendfile_chunk_bytes() -> usize {
  1024 * 1024
}

fn default_static_files_hot_object_cache_max_file_bytes() -> usize {
  64 * 1024
}

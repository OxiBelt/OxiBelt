//! HTTP/3 proxy scheduling configuration.
//! Defaults keep optimized request scheduling opt-in until an operator enables it.

use serde::Deserialize;

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
pub struct ProxyHttp3Config {
  #[serde(default)]
  pub inline_bodyless_fast_path: bool,
}

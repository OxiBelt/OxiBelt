//! HTTP/3 proxy scheduling configuration.
//! Defaults keep scheduling, draft16 advertisement, and dedicated sessions opt-in.

use serde::Deserialize;

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
pub struct ProxyHttp3Config {
  #[serde(default)]
  pub inline_bodyless_fast_path: bool,
  #[serde(default)]
  pub webtransport_draft16: bool,
  #[serde(default)]
  pub webtransport_only_connections: bool,
}

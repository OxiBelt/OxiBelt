//! Limit configuration defaults and validation.
//! Limit names and identities are resolved before runtime enforcement begins.

use super::LimitsConfig;

impl LimitsConfig {
  pub fn effective_max_webtransport_sessions(&self) -> usize {
    self
      .max_webtransport_sessions
      .unwrap_or(self.max_connections)
  }

  pub fn effective_max_webtransport_sessions_per_ip(&self) -> usize {
    self
      .max_webtransport_sessions_per_ip
      .unwrap_or(self.max_connections_per_ip)
  }
}

pub(super) fn default_max_connections() -> usize {
  65_536
}

pub(super) fn default_max_connections_per_ip() -> usize {
  128
}

pub(super) fn default_max_webtransport_sessions_per_connection() -> usize {
  256
}

pub(super) fn default_max_requests_per_connection() -> usize {
  1_000
}

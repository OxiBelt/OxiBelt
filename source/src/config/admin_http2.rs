//! Built-in Admin HTTP/2 WebTransport queue limits.

use anyhow::ensure;
use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AdminHttp2Config {
  pub webtransport: AdminHttp2WebTransportConfig,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AdminHttp2WebTransportConfig {
  pub outbound_queue_bytes_per_session: usize,
  pub outbound_queue_bytes_total: usize,
}

impl Default for AdminHttp2WebTransportConfig {
  fn default() -> Self {
    Self {
      outbound_queue_bytes_per_session: 65_536,
      outbound_queue_bytes_total: 4_194_304,
    }
  }
}

impl AdminHttp2WebTransportConfig {
  pub(crate) fn validate(&self) -> anyhow::Result<()> {
    ensure!(
      self.outbound_queue_bytes_per_session >= 4
        && self.outbound_queue_bytes_per_session <= self.outbound_queue_bytes_total
        && self.outbound_queue_bytes_total <= u32::MAX as usize,
      "admin.http2.webtransport requires 4 <= outbound_queue_bytes_per_session <= outbound_queue_bytes_total <= 4294967295"
    );
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn defaults_are_bounded_for_one_admin_session() {
    AdminHttp2WebTransportConfig::default().validate().unwrap();
  }

  #[test]
  fn permits_one_session_to_use_the_entire_total_queue() {
    let config = AdminHttp2WebTransportConfig {
      outbound_queue_bytes_per_session: 65_536,
      outbound_queue_bytes_total: 65_536,
    };
    config.validate().unwrap();
  }

  #[test]
  fn rejects_a_queue_too_small_for_serializer_and_carrier_overhead() {
    let config = AdminHttp2WebTransportConfig {
      outbound_queue_bytes_per_session: 3,
      outbound_queue_bytes_total: 3,
    };
    assert!(config.validate().is_err());
  }
}

//! HTTP/1 upgrade planning for runtime snapshots.
//! Upgrade decisions are precomputed from config so request handling stays cheap.

use crate::config::{Config, RouteConfig, UpstreamConfig};

pub(super) fn http1_upgrades_possible(config: &Config, upstreams: &[UpstreamConfig]) -> bool {
  let upgrades = &config.proxy.upgrades;
  config.routes.iter().any(|route| {
    (upgrades.connect_tunneling && route.connect_tunneling)
      || (upgrades.generic_http_upgrade && route.generic_http_upgrade)
      || (upgrades.websocket && route_websocket_upgrade_possible(route, upstreams))
  })
}

fn route_websocket_upgrade_possible(route: &RouteConfig, upstreams: &[UpstreamConfig]) -> bool {
  if route.upstream_pool.is_some() {
    return true;
  }

  route.upstream.as_deref().is_some_and(|name| {
    upstreams
      .iter()
      .any(|upstream| upstream.name == name && upstream.websocket)
  })
}

#[cfg(test)]
mod tests {
  use crate::config::Config;

  use super::*;

  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  fn parse_config(raw: &str) -> Config {
    let config: Config = toml::from_str(raw).expect("config should parse");
    config.validate().expect("config should validate");
    config
  }

  #[test]
  fn http1_upgrade_capability_tracks_route_and_upstream_features() {
    let temp_dir = common::TempDir::new("http1-upgrade-capability");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "http1-upgrade-capability");
    let raw = common::minimal_config_toml(&cert_path, &key_path);
    let websocket = parse_config(&raw);
    assert!(http1_upgrades_possible(&websocket, &websocket.upstreams));

    let no_websocket = parse_config(&raw.replace("websocket = true", "websocket = false"));
    assert!(!http1_upgrades_possible(
      &no_websocket,
      &no_websocket.upstreams
    ));

    let mut connect = no_websocket.clone();
    connect.proxy.upgrades.connect_tunneling = true;
    connect.routes[0].connect_tunneling = true;
    assert!(http1_upgrades_possible(&connect, &connect.upstreams));
  }
}

//! Restart-only TLS controls are compared by configured identity, not runtime membership.

use std::collections::BTreeSet;

use crate::config::{
  Config, UpstreamPoolServerSource, turn_upstream_pool_server_id, upstream_pool_server_id,
};

// Keep identity components separate: dots are legal in pool names and server IDs.
#[derive(Eq, PartialEq, Ord, PartialOrd)]
enum Secp256r1Mlkem768Control {
  Auxiliary,
  Admin,
  Upstream(String),
  PoolServer { pool: String, id: String },
  Discovery { pool: String, id: String },
  TurnServer { pool: String, id: String },
  Redis(String),
}

pub(super) fn secp256r1_mlkem768_changed(active: &Config, replacement: &Config) -> bool {
  configured_opt_ins(active) != configured_opt_ins(replacement)
}

fn configured_opt_ins(config: &Config) -> BTreeSet<Secp256r1Mlkem768Control> {
  let mut controls = BTreeSet::new();
  if config.crypto.auxiliary_tls.enable_secp256r1mlkem768 {
    controls.insert(Secp256r1Mlkem768Control::Auxiliary);
  }
  if config.admin.tls.enable_secp256r1mlkem768 {
    controls.insert(Secp256r1Mlkem768Control::Admin);
  }
  for upstream in &config.upstreams {
    if upstream.tls.enable_secp256r1mlkem768 {
      controls.insert(Secp256r1Mlkem768Control::Upstream(upstream.name.clone()));
    }
  }
  for pool in &config.upstream_pools {
    for (index, server) in pool.servers.iter().enumerate() {
      // Discovery copies its own policy to generated servers; Admin servers are
      // runtime-only too. Neither is an independent control in the file config.
      if server.source == UpstreamPoolServerSource::Static && server.tls.enable_secp256r1mlkem768 {
        controls.insert(Secp256r1Mlkem768Control::PoolServer {
          pool: pool.name.clone(),
          id: upstream_pool_server_id(index, server),
        });
      }
    }
    for discovery in &pool.discovery {
      if discovery.tls.enable_secp256r1mlkem768 {
        controls.insert(Secp256r1Mlkem768Control::Discovery {
          pool: pool.name.clone(),
          id: discovery.effective_id().to_string(),
        });
      }
    }
  }
  for pool in &config.turn_upstream_pools {
    for (index, server) in pool.servers.iter().enumerate() {
      if server.tls.enable_secp256r1mlkem768 {
        controls.insert(Secp256r1Mlkem768Control::TurnServer {
          pool: pool.name.clone(),
          id: turn_upstream_pool_server_id(index, server),
        });
      }
    }
  }
  for backend in &config.shared_state.backends {
    if backend.redis_tls.enable_secp256r1mlkem768 {
      controls.insert(Secp256r1Mlkem768Control::Redis(backend.name.clone()));
    }
  }
  controls
}

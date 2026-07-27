//! Canonical logical identities for durable UDP flow recovery.
//!
//! These fingerprints deliberately contain configuration semantics rather
//! than runtime health or resolved addresses.  A shared record can therefore
//! authorize only a target that is still present in the active snapshot.

use std::collections::BTreeSet;

use crate::config::{
  Config, LoadBalancingAlgorithm, StreamListenerConfig, StreamNetwork, StreamUpstreamPoolConfig,
  UdpFlowState, stream_upstream_pool_server_id,
};
use crate::shared_state::{UdpFlowStore, UdpFlowTarget};
use crate::stream::sni::{StreamRoute, StreamRouteIdentity};
use crate::stream::target::StreamTargetIdentity;

pub(super) fn listener_scope_material(listener: &StreamListenerConfig) -> Vec<u8> {
  let mut material = Vec::new();
  push_field(&mut material, b"oxibelt-udp-listener-scope-v1");
  push_field(&mut material, listener.name.as_bytes());
  push_field(&mut material, stream_network(listener.network));
  push_field(&mut material, listener.bind.to_string().as_bytes());
  material
}

pub(super) fn peer_material(peer: std::net::SocketAddr) -> Vec<u8> {
  let mut material = Vec::with_capacity(44);
  material.extend_from_slice(b"oxibelt-udp-peer-v2");
  match peer {
    std::net::SocketAddr::V4(peer) => {
      material.push(4);
      material.extend_from_slice(&peer.ip().octets());
      material.extend_from_slice(&peer.port().to_be_bytes());
    }
    std::net::SocketAddr::V6(peer) => {
      material.push(6);
      material.extend_from_slice(&peer.ip().octets());
      material.extend_from_slice(&peer.port().to_be_bytes());
      material.extend_from_slice(&peer.flowinfo().to_be_bytes());
      material.extend_from_slice(&peer.scope_id().to_be_bytes());
    }
  }
  material
}

pub(super) fn routing_fingerprint(config: &Config, listener: &StreamListenerConfig) -> [u8; 32] {
  let mut material = listener_scope_material(listener);
  push_u64(&mut material, listener.connect_timeout_ms);
  push_u64(&mut material, listener.idle_timeout_ms);
  push_field(
    &mut material,
    listener.target.as_deref().unwrap_or("").as_bytes(),
  );
  push_field(
    &mut material,
    listener.upstream_pool.as_deref().unwrap_or("").as_bytes(),
  );
  push_u64(
    &mut material,
    u64::try_from(listener.max_udp_flows).unwrap_or(u64::MAX),
  );
  push_field(
    &mut material,
    match listener.udp_flow_state {
      UdpFlowState::Local => b"local",
      UdpFlowState::SharedRequired => b"shared_required",
    },
  );
  push_field(
    &mut material,
    listener
      .udp_datagram_rate
      .as_deref()
      .unwrap_or("")
      .as_bytes(),
  );
  push_u64(&mut material, u64::from(listener.udp_datagram_burst));
  push_field(
    &mut material,
    listener
      .udp_new_flow_rate
      .as_deref()
      .unwrap_or("")
      .as_bytes(),
  );
  push_u64(&mut material, u64::from(listener.udp_new_flow_burst));

  let mut pool_names = BTreeSet::new();
  if let Some(pool) = listener.upstream_pool.as_deref() {
    pool_names.insert(pool);
  }
  for rule in &listener.sni_rules {
    push_field(&mut material, rule.name.as_bytes());
    for pattern in &rule.server_names {
      push_field(&mut material, pattern.as_bytes());
    }
    push_field(
      &mut material,
      rule.target.as_deref().unwrap_or("").as_bytes(),
    );
    push_field(
      &mut material,
      rule.upstream_pool.as_deref().unwrap_or("").as_bytes(),
    );
    push_u64(&mut material, rule.connect_timeout_ms);
    push_u64(&mut material, rule.idle_timeout_ms);
    if let Some(pool) = rule.upstream_pool.as_deref() {
      pool_names.insert(pool);
    }
  }
  for pool_name in pool_names {
    if let Some(pool) = config
      .stream_upstream_pools
      .iter()
      .find(|pool| pool.name == pool_name)
    {
      push_pool(&mut material, pool);
    }
  }
  crate::crypto::sha256(&material)
}

pub(super) fn direct_target_material() -> Vec<u8> {
  target_material("direct", "")
}

pub(super) fn pool_target_material(pool_name: &str, server_id: &str) -> Vec<u8> {
  target_material(pool_name, server_id)
}

pub(super) fn target_for_selection(
  store: &UdpFlowStore,
  route: StreamRoute<'_>,
  identity: &StreamTargetIdentity,
) -> anyhow::Result<UdpFlowTarget> {
  let target_material = match identity {
    StreamTargetIdentity::Direct => direct_target_material(),
    StreamTargetIdentity::Pool {
      pool_name,
      server_id,
    } => pool_target_material(pool_name, server_id),
  };
  store.target_for(&route_identity_material(route.identity), &target_material)
}

pub(super) fn restore_target_identity(
  store: &UdpFlowStore,
  config: &Config,
  route: StreamRoute<'_>,
  durable_target: &UdpFlowTarget,
) -> anyhow::Result<StreamTargetIdentity> {
  match route.target {
    crate::stream::sni::StreamRouteTarget::Direct(_) => {
      let identity = StreamTargetIdentity::Direct;
      if target_for_selection(store, route, &identity)? == *durable_target {
        Ok(identity)
      } else {
        anyhow::bail!("durable UDP direct target does not match the active route")
      }
    }
    crate::stream::sni::StreamRouteTarget::Pool(pool_name) => {
      let Some(pool) = config
        .stream_upstream_pools
        .iter()
        .find(|pool| pool.name == pool_name)
      else {
        anyhow::bail!("durable UDP pool target is absent from the active configuration");
      };
      for (index, server) in pool.servers.iter().enumerate() {
        let identity = StreamTargetIdentity::Pool {
          pool_name: pool_name.to_string(),
          server_id: stream_upstream_pool_server_id(index, server),
        };
        if target_for_selection(store, route, &identity)? == *durable_target {
          return Ok(identity);
        }
      }
      anyhow::bail!("durable UDP pool target is absent from the active configuration")
    }
  }
}

fn route_identity_material(identity: StreamRouteIdentity<'_>) -> Vec<u8> {
  let mut material = Vec::new();
  push_field(&mut material, b"oxibelt-udp-route-v1");
  match identity {
    StreamRouteIdentity::Default => push_field(&mut material, b"default"),
    StreamRouteIdentity::Rule(name) => {
      push_field(&mut material, b"rule");
      push_field(&mut material, name.as_bytes());
    }
  }
  material
}

fn target_material(target: &str, server_id: &str) -> Vec<u8> {
  let mut material = Vec::new();
  push_field(&mut material, b"oxibelt-udp-target-v1");
  push_field(&mut material, target.as_bytes());
  push_field(&mut material, server_id.as_bytes());
  material
}

fn push_pool(material: &mut Vec<u8>, pool: &StreamUpstreamPoolConfig) {
  push_field(material, pool.name.as_bytes());
  push_field(material, load_balancing_algorithm(pool.algorithm));
  push_field(material, pool.hash_key.as_deref().unwrap_or("").as_bytes());
  for (index, server) in pool.servers.iter().enumerate() {
    push_field(
      material,
      stream_upstream_pool_server_id(index, server).as_bytes(),
    );
    push_field(material, server.origin.as_str().as_bytes());
    push_u64(material, u64::from(server.weight));
    push_u64(
      material,
      u64::try_from(server.max_conns).unwrap_or(u64::MAX),
    );
    material.push(u8::from(server.backup));
    push_field(material, server.state.as_str().as_bytes());
  }
}

fn load_balancing_algorithm(algorithm: LoadBalancingAlgorithm) -> &'static [u8] {
  match algorithm {
    LoadBalancingAlgorithm::PowerOfTwoChoices => b"power_of_two_choices",
    LoadBalancingAlgorithm::WeightedLeastConn => b"weighted_least_conn",
    LoadBalancingAlgorithm::RendezvousHash => b"rendezvous_hash",
    LoadBalancingAlgorithm::RendezvousIpHash => b"rendezvous_ip_hash",
    LoadBalancingAlgorithm::Ewma => b"ewma",
    LoadBalancingAlgorithm::LeastTime => b"least_time",
    LoadBalancingAlgorithm::StickyCookie => b"sticky_cookie",
  }
}

fn stream_network(network: StreamNetwork) -> &'static [u8] {
  match network {
    StreamNetwork::Tcp => b"tcp",
    StreamNetwork::Udp => b"udp",
  }
}

fn push_u64(material: &mut Vec<u8>, value: u64) {
  material.extend_from_slice(&value.to_be_bytes());
}

fn push_field(material: &mut Vec<u8>, value: &[u8]) {
  let len = u64::try_from(value.len()).unwrap_or(u64::MAX);
  material.extend_from_slice(&len.to_be_bytes());
  material.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn peer_material_is_binary_and_address_family_separated() {
    let ipv4 = peer_material("127.0.0.1:49152".parse().unwrap());
    let ipv6 = peer_material("[::ffff:127.0.0.1]:49152".parse().unwrap());
    assert_ne!(ipv4, ipv6);
    assert!(!String::from_utf8_lossy(&ipv4).contains("127.0.0.1"));
  }

  #[test]
  fn peer_material_separates_ipv6_interface_scopes_and_flowinfo() {
    let ip = "fe80::1".parse().unwrap();
    let first_scope = peer_material(std::net::SocketAddrV6::new(ip, 49152, 0, 2).into());
    let second_scope = peer_material(std::net::SocketAddrV6::new(ip, 49152, 0, 3).into());
    let flowinfo = peer_material(std::net::SocketAddrV6::new(ip, 49152, 7, 2).into());
    assert_ne!(first_scope, second_scope);
    assert_ne!(first_scope, flowinfo);
  }

  #[test]
  fn target_material_is_domain_and_route_separated() {
    assert_ne!(
      route_identity_material(StreamRouteIdentity::Default),
      route_identity_material(StreamRouteIdentity::Rule("default"))
    );
    assert_ne!(
      direct_target_material(),
      pool_target_material("pool", "server")
    );
    assert_ne!(
      pool_target_material("pool", "server-a"),
      pool_target_material("pool", "server-b")
    );
  }
}

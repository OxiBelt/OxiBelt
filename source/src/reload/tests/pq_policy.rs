use super::*;
use crate::config::UpstreamPoolServerSource;

fn assert_restart(active: &Config, replacement: &Config) {
  for (from, to) in [(active, replacement), (replacement, active)] {
    assert_eq!(
      classify_full_reload_runtime_compatibility(from, to),
      FullReloadCompatibility::RestartRequired(
        FullReloadRestartReason::TlsKeyExchangeGroupControls
      )
    );
  }
}

#[test]
fn pq_static_server_controls_follow_explicit_ids() {
  let mut active = parse_secp256r1_mlkem768_reload_config();
  let pool = &mut active.upstream_pools[0];
  pool.servers[0].id = Some("enabled".into());
  let mut other = pool.servers[0].clone();
  other.id = Some("disabled".into());
  pool.servers[0].tls.enable_secp256r1mlkem768 = true;
  pool.servers.push(other);
  let mut reordered = active.clone();
  reordered.upstream_pools[0].servers.swap(0, 1);
  validate_full_reload_runtime_compatibility(&active, &reordered)
    .expect("reordering stable server IDs must preserve policy identity");
  // Keep the enabled array position while changing which identity owns it.
  reordered.upstream_pools[0].servers[0]
    .tls
    .enable_secp256r1mlkem768 = true;
  reordered.upstream_pools[0].servers[1]
    .tls
    .enable_secp256r1mlkem768 = false;
  assert_restart(&active, &reordered);

  let mut removed = active.clone();
  removed.upstream_pools[0].servers.remove(0);
  assert_restart(&active, &removed);
}

#[test]
fn pq_turn_server_controls_follow_explicit_ids() {
  let mut active = parse_secp256r1_mlkem768_reload_config();
  let pool = &mut active.turn_upstream_pools[0];
  pool.servers[0].id = Some("enabled".into());
  let mut other = pool.servers[0].clone();
  other.id = Some("disabled".into());
  pool.servers[0].tls.enable_secp256r1mlkem768 = true;
  pool.servers.push(other);
  let mut reordered = active.clone();
  reordered.turn_upstream_pools[0].servers.swap(0, 1);
  validate_full_reload_runtime_compatibility(&active, &reordered)
    .expect("reordering stable TURN server IDs must preserve policy identity");
  reordered.turn_upstream_pools[0].servers[0]
    .tls
    .enable_secp256r1mlkem768 = true;
  reordered.turn_upstream_pools[0].servers[1]
    .tls
    .enable_secp256r1mlkem768 = false;
  assert_restart(&active, &reordered);

  let mut removed = active.clone();
  removed.turn_upstream_pools[0].servers.remove(0);
  assert_restart(&active, &removed);
}

#[test]
fn pq_discovery_controls_follow_effective_ids() {
  let mut active = parse_secp256r1_mlkem768_reload_config();
  let pool = &mut active.upstream_pools[0];
  pool.discovery[0].id = Some("enabled".into());
  let mut other = pool.discovery[0].clone();
  other.id = Some("disabled".into());
  pool.discovery[0].tls.enable_secp256r1mlkem768 = true;
  pool.discovery.push(other);
  let mut reordered = active.clone();
  reordered.upstream_pools[0].discovery.swap(0, 1);
  validate_full_reload_runtime_compatibility(&active, &reordered)
    .expect("reordering discovery IDs must preserve policy identity");
  reordered.upstream_pools[0].discovery[0]
    .tls
    .enable_secp256r1mlkem768 = true;
  reordered.upstream_pools[0].discovery[1]
    .tls
    .enable_secp256r1mlkem768 = false;
  assert_restart(&active, &reordered);

  let mut removed = active.clone();
  removed.upstream_pools[0].discovery.remove(0);
  assert_restart(&active, &removed);

  active.upstream_pools[0].discovery[0].id = None;
  let mut explicit = active.clone();
  explicit.upstream_pools[0].discovery[0].id = Some("dns".into());
  validate_full_reload_runtime_compatibility(&active, &explicit)
    .expect("explicitly spelling the default effective ID preserves identity");
}

#[test]
fn pq_unnamed_servers_keep_positional_identity() {
  let mut active = parse_secp256r1_mlkem768_reload_config();
  let pool = &mut active.upstream_pools[0];
  pool.servers.push(pool.servers[0].clone());
  pool.servers[0].tls.enable_secp256r1mlkem768 = true;
  let mut reordered = active.clone();
  reordered.upstream_pools[0].servers.swap(0, 1);
  assert_restart(&active, &reordered);

  let mut active = parse_secp256r1_mlkem768_reload_config();
  let pool = &mut active.turn_upstream_pools[0];
  pool.servers.push(pool.servers[0].clone());
  pool.servers[0].tls.enable_secp256r1mlkem768 = true;
  let mut reordered = active.clone();
  reordered.turn_upstream_pools[0].servers.swap(0, 1);
  assert_restart(&active, &reordered);
}

#[test]
fn pq_runtime_server_copies_are_not_configured_controls() {
  let configured = parse_secp256r1_mlkem768_reload_config();
  for source in [
    UpstreamPoolServerSource::Dns,
    UpstreamPoolServerSource::File,
    UpstreamPoolServerSource::Kubernetes,
    UpstreamPoolServerSource::Consul,
    UpstreamPoolServerSource::Etcd,
    UpstreamPoolServerSource::Nomad,
    UpstreamPoolServerSource::Admin,
  ] {
    let mut active = configured.clone();
    let mut server = active.upstream_pools[0].servers[0].clone();
    server.id = Some("runtime-only".into());
    server.source = source;
    server.tls.enable_secp256r1mlkem768 = true;
    active.upstream_pools[0].servers.push(server);
    validate_full_reload_runtime_compatibility(&active, &configured)
      .expect("runtime source must not create an authoritative TLS control");
  }
}

#[test]
fn pq_control_identity_components_do_not_collide() {
  let mut active = parse_secp256r1_mlkem768_reload_config();
  active.upstream_pools[0].name = "x".into();
  active.upstream_pools[0].servers[0].id = Some("a.servers.b".into());
  active.upstream_pools[0].servers[0]
    .tls
    .enable_secp256r1mlkem768 = true;
  let mut replacement = active.clone();
  replacement.upstream_pools[0].name = "x.servers.a".into();
  replacement.upstream_pools[0].servers[0].id = Some("b".into());
  assert_restart(&active, &replacement);

  let mut active = parse_secp256r1_mlkem768_reload_config();
  active.upstream_pools[0].name = "x".into();
  active.upstream_pools[0].discovery[0].id = Some("a.discovery.b".into());
  active.upstream_pools[0].discovery[0]
    .tls
    .enable_secp256r1mlkem768 = true;
  let mut replacement = active.clone();
  replacement.upstream_pools[0].name = "x.discovery.a".into();
  replacement.upstream_pools[0].discovery[0].id = Some("b".into());
  assert_restart(&active, &replacement);

  let mut active = parse_secp256r1_mlkem768_reload_config();
  active.turn_upstream_pools[0].name = "x".into();
  active.turn_upstream_pools[0].servers[0].id = Some("a.servers.b".into());
  active.turn_upstream_pools[0].servers[0]
    .tls
    .enable_secp256r1mlkem768 = true;
  let mut replacement = active.clone();
  replacement.turn_upstream_pools[0].name = "x.servers.a".into();
  replacement.turn_upstream_pools[0].servers[0].id = Some("b".into());
  assert_restart(&active, &replacement);
}

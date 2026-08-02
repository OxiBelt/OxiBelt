use super::*;

use crate::config::Config;
use crate::state::{AppHandle, AppSnapshot};
use tokio::sync::watch;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

#[tokio::test]
async fn file_discovery_loop_updates_pool_runtime() {
  let temp_dir = common::TempDir::new("file-discovery-runtime");
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  let discovery_dir = config_dir.join("discovery");
  std::fs::create_dir_all(&discovery_dir).expect("discovery dir should be created");
  std::fs::create_dir_all(&cert_dir).expect("cert dir should be created");
  let (cert_path, key_path) = common::create_self_signed_cert(&cert_dir, "file-discovery-runtime");
  let cert_name = cert_path
    .file_name()
    .and_then(|name| name.to_str())
    .expect("cert file name should be UTF-8");
  let key_name = key_path
    .file_name()
    .and_then(|name| name.to_str())
    .expect("key file name should be UTF-8");
  std::fs::write(
    discovery_dir.join("app-pool.json"),
    r#"{"servers":[{"id":"file-alt","origin":"http://127.0.0.1:18081/alt"}]}"#,
  )
  .expect("discovery file should be written");
  let config_path = config_dir.join("oxibelt.toml");
  std::fs::write(
    &config_path,
    r#"
[logging]
level = "info"

[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true
worker_threads = "auto"

[runtime.accept]
workers = "auto"
reuse_port = true
backlog = 8192
accept_error_backoff_ms = 10

[listeners]
https_bind = "127.0.0.1:8443"
http1 = true
http2 = true
http3 = false

[tls]
cert_chain = "__CERT__"
private_key = "__KEY__"

[tls.ocsp]
mode = "disabled"

[proxy]
trusted_ca_certs = []

[proxy.auto_upgrade]
enabled = true
max_http_version = "h2"

[[upstream_pools]]
name = "app-pool"
algorithm = "power_of_two_choices"

[[upstream_pools.servers]]
id = "primary"
origin = "http://127.0.0.1:18080/origin"

[[upstream_pools.discovery]]
provider = "file"
file = "discovery/app-pool.json"
refresh_interval_ms = 50

[[routes]]
name = "main-route"
hosts = ["example.test"]
path_prefix = "/"
upstream_pool = "app-pool"
"#
    .replace("__CERT__", cert_name)
    .replace("__KEY__", key_name),
  )
  .expect("config should be written");

  let config = Config::load(&config_path).expect("config should load");
  config.validate().expect("config should validate");
  let state = AppHandle::new(
    AppSnapshot::new(config)
      .await
      .expect("snapshot should initialize"),
  );
  let (shutdown_tx, shutdown_rx) = watch::channel(false);
  let task_state = state.clone();
  let task = tokio::spawn(async move {
    run_dynamic_upstream_discovery(task_state, shutdown_rx).await;
  });

  let mut found = false;
  for _ in 0..20 {
    if state
      .snapshot()
      .pools
      .snapshot("app-pool")
      .expect("pool should exist")
      .servers
      .iter()
      .any(|server| {
        server.id
          == upstream_control::scoped_discovered_server_id(
            UpstreamPoolServerSource::File,
            "file",
            "file-alt",
          )
          && server.source == "file"
      })
    {
      found = true;
      break;
    }
    tokio::time::sleep(Duration::from_millis(25)).await;
  }

  shutdown_tx.send(true).expect("shutdown should send");
  task.await.expect("discovery task should join");
  assert!(found, "file discovery should add file-alt server");
}

#[tokio::test]
async fn discovered_server_noop_update_keeps_snapshot_generation() {
  let temp_dir = common::TempDir::new("discovery-noop-runtime");
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  std::fs::create_dir_all(&config_dir).expect("config dir should be created");
  std::fs::create_dir_all(&cert_dir).expect("cert dir should be created");
  std::fs::write(config_dir.join("servers.json"), r#"{"servers":[]}"#)
    .expect("discovery file should be written");
  let (cert_path, key_path) = common::create_self_signed_cert(&cert_dir, "discovery-noop-runtime");
  let cert_name = cert_path
    .file_name()
    .and_then(|name| name.to_str())
    .expect("cert file name should be UTF-8");
  let key_name = key_path
    .file_name()
    .and_then(|name| name.to_str())
    .expect("key file name should be UTF-8");
  let config_path = config_dir.join("oxibelt.toml");
  std::fs::write(
    &config_path,
    r#"
[logging]
level = "info"

[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true
worker_threads = "auto"

[runtime.accept]
workers = "auto"
reuse_port = true
backlog = 8192
accept_error_backoff_ms = 10

[listeners]
https_bind = "127.0.0.1:8443"
http1 = true
http2 = true
http3 = false

[tls]
cert_chain = "__CERT__"
private_key = "__KEY__"

[tls.ocsp]
mode = "disabled"

[proxy]
trusted_ca_certs = []

[proxy.auto_upgrade]
enabled = true
max_http_version = "h2"

[[upstream_pools]]
name = "app-pool"
algorithm = "power_of_two_choices"

[[upstream_pools.servers]]
id = "primary"
origin = "http://127.0.0.1:18080/origin"

[[upstream_pools.discovery]]
provider = "file"
file = "servers.json"
scheme = "https"
refresh_interval_ms = 50

[upstream_pools.discovery.tls]
server_name = "backend.example.test"
trust = "system"

[[routes]]
name = "main-route"
hosts = ["example.test"]
path_prefix = "/"
upstream_pool = "app-pool"
"#
    .replace("__CERT__", cert_name)
    .replace("__KEY__", key_name),
  )
  .expect("config should be written");

  let config = Config::load(&config_path).expect("config should load");
  config.validate().expect("config should validate");
  let state = AppHandle::new(
    AppSnapshot::new(config)
      .await
      .expect("snapshot should initialize"),
  );
  let servers = vec![UpstreamPoolServerConfig {
    id: Some("file-alt".to_string()),
    origin: "https://127.0.0.1:18081/alt".parse().expect("valid origin"),
    weight: 1,
    max_conns: 0,
    backup: false,
    state: UpstreamPoolServerState::Ready,
    tls: Default::default(),
    source: UpstreamPoolServerSource::File,
    discovery_instance_id: None,
    discovered_weight: None,
  }];
  let discovery = state.snapshot().config.upstream_pools[0].discovery[0].clone();

  apply_discovered_servers(&state, "app-pool", &discovery, servers.clone())
    .await
    .expect("first discovery update should apply");
  let snapshot_after_apply = state.snapshot();
  let discovered = snapshot_after_apply.config.upstream_pools[0]
    .servers
    .iter()
    .find(|server| server.source == UpstreamPoolServerSource::File)
    .expect("discovered server should be active");
  assert_eq!(
    discovered.tls.server_name.as_deref(),
    Some("backend.example.test")
  );
  assert_eq!(
    discovered.tls.trust,
    crate::config::UpstreamTlsTrust::System
  );

  apply_discovered_servers(&state, "app-pool", &discovery, servers)
    .await
    .expect("second discovery update should be accepted as a no-op");
  let snapshot_after_noop = state.snapshot();

  assert!(
    std::sync::Arc::ptr_eq(&snapshot_after_apply, &snapshot_after_noop),
    "identical discovered servers should not replace the app snapshot"
  );
}

fn file_discovered_server(id: &str, weight: u32) -> UpstreamPoolServerConfig {
  UpstreamPoolServerConfig {
    id: Some(id.to_string()),
    origin: format!("http://{id}.example/")
      .parse()
      .expect("test origin should be valid"),
    weight,
    max_conns: 0,
    backup: false,
    state: UpstreamPoolServerState::Ready,
    tls: Default::default(),
    source: UpstreamPoolServerSource::File,
    discovery_instance_id: None,
    discovered_weight: None,
  }
}

async fn discovery_instance_test_state(
  first_multiplier: u32,
  second_multiplier: u32,
) -> (
  AppHandle,
  UpstreamPoolDiscoveryConfig,
  UpstreamPoolDiscoveryConfig,
) {
  let temp_dir = common::TempDir::new("discovery-instance-runtime");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "discovery-instance-runtime");
  let raw = format!(
    r#"
{}

[[upstream_pools]]
name = "weighted-pool"
algorithm = "power_of_two_choices"

[[upstream_pools.discovery]]
provider = "file"
id = "alpha"
weight_multiplier = {first_multiplier}
file = "alpha.json"

[[upstream_pools.discovery]]
provider = "file"
id = "beta"
weight_multiplier = {second_multiplier}
file = "beta.json"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  let first = config.upstream_pools[0].discovery[0].clone();
  let second = config.upstream_pools[0].discovery[1].clone();
  let state = AppHandle::new(
    AppSnapshot::new(config)
      .await
      .expect("snapshot should initialize"),
  );
  (state, first, second)
}

#[tokio::test]
async fn discovery_instances_preserve_aggregate_weight_and_reconcile_independently() {
  let (state, alpha, beta) = discovery_instance_test_state(20, 80).await;
  apply_discovered_servers(
    &state,
    "weighted-pool",
    &alpha,
    vec![
      file_discovered_server("alpha-a", 1),
      file_discovered_server("alpha-b", 3),
    ],
  )
  .await
  .expect("first discovery cohort should apply");
  apply_discovered_servers(
    &state,
    "weighted-pool",
    &beta,
    vec![file_discovered_server("beta-a", 5)],
  )
  .await
  .expect("second discovery cohort should apply");

  let snapshot = state.snapshot();
  let servers = &snapshot.config.upstream_pools[0].servers;
  let alpha_weight = servers
    .iter()
    .filter(|server| server.discovery_instance_id.as_deref() == Some("alpha"))
    .map(|server| u64::from(server.weight))
    .sum::<u64>();
  let beta_weight = servers
    .iter()
    .filter(|server| server.discovery_instance_id.as_deref() == Some("beta"))
    .map(|server| u64::from(server.weight))
    .sum::<u64>();
  assert_eq!(alpha_weight, 400);
  assert_eq!(beta_weight, 1_600);
  assert_eq!(beta_weight, alpha_weight * 4);
  assert_eq!(
    servers
      .iter()
      .map(|server| server.id.as_deref().unwrap_or_default())
      .collect::<Vec<_>>(),
    [
      upstream_control::scoped_discovered_server_id(
        UpstreamPoolServerSource::File,
        "alpha",
        "alpha-a"
      ),
      upstream_control::scoped_discovered_server_id(
        UpstreamPoolServerSource::File,
        "alpha",
        "alpha-b"
      ),
      upstream_control::scoped_discovered_server_id(
        UpstreamPoolServerSource::File,
        "beta",
        "beta-a"
      ),
    ]
  );

  apply_discovered_servers(
    &state,
    "weighted-pool",
    &alpha,
    vec![file_discovered_server("alpha-a", 7)],
  )
  .await
  .expect("one cohort refresh should apply");
  let snapshot = state.snapshot();
  let servers = &snapshot.config.upstream_pools[0].servers;
  let alpha_weight = servers
    .iter()
    .filter(|server| server.discovery_instance_id.as_deref() == Some("alpha"))
    .map(|server| u64::from(server.weight))
    .sum::<u64>();
  let beta_weight = servers
    .iter()
    .filter(|server| server.discovery_instance_id.as_deref() == Some("beta"))
    .map(|server| u64::from(server.weight))
    .sum::<u64>();
  assert_eq!(beta_weight, alpha_weight * 4);
  assert!(servers.iter().any(|server| {
    server.id.as_deref()
      == Some(
        upstream_control::scoped_discovered_server_id(
          UpstreamPoolServerSource::File,
          "beta",
          "beta-a",
        )
        .as_str(),
      )
  }));

  apply_discovered_servers(&state, "weighted-pool", &alpha, Vec::new())
    .await
    .expect("empty refresh should remove only its owning cohort");
  let snapshot = state.snapshot();
  let servers = &snapshot.config.upstream_pools[0].servers;
  assert_eq!(servers.len(), 1);
  assert_eq!(
    servers[0].id.as_deref(),
    Some(
      upstream_control::scoped_discovered_server_id(
        UpstreamPoolServerSource::File,
        "beta",
        "beta-a"
      )
      .as_str()
    )
  );
  assert_eq!(servers[0].discovery_instance_id.as_deref(), Some("beta"));
}

#[tokio::test]
async fn discovery_instances_scope_colliding_provider_server_ids() {
  let (state, alpha, beta) = discovery_instance_test_state(50, 50).await;
  apply_discovered_servers(
    &state,
    "weighted-pool",
    &alpha,
    vec![file_discovered_server("shared", 1)],
  )
  .await
  .expect("first discovery cohort should apply");
  apply_discovered_servers(
    &state,
    "weighted-pool",
    &beta,
    vec![file_discovered_server("shared", 1)],
  )
  .await
  .expect("a sibling cohort with the same provider-local ID should apply");

  let snapshot = state.snapshot();
  let servers = &snapshot.config.upstream_pools[0].servers;
  assert_eq!(servers.len(), 2);
  assert_ne!(servers[0].id, servers[1].id);
  assert_eq!(
    servers
      .iter()
      .map(|server| server.discovery_instance_id.as_deref().unwrap_or_default())
      .collect::<Vec<_>>(),
    ["alpha", "beta"]
  );
}

#[tokio::test]
async fn unrepresentable_discovery_weight_update_is_atomic() {
  let (state, alpha, beta) = discovery_instance_test_state(1, u32::MAX).await;
  apply_discovered_servers(
    &state,
    "weighted-pool",
    &alpha,
    vec![
      file_discovered_server("alpha-small", 1),
      file_discovered_server("alpha-large", u32::MAX - 1),
    ],
  )
  .await
  .expect("representable first cohort should apply");
  let before = state.snapshot();

  let error = apply_discovered_servers(
    &state,
    "weighted-pool",
    &beta,
    vec![file_discovered_server("beta-large", u32::MAX - 1)],
  )
  .await
  .expect_err("a positive share rounded to zero must be rejected");
  assert!(
    error.to_string().contains("lose a positive backend share"),
    "unexpected error: {error:#}"
  );
  assert!(
    std::sync::Arc::ptr_eq(&before, &state.snapshot()),
    "rejected normalization must leave the previous snapshot active"
  );
}

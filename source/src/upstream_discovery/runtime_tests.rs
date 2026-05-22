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
      .any(|server| server.id == "file-alt" && server.source == "file")
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
    origin: "http://127.0.0.1:18081/alt".parse().expect("valid origin"),
    weight: 1,
    max_conns: 0,
    backup: false,
    state: UpstreamPoolServerState::Ready,
    source: UpstreamPoolServerSource::File,
  }];

  apply_discovered_servers(
    &state,
    "app-pool",
    UpstreamDiscoveryProvider::File,
    servers.clone(),
  )
  .await
  .expect("first discovery update should apply");
  let snapshot_after_apply = state.snapshot();

  apply_discovered_servers(&state, "app-pool", UpstreamDiscoveryProvider::File, servers)
    .await
    .expect("second discovery update should be accepted as a no-op");
  let snapshot_after_noop = state.snapshot();

  assert!(
    std::sync::Arc::ptr_eq(&snapshot_after_apply, &snapshot_after_noop),
    "identical discovered servers should not replace the app snapshot"
  );
}

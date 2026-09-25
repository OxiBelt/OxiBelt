use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use tokio::sync::mpsc;

use super::*;
use crate::config::{
  RuntimeOverrides, UpstreamPoolServerConfig, UpstreamPoolServerSource, UpstreamPoolServerState,
};
use crate::reload::{ReloadManager, ReloadTrigger};
use crate::state::{AppHandle, AppSnapshot};
use crate::upstream_control::{apply_runtime_pool_update, replace_discovered_servers};

#[tokio::test]
async fn full_reload_ignores_runtime_discovered_pq_tls_copies_for_poll_and_signal() {
  let temp_dir = super::common::TempDir::new("full-reload-runtime-discovered-pq");
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  std::fs::create_dir_all(&config_dir).expect("reload config directory should be created");
  std::fs::create_dir_all(&cert_dir).expect("reload certificate directory should be created");
  let (cert_path, key_path) =
    super::common::create_self_signed_cert(&cert_dir, "full-reload-runtime-discovered-pq");
  let config_path = config_dir.join("oxibelt.toml");
  std::fs::write(config_dir.join("discovery.json"), r#"{"servers":[]}"#)
    .expect("discovery fixture should be written");
  let http_bind = unused_loopback_port().await;
  let https_bind = unused_loopback_port().await;
  let initial_raw = full_reload_discovery_tls_config(&cert_path, &key_path, https_bind, http_bind);
  std::fs::write(&config_path, &initial_raw).expect("initial reload config should write");
  let initial_config = Config::load(&config_path).expect("initial reload config should load");
  initial_config
    .validate()
    .expect("initial reload config should validate");
  let state = AppHandle::new(
    AppSnapshot::new(initial_config)
      .await
      .expect("initial snapshot should initialize"),
  );
  let (error_tx, _error_rx) = mpsc::unbounded_channel();
  let mut supervisor = ListenerSupervisor::start(
    state.clone(),
    error_tx,
    test_admin_control(),
    test_admin_operations(),
  )
  .await
  .expect("listener supervisor should start");
  let mut reload = ReloadManager::new(
    config_path.clone(),
    RuntimeOverrides::default(),
    state.snapshot().as_ref(),
  )
  .expect("reload manager should initialize");

  install_runtime_discovered_https_server(&state).await;
  let before_poll = state.snapshot();
  let poll_candidate = initial_raw.replacen(
    "[compression]\nenabled = true",
    "[compression]\nenabled = false",
    1,
  );
  std::fs::write(&config_path, &poll_candidate).expect("poll candidate should write");
  reload
    .reload_if_changed(ReloadTrigger::Poll, &state, &mut supervisor)
    .await;
  let after_poll = state.snapshot();
  assert!(
    !Arc::ptr_eq(&before_poll, &after_poll),
    "an unrelated candidate must reload even when runtime discovery copied PQ TLS"
  );
  assert!(!after_poll.config.compression.enabled);

  install_runtime_discovered_https_server(&state).await;
  let before_signal = state.snapshot();
  let signal_candidate = poll_candidate.replacen(
    "[compression]\nenabled = false",
    "[compression]\nenabled = true",
    1,
  );
  std::fs::write(&config_path, &signal_candidate).expect("signal candidate should write");
  reload
    .reload_if_changed(ReloadTrigger::Signal, &state, &mut supervisor)
    .await;
  let after_signal = state.snapshot();
  assert!(
    !Arc::ptr_eq(&before_signal, &after_signal),
    "Signal reload must ignore the same runtime-discovered TLS copy"
  );
  assert!(after_signal.config.compression.enabled);

  supervisor.shutdown(after_signal.as_ref()).await;
}

#[tokio::test]
async fn full_reload_rejects_discovery_pq_tls_toggle_and_keeps_runtime_snapshot() {
  let temp_dir = super::common::TempDir::new("full-reload-discovery-pq-toggle");
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  std::fs::create_dir_all(&config_dir).expect("reload config directory should be created");
  std::fs::create_dir_all(&cert_dir).expect("reload certificate directory should be created");
  let (cert_path, key_path) =
    super::common::create_self_signed_cert(&cert_dir, "full-reload-discovery-pq-toggle");
  let config_path = config_dir.join("oxibelt.toml");
  std::fs::write(config_dir.join("discovery.json"), r#"{"servers":[]}"#)
    .expect("discovery fixture should be written");
  let http_bind = unused_loopback_port().await;
  let https_bind = unused_loopback_port().await;
  let initial_raw = full_reload_discovery_tls_config(&cert_path, &key_path, https_bind, http_bind);
  std::fs::write(&config_path, &initial_raw).expect("initial reload config should write");
  let initial_config = Config::load(&config_path).expect("initial reload config should load");
  initial_config
    .validate()
    .expect("initial reload config should validate");
  let state = AppHandle::new(
    AppSnapshot::new(initial_config)
      .await
      .expect("initial snapshot should initialize"),
  );
  let (error_tx, _error_rx) = mpsc::unbounded_channel();
  let mut supervisor = ListenerSupervisor::start(
    state.clone(),
    error_tx,
    test_admin_control(),
    test_admin_operations(),
  )
  .await
  .expect("listener supervisor should start");
  let mut reload = ReloadManager::new(
    config_path.clone(),
    RuntimeOverrides::default(),
    state.snapshot().as_ref(),
  )
  .expect("reload manager should initialize");

  install_runtime_discovered_https_server(&state).await;
  let before_toggle = state.snapshot();
  let toggle_candidate = initial_raw.replacen(
    "[upstream_pools.discovery.tls]\nenable_secp256r1mlkem768 = true",
    "[upstream_pools.discovery.tls]\nenable_secp256r1mlkem768 = false",
    1,
  );
  std::fs::write(&config_path, toggle_candidate).expect("toggle candidate should write");
  reload
    .reload_if_changed(ReloadTrigger::Signal, &state, &mut supervisor)
    .await;
  assert!(
    Arc::ptr_eq(&before_toggle, &state.snapshot()),
    "a configured discovery PQ toggle must remain restart-only and preserve the active snapshot"
  );

  supervisor.shutdown(before_toggle.as_ref()).await;
}

fn full_reload_discovery_tls_config(
  cert_path: &Path,
  key_path: &Path,
  https_bind: SocketAddr,
  http_bind: SocketAddr,
) -> String {
  let mut raw = full_reload_config(
    cert_path,
    key_path,
    https_bind,
    http_bind,
    "127.0.0.1:18080"
      .parse()
      .expect("fixed test upstream address should parse"),
  );
  raw.push_str(
    r#"

[[upstream_pools]]
name = "runtime-discovery"

[[upstream_pools.servers]]
id = "static-https"
origin = "https://127.0.0.1:18443/static"

[upstream_pools.servers.tls]
enable_secp256r1mlkem768 = true

[[upstream_pools.discovery]]
id = "runtime-file"
provider = "file"
file = "discovery.json"
scheme = "https"

[upstream_pools.discovery.tls]
enable_secp256r1mlkem768 = true
"#,
  );
  raw
}

async fn install_runtime_discovered_https_server(state: &AppHandle) {
  apply_runtime_pool_update(state, |config| {
    replace_discovered_servers(
      config,
      "runtime-discovery",
      UpstreamPoolServerSource::File,
      "runtime-file",
      vec![UpstreamPoolServerConfig {
        id: Some("runtime-https".to_string()),
        origin: "https://127.0.0.1:19443/discovered"
          .parse()
          .expect("runtime discovered HTTPS endpoint should parse"),
        weight: 1,
        max_conns: 0,
        backup: false,
        state: UpstreamPoolServerState::Ready,
        tls: Default::default(),
        source: UpstreamPoolServerSource::File,
        discovery_instance_id: None,
        discovered_weight: None,
        webtransport_http3_draft: Default::default(),
      }],
    )
  })
  .await
  .expect("runtime discovery update should apply");
  let snapshot = state.snapshot();
  let server = snapshot.config.upstream_pools[0]
    .servers
    .iter()
    .find(|server| server.source == UpstreamPoolServerSource::File)
    .expect("runtime discovered HTTPS server should be installed");
  assert!(server.tls.enable_secp256r1mlkem768);
  assert!(
    server
      .id
      .as_deref()
      .is_some_and(|id| id.starts_with("discovered-")),
    "discovery must replace the provider id with its stable scoped id"
  );
}

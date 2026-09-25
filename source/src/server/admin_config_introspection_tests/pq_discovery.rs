use std::sync::Arc;

use ::http::StatusCode;
use tokio::sync::mpsc;

use super::*;
use crate::config::{
  Config, UpstreamPoolServerConfig, UpstreamPoolServerSource, UpstreamPoolServerState,
};
use crate::state::{AppHandle, AppSnapshot};
use crate::upstream_control::{apply_runtime_pool_update, replace_discovered_servers};

#[tokio::test]
async fn activation_planner_and_config_load_share_discovery_pq_tls_classification() {
  let (_temp_dir, state, current, effective) =
    discovery_pq_test_state("planner-runtime-discovered-pq").await;
  let activation: toml::Value = toml::from_str(&effective).expect("effective TOML should parse");
  let (control, mut receiver) = AdminControlHandle::new(Some(effective), Some(&activation))
    .expect("Admin control should initialize");
  let (error_tx, _error_rx) = mpsc::unbounded_channel();
  let mut listeners = ListenerSupervisor::start(
    state.clone(),
    error_tx,
    control.clone(),
    super::super::test_admin_operations(),
  )
  .await
  .expect("discovery planner listener supervisor should start");

  install_runtime_discovered_https_server(&state).await;
  let unrelated_candidate = current.replacen(
    "[compression]\nenabled = true",
    "[compression]\nenabled = false",
    1,
  );
  let unrelated_plan =
    online_activation_plan(state.clone(), control.clone(), &unrelated_candidate).await;
  let before_unrelated = state.snapshot();
  let response = drive_config_load(
    &state,
    &mut listeners,
    &control,
    &mut receiver,
    unrelated_candidate.clone(),
  )
  .await;
  assert_eq!(response.status, StatusCode::OK, "{:#}", response.body);
  let after_unrelated = state.snapshot();
  assert!(
    !Arc::ptr_eq(&before_unrelated, &after_unrelated),
    "an unrelated Admin config load must not count the runtime-discovered TLS copy"
  );
  assert!(!after_unrelated.config.compression.enabled);
  assert_plan_covers_observed_executor(
    "runtime discovered TLS copy with unrelated config load",
    &unrelated_plan,
    ObservedExecutorOutcome::SnapshotApplied,
  );

  install_runtime_discovered_https_server(&state).await;
  let discovery_toggle_candidate = unrelated_candidate.replacen(
    "[upstream_pools.discovery.tls]\nenable_secp256r1mlkem768 = true",
    "[upstream_pools.discovery.tls]\nenable_secp256r1mlkem768 = false",
    1,
  );
  let discovery_toggle_plan =
    online_activation_plan(state.clone(), control.clone(), &discovery_toggle_candidate).await;
  let before_toggle_status = control.status().await;
  let before_toggle = state.snapshot();
  let response = drive_config_load(
    &state,
    &mut listeners,
    &control,
    &mut receiver,
    discovery_toggle_candidate,
  )
  .await;
  assert_eq!(
    response.status,
    StatusCode::BAD_REQUEST,
    "{:#}",
    response.body
  );
  assert!(
    response
      .body
      .get("error")
      .and_then(serde_json::Value::as_str)
      .is_some_and(|error| {
        error
          == "full hot reload rejected because SecP256r1MLKEM768 TLS key-exchange policy is restart-only"
      }),
    "configured discovery PQ toggle should be restart-only: {:#}",
    response.body
  );
  assert_rejected_load_preserves_revision(&before_toggle_status, &control.status().await);
  assert!(
    Arc::ptr_eq(&before_toggle, &state.snapshot()),
    "a rejected discovery PQ toggle must retain the active runtime snapshot"
  );
  assert_plan_covers_observed_executor(
    "configured discovery PQ toggle",
    &discovery_toggle_plan,
    ObservedExecutorOutcome::RestartOnlyRejected,
  );

  listeners.shutdown(before_toggle.as_ref()).await;
}

async fn discovery_pq_test_state(
  name: &str,
) -> (super::common::TempDir, AppHandle, String, String) {
  let temp_dir = super::common::TempDir::new(name);
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  std::fs::create_dir_all(&config_dir).expect("config directory should be created");
  std::fs::create_dir_all(&cert_dir).expect("certificate directory should be created");
  let (cert_path, key_path) = super::common::create_self_signed_cert(&cert_dir, name);
  std::fs::write(config_dir.join("discovery.json"), r#"{"servers":[]}"#)
    .expect("discovery fixture should be written");
  let candidate = discovery_pq_test_config(&super::common::minimal_config_toml_with_paths(
    cert_path.file_name().unwrap().to_str().unwrap(),
    key_path.file_name().unwrap().to_str().unwrap(),
  ));
  let effective =
    discovery_pq_test_config(&super::common::minimal_config_toml(&cert_path, &key_path));
  let config_path = config_dir.join("oxibelt.toml");
  std::fs::write(&config_path, &candidate).expect("config should be written");
  let config = Config::load(&config_path).expect("discovery config should load");
  config.validate().expect("discovery config should validate");
  let snapshot = AppSnapshot::new(config)
    .await
    .expect("discovery snapshot should initialize");
  (temp_dir, AppHandle::new(snapshot), candidate, effective)
}

fn discovery_pq_test_config(base: &str) -> String {
  format!(
    r#"{base}

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
"#
  )
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

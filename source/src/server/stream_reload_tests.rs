use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

use super::*;
use crate::config::RuntimeOverrides;
use crate::config::{Config, StreamListenerConfig, StreamNetwork, UdpFlowState};
use crate::reload::{ReloadManager, ReloadTrigger};
use crate::shared_state::SharedState;
use crate::state::{AppHandle, AppSnapshot};

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

#[test]
fn stream_listener_set_rejects_duplicate_desired_names() {
  let options = TcpListenOptions {
    workers: 1,
    reuse_port: false,
    backlog: 16,
  };
  let first = StreamListenerGeneration::new(
    stream_listener(
      "duplicate",
      StreamNetwork::Tcp,
      UdpFlowState::Local,
      "127.0.0.1:31001".parse().expect("test bind should parse"),
    ),
    options,
    Default::default(),
    None,
  )
  .expect("first generation should build");
  let second = StreamListenerGeneration::new(
    stream_listener(
      "duplicate",
      StreamNetwork::Tcp,
      UdpFlowState::Local,
      "127.0.0.1:31002".parse().expect("test bind should parse"),
    ),
    options,
    Default::default(),
    None,
  )
  .expect("second generation should build");
  let error = match listener_sets::prepare_stream_listener_set_update(
    &BTreeMap::new(),
    vec![first, second],
    1,
  ) {
    Ok(_) => panic!("duplicate desired stream names must fail preparation"),
    Err(error) => error,
  };
  assert!(
    error.to_string().contains("duplicate stream listener name"),
    "duplicate-name failure should identify the invariant: {error:#}"
  );
}

#[tokio::test]
async fn stream_runtime_rotation_reuses_unaffected_tasks() {
  const TEST_NAME: &str =
    "server::stream_reload_tests::stream_runtime_rotation_reuses_unaffected_tasks";
  const IDENTITY_KEY_ENV: &str = "OXIBELT_STREAM_RELOAD_UDP_IDENTITY_KEY";
  if common::run_test_in_subprocess_with_env(
    TEST_NAME,
    &[(
      IDENTITY_KEY_ENV,
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )],
  ) {
    return;
  }

  let temp_dir = common::TempDir::new("stream-runtime-rotation");
  let cert_dir = temp_dir.path().join("cert");
  std::fs::create_dir_all(&cert_dir).expect("certificate directory should be created");
  let (cert_path, key_path) = common::create_self_signed_cert(&cert_dir, "stream-runtime-rotation");
  let https_bind = unused_loopback_port().await;
  let tcp_bind = unused_loopback_port().await;
  let local_udp_bind = unused_loopback_udp_port().await;
  let shared_udp_bind = unused_loopback_udp_port().await;
  let listeners = vec![
    stream_listener("tcp", StreamNetwork::Tcp, UdpFlowState::Local, tcp_bind),
    stream_listener(
      "local-udp",
      StreamNetwork::Udp,
      UdpFlowState::Local,
      local_udp_bind,
    ),
    stream_listener(
      "shared-udp",
      StreamNetwork::Udp,
      UdpFlowState::SharedRequired,
      shared_udp_bind,
    ),
  ];
  let initial_runtime = SharedState::test_memory("stream-runtime-rotation");
  let initial_snapshot = stream_snapshot(
    stream_test_config(&cert_path, &key_path, https_bind, listeners),
    initial_runtime,
  )
  .await;
  let state = AppHandle::new(initial_snapshot);
  let (error_tx, mut error_rx) = mpsc::unbounded_channel();
  let mut supervisor = ListenerSupervisor::start(
    state.clone(),
    error_tx,
    test_admin_control(),
    test_admin_operations(),
  )
  .await
  .expect("listener supervisor should start");
  assert_no_listener_error(&mut error_rx).await;

  let tcp_identity = stream_task_identity(&supervisor, "tcp");
  let mut local_udp_identity = stream_task_identity(&supervisor, "local-udp");
  let shared_udp_identity = stream_task_identity(&supervisor, "shared-udp");
  let unchanged = supervisor
    .prepare(state.snapshot().as_ref())
    .await
    .expect("unchanged stream listeners should prepare");
  assert!(
    !unchanged.has_stream_update(),
    "the same runtime and listener generations must not prepare replacements"
  );

  let mut reordered = state.snapshot().as_ref().clone();
  reordered.config.stream_listeners.reverse();
  let reordered = supervisor
    .prepare(&reordered)
    .await
    .expect("reordered stream listeners should prepare");
  assert!(
    !reordered.has_stream_update(),
    "listener ordering alone must not replace stream tasks"
  );

  let mut replacement = state.snapshot().as_ref().clone();
  let replacement_runtime = SharedState::test_memory("stream-runtime-rotation");
  replacement.shared_state = Some(replacement_runtime.clone());
  let pending = supervisor
    .prepare(&replacement)
    .await
    .expect("shared-state runtime rotation should prepare");
  assert!(
    pending.has_stream_update(),
    "shared-required UDP must prepare a replacement for a new runtime"
  );
  state.replace(replacement);
  let active = state.snapshot();
  supervisor.commit(pending, active.as_ref(), state.clone());
  assert_no_listener_error(&mut error_rx).await;

  assert_same_stream_task(&supervisor, "tcp", &tcp_identity);
  assert_same_stream_task(&supervisor, "local-udp", &local_udp_identity);
  assert_different_stream_task(&supervisor, "shared-udp", &shared_udp_identity);
  assert!(
    supervisor.streams["shared-udp"]
      .generation
      .test_uses_shared_state(&replacement_runtime),
    "replacement durable UDP task must carry the candidate shared-state runtime"
  );

  TcpStream::connect(tcp_bind)
    .await
    .expect("unaffected TCP stream listener should retain its socket");

  let tcp_after_rotation = stream_task_identity(&supervisor, "tcp");
  let shared_udp_after_rotation = stream_task_identity(&supervisor, "shared-udp");
  let added_udp_bind = unused_loopback_udp_port().await;
  let mut changed_set = state.snapshot().as_ref().clone();
  changed_set
    .config
    .stream_listeners
    .retain(|listener| listener.name != "local-udp");
  changed_set.config.stream_listeners.push(stream_listener(
    "added-udp",
    StreamNetwork::Udp,
    UdpFlowState::Local,
    added_udp_bind,
  ));
  let pending = supervisor
    .prepare(&changed_set)
    .await
    .expect("independent stream add and remove should prepare");
  assert!(
    pending.has_stream_update(),
    "an added and removed listener must prepare a set update"
  );
  state.replace(changed_set);
  let active = state.snapshot();
  supervisor.commit(pending, active.as_ref(), state.clone());
  assert_no_listener_error(&mut error_rx).await;
  assert_same_stream_task(&supervisor, "tcp", &tcp_after_rotation);
  assert_same_stream_task(&supervisor, "shared-udp", &shared_udp_after_rotation);
  assert!(
    !supervisor.streams.contains_key("local-udp"),
    "removed stream listener must leave the active set"
  );
  assert!(
    supervisor.streams.contains_key("added-udp"),
    "added stream listener must join the active set"
  );
  tokio::time::timeout(
    std::time::Duration::from_secs(1),
    local_udp_identity.changed(),
  )
  .await
  .expect("removed local UDP listener should quiesce promptly")
  .expect("removed local UDP listener quiesce channel should stay observable");
  assert!(
    *local_udp_identity.borrow(),
    "removed local UDP listener must receive quiesce"
  );
  supervisor.shutdown(active.as_ref()).await;
}

#[tokio::test]
async fn stream_bind_failure_keeps_last_good_state_and_task() {
  let temp_dir = common::TempDir::new("stream-bind-failure");
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  std::fs::create_dir_all(&config_dir).expect("config directory should be created");
  std::fs::create_dir_all(&cert_dir).expect("certificate directory should be created");
  let (cert_path, key_path) = common::create_self_signed_cert(&cert_dir, "stream-bind-failure");
  let relative_cert_path = Path::new(
    cert_path
      .file_name()
      .expect("test certificate should have a filename"),
  );
  let relative_key_path = Path::new(
    key_path
      .file_name()
      .expect("test private key should have a filename"),
  );
  let config_path = config_dir.join("oxibelt.toml");
  let https_bind = unused_loopback_port().await;
  let initial_bind = unused_loopback_port().await;
  let initial_listeners = vec![stream_listener(
    "tcp",
    StreamNetwork::Tcp,
    UdpFlowState::Local,
    initial_bind,
  )];
  let initial_raw = stream_reload_config(
    &relative_cert_path,
    &relative_key_path,
    https_bind,
    &initial_listeners,
  );
  std::fs::write(&config_path, initial_raw).expect("initial stream reload config should write");
  let initial_config =
    Config::load(&config_path).expect("initial stream reload config should load");
  initial_config
    .validate()
    .expect("initial stream reload config should validate");
  let initial_snapshot = AppSnapshot::new(initial_config)
    .await
    .expect("initial stream reload snapshot should initialize");
  let state = AppHandle::new(initial_snapshot);
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
  .expect("stream reload manager should initialize");
  let original = state.snapshot();
  let original_task = stream_task_identity(&supervisor, "tcp");

  let staged_addr = unused_loopback_port().await;
  let occupied = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("candidate collision listener should bind");
  let occupied_addr = occupied
    .local_addr()
    .expect("candidate collision address should be available");
  let mut candidate_listeners = initial_listeners;
  candidate_listeners.push(stream_listener(
    "a-staged",
    StreamNetwork::Tcp,
    UdpFlowState::Local,
    staged_addr,
  ));
  candidate_listeners.push(stream_listener(
    "z-occupied",
    StreamNetwork::Tcp,
    UdpFlowState::Local,
    occupied_addr,
  ));
  let candidate_raw = stream_reload_config(
    &relative_cert_path,
    &relative_key_path,
    https_bind,
    &candidate_listeners,
  );
  std::fs::write(&config_path, candidate_raw).expect("candidate stream reload config should write");
  reload
    .reload_if_changed(ReloadTrigger::Signal, &state, &mut supervisor)
    .await;
  assert!(
    Arc::ptr_eq(&original, &state.snapshot()),
    "failed preparation must not publish the candidate snapshot"
  );
  assert_same_stream_task(&supervisor, "tcp", &original_task);
  let staged_rebind = TcpListener::bind(staged_addr)
    .await
    .expect("a staged socket must be released after later bind failure");
  TcpStream::connect(initial_bind)
    .await
    .expect("last-good TCP stream listener should remain reachable");

  drop(staged_rebind);
  drop(occupied);
  supervisor.shutdown(original.as_ref()).await;
}

fn stream_test_config(
  cert_path: &Path,
  key_path: &Path,
  https_bind: SocketAddr,
  stream_listeners: Vec<StreamListenerConfig>,
) -> Config {
  let raw = common::minimal_config_toml(cert_path, key_path)
    .replace("unprivileged_mode = true", "unprivileged_mode = false")
    .replace(
      "https_bind = \"127.0.0.1:8443\"",
      &format!("https_bind = \"{https_bind}\""),
    );
  let mut config: Config = toml::from_str(&raw).expect("base stream test config should parse");
  config.runtime.accept.workers = 1;
  config.runtime.accept.reuse_port = false;
  config.stream_listeners = stream_listeners;
  if config
    .stream_listeners
    .iter()
    .any(|listener| listener.udp_flow_state == UdpFlowState::SharedRequired)
  {
    config.shared_state = toml::from_str(
      r#"
enabled = true
namespace = "stream-reload-test"
udp_flows_backend = "state"
connection_limits_backend = "state"
udp_flow_identity_key_env = "OXIBELT_STREAM_RELOAD_UDP_IDENTITY_KEY"
operation_timeout_ms = 500

[[backends]]
name = "state"
kind = "redis"
connection_url = "redis://127.0.0.1:1/0"
max_connections = 64
connect_timeout_ms = 100
"#,
    )
    .expect("shared-state test configuration should parse");
  }
  config
}

async fn stream_snapshot(config: Config, shared_state: Arc<SharedState>) -> AppSnapshot {
  config
    .validate()
    .expect("production-shaped stream test config should validate");
  let mut bootstrap = config.clone();
  bootstrap.stream_listeners.clear();
  bootstrap.shared_state = Default::default();
  let mut snapshot = AppSnapshot::new(bootstrap)
    .await
    .expect("stream test snapshot should initialize");
  snapshot.config = config;
  snapshot.shared_state = Some(shared_state);
  snapshot
}

fn stream_reload_config(
  cert_path: &Path,
  key_path: &Path,
  https_bind: SocketAddr,
  stream_listeners: &[StreamListenerConfig],
) -> String {
  let mut raw = common::minimal_config_toml(cert_path, key_path)
    .replace("unprivileged_mode = true", "unprivileged_mode = false")
    .replace("workers = \"auto\"", "workers = 1")
    .replace("reuse_port = true", "reuse_port = false")
    .replace(
      "https_bind = \"127.0.0.1:8443\"",
      &format!("https_bind = \"{https_bind}\""),
    );
  raw.push_str(
    r#"

[runtime.hot_reload]
mode = "full"
poll_interval_ms = 60000
"#,
  );
  for listener in stream_listeners {
    let network = match listener.network {
      StreamNetwork::Tcp => "tcp",
      StreamNetwork::Udp => "udp",
    };
    let udp_flow_state = match listener.udp_flow_state {
      UdpFlowState::Local => "local",
      UdpFlowState::SharedRequired => "shared_required",
    };
    raw.push_str(&format!(
      r#"

[[stream_listeners]]
name = "{}"
network = "{network}"
bind = "{}"
target = "127.0.0.1:9"
udp_flow_state = "{udp_flow_state}"
"#,
      listener.name, listener.bind
    ));
  }
  raw
}

fn stream_listener(
  name: &str,
  network: StreamNetwork,
  udp_flow_state: UdpFlowState,
  bind: SocketAddr,
) -> StreamListenerConfig {
  let network = match network {
    StreamNetwork::Tcp => "tcp",
    StreamNetwork::Udp => "udp",
  };
  let udp_flow_state = match udp_flow_state {
    UdpFlowState::Local => "local",
    UdpFlowState::SharedRequired => "shared_required",
  };
  toml::from_str(&format!(
    "name = \"{name}\"\nnetwork = \"{network}\"\nbind = \"{bind}\"\ntarget = \"127.0.0.1:9\"\nudp_flow_state = \"{udp_flow_state}\"\n"
  ))
  .expect("stream test listener should parse")
}

fn stream_task_identity(supervisor: &ListenerSupervisor, name: &str) -> watch::Receiver<bool> {
  supervisor
    .streams
    .get(name)
    .unwrap_or_else(|| panic!("stream listener task should exist: {name}"))
    .test_identity()
}

fn assert_same_stream_task(
  supervisor: &ListenerSupervisor,
  name: &str,
  identity: &watch::Receiver<bool>,
) {
  assert!(
    stream_task_identity(supervisor, name).same_channel(identity),
    "stream listener task should be retained: {name}"
  );
}

fn assert_different_stream_task(
  supervisor: &ListenerSupervisor,
  name: &str,
  identity: &watch::Receiver<bool>,
) {
  assert!(
    !stream_task_identity(supervisor, name).same_channel(identity),
    "stream listener task should be replaced: {name}"
  );
}

async fn assert_no_listener_error(error_rx: &mut mpsc::UnboundedReceiver<anyhow::Error>) {
  tokio::time::sleep(std::time::Duration::from_millis(25)).await;
  assert!(
    matches!(error_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
    "stream listener worker reported an unexpected startup error"
  );
}

async fn unused_loopback_port() -> SocketAddr {
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("ephemeral TCP port should bind");
  listener
    .local_addr()
    .expect("ephemeral TCP address should be available")
}

async fn unused_loopback_udp_port() -> SocketAddr {
  let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
    .await
    .expect("ephemeral UDP port should bind");
  socket
    .local_addr()
    .expect("ephemeral UDP address should be available")
}

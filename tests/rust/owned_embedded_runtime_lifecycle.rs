use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use oxibelt::config::Config;
use oxibelt::server::{
  BoundListenerKind, BoundListenerTransport, ServerHandle, ShutdownOutcome, ShutdownReason,
};
use oxibelt::{OxiBelt, ProcessGlobalHooks, ProcessPolicy, RuntimePolicy};

mod common;

const TEST_NAME: &str = "public_owned_and_embedded_lifecycle_reuses_listener_after_join";
const OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const LIFECYCLE_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

struct LifecycleWatchdog {
  disarm_tx: mpsc::SyncSender<()>,
  thread: JoinHandle<()>,
}

impl LifecycleWatchdog {
  fn arm(timeout: Duration) -> Self {
    let (disarm_tx, disarm_rx) = mpsc::sync_channel(1);
    let thread = thread::Builder::new()
      .name("oxibelt-lifecycle-test-watchdog".to_string())
      .spawn(move || match disarm_rx.recv_timeout(timeout) {
        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {}
        Err(mpsc::RecvTimeoutError::Timeout) => {
          eprintln!(
            "owned-embedded lifecycle child watchdog exceeded {timeout:?}; aborting the child so its parent receives a terminal failure"
          );
          std::process::abort();
        }
      })
      .expect("lifecycle test should start its child watchdog");
    Self { disarm_tx, thread }
  }

  fn disarm(self) {
    self
      .disarm_tx
      .send(())
      .expect("lifecycle watchdog must accept disarm after a successful lifecycle");
    self
      .thread
      .join()
      .expect("lifecycle watchdog thread should join after disarm");
  }
}

#[test]
fn lifecycle_watchdog_contract_keeps_timeout_termination() {
  let source = include_str!("owned_embedded_runtime_lifecycle.rs");
  let implementation = source
    .split_once("impl LifecycleWatchdog {")
    .and_then(|(_, source)| source.split_once("#[test]"))
    .map(|(implementation, _)| implementation)
    .expect("lifecycle watchdog implementation should precede its tests");
  assert!(
    implementation.contains("recv_timeout(timeout)"),
    "lifecycle watchdog must keep its bounded receive"
  );
  assert!(
    implementation.contains("std::process::abort();"),
    "lifecycle watchdog timeout must terminate the child process"
  );
}

#[test]
fn lifecycle_watchdog_contract_keeps_child_lifecycle_placement() {
  let source = include_str!("owned_embedded_runtime_lifecycle.rs");
  let body = source
    .split_once("\nfn public_owned_and_embedded_lifecycle_reuses_listener_after_join() {")
    .and_then(|(_, source)| source.split_once("\n}\n\nasync fn exercise_public_lifecycle()"))
    .map(|(body, _)| body)
    .expect("public lifecycle test body should remain delimited by its async helper");
  let required_steps = [
    "if common::run_test_in_subprocess_with_env(TEST_NAME, &[(\"RUST_BACKTRACE\", \"1\")])",
    "let watchdog = LifecycleWatchdog::arm(LIFECYCLE_TOTAL_TIMEOUT);",
    "let runtime = tokio::runtime::Builder::new_current_thread()",
    "runtime.block_on(exercise_public_lifecycle());",
    "watchdog.disarm();",
  ];
  let mut previous = None;
  for step in required_steps {
    assert_eq!(
      body.matches(step).count(),
      1,
      "public lifecycle test must contain exactly one `{step}`"
    );
    let position = body
      .find(step)
      .expect("required lifecycle step should have one source position");
    if let Some(previous) = previous {
      assert!(
        position > previous,
        "public lifecycle test must keep `{step}` after its preceding lifecycle step"
      );
    }
    previous = Some(position);
  }
}

#[test]
fn lifecycle_watchdog_disarms_without_waiting_for_its_deadline() {
  let watchdog = LifecycleWatchdog::arm(LIFECYCLE_TOTAL_TIMEOUT);
  let start = Instant::now();
  watchdog.disarm();
  assert!(
    start.elapsed() < OPERATION_TIMEOUT,
    "watchdog disarm should join before the lifecycle operation deadline"
  );
}

#[test]
fn public_owned_and_embedded_lifecycle_reuses_listener_after_join() {
  // `build_owned` necessarily selects standalone process ownership. Keep those mandatory
  // process-global claims in an isolated child, while exercising the public API unchanged.
  if common::run_test_in_subprocess_with_env(TEST_NAME, &[("RUST_BACKTRACE", "1")]) {
    return;
  }

  let watchdog = LifecycleWatchdog::arm(LIFECYCLE_TOTAL_TIMEOUT);
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("lifecycle test should create its caller-managed Tokio runtime");
  runtime.block_on(exercise_public_lifecycle());
  watchdog.disarm();
}

async fn exercise_public_lifecycle() {
  let temporary = common::TempDir::new("owned-embedded-runtime-lifecycle");
  let bind = reserve_loopback_address();
  let config = lifecycle_config(temporary.path(), bind);

  let mut owned = OxiBelt::builder(config.clone())
    .runtime_policy(RuntimePolicy::FromConfig)
    .process_policy(ProcessPolicy::Standalone)
    .build_owned()
    .expect("owned lifecycle builder should accept explicit standalone ownership")
    .start()
    .unwrap_or_else(|error| panic!("owned lifecycle start should bind {bind}: {error}"));
  wait_for_readiness_and_observe_listener(&mut owned, bind, "owned").await;
  let owned_result = within("owned graceful shutdown", owned.shutdown(deadline()))
    .await
    .expect("owned lifecycle should return a joined graceful shutdown result");
  assert_eq!(owned_result.outcome, ShutdownOutcome::Graceful);
  assert_eq!(owned_result.reason, ShutdownReason::CallerRequested);

  // This is intentionally sequential: the same explicit address is reused only after the
  // owned handle's joined result confirms its runtime driver has finished.
  let mut embedded = within(
    "embedded caller-managed start",
    OxiBelt::builder(config)
      .runtime_policy(RuntimePolicy::CurrentRuntime)
      .process_policy(ProcessPolicy::Embedded(ProcessGlobalHooks::CallerManaged))
      .build_embedded()
      .expect("embedded lifecycle builder should accept caller-managed ownership")
      .start(),
  )
  .await
  .unwrap_or_else(|error| panic!("embedded lifecycle start should reuse {bind}: {error}"));
  wait_for_readiness_and_observe_listener(&mut embedded, bind, "embedded").await;
  embedded
    .cancel()
    .expect("embedded lifecycle cancellation should remain available before terminal wait");
  let embedded_result = within("embedded cancellation wait", embedded.wait())
    .await
    .expect("embedded lifecycle should return a terminal cancellation result");
  assert_eq!(embedded_result.outcome, ShutdownOutcome::Cancelled);
  assert_eq!(
    embedded_result.reason,
    ShutdownReason::ImmediateCancellation
  );
}

async fn wait_for_readiness_and_observe_listener(
  handle: &mut ServerHandle,
  expected_bind: SocketAddr,
  mode: &str,
) {
  let readiness = handle
    .wait_ready(deadline())
    .await
    .unwrap_or_else(|error| panic!("{mode} lifecycle did not become ready: {error}"));
  assert!(
    readiness.is_ready(),
    "{mode} lifecycle readiness must be ready"
  );
  assert!(
    handle.bound_listeners().iter().any(|listener| {
      listener.kind == BoundListenerKind::Https
        && listener.transport == BoundListenerTransport::Tcp
        && listener.address == expected_bind
    }),
    "{mode} lifecycle must publish its explicit HTTPS/TCP listener {expected_bind}"
  );
  assert_kernel_observes_listener(expected_bind, mode);
}

fn assert_kernel_observes_listener(address: SocketAddr, mode: &str) {
  match TcpListener::bind(address) {
    Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
    Ok(listener) => {
      drop(listener);
      panic!("{mode} lifecycle reported {address}, but the kernel did not keep it bound");
    }
    Err(error) => panic!("{mode} lifecycle kernel bind observation for {address} failed: {error}"),
  }

  let stream = TcpStream::connect_timeout(&address, OPERATION_TIMEOUT)
    .unwrap_or_else(|error| panic!("{mode} lifecycle kernel connect to {address} failed: {error}"));
  drop(stream);
}

fn reserve_loopback_address() -> SocketAddr {
  let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|error| {
    panic!(
      "lifecycle loopback socket preflight failed ({error}); if this is EPERM/PermissionDenied, rerun this focused Cargo test through the allowed privileged channel"
    )
  });
  listener
    .local_addr()
    .expect("lifecycle loopback socket should report its ephemeral address")
}

fn lifecycle_config(temp_dir: &std::path::Path, bind: SocketAddr) -> Config {
  let config_dir = temp_dir.join("config");
  let cert_dir = temp_dir.join("cert");
  fs::create_dir_all(&config_dir).expect("lifecycle test should create its local config directory");
  fs::create_dir_all(&cert_dir)
    .expect("lifecycle test should create its local certificate directory");
  let (certificate, private_key) = common::create_self_signed_cert(&cert_dir, "lifecycle.local");
  let certificate = certificate
    .file_name()
    .and_then(|name| name.to_str())
    .expect("temporary certificate filename should be UTF-8");
  let private_key = private_key
    .file_name()
    .and_then(|name| name.to_str())
    .expect("temporary private-key filename should be UTF-8");
  let config_path = config_dir.join("lifecycle.toml");
  fs::write(
    &config_path,
    format!(
      r#"
[logging]
level = "error"

[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true
worker_threads = 1
main_runtime = "tokio_hyper"
topology_policy = "allow_fallback"
direct_h1_io = "tokio_hyper"

[runtime.accept]
workers = 1
reuse_port = false
backlog = 128
accept_error_backoff_ms = 10

[runtime.drain]
graceful_timeout_ms = 1000
long_connection_close_delay_ms = 1
shutdown_delay_ms = 0

[runtime.hardening]
close_range = "off"

[runtime.hardening.landlock]
mode = "off"

[listeners]
https_bind = "{bind}"
http1 = true
http2 = false
http3 = false

[tls]
cert_chain = "{certificate}"
private_key = "{private_key}"

[tls.ocsp]
mode = "disabled"

[proxy]
trusted_ca_certs = []

[compression]
enabled = false

[[routes]]
name = "lifecycle-redirect"
hosts = ["lifecycle.local"]
path_prefix = "/"

[routes.actions.redirect]
status = 308
location_template = "/lifecycle"
"#,
    ),
  )
  .expect("lifecycle test should write its local configuration");
  Config::load(&config_path).expect("lifecycle test configuration should load")
}

fn deadline() -> Instant {
  Instant::now() + OPERATION_TIMEOUT
}

async fn within<T>(operation: &str, future: impl std::future::Future<Output = T>) -> T {
  tokio::time::timeout(OPERATION_TIMEOUT, future)
    .await
    .unwrap_or_else(|_| panic!("{operation} exceeded {OPERATION_TIMEOUT:?}"))
}

use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

#[test]
fn fingerprint_changes_when_symlink_target_changes() {
  let root = test_artifact_root().join(format!(
    "fingerprint-symlink-{}",
    NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
  ));
  fs::create_dir_all(&root).expect("failed to create temp dir");
  let first = root.join("first.pem");
  let second = root.join("second.pem");
  let link = root.join("current.pem");
  fs::write(&first, b"first").expect("failed to write first target");
  fs::write(&second, b"second certificate body").expect("failed to write second target");

  std::os::unix::fs::symlink(&first, &link).expect("failed to create symlink");
  let first_fingerprint = fingerprint_files(vec![link.clone()]);
  fs::remove_file(&link).expect("failed to remove symlink");
  std::os::unix::fs::symlink(&second, &link).expect("failed to retarget symlink");
  let second_fingerprint = fingerprint_files(vec![link.clone()]);

  let _ = fs::remove_dir_all(&root);
  assert_ne!(first_fingerprint, second_fingerprint);
}

#[test]
fn full_reload_rejects_runtime_worker_thread_resize() {
  let active = parse_worker_reload_config(2);
  let replacement = parse_worker_reload_config(3);

  let error = validate_full_reload_runtime_compatibility(&active, &replacement)
    .expect_err("runtime worker resize should require process restart");
  assert!(
    error
      .to_string()
      .contains("runtime.workers.tokio changed from 2 to 3"),
    "unexpected error: {error}"
  );
}

#[test]
fn full_reload_accepts_legacy_compio_alias_to_canonical_name() {
  let mut active = parse_worker_reload_config(2);
  active.runtime.main_runtime = crate::config::RuntimeMainRuntimeMode::Compio;
  let mut replacement = active.clone();
  replacement.runtime.main_runtime = crate::config::RuntimeMainRuntimeMode::HybridCompio;

  assert_eq!(
    classify_runtime_topology_change(&active, &replacement),
    crate::runtime::topology::RuntimeTopologyChangePlan::InProcess
  );
  validate_full_reload_runtime_compatibility(&active, &replacement)
    .expect("renaming the compatibility alias must not require a restart");
}

#[test]
fn full_reload_accepts_compio_direct_h1_worker_resize() {
  let active = parse_worker_reload_config(2);
  let mut replacement = active.clone();
  replacement.runtime.workers.compio_direct_h1 = 3;

  assert_eq!(
    classify_runtime_topology_change(&active, &replacement),
    crate::runtime::topology::RuntimeTopologyChangePlan::InProcess
  );
  validate_full_reload_runtime_compatibility(&active, &replacement)
    .expect("the replacement Compio direct-H1 fleet can be staged in process");
}

#[test]
fn full_reload_rejects_mutation_runtime_policy_changes() {
  let active = parse_worker_reload_config(2);
  let mut replacement = active.clone();
  replacement.admin.mutations.mode = crate::config::AdminMutationMode::Optional;

  let error = validate_full_reload_runtime_compatibility(&active, &replacement)
    .expect_err("mutation trust changes should require process restart");
  assert!(error.to_string().contains("admin.mutations"));
}

#[test]
fn full_reload_rejects_admin_audit_authority_changes() {
  let mut active = parse_worker_reload_config(2);
  active.admin.audit.enabled = true;
  let mut replacement = active.clone();
  replacement.admin.audit.mode = crate::config::AdminAuditMode::BestEffort;

  let error = validate_full_reload_runtime_compatibility(&active, &replacement)
    .expect_err("audit authority changes should require process restart");
  assert!(error.to_string().contains("admin.audit"));
}

#[test]
fn full_reload_rejects_runtime_hardening_changes() {
  let active = parse_worker_reload_config(2);
  let mut replacement = active.clone();
  replacement.runtime.hardening.close_range = crate::config::HardeningAutoMode::Required;

  assert_eq!(
    classify_full_reload_runtime_compatibility(&active, &replacement),
    FullReloadCompatibility::RestartRequired(FullReloadRestartReason::RuntimeHardening)
  );
  let error = validate_full_reload_runtime_compatibility(&active, &replacement)
    .expect_err("irreversible hardening changes must require process restart");
  assert!(error.to_string().contains("runtime.hardening"));
}

#[test]
fn full_reload_rejects_process_owned_listener_changes() {
  let active = parse_worker_reload_config(2);
  let mut replacement = active.clone();
  replacement.metrics.enabled = !active.metrics.enabled;

  assert_eq!(
    classify_full_reload_runtime_compatibility(&active, &replacement),
    FullReloadCompatibility::RestartRequired(FullReloadRestartReason::MetricsListener)
  );
  let error = validate_full_reload_runtime_compatibility(&active, &replacement)
    .expect_err("metrics listener ownership must require process restart");
  assert!(error.to_string().contains("metrics listener"));
}

#[test]
fn full_reload_rejects_hot_reload_manager_changes() {
  let active = parse_worker_reload_config(2);
  let mut replacement = active.clone();
  replacement.runtime.hot_reload.mode = crate::config::HotReloadMode::Full;

  assert_eq!(
    classify_full_reload_runtime_compatibility(&active, &replacement),
    FullReloadCompatibility::RestartRequired(FullReloadRestartReason::HotReloadManager)
  );
}

fn parse_worker_reload_config(worker_threads: usize) -> Config {
  toml::from_str(&format!(
    r#"
[runtime]
worker_threads = {worker_threads}

[runtime.accept]
workers = 1
reuse_port = false
backlog = 1024
accept_error_backoff_ms = 50

[listeners]
https_bind = "127.0.0.1:8443"
http1 = true
http2 = true
http3 = false

[tls]
cert_chain = "fullchain.pem"
private_key = "privkey.pem"
"#
  ))
  .expect("test config should parse")
}

fn test_artifact_root() -> PathBuf {
  let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/oxibelt-reload-test-fixtures");
  fs::create_dir_all(&root).expect("failed to create test artifact root");
  root
    .canonicalize()
    .expect("failed to resolve test artifact root")
}

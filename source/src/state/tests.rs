use std::collections::HashMap;
use std::time::Duration;

use super::*;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

fn parse_config(raw: &str) -> Config {
  let config: Config = toml::from_str(raw).expect("config should parse");
  config.validate().expect("config should validate");
  config
}

fn metrics_body(snapshot: &AppSnapshot) -> String {
  snapshot.metrics.prometheus(
    &snapshot.config.metrics,
    crate::cache::CacheStats::default(),
    crate::tls::TlsServerSessionStorageStats::default(),
  )
}

async fn redis_memory_info_fixture(
  info: &str,
) -> (String, tokio::task::JoinHandle<anyhow::Result<()>>) {
  use tokio::io::{AsyncReadExt, AsyncWriteExt};

  let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
    .await
    .expect("Redis fixture should bind");
  let address = listener
    .local_addr()
    .expect("Redis fixture should expose its address");
  let info = info.as_bytes().to_vec();
  let server = tokio::spawn(async move {
    let (mut stream, _) = listener.accept().await?;
    let expected = b"*2\r\n$4\r\nINFO\r\n$6\r\nmemory\r\n";
    let mut command = vec![0; expected.len()];
    stream.read_exact(&mut command).await?;
    anyhow::ensure!(
      command == expected,
      "unexpected Redis fixture command: {command:?}"
    );
    stream
      .write_all(format!("${}\r\n", info.len()).as_bytes())
      .await?;
    stream.write_all(&info).await?;
    stream.write_all(b"\r\n").await?;
    Ok(())
  });
  (format!("redis://{address}/"), server)
}

#[test]
fn effective_direct_h1_io_falls_back_when_active_runtime_is_tokio_hyper() {
  let temp_dir = common::TempDir::new("effective-direct-h1-fallback");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "effective-direct-h1-fallback");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "worker_threads = \"auto\"",
    "worker_threads = 2\nmain_runtime = \"auto\"\ndirect_h1_io = \"compio\"",
  );
  let config = parse_config(&raw);
  let backend = crate::runtime::backend::runtime_backend_snapshot_for(
    crate::runtime::main_runtime::ActiveMainRuntime::TokioHyper,
    None,
  );

  assert_eq!(config.runtime.direct_h1_io, RuntimeDirectH1IoMode::Compio);
  assert_eq!(
    effective_direct_h1_io_for_backend(&config, backend),
    RuntimeDirectH1IoMode::TokioHyper
  );
}

#[test]
fn effective_direct_h1_io_preserves_compio_when_active_runtime_is_compio() {
  let temp_dir = common::TempDir::new("effective-direct-h1-compio");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "effective-direct-h1-compio");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "worker_threads = \"auto\"",
    "worker_threads = 2\nmain_runtime = \"compio\"\ndirect_h1_io = \"compio\"",
  );
  let config = parse_config(&raw);
  let backend = crate::runtime::backend::runtime_backend_snapshot_for(
    crate::runtime::main_runtime::ActiveMainRuntime::Compio,
    Some(crate::runtime::backend::CompioDriverSelection::IoUring),
  );

  assert_eq!(
    effective_direct_h1_io_for_backend(&config, backend),
    RuntimeDirectH1IoMode::Compio
  );
}

#[tokio::test]
async fn snapshot_for_explicit_tokio_runtime_keeps_raw_config_but_disables_compio_direct_h1() {
  let temp_dir = common::TempDir::new("snapshot-effective-direct-h1");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "snapshot-effective-direct-h1");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "worker_threads = \"auto\"",
    "worker_threads = 2\nmain_runtime = \"tokio_hyper\"\ndirect_h1_io = \"compio\"",
  );

  let snapshot = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");

  assert_eq!(
    snapshot.config.runtime.direct_h1_io,
    RuntimeDirectH1IoMode::Compio
  );
  assert_eq!(
    snapshot.effective_direct_h1_io,
    RuntimeDirectH1IoMode::TokioHyper
  );
}

#[tokio::test]
async fn direct_h1_plan_generation_changes_only_for_transport_relevant_state() {
  let temp_dir = common::TempDir::new("direct-h1-plan-generation");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "direct-h1-plan-generation");
  let snapshot = AppSnapshot::new(parse_config(&common::minimal_config_toml(
    &cert_path, &key_path,
  )))
  .await
  .expect("snapshot should initialize");

  let unchanged = generation::next_direct_h1_plan_generation(
    &snapshot.config,
    snapshot.effective_direct_h1_io,
    snapshot.compio_direct_h1_budget,
    Some(&snapshot),
  );
  assert_eq!(unchanged, snapshot.direct_h1_plan_generation);

  let mut unrelated = snapshot.config.clone();
  unrelated.compression.enabled = !unrelated.compression.enabled;
  let unrelated_generation = generation::next_direct_h1_plan_generation(
    &unrelated,
    snapshot.effective_direct_h1_io,
    snapshot.compio_direct_h1_budget,
    Some(&snapshot),
  );
  assert_eq!(unrelated_generation, snapshot.direct_h1_plan_generation);

  let mut changed_upstream = snapshot.config.clone();
  changed_upstream.upstreams[0].idle_timeout_ms = changed_upstream.upstreams[0]
    .idle_timeout_ms
    .saturating_add(1);
  let changed_generation = generation::next_direct_h1_plan_generation(
    &changed_upstream,
    snapshot.effective_direct_h1_io,
    snapshot.compio_direct_h1_budget,
    Some(&snapshot),
  );
  assert_eq!(
    changed_generation,
    snapshot.direct_h1_plan_generation.saturating_add(1)
  );
}

#[tokio::test]
async fn replace_signals_old_data_plane_generation_and_installs_fresh_one() {
  let temp_dir = common::TempDir::new("app-generation-drain");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "app-generation-drain");
  let initial = common::minimal_config_toml(&cert_path, &key_path);
  let reloaded = initial.replace(
    "[compression]\nenabled = true",
    "[compression]\nenabled = false",
  );
  let handle = AppHandle::new(
    AppSnapshot::new(parse_config(&initial))
      .await
      .expect("initial snapshot should initialize"),
  );
  let old_connection = handle.connection_snapshot();
  assert!(old_connection.snapshot.config.compression.enabled);
  assert!(!*old_connection.data_plane_drain.borrow());

  handle.replace(
    AppSnapshot::new(parse_config(&reloaded))
      .await
      .expect("replacement snapshot should initialize"),
  );

  assert!(*old_connection.data_plane_drain.borrow());
  let new_connection = handle.connection_snapshot();
  assert!(!new_connection.snapshot.config.compression.enabled);
  assert!(!*new_connection.data_plane_drain.borrow());
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rollback_restages_retired_compio_fleet_with_bounded_overlap() {
  let temp_dir = common::TempDir::new("compio-rollback-restage");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "compio-rollback-restage");
  let mut initial = AppSnapshot::new(parse_config(&common::minimal_config_toml(
    &cert_path, &key_path,
  )))
  .await
  .expect("initial snapshot should initialize");
  initial.effective_direct_h1_io = RuntimeDirectH1IoMode::Compio;
  initial.compio_direct_h1_budget = Some(crate::circuit_breakers::CompioDirectH1Budget {
    worker_count: 1,
    queue_capacity_per_worker: 2,
    max_waiters: 1,
    queue_wait_timeout: Duration::from_millis(25),
    max_connections_global: 2,
    max_connections_per_origin: 2,
  });
  initial.direct_h1_plan_generation = 7;
  initial
    .restage_compio_direct_h1_service_for_publication()
    .expect("initial Compio fleet should stage");

  let overlap_budget = initial.compio_direct_h1_overlap_budget.clone();
  let handle = AppHandle::new(initial);
  let original = handle.snapshot();
  let rollback = original.as_ref().clone();
  let original_service = original
    .compio_direct_h1_service
    .clone()
    .expect("initial Compio fleet should be active");
  assert_eq!(overlap_budget.fleets(), 1);

  let mut replacement = rollback.clone();
  replacement.direct_h1_plan_generation = 8;
  replacement
    .restage_compio_direct_h1_service_for_publication()
    .expect("one replacement Compio fleet should stage");
  let replacement_service = replacement
    .compio_direct_h1_service
    .clone()
    .expect("replacement Compio fleet should be staged");
  assert!(!Arc::ptr_eq(&original_service, &replacement_service));
  assert_eq!(overlap_budget.fleets(), 2);

  let mut excess = rollback.clone();
  excess.direct_h1_plan_generation = 9;
  let error = excess
    .restage_compio_direct_h1_service_for_publication()
    .expect_err("a third overlapping Compio fleet must be rejected");
  assert!(error.to_string().contains("overlap budget exhausted"));
  assert_eq!(overlap_budget.fleets(), 2);

  assert!(handle.replace_if_current(&original, replacement));
  tokio::time::timeout(Duration::from_secs(2), async {
    while overlap_budget.fleets() != 1 {
      tokio::task::yield_now().await;
    }
  })
  .await
  .expect("retired initial Compio fleet should release its reservation");

  let current = handle.snapshot();
  assert!(handle.replace_if_current(&current, rollback));
  let restored = handle.snapshot();
  let restored_service = restored
    .compio_direct_h1_service
    .clone()
    .expect("rollback should publish a fresh Compio fleet");
  assert!(!Arc::ptr_eq(&restored_service, &original_service));
  assert!(!Arc::ptr_eq(&restored_service, &replacement_service));
  assert!(restored_service.is_healthy());

  tokio::time::timeout(Duration::from_secs(2), async {
    while overlap_budget.fleets() != 1 {
      tokio::task::yield_now().await;
    }
  })
  .await
  .expect("retired replacement Compio fleet should release its reservation");
  assert!(restored.runtime_health.is_ready());

  let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
  handle.shutdown_compio_direct_h1(deadline).await;
  assert_eq!(overlap_budget.fleets(), 0);
}

#[cfg(feature = "admin-runtime")]
#[tokio::test]
async fn required_admin_audit_anchor_failure_fails_readiness_after_snapshot_reload() {
  let temp_dir = common::TempDir::new("admin-audit-anchor-health-reload");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-audit-anchor-health-reload");
  let config = parse_config(&common::minimal_config_toml(&cert_path, &key_path));
  let mut initial = AppSnapshot::new(config)
    .await
    .expect("initial snapshot should initialize");
  let anchor = crate::admin_audit::anchor::AuditAnchorRuntime::test_health_only(
    initial.runtime_health.clone(),
    true,
  );
  initial.admin_audit = crate::admin_audit::AdminAuditRuntime::test_with_anchor(anchor.clone());
  let handle = AppHandle::new(initial);
  assert!(handle.snapshot().runtime_health.is_ready());

  let current = handle.snapshot();
  let replacement = AppSnapshot::new_with_previous(current.config.clone(), Some(current.as_ref()))
    .await
    .expect("replacement snapshot should initialize");
  handle.replace(replacement);
  assert!(handle.snapshot().runtime_health.is_ready());

  anchor.test_fail();
  let active = handle.snapshot();
  assert_eq!(active.admin_audit.anchor_status().state, "failed");
  assert!(!active.runtime_health.is_ready());
  let health = active.runtime_health.snapshot();
  assert_eq!(health.failed_subsystems, vec!["admin_audit"]);
  assert_eq!(health.failed_tasks, vec!["admin_audit_anchor"]);

  anchor.test_healthy();
  assert!(active.runtime_health.is_ready());
}

#[cfg(feature = "admin-runtime")]
#[tokio::test]
async fn best_effort_admin_audit_anchor_stays_ready_after_snapshot_reload() {
  let temp_dir = common::TempDir::new("best-effort-admin-audit-anchor-health-reload");
  let (cert_path, key_path) = common::create_self_signed_cert(
    temp_dir.path(),
    "best-effort-admin-audit-anchor-health-reload",
  );
  let config = parse_config(&common::minimal_config_toml(&cert_path, &key_path));
  let mut initial = AppSnapshot::new(config)
    .await
    .expect("initial snapshot should initialize");
  let anchor = crate::admin_audit::anchor::AuditAnchorRuntime::test_health_only(
    initial.runtime_health.clone(),
    false,
  );
  initial.admin_audit = crate::admin_audit::AdminAuditRuntime::test_with_anchor(anchor.clone());
  let handle = AppHandle::new(initial);

  let current = handle.snapshot();
  let replacement = AppSnapshot::new_with_previous(current.config.clone(), Some(current.as_ref()))
    .await
    .expect("replacement snapshot should initialize");
  handle.replace(replacement);
  anchor.test_fail();

  let active = handle.snapshot();
  assert_eq!(active.admin_audit.anchor_status().state, "degraded");
  assert!(active.runtime_health.is_ready());
  let health = active.runtime_health.snapshot();
  assert_eq!(health.degraded_subsystems, vec!["admin_audit"]);
  assert_eq!(health.degraded_tasks, vec!["admin_audit_anchor"]);

  anchor.test_healthy();
  assert!(active.runtime_health.is_ready());
}

#[cfg(feature = "admin-runtime")]
#[tokio::test]
async fn snapshot_cas_replays_new_anchor_failure_and_retires_previous_anchor() {
  let temp_dir = common::TempDir::new("admin-audit-anchor-health-cas");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-audit-anchor-health-cas");
  let config = parse_config(&common::minimal_config_toml(&cert_path, &key_path));
  let mut initial = AppSnapshot::new(config)
    .await
    .expect("initial snapshot should initialize");
  let previous_anchor = crate::admin_audit::anchor::AuditAnchorRuntime::test_health_only(
    initial.runtime_health.clone(),
    true,
  );
  initial.admin_audit =
    crate::admin_audit::AdminAuditRuntime::test_with_anchor(previous_anchor.clone());
  let handle = AppHandle::new(initial);
  let expected = handle.snapshot();

  let mut replacement =
    AppSnapshot::new_with_previous(expected.config.clone(), Some(expected.as_ref()))
      .await
      .expect("replacement snapshot should initialize");
  let active_anchor = crate::admin_audit::anchor::AuditAnchorRuntime::test_health_only(
    replacement.runtime_health.clone(),
    true,
  );
  replacement.admin_audit =
    crate::admin_audit::AdminAuditRuntime::test_with_anchor(active_anchor.clone());
  active_anchor.test_fail();
  assert!(expected.runtime_health.is_ready());
  assert!(handle.replace_if_current(&expected, replacement));

  let active = handle.snapshot();
  assert_eq!(active.admin_audit.anchor_status().state, "failed");
  assert!(!active.runtime_health.is_ready());
  previous_anchor.test_healthy();
  assert!(!active.runtime_health.is_ready());

  let stale_candidate = expected.as_ref().clone();
  assert!(!handle.replace_if_current(&expected, stale_candidate));
  active_anchor.test_healthy();
  assert!(active.runtime_health.is_ready());
}

#[tokio::test]
async fn full_reload_rebuilds_telemetry_runtime_from_new_config() {
  let temp_dir = common::TempDir::new("telemetry-full-reload");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "telemetry-full-reload");
  let base_raw = common::minimal_config_toml(&cert_path, &key_path);
  let initial_raw = base_raw.clone()
    + r#"

[telemetry.tracing]
enabled = true
endpoint = "http://127.0.0.1:4318/v1/traces"
service_name = "oxibelt-test"
sample_ratio = 1.0
export_timeout_ms = 1
propagate_trace_context = true
"#;
  let disabled_raw = base_raw
    + r#"

[telemetry.tracing]
enabled = false
endpoint = "http://127.0.0.1:4319/v1/traces"
service_name = "oxibelt-test-disabled"
sample_ratio = 0.0
export_timeout_ms = 1
propagate_trace_context = false
"#;

  let initial = AppSnapshot::new(parse_config(&initial_raw))
    .await
    .expect("initial telemetry snapshot should initialize");
  let initial_context = initial
    .telemetry
    .context_from_headers(&http::HeaderMap::new());
  let mut initial_headers = http::HeaderMap::new();
  initial
    .telemetry
    .inject_trace_context(&mut initial_headers, initial_context);
  assert!(initial.telemetry.enabled());
  assert!(initial_headers.contains_key("traceparent"));

  let reloaded = AppSnapshot::new_with_previous(parse_config(&disabled_raw), Some(&initial))
    .await
    .expect("reloaded telemetry snapshot should initialize");
  let mut reloaded_headers = http::HeaderMap::new();
  reloaded
    .telemetry
    .inject_trace_context(&mut reloaded_headers, initial_context);

  assert!(!reloaded.config.telemetry.tracing.enabled);
  assert!(!reloaded.telemetry.enabled());
  assert!(
    reloaded
      .telemetry
      .context_from_headers(&http::HeaderMap::new())
      .is_none()
  );
  assert!(!reloaded_headers.contains_key("traceparent"));
  assert!(initial.telemetry.enabled());
}

#[tokio::test]
async fn shared_state_reload_preserves_pool_warning_limiter() {
  let temp_dir = common::TempDir::new("shared-pool-warning-reload");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "shared-pool-warning-reload");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    + r#"

[shared_state]
enabled = true
namespace = "warning-reload-test"
operation_timeout_ms = 50
upstream_health_backend = "pool-warning-test"

[[shared_state.backends]]
name = "pool-warning-test"
kind = "redis"
connection_url = "redis://127.0.0.1:0/"
max_connections = 4
connect_timeout_ms = 50
"#;

  let config = parse_config(&raw);
  let metrics = Metrics::new();
  let initial = SharedState::new(&config, metrics.clone())
    .await
    .expect("initial shared state should initialize")
    .expect("shared state should be enabled");
  let pool_identity = initial
    .test_redis_pool_identity("pool-warning-test")
    .expect("initial Redis pool should exist");
  assert!(initial.should_log_pool_warning());

  let reloaded = SharedState::new_with_previous(&config, metrics, Some(initial.as_ref()))
    .await
    .expect("reloaded shared state should initialize")
    .expect("reloaded shared state should stay enabled");
  assert_eq!(
    reloaded.test_redis_pool_identity("pool-warning-test"),
    Some(pool_identity),
    "unchanged Redis backends must retain their persistent pool over reload"
  );
  assert!(!reloaded.should_log_pool_warning());
}

#[tokio::test]
async fn shared_state_udp_redis_rejects_evicting_policy_during_startup() {
  let (url, server) =
    redis_memory_info_fixture("# Memory\r\nmaxmemory:33554432\r\nmaxmemory_policy:allkeys-lru\r\n")
      .await;
  let temp_dir = common::TempDir::new("shared-state-udp-redis-policy-startup");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "shared-state-udp-redis-policy-startup");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    + &format!(
      r#"

[shared_state]
enabled = true
namespace = "udp-policy-startup"
operation_timeout_ms = 250
udp_flows_backend = "udp-policy"

[[shared_state.backends]]
name = "udp-policy"
kind = "redis"
connection_url = "{url}"
max_connections = 2
connect_timeout_ms = 100
"#
    );

  let error = SharedState::new(&parse_config(&raw), Metrics::new())
    .await
    .expect_err("an evicting Redis policy must reject UDP-flow activation");
  let message = format!("{error:#}");
  assert!(
    message.contains("must use maxmemory 0 or maxmemory_policy noeviction"),
    "unexpected activation error: {message}"
  );
  tokio::time::timeout(std::time::Duration::from_secs(1), server)
    .await
    .expect("Redis fixture should complete")
    .expect("Redis fixture task should not panic")
    .expect("Redis fixture should serve INFO memory");
}

#[tokio::test]
async fn shared_state_udp_redis_rechecks_evicting_policy_on_reused_pool_reload() {
  let (url, server) = redis_memory_info_fixture(
    "# Memory\r\nmaxmemory:33554432\r\nmaxmemory_policy:volatile-lru\r\n",
  )
  .await;
  let metrics = Metrics::new();
  let previous = SharedState::test_redis("udp-policy-reload", &url, metrics.clone());
  let temp_dir = common::TempDir::new("shared-state-udp-redis-policy-reload");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "shared-state-udp-redis-policy-reload");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    + &format!(
      r#"

[shared_state]
enabled = true
namespace = "udp-policy-reload"
operation_timeout_ms = 250
udp_flows_backend = "pool-warning-test"

[[shared_state.backends]]
name = "pool-warning-test"
kind = "redis"
connection_url = "{url}"
max_connections = 64
connect_timeout_ms = 100
"#
    );

  let error = SharedState::new_with_previous(&parse_config(&raw), metrics, Some(previous.as_ref()))
    .await
    .expect_err("reload must recheck an unchanged UDP-flow Redis pool");
  let message = format!("{error:#}");
  assert!(
    message.contains("must use maxmemory 0 or maxmemory_policy noeviction"),
    "unexpected reload error: {message}"
  );
  tokio::time::timeout(std::time::Duration::from_secs(1), server)
    .await
    .expect("Redis fixture should complete")
    .expect("Redis fixture task should not panic")
    .expect("Redis fixture should serve INFO memory");
}

#[tokio::test]
async fn shared_state_required_redis_idle_connections_fail_activation_when_unavailable() {
  let temp_dir = common::TempDir::new("shared-state-required-redis-idle");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "shared-state-required-redis-idle");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    + r#"

[shared_state]
enabled = true
upstream_health_backend = "required-idle-test"
operation_timeout_ms = 50

[[shared_state.backends]]
name = "required-idle-test"
kind = "redis"
connection_url = "redis://127.0.0.1:0/"
connect_timeout_ms = 10

[shared_state.backends.redis_pool]
min_idle_connections = 1
pool_wait_timeout_ms = 10
command_timeout_ms = 10
idle_timeout_ms = 100
health_check_interval_ms = 10
reconnect_min_backoff_ms = 1
reconnect_max_backoff_ms = 1
circuit_breaker_failure_threshold = 1
circuit_breaker_open_timeout_ms = 1
"#;

  let error = SharedState::new(&parse_config(&raw), Metrics::new())
    .await
    .expect_err("required Redis idle connections must fail activation when unavailable");
  assert!(
    error
      .to_string()
      .contains("shared state Redis backend required-idle-test")
  );
}

#[test]
fn upstream_client_pools_returns_precomputed_index_by_name() {
  let mut by_upstream = HashMap::new();
  by_upstream.insert("primary".to_string(), 3);
  let pools = UpstreamClientPools {
    by_upstream,
    pools: Vec::new(),
  };

  assert_eq!(pools.upstream_index("primary"), Some(3));
  assert_eq!(pools.upstream_index("missing"), None);
}

#[tokio::test]
async fn hot_path_metrics_helpers_skip_disabled_basic_metrics() {
  let temp_dir = common::TempDir::new("hot-path-metrics-disabled");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "hot-path-metrics-disabled");
  let snapshot = AppSnapshot::new(parse_config(&common::minimal_config_toml(
    &cert_path, &key_path,
  )))
  .await
  .expect("snapshot should initialize");

  snapshot.record_hot_path_request();
  snapshot.record_hot_path_response(http::StatusCode::BAD_GATEWAY);

  let body = metrics_body(&snapshot);
  assert!(body.contains("oxibelt_requests_total 0\n"));
  assert!(body.contains("oxibelt_responses_total 0\n"));
  assert!(body.contains("oxibelt_upstream_errors_total 0\n"));
}

#[tokio::test]
async fn hot_path_metrics_helpers_record_when_basic_metrics_are_enabled() {
  let temp_dir = common::TempDir::new("hot-path-metrics-enabled");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "hot-path-metrics-enabled");
  let mut config = parse_config(&common::minimal_config_toml(&cert_path, &key_path));
  config.metrics.enabled = true;
  let snapshot = AppSnapshot::new(config)
    .await
    .expect("snapshot should initialize");

  snapshot.record_hot_path_request();
  snapshot.record_hot_path_response(http::StatusCode::BAD_GATEWAY);

  let body = metrics_body(&snapshot);
  assert!(body.contains("oxibelt_requests_total 1\n"));
  assert!(body.contains("oxibelt_responses_total 1\n"));
  assert!(body.contains("oxibelt_upstream_errors_total 1\n"));
}

use std::collections::HashMap;

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
  let initial = SharedState::new(&config, Metrics::new())
    .await
    .expect("initial shared state should initialize")
    .expect("shared state should be enabled");
  assert!(initial.should_log_pool_warning());

  let reloaded = SharedState::new_with_previous(&config, Metrics::new(), Some(initial.as_ref()))
    .await
    .expect("reloaded shared state should initialize")
    .expect("reloaded shared state should stay enabled");
  assert!(!reloaded.should_log_pool_warning());
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

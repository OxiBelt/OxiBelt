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

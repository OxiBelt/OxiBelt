use super::*;

#[test]
fn normalizes_concrete_array_indexes() {
  assert_eq!(
    normalize_field_path("routes[12].tls.min_version"),
    "routes[].tls.min_version"
  );
}

#[test]
fn rejects_unknown_schema_epoch() {
  assert!(native_config_schema(2).is_err());
}

#[test]
fn keeps_native_epoch_and_advances_report_contract() {
  assert_eq!(NATIVE_CONFIG_SCHEMA_EPOCH, 1);
  assert_eq!(NATIVE_CONFIG_REPORT_SCHEMA_VERSION, 3);
}

#[test]
fn assigns_runtime_topology_activation_by_owner() {
  for path in ["runtime.main_runtime", "runtime.topology_policy"] {
    assert_eq!(
      native_config_field_metadata(path).config_activation,
      NativeConfigActivation::Conditional,
      "{path}"
    );
  }
  for path in [
    "runtime.worker_threads",
    "runtime.workers.tokio",
    "runtime.worker_multipliers.runtime",
    "runtime.worker_multipliers.tokio",
  ] {
    assert_eq!(
      native_config_field_metadata(path).config_activation,
      NativeConfigActivation::RestartRequired,
      "{path}"
    );
  }
  for path in [
    "runtime.workers.compio_direct_h1",
    "runtime.worker_multipliers.compio_direct_h1",
  ] {
    assert_eq!(
      native_config_field_metadata(path).config_activation,
      NativeConfigActivation::FullReload,
      "{path}"
    );
  }
  for path in ["runtime.workers", "runtime.worker_multipliers"] {
    assert_eq!(
      native_config_field_metadata(path).config_activation,
      NativeConfigActivation::Conditional,
      "{path}"
    );
  }
}

#[test]
fn assigns_quic_upstream_resolution_full_reload_activation() {
  for path in [
    "quic.upstream.resolution",
    "quic.upstream.resolution.address_family_stagger_ms",
    "quic.upstream.resolution.cooldown_base_ms",
    "quic.upstream.resolution.cooldown_max_ms",
    "quic.upstream.resolution.max_connect_attempts",
    "quic.upstream.resolution.max_endpoint_count",
    "quic.upstream.resolution.max_ttl_ms",
    "quic.upstream.resolution.min_ttl_ms",
    "quic.upstream.resolution.negative_ttl_ms",
  ] {
    let metadata = native_config_field_metadata(path);
    assert_eq!(metadata.introduced_epoch, 1, "{path}");
    assert_eq!(
      metadata.secret_class,
      NativeConfigSecretClass::None,
      "{path}"
    );
    assert_eq!(
      metadata.config_activation,
      NativeConfigActivation::FullReload,
      "{path}"
    );
    assert_eq!(
      metadata.reference_activation,
      NativeConfigActivation::None,
      "{path}"
    );
  }
}

#[test]
fn upstream_client_identity_private_keys_are_redacted_file_references() {
  for path in [
    "upstreams[0].tls.client_identity.private_key",
    "upstream_pools[0].servers[0].tls.client_identity.private_key",
    "upstream_pools[0].discovery[0].tls.client_identity.private_key",
  ] {
    let metadata = native_config_field_metadata(path);
    assert_eq!(
      metadata.secret_class,
      NativeConfigSecretClass::FileReference,
      "{path} must be redacted as a file reference"
    );
    assert_eq!(
      metadata.config_activation,
      NativeConfigActivation::FullReload,
      "{path}"
    );
    assert_eq!(
      metadata.reference_activation,
      NativeConfigActivation::FullReload,
      "{path}"
    );
  }
}

#[cfg(feature = "config-tooling")]
#[test]
fn upstream_client_identity_paths_are_cert_relative() {
  for path in [
    "upstreams.tls.client_identity.cert_chain",
    "upstreams.tls.client_identity.private_key",
    "upstream_pools.servers.tls.client_identity.cert_chain",
    "upstream_pools.servers.tls.client_identity.private_key",
    "upstream_pools.discovery.tls.client_identity.cert_chain",
    "upstream_pools.discovery.tls.client_identity.private_key",
  ] {
    assert_eq!(path_kind(path), Some("cert_relative"), "{path}");
  }
}

#[cfg(feature = "config-tooling")]
#[test]
fn declares_canonical_and_compatibility_runtime_values() {
  assert_eq!(
    enum_values("runtime.main_runtime"),
    Some(vec!["hybrid_compio", "tokio_hyper", "auto", "compio"])
  );
  assert_eq!(
    enum_values("runtime.topology_policy"),
    Some(vec!["allow_fallback", "require_exact"])
  );
  assert_eq!(
    default_value("runtime.main_runtime"),
    Some(json!("hybrid_compio"))
  );
}

#[cfg(feature = "config-tooling")]
#[test]
fn declares_quic_upstream_resolution_schema_bounds_and_defaults() {
  let expected = [
    (
      "quic.upstream.resolution.address_family_stagger_ms",
      10,
      5_000,
      json!(250),
    ),
    (
      "quic.upstream.resolution.cooldown_base_ms",
      1,
      300_000,
      json!(1_000),
    ),
    (
      "quic.upstream.resolution.cooldown_max_ms",
      1,
      300_000,
      json!(30_000),
    ),
    (
      "quic.upstream.resolution.max_connect_attempts",
      1,
      16,
      json!(4),
    ),
    (
      "quic.upstream.resolution.max_endpoint_count",
      1,
      64,
      json!(16),
    ),
    (
      "quic.upstream.resolution.max_ttl_ms",
      1,
      3_600_000,
      json!(30_000),
    ),
    (
      "quic.upstream.resolution.min_ttl_ms",
      1,
      3_600_000,
      json!(1_000),
    ),
    (
      "quic.upstream.resolution.negative_ttl_ms",
      1,
      30_000,
      json!(1_000),
    ),
  ];

  for (path, minimum, maximum, default) in expected {
    assert_eq!(
      bounded_integer_range(path),
      Some((minimum, maximum)),
      "{path}"
    );
    assert_eq!(default_value(path), Some(default), "{path}");
  }
}

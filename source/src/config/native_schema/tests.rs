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
  assert_eq!(NATIVE_CONFIG_REPORT_SCHEMA_VERSION, 2);
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

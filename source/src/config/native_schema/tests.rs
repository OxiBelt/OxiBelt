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

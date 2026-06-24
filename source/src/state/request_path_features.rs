//! Request-path feature planning.
//! Path feature flags are derived from config and metrics detail settings once per snapshot.

use crate::config::{Config, MetricsDetail};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RequestPathFeaturePlan {
  pub(crate) cache: bool,
  pub(crate) compression: bool,
  pub(crate) detailed_metrics: bool,
  pub(crate) dynamic_policy: bool,
  pub(crate) hot_path_diagnostic_metrics: bool,
  pub(crate) hot_path_metrics: bool,
  pub(crate) person_proof_api: bool,
  pub(crate) rate_limits: bool,
  pub(crate) runtime_introspection: bool,
  pub(crate) security_response_headers: bool,
  pub(crate) stage_timing_metrics: bool,
  pub(crate) system_access_log: bool,
  pub(crate) telemetry: bool,
}

impl RequestPathFeaturePlan {
  pub(crate) fn new(
    config: &Config,
    cache_enabled: bool,
    dynamic_policy_enabled: bool,
    telemetry_enabled: bool,
    system_access_log_enabled: bool,
    person_proof_api: bool,
  ) -> Self {
    let detailed_metrics =
      config.metrics.enabled && config.metrics.detail == MetricsDetail::Detailed;

    Self {
      cache: cache_enabled,
      compression: config.compression.enabled,
      detailed_metrics,
      dynamic_policy: dynamic_policy_enabled,
      hot_path_diagnostic_metrics: detailed_metrics,
      hot_path_metrics: config.metrics.enabled || config.admin.enabled,
      person_proof_api,
      rate_limits: !config.rate_limits.is_empty(),
      runtime_introspection: config.admin.enabled,
      security_response_headers: config.security.headers.enabled(),
      stage_timing_metrics: detailed_metrics,
      system_access_log: system_access_log_enabled,
      telemetry: telemetry_enabled,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::state::AppSnapshot;

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

  #[test]
  fn request_path_feature_plan_is_empty_when_optional_features_are_off() {
    let temp_dir = common::TempDir::new("request-path-features-empty");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "request-path-features-empty");
    let config = parse_config(&common::minimal_config_toml(&cert_path, &key_path).replace(
      "[compression]\nenabled = true",
      "[compression]\nenabled = false",
    ));
    let plan = RequestPathFeaturePlan::new(&config, false, false, false, false, false);

    assert_eq!(plan, RequestPathFeaturePlan::default());
  }

  #[test]
  fn request_path_feature_plan_tracks_global_optional_features() {
    let temp_dir = common::TempDir::new("request-path-features-global");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "request-path-features-global");
    let raw = format!(
      "{}{}",
      common::minimal_config_toml(&cert_path, &key_path),
      r#"

[[rate_limits]]
name = "ip"
key = "client-ip"
rate = "1r/s"
burst = 1

[cache]
enabled = true
store = "memory"
default_ttl_seconds = 60
cache_methods = ["GET"]

[metrics]
enabled = true
detail = "detailed"
"#
    );
    let config = parse_config(&raw);
    let plan = RequestPathFeaturePlan::new(&config, true, true, true, true, true);

    assert!(plan.cache);
    assert!(plan.compression);
    assert!(plan.detailed_metrics);
    assert!(plan.dynamic_policy);
    assert!(plan.hot_path_diagnostic_metrics);
    assert!(plan.hot_path_metrics);
    assert!(plan.person_proof_api);
    assert!(plan.rate_limits);
    assert!(plan.stage_timing_metrics);
    assert!(plan.system_access_log);
    assert!(plan.telemetry);
  }

  #[test]
  fn request_path_feature_plan_tracks_security_response_headers() {
    let temp_dir = common::TempDir::new("request-path-features-security-headers");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "request-path-features-security-headers");
    let raw = format!(
      "{}{}",
      common::minimal_config_toml(&cert_path, &key_path).replace(
        "[compression]\nenabled = true",
        "[compression]\nenabled = false",
      ),
      r#"

[security.headers]
x_content_type_options = "nosniff"
"#
    );
    let config = parse_config(&raw);
    let plan = RequestPathFeaturePlan::new(&config, false, false, false, false, false);

    assert!(plan.security_response_headers);
  }

  #[test]
  fn request_path_feature_plan_tracks_admin_observability() {
    let temp_dir = common::TempDir::new("request-path-features-admin");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "request-path-features-admin");
    let mut config = parse_config(&common::minimal_config_toml(&cert_path, &key_path).replace(
      "[compression]\nenabled = true",
      "[compression]\nenabled = false",
    ));
    config.admin.enabled = true;
    let plan = RequestPathFeaturePlan::new(&config, false, false, false, false, false);

    assert!(plan.hot_path_metrics);
    assert!(plan.runtime_introspection);
    assert!(!plan.detailed_metrics);
    assert!(!plan.hot_path_diagnostic_metrics);
    assert!(!plan.stage_timing_metrics);
  }

  #[test]
  fn request_path_feature_plan_keeps_basic_metrics_diagnostics_off() {
    let temp_dir = common::TempDir::new("request-path-features-basic-metrics");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "request-path-features-basic-metrics");
    let mut config = parse_config(&common::minimal_config_toml(&cert_path, &key_path).replace(
      "[compression]\nenabled = true",
      "[compression]\nenabled = false",
    ));
    config.metrics.enabled = true;
    config.metrics.detail = MetricsDetail::Basic;
    let plan = RequestPathFeaturePlan::new(&config, false, false, false, false, false);

    assert!(plan.hot_path_metrics);
    assert!(!plan.hot_path_diagnostic_metrics);
    assert!(!plan.stage_timing_metrics);
  }

  #[tokio::test]
  async fn app_snapshot_marks_person_proof_api_when_policy_exists() {
    let temp_dir = common::TempDir::new("request-path-features-person-proof");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "request-path-features-person-proof");
    let raw = format!(
      "{}{}",
      common::minimal_config_toml(&cert_path, &key_path).replace(
        "[compression]\nenabled = true",
        "[compression]\nenabled = false",
      ),
      r#"

[waf]
enabled = true

[[waf.rules]]
name = "proof"
phase = "request"
priority = 10
when = "Request.Http.Path == '/protected'"

[[waf.rules.actions]]
type = "require_person_proof"
difficulty = 4
token_validity_seconds = 60
"#
    );
    let snapshot = AppSnapshot::new(parse_config(&raw))
      .await
      .expect("snapshot should initialize");

    assert!(snapshot.request_path_features.person_proof_api);
    assert!(
      snapshot
        .waf
        .has_person_proof_api_path("/.oxibelt/person-proof/session")
    );
  }
}

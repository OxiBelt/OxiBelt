use super::{AccessLogConfig, effective_access_log_config};

#[test]
fn effective_config_enables_system_for_new_or_legacy_setting() {
  for (system_enabled, legacy_enabled, expected_enabled) in [
    (false, false, false),
    (false, true, true),
    (true, false, true),
    (true, true, true),
  ] {
    let mut configured = AccessLogConfig::default();
    configured.system.enabled = system_enabled;
    configured.waf.enabled = false;
    configured.admin.enabled = true;
    configured.stdout.enabled = false;
    configured.otlp.service_name = "preserved-service-name".to_string();
    let original = configured.clone();

    let effective = effective_access_log_config(&configured, legacy_enabled);
    let mut expected = original.clone();
    expected.system.enabled = expected_enabled;

    assert_eq!(effective, expected);
    assert_eq!(configured, original);
  }
}

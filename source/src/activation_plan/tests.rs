use pretty_assertions::assert_eq;

use super::{
  ActivationPrerequisite, ActivationReasonCode, ChangeOperation, ConfigActivationChange,
  ConfigComparisonKey, ConfigComparisonProjection, ConfinementDifference,
  ConfinementDifferenceKind, MAX_ACTIVATION_CHANGES, MetadataProvenance, NativeActivation,
  PlanningBasis, ResolvedActivationOperation, RollbackKind, plan_config_projections,
};

fn parsed(value: &str) -> toml::Value {
  toml::from_str(value).expect("test TOML should parse")
}

#[test]
fn confinement_differences_are_subject_tagged_and_seccomp_has_no_fake_path() {
  let filesystem = ConfinementDifference::Filesystem {
    path_id: "path-0001".to_string(),
    source_config_path: Some("tls.cert_chain".to_string()),
    kind: ConfinementDifferenceKind::RightsExpanded,
  };
  let seccomp = ConfinementDifference::Seccomp {
    assertion_id: "profile_digest".to_string(),
    kind: ConfinementDifferenceKind::SeccompAssertionMismatch,
  };

  assert_eq!(
    serde_json::to_value(filesystem).expect("filesystem difference should serialize"),
    serde_json::json!({
      "subject": "filesystem",
      "path_id": "path-0001",
      "source_config_path": "tls.cert_chain",
      "kind": "rights_expanded"
    })
  );
  assert_eq!(
    serde_json::to_value(seccomp).expect("seccomp difference should serialize"),
    serde_json::json!({
      "subject": "seccomp",
      "assertion_id": "profile_digest",
      "kind": "seccomp_assertion_mismatch"
    })
  );
}

fn plan(current: &str, candidate: &str) -> super::ConfigActivationReport {
  let key = ConfigComparisonKey::for_test([7; 32]);
  let current = ConfigComparisonProjection::from_value(&parsed(current), &key);
  let candidate = ConfigComparisonProjection::from_value(&parsed(candidate), &key);
  plan_config_projections(&current, &candidate, PlanningBasis::OfflineConfig)
}

#[test]
fn recursive_diff_orders_tables_and_expands_arrays() {
  let report = plan(
    r#"
      z = 1
      [[routes]]
      name = "old"
      [routes.waf]
      enabled = false
    "#,
    r#"
      a = 2
      z = 3
      [[routes]]
      name = "new"
      [routes.waf]
      enabled = true
    "#,
  );

  let paths = report
    .changes
    .iter()
    .map(|change| change.path.as_str())
    .collect::<Vec<_>>();
  assert_eq!(
    paths,
    vec!["a", "routes[0].name", "routes[0].waf.enabled", "z"]
  );
  assert_eq!(
    report.changes[2].metadata_provenance,
    MetadataProvenance::Pattern
  );
  assert_eq!(
    report.changes[2].resolved_operation,
    ResolvedActivationOperation::OxiRuleReload
  );
}

#[test]
fn mixed_oxirule_and_tls_changes_promote_to_full_snapshot() {
  let changes = vec![
    synthetic_change(
      "waf.enabled",
      NativeActivation::OxiRuleReload,
      ResolvedActivationOperation::OxiRuleReload,
      ActivationReasonCode::OxiRuleChanged,
    ),
    synthetic_change(
      "tls.private_key",
      NativeActivation::DownstreamTlsReload,
      ResolvedActivationOperation::DownstreamTlsReload,
      ActivationReasonCode::DownstreamTlsMaterialChanged,
    ),
  ];
  let activation_plan = super::aggregate::aggregate(&changes);

  assert_eq!(
    activation_plan.selected_operation,
    ResolvedActivationOperation::FullSnapshotReload
  );
  assert!(
    activation_plan
      .reason_codes
      .contains(&ActivationReasonCode::FullSnapshotReload)
  );
}

fn synthetic_change(
  path: &str,
  native_activation: NativeActivation,
  resolved_operation: ResolvedActivationOperation,
  reason_code: ActivationReasonCode,
) -> ConfigActivationChange {
  ConfigActivationChange {
    path: path.to_string(),
    op: ChangeOperation::Change,
    secret: false,
    native_activation,
    metadata_provenance: MetadataProvenance::Explicit,
    resolved_operation,
    reason_code,
    conditional: false,
    prerequisite_missing: false,
    missing_prerequisites: Vec::new(),
    long_connections_affected: false,
    rollback: RollbackKind::Conditional,
  }
}

#[test]
fn conditional_metadata_requires_runtime_context() {
  let report = plan(
    "[runtime]\nmain_runtime = 'tokio_hyper'\n",
    "[runtime]\nmain_runtime = 'hybrid_compio'\n",
  );

  let change = &report.changes[0];
  assert!(change.conditional);
  assert_eq!(
    change.missing_prerequisites,
    vec![ActivationPrerequisite::RuntimeCapabilityContext]
  );
  assert!(!report.activation_plan.can_apply_in_process);
}

#[test]
fn secret_equality_is_visible_without_secret_values() {
  let unchanged = plan(
    "[admin]\nbearer_token_env = 'TOKEN_A'\n",
    "[admin]\nbearer_token_env = 'TOKEN_A'\n",
  );
  assert!(unchanged.changes.is_empty());

  let changed = plan(
    "[admin]\nbearer_token_env = 'TOKEN_A'\n",
    "[admin]\nbearer_token_env = 'TOKEN_B'\n",
  );
  assert_eq!(changed.changes.len(), 1);
  assert!(changed.changes[0].secret);

  let json = serde_json::to_string(&changed).expect("report should serialize");
  assert!(!json.contains("TOKEN_A"));
  assert!(!json.contains("TOKEN_B"));
  assert!(!json.contains("redacted"));
  assert!(!json.contains("sha256"));
}

#[test]
fn filesystem_manifest_expectations_are_secret_restart_changes() {
  let current_digest = format!("sha256:{}", "a".repeat(64));
  let candidate_digest = format!("sha256:{}", "b".repeat(64));
  let digest_change = plan(
    &format!("[runtime.hardening.filesystem_manifest]\nexpected_digest = '{current_digest}'\n"),
    &format!("[runtime.hardening.filesystem_manifest]\nexpected_digest = '{candidate_digest}'\n"),
  );
  assert_secret_restart_change(
    &digest_change,
    "runtime.hardening.filesystem_manifest.expected_digest",
    &[&current_digest, &candidate_digest],
  );

  let current_path = "/var/lib/oxibelt/tenant-alpha/uploads";
  let candidate_path = "/var/lib/oxibelt/tenant-beta/uploads";
  let writable_paths_change = plan(
    &format!(
      "[runtime.hardening.filesystem_manifest]\nexpected_writable_paths = ['{current_path}']\n"
    ),
    &format!(
      "[runtime.hardening.filesystem_manifest]\nexpected_writable_paths = ['{candidate_path}']\n"
    ),
  );
  assert_secret_restart_change(
    &writable_paths_change,
    "runtime.hardening.filesystem_manifest.expected_writable_paths",
    &[current_path, candidate_path],
  );
}

fn assert_secret_restart_change(
  report: &super::ConfigActivationReport,
  expected_path: &str,
  forbidden_values: &[&str],
) {
  assert_eq!(report.changes.len(), 1);
  let change = &report.changes[0];
  assert_eq!(change.path, expected_path);
  assert!(change.secret);
  assert_eq!(change.native_activation, NativeActivation::RestartRequired);
  assert_eq!(
    change.resolved_operation,
    ResolvedActivationOperation::ProcessRestart
  );
  assert_eq!(change.metadata_provenance, MetadataProvenance::Explicit);
  let json = serde_json::to_string(report).expect("report should serialize");
  for value in forbidden_values {
    assert!(!json.contains(value), "plan leaked {value}");
  }
}

#[test]
fn fallback_metadata_is_explicitly_conservative() {
  let report = plan("custom = 1\n", "custom = 2\n");
  assert_eq!(
    report.changes[0].metadata_provenance,
    MetadataProvenance::ConservativeDefault
  );
  assert_eq!(
    report.changes[0].resolved_operation,
    ResolvedActivationOperation::FullSnapshotReload
  );
}

#[test]
fn explicit_metadata_is_distinct_from_array_patterns() {
  let report = plan(
    "[tls]\nprivate_key = 'old.pem'\n[[routes]]\nname = 'old'\n",
    "[tls]\nprivate_key = 'new.pem'\n[[routes]]\nname = 'new'\n",
  );
  assert_eq!(report.changes[0].path, "routes[0].name");
  assert_eq!(
    report.changes[0].metadata_provenance,
    MetadataProvenance::ConservativeDefault
  );
  assert_eq!(report.changes[1].path, "tls.private_key");
  assert_eq!(
    report.changes[1].metadata_provenance,
    MetadataProvenance::Explicit
  );
}

#[test]
fn one_sided_table_diff_is_independent_of_input_key_order() {
  let first = plan("", "[new]\nz = 1\na = 2\n");
  let second = plan("", "[new]\na = 2\nz = 1\n");
  assert_eq!(first, second);
  assert_eq!(
    first
      .changes
      .iter()
      .map(|change| change.path.as_str())
      .collect::<Vec<_>>(),
    vec!["new.a", "new.z"]
  );
}

#[test]
fn output_is_deterministic_across_comparison_keys() {
  let current = parsed("[admin]\nbearer_token_env = 'TOKEN_A'\nvalue = 1\n");
  let candidate = parsed("[admin]\nbearer_token_env = 'TOKEN_B'\nvalue = 2\n");
  let left_key = ConfigComparisonKey::for_test([1; 32]);
  let right_key = ConfigComparisonKey::for_test([2; 32]);
  let first = plan_config_projections(
    &ConfigComparisonProjection::from_value(&current, &left_key),
    &ConfigComparisonProjection::from_value(&candidate, &left_key),
    PlanningBasis::OfflineConfig,
  );
  let second = plan_config_projections(
    &ConfigComparisonProjection::from_value(&current, &right_key),
    &ConfigComparisonProjection::from_value(&candidate, &right_key),
    PlanningBasis::OfflineConfig,
  );
  assert_eq!(first, second);
}

#[test]
fn different_config_roots_mark_identical_relative_secret_files_changed() {
  let current = parsed("[tls]\nprivate_key = 'private/key.pem'\n");
  let candidate = current.clone();
  let key = ConfigComparisonKey::for_test([3; 32]);
  let mut report = plan_config_projections(
    &ConfigComparisonProjection::from_value(&current, &key),
    &ConfigComparisonProjection::from_value(&candidate, &key),
    PlanningBasis::OfflineConfig,
  );
  super::file_adapter::add_relative_file_reference_root_changes(
    &mut report,
    &current,
    &candidate,
    std::path::Path::new("/config/current"),
    std::path::Path::new("/config/candidate"),
  );

  assert_eq!(report.changes.len(), 1);
  assert_eq!(report.changes[0].path, "tls.private_key");
  assert!(report.changes[0].secret);
  let json = serde_json::to_string(&report).expect("report should serialize");
  assert!(!json.contains("/config/current"));
  assert!(!json.contains("/config/candidate"));
  assert!(!json.contains("private/key.pem"));
}

#[test]
fn stable_wire_vocabulary_and_invalid_outcome_are_explicit() {
  assert_eq!(
    serde_json::to_value(ActivationReasonCode::RuntimeNotResizable)
      .expect("reason should serialize"),
    serde_json::json!("runtime_not_resizable")
  );
  assert_eq!(
    serde_json::to_value(ActivationReasonCode::ImmutableConfigRequiresRollout)
      .expect("reason should serialize"),
    serde_json::json!("immutable_config_requires_rollout")
  );
  assert_eq!(
    serde_json::to_value(ResolvedActivationOperation::AdminClusterRollout)
      .expect("operation should serialize"),
    serde_json::json!("admin_cluster_rollout")
  );

  let report = super::ConfigActivationReport::invalid_configuration(PlanningBasis::OfflineConfig);
  assert!(!report.is_success());
  assert_eq!(
    report.activation_plan.selected_operation,
    ResolvedActivationOperation::InvalidOrUnsupported
  );
  assert_eq!(
    report.activation_plan.reason_codes,
    vec![ActivationReasonCode::InvalidConfiguration]
  );
}

#[test]
fn excessive_changes_fail_closed_without_truncation() {
  let mut candidate = toml::map::Map::new();
  for index in 0..=MAX_ACTIVATION_CHANGES {
    candidate.insert(
      format!("field_{index:04}"),
      toml::Value::Integer(index as i64),
    );
  }
  let current = toml::Value::Table(toml::map::Map::new());
  let candidate = toml::Value::Table(candidate);
  let key = ConfigComparisonKey::for_test([9; 32]);
  let report = plan_config_projections(
    &ConfigComparisonProjection::from_value(&current, &key),
    &ConfigComparisonProjection::from_value(&candidate, &key),
    PlanningBasis::OfflineConfig,
  );

  assert!(!report.is_success());
  assert!(report.changes.is_empty());
  assert_eq!(
    report.activation_plan.selected_operation,
    ResolvedActivationOperation::InvalidOrUnsupported
  );
  assert_eq!(
    report.activation_plan.reason_codes,
    vec![ActivationReasonCode::ChangeLimitExceeded]
  );
}

use super::*;
use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::json;

fn summary(name: &str, version: &str, rules: usize) -> WafRulepackSummary {
  WafRulepackSummary {
    name: name.to_string(),
    version: version.to_string(),
    description: None,
    targets: Vec::new(),
    requires: Vec::new(),
    default_mode: "monitor".to_string(),
    rules,
    group_files: 0,
    exceptions: 0,
    loaded_files: Vec::<PathBuf>::new(),
    source_commit: None,
    source_url: None,
    source_sha256: None,
    source_openpgp_signature_url: None,
    source_openpgp_signer_fingerprint: None,
  }
}

#[test]
fn new_install_diff_counts_added_rules() {
  let mut warnings = Vec::new();
  let diff = diff_for_summary(&summary("vaultwarden", "0.1.0", 2), None, &mut warnings);

  assert_eq!(diff.added_rules, 2);
  assert_eq!(diff.changed_rules, Some(0));
  assert_eq!(diff.deleted_rules, 0);
  assert_eq!(diff.basis, "new_install");
  assert!(warnings.is_empty());
}

#[test]
fn active_summary_diff_marks_changed_rules_unknown() {
  let mut warnings = Vec::new();
  let active = ActiveRulepackSummary {
    version: Some("0.1.0".to_string()),
    rules: 3,
  };
  let diff = diff_for_summary(
    &summary("vaultwarden", "0.2.0", 5),
    Some(&active),
    &mut warnings,
  );

  assert_eq!(diff.added_rules, 2);
  assert_eq!(diff.changed_rules, None);
  assert_eq!(diff.deleted_rules, 0);
  assert_eq!(diff.basis, "active_summary");
  assert!(warnings.is_empty());
}

#[test]
fn static_risk_extracts_terminal_actions() {
  let actions = risk::terminal_actions_for_content(
    r#"when = "true"

[[actions]]
type = "rate_limit"
name = "login"
rate = "5r/m"

[[actions]]
type = "reject"
status = 403
"#,
  );

  assert_eq!(actions, vec!["rate_limit", "reject"]);
}

#[test]
fn complete_install_plan_keeps_paths_and_bindings() {
  let prepared = PreparedRulepackApply {
    name: "vaultwarden".to_string(),
    request_body: json!({ "apply": "oxirule", "operations": [] }),
    summary: summary("vaultwarden", "0.1.0", 1),
    source_label: "file vaultwarden.oxirule-rulepack.toml".to_string(),
    git_commit: None,
    selected_profile: Some("public-production".to_string()),
    effective_mode: RulepackModeArg::Enforcing,
    force_mode: false,
    bindings: BTreeMap::from([("app_route".to_string(), "mmsecretvault".to_string())]),
    values: BTreeMap::from([("admin_cidr".to_string(), "10.0.0.0/8".to_string())]),
    rendered_manifest: String::new(),
    rendered_rule_files: BTreeMap::new(),
    rendered_group_files: BTreeMap::new(),
    will_put: vec![
      "rulepacks/vaultwarden.oxirule-rulepack.toml".to_string(),
      "rulepacks/vaultwarden.install.toml".to_string(),
    ],
  };

  let plan = complete_install_plan(&prepared);

  assert!(plan.ready);
  assert_eq!(plan.will_reload, Some("oxirule"));
  assert_eq!(plan.mode, "enforcing");
  assert_eq!(plan.profile.as_deref(), Some("public-production"));
  assert_eq!(
    plan.bindings.get("app_route").map(String::as_str),
    Some("mmsecretvault")
  );
  assert_eq!(plan.values_count, 1);
  assert!(
    plan
      .will_put
      .iter()
      .any(|path| path == "rulepacks/vaultwarden.install.toml")
  );
}

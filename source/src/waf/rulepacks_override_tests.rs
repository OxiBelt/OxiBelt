use super::*;

#[test]
fn rulepack_overrides_apply_with_local_specificity_last() {
  let raw = r#"[rulepack]
schema_version = 2
name = "vaultwarden-hardening"
version = "0.1.0"

[[overrides]]
selector = { rulepack = "vaultwarden-hardening" }
mode = "monitor"
priority = 10

[[overrides]]
selector = { tags = ["surface:login"] }
mode = "enforcing"
priority = 20

[[rules]]
name = "login"
id = "oxibelt.vaultwarden.login_rate_limit"
tags = ["surface:login"]
phase = "request"
priority = 100
content = '''
when = "true"

[[actions]]
type = "rate_limit"
name = "login"
key = "client_ip_path"
rate = "5r/m"
burst = 5
status = 429
body = "Too Many Requests"
'''
"#;
  let rendered = render_rulepack_for_install(
    raw,
    "test rulepack",
    RulepackRenderOptions {
      local_overrides: vec![RulepackOverride {
        selector: RulepackOverrideSelector {
          rulepack: None,
          tags: Vec::new(),
          rule_id: Some("oxibelt.vaultwarden.login_rate_limit".to_string()),
          rule_name: None,
        },
        action: Some(RulepackActionSelector {
          action_type: "rate_limit".to_string(),
          name: Some("login".to_string()),
        }),
        mode: Some(WafMode::Monitor),
        priority: Some(90),
        enabled: None,
        rate: Some("10r/m".to_string()),
        burst: Some(9),
        status: Some(403),
        body: Some("Local limit".to_string()),
      }],
      ..RulepackRenderOptions::default()
    },
  )
  .expect("render");

  assert!(rendered.contains("priority = 90"));
  assert!(rendered.contains("mode = \"monitor\""));
  assert!(rendered.contains("rate = \"10r/m\""));
  assert!(rendered.contains("burst = 9"));
  assert!(rendered.contains("status = 403"));
  assert!(rendered.contains("body = \"Local limit\""));
  assert!(!rendered.contains("[[overrides]]"));
  validate_rulepack_manifest(&rendered).expect("rendered overrides should validate");
}

#[test]
fn forced_mode_wins_over_manifest_rule_mode_override() {
  let raw = r#"[rulepack]
schema_version = 2
name = "demo"
version = "0.1.0"
default_mode = "monitor"

[[overrides]]
selector = { rule_name = "admin_guard" }
mode = "monitor"

[[rules]]
name = "admin_guard"
phase = "request"
priority = 100
content = "when = \"true\"\n"

[[rules]]
name = "other_guard"
phase = "request"
priority = 100
content = "when = \"true\"\n"
"#;
  let rendered = render_rulepack_for_install(
    raw,
    "test rulepack",
    RulepackRenderOptions {
      mode_override: Some(RulepackModeOverride {
        mode: WafMode::Enforcing,
        force: true,
      }),
      ..RulepackRenderOptions::default()
    },
  )
  .expect("render");

  assert_eq!(
    rule_mode(&rendered, "admin_guard").as_deref(),
    Some("enforcing")
  );
  assert_eq!(
    rule_mode(&rendered, "other_guard").as_deref(),
    Some("enforcing")
  );
}

#[test]
fn forced_mode_wins_over_local_rule_mode_override() {
  let raw = r#"[rulepack]
schema_version = 2
name = "demo"
version = "0.1.0"
default_mode = "monitor"

[[rules]]
name = "admin_guard"
id = "admin-guard"
phase = "request"
priority = 100
content = "when = \"true\"\n"
"#;
  let rendered = render_rulepack_for_install(
    raw,
    "test rulepack",
    RulepackRenderOptions {
      local_overrides: vec![RulepackOverride {
        selector: RulepackOverrideSelector {
          rulepack: None,
          tags: Vec::new(),
          rule_id: Some("admin-guard".to_string()),
          rule_name: None,
        },
        action: None,
        mode: Some(WafMode::Monitor),
        priority: Some(90),
        enabled: None,
        rate: None,
        burst: None,
        status: None,
        body: None,
      }],
      mode_override: Some(RulepackModeOverride {
        mode: WafMode::Enforcing,
        force: true,
      }),
      ..RulepackRenderOptions::default()
    },
  )
  .expect("render");

  assert_eq!(
    rule_mode(&rendered, "admin_guard").as_deref(),
    Some("enforcing")
  );
  assert_eq!(rule_priority(&rendered, "admin_guard"), Some(90));
}

#[test]
fn non_forced_mode_override_keeps_rule_specific_mode() {
  let raw = r#"[rulepack]
schema_version = 2
name = "demo"
version = "0.1.0"
default_mode = "monitor"

[[overrides]]
selector = { rule_name = "admin_guard" }
mode = "monitor"

[[rules]]
name = "admin_guard"
phase = "request"
priority = 100
content = "when = \"true\"\n"
"#;
  let rendered = render_rulepack_for_install(
    raw,
    "test rulepack",
    RulepackRenderOptions {
      mode_override: Some(RulepackModeOverride {
        mode: WafMode::Enforcing,
        force: false,
      }),
      ..RulepackRenderOptions::default()
    },
  )
  .expect("render");

  assert!(rendered.contains("default_mode = \"enforcing\""));
  assert_eq!(
    rule_mode(&rendered, "admin_guard").as_deref(),
    Some("monitor")
  );
}

#[test]
fn rulepack_override_can_disable_rule() {
  let raw = r#"[rulepack]
schema_version = 2
name = "demo"
version = "0.1.0"

[[overrides]]
selector = { rule_name = "disabled" }
enabled = false

[[rules]]
name = "kept"
phase = "request"
priority = 100
content = "when = \"true\"\n"

[[rules]]
name = "disabled"
phase = "request"
priority = 100
content = "when = \"true\"\n"
"#;
  let rendered =
    render_rulepack_for_install(raw, "test rulepack", RulepackRenderOptions::default())
      .expect("render");
  let value: toml::Value = toml::from_str(&rendered).expect("rendered TOML");
  let rules = value
    .get("rules")
    .and_then(toml::Value::as_array)
    .expect("rules");

  assert_eq!(rules.len(), 1);
  assert_eq!(
    rules[0].get("name").and_then(toml::Value::as_str),
    Some("kept")
  );
}

#[test]
fn rulepack_overrides_reject_unsafe_or_ambiguous_shapes() {
  let raw = r#"[rulepack]
schema_version = 2
name = "demo"
version = "0.1.0"

[[overrides]]
selector = { tags = ["surface:login"], rule_name = "login" }
mode = "monitor"

[[rules]]
name = "login"
phase = "request"
priority = 100
content = "when = \"true\"\n"
"#;
  let error = validate_rulepack_manifest(raw).expect_err("mixed selector kinds should be rejected");
  assert!(error.to_string().contains("exactly one selector kind"));

  let raw = r#"[rulepack]
schema_version = 2
name = "demo"
version = "0.1.0"

[[overrides]]
selector = { rule_name = "login" }
raw = "status = 200"

[[rules]]
name = "login"
phase = "request"
priority = 100
content = "when = \"true\"\n"
"#;
  let error = validate_rulepack_manifest(raw).expect_err("raw override should be rejected");
  assert!(error.to_string().contains("failed to decode"));
}

#[test]
fn rulepack_action_overrides_require_one_action_match() {
  let raw = r#"[rulepack]
schema_version = 2
name = "demo"
version = "0.1.0"

[[overrides]]
selector = { rule_name = "login" }
action = { type = "reject" }
status = 403

[[rules]]
name = "login"
phase = "request"
priority = 100
content = '''
when = "true"

[[actions]]
type = "reject"
status = 401

[[actions]]
type = "reject"
status = 402
'''
"#;
  let error = render_rulepack_for_install(raw, "test rulepack", RulepackRenderOptions::default())
    .expect_err("ambiguous action override should fail");

  assert!(error.to_string().contains("expected exactly one"));
}

fn rule_mode(rendered: &str, name: &str) -> Option<String> {
  rule_field(rendered, name, "mode").and_then(|value| value.as_str().map(str::to_string))
}

fn rule_priority(rendered: &str, name: &str) -> Option<i64> {
  rule_field(rendered, name, "priority").and_then(|value| value.as_integer())
}

fn rule_field(rendered: &str, name: &str, field: &str) -> Option<toml::Value> {
  let value: toml::Value = toml::from_str(rendered).expect("rendered TOML");
  let rules = value.get("rules").and_then(toml::Value::as_array)?;
  rules.iter().find_map(|rule| {
    let table = rule.as_table()?;
    if table.get("name").and_then(toml::Value::as_str) == Some(name) {
      table.get(field).cloned()
    } else {
      None
    }
  })
}

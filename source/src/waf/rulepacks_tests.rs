use super::*;

fn minimal_rulepack(body: &str) -> String {
  format!(
    r#"[rulepack]
schema_version = 1
name = "demo"
version = "0.1.0"

[[rules]]
name = "block-demo"
phase = "request"
priority = 100
content = '''
when = "{body}"

[[actions]]
type = "reject"
status = 403
'''
"#
  )
}

#[test]
fn renders_variables_and_defaults_to_monitor() {
  let raw = r#"[rulepack]
schema_version = 1
name = "demo"
version = "0.1.0"

[[variables]]
name = "path"
default = "/admin"

[[rules]]
name = "block-demo"
phase = "request"
priority = 100
content = '''
when = "Request.Http.Path.startsWith('{{path}}')"

[[actions]]
type = "reject"
status = 403
'''
"#;
  let parsed =
    ParsedRulepack::parse(raw, "test rulepack", RulepackRenderOptions::default()).expect("parse");
  assert!(parsed.rendered.contains("/admin"));
  assert_eq!(parsed.document.rulepack.default_mode, WafMode::Monitor);
}

#[test]
fn rejects_missing_required_variable() {
  let raw = r#"[rulepack]
schema_version = 1
name = "demo"
version = "0.1.0"

[[variables]]
name = "path"
required = true

[[rules]]
name = "block-demo"
phase = "request"
priority = 100
content = "when = \"true\"\n"
"#;
  let error = ParsedRulepack::parse(raw, "test rulepack", RulepackRenderOptions::default())
    .expect_err("missing variable should fail");
  assert!(error.to_string().contains("requires variable path"));
}

#[test]
fn rejects_invalid_reference_suffix() {
  let raw = r#"[rulepack]
schema_version = 1
name = "demo"
version = "0.1.0"

[[rules]]
name = "block-demo"
phase = "request"
priority = 100
path = "rules/bad.toml"
"#;
  let parsed =
    ParsedRulepack::parse(raw, "test rulepack", RulepackRenderOptions::default()).expect("parse");
  let error = parsed
    .validate_references(false)
    .expect_err("bad suffix should fail");
  assert!(error.to_string().contains(".oxirule.toml"));
}

#[test]
fn group_only_rulepack_is_valid() {
  let raw = r#"[rulepack]
schema_version = 1
name = "groups"
version = "0.1.0"

[[group_files]]
content = '''
[[rule_groups]]
name = "trusted-admin"
when = "true"
'''
"#;
  validate_rulepack_manifest(raw).expect("group-only rulepack should validate");
}

#[test]
fn force_mode_sets_rule_modes() {
  let raw = minimal_rulepack("true");
  let rendered = render_rulepack_for_install(
    &raw,
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
  assert!(rendered.contains("default_mode = \"enforcing\""));
  assert!(rendered.contains("mode = \"enforcing\""));
}

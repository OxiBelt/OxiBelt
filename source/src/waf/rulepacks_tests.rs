use super::*;

fn minimal_rulepack(body: &str) -> String {
  format!(
    r#"[rulepack]
schema_version = 2
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
schema_version = 2
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
schema_version = 2
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
schema_version = 2
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
schema_version = 2
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

#[test]
fn render_records_url_source_provenance() {
  let raw = minimal_rulepack("true");
  let rendered = render_rulepack_for_install(
    &raw,
    "test rulepack",
    RulepackRenderOptions {
      source_provenance: Some(RulepackSourceProvenance {
        source_url: "https://packs.example.test/demo.oxirule-rulepack.toml".to_string(),
        source_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
          .to_string(),
        source_openpgp_signature_url: Some(
          "https://packs.example.test/demo.oxirule-rulepack.toml.sig".to_string(),
        ),
        source_openpgp_signer_fingerprint: Some(
          "0123456789abcdef0123456789abcdef01234567".to_string(),
        ),
      }),
      ..RulepackRenderOptions::default()
    },
  )
  .expect("render");

  assert!(
    rendered.contains("source_url = \"https://packs.example.test/demo.oxirule-rulepack.toml\"")
  );
  assert!(rendered.contains(
    "source_sha256 = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\""
  ));
  assert!(rendered.contains("source_openpgp_signature_url"));
  let inspection = inspect_rulepack(
    &rendered,
    "rendered rulepack",
    RulepackRenderOptions::default(),
  )
  .expect("inspect");
  assert_eq!(
    inspection
      .summary
      .source_openpgp_signer_fingerprint
      .as_deref(),
    Some("0123456789abcdef0123456789abcdef01234567")
  );
}

#[test]
fn schema_v2_exposes_route_binding_metadata() {
  let raw = r#"[rulepack]
schema_version = 2
name = "vaultwarden-hardening"
version = "0.1.0"
targets = ["vaultwarden"]

[[variables]]
name = "route_name"
type = "route"
required = true
prompt = "Select the Vaultwarden route."

[[bindings]]
name = "app_route"
kind = "route"
bind_as = "route_name"
required = true
prompt = "Select the route that serves Vaultwarden."

[bindings.discovery]
name_any = ["vault", "secret"]
host_contains_any = ["vaultwarden"]
upstream_contains_any = ["vaultwarden"]
path_prefix_any = ["/"]

[[rules]]
name = "block-demo"
phase = "request"
priority = 100
content = "when = \"Context.Route.Name == '{{route_name}}'\"\n"
"#;

  let metadata = inspect_rulepack_inputs(raw, "test rulepack").expect("metadata");

  assert_eq!(metadata.summary.name, "vaultwarden-hardening");
  assert_eq!(metadata.bindings[0].name, "app_route");
  assert_eq!(metadata.bindings[0].bind_as, "route_name");
  assert_eq!(
    metadata.bindings[0].discovery.name_any,
    vec!["vault", "secret"]
  );
}

#[test]
fn schema_v2_exposes_variable_discovery_as_route_binding() {
  let raw = r#"[rulepack]
schema_version = 2
name = "vaultwarden-hardening"
version = "0.1.0"
targets = ["vaultwarden"]

[[variables]]
name = "route_name"
type = "route"
required = true
prompt = "Select the Vaultwarden route."

[variables.discovery]
name_any = ["vault"]
host_contains_any = ["vaultwarden"]

[[rules]]
name = "block-demo"
phase = "request"
priority = 100
content = "when = \"Context.Route.Name == '{{route_name}}'\"\n"
"#;

  let metadata = inspect_rulepack_inputs(raw, "test rulepack").expect("metadata");

  assert_eq!(metadata.bindings.len(), 1);
  assert_eq!(metadata.bindings[0].name, "route_name");
  assert_eq!(metadata.bindings[0].bind_as, "route_name");
  assert!(metadata.bindings[0].required);
  assert_eq!(metadata.bindings[0].discovery.name_any, vec!["vault"]);
}

#[test]
fn schema_v2_rejects_mixed_variable_discovery_and_explicit_binding() {
  let raw = r#"[rulepack]
schema_version = 2
name = "demo"
version = "0.1.0"

[[variables]]
name = "route_name"
type = "route"
required = true

[variables.discovery]
name_any = ["vault"]

[[bindings]]
name = "app_route"
kind = "route"
bind_as = "route_name"

[[rules]]
name = "block-demo"
phase = "request"
priority = 100
content = "when = \"true\"\n"
"#;

  let error =
    inspect_rulepack_inputs(raw, "test rulepack").expect_err("mixed discovery forms should fail");

  assert!(error.to_string().contains("choose either"));
}

#[test]
fn schema_v1_manifests_are_rejected() {
  let raw = r#"[rulepack]
schema_version = 1
name = "demo"
version = "0.1.0"

[[rules]]
name = "block-demo"
phase = "request"
priority = 100
content = "when = \"true\"\n"
"#;

  let error =
    inspect_rulepack_inputs(raw, "test rulepack").expect_err("schema v1 should be rejected");

  assert!(error.to_string().contains("only schema_version 2"));
}

#[test]
fn schema_v2_rejects_binding_to_unknown_variable() {
  let raw = r#"[rulepack]
schema_version = 2
name = "demo"
version = "0.1.0"

[[bindings]]
name = "app_route"
kind = "route"
bind_as = "route_name"

[[rules]]
name = "block-demo"
phase = "request"
priority = 100
content = "when = \"true\"\n"
"#;

  let error = inspect_rulepack_inputs(raw, "test rulepack")
    .expect_err("binding should require a declared render variable");

  assert!(error.to_string().contains("undeclared variable route_name"));
}

#[test]
fn schema_v2_rejects_invalid_typed_defaults() {
  let raw = r#"[rulepack]
schema_version = 2
name = "demo"
version = "0.1.0"

[[variables]]
name = "admin_cidr"
type = "cidr"
default = "not-a-cidr"

[[rules]]
name = "block-demo"
phase = "request"
priority = 100
content = "when = \"true\"\n"
"#;

  let error = inspect_rulepack_inputs(raw, "test rulepack").expect_err("invalid CIDR should fail");

  assert!(error.to_string().contains("valid CIDR"));

  let raw = r#"[rulepack]
schema_version = 2
name = "demo"
version = "0.1.0"

[[variables]]
name = "login_rate"
type = "rate"
default = "5/min"

[[rules]]
name = "block-demo"
phase = "request"
priority = 100
content = "when = \"true\"\n"
"#;

  let error = inspect_rulepack_inputs(raw, "test rulepack").expect_err("invalid rate should fail");

  assert!(error.to_string().contains("valid rate"));
}

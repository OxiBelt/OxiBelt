use super::*;

fn minimal_exception() -> RulepackException {
  RulepackException {
    name: "allow-healthcheck-login-preflight".to_string(),
    rule_ids: vec!["oxibelt.demo.login".to_string()],
    rule_names: Vec::new(),
    tags: Vec::new(),
    routes: vec!["app-root".to_string()],
    methods: vec!["GET".to_string()],
    path_prefixes: vec!["/identity/accounts/prelogin".to_string()],
    source_cidrs: vec!["10.20.0.0/16".to_string()],
    reason: "internal synthetic healthcheck".to_string(),
    expires_at: Some("2999-07-01T00:00:00Z".to_string()),
  }
}

#[test]
fn schema_v2_accepts_rulepack_exceptions_with_rendered_bindings() {
  let raw = r#"[rulepack]
schema_version = 2
name = "vaultwarden-hardening"
version = "0.1.0"

[[bindings]]
name = "app_route"
kind = "route"
bind_as = "route_name"
required = true

[[exceptions]]
name = "allow-healthcheck-login-preflight"
rule_ids = ["oxibelt.vaultwarden.login_rate_limit"]
routes = ["{{route_name}}"]
methods = ["GET"]
path_prefixes = ["/identity/accounts/prelogin"]
source_cidrs = ["10.20.0.0/16"]
reason = "internal synthetic healthcheck"
expires_at = "2999-07-01T00:00:00Z"

[[rules]]
name = "login"
id = "oxibelt.vaultwarden.login_rate_limit"
phase = "request"
priority = 100
content = '''
when = "Request.Http.Path.startsWith('/identity/accounts/prelogin')"

[[actions]]
type = "reject"
status = 403
'''
"#;

  let rendered = render_rulepack_for_install(
    raw,
    "test rulepack",
    RulepackRenderOptions {
      variables: BTreeMap::from([("route_name".to_string(), "mmsecretvault".to_string())]),
      ..RulepackRenderOptions::default()
    },
  )
  .expect("render");

  assert!(rendered.contains("[[exceptions]]"));
  assert!(rendered.contains("routes = [\"mmsecretvault\"]"));
  let inspection = inspect_rulepack(
    &rendered,
    "rendered rulepack",
    RulepackRenderOptions::default(),
  )
  .expect("inspect");
  assert_eq!(inspection.summary.exceptions, 1);
}

#[test]
fn rulepack_exceptions_rewrite_matching_rule_when() {
  let raw = r#"[rulepack]
schema_version = 2
name = "demo"
version = "0.1.0"

[[exceptions]]
name = "allow-healthcheck-login-preflight"
rule_ids = ["oxibelt.demo.login"]
routes = ["app-root"]
methods = ["GET"]
path_prefixes = ["/identity/accounts/prelogin"]
source_cidrs = ["10.20.0.0/16"]
reason = "internal synthetic healthcheck"
expires_at = "2999-07-01T00:00:00Z"

[[rules]]
name = "login"
id = "oxibelt.demo.login"
phase = "request"
priority = 100
content = '''
when = "Request.Http.Path.startsWith('/identity/accounts/prelogin')"

[[actions]]
type = "reject"
status = 403
'''
"#;

  let parsed =
    ParsedRulepack::parse(raw, "test rulepack", RulepackRenderOptions::default()).expect("parse");
  let loaded = parsed
    .expand(Path::new("."), Path::new("demo.oxirule-rulepack.toml"))
    .expect("expand");

  let when = loaded.rules[0].when.as_deref().expect("when");
  assert!(when.contains("Request.Http.Path.startsWith('/identity/accounts/prelogin')"));
  assert!(when.contains("Context.RouteName == 'app-root'"));
  assert!(when.contains("Request.Http.Method == 'GET'"));
  assert!(when.contains("Request.Client.Ip.inCidr('10.20.0.0/16')"));
  assert!(when.contains("Request.ReceivedAtUnixMs < 32487782400000"));
  assert!(when.contains("!"));
}

#[test]
fn rulepack_exceptions_apply_to_referenced_rule_paths() {
  let temp_dir = tempfile::TempDir::new().expect("temp dir");
  let rules_dir = temp_dir.path().join("rules");
  std::fs::create_dir_all(&rules_dir).expect("rules dir");
  std::fs::write(
    rules_dir.join("login.oxirule.toml"),
    r#"when = "Request.Http.Path.startsWith('/identity/accounts/prelogin')"

[[actions]]
type = "reject"
status = 403
"#,
  )
  .expect("rule file");
  let raw = r#"[rulepack]
schema_version = 2
name = "demo"
version = "0.1.0"

[[exceptions]]
name = "allow-healthcheck-login-preflight"
rule_names = ["login"]
routes = ["app-root"]
methods = ["GET"]
path_prefixes = ["/identity/accounts/prelogin"]
source_cidrs = ["10.20.0.0/16"]
reason = "internal synthetic healthcheck"

[[rules]]
name = "login"
phase = "request"
priority = 100
path = "rules/login.oxirule.toml"
"#;

  let parsed =
    ParsedRulepack::parse(raw, "test rulepack", RulepackRenderOptions::default()).expect("parse");
  let loaded = parsed
    .expand(temp_dir.path(), Path::new("demo.oxirule-rulepack.toml"))
    .expect("expand");

  let when = loaded.rules[0].when.as_deref().expect("when");
  assert!(when.contains("Context.RouteName == 'app-root'"));
  assert!(
    loaded
      .summary
      .loaded_files
      .iter()
      .any(|path| { path.to_string_lossy().ends_with("rules/login.oxirule.toml") })
  );
}

#[test]
fn expired_rulepack_exceptions_are_ignored() {
  let raw = r#"[rulepack]
schema_version = 2
name = "demo"
version = "0.1.0"

[[exceptions]]
name = "expired-login-exception"
rule_names = ["login"]
routes = ["app-root"]
methods = ["GET"]
reason = "old healthcheck"
expires_at = "2000-01-01T00:00:00Z"

[[rules]]
name = "login"
phase = "request"
priority = 100
content = '''
when = "Request.Http.Path.startsWith('/identity/accounts/prelogin')"

[[actions]]
type = "reject"
status = 403
'''
"#;

  let parsed =
    ParsedRulepack::parse(raw, "test rulepack", RulepackRenderOptions::default()).expect("parse");
  let loaded = parsed
    .expand(Path::new("."), Path::new("demo.oxirule-rulepack.toml"))
    .expect("expand");

  assert_eq!(
    loaded.rules[0].when.as_deref(),
    Some("Request.Http.Path.startsWith('/identity/accounts/prelogin')")
  );
}

#[test]
fn local_rulepack_exceptions_render_into_install_manifest() {
  let raw = r#"[rulepack]
schema_version = 2
name = "demo"
version = "0.1.0"

[[rules]]
name = "login"
id = "oxibelt.demo.login"
phase = "request"
priority = 100
content = '''
when = "Request.Http.Path.startsWith('/identity/accounts/prelogin')"

[[actions]]
type = "reject"
status = 403
'''
"#;

  let rendered = render_rulepack_for_install(
    raw,
    "test rulepack",
    RulepackRenderOptions {
      local_exceptions: vec![minimal_exception()],
      ..RulepackRenderOptions::default()
    },
  )
  .expect("render");

  assert!(rendered.contains("[[exceptions]]"));
  assert!(rendered.contains("allow-healthcheck-login-preflight"));
  assert!(rendered.contains("source_cidrs = [\"10.20.0.0/16\"]"));
}

#[test]
fn rulepack_exceptions_reject_invalid_shapes() {
  for (name, extra, expected) in [
    (
      "missing-rule-selector",
      r#"
[[exceptions]]
name = "bad"
routes = ["app-root"]
reason = "missing rule selector"
"#,
      "at least one rule selector",
    ),
    (
      "missing-traffic-selector",
      r#"
[[exceptions]]
name = "bad"
rule_names = ["login"]
reason = "missing traffic selector"
"#,
      "at least one traffic selector",
    ),
    (
      "invalid-method",
      r#"
[[exceptions]]
name = "bad"
rule_names = ["login"]
methods = ["GET BAD"]
reason = "invalid method"
"#,
      "invalid HTTP method",
    ),
    (
      "invalid-path-prefix",
      r#"
[[exceptions]]
name = "bad"
rule_names = ["login"]
path_prefixes = ["identity"]
reason = "invalid path"
"#,
      "path_prefixes entries must start with /",
    ),
    (
      "invalid-cidr",
      r#"
[[exceptions]]
name = "bad"
rule_names = ["login"]
source_cidrs = ["10.0.0.0/99"]
reason = "invalid cidr"
"#,
      "source_cidrs entry",
    ),
    (
      "duplicate-name",
      r#"
[[exceptions]]
name = "bad"
rule_names = ["login"]
routes = ["app-root"]
reason = "first"

[[exceptions]]
name = "bad"
rule_names = ["login"]
routes = ["app-root"]
reason = "second"
"#,
      "duplicate exception bad",
    ),
    (
      "bad-expiry",
      r#"
[[exceptions]]
name = "bad"
rule_names = ["login"]
routes = ["app-root"]
reason = "bad expiry"
expires_at = "2999-07-01 00:00:00Z"
"#,
      "expires_at is invalid",
    ),
    (
      "unmatched",
      r#"
[[exceptions]]
name = "bad"
rule_names = ["missing"]
routes = ["app-root"]
reason = "unmatched"
"#,
      "did not match any rule",
    ),
    (
      "unknown-field",
      r#"
[[exceptions]]
name = "bad"
rule_names = ["login"]
routes = ["app-root"]
header_equals = { "x-app-context" = "trusted" }
reason = "unknown field"
"#,
      "failed to decode",
    ),
  ] {
    let raw = format!(
      r#"[rulepack]
schema_version = 2
name = "demo-{name}"
version = "0.1.0"
{extra}
[[rules]]
name = "login"
phase = "request"
priority = 100
content = "when = \"true\"\n"
"#
    );

    let error = validate_rulepack_manifest(&raw).expect_err("invalid exception should fail");
    assert!(
      error.to_string().contains(expected),
      "{name} expected {expected:?}, got {error}"
    );
  }
}

#[test]
fn rulepack_exceptions_reject_stream_phase_matches() {
  let raw = r#"[rulepack]
schema_version = 2
name = "demo"
version = "0.1.0"

[[exceptions]]
name = "bad-stream-exception"
rule_names = ["stream-rule"]
routes = ["app-root"]
reason = "stream selectors are unsupported"

[[rules]]
name = "stream-rule"
phase = "stream"
priority = 100
content = '''
when = "Stream.Payload.Text.contains('secret')"

[[actions]]
type = "close_stream"
websocket_code = 1008
'''
"#;

  let error = validate_rulepack_manifest(raw).expect_err("stream exception should fail");

  assert!(error.to_string().contains("stream-phase rule"));
}

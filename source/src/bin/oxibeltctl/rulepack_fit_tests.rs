use super::*;

fn vaultwarden_rulepack() -> &'static str {
  r#"[rulepack]
schema_version = 2
name = "vaultwarden-hardening"
version = "0.1.0"
targets = ["vaultwarden"]

[[variables]]
name = "route_name"
type = "route"
required = true

[[variables]]
name = "admin_cidr"
type = "cidr"
required = true

[[bindings]]
name = "app_route"
kind = "route"
bind_as = "route_name"
required = true

[bindings.discovery]
name_any = ["vault", "secret"]
host_contains_any = ["vaultwarden", "vault"]
upstream_contains_any = ["vaultwarden"]
path_prefix_any = ["/"]

[[rules]]
name = "admin-guard"
phase = "request"
priority = 100
content = "when = \"Context.Route.Name == '{{route_name}}'\"\n"
"#
}

fn variable_discovery_rulepack() -> &'static str {
  r#"[rulepack]
schema_version = 2
name = "vaultwarden-hardening"
version = "0.1.0"
targets = ["vaultwarden"]

[[variables]]
name = "route_name"
type = "route"
required = true

[variables.discovery]
name_any = ["vault", "secret"]
host_contains_any = ["vaultwarden", "vault"]
upstream_contains_any = ["vaultwarden"]
path_prefix_any = ["/"]

[[rules]]
name = "admin-guard"
phase = "request"
priority = 100
content = "when = \"Context.Route.Name == '{{route_name}}'\"\n"
"#
}

#[test]
fn fit_ranks_matching_route_above_generic_root() {
  let inputs = inspect_rulepack_inputs(vaultwarden_rulepack(), "test rulepack").expect("inputs");
  let config = r#"
[[upstreams]]
name = "vaultwarden-origin"
origin = "https://vaultwarden.internal"

[[upstreams]]
name = "generic-origin"
origin = "https://app.internal"

[[routes]]
name = "app-root"
hosts = ["example.com"]
path_prefix = "/"
upstream = "generic-origin"

[[routes]]
name = "mmsecretvault"
hosts = ["vault.example.com"]
path_prefix = "/"
upstream = "vaultwarden-origin"
"#;
  let config = toml::from_str::<toml::Value>(config).expect("config");
  let routes = route_inventory(&config);
  let candidates = score_route_candidates(
    &inputs.bindings[0],
    &routes,
    &default_discovery_tokens(&inputs),
  );

  assert_eq!(candidates[0].name, "mmsecretvault");
  assert!(candidates[0].score > candidates[1].score);
  assert!(
    candidates[0]
      .reason
      .iter()
      .any(|reason| reason.contains("route name contains"))
  );
}

#[test]
fn variable_discovery_feeds_route_candidates_and_suggested_bind() {
  let inputs =
    inspect_rulepack_inputs(variable_discovery_rulepack(), "test rulepack").expect("inputs");
  let config = r#"
[[upstreams]]
name = "vaultwarden-origin"
origin = "https://vaultwarden.internal"

[[routes]]
name = "mmsecretvault"
hosts = ["vault.example.com"]
path_prefix = "/"
upstream = "vaultwarden-origin"
"#;
  let config = toml::from_str::<toml::Value>(config).expect("config");
  let routes = route_inventory(&config);
  let candidates = score_route_candidates(
    &inputs.bindings[0],
    &routes,
    &default_discovery_tokens(&inputs),
  );
  let route_candidates = vec![RouteCandidateSet {
    binding: "route_name".to_string(),
    candidates,
  }];
  let source_args = RulepackSourceArgs {
    file: Some(std::path::PathBuf::from(
      "vaultwarden.oxirule-rulepack.toml",
    )),
    dir: None,
    url: None,
    git: None,
    manifest: std::path::PathBuf::from("rulepack.oxirule-rulepack.toml"),
    ca_certs: Vec::new(),
    token_env: None,
    sha256: None,
    allow_unpinned_rulepack: false,
    allow_insecure_rulepack_url: false,
    require_openpgp_signature: false,
    openpgp_signature_url: None,
    openpgp_signature_file: None,
    openpgp_key_files: Vec::new(),
    openpgp_keyring_dirs: Vec::new(),
    openpgp_fingerprints: Vec::new(),
    git_ref: None,
  };

  let command = suggested_apply_command(SuggestedCommandContext {
    source_args: &source_args,
    inputs: &inputs,
    binds: &BTreeMap::new(),
    vars: &BTreeMap::new(),
    missing_bindings: &["route_name".to_string()],
    missing_variables: &[],
    route_candidates: &route_candidates,
    mode: None,
    force_mode: false,
  });

  assert_eq!(inputs.bindings[0].name, "route_name");
  assert!(command.contains("--bind route_name=mmsecretvault"));
}

#[test]
fn source_command_parts_preserve_openpgp_url_options() {
  let source_args = RulepackSourceArgs {
    file: None,
    dir: None,
    url: Some(
      "https://packs.example.test/pack.oxirule-rulepack.toml?token=secret"
        .parse()
        .expect("url"),
    ),
    git: None,
    manifest: std::path::PathBuf::from("rulepack.oxirule-rulepack.toml"),
    ca_certs: Vec::new(),
    token_env: Some("RULEPACK_TOKEN".to_string()),
    sha256: None,
    allow_unpinned_rulepack: false,
    allow_insecure_rulepack_url: false,
    require_openpgp_signature: true,
    openpgp_signature_url: Some(
      "https://packs.example.test/pack.oxirule-rulepack.toml.sig?token=secret"
        .parse()
        .expect("signature url"),
    ),
    openpgp_signature_file: None,
    openpgp_key_files: vec![std::path::PathBuf::from("publisher.asc")],
    openpgp_keyring_dirs: vec![std::path::PathBuf::from("trusted-publishers")],
    openpgp_fingerprints: vec!["0123456789abcdef0123456789abcdef01234567".to_string()],
    git_ref: None,
  };

  let command = source_command_parts(&source_args).join(" ");

  assert!(command.contains("--require-rulepack-openpgp-signature"));
  assert!(command.contains("--rulepack-openpgp-signature-url"));
  assert!(command.contains("https://packs.example.test/pack.oxirule-rulepack.toml.sig"));
  assert!(!command.contains("token=secret"));
  assert!(command.contains("--rulepack-openpgp-key publisher.asc"));
  assert!(command.contains("--rulepack-openpgp-keyring trusted-publishers"));
  assert!(command.contains("--rulepack-openpgp-fingerprint 0123456789abcdef"));
}

#[test]
fn bind_values_feed_declared_render_variables() {
  let vars = BTreeMap::from([("admin_cidr".to_string(), "10.0.0.0/8".to_string())]);
  let binds = BTreeMap::from([("app_route".to_string(), "mmsecretvault".to_string())]);

  let render_vars =
    resolve_render_variables(vaultwarden_rulepack(), "test rulepack", &vars, &binds, true)
      .expect("render variables");

  assert_eq!(
    render_vars.get("route_name").map(String::as_str),
    Some("mmsecretvault")
  );
  assert_eq!(
    render_vars.get("admin_cidr").map(String::as_str),
    Some("10.0.0.0/8")
  );
}

#[test]
fn bind_conflicts_with_var_for_same_render_variable() {
  let vars = BTreeMap::from([
    ("route_name".to_string(), "other".to_string()),
    ("admin_cidr".to_string(), "10.0.0.0/8".to_string()),
  ]);
  let binds = BTreeMap::from([("app_route".to_string(), "mmsecretvault".to_string())]);

  let error =
    resolve_render_variables(vaultwarden_rulepack(), "test rulepack", &vars, &binds, true)
      .expect_err("conflicting binding should fail");

  assert!(error.to_string().contains("conflicts"));
}

#[test]
fn invalid_typed_cli_values_fail_closed() {
  let vars = BTreeMap::from([("admin_cidr".to_string(), "not-a-cidr".to_string())]);
  let binds = BTreeMap::from([("app_route".to_string(), "mmsecretvault".to_string())]);

  let error =
    resolve_render_variables(vaultwarden_rulepack(), "test rulepack", &vars, &binds, true)
      .expect_err("invalid CIDR should fail");

  assert!(error.to_string().contains("valid CIDR"));

  let raw = r#"[rulepack]
schema_version = 2
name = "rate-pack"
version = "0.1.0"

[[variables]]
name = "login_rate"
type = "rate"
required = true

[[rules]]
name = "login-rate"
phase = "request"
priority = 100
content = "when = \"true\"\n"
"#;
  let vars = BTreeMap::from([("login_rate".to_string(), "5/min".to_string())]);

  let error = resolve_render_variables(raw, "test rulepack", &vars, &BTreeMap::new(), true)
    .expect_err("invalid rate should fail");

  assert!(error.to_string().contains("valid rate"));
}

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

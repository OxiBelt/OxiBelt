use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, bail};
use http::Method;
use oxibelt::admin_client::AdminClient;
use oxibelt::identity::Cidr;
use oxibelt::waf::{
  RulepackBinding, RulepackBindingKind, RulepackInputMetadata, inspect_rulepack_inputs,
};
use serde::Serialize;
use serde_json::Value;

use crate::cli::{RulepackModeArg, RulepackSourceArgs};
use crate::rulepack::LoadedRulepackSource;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RulepackFitReport {
  pub(crate) rulepack: String,
  pub(crate) required_bindings: Vec<String>,
  pub(crate) missing_bindings: Vec<String>,
  pub(crate) route_candidates: Vec<RouteCandidateSet>,
  pub(crate) missing_variables: Vec<String>,
  pub(crate) resolved_bindings: BTreeMap<String, String>,
  pub(crate) warnings: Vec<String>,
  pub(crate) suggested_command: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RouteCandidateSet {
  pub(crate) binding: String,
  pub(crate) candidates: Vec<RouteCandidate>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RouteCandidate {
  pub(crate) name: String,
  pub(crate) score: i64,
  pub(crate) reason: Vec<String>,
  pub(crate) hosts: Vec<String>,
  pub(crate) path_prefix: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(crate) upstream: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct RulepackFitEvaluation {
  pub(crate) inputs: RulepackInputMetadata,
  pub(crate) report: RulepackFitReport,
}

#[derive(Debug, Clone)]
struct RouteInventory {
  name: String,
  hosts: Vec<String>,
  path_prefix: String,
  upstream: Option<String>,
  upstream_text: Vec<String>,
}

pub(crate) async fn evaluate_fit(
  client: &AdminClient,
  loaded: &LoadedRulepackSource,
  source_args: &RulepackSourceArgs,
  vars: &BTreeMap<String, String>,
  binds: &BTreeMap<String, String>,
  mode: Option<RulepackModeArg>,
  force_mode: bool,
) -> anyhow::Result<RulepackFitEvaluation> {
  let inputs = inspect_rulepack_inputs(&loaded.manifest, &loaded.source_label)?;
  let _ = resolve_render_variables_from_inputs(&inputs, vars, binds)?;
  let config = effective_config_toml(client).await?;
  let routes = route_inventory(&config);
  let default_tokens = default_discovery_tokens(&inputs);
  let route_candidates = inputs
    .bindings
    .iter()
    .filter(|binding| binding.kind == RulepackBindingKind::Route)
    .map(|binding| RouteCandidateSet {
      binding: binding.name.clone(),
      candidates: score_route_candidates(binding, &routes, &default_tokens),
    })
    .collect::<Vec<_>>();
  let required_bindings = inputs
    .bindings
    .iter()
    .filter(|binding| binding.required)
    .map(|binding| binding.name.clone())
    .collect::<Vec<_>>();
  let missing_bindings = missing_bindings(&inputs, vars, binds);
  let missing_variables = missing_variables(&inputs, vars, binds, &missing_bindings);
  let resolved_bindings = resolved_bindings(&inputs, vars, binds);
  let warnings = fit_warnings(&inputs, &route_candidates);
  let suggested_command = suggested_apply_command(SuggestedCommandContext {
    source_args,
    inputs: &inputs,
    binds,
    vars,
    missing_bindings: &missing_bindings,
    missing_variables: &missing_variables,
    route_candidates: &route_candidates,
    mode,
    force_mode,
  });
  let report = RulepackFitReport {
    rulepack: inputs.summary.name.clone(),
    required_bindings,
    missing_bindings,
    route_candidates,
    missing_variables,
    resolved_bindings,
    warnings,
    suggested_command,
  };
  Ok(RulepackFitEvaluation { inputs, report })
}

pub(crate) fn parse_key_values(
  items: &[String],
  label: &str,
) -> anyhow::Result<BTreeMap<String, String>> {
  let mut parsed = BTreeMap::new();
  for item in items {
    let Some((key, value)) = item.split_once('=') else {
      bail!("{label} must use KEY=VALUE");
    };
    if key.trim().is_empty() {
      bail!("{label} key must not be empty");
    }
    if parsed.insert(key.to_string(), value.to_string()).is_some() {
      bail!("{label} contains duplicate key {key}");
    }
  }
  Ok(parsed)
}

pub(crate) fn resolve_render_variables(
  raw: &str,
  source: &str,
  vars: &BTreeMap<String, String>,
  binds: &BTreeMap<String, String>,
  require_all: bool,
) -> anyhow::Result<BTreeMap<String, String>> {
  let inputs = inspect_rulepack_inputs(raw, source)?;
  let render_vars = resolve_render_variables_from_inputs(&inputs, vars, binds)?;
  if require_all {
    let missing_bindings = missing_bindings(&inputs, vars, binds);
    if let Some(binding) = missing_bindings.first() {
      bail!(
        "rulepack requires binding {binding}; pass --bind {binding}=VALUE or use --interactive"
      );
    }
    let missing_variables = missing_variables(&inputs, vars, binds, &missing_bindings);
    if let Some(variable) = missing_variables.first() {
      bail!(
        "rulepack requires variable {variable}; pass --var {variable}=VALUE or use --interactive"
      );
    }
  }
  Ok(render_vars)
}

fn resolve_render_variables_from_inputs(
  inputs: &RulepackInputMetadata,
  vars: &BTreeMap<String, String>,
  binds: &BTreeMap<String, String>,
) -> anyhow::Result<BTreeMap<String, String>> {
  validate_input_keys(inputs, vars, binds)?;
  let mut render_vars = vars.clone();
  for binding in &inputs.bindings {
    if let Some(value) = binds.get(&binding.name) {
      if let Some(existing) = render_vars.get(&binding.bind_as)
        && existing != value
      {
        bail!(
          "--bind {} conflicts with --var {}",
          binding.name,
          binding.bind_as
        );
      }
      render_vars.insert(binding.bind_as.clone(), value.clone());
    }
  }
  validate_render_values(inputs, &render_vars)?;
  Ok(render_vars)
}

fn validate_render_values(
  inputs: &RulepackInputMetadata,
  render_vars: &BTreeMap<String, String>,
) -> anyhow::Result<()> {
  for variable in &inputs.variables {
    let Some(value) = render_vars.get(&variable.name) else {
      continue;
    };
    match variable.value_type.as_deref() {
      Some("cidr") => {
        Cidr::parse(value).with_context(|| {
          format!(
            "rulepack {} variable {} must be a valid CIDR",
            inputs.summary.name, variable.name
          )
        })?;
      }
      Some("rate") => {
        oxibelt::limits::parse_rate(value).with_context(|| {
          format!(
            "rulepack {} variable {} must be a valid rate",
            inputs.summary.name, variable.name
          )
        })?;
      }
      Some("route") | Some("string") | None => {}
      Some(other) => bail!(
        "rulepack {} variable {} uses unsupported type {}",
        inputs.summary.name,
        variable.name,
        other
      ),
    }
  }
  Ok(())
}

fn validate_input_keys(
  inputs: &RulepackInputMetadata,
  vars: &BTreeMap<String, String>,
  binds: &BTreeMap<String, String>,
) -> anyhow::Result<()> {
  let variables = inputs
    .variables
    .iter()
    .map(|variable| variable.name.as_str())
    .collect::<BTreeSet<_>>();
  for key in vars.keys() {
    if !variables.contains(key.as_str()) {
      bail!(
        "rulepack {} does not declare variable {key}",
        inputs.summary.name
      );
    }
  }
  let bindings = inputs
    .bindings
    .iter()
    .map(|binding| binding.name.as_str())
    .collect::<BTreeSet<_>>();
  for key in binds.keys() {
    if !bindings.contains(key.as_str()) {
      bail!(
        "rulepack {} does not declare binding {key}",
        inputs.summary.name
      );
    }
  }
  Ok(())
}

async fn effective_config_toml(client: &AdminClient) -> anyhow::Result<toml::Value> {
  let response = client
    .request_json(Method::GET, "/admin/v1/config/effective", None, None)
    .await?;
  if !response.status.is_success() {
    bail!("failed to fetch effective config: {}", response.status);
  }
  let value: Value =
    serde_json::from_slice(&response.body).context("effective config response was not JSON")?;
  let raw = value
    .get("config")
    .and_then(Value::as_str)
    .context("effective config response did not include config")?;
  toml::from_str(raw).context("effective config was not TOML")
}

fn route_inventory(config: &toml::Value) -> Vec<RouteInventory> {
  let upstreams = config
    .get("upstreams")
    .and_then(toml::Value::as_array)
    .into_iter()
    .flatten()
    .filter_map(toml::Value::as_table)
    .filter_map(|table| {
      let name = table.get("name")?.as_str()?.to_string();
      let origin = table
        .get("origin")
        .and_then(toml::Value::as_str)
        .unwrap_or_default()
        .to_string();
      Some((name, origin))
    })
    .collect::<BTreeMap<_, _>>();

  config
    .get("routes")
    .and_then(toml::Value::as_array)
    .into_iter()
    .flatten()
    .filter_map(toml::Value::as_table)
    .filter_map(|table| {
      let name = table.get("name")?.as_str()?.to_string();
      let hosts = table
        .get("hosts")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .map(str::to_string)
        .collect::<Vec<_>>();
      let path_prefix = table
        .get("path_prefix")
        .and_then(toml::Value::as_str)
        .unwrap_or("/")
        .to_string();
      let upstream = table
        .get("upstream")
        .and_then(toml::Value::as_str)
        .map(str::to_string);
      let upstream_pool = table
        .get("upstream_pool")
        .and_then(toml::Value::as_str)
        .map(str::to_string);
      let mut upstream_text = Vec::new();
      if let Some(upstream) = &upstream {
        upstream_text.push(upstream.clone());
        if let Some(origin) = upstreams.get(upstream) {
          upstream_text.push(origin.clone());
        }
      }
      if let Some(upstream_pool) = &upstream_pool {
        upstream_text.push(upstream_pool.clone());
      }
      Some(RouteInventory {
        name,
        hosts,
        path_prefix,
        upstream: upstream.or(upstream_pool),
        upstream_text,
      })
    })
    .collect()
}

fn score_route_candidates(
  binding: &RulepackBinding,
  routes: &[RouteInventory],
  default_tokens: &[String],
) -> Vec<RouteCandidate> {
  let mut candidates = routes
    .iter()
    .filter_map(|route| score_route_candidate(binding, route, default_tokens))
    .collect::<Vec<_>>();
  candidates.sort_by(|left, right| {
    right
      .score
      .cmp(&left.score)
      .then_with(|| left.name.cmp(&right.name))
  });
  candidates.truncate(10);
  candidates
}

fn score_route_candidate(
  binding: &RulepackBinding,
  route: &RouteInventory,
  default_tokens: &[String],
) -> Option<RouteCandidate> {
  let discovery = &binding.discovery;
  let name_tokens = tokens_or_default(&discovery.name_any, default_tokens);
  let host_tokens = tokens_or_default(&discovery.host_contains_any, default_tokens);
  let upstream_tokens = tokens_or_default(&discovery.upstream_contains_any, default_tokens);
  let mut score = 0;
  let mut reason = Vec::new();

  if let Some(token) = first_contains(std::slice::from_ref(&route.name), &name_tokens) {
    score += 50;
    reason.push(format!("route name contains {token}"));
  }
  if let Some((value, token)) = first_contains_value(&route.hosts, &host_tokens) {
    score += 30;
    reason.push(format!("host {value} contains {token}"));
  }
  if let Some((value, token)) = first_contains_value(&route.upstream_text, &upstream_tokens) {
    score += 25;
    reason.push(format!("upstream {value} contains {token}"));
  }
  if discovery
    .path_prefix_any
    .iter()
    .any(|prefix| prefix == &route.path_prefix)
  {
    score += 5;
    reason.push(format!("path_prefix is {}", route.path_prefix));
  }

  (score > 0).then(|| RouteCandidate {
    name: route.name.clone(),
    score,
    reason,
    hosts: route.hosts.clone(),
    path_prefix: route.path_prefix.clone(),
    upstream: route.upstream.clone(),
  })
}

fn tokens_or_default<'a>(tokens: &'a [String], default_tokens: &'a [String]) -> Vec<&'a str> {
  let values = if tokens.is_empty() {
    default_tokens
  } else {
    tokens
  };
  values
    .iter()
    .map(String::as_str)
    .filter(|token| !token.trim().is_empty())
    .collect()
}

fn first_contains(values: &[String], tokens: &[&str]) -> Option<String> {
  first_contains_value(values, tokens).map(|(_, token)| token)
}

fn first_contains_value(values: &[String], tokens: &[&str]) -> Option<(String, String)> {
  for value in values {
    let lower = value.to_ascii_lowercase();
    for token in tokens {
      let token = token.to_ascii_lowercase();
      if !token.is_empty() && lower.contains(&token) {
        return Some((value.clone(), token));
      }
    }
  }
  None
}

fn default_discovery_tokens(inputs: &RulepackInputMetadata) -> Vec<String> {
  let mut tokens = BTreeSet::new();
  for value in inputs
    .summary
    .targets
    .iter()
    .chain(std::iter::once(&inputs.summary.name))
  {
    for token in value
      .split(['-', '_', '.', ':'])
      .map(str::trim)
      .filter(|token| !token.is_empty())
    {
      tokens.insert(token.to_ascii_lowercase());
    }
  }
  tokens.into_iter().collect()
}

fn missing_bindings(
  inputs: &RulepackInputMetadata,
  vars: &BTreeMap<String, String>,
  binds: &BTreeMap<String, String>,
) -> Vec<String> {
  inputs
    .bindings
    .iter()
    .filter(|binding| binding.required && binding_value(binding, inputs, vars, binds).is_none())
    .map(|binding| binding.name.clone())
    .collect()
}

pub(crate) fn missing_required_bindings(
  inputs: &RulepackInputMetadata,
  vars: &BTreeMap<String, String>,
  binds: &BTreeMap<String, String>,
) -> Vec<String> {
  missing_bindings(inputs, vars, binds)
}

pub(crate) fn missing_required_variables(
  inputs: &RulepackInputMetadata,
  vars: &BTreeMap<String, String>,
  binds: &BTreeMap<String, String>,
) -> Vec<String> {
  let missing_bindings = missing_bindings(inputs, vars, binds);
  missing_variables(inputs, vars, binds, &missing_bindings)
}

fn missing_variables(
  inputs: &RulepackInputMetadata,
  vars: &BTreeMap<String, String>,
  binds: &BTreeMap<String, String>,
  missing_bindings: &[String],
) -> Vec<String> {
  let unresolved_binding_vars = inputs
    .bindings
    .iter()
    .filter(|binding| {
      missing_bindings
        .iter()
        .any(|missing| missing == &binding.name)
    })
    .map(|binding| binding.bind_as.as_str())
    .collect::<BTreeSet<_>>();
  inputs
    .variables
    .iter()
    .filter(|variable| {
      variable.required
        && variable.default.is_none()
        && !vars.contains_key(&variable.name)
        && !unresolved_binding_vars.contains(variable.name.as_str())
        && !inputs
          .bindings
          .iter()
          .any(|binding| binding.bind_as == variable.name && binds.contains_key(&binding.name))
    })
    .map(|variable| variable.name.clone())
    .collect()
}

fn resolved_bindings(
  inputs: &RulepackInputMetadata,
  vars: &BTreeMap<String, String>,
  binds: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
  inputs
    .bindings
    .iter()
    .filter_map(|binding| {
      binding_value(binding, inputs, vars, binds).map(|value| (binding.name.clone(), value))
    })
    .collect()
}

fn binding_value(
  binding: &RulepackBinding,
  inputs: &RulepackInputMetadata,
  vars: &BTreeMap<String, String>,
  binds: &BTreeMap<String, String>,
) -> Option<String> {
  binds
    .get(&binding.name)
    .or_else(|| vars.get(&binding.bind_as))
    .cloned()
    .or_else(|| {
      inputs
        .variables
        .iter()
        .find(|variable| variable.name == binding.bind_as)
        .and_then(|variable| variable.default.clone())
    })
}

fn fit_warnings(
  inputs: &RulepackInputMetadata,
  route_candidates: &[RouteCandidateSet],
) -> Vec<String> {
  let mut warnings = Vec::new();
  for binding in &inputs.bindings {
    if binding.kind == RulepackBindingKind::Route
      && route_candidates
        .iter()
        .find(|set| set.binding == binding.name)
        .is_none_or(|set| set.candidates.is_empty())
    {
      warnings.push(format!(
        "no route candidates matched binding {}",
        binding.name
      ));
    }
  }
  warnings
}

struct SuggestedCommandContext<'a> {
  source_args: &'a RulepackSourceArgs,
  inputs: &'a RulepackInputMetadata,
  binds: &'a BTreeMap<String, String>,
  vars: &'a BTreeMap<String, String>,
  missing_bindings: &'a [String],
  missing_variables: &'a [String],
  route_candidates: &'a [RouteCandidateSet],
  mode: Option<RulepackModeArg>,
  force_mode: bool,
}

fn suggested_apply_command(context: SuggestedCommandContext<'_>) -> String {
  let mut parts = vec![
    "oxibeltctl".to_string(),
    "rulepack".to_string(),
    "apply".to_string(),
  ];
  parts.extend(source_command_parts(context.source_args));
  for binding in &context.inputs.bindings {
    let value = context.binds.get(&binding.name).cloned().or_else(|| {
      context
        .missing_bindings
        .iter()
        .any(|missing| missing == &binding.name)
        .then(|| top_candidate(context.route_candidates, &binding.name))
        .flatten()
    });
    if let Some(value) = value {
      parts.push("--bind".to_string());
      parts.push(format!("{}={value}", binding.name));
    }
  }
  for (name, value) in context.vars {
    parts.push("--var".to_string());
    parts.push(format!("{name}={value}"));
  }
  for variable in context.missing_variables {
    parts.push("--var".to_string());
    parts.push(format!("{variable}=<value>"));
  }
  if let Some(mode) = context.mode {
    parts.push("--mode".to_string());
    parts.push(rulepack_mode_name(mode).to_string());
  }
  if context.force_mode {
    parts.push("--force-mode".to_string());
  }
  parts
    .into_iter()
    .map(|part| shell_quote(&part))
    .collect::<Vec<_>>()
    .join(" ")
}

fn top_candidate(route_candidates: &[RouteCandidateSet], binding: &str) -> Option<String> {
  route_candidates
    .iter()
    .find(|set| set.binding == binding)
    .and_then(|set| set.candidates.first())
    .map(|candidate| candidate.name.clone())
}

fn source_command_parts(args: &RulepackSourceArgs) -> Vec<String> {
  let mut parts = Vec::new();
  if let Some(file) = &args.file {
    parts.push("--file".to_string());
    parts.push(file.to_string_lossy().to_string());
  } else if let Some(dir) = &args.dir {
    parts.push("--dir".to_string());
    parts.push(dir.to_string_lossy().to_string());
    parts.push("--manifest".to_string());
    parts.push(args.manifest.to_string_lossy().to_string());
  } else if let Some(url) = &args.url {
    parts.push("--url".to_string());
    parts.push(safe_command_url(url));
    if let Some(sha256) = &args.sha256 {
      parts.push("--sha256".to_string());
      parts.push(sha256.clone());
    }
    for cert in &args.ca_certs {
      parts.push("--rulepack-ca-cert".to_string());
      parts.push(cert.to_string_lossy().to_string());
    }
    if let Some(token_env) = &args.token_env {
      parts.push("--rulepack-token-env".to_string());
      parts.push(token_env.clone());
    }
    if args.allow_unpinned_rulepack {
      parts.push("--allow-unpinned-rulepack".to_string());
    }
    if args.allow_insecure_rulepack_url {
      parts.push("--allow-insecure-rulepack-url".to_string());
    }
    if args.require_openpgp_signature {
      parts.push("--require-rulepack-openpgp-signature".to_string());
    }
    if let Some(signature_url) = &args.openpgp_signature_url {
      parts.push("--rulepack-openpgp-signature-url".to_string());
      parts.push(safe_command_url(signature_url));
    }
    if let Some(signature_file) = &args.openpgp_signature_file {
      parts.push("--rulepack-openpgp-signature-file".to_string());
      parts.push(signature_file.to_string_lossy().to_string());
    }
    for key_file in &args.openpgp_key_files {
      parts.push("--rulepack-openpgp-key".to_string());
      parts.push(key_file.to_string_lossy().to_string());
    }
    for keyring_dir in &args.openpgp_keyring_dirs {
      parts.push("--rulepack-openpgp-keyring".to_string());
      parts.push(keyring_dir.to_string_lossy().to_string());
    }
    for fingerprint in &args.openpgp_fingerprints {
      parts.push("--rulepack-openpgp-fingerprint".to_string());
      parts.push(fingerprint.clone());
    }
  } else if let Some(git) = &args.git {
    parts.push("--git".to_string());
    parts.push(git.clone());
    parts.push("--manifest".to_string());
    parts.push(args.manifest.to_string_lossy().to_string());
    if let Some(git_ref) = &args.git_ref {
      parts.push("--git-ref".to_string());
      parts.push(git_ref.clone());
    }
  }
  parts
}

fn safe_command_url(url: &url::Url) -> String {
  let mut safe = url.clone();
  let _ = safe.set_username("");
  let _ = safe.set_password(None);
  safe.set_query(None);
  safe.set_fragment(None);
  safe.to_string()
}

fn shell_quote(value: &str) -> String {
  if value.bytes().all(|byte| {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'=')
  }) {
    return value.to_string();
  }
  format!("'{}'", value.replace('\'', "'\\''"))
}

fn rulepack_mode_name(mode: RulepackModeArg) -> &'static str {
  match mode {
    RulepackModeArg::Monitor => "monitor",
    RulepackModeArg::Enforcing => "enforcing",
  }
}

#[cfg(test)]
#[path = "rulepack_fit_tests.rs"]
mod tests;

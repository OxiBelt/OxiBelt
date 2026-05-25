use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use http::Method;
use oxibelt::admin_client::AdminClient;
use serde_json::{Value, json};

use super::cli::*;

pub(crate) struct RequestPlan {
  pub(crate) method: Method,
  pub(crate) endpoint: String,
  pub(crate) body: Option<Value>,
  pub(crate) if_match: Option<String>,
  pub(crate) permission: PermissionHint,
  pub(crate) filter: ResponseFilter,
}

pub(crate) struct PermissionHint {
  pub(crate) action: String,
  pub(crate) resource: String,
}

pub(crate) enum ResponseFilter {
  None,
  TopRules(usize),
}

pub(crate) async fn plan_command(
  client: &AdminClient,
  command: &Command,
) -> anyhow::Result<RequestPlan> {
  match command {
    Command::Status => get("/admin/v1/config/status", "config:GetStatus", "*"),
    Command::Doctor(args) => plan_doctor(args),
    Command::SupportBundle(args) => plan_support_bundle(args),
    Command::Runtime(command) => plan_runtime(command),
    Command::Config(command) => plan_config(client, command).await,
    Command::Tls(command) => plan_tls(client, command).await,
    Command::Lifecycle(command) => plan_lifecycle(command),
    Command::Pool(command) => plan_pool(command),
    Command::Waf(command) => plan_waf(command),
    Command::OxiRule(command) => plan_oxirule(command),
    Command::DynamicPolicy(command) => plan_dynamic_policy(command),
    Command::Block(args) => plan_mitigation("reject", args),
    Command::Allow(args) => plan_mitigation("allow", args),
    Command::RateLimit(args) => plan_rate_limit(args),
    Command::Cache(command) => plan_cache(command),
    Command::Ipm(command) => plan_ipm(command),
    Command::Auth(command) => match &command.command {
      AuthSubcommand::Check(args) => post_json(
        "/admin/v1/ipm/simulate",
        json!({ "action": args.action, "resource": args.resource }),
        "ipm:Simulate",
        "*",
      ),
    },
    Command::Files(command) => match &command.command {
      FilesSubcommand::Sync(args) => post_json(
        "/admin/v1/files/sync",
        read_json_file(&args.json)?,
        "config:SyncFiles",
        "*",
      ),
    },
  }
}

fn plan_support_bundle(args: &SupportBundleArgs) -> anyhow::Result<RequestPlan> {
  if !args.redact {
    bail!("support-bundle requires --redact");
  }
  get(
    &support_bundle_endpoint(&args.external_probes),
    "diagnostics:ReadSupportBundle",
    "support-bundle/current",
  )
}

fn plan_runtime(command: &RuntimeCommand) -> anyhow::Result<RequestPlan> {
  match &command.command {
    RuntimeSubcommand::Introspection(args) => {
      if !args.redact {
        bail!("runtime introspection requires --redact");
      }
      get(
        "/admin/v1/runtime/introspection?redact=true",
        "runtime:ReadIntrospection",
        "introspection/current",
      )
    }
  }
}

fn plan_doctor(args: &DoctorArgs) -> anyhow::Result<RequestPlan> {
  match &args.candidate {
    Some(path) => post_json(
      "/admin/v1/diagnostics/preflight",
      json!({
        "format": "toml",
        "config": read_text_file(path)?,
        "external_probes": args.external_probes,
      }),
      "diagnostics:RunPreflight",
      "preflight/candidate",
    ),
    None => get(
      "/admin/v1/diagnostics/preflight",
      "diagnostics:ReadPreflight",
      "preflight/current",
    ),
  }
}

fn support_bundle_endpoint(external_probes: &[String]) -> String {
  let mut serializer = url::form_urlencoded::Serializer::new(String::new());
  serializer.append_pair("redact", "true");
  for probe in external_probes {
    serializer.append_pair("external_probe", probe);
  }
  format!(
    "/admin/v1/diagnostics/support-bundle?{}",
    serializer.finish()
  )
}

async fn plan_config(client: &AdminClient, command: &ConfigCommand) -> anyhow::Result<RequestPlan> {
  match &command.command {
    ConfigSubcommand::Status => get("/admin/v1/config/status", "config:GetStatus", "*"),
    ConfigSubcommand::Effective => get("/admin/v1/config/effective", "config:GetEffective", "*"),
    ConfigSubcommand::Validate(args) => config_file_post(
      "/admin/v1/config/validate",
      &args.file,
      "config:Validate",
      None,
    ),
    ConfigSubcommand::Diff(args) => {
      config_file_post("/admin/v1/config/diff", &args.file, "config:Diff", None)
    }
    ConfigSubcommand::Apply(args) => {
      let etag = etag_or_current(client, &args.etag).await?;
      config_file_post(
        "/admin/v1/config/load",
        &args.file,
        "config:Load",
        Some(etag),
      )
    }
    ConfigSubcommand::Rollback(args) => {
      let etag = etag_or_current(client, &args.etag).await?;
      post_json_with_etag(
        "/admin/v1/config/rollback",
        Value::Object(Default::default()),
        "config:Rollback",
        "*",
        etag,
      )
    }
  }
}

async fn plan_tls(client: &AdminClient, command: &TlsCommand) -> anyhow::Result<RequestPlan> {
  match &command.command {
    TlsSubcommand::Status => get("/admin/v1/tls/downstream", "config:ReadDownstreamTls", "*"),
    TlsSubcommand::Reload(args) => {
      let etag = etag_or_current(client, &args.etag).await?;
      post_json_with_etag(
        "/admin/v1/tls/downstream/reload",
        Value::Object(Default::default()),
        "config:ReloadDownstreamTls",
        "*",
        etag,
      )
    }
  }
}

fn plan_lifecycle(command: &LifecycleCommand) -> anyhow::Result<RequestPlan> {
  match &command.command {
    LifecycleSubcommand::Status => get("/admin/v1/lifecycle", "lifecycle:Get", "*"),
    LifecycleSubcommand::Drain => post_empty("/admin/v1/lifecycle/drain", "lifecycle:Drain", "*"),
    LifecycleSubcommand::Undrain => {
      post_empty("/admin/v1/lifecycle/undrain", "lifecycle:Undrain", "*")
    }
  }
}

fn plan_pool(command: &PoolCommand) -> anyhow::Result<RequestPlan> {
  match &command.command {
    PoolSubcommand::List => get("/admin/v1/upstream-pools", "upstream-pool:List", "*"),
    PoolSubcommand::Get(args) => get(
      &format!("/admin/v1/upstream-pools/{}", path_id(&args.pool)?),
      "upstream-pool:Get",
      &args.pool,
    ),
    PoolSubcommand::AddServer(args) => post_json(
      &format!("/admin/v1/upstream-pools/{}/servers", path_id(&args.pool)?),
      json!({
        "id": args.id,
        "origin": args.origin,
        "state": args.state,
        "weight": args.weight,
        "max_conns": args.max_conns,
        "backup": args.backup,
      }),
      "upstream-pool:AddServer",
      &args.pool,
    ),
    PoolSubcommand::UpdateServer(args) => pool_patch(
      &args.pool,
      &args.server_id,
      json!({
        "state": args.state,
        "weight": args.weight,
        "max_conns": args.max_conns,
        "backup": args.backup,
      }),
    ),
    PoolSubcommand::RemoveServer(args) => delete(
      &format!(
        "/admin/v1/upstream-pools/{}/servers/{}",
        path_id(&args.pool)?,
        path_id(&args.server_id)?
      ),
      "upstream-pool:RemoveServer",
      &args.pool,
    ),
    PoolSubcommand::Ready(args) => pool_state(args, "ready"),
    PoolSubcommand::Drain(args) => pool_state(args, "drain"),
    PoolSubcommand::Down(args) => pool_state(args, "down"),
    PoolSubcommand::Maintenance(args) => pool_state(args, "maintenance"),
  }
}

fn plan_waf(command: &WafCommand) -> anyhow::Result<RequestPlan> {
  match &command.command {
    WafSubcommand::Hits(args) => get_with_filter(
      "/admin/v1/waf/rule-hits",
      "waf:GetRuleHits",
      "*",
      args.top.map(ResponseFilter::TopRules),
    ),
    WafSubcommand::Costs(args) => get_with_filter(
      "/admin/v1/waf/rule-costs",
      "waf:GetRuleCosts",
      "*",
      args.top.map(ResponseFilter::TopRules),
    ),
    WafSubcommand::CrsCompatibility => get(
      "/admin/v1/waf/crs/compatibility",
      "waf:GetCrsCompatibility",
      "*",
    ),
  }
}

fn plan_oxirule(command: &OxiRuleCommand) -> anyhow::Result<RequestPlan> {
  match &command.command {
    OxiRuleSubcommand::Check(args) => post_json(
      "/admin/v1/waf/oxirule/check",
      json!({
        "rule": rule_candidate(&args.rule)?,
        "groups": group_candidates(&args.group)?,
        "include_active_rules": args.include_active_rules,
      }),
      "waf:CheckOxiRule",
      "oxirule/inline",
    ),
    OxiRuleSubcommand::Cost(args) => post_json(
      "/admin/v1/waf/oxirule/cost",
      json!({
        "rule": rule_candidate(&args.rule)?,
        "groups": group_candidates(&args.group)?,
        "include_active_rules": args.include_active_rules,
      }),
      "waf:EstimateOxiRuleCost",
      "oxirule/inline",
    ),
    OxiRuleSubcommand::Test(args) => {
      oxirule_eval("/admin/v1/waf/oxirule/test", args, "waf:TestOxiRule")
    }
    OxiRuleSubcommand::Explain(args) => {
      oxirule_eval("/admin/v1/waf/oxirule/explain", args, "waf:ExplainOxiRule")
    }
    OxiRuleSubcommand::Replay(args) => post_json(
      "/admin/v1/waf/oxirule/replay",
      json!({
        "rule": rule_candidate(&args.rule)?,
        "groups": group_candidates(&args.group)?,
        "include_active_rules": args.include_active_rules,
        "input": read_text_file(&args.input)?,
      }),
      "waf:ReplayOxiRule",
      "replay/inline",
    ),
    OxiRuleSubcommand::Templates => get(
      "/admin/v1/waf/oxirule/templates",
      "waf:ListOxiRuleTemplates",
      "template/*",
    ),
    OxiRuleSubcommand::RenderTemplate(args) => post_json(
      "/admin/v1/waf/oxirule/templates/render",
      json!({ "name": args.name, "variables": parse_vars(&args.vars)? }),
      "waf:RenderOxiRuleTemplate",
      &format!("template/{}", args.name),
    ),
    OxiRuleSubcommand::FalsePositive(args) => post_json(
      "/admin/v1/waf/oxirule/false-positive",
      json!({ "finding": read_json_or_inline(&args.input)? }),
      "waf:PlanOxiRuleFalsePositive",
      "false-positive/inline",
    ),
  }
}

fn plan_dynamic_policy(command: &DynamicPolicyCommand) -> anyhow::Result<RequestPlan> {
  match &command.command {
    DynamicPolicySubcommand::List => get("/admin/v1/dynamic-policies", "dynamic-policy:List", "*"),
    DynamicPolicySubcommand::Get(args) => get(
      &format!("/admin/v1/dynamic-policies/{}", args.id),
      "dynamic-policy:Get",
      &args.id.to_string(),
    ),
    DynamicPolicySubcommand::Create(args) => post_json(
      "/admin/v1/dynamic-policies",
      read_json_file(&args.json)?,
      "dynamic-policy:Create",
      "*",
    ),
    DynamicPolicySubcommand::Patch(args) => patch_json(
      &format!("/admin/v1/dynamic-policies/{}", args.id),
      read_json_file(&args.json)?,
      "dynamic-policy:Update",
      &args.id.to_string(),
    ),
    DynamicPolicySubcommand::Delete(args) => delete(
      &format!("/admin/v1/dynamic-policies/{}", args.id),
      "dynamic-policy:Delete",
      &args.id.to_string(),
    ),
    DynamicPolicySubcommand::Export => get(
      "/admin/v1/dynamic-policies/export",
      "dynamic-policy:Export",
      "*",
    ),
    DynamicPolicySubcommand::Import(args) => post_json(
      "/admin/v1/dynamic-policies/import",
      read_json_file(&args.json)?,
      "dynamic-policy:Import",
      "*",
    ),
  }
}

fn plan_mitigation(action: &str, args: &MitigationArgs) -> anyhow::Result<RequestPlan> {
  let (subject_type, values) = match &args.subject {
    MitigationSubject::Ip(values) => ("client_ip", values),
    MitigationSubject::Cidr(values) => ("client_ip_cidr", values),
  };
  let name = values
    .name
    .clone()
    .unwrap_or_else(|| mitigation_name(action, subject_type, &values.subject));
  post_json(
    "/admin/v1/dynamic-policies",
    json!({
      "enabled": true,
      "priority": values.priority,
      "source": "oxibeltctl",
      "name": name,
      "action": action,
      "subject_type": subject_type,
      "subject": values.subject,
      "reason": values.reason,
      "ttl_seconds": values.ttl,
      "mode": "enforce",
    }),
    "dynamic-policy:Create",
    "*",
  )
}

fn plan_rate_limit(args: &RateLimitArgs) -> anyhow::Result<RequestPlan> {
  let (subject_type, values) = match &args.subject {
    RateLimitSubject::Ip(values) => ("client_ip", values),
    RateLimitSubject::Cidr(values) => ("client_ip_cidr", values),
  };
  let name = values
    .name
    .clone()
    .unwrap_or_else(|| mitigation_name("rate-limit", subject_type, &values.subject));
  post_json(
    "/admin/v1/dynamic-policies",
    json!({
      "enabled": true,
      "priority": values.priority,
      "source": "oxibeltctl",
      "name": name,
      "action": "rate_limit",
      "subject_type": subject_type,
      "subject": values.subject,
      "rate": values.rate,
      "burst": values.burst,
      "reason": values.reason,
      "ttl_seconds": values.ttl,
      "mode": "enforce",
    }),
    "dynamic-policy:Create",
    "*",
  )
}

fn plan_cache(command: &CacheCommand) -> anyhow::Result<RequestPlan> {
  match &command.command {
    CacheSubcommand::Warm(args) => post_json(
      "/admin/v1/cache/warm",
      read_json_file(&args.json)?,
      "cache:Warm",
      "policy/*",
    ),
    CacheSubcommand::KeyExplain(args) => post_json(
      "/admin/v1/cache/key-explain",
      read_json_file(&args.json)?,
      "cache:ExplainKey",
      "policy/*",
    ),
    CacheSubcommand::Purge(purge) => plan_cache_purge(purge),
  }
}

fn plan_cache_purge(purge: &CachePurgeCommand) -> anyhow::Result<RequestPlan> {
  match &purge.command {
    CachePurgeSubcommand::Exact(args) => cache_purge(
      json!({
        "type": "exact",
        "policy": args.policy,
        "scheme": args.scheme,
        "host": args.host,
        "uri": args.uri,
        "partition": args.partition,
      }),
      "cache:PurgeObject",
      &args.policy,
    ),
    CachePurgeSubcommand::Prefix(args) => cache_purge(
      json!({
        "type": "prefix",
        "policy": args.policy,
        "scheme": args.scheme,
        "host": args.host,
        "path_prefix": args.path_prefix,
        "partition": args.partition,
      }),
      "cache:PurgePrefix",
      &args.policy,
    ),
    CachePurgeSubcommand::Tag(args) => cache_purge(
      json!({
        "type": "tag",
        "policy": args.policy,
        "scheme": args.scheme,
        "host": args.host,
        "tag": args.tag,
        "partition": args.partition,
      }),
      "cache:PurgeTag",
      &args.policy,
    ),
  }
}

fn plan_ipm(command: &IpmCommand) -> anyhow::Result<RequestPlan> {
  match &command.command {
    IpmSubcommand::List(args) => match &args.target {
      IpmListTarget::Principals => get("/admin/v1/ipm/principals", "ipm:ListPrincipals", "*"),
      IpmListTarget::Credentials => get("/admin/v1/ipm/credentials", "ipm:ListCredentials", "*"),
      IpmListTarget::Policies => get("/admin/v1/ipm/policies", "ipm:ListPolicies", "*"),
      IpmListTarget::Bindings => get("/admin/v1/ipm/bindings", "ipm:ListBindings", "*"),
    },
    IpmSubcommand::Simulate(args) => post_json(
      "/admin/v1/ipm/simulate",
      json!({ "action": args.action, "resource": args.resource }),
      "ipm:Simulate",
      "*",
    ),
  }
}

async fn current_etag(client: &AdminClient) -> anyhow::Result<String> {
  let response = client
    .request_json(Method::GET, "/admin/v1/config/status", None, None)
    .await?;
  if !response.status.is_success() {
    bail!("failed to fetch current config ETag: {}", response.status);
  }
  let value =
    serde_json::from_slice::<Value>(&response.body).context("config status was not JSON")?;
  value
    .get("etag")
    .and_then(Value::as_str)
    .map(str::to_string)
    .context("config status response did not include etag")
}

async fn etag_or_current(client: &AdminClient, etag: &Option<String>) -> anyhow::Result<String> {
  match etag {
    Some(etag) => Ok(etag.clone()),
    None => current_etag(client).await,
  }
}

fn get(endpoint: &str, action: &str, resource: &str) -> anyhow::Result<RequestPlan> {
  get_with_filter(endpoint, action, resource, None)
}

fn get_with_filter(
  endpoint: &str,
  action: &str,
  resource: &str,
  filter: Option<ResponseFilter>,
) -> anyhow::Result<RequestPlan> {
  Ok(RequestPlan {
    method: Method::GET,
    endpoint: endpoint.to_string(),
    body: None,
    if_match: None,
    permission: permission(action, resource),
    filter: filter.unwrap_or(ResponseFilter::None),
  })
}

fn post_empty(endpoint: &str, action: &str, resource: &str) -> anyhow::Result<RequestPlan> {
  post_json(
    endpoint,
    Value::Object(Default::default()),
    action,
    resource,
  )
}

fn post_json(
  endpoint: &str,
  body: Value,
  action: &str,
  resource: &str,
) -> anyhow::Result<RequestPlan> {
  Ok(RequestPlan {
    method: Method::POST,
    endpoint: endpoint.to_string(),
    body: Some(body),
    if_match: None,
    permission: permission(action, resource),
    filter: ResponseFilter::None,
  })
}

fn post_json_with_etag(
  endpoint: &str,
  body: Value,
  action: &str,
  resource: &str,
  etag: String,
) -> anyhow::Result<RequestPlan> {
  let mut plan = post_json(endpoint, body, action, resource)?;
  plan.if_match = Some(etag);
  Ok(plan)
}

fn patch_json(
  endpoint: &str,
  body: Value,
  action: &str,
  resource: &str,
) -> anyhow::Result<RequestPlan> {
  Ok(RequestPlan {
    method: Method::PATCH,
    endpoint: endpoint.to_string(),
    body: Some(body),
    if_match: None,
    permission: permission(action, resource),
    filter: ResponseFilter::None,
  })
}

fn delete(endpoint: &str, action: &str, resource: &str) -> anyhow::Result<RequestPlan> {
  Ok(RequestPlan {
    method: Method::DELETE,
    endpoint: endpoint.to_string(),
    body: None,
    if_match: None,
    permission: permission(action, resource),
    filter: ResponseFilter::None,
  })
}

fn config_file_post(
  endpoint: &str,
  file: &Path,
  action: &str,
  etag: Option<String>,
) -> anyhow::Result<RequestPlan> {
  let mut plan = post_json(
    endpoint,
    json!({ "format": "toml", "config": read_text_file(file)? }),
    action,
    "*",
  )?;
  plan.if_match = etag;
  Ok(plan)
}

fn pool_patch(pool: &str, server_id: &str, body: Value) -> anyhow::Result<RequestPlan> {
  patch_json(
    &format!(
      "/admin/v1/upstream-pools/{}/servers/{}",
      path_id(pool)?,
      path_id(server_id)?
    ),
    remove_nulls(body),
    "upstream-pool:UpdateServer",
    pool,
  )
}

fn pool_state(args: &PoolServerArg, state: &str) -> anyhow::Result<RequestPlan> {
  pool_patch(&args.pool, &args.server_id, json!({ "state": state }))
}

fn oxirule_eval(
  endpoint: &str,
  args: &OxiRuleFixtureArgs,
  action: &str,
) -> anyhow::Result<RequestPlan> {
  post_json(
    endpoint,
    json!({
      "rule": rule_candidate(&args.rule)?,
      "groups": group_candidates(&args.group)?,
      "include_active_rules": args.include_active_rules,
      "fixture": read_json_file(&args.fixture)?,
    }),
    action,
    "oxirule/inline",
  )
}

fn cache_purge(body: Value, action: &str, policy: &str) -> anyhow::Result<RequestPlan> {
  post_json(
    "/admin/v1/cache/purge",
    remove_nulls(body),
    action,
    &format!("policy/{policy}"),
  )
}

fn permission(action: &str, resource: &str) -> PermissionHint {
  PermissionHint {
    action: action.to_string(),
    resource: resource.to_string(),
  }
}

fn read_text_file(path: &Path) -> anyhow::Result<String> {
  std::fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
}

fn read_json_file(path: &Path) -> anyhow::Result<Value> {
  let raw = read_text_file(path)?;
  serde_json::from_str(&raw).with_context(|| format!("failed to parse JSON {}", path.display()))
}

fn read_json_or_inline(input: &str) -> anyhow::Result<Value> {
  let path = Path::new(input);
  if path.exists() {
    read_json_file(path)
  } else {
    serde_json::from_str(input).context("failed to parse inline JSON")
  }
}

fn rule_candidate(path: &Path) -> anyhow::Result<Value> {
  Ok(json!({
    "content": read_text_file(path)?,
    "name": path.file_name().and_then(|name| name.to_str()).unwrap_or("inline"),
  }))
}

fn group_candidates(paths: &[PathBuf]) -> anyhow::Result<Vec<Value>> {
  paths
    .iter()
    .map(|path| {
      Ok(json!({
        "content": read_text_file(path)?,
        "name": path.file_name().and_then(|name| name.to_str()).unwrap_or("group"),
      }))
    })
    .collect()
}

fn parse_vars(vars: &[String]) -> anyhow::Result<serde_json::Map<String, Value>> {
  let mut map = serde_json::Map::new();
  for var in vars {
    let Some((key, value)) = var.split_once('=') else {
      bail!("--var must use KEY=VALUE");
    };
    if key.trim().is_empty() {
      bail!("--var key must not be empty");
    }
    map.insert(key.to_string(), Value::String(value.to_string()));
  }
  Ok(map)
}

fn remove_nulls(mut value: Value) -> Value {
  if let Value::Object(map) = &mut value {
    map.retain(|_, value| !value.is_null());
  }
  value
}

fn path_id(value: &str) -> anyhow::Result<&str> {
  if value.is_empty()
    || value
      .chars()
      .any(|character| matches!(character, '/' | '?' | '#'))
  {
    bail!("Admin path identifier must not be empty or contain '/', '?', or '#'");
  }
  Ok(value)
}

fn mitigation_name(action: &str, subject_type: &str, subject: &str) -> String {
  let sanitized = subject
    .chars()
    .map(|character| {
      if character.is_ascii_alphanumeric() {
        character
      } else {
        '-'
      }
    })
    .collect::<String>();
  format!("{action}-{subject_type}-{sanitized}")
}

#[cfg(test)]
#[path = "plan_tests.rs"]
mod tests;

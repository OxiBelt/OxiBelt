use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use http::Method;
use oxibelt::admin_client::AdminClient;
use serde_json::{Value, json};

use super::cli::*;
use crate::resource_hint;

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
  pub(crate) resources: Vec<String>,
}

impl PermissionHint {
  pub(crate) fn new(action: &str, resource: &str) -> Self {
    Self::with_resources(action, vec![resource.to_string()])
  }

  pub(crate) fn with_resources(action: &str, resources: Vec<String>) -> Self {
    let mut resources = resource_hint::unique(resources);
    if resources.is_empty() {
      resources.push("*".to_string());
    }
    Self {
      action: action.to_string(),
      resources,
    }
  }
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
    Command::Audit(args) => {
      if args.command.is_some() {
        bail!("Admin audit verifier must run before Admin request planning");
      }
      get(
        &admin_audit_endpoint(args),
        "admin:ReadAudit",
        "audit/admin",
      )
    }
    Command::Doctor(args) => crate::doctor_plan::plan_doctor(args),
    Command::SupportBundle(args) => plan_support_bundle(args),
    Command::Runtime(command) => plan_runtime(command),
    Command::Config(command) => plan_config(client, command).await,
    Command::Tls(command) => plan_tls(client, command).await,
    Command::Lifecycle(command) => plan_lifecycle(command),
    Command::Pool(command) => crate::pool_plan::plan_pool(client, command).await,
    Command::Waf(command) => plan_waf(command),
    Command::OxiRule(command) => plan_oxirule(command),
    Command::Rulepack(command) => crate::rulepack::plan_rulepack(client, command).await,
    Command::DynamicPolicy(command) => {
      crate::dynamic_policy_plan::plan_dynamic_policy(client, command).await
    }
    Command::Block(args) => crate::dynamic_policy_plan::plan_mitigation("reject", args),
    Command::Allow(args) => crate::dynamic_policy_plan::plan_mitigation("allow", args),
    Command::SilentClose(args) => crate::dynamic_policy_plan::plan_mitigation("silent_close", args),
    Command::Challenge(args) => crate::dynamic_policy_plan::plan_challenge(args),
    Command::RateLimit(args) => crate::dynamic_policy_plan::plan_rate_limit(args),
    Command::Mitigate(args) => {
      let catalog =
        crate::profile_catalog::load_mitigation_profile_catalog(args, client.timeout()).await?;
      crate::dynamic_policy_plan::plan_mitigate(args, &catalog)
    }
    Command::Cache(command) => plan_cache(command),
    Command::Ipm(command) => crate::ipm_plan::plan_ipm(client, command).await,
    Command::Membership(command) => plan_membership(command),
    Command::SupplyChain(_) | Command::Ct(_) => bail!("command is local-only"),
    Command::Auth(command) => match &command.command {
      AuthSubcommand::Check(args) => crate::ipm_plan::plan_auth_check(args),
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

fn plan_membership(command: &MembershipCommand) -> anyhow::Result<RequestPlan> {
  match &command.command {
    MembershipSubcommand::Status => get(
      "/admin/v1/membership",
      "membership:GetStatus",
      "membership/current",
    ),
    MembershipSubcommand::Propose(args) => with_etag(
      post_json(
        "/admin/v1/membership/transitions",
        read_json_file(&args.file)?,
        "membership:Propose",
        "membership/current",
      )?,
      args.etag.clone(),
    ),
    MembershipSubcommand::Activate(args) => with_etag(
      post_json(
        &format!(
          "/admin/v1/membership/transitions/{}/activate",
          path_component(&args.transition_id)?
        ),
        read_json_file(&args.file)?,
        "membership:Activate",
        &format!("membership/transition/{}", args.transition_id),
      )?,
      args.etag.clone(),
    ),
    MembershipSubcommand::Cancel(args) => with_etag(
      post_json(
        &format!(
          "/admin/v1/membership/transitions/{}/cancel",
          path_component(&args.transition_id)?
        ),
        read_json_file(&args.file)?,
        "membership:Cancel",
        &format!("membership/transition/{}", args.transition_id),
      )?,
      args.etag.clone(),
    ),
    MembershipSubcommand::Catchup(args) => get(
      &format!(
        "/admin/v1/membership/transitions/{}/catchup",
        path_component(&args.transition_id)?
      ),
      "membership:GetCatchUp",
      &format!("membership/transition/{}", args.transition_id),
    ),
    MembershipSubcommand::Readiness(args) => post_json(
      &format!(
        "/admin/v1/membership/transitions/{}/readiness",
        path_component(&args.transition_id)?
      ),
      read_json_file(&args.file)?,
      "membership:SubmitReadiness",
      &format!("membership/transition/{}", args.transition_id),
    ),
  }
}

fn path_component(value: &str) -> anyhow::Result<String> {
  if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
    bail!("path identifier is invalid");
  }
  Ok(url::form_urlencoded::byte_serialize(value.as_bytes()).collect())
}

fn admin_audit_endpoint(args: &AdminAuditArgs) -> String {
  let mut serializer = url::form_urlencoded::Serializer::new(String::new());
  serializer.append_pair("limit", &args.limit.to_string());
  if let Some(outcome) = &args.outcome {
    serializer.append_pair("outcome", outcome);
  }
  if let Some(actor) = &args.actor {
    serializer.append_pair("actor", actor);
  }
  if let Some(principal) = &args.principal {
    serializer.append_pair("principal", principal);
  }
  if let Some(service) = &args.service {
    serializer.append_pair("service", service);
  }
  if let Some(operation) = &args.operation {
    serializer.append_pair("operation", operation);
  }
  if let Some(request_id) = &args.request_id {
    serializer.append_pair("request_id", request_id);
  }
  if let Some(path_prefix) = &args.path_prefix {
    serializer.append_pair("path_prefix", path_prefix);
  }
  if let Some(before_id) = args.before_id {
    serializer.append_pair("before_id", &before_id.to_string());
  }
  format!("/admin/v1/audit?{}", serializer.finish())
}

pub(crate) fn list_endpoint(base: &str, args: &ListQueryArgs) -> anyhow::Result<String> {
  let mut serializer = url::form_urlencoded::Serializer::new(String::new());
  if let Some(limit) = args.limit {
    serializer.append_pair("limit", &limit.to_string());
  }
  if let Some(cursor) = &args.cursor {
    serializer.append_pair("cursor", cursor);
  }
  if let Some(sort) = &args.sort {
    serializer.append_pair("sort", sort);
  }
  if let Some(order) = &args.order {
    serializer.append_pair("order", order);
  }
  for filter in &args.filters {
    let (key, value) = filter
      .split_once('=')
      .ok_or_else(|| anyhow::anyhow!("--filter must use KEY=VALUE"))?;
    if key.is_empty() {
      bail!("--filter key must not be empty");
    }
    serializer.append_pair(&format!("filter[{key}]"), value);
  }
  let query = serializer.finish();
  if query.is_empty() {
    Ok(base.to_string())
  } else {
    Ok(format!("{base}?{query}"))
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
    ConfigSubcommand::Explain(args) if args.file.is_none() => {
      if args.field_path.trim().is_empty() {
        bail!("config explain field path must not be empty");
      }
      let mut query = url::form_urlencoded::Serializer::new(String::new());
      query.append_pair("field_path", &args.field_path);
      get(
        &format!("/admin/v1/config/explain?{}", query.finish()),
        "config:GetEffective",
        "*",
      )
    }
    ConfigSubcommand::Diff(args) => config_file_post(
      "/admin/v1/config/diff",
      &args.file,
      "config:DiffSecrets",
      None,
    ),
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
    ConfigSubcommand::Schema(_)
    | ConfigSubcommand::Validate(_)
    | ConfigSubcommand::FilesystemAccess(_)
    | ConfigSubcommand::Explain(_)
    | ConfigSubcommand::Migrate(_)
    | ConfigSubcommand::Plan(_)
    | ConfigSubcommand::LbPolicyCompat(_) => bail!("requested config command is local-only"),
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

fn plan_cache(command: &CacheCommand) -> anyhow::Result<RequestPlan> {
  match &command.command {
    CacheSubcommand::Warm(args) => {
      let body = read_json_file(&args.json)?;
      let permission =
        PermissionHint::with_resources("cache:Warm", resource_hint::cache_warm_target(&body));
      post_json_with_permission("/admin/v1/cache/warm", body, permission)
    }
    CacheSubcommand::KeyExplain(args) => {
      let body = read_json_file(&args.json)?;
      let permission = PermissionHint::with_resources(
        "cache:ExplainKey",
        resource_hint::cache_key_explain_target(&body),
      );
      post_json_with_permission("/admin/v1/cache/key-explain", body, permission)
    }
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
      Some(&args.host),
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
      args.host.as_deref(),
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
      args.host.as_deref(),
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

pub(crate) fn get(endpoint: &str, action: &str, resource: &str) -> anyhow::Result<RequestPlan> {
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

pub(crate) fn post_json(
  endpoint: &str,
  body: Value,
  action: &str,
  resource: &str,
) -> anyhow::Result<RequestPlan> {
  post_json_with_permission(endpoint, body, PermissionHint::new(action, resource))
}

pub(crate) fn post_json_with_permission(
  endpoint: &str,
  body: Value,
  permission: PermissionHint,
) -> anyhow::Result<RequestPlan> {
  Ok(RequestPlan {
    method: Method::POST,
    endpoint: endpoint.to_string(),
    body: Some(body),
    if_match: None,
    permission,
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

pub(crate) fn with_etag(mut plan: RequestPlan, etag: String) -> anyhow::Result<RequestPlan> {
  plan.if_match = Some(etag);
  Ok(plan)
}

pub(crate) fn patch_json(
  endpoint: &str,
  body: Value,
  action: &str,
  resource: &str,
) -> anyhow::Result<RequestPlan> {
  patch_json_with_permission(endpoint, body, PermissionHint::new(action, resource))
}

pub(crate) fn patch_json_with_permission(
  endpoint: &str,
  body: Value,
  permission: PermissionHint,
) -> anyhow::Result<RequestPlan> {
  Ok(RequestPlan {
    method: Method::PATCH,
    endpoint: endpoint.to_string(),
    body: Some(body),
    if_match: None,
    permission,
    filter: ResponseFilter::None,
  })
}

pub(crate) fn delete(endpoint: &str, action: &str, resource: &str) -> anyhow::Result<RequestPlan> {
  delete_with_permission(endpoint, PermissionHint::new(action, resource))
}

pub(crate) fn delete_with_permission(
  endpoint: &str,
  permission: PermissionHint,
) -> anyhow::Result<RequestPlan> {
  Ok(RequestPlan {
    method: Method::DELETE,
    endpoint: endpoint.to_string(),
    body: None,
    if_match: None,
    permission,
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

fn cache_purge(
  body: Value,
  action: &str,
  policy: &str,
  host: Option<&str>,
) -> anyhow::Result<RequestPlan> {
  post_json_with_permission(
    "/admin/v1/cache/purge",
    remove_nulls(body),
    PermissionHint::with_resources(action, resource_hint::cache_target(policy, host)),
  )
}

fn permission(action: &str, resource: &str) -> PermissionHint {
  PermissionHint::new(action, resource)
}

fn read_text_file(path: &Path) -> anyhow::Result<String> {
  std::fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
}

pub(crate) fn read_json_file(path: &Path) -> anyhow::Result<Value> {
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

pub(crate) fn remove_nulls(mut value: Value) -> Value {
  if let Value::Object(map) = &mut value {
    map.retain(|_, value| !value.is_null());
  }
  value
}

pub(crate) fn path_id(value: &str) -> anyhow::Result<&str> {
  if value.is_empty()
    || value
      .chars()
      .any(|character| matches!(character, '/' | '?' | '#'))
  {
    bail!("Admin path identifier must not be empty or contain '/', '?', or '#'");
  }
  Ok(value)
}

#[cfg(test)]
#[path = "etag_plan_tests.rs"]
mod etag_plan_tests;

#[cfg(test)]
#[path = "plan_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "resource_hint_plan_tests.rs"]
mod resource_hint_plan_tests;

#[cfg(test)]
#[path = "ipm_plan_tests.rs"]
mod ipm_plan_tests;

#[cfg(test)]
#[path = "profile_catalog_tests.rs"]
mod profile_catalog_tests;

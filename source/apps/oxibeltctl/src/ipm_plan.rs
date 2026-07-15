use anyhow::{Context, bail};
use http::Method;
use oxibelt::admin_client::AdminClient;
use serde_json::{Map, Value, json};

use crate::cli::*;
use crate::plan::{
  PermissionHint, RequestPlan, delete, delete_with_permission, get, list_endpoint, patch_json,
  patch_json_with_permission, post_json, post_json_with_permission, read_json_file,
};
use crate::resource_hint;

pub(crate) async fn plan_ipm(
  client: &AdminClient,
  command: &IpmCommand,
) -> anyhow::Result<RequestPlan> {
  match &command.command {
    IpmSubcommand::Status => get(
      "/admin/v1/ipm/status",
      "ipm:GetStatus",
      resource_hint::ipm_status(),
    ),
    IpmSubcommand::List(args) => plan_legacy_list(args),
    IpmSubcommand::Simulate(args) => plan_ipm_simulate(args),
    IpmSubcommand::Principal(command) => plan_principal(client, command).await,
    IpmSubcommand::Credential(command) => plan_credential(client, command).await,
    IpmSubcommand::Policy(command) => plan_policy(client, command).await,
    IpmSubcommand::Binding(command) => plan_binding(client, command).await,
    IpmSubcommand::Audit(args) => get(
      &audit_endpoint(args),
      "ipm:ReadAudit",
      resource_hint::ipm_audit(),
    ),
  }
}

pub(crate) fn plan_auth_check(args: &AuthCheckArgs) -> anyhow::Result<RequestPlan> {
  post_json(
    "/admin/v1/ipm/simulate",
    auth_check_body(args)?,
    "ipm:SimulateSelf",
    resource_hint::ipm_simulation(),
  )
}

fn plan_ipm_simulate(args: &IpmSimulateArgs) -> anyhow::Result<RequestPlan> {
  let overlay = args.overlay.as_deref().map(read_json_file).transpose()?;
  let body = ipm_simulate_body(args, overlay.clone())?;
  let permission = ipm_simulate_permission(args, overlay.as_ref());
  post_json_with_permission("/admin/v1/ipm/simulate", body, permission)
}

fn plan_legacy_list(args: &IpmListArgs) -> anyhow::Result<RequestPlan> {
  match &args.target {
    IpmListTarget::Principals(list) => get(
      &list_endpoint("/admin/v1/ipm/principals", list)?,
      "ipm:ListPrincipals",
      "principal/*",
    ),
    IpmListTarget::Credentials(list) => get(
      &list_endpoint("/admin/v1/ipm/credentials", list)?,
      "ipm:ListCredentials",
      "credential/*",
    ),
    IpmListTarget::Policies(list) => get(
      &list_endpoint("/admin/v1/ipm/policies", list)?,
      "ipm:ListPolicies",
      "policy/*",
    ),
    IpmListTarget::Bindings(list) => get(
      &list_endpoint("/admin/v1/ipm/bindings", list)?,
      "ipm:ListBindings",
      "binding/*",
    ),
  }
}

async fn plan_principal(
  client: &AdminClient,
  command: &IpmPrincipalCommand,
) -> anyhow::Result<RequestPlan> {
  match &command.command {
    IpmPrincipalSubcommand::List(args) => get(
      &list_endpoint("/admin/v1/ipm/principals", args)?,
      "ipm:ListPrincipals",
      "principal/*",
    ),
    IpmPrincipalSubcommand::Get(args) => get(
      &format!("/admin/v1/ipm/principals/{}", path_id(&args.id)?),
      "ipm:GetPrincipal",
      &resource_hint::ipm_principal(&args.id),
    ),
    IpmPrincipalSubcommand::Create(args) => {
      let etag = ipm_etag_or_current(client, &args.etag).await?;
      with_etag(
        post_json(
          "/admin/v1/ipm/principals",
          json!({
            "id": args.id,
            "subject": args.subject,
            "groups": args.groups,
            "enabled": !args.disabled,
          }),
          "ipm:CreatePrincipal",
          &resource_hint::ipm_principal(&args.id),
        )?,
        etag,
      )
    }
    IpmPrincipalSubcommand::Patch(args) => {
      let etag = ipm_etag_or_current(client, &args.etag).await?;
      let groups = if args.groups.is_empty() {
        Value::Null
      } else {
        json!(args.groups)
      };
      with_etag(
        patch_json(
          &format!("/admin/v1/ipm/principals/{}", path_id(&args.id)?),
          remove_nulls(json!({
            "subject": args.subject,
            "groups": groups,
            "enabled": enabled_flag(args.enable, args.disable),
          })),
          "ipm:UpdatePrincipal",
          &resource_hint::ipm_principal(&args.id),
        )?,
        etag,
      )
    }
    IpmPrincipalSubcommand::Delete(args) => {
      let etag = ipm_etag_or_current(client, &args.etag).await?;
      with_etag(
        delete(
          &format!("/admin/v1/ipm/principals/{}", path_id(&args.id)?),
          "ipm:DeletePrincipal",
          &resource_hint::ipm_principal(&args.id),
        )?,
        etag,
      )
    }
  }
}

async fn plan_credential(
  client: &AdminClient,
  command: &IpmCredentialCommand,
) -> anyhow::Result<RequestPlan> {
  match &command.command {
    IpmCredentialSubcommand::List(args) => get(
      &list_endpoint("/admin/v1/ipm/credentials", args)?,
      "ipm:ListCredentials",
      "credential/*",
    ),
    IpmCredentialSubcommand::Get(args) => get(
      &format!("/admin/v1/ipm/credentials/{}", path_id(&args.id)?),
      "ipm:GetCredential",
      &resource_hint::ipm_credential(&args.id),
    ),
    IpmCredentialSubcommand::Create(args) => {
      let etag = ipm_etag_or_current(client, &args.etag).await?;
      with_etag(
        post_json_with_permission(
          "/admin/v1/ipm/credentials",
          remove_nulls(json!({
            "id": args.id,
            "principal": args.principal,
            "ttl_seconds": args.expires,
            "no_expiry": args.no_expiry,
          })),
          PermissionHint::with_resources(
            "ipm:CreateCredential",
            vec![
              resource_hint::ipm_credential(&args.id),
              resource_hint::ipm_principal(&args.principal),
            ],
          ),
        )?,
        etag,
      )
    }
    IpmCredentialSubcommand::Patch(args) => {
      let etag = ipm_etag_or_current(client, &args.etag).await?;
      with_etag(
        patch_json_with_permission(
          &format!("/admin/v1/ipm/credentials/{}", path_id(&args.id)?),
          remove_nulls(json!({
            "principal": args.principal,
            "enabled": enabled_flag(args.enable, args.disable),
            "ttl_seconds": args.expires,
          })),
          PermissionHint::with_resources(
            "ipm:UpdateCredential",
            credential_patch_resources(&args.id, args.principal.as_deref()),
          ),
        )?,
        etag,
      )
    }
    IpmCredentialSubcommand::Rotate(args) => {
      let etag = ipm_etag_or_current(client, &args.etag).await?;
      with_etag(
        post_json(
          &format!("/admin/v1/ipm/credentials/{}/rotate", path_id(&args.id)?),
          remove_nulls(json!({
            "overlap_seconds": args.overlap,
            "ttl_seconds": args.expires,
            "no_expiry": args.no_expiry,
          })),
          "ipm:RotateCredential",
          &resource_hint::ipm_credential(&args.id),
        )?,
        etag,
      )
    }
    IpmCredentialSubcommand::Revoke(args) => {
      let etag = ipm_etag_or_current(client, &args.etag).await?;
      with_etag(
        post_json(
          &format!("/admin/v1/ipm/credentials/{}/revoke", path_id(&args.id)?),
          remove_nulls(json!({ "reason": args.reason })),
          "ipm:RevokeCredential",
          &resource_hint::ipm_credential(&args.id),
        )?,
        etag,
      )
    }
    IpmCredentialSubcommand::Delete(args) => {
      let etag = ipm_etag_or_current(client, &args.etag).await?;
      with_etag(
        delete(
          &format!("/admin/v1/ipm/credentials/{}", path_id(&args.id)?),
          "ipm:DeleteCredential",
          &resource_hint::ipm_credential(&args.id),
        )?,
        etag,
      )
    }
  }
}

async fn plan_policy(
  client: &AdminClient,
  command: &IpmPolicyCommand,
) -> anyhow::Result<RequestPlan> {
  match &command.command {
    IpmPolicySubcommand::List(args) => get(
      &list_endpoint("/admin/v1/ipm/policies", args)?,
      "ipm:ListPolicies",
      "policy/*",
    ),
    IpmPolicySubcommand::Get(args) => get(
      &format!("/admin/v1/ipm/policies/{}", path_id(&args.id)?),
      "ipm:GetPolicy",
      &resource_hint::ipm_policy(&args.id),
    ),
    IpmPolicySubcommand::Create(args) => {
      let etag = ipm_etag_or_current(client, &args.etag).await?;
      let body = read_json_file(&args.json)?;
      let resource = resource_hint::ipm_policy_create_target(&body);
      with_etag(
        post_json_with_permission(
          "/admin/v1/ipm/policies",
          body,
          PermissionHint::new("ipm:CreatePolicy", &resource),
        )?,
        etag,
      )
    }
    IpmPolicySubcommand::Patch(args) => {
      let etag = ipm_etag_or_current(client, &args.etag).await?;
      with_etag(
        patch_json(
          &format!("/admin/v1/ipm/policies/{}", path_id(&args.id)?),
          read_json_file(&args.json)?,
          "ipm:UpdatePolicy",
          &resource_hint::ipm_policy(&args.id),
        )?,
        etag,
      )
    }
    IpmPolicySubcommand::Delete(args) => {
      let etag = ipm_etag_or_current(client, &args.etag).await?;
      with_etag(
        delete(
          &format!("/admin/v1/ipm/policies/{}", path_id(&args.id)?),
          "ipm:DeletePolicy",
          &resource_hint::ipm_policy(&args.id),
        )?,
        etag,
      )
    }
  }
}

async fn plan_binding(
  client: &AdminClient,
  command: &IpmBindingCommand,
) -> anyhow::Result<RequestPlan> {
  match &command.command {
    IpmBindingSubcommand::List(args) => get(
      &list_endpoint("/admin/v1/ipm/bindings", args)?,
      "ipm:ListBindings",
      "binding/*",
    ),
    IpmBindingSubcommand::Create(args) => {
      let etag = ipm_etag_or_current(client, &args.etag).await?;
      with_etag(
        post_json_with_permission(
          "/admin/v1/ipm/bindings",
          remove_nulls(json!({
            "id": args.id,
            "principal": args.principal,
            "group": args.group,
            "policy": args.policy,
            "enabled": !args.disabled,
          })),
          PermissionHint::with_resources(
            "ipm:CreateBinding",
            resource_hint::ipm_binding_create_target(
              args.id.as_deref(),
              args.principal.as_deref(),
              args.group.as_deref(),
              &args.policy,
            ),
          ),
        )?,
        etag,
      )
    }
    IpmBindingSubcommand::Delete(args) => {
      let etag = ipm_etag_or_current(client, &args.etag).await?;
      with_etag(
        delete_with_permission(
          &format!("/admin/v1/ipm/bindings/{}", path_id(&args.id)?),
          PermissionHint::new("ipm:DeleteBinding", &resource_hint::ipm_binding(&args.id)),
        )?,
        etag,
      )
    }
  }
}

async fn ipm_etag_or_current(
  client: &AdminClient,
  etag: &Option<String>,
) -> anyhow::Result<String> {
  match etag {
    Some(etag) => Ok(etag.clone()),
    None => current_ipm_etag(client).await,
  }
}

async fn current_ipm_etag(client: &AdminClient) -> anyhow::Result<String> {
  let response = client
    .request_json(Method::GET, "/admin/v1/ipm/status", None, None)
    .await?;
  if !response.status.is_success() {
    bail!("failed to fetch current IPM ETag: {}", response.status);
  }
  let value = serde_json::from_slice::<Value>(&response.body).context("IPM status was not JSON")?;
  value
    .get("etag")
    .and_then(Value::as_str)
    .map(str::to_string)
    .context("IPM status response did not include etag")
}

fn with_etag(mut plan: RequestPlan, etag: String) -> anyhow::Result<RequestPlan> {
  plan.if_match = Some(etag);
  Ok(plan)
}

fn enabled_flag(enable: bool, disable: bool) -> Option<bool> {
  match (enable, disable) {
    (true, false) => Some(true),
    (false, true) => Some(false),
    _ => None,
  }
}

fn credential_patch_resources(id: &str, principal: Option<&str>) -> Vec<String> {
  let mut resources = vec![resource_hint::ipm_credential(id)];
  if let Some(principal) = principal {
    resources.push(resource_hint::ipm_principal(principal));
  }
  resources
}

fn auth_check_body(args: &AuthCheckArgs) -> anyhow::Result<Value> {
  let mut body = Map::new();
  body.insert("action".to_string(), json!(args.action));
  body.insert("resource".to_string(), json!(args.resource));
  if let Some(context) = simulation_context_body(
    args.source_ip.as_ref().map(ToString::to_string),
    args.method.as_ref(),
    args.host.as_ref(),
    args.path.as_ref(),
    args.route.as_ref(),
    args.protocol.as_ref(),
    &args.claims,
  )? {
    body.insert("context".to_string(), context);
  }
  Ok(Value::Object(body))
}

fn ipm_simulate_body(args: &IpmSimulateArgs, overlay: Option<Value>) -> anyhow::Result<Value> {
  let mut body = Map::new();
  body.insert("action".to_string(), json!(args.action));
  body.insert("resource".to_string(), json!(args.resource));
  if let Some(target) = simulation_target_body(args) {
    body.insert("target".to_string(), target);
  }
  if let Some(context) = simulation_context_body(
    args.source_ip.as_ref().map(ToString::to_string),
    args.method.as_ref(),
    args.host.as_ref(),
    args.path.as_ref(),
    args.route.as_ref(),
    args.protocol.as_ref(),
    &args.claims,
  )? {
    body.insert("context".to_string(), context);
  }
  if let Some(overlay) = overlay {
    body.insert("overlay".to_string(), overlay);
  }
  Ok(Value::Object(body))
}

fn simulation_target_body(args: &IpmSimulateArgs) -> Option<Value> {
  let mut target = Map::new();
  if let Some(principal) = &args.principal {
    target.insert("principal".to_string(), json!(principal));
  }
  if let Some(credential) = &args.credential {
    target.insert("credential".to_string(), json!(credential));
  }
  if let Some(subject) = &args.subject {
    target.insert("subject".to_string(), json!(subject));
  }
  if !args.groups.is_empty() {
    target.insert("groups".to_string(), json!(args.groups));
  }
  (!target.is_empty()).then_some(Value::Object(target))
}

fn simulation_context_body(
  source_ip: Option<String>,
  method: Option<&String>,
  host: Option<&String>,
  path: Option<&String>,
  route: Option<&String>,
  protocol: Option<&String>,
  claims: &[String],
) -> anyhow::Result<Option<Value>> {
  let mut context = Map::new();
  if let Some(source_ip) = source_ip {
    context.insert("source_ip".to_string(), json!(source_ip));
  }
  if let Some(method) = method {
    context.insert("method".to_string(), json!(method));
  }
  if let Some(host) = host {
    context.insert("host".to_string(), json!(host));
  }
  if let Some(path) = path {
    context.insert("path".to_string(), json!(path));
  }
  if let Some(route) = route {
    context.insert("route".to_string(), json!(route));
  }
  if let Some(protocol) = protocol {
    context.insert("protocol".to_string(), json!(protocol));
  }
  let claims = claim_map(claims)?;
  if !claims.is_empty() {
    context.insert("claims".to_string(), Value::Object(claims));
  }
  Ok((!context.is_empty()).then_some(Value::Object(context)))
}

fn claim_map(claims: &[String]) -> anyhow::Result<Map<String, Value>> {
  let mut parsed = Map::new();
  for claim in claims {
    let Some((key, value)) = claim.split_once('=') else {
      bail!("--claim must use KEY=VALUE syntax");
    };
    if key.trim().is_empty() {
      bail!("--claim key must not be empty");
    }
    parsed.insert(key.to_string(), Value::String(value.to_string()));
  }
  Ok(parsed)
}

fn ipm_simulate_permission(args: &IpmSimulateArgs, overlay: Option<&Value>) -> PermissionHint {
  let mut resources = vec![resource_hint::ipm_simulation().to_string()];
  if let Some(principal) = &args.principal {
    resources.push(resource_hint::ipm_principal(principal));
  }
  if let Some(credential) = &args.credential {
    resources.push(resource_hint::ipm_credential(credential));
  }
  for group in &args.groups {
    resources.push(resource_hint::ipm_group(group));
  }
  let mut action = if args.principal.is_some()
    || args.credential.is_some()
    || args.subject.is_some()
    || !args.groups.is_empty()
  {
    "ipm:SimulatePrincipal"
  } else {
    "ipm:SimulateSelf"
  };
  if let Some(overlay) = overlay {
    action = "ipm:SimulatePolicy";
    resources.extend(overlay_permission_resources(overlay));
  }
  PermissionHint::with_resources(action, resources)
}

fn overlay_permission_resources(overlay: &Value) -> Vec<String> {
  let mut resources = Vec::new();
  if let Some(policies) = overlay.get("policies").and_then(Value::as_array) {
    for policy in policies {
      resources.push(
        string_field(policy, "name")
          .map(resource_hint::ipm_policy)
          .unwrap_or_else(|| "policy/*".to_string()),
      );
    }
  }
  if let Some(bindings) = overlay.get("bindings").and_then(Value::as_array) {
    for binding in bindings {
      let principal = string_field(binding, "principal");
      let group = string_field(binding, "group");
      let policy = string_field(binding, "policy").unwrap_or("*");
      resources.extend(resource_hint::ipm_binding_create_target(
        string_field(binding, "id"),
        principal,
        group,
        policy,
      ));
    }
  }
  resources
}

fn string_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
  value.get(field).and_then(Value::as_str)
}

fn audit_endpoint(args: &IpmAuditArgs) -> String {
  let mut serializer = url::form_urlencoded::Serializer::new(String::new());
  serializer.append_pair("limit", &args.limit.to_string());
  if let Some(value) = &args.target_kind {
    serializer.append_pair("target_kind", value);
  }
  if let Some(value) = &args.target_id {
    serializer.append_pair("target_id", value);
  }
  if let Some(value) = &args.outcome {
    serializer.append_pair("outcome", value);
  }
  if let Some(value) = &args.actor {
    serializer.append_pair("actor", value);
  }
  format!("/admin/v1/ipm/audit?{}", serializer.finish())
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

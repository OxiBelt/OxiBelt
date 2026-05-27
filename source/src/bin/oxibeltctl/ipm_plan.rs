use anyhow::{Context, bail};
use http::Method;
use oxibelt::admin_client::AdminClient;
use serde_json::{Value, json};

use crate::cli::*;
use crate::plan::{RequestPlan, delete, get, patch_json, post_json, read_json_file};

pub(crate) async fn plan_ipm(
  client: &AdminClient,
  command: &IpmCommand,
) -> anyhow::Result<RequestPlan> {
  match &command.command {
    IpmSubcommand::Status => get("/admin/v1/ipm/status", "ipm:GetStatus", "*"),
    IpmSubcommand::List(args) => plan_legacy_list(args),
    IpmSubcommand::Simulate(args) => post_json(
      "/admin/v1/ipm/simulate",
      json!({ "action": args.action, "resource": args.resource }),
      "ipm:Simulate",
      "*",
    ),
    IpmSubcommand::Principal(command) => plan_principal(client, command).await,
    IpmSubcommand::Credential(command) => plan_credential(client, command).await,
    IpmSubcommand::Policy(command) => plan_policy(client, command).await,
    IpmSubcommand::Binding(command) => plan_binding(client, command).await,
    IpmSubcommand::Audit(args) => get(&audit_endpoint(args), "ipm:ReadAudit", "audit/ipm"),
  }
}

fn plan_legacy_list(args: &IpmListArgs) -> anyhow::Result<RequestPlan> {
  match &args.target {
    IpmListTarget::Principals => get("/admin/v1/ipm/principals", "ipm:ListPrincipals", "*"),
    IpmListTarget::Credentials => get("/admin/v1/ipm/credentials", "ipm:ListCredentials", "*"),
    IpmListTarget::Policies => get("/admin/v1/ipm/policies", "ipm:ListPolicies", "*"),
    IpmListTarget::Bindings => get("/admin/v1/ipm/bindings", "ipm:ListBindings", "*"),
  }
}

async fn plan_principal(
  client: &AdminClient,
  command: &IpmPrincipalCommand,
) -> anyhow::Result<RequestPlan> {
  match &command.command {
    IpmPrincipalSubcommand::List => get("/admin/v1/ipm/principals", "ipm:ListPrincipals", "*"),
    IpmPrincipalSubcommand::Get(args) => get(
      &format!("/admin/v1/ipm/principals/{}", path_id(&args.id)?),
      "ipm:GetPrincipal",
      &args.id,
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
          &args.id,
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
          &args.id,
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
          &args.id,
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
    IpmCredentialSubcommand::List => get("/admin/v1/ipm/credentials", "ipm:ListCredentials", "*"),
    IpmCredentialSubcommand::Get(args) => get(
      &format!("/admin/v1/ipm/credentials/{}", path_id(&args.id)?),
      "ipm:GetCredential",
      &args.id,
    ),
    IpmCredentialSubcommand::Create(args) => {
      let etag = ipm_etag_or_current(client, &args.etag).await?;
      with_etag(
        post_json(
          "/admin/v1/ipm/credentials",
          remove_nulls(json!({
            "id": args.id,
            "principal": args.principal,
            "ttl_seconds": args.expires,
            "no_expiry": args.no_expiry,
          })),
          "ipm:CreateCredential",
          &args.id,
        )?,
        etag,
      )
    }
    IpmCredentialSubcommand::Patch(args) => {
      let etag = ipm_etag_or_current(client, &args.etag).await?;
      with_etag(
        patch_json(
          &format!("/admin/v1/ipm/credentials/{}", path_id(&args.id)?),
          remove_nulls(json!({
            "principal": args.principal,
            "enabled": enabled_flag(args.enable, args.disable),
            "ttl_seconds": args.expires,
          })),
          "ipm:UpdateCredential",
          &args.id,
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
          &args.id,
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
          &args.id,
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
          &args.id,
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
    IpmPolicySubcommand::List => get("/admin/v1/ipm/policies", "ipm:ListPolicies", "*"),
    IpmPolicySubcommand::Get(args) => get(
      &format!("/admin/v1/ipm/policies/{}", path_id(&args.id)?),
      "ipm:GetPolicy",
      &args.id,
    ),
    IpmPolicySubcommand::Create(args) => {
      let etag = ipm_etag_or_current(client, &args.etag).await?;
      with_etag(
        post_json(
          "/admin/v1/ipm/policies",
          read_json_file(&args.json)?,
          "ipm:CreatePolicy",
          "*",
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
          &args.id,
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
          &args.id,
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
    IpmBindingSubcommand::List => get("/admin/v1/ipm/bindings", "ipm:ListBindings", "*"),
    IpmBindingSubcommand::Create(args) => {
      let etag = ipm_etag_or_current(client, &args.etag).await?;
      with_etag(
        post_json(
          "/admin/v1/ipm/bindings",
          remove_nulls(json!({
            "id": args.id,
            "principal": args.principal,
            "group": args.group,
            "policy": args.policy,
            "enabled": !args.disabled,
          })),
          "ipm:CreateBinding",
          args.id.as_deref().unwrap_or("*"),
        )?,
        etag,
      )
    }
    IpmBindingSubcommand::Delete(args) => {
      let etag = ipm_etag_or_current(client, &args.etag).await?;
      with_etag(
        delete(
          &format!("/admin/v1/ipm/bindings/{}", path_id(&args.id)?),
          "ipm:DeleteBinding",
          &args.id,
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

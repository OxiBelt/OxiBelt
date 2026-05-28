use anyhow::{Context, bail};
use http::Method;
use oxibelt::admin_client::AdminClient;
use serde_json::{Value, json};

use crate::cli::*;
use crate::plan::{
  PermissionHint, RequestPlan, delete, get, patch_json, post_json_with_permission, read_json_file,
  with_etag,
};
use crate::profile_catalog::MitigationProfileCatalog;
use crate::resource_hint;

pub(crate) async fn plan_dynamic_policy(
  client: &AdminClient,
  command: &DynamicPolicyCommand,
) -> anyhow::Result<RequestPlan> {
  match &command.command {
    DynamicPolicySubcommand::Status => get(
      "/admin/v1/dynamic-policies/status",
      "dynamic-policy:GetStatus",
      resource_hint::dynamic_policy_status(),
    ),
    DynamicPolicySubcommand::List => get("/admin/v1/dynamic-policies", "dynamic-policy:List", "*"),
    DynamicPolicySubcommand::Get(args) => get(
      &format!("/admin/v1/dynamic-policies/{}", args.id),
      "dynamic-policy:Get",
      "*",
    ),
    DynamicPolicySubcommand::Create(args) => {
      let etag = dynamic_policy_etag_or_current(client, &args.etag).await?;
      let body = read_json_file(&args.json)?;
      let resources = resource_hint::dynamic_policy_target(&body);
      with_etag(
        post_json_with_permission(
          "/admin/v1/dynamic-policies",
          body,
          PermissionHint::with_resources("dynamic-policy:Create", resources),
        )?,
        etag,
      )
    }
    DynamicPolicySubcommand::Apply(args) => {
      let body = read_json_file(&args.json)?;
      let resources = resource_hint::dynamic_policy_target(&body);
      let mut plan = post_json_with_permission(
        "/admin/v1/dynamic-policies/apply",
        body,
        PermissionHint::with_resources("dynamic-policy:Apply", resources),
      )?;
      plan.if_match = args.etag.clone();
      Ok(plan)
    }
    DynamicPolicySubcommand::Patch(args) => {
      let etag = dynamic_policy_etag_or_current(client, &args.etag).await?;
      with_etag(
        patch_json(
          &format!("/admin/v1/dynamic-policies/{}", args.id),
          read_json_file(&args.json)?,
          "dynamic-policy:Update",
          "*",
        )?,
        etag,
      )
    }
    DynamicPolicySubcommand::Delete(args) => {
      let etag = dynamic_policy_etag_or_current(client, &args.etag).await?;
      with_etag(
        delete(
          &format!("/admin/v1/dynamic-policies/{}", args.id),
          "dynamic-policy:Delete",
          "*",
        )?,
        etag,
      )
    }
    DynamicPolicySubcommand::Audit(args) => {
      get(&audit_endpoint(args), "dynamic-policy:ReadAudit", "*")
    }
    DynamicPolicySubcommand::Export => get(
      "/admin/v1/dynamic-policies/export",
      "dynamic-policy:Export",
      "*",
    ),
    DynamicPolicySubcommand::Import(args) => {
      let etag = dynamic_policy_etag_or_current(client, &args.etag).await?;
      let body = read_json_file(&args.json)?;
      let resources = resource_hint::dynamic_policy_import_target(&body);
      with_etag(
        post_json_with_permission(
          "/admin/v1/dynamic-policies/import",
          body,
          PermissionHint::with_resources("dynamic-policy:Import", resources),
        )?,
        etag,
      )
    }
  }
}

pub(crate) fn plan_mitigation(action: &str, args: &MitigationArgs) -> anyhow::Result<RequestPlan> {
  let (subject_type, values) = match &args.subject {
    MitigationSubject::Ip(values) => ("client_ip", values),
    MitigationSubject::Cidr(values) => ("client_ip_cidr", values),
  };
  let (subject_type, subject, route_name, path_prefix) = policy_subject(
    subject_type,
    &values.subject,
    values.route.as_deref(),
    values.path_prefix.as_deref(),
  );
  let name = values
    .name
    .clone()
    .unwrap_or_else(|| mitigation_name(action, &subject_type, &subject));
  let reason = reason_or_default(
    values.reason.as_deref(),
    &format!("oxibeltctl {action} {subject}"),
  )?;
  let body = json!({
    "enabled": true,
    "priority": values.priority,
    "source": "oxibeltctl",
    "name": name,
    "action": action,
    "subject_type": subject_type,
    "subject": subject,
    "route_name": route_name,
    "path_prefix": path_prefix,
    "method": values.method.as_ref().map(|method| method.to_ascii_uppercase()),
    "reason": reason,
    "ttl_seconds": values.ttl,
    "mode": policy_mode(values.dry_run),
  });
  let resources = resource_hint::dynamic_policy_target(&body);
  let mut plan = post_json_with_permission(
    "/admin/v1/dynamic-policies/apply",
    body,
    PermissionHint::with_resources("dynamic-policy:Apply", resources),
  )?;
  plan.if_match = values.etag.clone();
  Ok(plan)
}

pub(crate) fn plan_challenge(args: &ChallengeArgs) -> anyhow::Result<RequestPlan> {
  if !args.person_proof {
    bail!("challenge requires --person-proof");
  }
  let mitigation = MitigationArgs {
    subject: args.subject.clone(),
  };
  plan_mitigation("challenge", &mitigation)
}

pub(crate) fn plan_rate_limit(args: &RateLimitArgs) -> anyhow::Result<RequestPlan> {
  let (subject_type, values) = match &args.subject {
    RateLimitSubject::Source(values) => ("client_ip", values),
    RateLimitSubject::Ip(values) => ("client_ip", values),
    RateLimitSubject::Cidr(values) => ("client_ip_cidr", values),
  };
  let (subject_type, subject, route_name, path_prefix) = policy_subject(
    subject_type,
    &values.subject,
    values.route.as_deref(),
    values.path_prefix.as_deref(),
  );
  let rate = rate_limit_rate(values)?;
  let burst = values
    .burst
    .unwrap_or_else(|| default_rate_limit_burst(&rate));
  let name = values
    .name
    .clone()
    .unwrap_or_else(|| mitigation_name("rate-limit", &subject_type, &subject));
  let reason = reason_or_default(
    values.reason.as_deref(),
    &format!("oxibeltctl rate-limit {subject}"),
  )?;
  let body = json!({
    "enabled": true,
    "priority": values.priority,
    "source": "oxibeltctl",
    "name": name,
    "action": "rate_limit",
    "subject_type": subject_type,
    "subject": subject,
    "route_name": route_name,
    "path_prefix": path_prefix,
    "method": values.method.as_ref().map(|method| method.to_ascii_uppercase()),
    "rate": rate,
    "burst": burst,
    "reason": reason,
    "ttl_seconds": values.ttl,
    "mode": policy_mode(values.dry_run),
  });
  let resources = resource_hint::dynamic_policy_target(&body);
  let mut plan = post_json_with_permission(
    "/admin/v1/dynamic-policies/apply",
    body,
    PermissionHint::with_resources("dynamic-policy:Apply", resources),
  )?;
  plan.if_match = values.etag.clone();
  Ok(plan)
}

pub(crate) fn plan_mitigate(
  args: &MitigateArgs,
  catalog: &MitigationProfileCatalog,
) -> anyhow::Result<RequestPlan> {
  let profile = catalog.profiles.get(&args.profile).with_context(|| {
    format!(
      "mitigation profile {} was not found in catalog",
      args.profile
    )
  })?;
  let path_prefix = args
    .path_prefix
    .as_deref()
    .or(profile.path_prefix.as_deref());
  let route = args.route.as_deref().or(profile.route_name.as_deref());
  let (subject_type, subject, route_name, path_prefix) =
    policy_subject("client_ip", &args.source, route, path_prefix);
  let name = args
    .name
    .clone()
    .unwrap_or_else(|| mitigation_profile_name(&args.profile, &subject_type, &subject));
  let reason = reason_or_default(
    args.reason.as_deref().or(profile.reason.as_deref()),
    &format!("oxibeltctl mitigate {} {}", args.profile, args.source),
  )?;
  let mode = if args.dry_run {
    "dry_run"
  } else {
    profile.mode.as_deref().unwrap_or("enforce")
  };
  let body = json!({
    "enabled": true,
    "priority": args.priority.or(profile.priority).unwrap_or(100),
    "source": profile.source.as_deref().unwrap_or("oxibeltctl-profile"),
    "name": name,
    "action": &profile.action,
    "subject_type": subject_type,
    "subject": subject,
    "route_name": route_name,
    "path_prefix": path_prefix,
    "method": args.method.as_ref().or(profile.method.as_ref()).map(|method| method.to_ascii_uppercase()),
    "rate": profile.rate.as_ref(),
    "burst": profile.burst,
    "status": profile.status,
    "body": profile.body.as_ref(),
    "reason": reason,
    "code": profile.code.as_ref(),
    "ttl_seconds": args.ttl.or(profile.ttl_seconds),
    "mode": mode,
  });
  let resources = resource_hint::dynamic_policy_target(&body);
  let mut plan = post_json_with_permission(
    "/admin/v1/dynamic-policies/apply",
    body,
    PermissionHint::with_resources("dynamic-policy:Apply", resources),
  )?;
  plan.if_match = args.etag.clone();
  Ok(plan)
}

async fn dynamic_policy_etag_or_current(
  client: &AdminClient,
  etag: &Option<String>,
) -> anyhow::Result<String> {
  match etag {
    Some(etag) => Ok(etag.clone()),
    None => current_dynamic_policy_etag(client).await,
  }
}

async fn current_dynamic_policy_etag(client: &AdminClient) -> anyhow::Result<String> {
  let response = client
    .request_json(Method::GET, "/admin/v1/dynamic-policies/status", None, None)
    .await?;
  if !response.status.is_success() {
    bail!(
      "failed to fetch current dynamic policy ETag: {}",
      response.status
    );
  }
  let value = serde_json::from_slice::<Value>(&response.body)
    .context("dynamic policy status was not JSON")?;
  value
    .get("etag")
    .and_then(Value::as_str)
    .map(str::to_string)
    .context("dynamic policy status response did not include etag")
}

fn audit_endpoint(args: &DynamicPolicyAuditArgs) -> String {
  let mut serializer = url::form_urlencoded::Serializer::new(String::new());
  serializer.append_pair("limit", &args.limit.to_string());
  if let Some(policy_id) = args.policy_id {
    serializer.append_pair("policy_id", &policy_id.to_string());
  }
  format!("/admin/v1/dynamic-policies/audit?{}", serializer.finish())
}

fn policy_subject(
  base_subject_type: &str,
  subject: &str,
  route_name: Option<&str>,
  path_prefix: Option<&str>,
) -> (String, String, Option<String>, Option<String>) {
  match (base_subject_type, route_name, path_prefix) {
    ("client_ip", _, Some(path_prefix)) => (
      "client_ip_path".to_string(),
      format!("{subject}|{path_prefix}"),
      route_name.map(str::to_string),
      Some(path_prefix.to_string()),
    ),
    ("client_ip", Some(route_name), None) => (
      "client_ip_route".to_string(),
      format!("{subject}|{route_name}"),
      Some(route_name.to_string()),
      None,
    ),
    _ => (
      base_subject_type.to_string(),
      subject.to_string(),
      route_name.map(str::to_string),
      path_prefix.map(str::to_string),
    ),
  }
}

fn reason_or_default(value: Option<&str>, default: &str) -> anyhow::Result<String> {
  let reason = value.unwrap_or(default).trim();
  if reason.is_empty() {
    bail!("mitigation reason must not be empty");
  }
  Ok(reason.to_string())
}

fn policy_mode(dry_run: bool) -> &'static str {
  if dry_run { "dry_run" } else { "enforce" }
}

fn rate_limit_rate(args: &RateLimitSubjectArgs) -> anyhow::Result<String> {
  match (&args.rate, args.rps) {
    (Some(rate), None) => Ok(rate.clone()),
    (None, Some(rps)) if rps.is_finite() && rps > 0.0 => Ok(format!("{rps}r/s")),
    (None, Some(_)) => bail!("--rps must be greater than 0"),
    (None, None) => bail!("rate-limit requires --rate or --rps"),
    (Some(_), Some(_)) => bail!("rate-limit accepts only one of --rate or --rps"),
  }
}

fn default_rate_limit_burst(rate: &str) -> i32 {
  let amount = rate
    .split_once("r/")
    .and_then(|(amount, _)| amount.parse::<f64>().ok())
    .filter(|value| value.is_finite() && *value > 0.0)
    .unwrap_or(1.0);
  amount.ceil().clamp(1.0, i32::MAX as f64) as i32
}

fn mitigation_name(action: &str, subject_type: &str, subject: &str) -> String {
  format!(
    "{action}-{subject_type}-{}",
    sanitized_name_component(subject)
  )
}

fn mitigation_profile_name(profile: &str, subject_type: &str, subject: &str) -> String {
  format!(
    "mitigate-{}-{subject_type}-{}",
    sanitized_name_component(profile),
    sanitized_name_component(subject)
  )
}

fn sanitized_name_component(value: &str) -> String {
  value
    .chars()
    .map(|character| {
      if character.is_ascii_alphanumeric() {
        character
      } else {
        '-'
      }
    })
    .collect::<String>()
}

use anyhow::bail;
use serde_json::json;

use crate::cli::*;
use crate::plan::{RequestPlan, delete, get, patch_json, post_json, read_json_file};

pub(crate) fn plan_dynamic_policy(command: &DynamicPolicyCommand) -> anyhow::Result<RequestPlan> {
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
    DynamicPolicySubcommand::Apply(args) => post_json(
      "/admin/v1/dynamic-policies/apply",
      read_json_file(&args.json)?,
      "dynamic-policy:Apply",
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
    DynamicPolicySubcommand::Audit(args) => {
      get(&audit_endpoint(args), "dynamic-policy:ReadAudit", "*")
    }
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
  post_json(
    "/admin/v1/dynamic-policies/apply",
    json!({
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
    }),
    "dynamic-policy:Apply",
    "*",
  )
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
  post_json(
    "/admin/v1/dynamic-policies/apply",
    json!({
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
    }),
    "dynamic-policy:Apply",
    "*",
  )
}

pub(crate) fn plan_mitigate(args: &MitigateArgs) -> anyhow::Result<RequestPlan> {
  match args.playbook.as_str() {
    "vaultwarden-bruteforce" => plan_vaultwarden_bruteforce(args),
    _ => bail!("unknown mitigation playbook {}", args.playbook),
  }
}

fn plan_vaultwarden_bruteforce(args: &MitigateArgs) -> anyhow::Result<RequestPlan> {
  let path_prefix = args.path_prefix.as_deref().unwrap_or("/identity");
  let (subject_type, subject, route_name, path_prefix) = policy_subject(
    "client_ip",
    &args.source,
    args.route.as_deref(),
    Some(path_prefix),
  );
  let name = args
    .name
    .clone()
    .unwrap_or_else(|| mitigation_name("vaultwarden-bruteforce", &subject_type, &subject));
  let reason = reason_or_default(
    args.reason.as_deref(),
    &format!("vaultwarden brute-force mitigation for {}", args.source),
  )?;
  post_json(
    "/admin/v1/dynamic-policies/apply",
    json!({
      "enabled": true,
      "priority": args.priority,
      "source": "oxibeltctl-playbook",
      "name": name,
      "action": "reject",
      "subject_type": subject_type,
      "subject": subject,
      "route_name": route_name,
      "path_prefix": path_prefix,
      "method": args.method.as_ref().map(|method| method.to_ascii_uppercase()),
      "status": 429,
      "reason": reason,
      "code": "vaultwarden.bruteforce",
      "ttl_seconds": args.ttl.unwrap_or(900),
      "mode": policy_mode(args.dry_run),
    }),
    "dynamic-policy:Apply",
    "*",
  )
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

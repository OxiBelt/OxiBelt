use anyhow::bail;

use super::{DynamicPolicyAdminCreate, DynamicPolicyAdminPatch, DynamicPolicyAdminRecord};
use crate::dynamic_policy::{
  MAX_DYNAMIC_POLICY_BODY_BYTES, MAX_DYNAMIC_POLICY_NAME_BYTES, MAX_DYNAMIC_POLICY_RATE_BYTES,
  MAX_DYNAMIC_POLICY_REASON_BYTES, MAX_DYNAMIC_POLICY_SUBJECT_BYTES, validate_method,
  validate_path_prefix, validate_route_name, validate_status, validate_string_len,
  validate_subject,
};

pub(super) fn validate_create(
  inner: &crate::dynamic_policy::DynamicPolicyInner,
  input: &DynamicPolicyAdminCreate,
) -> anyhow::Result<()> {
  validate_ttl(inner, input.expires_at.as_deref(), input.ttl_seconds)?;
  validate_policy_fields(
    inner,
    &input.name,
    &input.source,
    &input.action,
    &input.subject_type,
    &input.subject,
    input.route_name.as_deref(),
    input.method.as_deref(),
    input.path_prefix.as_deref(),
    input.rate.as_deref(),
    input.burst,
    input.status,
    input.body.as_deref(),
    input.reason.as_deref(),
    input.code.as_deref(),
    input.mode.as_deref().unwrap_or("enforce"),
  )
}

pub(super) fn validate_patch(
  inner: &crate::dynamic_policy::DynamicPolicyInner,
  input: &DynamicPolicyAdminPatch,
) -> anyhow::Result<()> {
  if input.expires_at.is_some() || input.ttl_seconds.is_some() {
    validate_ttl(inner, input.expires_at.as_deref(), input.ttl_seconds)?;
  }
  if let Some(name) = &input.name {
    validate_string_len("dynamic policy name", name, MAX_DYNAMIC_POLICY_NAME_BYTES)?;
  }
  if let Some(source) = &input.source {
    validate_string_len(
      "dynamic policy source",
      source,
      MAX_DYNAMIC_POLICY_NAME_BYTES,
    )?;
  }
  if let Some(method) = &input.method {
    validate_method(0, method.clone())?;
  }
  if let Some(path) = &input.path_prefix {
    validate_path_prefix(0, path, inner.config.matching.normalize_path)?;
  }
  if let Some(status) = input.status {
    validate_status(status)?;
  }
  if let Some(body) = &input.body {
    validate_string_len("dynamic policy body", body, MAX_DYNAMIC_POLICY_BODY_BYTES)?;
  }
  if let Some(reason) = &input.reason {
    validate_string_len(
      "dynamic policy reason",
      reason,
      MAX_DYNAMIC_POLICY_REASON_BYTES,
    )?;
  }
  if let Some(code) = &input.code {
    validate_code(code)?;
  }
  if let Some(mode) = &input.mode {
    validate_mode(mode)?;
  }
  if let Some(rate) = &input.rate {
    validate_string_len("dynamic policy rate", rate, MAX_DYNAMIC_POLICY_RATE_BYTES)?;
    crate::limits::parse_rate(rate)?;
  }
  if let Some(burst) = input.burst
    && burst <= 0
  {
    bail!("dynamic policy burst must be greater than 0");
  }
  Ok(())
}

pub(super) fn validate_patch_merged(
  inner: &crate::dynamic_policy::DynamicPolicyInner,
  existing: &DynamicPolicyAdminRecord,
  input: &DynamicPolicyAdminPatch,
) -> anyhow::Result<()> {
  if input.enabled.unwrap_or(existing.enabled) {
    let expires_at = input
      .expires_at
      .as_deref()
      .or(existing.expires_at.as_deref());
    validate_ttl(inner, expires_at, input.ttl_seconds)?;
  }
  validate_policy_fields(
    inner,
    input.name.as_deref().unwrap_or(&existing.name),
    input.source.as_deref().unwrap_or(&existing.source),
    input.action.as_deref().unwrap_or(&existing.action),
    input
      .subject_type
      .as_deref()
      .unwrap_or(&existing.subject_type),
    input.subject.as_deref().unwrap_or(&existing.subject),
    input
      .route_name
      .as_deref()
      .or(existing.route_name.as_deref()),
    input.method.as_deref().or(existing.method.as_deref()),
    input
      .path_prefix
      .as_deref()
      .or(existing.path_prefix.as_deref()),
    input.rate.as_deref().or(existing.rate.as_deref()),
    input.burst.or(existing.burst),
    input.status.or(existing.status),
    input.body.as_deref().or(existing.body.as_deref()),
    input.reason.as_deref().or(existing.reason.as_deref()),
    input.code.as_deref().or(existing.code.as_deref()),
    input.mode.as_deref().unwrap_or(&existing.mode),
  )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_policy_fields(
  inner: &crate::dynamic_policy::DynamicPolicyInner,
  name: &str,
  source: &str,
  action: &str,
  subject_type: &str,
  subject: &str,
  route_name: Option<&str>,
  method: Option<&str>,
  path_prefix: Option<&str>,
  rate: Option<&str>,
  burst: Option<i32>,
  status: Option<i32>,
  body: Option<&str>,
  reason: Option<&str>,
  code: Option<&str>,
  mode: &str,
) -> anyhow::Result<()> {
  validate_string_len("dynamic policy name", name, MAX_DYNAMIC_POLICY_NAME_BYTES)?;
  validate_string_len(
    "dynamic policy source",
    source,
    MAX_DYNAMIC_POLICY_NAME_BYTES,
  )?;
  validate_string_len(
    "dynamic policy subject",
    subject,
    MAX_DYNAMIC_POLICY_SUBJECT_BYTES,
  )?;
  if name.trim().is_empty() || source.trim().is_empty() {
    bail!("dynamic policy source and name must not be empty");
  }
  let subject_type = match subject_type {
    "client_ip" => crate::dynamic_policy::DynamicPolicySubjectType::Ip,
    "client_ip_cidr" => crate::dynamic_policy::DynamicPolicySubjectType::IpCidr,
    "client_ip_route" => crate::dynamic_policy::DynamicPolicySubjectType::IpRoute,
    "client_ip_path" => crate::dynamic_policy::DynamicPolicySubjectType::IpPath,
    _ => bail!("dynamic policy has unsupported subject_type {subject_type}"),
  };
  let route_name = route_name
    .map(|route| validate_route_name(0, route.to_string(), &inner.route_names))
    .transpose()?;
  let path_prefix = path_prefix
    .map(|path| validate_path_prefix(0, path, inner.config.matching.normalize_path))
    .transpose()?;
  validate_subject(
    0,
    subject_type,
    subject,
    route_name.as_deref(),
    path_prefix.as_deref(),
  )?;
  if let Some(method) = method {
    validate_method(0, method.to_string())?;
  }
  if let Some(status) = status {
    validate_status(status)?;
  }
  if let Some(body) = body {
    validate_string_len("dynamic policy body", body, MAX_DYNAMIC_POLICY_BODY_BYTES)?;
  }
  if let Some(reason) = reason {
    validate_string_len(
      "dynamic policy reason",
      reason,
      MAX_DYNAMIC_POLICY_REASON_BYTES,
    )?;
  }
  if let Some(code) = code {
    validate_code(code)?;
  }
  validate_mode(mode)?;
  match action {
    "allow" | "reject" => {}
    "rate_limit" => {
      let Some(rate) = rate else {
        bail!("dynamic policy rate_limit action requires rate");
      };
      validate_string_len("dynamic policy rate", rate, MAX_DYNAMIC_POLICY_RATE_BYTES)?;
      crate::limits::parse_rate(rate)?;
      if burst.is_none_or(|burst| burst <= 0) {
        bail!("dynamic policy rate_limit action requires burst");
      }
    }
    _ => bail!("dynamic policy has unsupported action {action}"),
  }
  Ok(())
}

pub(super) fn validate_ttl(
  inner: &crate::dynamic_policy::DynamicPolicyInner,
  expires_at: Option<&str>,
  ttl_seconds: Option<i64>,
) -> anyhow::Result<()> {
  if expires_at.is_some() && ttl_seconds.is_some() {
    bail!("dynamic policy must set only one of expires_at or ttl_seconds");
  }
  if inner.config.automation_api.require_ttl && expires_at.is_none() && ttl_seconds.is_none() {
    bail!("dynamic policy automation API requires expires_at or ttl_seconds");
  }
  if let Some(ttl_seconds) = ttl_seconds
    && ttl_seconds <= 0
  {
    bail!("dynamic policy ttl_seconds must be greater than 0");
  }
  Ok(())
}

fn validate_code(code: &str) -> anyhow::Result<()> {
  validate_string_len("dynamic policy code", code, MAX_DYNAMIC_POLICY_NAME_BYTES)?;
  if code
    .bytes()
    .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')))
  {
    bail!("dynamic policy code contains invalid characters");
  }
  Ok(())
}

fn validate_mode(mode: &str) -> anyhow::Result<()> {
  match mode {
    "enforce" | "dry_run" => Ok(()),
    _ => bail!("dynamic policy has unsupported mode {mode}"),
  }
}

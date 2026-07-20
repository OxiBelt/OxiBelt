//! PostgreSQL snapshot loading and row validation.

use super::*;

pub(super) async fn load_snapshot(
  pool: &Pool<Postgres>,
  config: &DynamicPolicyConfig,
  namespace: &str,
  route_names: &HashSet<String>,
  signature_key: Option<&[u8; 32]>,
) -> anyhow::Result<DynamicPolicySnapshot> {
  let generation = load_generation(pool, namespace).await?;
  let limit = i64::try_from(config.max_policies.saturating_add(1))
    .context("dynamic_policy.max_policies does not fit in i64")?;
  let rows = sqlx::query(
    "SELECT id, enabled, priority, name, source, action, subject_type, subject, route_name, method,
            path_prefix, rate, burst, status, body, reason, code, mode, writer_identity,
            signature_version, row_signature, expires_at::text AS expires_at
       FROM oxibelt_dynamic_policies
      WHERE namespace = $1
        AND enabled = true
        AND (expires_at IS NULL OR expires_at > now())
      ORDER BY priority ASC, id ASC
      LIMIT $2",
  )
  .bind(namespace)
  .bind(limit)
  .fetch_all(pool)
  .await?;
  if rows.len() > config.max_policies {
    bail!(
      "dynamic policy active policy count exceeds max_policies ({})",
      config.max_policies
    );
  }

  let mut hasher = std::collections::hash_map::DefaultHasher::new();
  generation.hash(&mut hasher);
  let mut policies = Vec::with_capacity(rows.len());
  for row in rows {
    let row = policy_row_from_pg(&row)?;
    hash_policy_row(&row, &mut hasher);
    policies.push(validate_policy_row(
      row,
      config,
      namespace,
      route_names,
      signature_key,
    )?);
  }

  Ok(DynamicPolicySnapshot {
    generation,
    fingerprint: hasher.finish(),
    policies: Arc::from(policies),
  })
}

fn hash_policy_row(row: &PolicyRow, hasher: &mut impl Hasher) {
  row.id.hash(hasher);
  row.enabled.hash(hasher);
  row.priority.hash(hasher);
  row.name.hash(hasher);
  row.source.hash(hasher);
  row.action.hash(hasher);
  row.subject_type.hash(hasher);
  row.subject.hash(hasher);
  row.route_name.hash(hasher);
  row.method.hash(hasher);
  row.path_prefix.hash(hasher);
  row.rate.hash(hasher);
  row.burst.hash(hasher);
  row.status.hash(hasher);
  row.body.hash(hasher);
  row.reason.hash(hasher);
  row.code.hash(hasher);
  row.mode.hash(hasher);
  row.writer_identity.hash(hasher);
  row.signature_version.hash(hasher);
  row.row_signature.hash(hasher);
  row.expires_at.hash(hasher);
}

pub(super) fn policy_row_from_pg(row: &sqlx::postgres::PgRow) -> anyhow::Result<PolicyRow> {
  Ok(PolicyRow {
    id: row.try_get("id")?,
    enabled: row.try_get("enabled")?,
    priority: row.try_get("priority")?,
    name: row.try_get("name")?,
    source: row.try_get("source")?,
    action: row.try_get("action")?,
    subject_type: row.try_get("subject_type")?,
    subject: row.try_get("subject")?,
    route_name: row.try_get("route_name")?,
    method: row.try_get("method")?,
    path_prefix: row.try_get("path_prefix")?,
    rate: row.try_get("rate")?,
    burst: row.try_get("burst")?,
    status: row.try_get("status")?,
    body: row.try_get("body")?,
    reason: row.try_get("reason")?,
    code: row.try_get("code")?,
    mode: row.try_get("mode")?,
    writer_identity: row.try_get("writer_identity")?,
    signature_version: row.try_get("signature_version")?,
    row_signature: row.try_get("row_signature")?,
    expires_at: row.try_get("expires_at")?,
  })
}

async fn load_generation(pool: &Pool<Postgres>, namespace: &str) -> anyhow::Result<i64> {
  let generation: Option<i64> = sqlx::query_scalar(
    "SELECT generation FROM oxibelt_dynamic_policy_generation WHERE namespace = $1",
  )
  .bind(namespace)
  .fetch_optional(pool)
  .await?;
  Ok(generation.unwrap_or(0))
}

pub(super) fn validate_policy_row(
  row: PolicyRow,
  config: &DynamicPolicyConfig,
  namespace: &str,
  route_names: &HashSet<String>,
  signature_key: Option<&[u8; 32]>,
) -> anyhow::Result<DynamicPolicy> {
  let PolicyRow {
    id,
    enabled,
    priority,
    name,
    source,
    action,
    subject_type,
    subject,
    route_name,
    method,
    path_prefix,
    rate,
    burst,
    status,
    body,
    reason,
    code,
    mode,
    writer_identity,
    signature_version,
    row_signature,
    expires_at,
  } = row;

  if config.automation_api.enabled {
    if config.automation_api.require_ttl && expires_at.is_none() {
      bail!("dynamic policy {id} requires expires_at when automation API require_ttl is enabled");
    }
    let Some(signature_key) = signature_key else {
      bail!("dynamic policy automation API requires a signature key");
    };
    if signature_version.as_deref() != Some(signature::SIGNATURE_VERSION) {
      bail!("dynamic policy {id} has missing or unsupported signature_version");
    }
    let Some(row_signature) = row_signature.as_deref() else {
      bail!("dynamic policy {id} is missing row_signature");
    };
    signature::verify(
      signature_key,
      &signature::DynamicPolicySignatureFields {
        namespace,
        enabled,
        priority,
        name: &name,
        source: &source,
        action: &action,
        subject_type: &subject_type,
        subject: &subject,
        route_name: route_name.as_deref(),
        method: method.as_deref(),
        path_prefix: path_prefix.as_deref(),
        rate: rate.as_deref(),
        burst,
        status,
        body: body.as_deref(),
        reason: reason.as_deref(),
        code: code.as_deref(),
        mode: &mode,
        writer_identity: writer_identity.as_deref(),
        expires_at: expires_at.as_deref(),
      },
      row_signature,
    )
    .with_context(|| format!("dynamic policy {id} signature verification failed"))?;
  }

  validate_string_len("dynamic policy name", &name, MAX_DYNAMIC_POLICY_NAME_BYTES)?;
  validate_string_len(
    "dynamic policy source",
    &source,
    MAX_DYNAMIC_POLICY_NAME_BYTES,
  )?;
  validate_string_len(
    "dynamic policy subject",
    &subject,
    MAX_DYNAMIC_POLICY_SUBJECT_BYTES,
  )?;
  if name.trim().is_empty() {
    bail!("dynamic policy {id} name must not be empty");
  }

  let action = match action.as_str() {
    "allow" => DynamicPolicyAction::Allow,
    "challenge" => DynamicPolicyAction::Challenge,
    "reject" => DynamicPolicyAction::Reject,
    "rate_limit" => DynamicPolicyAction::RateLimit,
    "silent_close" => DynamicPolicyAction::SilentClose,
    _ => bail!("dynamic policy {id} has unsupported action {action}"),
  };
  let subject_type = parse_subject_type(&subject_type)
    .with_context(|| format!("dynamic policy {id} has unsupported subject_type {subject_type}"))?;
  let mode = match mode.as_str() {
    "enforce" => DynamicPolicyMode::Enforce,
    "dry_run" => DynamicPolicyMode::DryRun,
    _ => bail!("dynamic policy {id} has unsupported mode {mode}"),
  };

  let route_name = route_name
    .map(|route| validate_route_name(id, route, route_names))
    .transpose()?;
  let method = method
    .map(|method| validate_method(id, method))
    .transpose()?;
  let path_prefix = path_prefix
    .map(|path| validate_path_prefix(id, &path, config.matching.normalize_path))
    .transpose()?;
  let reason = reason
    .map(|reason| {
      validate_string_len(
        "dynamic policy reason",
        &reason,
        MAX_DYNAMIC_POLICY_REASON_BYTES,
      )?;
      Ok::<_, anyhow::Error>(reason)
    })
    .transpose()?;
  let code = code
    .map(|code| {
      validate_string_len("dynamic policy code", &code, MAX_DYNAMIC_POLICY_NAME_BYTES)?;
      if code
        .bytes()
        .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')))
      {
        bail!("dynamic policy {id} code contains invalid characters");
      }
      Ok::<_, anyhow::Error>(code)
    })
    .transpose()?;
  let status_provided = status.is_some();
  let status = match status
    .map(validate_status)
    .transpose()
    .with_context(|| format!("dynamic policy {id} has invalid status"))?
  {
    Some(status) => status,
    None if action == DynamicPolicyAction::Challenge => StatusCode::FORBIDDEN,
    None => StatusCode::from_u16(config.default_status)
      .context("dynamic_policy.default_status is not a valid HTTP status")?,
  };
  if action == DynamicPolicyAction::SilentClose {
    if status_provided || body.is_some() {
      bail!("dynamic policy {id} silent_close action does not support status or body");
    }
    if rate.is_some() || burst.is_some() {
      bail!("dynamic policy {id} silent_close action does not support rate or burst");
    }
  }
  if action == DynamicPolicyAction::Challenge {
    if body.is_some() {
      bail!("dynamic policy {id} challenge action does not support body");
    }
    if rate.is_some() || burst.is_some() {
      bail!("dynamic policy {id} challenge action does not support rate or burst");
    }
  }
  let body = if action == DynamicPolicyAction::SilentClose {
    String::new()
  } else {
    body.unwrap_or_else(|| config.default_body.clone())
  };
  validate_string_len("dynamic policy body", &body, MAX_DYNAMIC_POLICY_BODY_BYTES)?;

  let (subject, cidr) = validate_subject(
    id,
    subject_type,
    &subject,
    route_name.as_deref(),
    path_prefix.as_deref(),
  )?;

  let burst = burst
    .map(|value| {
      if value <= 0 {
        bail!("dynamic policy {id} burst must be greater than 0");
      }
      u32::try_from(value).context("dynamic policy burst does not fit in u32")
    })
    .transpose()?;
  if action == DynamicPolicyAction::RateLimit {
    let Some(rate) = rate.as_deref() else {
      bail!("dynamic policy {id} rate_limit action requires rate");
    };
    validate_string_len("dynamic policy rate", rate, MAX_DYNAMIC_POLICY_RATE_BYTES)?;
    crate::limits::parse_rate(rate)
      .with_context(|| format!("dynamic policy {id} has invalid rate"))?;
    if burst.is_none() {
      bail!("dynamic policy {id} rate_limit action requires burst");
    }
  }

  Ok(DynamicPolicy {
    id,
    priority,
    name,
    source,
    action,
    subject_type,
    subject,
    cidr,
    route_name,
    method,
    path_prefix,
    rate,
    burst,
    status,
    body,
    reason,
    code,
    mode,
  })
}

pub(super) fn validate_string_len(field: &str, value: &str, max: usize) -> anyhow::Result<()> {
  if value.len() > max {
    bail!("{field} must be at most {max} bytes");
  }
  Ok(())
}

pub(super) fn validate_route_name(
  id: i64,
  route: String,
  route_names: &HashSet<String>,
) -> anyhow::Result<String> {
  validate_string_len(
    "dynamic policy route_name",
    &route,
    MAX_DYNAMIC_POLICY_ROUTE_BYTES,
  )?;
  if !route_names.contains(&route) {
    bail!("dynamic policy {id} references unknown route_name {route}");
  }
  Ok(route)
}

pub(super) fn validate_method(id: i64, method: String) -> anyhow::Result<Method> {
  validate_string_len("dynamic policy method", &method, 32)?;
  if method != method.to_ascii_uppercase() {
    bail!("dynamic policy {id} method must be uppercase");
  }
  Method::from_bytes(method.as_bytes())
    .with_context(|| format!("dynamic policy {id} has invalid method {method}"))
}

pub(super) fn validate_path_prefix(id: i64, path: &str, normalize: bool) -> anyhow::Result<String> {
  validate_string_len(
    "dynamic policy path_prefix",
    path,
    MAX_DYNAMIC_POLICY_PATH_BYTES,
  )?;
  let path = if normalize {
    crate::waf::normalization::normalize_path(path)
  } else {
    path.to_string()
  };
  if !path.starts_with('/') {
    bail!("dynamic policy {id} path_prefix must start with '/'");
  }
  if path
    .bytes()
    .any(|byte| byte.is_ascii_control() || byte == b'\\')
  {
    bail!("dynamic policy {id} path_prefix contains unsafe characters");
  }
  Ok(path)
}

pub(super) fn validate_status(status: i32) -> anyhow::Result<StatusCode> {
  if status < 0 {
    bail!("status must be positive");
  }
  let status = u16::try_from(status).context("status does not fit in u16")?;
  StatusCode::from_u16(status).map_err(Into::into)
}

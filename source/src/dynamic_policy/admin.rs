use std::sync::Arc;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};

use super::{DynamicPolicyRuntime, PolicyRow, signature};

mod store;
mod validation;
use store::*;
use validation::*;

#[derive(Debug, Clone, Deserialize)]
pub struct DynamicPolicyAdminCreate {
  #[serde(default)]
  pub enabled: Option<bool>,
  #[serde(default)]
  pub priority: Option<i32>,
  pub source: String,
  pub name: String,
  pub action: String,
  pub subject_type: String,
  pub subject: String,
  #[serde(default)]
  pub route_name: Option<String>,
  #[serde(default)]
  pub method: Option<String>,
  #[serde(default)]
  pub path_prefix: Option<String>,
  #[serde(default)]
  pub rate: Option<String>,
  #[serde(default)]
  pub burst: Option<i32>,
  #[serde(default)]
  pub status: Option<i32>,
  #[serde(default)]
  pub body: Option<String>,
  #[serde(default)]
  pub reason: Option<String>,
  #[serde(default)]
  pub code: Option<String>,
  #[serde(default)]
  pub mode: Option<String>,
  #[serde(default)]
  pub expires_at: Option<String>,
  #[serde(default)]
  pub ttl_seconds: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DynamicPolicyAdminPatch {
  #[serde(default)]
  pub enabled: Option<bool>,
  #[serde(default)]
  pub priority: Option<i32>,
  #[serde(default)]
  pub source: Option<String>,
  #[serde(default)]
  pub name: Option<String>,
  #[serde(default)]
  pub action: Option<String>,
  #[serde(default)]
  pub subject_type: Option<String>,
  #[serde(default)]
  pub subject: Option<String>,
  #[serde(default)]
  pub route_name: Option<String>,
  #[serde(default)]
  pub method: Option<String>,
  #[serde(default)]
  pub path_prefix: Option<String>,
  #[serde(default)]
  pub rate: Option<String>,
  #[serde(default)]
  pub burst: Option<i32>,
  #[serde(default)]
  pub status: Option<i32>,
  #[serde(default)]
  pub body: Option<String>,
  #[serde(default)]
  pub reason: Option<String>,
  #[serde(default)]
  pub code: Option<String>,
  #[serde(default)]
  pub mode: Option<String>,
  #[serde(default)]
  pub expires_at: Option<String>,
  #[serde(default)]
  pub ttl_seconds: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DynamicPolicyAdminImport {
  pub policies: Vec<DynamicPolicyAdminCreate>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DynamicPolicyAdminRecord {
  pub id: i64,
  pub namespace: String,
  pub enabled: bool,
  pub priority: i32,
  pub source: String,
  pub name: String,
  pub action: String,
  pub subject_type: String,
  pub subject: String,
  pub route_name: Option<String>,
  pub method: Option<String>,
  pub path_prefix: Option<String>,
  pub rate: Option<String>,
  pub burst: Option<i32>,
  pub status: Option<i32>,
  pub body: Option<String>,
  pub reason: Option<String>,
  pub code: Option<String>,
  pub mode: String,
  pub writer_identity: Option<String>,
  pub signature_version: Option<String>,
  pub row_signature: Option<String>,
  pub expires_at: Option<String>,
  pub created_at: String,
  pub updated_at: String,
}

impl DynamicPolicyRuntime {
  pub async fn admin_list(&self) -> anyhow::Result<Vec<DynamicPolicyAdminRecord>> {
    let inner = self.admin_inner()?;
    select_admin_records(&inner.pool, &inner.namespace).await
  }

  pub async fn admin_get(&self, id: i64) -> anyhow::Result<Option<DynamicPolicyAdminRecord>> {
    let inner = self.admin_inner()?;
    select_admin_record(&inner.pool, &inner.namespace, id).await
  }

  pub async fn admin_create(
    &self,
    actor: &str,
    input: DynamicPolicyAdminCreate,
  ) -> anyhow::Result<DynamicPolicyAdminRecord> {
    let inner = self.admin_inner()?;
    validate_create(&inner, &input)?;
    enforce_source_quota(&inner, &input.source, None, input.enabled.unwrap_or(true)).await?;
    let id = insert_policy(&inner.pool, &inner.namespace, actor, &input).await?;
    sign_policy(&inner, id).await?;
    bump_generation(&inner.pool, &inner.namespace).await?;
    audit(
      &inner.pool,
      &inner.namespace,
      Some(id),
      actor,
      "create",
      &input.source,
      &input.name,
      "applied",
      None,
    )
    .await?;
    select_admin_record(&inner.pool, &inner.namespace, id)
      .await?
      .context("created dynamic policy disappeared")
  }

  pub async fn admin_patch(
    &self,
    actor: &str,
    id: i64,
    input: DynamicPolicyAdminPatch,
  ) -> anyhow::Result<Option<DynamicPolicyAdminRecord>> {
    let inner = self.admin_inner()?;
    let Some(existing) = select_admin_record(&inner.pool, &inner.namespace, id).await? else {
      return Ok(None);
    };
    validate_patch(&inner, &input)?;
    validate_patch_merged(&inner, &existing, &input)?;
    let source = input.source.as_deref().unwrap_or(&existing.source);
    let enabled = input.enabled.unwrap_or(existing.enabled);
    enforce_source_quota(&inner, source, Some(id), enabled).await?;
    update_policy(&inner.pool, &inner.namespace, actor, id, &input).await?;
    sign_policy(&inner, id).await?;
    bump_generation(&inner.pool, &inner.namespace).await?;
    audit(
      &inner.pool,
      &inner.namespace,
      Some(id),
      actor,
      "patch",
      source,
      &existing.name,
      "applied",
      None,
    )
    .await?;
    select_admin_record(&inner.pool, &inner.namespace, id).await
  }

  pub async fn admin_delete(&self, actor: &str, id: i64) -> anyhow::Result<bool> {
    let inner = self.admin_inner()?;
    let result = sqlx::query(
      "UPDATE oxibelt_dynamic_policies
          SET enabled = false, writer_identity = $3, signature_version = NULL,
              row_signature = NULL, updated_at = now()
        WHERE namespace = $1 AND id = $2",
    )
    .bind(inner.namespace.as_ref())
    .bind(id)
    .bind(actor)
    .execute(&inner.pool)
    .await?;
    if result.rows_affected() == 0 {
      return Ok(false);
    }
    bump_generation(&inner.pool, &inner.namespace).await?;
    audit(
      &inner.pool,
      &inner.namespace,
      Some(id),
      actor,
      "delete",
      "",
      "",
      "applied",
      None,
    )
    .await?;
    Ok(true)
  }

  pub async fn admin_export(&self) -> anyhow::Result<Vec<DynamicPolicyAdminRecord>> {
    self.admin_list().await
  }

  pub async fn admin_import(
    &self,
    actor: &str,
    input: DynamicPolicyAdminImport,
  ) -> anyhow::Result<Vec<DynamicPolicyAdminRecord>> {
    let inner = self.admin_inner()?;
    let mut records = Vec::with_capacity(input.policies.len());
    for policy in input.policies {
      validate_create(&inner, &policy)?;
      let existing =
        policy_ids_by_source_name(&inner.pool, &inner.namespace, &policy.source, &policy.name)
          .await?;
      let id = if let Some((&id, duplicates)) = existing.split_first() {
        enforce_source_quota(
          &inner,
          &policy.source,
          Some(id),
          policy.enabled.unwrap_or(true),
        )
        .await?;
        replace_policy(&inner.pool, &inner.namespace, actor, id, &policy).await?;
        if !duplicates.is_empty() {
          sqlx::query("UPDATE oxibelt_dynamic_policies SET enabled = false, updated_at = now(), writer_identity = $3, signature_version = NULL, row_signature = NULL WHERE namespace = $1 AND id = ANY($2)")
            .bind(inner.namespace.as_ref())
            .bind(duplicates)
            .bind(actor)
            .execute(&inner.pool)
            .await?;
        }
        id
      } else {
        enforce_source_quota(&inner, &policy.source, None, policy.enabled.unwrap_or(true)).await?;
        insert_policy(&inner.pool, &inner.namespace, actor, &policy).await?
      };
      sign_policy(&inner, id).await?;
      records.push(
        select_admin_record(&inner.pool, &inner.namespace, id)
          .await?
          .context("imported dynamic policy disappeared")?,
      );
      audit(
        &inner.pool,
        &inner.namespace,
        Some(id),
        actor,
        "import",
        &policy.source,
        &policy.name,
        "applied",
        None,
      )
      .await?;
    }
    bump_generation(&inner.pool, &inner.namespace).await?;
    Ok(records)
  }

  fn admin_inner(&self) -> anyhow::Result<Arc<super::DynamicPolicyInner>> {
    let Some(inner) = &self.inner else {
      bail!("dynamic policy is disabled");
    };
    if !inner.config.automation_api.enabled {
      bail!("dynamic policy automation API is disabled");
    }
    Ok(inner.clone())
  }
}

async fn insert_policy(
  pool: &Pool<Postgres>,
  namespace: &str,
  actor: &str,
  input: &DynamicPolicyAdminCreate,
) -> anyhow::Result<i64> {
  let id: i64 = sqlx::query_scalar(
    "INSERT INTO oxibelt_dynamic_policies
       (namespace, enabled, priority, name, source, action, subject_type, subject, route_name,
        method, path_prefix, rate, burst, status, body, reason, code, mode, writer_identity,
        expires_at)
     VALUES
       ($1, $2, $3, $4, $5, $6, $7, $8, $9,
        $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
        CASE
          WHEN $20::bigint IS NOT NULL THEN now() + ($20::bigint * interval '1 second')
          WHEN $21::text IS NOT NULL THEN $21::timestamptz
          ELSE NULL
        END)
     RETURNING id",
  )
  .bind(namespace)
  .bind(input.enabled.unwrap_or(true))
  .bind(input.priority.unwrap_or(100))
  .bind(&input.name)
  .bind(&input.source)
  .bind(&input.action)
  .bind(&input.subject_type)
  .bind(&input.subject)
  .bind(&input.route_name)
  .bind(&input.method)
  .bind(&input.path_prefix)
  .bind(&input.rate)
  .bind(input.burst)
  .bind(input.status)
  .bind(&input.body)
  .bind(&input.reason)
  .bind(&input.code)
  .bind(input.mode.as_deref().unwrap_or("enforce"))
  .bind(actor)
  .bind(input.ttl_seconds)
  .bind(&input.expires_at)
  .fetch_one(pool)
  .await?;
  Ok(id)
}

async fn replace_policy(
  pool: &Pool<Postgres>,
  namespace: &str,
  actor: &str,
  id: i64,
  input: &DynamicPolicyAdminCreate,
) -> anyhow::Result<()> {
  sqlx::query(
    "UPDATE oxibelt_dynamic_policies
        SET enabled = $3, priority = $4, name = $5, source = $6, action = $7,
            subject_type = $8, subject = $9, route_name = $10, method = $11,
            path_prefix = $12, rate = $13, burst = $14, status = $15, body = $16,
            reason = $17, code = $18, mode = $19, writer_identity = $20,
            expires_at = CASE
              WHEN $21::bigint IS NOT NULL THEN now() + ($21::bigint * interval '1 second')
              WHEN $22::text IS NOT NULL THEN $22::timestamptz
              ELSE NULL
            END,
            signature_version = NULL, row_signature = NULL, updated_at = now()
      WHERE namespace = $1 AND id = $2",
  )
  .bind(namespace)
  .bind(id)
  .bind(input.enabled.unwrap_or(true))
  .bind(input.priority.unwrap_or(100))
  .bind(&input.name)
  .bind(&input.source)
  .bind(&input.action)
  .bind(&input.subject_type)
  .bind(&input.subject)
  .bind(&input.route_name)
  .bind(&input.method)
  .bind(&input.path_prefix)
  .bind(&input.rate)
  .bind(input.burst)
  .bind(input.status)
  .bind(&input.body)
  .bind(&input.reason)
  .bind(&input.code)
  .bind(input.mode.as_deref().unwrap_or("enforce"))
  .bind(actor)
  .bind(input.ttl_seconds)
  .bind(&input.expires_at)
  .execute(pool)
  .await?;
  Ok(())
}

async fn update_policy(
  pool: &Pool<Postgres>,
  namespace: &str,
  actor: &str,
  id: i64,
  input: &DynamicPolicyAdminPatch,
) -> anyhow::Result<()> {
  sqlx::query(
    "UPDATE oxibelt_dynamic_policies
        SET enabled = COALESCE($3, enabled), priority = COALESCE($4, priority),
            name = COALESCE($5, name), source = COALESCE($6, source),
            action = COALESCE($7, action), subject_type = COALESCE($8, subject_type),
            subject = COALESCE($9, subject), route_name = COALESCE($10, route_name),
            method = COALESCE($11, method), path_prefix = COALESCE($12, path_prefix),
            rate = COALESCE($13, rate), burst = COALESCE($14, burst),
            status = COALESCE($15, status), body = COALESCE($16, body),
            reason = COALESCE($17, reason), code = COALESCE($18, code),
            mode = COALESCE($19, mode), writer_identity = $20,
            expires_at = CASE
              WHEN $21::bigint IS NOT NULL THEN now() + ($21::bigint * interval '1 second')
              WHEN $22::text IS NOT NULL THEN $22::timestamptz
              ELSE expires_at
            END,
            signature_version = NULL, row_signature = NULL, updated_at = now()
      WHERE namespace = $1 AND id = $2",
  )
  .bind(namespace)
  .bind(id)
  .bind(input.enabled)
  .bind(input.priority)
  .bind(&input.name)
  .bind(&input.source)
  .bind(&input.action)
  .bind(&input.subject_type)
  .bind(&input.subject)
  .bind(&input.route_name)
  .bind(&input.method)
  .bind(&input.path_prefix)
  .bind(&input.rate)
  .bind(input.burst)
  .bind(input.status)
  .bind(&input.body)
  .bind(&input.reason)
  .bind(&input.code)
  .bind(&input.mode)
  .bind(actor)
  .bind(input.ttl_seconds)
  .bind(&input.expires_at)
  .execute(pool)
  .await?;
  Ok(())
}

async fn sign_policy(inner: &super::DynamicPolicyInner, id: i64) -> anyhow::Result<()> {
  let key = inner
    .signature_key
    .as_ref()
    .context("dynamic policy automation API signature key is unavailable")?;
  let row = select_policy_row(&inner.pool, &inner.namespace, id)
    .await?
    .context("dynamic policy row not found for signing")?;
  if row.enabled {
    validate_ttl(inner, row.expires_at.as_deref(), None)?;
  }
  validate_policy_fields(
    inner,
    &row.name,
    &row.source,
    &row.action,
    &row.subject_type,
    &row.subject,
    row.route_name.as_deref(),
    row.method.as_deref(),
    row.path_prefix.as_deref(),
    row.rate.as_deref(),
    row.burst,
    row.status,
    row.body.as_deref(),
    row.reason.as_deref(),
    row.code.as_deref(),
    &row.mode,
  )?;
  let signature = signature::sign(key, &signature_fields(&inner.namespace, &row));
  sqlx::query(
    "UPDATE oxibelt_dynamic_policies
        SET signature_version = $3, row_signature = $4
      WHERE namespace = $1 AND id = $2",
  )
  .bind(inner.namespace.as_ref())
  .bind(id)
  .bind(signature::SIGNATURE_VERSION)
  .bind(signature)
  .execute(&inner.pool)
  .await?;
  Ok(())
}

fn signature_fields<'a>(
  namespace: &'a str,
  row: &'a PolicyRow,
) -> signature::DynamicPolicySignatureFields<'a> {
  signature::DynamicPolicySignatureFields {
    namespace,
    enabled: row.enabled,
    priority: row.priority,
    name: &row.name,
    source: &row.source,
    action: &row.action,
    subject_type: &row.subject_type,
    subject: &row.subject,
    route_name: row.route_name.as_deref(),
    method: row.method.as_deref(),
    path_prefix: row.path_prefix.as_deref(),
    rate: row.rate.as_deref(),
    burst: row.burst,
    status: row.status,
    body: row.body.as_deref(),
    reason: row.reason.as_deref(),
    code: row.code.as_deref(),
    mode: &row.mode,
    writer_identity: row.writer_identity.as_deref(),
    expires_at: row.expires_at.as_deref(),
  }
}

async fn enforce_source_quota(
  inner: &super::DynamicPolicyInner,
  source: &str,
  exclude_id: Option<i64>,
  enabled: bool,
) -> anyhow::Result<()> {
  if !enabled {
    return Ok(());
  }
  let quota = inner
    .config
    .automation_api
    .quota_for_source(source, inner.config.max_policies);
  let count: i64 = sqlx::query_scalar(
    "SELECT count(*) FROM oxibelt_dynamic_policies
      WHERE namespace = $1 AND source = $2 AND enabled = true
        AND (expires_at IS NULL OR expires_at > now())
        AND ($3::bigint IS NULL OR id <> $3)",
  )
  .bind(inner.namespace.as_ref())
  .bind(source)
  .bind(exclude_id)
  .fetch_one(&inner.pool)
  .await?;
  if count >= i64::try_from(quota).unwrap_or(i64::MAX) {
    bail!("dynamic policy source {source} exceeds active policy quota {quota}");
  }
  Ok(())
}

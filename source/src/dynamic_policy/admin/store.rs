use anyhow::Context;
use sqlx::{Pool, Postgres, Row, Transaction};

use super::{DynamicPolicyAdminAuditRecord, DynamicPolicyAdminRecord};
use crate::dynamic_policy::{PolicyRow, policy_row_from_pg};

pub(super) async fn select_policy_row_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  id: i64,
) -> anyhow::Result<Option<PolicyRow>> {
  let row = sqlx::query(
    "SELECT id, enabled, priority, name, source, action, subject_type, subject, route_name, method,
            path_prefix, rate, burst, status, body, reason, code, mode, writer_identity,
            signature_version, row_signature, expires_at::text AS expires_at
       FROM oxibelt_dynamic_policies
      WHERE namespace = $1 AND id = $2",
  )
  .bind(namespace)
  .bind(id)
  .fetch_optional(&mut **tx)
  .await?;
  row.as_ref().map(policy_row_from_pg).transpose()
}

pub(super) async fn select_admin_records(
  pool: &Pool<Postgres>,
  namespace: &str,
) -> anyhow::Result<Vec<DynamicPolicyAdminRecord>> {
  let rows = sqlx::query(
    "SELECT id, namespace, enabled, priority, name, source, action, subject_type, subject,
            route_name, method, path_prefix, rate, burst, status, body, reason, code, mode,
            writer_identity, signature_version, row_signature, expires_at::text AS expires_at,
            created_at::text AS created_at, updated_at::text AS updated_at
       FROM oxibelt_dynamic_policies
      WHERE namespace = $1
      ORDER BY source ASC, name ASC, id ASC",
  )
  .bind(namespace)
  .fetch_all(pool)
  .await?;
  rows.iter().map(admin_record_from_row).collect()
}

pub(super) async fn select_admin_record(
  pool: &Pool<Postgres>,
  namespace: &str,
  id: i64,
) -> anyhow::Result<Option<DynamicPolicyAdminRecord>> {
  let row = sqlx::query(
    "SELECT id, namespace, enabled, priority, name, source, action, subject_type, subject,
            route_name, method, path_prefix, rate, burst, status, body, reason, code, mode,
            writer_identity, signature_version, row_signature, expires_at::text AS expires_at,
            created_at::text AS created_at, updated_at::text AS updated_at
       FROM oxibelt_dynamic_policies
      WHERE namespace = $1 AND id = $2",
  )
  .bind(namespace)
  .bind(id)
  .fetch_optional(pool)
  .await?;
  row.as_ref().map(admin_record_from_row).transpose()
}

pub(super) async fn select_admin_record_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  id: i64,
) -> anyhow::Result<Option<DynamicPolicyAdminRecord>> {
  let row = sqlx::query(
    "SELECT id, namespace, enabled, priority, name, source, action, subject_type, subject,
            route_name, method, path_prefix, rate, burst, status, body, reason, code, mode,
            writer_identity, signature_version, row_signature, expires_at::text AS expires_at,
            created_at::text AS created_at, updated_at::text AS updated_at
       FROM oxibelt_dynamic_policies
      WHERE namespace = $1 AND id = $2",
  )
  .bind(namespace)
  .bind(id)
  .fetch_optional(&mut **tx)
  .await?;
  row.as_ref().map(admin_record_from_row).transpose()
}

pub(super) async fn select_audit_records(
  pool: &Pool<Postgres>,
  namespace: &str,
  policy_id: Option<i64>,
  limit: i64,
) -> anyhow::Result<Vec<DynamicPolicyAdminAuditRecord>> {
  let rows = sqlx::query(
    "SELECT id, namespace, policy_id, actor, operation, source, name, outcome, error,
            created_at::text AS created_at
       FROM oxibelt_dynamic_policy_audit
      WHERE namespace = $1
        AND ($2::bigint IS NULL OR policy_id = $2)
      ORDER BY id DESC
      LIMIT $3",
  )
  .bind(namespace)
  .bind(policy_id)
  .bind(limit)
  .fetch_all(pool)
  .await?;
  rows.iter().map(audit_record_from_row).collect()
}

fn admin_record_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<DynamicPolicyAdminRecord> {
  Ok(DynamicPolicyAdminRecord {
    id: row.try_get("id")?,
    namespace: row.try_get("namespace")?,
    enabled: row.try_get("enabled")?,
    priority: row.try_get("priority")?,
    source: row.try_get("source")?,
    name: row.try_get("name")?,
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
    created_at: row.try_get("created_at")?,
    updated_at: row.try_get("updated_at")?,
  })
}

fn audit_record_from_row(
  row: &sqlx::postgres::PgRow,
) -> anyhow::Result<DynamicPolicyAdminAuditRecord> {
  Ok(DynamicPolicyAdminAuditRecord {
    id: row.try_get("id")?,
    namespace: row.try_get("namespace")?,
    policy_id: row.try_get("policy_id")?,
    actor: row.try_get("actor")?,
    operation: row.try_get("operation")?,
    source: row.try_get("source")?,
    name: row.try_get("name")?,
    outcome: row.try_get("outcome")?,
    error: row.try_get("error")?,
    created_at: row.try_get("created_at")?,
  })
}

pub(super) async fn policy_ids_by_source_name_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  source: &str,
  name: &str,
) -> anyhow::Result<Vec<i64>> {
  let ids = sqlx::query_scalar(
    "SELECT id FROM oxibelt_dynamic_policies
      WHERE namespace = $1 AND source = $2 AND name = $3
      ORDER BY id ASC",
  )
  .bind(namespace)
  .bind(source)
  .bind(name)
  .fetch_all(&mut **tx)
  .await?;
  Ok(ids)
}

pub(super) async fn select_generation(
  pool: &Pool<Postgres>,
  namespace: &str,
) -> anyhow::Result<i64> {
  let generation: Option<i64> = sqlx::query_scalar(
    "SELECT generation FROM oxibelt_dynamic_policy_generation WHERE namespace = $1",
  )
  .bind(namespace)
  .fetch_optional(pool)
  .await?;
  Ok(generation.unwrap_or(0))
}

pub(super) async fn lock_generation_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
) -> anyhow::Result<i64> {
  sqlx::query(
    "INSERT INTO oxibelt_dynamic_policy_generation (namespace, generation, updated_at)
     VALUES ($1, 0, now())
     ON CONFLICT (namespace) DO NOTHING",
  )
  .bind(namespace)
  .execute(&mut **tx)
  .await?;
  let generation = sqlx::query_scalar(
    "SELECT generation FROM oxibelt_dynamic_policy_generation
      WHERE namespace = $1
      FOR UPDATE",
  )
  .bind(namespace)
  .fetch_one(&mut **tx)
  .await?;
  Ok(generation)
}

pub(super) async fn bump_generation_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
) -> anyhow::Result<()> {
  sqlx::query(
    "INSERT INTO oxibelt_dynamic_policy_generation (namespace, generation, updated_at)
     VALUES ($1, 1, now())
     ON CONFLICT (namespace)
     DO UPDATE SET generation = oxibelt_dynamic_policy_generation.generation + 1,
                   updated_at = now()",
  )
  .bind(namespace)
  .execute(&mut **tx)
  .await?;
  Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn audit(
  pool: &Pool<Postgres>,
  namespace: &str,
  policy_id: Option<i64>,
  actor: &str,
  operation: &str,
  source: &str,
  name: &str,
  outcome: &str,
  error: Option<&str>,
) -> anyhow::Result<()> {
  sqlx::query(
    "INSERT INTO oxibelt_dynamic_policy_audit
       (namespace, policy_id, actor, operation, source, name, outcome, error)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
  )
  .bind(namespace)
  .bind(policy_id)
  .bind(actor)
  .bind(operation)
  .bind(source)
  .bind(name)
  .bind(outcome)
  .bind(error)
  .execute(pool)
  .await
  .context("failed to write dynamic policy audit row")?;
  Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn audit_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  policy_id: Option<i64>,
  actor: &str,
  operation: &str,
  source: &str,
  name: &str,
  outcome: &str,
  error: Option<&str>,
) -> anyhow::Result<()> {
  sqlx::query(
    "INSERT INTO oxibelt_dynamic_policy_audit
       (namespace, policy_id, actor, operation, source, name, outcome, error)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
  )
  .bind(namespace)
  .bind(policy_id)
  .bind(actor)
  .bind(operation)
  .bind(source)
  .bind(name)
  .bind(outcome)
  .bind(error)
  .execute(&mut **tx)
  .await
  .context("failed to write dynamic policy audit row")?;
  Ok(())
}

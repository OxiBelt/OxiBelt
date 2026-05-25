use sqlx::{Postgres, Transaction};

use super::{DynamicPolicyAdminCreate, DynamicPolicyAdminPatch};

pub(super) async fn begin_admin_write(
  inner: &super::super::DynamicPolicyInner,
) -> anyhow::Result<Transaction<'static, Postgres>> {
  let mut tx = inner.pool.begin().await?;
  sqlx::query("LOCK TABLE oxibelt_dynamic_policies IN SHARE ROW EXCLUSIVE MODE")
    .execute(&mut *tx)
    .await?;
  Ok(tx)
}

pub(super) async fn insert_policy(
  tx: &mut Transaction<'_, Postgres>,
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
  .fetch_one(&mut **tx)
  .await?;
  Ok(id)
}

pub(super) async fn replace_policy(
  tx: &mut Transaction<'_, Postgres>,
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
  .execute(&mut **tx)
  .await?;
  Ok(())
}

pub(super) async fn update_policy(
  tx: &mut Transaction<'_, Postgres>,
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
  .execute(&mut **tx)
  .await?;
  Ok(())
}

use anyhow::Context;
use serde_json::{Value, json};
use sqlx::{Pool, Postgres, QueryBuilder, Row, Transaction};

use super::{DynamicPolicyAdminAuditRecord, DynamicPolicyAdminRecord};
use crate::admin_list::{AdminListOrder, AdminListPage, AdminListQuery, parse_bool};
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

pub(super) async fn select_admin_records_page(
  pool: &Pool<Postgres>,
  namespace: &str,
  list: &AdminListQuery,
) -> anyhow::Result<AdminListPage<DynamicPolicyAdminRecord>> {
  let mut query = QueryBuilder::<Postgres>::new(
    "SELECT id, namespace, enabled, priority, name, source, action, subject_type, subject,
            route_name, method, path_prefix, rate, burst, status, body, reason, code, mode,
            writer_identity, signature_version, row_signature, expires_at::text AS expires_at,
            created_at::text AS created_at, updated_at::text AS updated_at
       FROM oxibelt_dynamic_policies
      WHERE namespace = ",
  );
  query.push_bind(namespace.to_string());
  push_admin_filters(&mut query, list)?;
  push_admin_cursor(&mut query, list)?;
  push_admin_order(&mut query, list);
  query.push(" LIMIT ");
  query.push_bind(i64::try_from(list.limit().saturating_add(1)).unwrap_or(1001));

  let rows = query.build().fetch_all(pool).await?;
  let mut records = rows
    .iter()
    .map(admin_record_from_row)
    .collect::<anyhow::Result<Vec<_>>>()?;
  let has_more = records.len() > list.limit();
  if has_more {
    records.truncate(list.limit());
  }
  let next_position = if has_more {
    records
      .last()
      .map(|record| admin_cursor_position(record, list.sort()))
  } else {
    None
  };
  let pagination = list.pagination(has_more, next_position)?;
  Ok(AdminListPage {
    items: records,
    pagination,
  })
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

fn push_admin_filters(
  query: &mut QueryBuilder<Postgres>,
  list: &AdminListQuery,
) -> anyhow::Result<()> {
  if let Some(source) = list.filter("source") {
    query.push(" AND source = ");
    query.push_bind(source.to_string());
  }
  if let Some(name) = list.filter("name") {
    query.push(" AND name = ");
    query.push_bind(name.to_string());
  }
  if let Some(enabled) = list.filter("enabled") {
    query.push(" AND enabled = ");
    query.push_bind(parse_bool(enabled)?);
  }
  Ok(())
}

fn push_admin_cursor(
  query: &mut QueryBuilder<Postgres>,
  list: &AdminListQuery,
) -> anyhow::Result<()> {
  let Some(position) = list.cursor_position() else {
    return Ok(());
  };
  let id = position
    .get("id")
    .and_then(Value::as_i64)
    .context("cursor position is invalid")?;
  let op = match list.order() {
    AdminListOrder::Asc => ">",
    AdminListOrder::Desc => "<",
  };
  if list.sort() == "id" {
    query.push(" AND id ");
    query.push(op);
    query.push(" ");
    query.push_bind(id);
    return Ok(());
  }

  query.push(" AND (");
  push_admin_sort_column(query, list.sort());
  query.push(" ");
  query.push(op);
  query.push(" ");
  push_admin_cursor_value(query, list.sort(), position)?;
  query.push(" OR (");
  push_admin_sort_column(query, list.sort());
  query.push(" = ");
  push_admin_cursor_value(query, list.sort(), position)?;
  query.push(" AND id ");
  query.push(op);
  query.push(" ");
  query.push_bind(id);
  query.push("))");
  Ok(())
}

fn push_admin_order(query: &mut QueryBuilder<Postgres>, list: &AdminListQuery) {
  query.push(" ORDER BY ");
  push_admin_sort_column(query, list.sort());
  push_order_direction(query, list.order());
  if list.sort() != "id" {
    query.push(", id");
    push_order_direction(query, list.order());
  }
}

fn push_admin_sort_column(query: &mut QueryBuilder<Postgres>, sort: &str) {
  match sort {
    "source" => query.push("source"),
    "name" => query.push("name"),
    "enabled" => query.push("enabled"),
    "priority" => query.push("priority"),
    "created_at" => query.push("created_at"),
    "updated_at" => query.push("updated_at"),
    "id" => query.push("id"),
    _ => query.push("source"),
  };
}

fn push_order_direction(query: &mut QueryBuilder<Postgres>, order: AdminListOrder) {
  match order {
    AdminListOrder::Asc => query.push(" ASC"),
    AdminListOrder::Desc => query.push(" DESC"),
  };
}

fn push_admin_cursor_value(
  query: &mut QueryBuilder<Postgres>,
  sort: &str,
  position: &Value,
) -> anyhow::Result<()> {
  let value = position
    .get("value")
    .context("cursor position is invalid")?;
  match sort {
    "source" | "name" => {
      query.push_bind(
        value
          .as_str()
          .context("cursor position is invalid")?
          .to_string(),
      );
    }
    "enabled" => {
      query.push_bind(value.as_bool().context("cursor position is invalid")?);
    }
    "priority" => {
      query.push_bind(
        i32::try_from(value.as_i64().context("cursor position is invalid")?)
          .context("cursor position is invalid")?,
      );
    }
    "created_at" | "updated_at" => {
      query.push_bind(
        value
          .as_str()
          .context("cursor position is invalid")?
          .to_string(),
      );
      query.push("::timestamptz");
    }
    _ => anyhow::bail!("unsupported cursor sort field {sort}"),
  }
  Ok(())
}

fn admin_cursor_position(record: &DynamicPolicyAdminRecord, sort: &str) -> Value {
  let value = match sort {
    "source" => json!(record.source),
    "name" => json!(record.name),
    "enabled" => json!(record.enabled),
    "priority" => json!(record.priority),
    "created_at" => json!(record.created_at),
    "updated_at" => json!(record.updated_at),
    "id" => json!(record.id),
    _ => json!(record.source),
  };
  json!({ "id": record.id, "value": value })
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

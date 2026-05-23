use anyhow::{Context, bail};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres, Row, Transaction};

use crate::config::{AdminPermission, AdminRole, validate_runtime_identifier};

use super::AdminTokenRuntime;

#[derive(Debug, Clone, Deserialize)]
pub struct AdminTokenAdminCreate {
  #[serde(default)]
  pub token_id: Option<String>,
  pub subject: String,
  pub name: String,
  #[serde(default)]
  pub enabled: Option<bool>,
  #[serde(default)]
  pub roles: Vec<AdminRole>,
  #[serde(default)]
  pub permissions: Vec<AdminPermission>,
  #[serde(default)]
  pub deny_permissions: Vec<AdminPermission>,
  #[serde(default)]
  pub expires_at: Option<String>,
  #[serde(default)]
  pub ttl_seconds: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminTokenAdminPatch {
  #[serde(default)]
  pub subject: Option<String>,
  #[serde(default)]
  pub name: Option<String>,
  #[serde(default)]
  pub enabled: Option<bool>,
  #[serde(default)]
  pub roles: Option<Vec<AdminRole>>,
  #[serde(default)]
  pub permissions: Option<Vec<AdminPermission>>,
  #[serde(default)]
  pub deny_permissions: Option<Vec<AdminPermission>>,
  #[serde(default)]
  pub expires_at: Option<String>,
  #[serde(default)]
  pub ttl_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminTokenAdminRecord {
  pub token_id: String,
  pub namespace: String,
  pub subject: String,
  pub name: String,
  pub enabled: bool,
  pub revoked: bool,
  pub roles: Vec<String>,
  pub permissions: Vec<String>,
  pub deny_permissions: Vec<String>,
  pub writer_identity: Option<String>,
  pub expires_at: Option<String>,
  pub created_at: String,
  pub updated_at: String,
  pub revoked_at: Option<String>,
}

impl AdminTokenRuntime {
  pub async fn admin_list(&self) -> anyhow::Result<Vec<AdminTokenAdminRecord>> {
    let inner = self.admin_inner()?;
    select_admin_records(&inner.pool, &inner.namespace).await
  }

  pub async fn admin_get(&self, token_id: &str) -> anyhow::Result<Option<AdminTokenAdminRecord>> {
    let inner = self.admin_inner()?;
    select_admin_record(&inner.pool, &inner.namespace, token_id).await
  }

  pub async fn admin_create(
    &self,
    actor: &str,
    input: AdminTokenAdminCreate,
  ) -> anyhow::Result<AdminTokenAdminRecord> {
    let inner = self.admin_inner()?;
    validate_create(&input)?;
    let token_id = match input.token_id.clone() {
      Some(token_id) => token_id,
      None => generate_token_id()?,
    };
    validate_token_id(&token_id)?;
    let mut tx = begin_admin_write(&inner.pool).await?;
    insert_token(&mut tx, &inner.namespace, actor, &token_id, &input).await?;
    bump_generation_tx(&mut tx, &inner.namespace).await?;
    audit_tx(
      &mut tx,
      &inner.namespace,
      Some(&token_id),
      actor,
      "create",
      &input.name,
      "applied",
      None,
    )
    .await?;
    tx.commit().await?;
    select_admin_record(&inner.pool, &inner.namespace, &token_id)
      .await?
      .context("created admin token disappeared")
  }

  pub async fn admin_patch(
    &self,
    actor: &str,
    token_id: &str,
    input: AdminTokenAdminPatch,
  ) -> anyhow::Result<Option<AdminTokenAdminRecord>> {
    let inner = self.admin_inner()?;
    validate_token_id(token_id)?;
    validate_patch(&input)?;
    let mut tx = begin_admin_write(&inner.pool).await?;
    let Some(existing) = select_admin_record_tx(&mut tx, &inner.namespace, token_id).await? else {
      return Ok(None);
    };
    validate_patch_merged(&existing, &input)?;
    update_token(&mut tx, &inner.namespace, actor, token_id, &input).await?;
    bump_generation_tx(&mut tx, &inner.namespace).await?;
    audit_tx(
      &mut tx,
      &inner.namespace,
      Some(token_id),
      actor,
      "patch",
      input.name.as_deref().unwrap_or(&existing.name),
      "applied",
      None,
    )
    .await?;
    tx.commit().await?;
    select_admin_record(&inner.pool, &inner.namespace, token_id).await
  }

  pub async fn admin_delete(&self, actor: &str, token_id: &str) -> anyhow::Result<bool> {
    let inner = self.admin_inner()?;
    validate_token_id(token_id)?;
    let result = sqlx::query(
      "UPDATE oxibelt_admin_tokens
          SET enabled = false, revoked = true, revoked_at = now(),
              writer_identity = $3, row_version = row_version + 1, updated_at = now()
        WHERE namespace = $1 AND token_id = $2",
    )
    .bind(inner.namespace.as_ref())
    .bind(token_id)
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
      Some(token_id),
      actor,
      "delete",
      "",
      "applied",
      None,
    )
    .await?;
    Ok(true)
  }

  fn admin_inner(&self) -> anyhow::Result<std::sync::Arc<super::AdminTokenInner>> {
    self
      .inner
      .clone()
      .ok_or_else(|| anyhow::anyhow!("admin token store is disabled"))
  }
}

async fn begin_admin_write(
  pool: &Pool<Postgres>,
) -> anyhow::Result<Transaction<'static, Postgres>> {
  let mut tx = pool.begin().await?;
  sqlx::query("LOCK TABLE oxibelt_admin_tokens IN SHARE ROW EXCLUSIVE MODE")
    .execute(&mut *tx)
    .await?;
  Ok(tx)
}

async fn insert_token(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  actor: &str,
  token_id: &str,
  input: &AdminTokenAdminCreate,
) -> anyhow::Result<()> {
  let roles = role_strings(&input.roles);
  let permissions = permission_strings(&input.permissions);
  let deny_permissions = permission_strings(&input.deny_permissions);
  sqlx::query(
    "INSERT INTO oxibelt_admin_tokens
       (namespace, token_id, subject, name, enabled, roles, permissions, deny_permissions,
        writer_identity, expires_at)
     VALUES
       ($1, $2, $3, $4, $5, $6::text[], $7::text[], $8::text[], $9,
        CASE
          WHEN $10::bigint IS NOT NULL THEN now() + ($10::bigint * interval '1 second')
          WHEN $11::text IS NOT NULL THEN $11::timestamptz
          ELSE NULL
        END)",
  )
  .bind(namespace)
  .bind(token_id)
  .bind(&input.subject)
  .bind(&input.name)
  .bind(input.enabled.unwrap_or(true))
  .bind(&roles)
  .bind(&permissions)
  .bind(&deny_permissions)
  .bind(actor)
  .bind(input.ttl_seconds)
  .bind(&input.expires_at)
  .execute(&mut **tx)
  .await?;
  Ok(())
}

async fn update_token(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  actor: &str,
  token_id: &str,
  input: &AdminTokenAdminPatch,
) -> anyhow::Result<()> {
  let roles = input.roles.as_ref().map(|roles| role_strings(roles));
  let permissions = input
    .permissions
    .as_ref()
    .map(|permissions| permission_strings(permissions));
  let deny_permissions = input
    .deny_permissions
    .as_ref()
    .map(|permissions| permission_strings(permissions));
  sqlx::query(
    "UPDATE oxibelt_admin_tokens
        SET subject = COALESCE($3, subject),
            name = COALESCE($4, name),
            enabled = COALESCE($5, enabled),
            roles = COALESCE($6::text[], roles),
            permissions = COALESCE($7::text[], permissions),
            deny_permissions = COALESCE($8::text[], deny_permissions),
            writer_identity = $9,
            expires_at = CASE
              WHEN $10::bigint IS NOT NULL THEN now() + ($10::bigint * interval '1 second')
              WHEN $11::text IS NOT NULL THEN $11::timestamptz
              ELSE expires_at
            END,
            row_version = row_version + 1,
            updated_at = now()
      WHERE namespace = $1 AND token_id = $2",
  )
  .bind(namespace)
  .bind(token_id)
  .bind(&input.subject)
  .bind(&input.name)
  .bind(input.enabled)
  .bind(&roles)
  .bind(&permissions)
  .bind(&deny_permissions)
  .bind(actor)
  .bind(input.ttl_seconds)
  .bind(&input.expires_at)
  .execute(&mut **tx)
  .await?;
  Ok(())
}

async fn select_admin_records(
  pool: &Pool<Postgres>,
  namespace: &str,
) -> anyhow::Result<Vec<AdminTokenAdminRecord>> {
  let rows = sqlx::query(
    "SELECT namespace, token_id, subject, name, enabled, revoked, roles, permissions,
            deny_permissions, writer_identity, expires_at::text AS expires_at,
            created_at::text AS created_at, updated_at::text AS updated_at,
            revoked_at::text AS revoked_at
       FROM oxibelt_admin_tokens
      WHERE namespace = $1
      ORDER BY name ASC, token_id ASC",
  )
  .bind(namespace)
  .fetch_all(pool)
  .await?;
  rows.iter().map(admin_record_from_row).collect()
}

async fn select_admin_record(
  pool: &Pool<Postgres>,
  namespace: &str,
  token_id: &str,
) -> anyhow::Result<Option<AdminTokenAdminRecord>> {
  let row = sqlx::query(
    "SELECT namespace, token_id, subject, name, enabled, revoked, roles, permissions,
            deny_permissions, writer_identity, expires_at::text AS expires_at,
            created_at::text AS created_at, updated_at::text AS updated_at,
            revoked_at::text AS revoked_at
       FROM oxibelt_admin_tokens
      WHERE namespace = $1 AND token_id = $2",
  )
  .bind(namespace)
  .bind(token_id)
  .fetch_optional(pool)
  .await?;
  row.as_ref().map(admin_record_from_row).transpose()
}

async fn select_admin_record_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  token_id: &str,
) -> anyhow::Result<Option<AdminTokenAdminRecord>> {
  let row = sqlx::query(
    "SELECT namespace, token_id, subject, name, enabled, revoked, roles, permissions,
            deny_permissions, writer_identity, expires_at::text AS expires_at,
            created_at::text AS created_at, updated_at::text AS updated_at,
            revoked_at::text AS revoked_at
       FROM oxibelt_admin_tokens
      WHERE namespace = $1 AND token_id = $2",
  )
  .bind(namespace)
  .bind(token_id)
  .fetch_optional(&mut **tx)
  .await?;
  row.as_ref().map(admin_record_from_row).transpose()
}

fn admin_record_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<AdminTokenAdminRecord> {
  Ok(AdminTokenAdminRecord {
    namespace: row.try_get("namespace")?,
    token_id: row.try_get("token_id")?,
    subject: row.try_get("subject")?,
    name: row.try_get("name")?,
    enabled: row.try_get("enabled")?,
    revoked: row.try_get("revoked")?,
    roles: row.try_get("roles")?,
    permissions: row.try_get("permissions")?,
    deny_permissions: row.try_get("deny_permissions")?,
    writer_identity: row.try_get("writer_identity")?,
    expires_at: row.try_get("expires_at")?,
    created_at: row.try_get("created_at")?,
    updated_at: row.try_get("updated_at")?,
    revoked_at: row.try_get("revoked_at")?,
  })
}

async fn bump_generation(pool: &Pool<Postgres>, namespace: &str) -> anyhow::Result<()> {
  sqlx::query(
    "INSERT INTO oxibelt_admin_token_generation (namespace, generation, updated_at)
     VALUES ($1, 1, now())
     ON CONFLICT (namespace)
     DO UPDATE SET generation = oxibelt_admin_token_generation.generation + 1,
                   updated_at = now()",
  )
  .bind(namespace)
  .execute(pool)
  .await?;
  Ok(())
}

async fn bump_generation_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
) -> anyhow::Result<()> {
  sqlx::query(
    "INSERT INTO oxibelt_admin_token_generation (namespace, generation, updated_at)
     VALUES ($1, 1, now())
     ON CONFLICT (namespace)
     DO UPDATE SET generation = oxibelt_admin_token_generation.generation + 1,
                   updated_at = now()",
  )
  .bind(namespace)
  .execute(&mut **tx)
  .await?;
  Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn audit(
  pool: &Pool<Postgres>,
  namespace: &str,
  token_id: Option<&str>,
  actor: &str,
  operation: &str,
  name: &str,
  outcome: &str,
  error: Option<&str>,
) -> anyhow::Result<()> {
  sqlx::query(
    "INSERT INTO oxibelt_admin_token_audit
       (namespace, token_id, actor, operation, name, outcome, error)
     VALUES ($1, $2, $3, $4, $5, $6, $7)",
  )
  .bind(namespace)
  .bind(token_id)
  .bind(actor)
  .bind(operation)
  .bind(name)
  .bind(outcome)
  .bind(error)
  .execute(pool)
  .await
  .context("failed to write admin token audit row")?;
  Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn audit_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  token_id: Option<&str>,
  actor: &str,
  operation: &str,
  name: &str,
  outcome: &str,
  error: Option<&str>,
) -> anyhow::Result<()> {
  sqlx::query(
    "INSERT INTO oxibelt_admin_token_audit
       (namespace, token_id, actor, operation, name, outcome, error)
     VALUES ($1, $2, $3, $4, $5, $6, $7)",
  )
  .bind(namespace)
  .bind(token_id)
  .bind(actor)
  .bind(operation)
  .bind(name)
  .bind(outcome)
  .bind(error)
  .execute(&mut **tx)
  .await
  .context("failed to write admin token audit row")?;
  Ok(())
}

fn validate_create(input: &AdminTokenAdminCreate) -> anyhow::Result<()> {
  if let Some(token_id) = &input.token_id {
    validate_token_id(token_id)?;
  }
  validate_subject_and_name(&input.subject, &input.name)?;
  validate_authz(
    &input.roles,
    &input.permissions,
    input.enabled.unwrap_or(true),
  )?;
  validate_expiry(input.expires_at.as_deref(), input.ttl_seconds)
}

fn validate_patch(input: &AdminTokenAdminPatch) -> anyhow::Result<()> {
  if let Some(subject) = &input.subject {
    validate_non_empty("admin token subject", subject)?;
  }
  if let Some(name) = &input.name {
    validate_non_empty("admin token name", name)?;
  }
  validate_expiry(input.expires_at.as_deref(), input.ttl_seconds)
}

fn validate_patch_merged(
  existing: &AdminTokenAdminRecord,
  input: &AdminTokenAdminPatch,
) -> anyhow::Result<()> {
  let enabled = input.enabled.unwrap_or(existing.enabled);
  let roles_empty = input
    .roles
    .as_ref()
    .map_or_else(|| existing.roles.is_empty(), Vec::is_empty);
  let permissions_empty = input
    .permissions
    .as_ref()
    .map_or_else(|| existing.permissions.is_empty(), Vec::is_empty);
  if enabled && roles_empty && permissions_empty {
    bail!("enabled admin tokens must include at least one role or permission");
  }
  Ok(())
}

fn validate_subject_and_name(subject: &str, name: &str) -> anyhow::Result<()> {
  validate_non_empty("admin token subject", subject)?;
  validate_non_empty("admin token name", name)
}

fn validate_token_id(token_id: &str) -> anyhow::Result<()> {
  validate_runtime_identifier("admin token token_id", token_id)?;
  if token_id.len() > 128 {
    bail!("admin token token_id must be at most 128 bytes");
  }
  Ok(())
}

fn validate_non_empty(field: &str, value: &str) -> anyhow::Result<()> {
  if value.trim().is_empty() {
    bail!("{field} must not be empty");
  }
  if value.len() > 128 {
    bail!("{field} must be at most 128 bytes");
  }
  Ok(())
}

fn validate_authz(
  roles: &[AdminRole],
  permissions: &[AdminPermission],
  enabled: bool,
) -> anyhow::Result<()> {
  if enabled && roles.is_empty() && permissions.is_empty() {
    bail!("enabled admin tokens must include at least one role or permission");
  }
  Ok(())
}

fn validate_expiry(expires_at: Option<&str>, ttl_seconds: Option<i64>) -> anyhow::Result<()> {
  if expires_at.is_some() && ttl_seconds.is_some() {
    bail!("admin token must set only one of expires_at or ttl_seconds");
  }
  if let Some(ttl_seconds) = ttl_seconds
    && ttl_seconds <= 0
  {
    bail!("admin token ttl_seconds must be greater than 0");
  }
  Ok(())
}

fn generate_token_id() -> anyhow::Result<String> {
  let mut bytes = [0u8; 16];
  SystemRandom::new()
    .fill(&mut bytes)
    .map_err(|_| anyhow::anyhow!("failed to generate admin token id"))?;
  Ok(format!(
    "tok_{}",
    crate::admin_tokens::base64_url_no_pad(&bytes)
  ))
}

fn role_strings(roles: &[AdminRole]) -> Vec<String> {
  roles.iter().map(|role| role.as_str().to_string()).collect()
}

fn permission_strings(permissions: &[AdminPermission]) -> Vec<String> {
  permissions
    .iter()
    .map(|permission| permission.as_str().to_string())
    .collect()
}

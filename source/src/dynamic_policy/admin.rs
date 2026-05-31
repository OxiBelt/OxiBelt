use std::sync::Arc;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};

use crate::admin_list::{AdminListPage, AdminListQuery};

use super::{DynamicPolicyRuntime, PolicyRow, signature};

mod precondition;
mod quota;
mod store;
mod validation;
mod write;
pub use precondition::{
  DynamicPolicyAdminStatus, DynamicPolicyPreconditionError, DynamicPolicyPreconditionErrorKind,
  dynamic_policy_etag,
};
use precondition::{DynamicPolicyPreconditionMode, check_if_match_tx};
use quota::enforce_policy_quotas;
use store::*;
use validation::*;
use write::*;

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
pub struct DynamicPolicyAdminAuditRecord {
  pub id: i64,
  pub namespace: String,
  pub policy_id: Option<i64>,
  pub actor: String,
  pub operation: String,
  pub source: Option<String>,
  pub name: Option<String>,
  pub outcome: String,
  pub error: Option<String>,
  pub created_at: String,
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
  pub async fn admin_status(&self) -> anyhow::Result<DynamicPolicyAdminStatus> {
    let inner = self.admin_inner()?;
    let generation = select_generation(&inner.pool, &inner.namespace).await?;
    Ok(DynamicPolicyAdminStatus {
      namespace: inner.namespace.to_string(),
      generation,
      etag: dynamic_policy_etag(generation),
    })
  }

  pub async fn admin_list(&self) -> anyhow::Result<Vec<DynamicPolicyAdminRecord>> {
    let inner = self.admin_inner()?;
    select_admin_records(&inner.pool, &inner.namespace).await
  }

  pub async fn admin_list_page(
    &self,
    query: &AdminListQuery,
  ) -> anyhow::Result<AdminListPage<DynamicPolicyAdminRecord>> {
    let inner = self.admin_inner()?;
    select_admin_records_page(&inner.pool, &inner.namespace, query).await
  }

  pub async fn admin_get(&self, id: i64) -> anyhow::Result<Option<DynamicPolicyAdminRecord>> {
    let inner = self.admin_inner()?;
    select_admin_record(&inner.pool, &inner.namespace, id).await
  }

  pub async fn admin_create(
    &self,
    actor: &str,
    input: DynamicPolicyAdminCreate,
    if_match: Option<&str>,
  ) -> anyhow::Result<DynamicPolicyAdminRecord> {
    let inner = self.admin_inner()?;
    let mut tx = begin_admin_write(&inner).await?;
    check_if_match_tx(
      &mut tx,
      &inner.namespace,
      if_match,
      DynamicPolicyPreconditionMode::Required,
    )
    .await?;
    if let Err(error) = validate_create(&inner, &input) {
      let _ = tx.rollback().await;
      audit_rejected(
        &inner,
        None,
        actor,
        "create",
        &input.source,
        &input.name,
        &error,
      )
      .await;
      return Err(error);
    }
    if let Err(error) = enforce_policy_quotas(
      &mut tx,
      &inner,
      &input.source,
      None,
      input.enabled.unwrap_or(true),
    )
    .await
    {
      let _ = tx.rollback().await;
      audit_rejected(
        &inner,
        None,
        actor,
        "create",
        &input.source,
        &input.name,
        &error,
      )
      .await;
      return Err(error);
    }
    let id = insert_policy(&mut tx, &inner.namespace, actor, &input).await?;
    sign_policy(&mut tx, &inner, id).await?;
    bump_generation_tx(&mut tx, &inner.namespace).await?;
    audit_tx(
      &mut tx,
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
    tx.commit().await?;
    select_admin_record(&inner.pool, &inner.namespace, id)
      .await?
      .context("created dynamic policy disappeared")
  }

  pub async fn admin_apply(
    &self,
    actor: &str,
    input: DynamicPolicyAdminCreate,
    if_match: Option<&str>,
  ) -> anyhow::Result<DynamicPolicyAdminRecord> {
    let inner = self.admin_inner()?;
    let mut tx = begin_admin_write(&inner).await?;
    check_if_match_tx(
      &mut tx,
      &inner.namespace,
      if_match,
      DynamicPolicyPreconditionMode::Optional,
    )
    .await?;
    if let Err(error) = validate_create(&inner, &input) {
      let _ = tx.rollback().await;
      audit_rejected(
        &inner,
        None,
        actor,
        "apply",
        &input.source,
        &input.name,
        &error,
      )
      .await;
      return Err(error);
    }
    let existing =
      policy_ids_by_source_name_tx(&mut tx, &inner.namespace, &input.source, &input.name).await?;
    let id = if let Some((&id, duplicates)) = existing.split_first() {
      if let Err(error) = enforce_policy_quotas(
        &mut tx,
        &inner,
        &input.source,
        Some(id),
        input.enabled.unwrap_or(true),
      )
      .await
      {
        let _ = tx.rollback().await;
        audit_rejected(
          &inner,
          Some(id),
          actor,
          "apply",
          &input.source,
          &input.name,
          &error,
        )
        .await;
        return Err(error);
      }
      replace_policy(&mut tx, &inner.namespace, actor, id, &input).await?;
      if !duplicates.is_empty() {
        sqlx::query("UPDATE oxibelt_dynamic_policies SET enabled = false, updated_at = now(), writer_identity = $3, signature_version = NULL, row_signature = NULL WHERE namespace = $1 AND id = ANY($2)")
          .bind(inner.namespace.as_ref())
          .bind(duplicates)
          .bind(actor)
          .execute(&mut *tx)
          .await?;
      }
      id
    } else {
      if let Err(error) = enforce_policy_quotas(
        &mut tx,
        &inner,
        &input.source,
        None,
        input.enabled.unwrap_or(true),
      )
      .await
      {
        let _ = tx.rollback().await;
        audit_rejected(
          &inner,
          None,
          actor,
          "apply",
          &input.source,
          &input.name,
          &error,
        )
        .await;
        return Err(error);
      }
      insert_policy(&mut tx, &inner.namespace, actor, &input).await?
    };
    sign_policy(&mut tx, &inner, id).await?;
    bump_generation_tx(&mut tx, &inner.namespace).await?;
    audit_tx(
      &mut tx,
      &inner.namespace,
      Some(id),
      actor,
      "apply",
      &input.source,
      &input.name,
      "applied",
      None,
    )
    .await?;
    tx.commit().await?;
    select_admin_record(&inner.pool, &inner.namespace, id)
      .await?
      .context("applied dynamic policy disappeared")
  }

  pub async fn admin_patch(
    &self,
    actor: &str,
    id: i64,
    input: DynamicPolicyAdminPatch,
    if_match: Option<&str>,
  ) -> anyhow::Result<Option<DynamicPolicyAdminRecord>> {
    let inner = self.admin_inner()?;
    let mut tx = begin_admin_write(&inner).await?;
    check_if_match_tx(
      &mut tx,
      &inner.namespace,
      if_match,
      DynamicPolicyPreconditionMode::Required,
    )
    .await?;
    let Some(existing) = select_admin_record_tx(&mut tx, &inner.namespace, id).await? else {
      return Ok(None);
    };
    if let Err(error) =
      validate_patch(&inner, &input).and_then(|_| validate_patch_merged(&inner, &existing, &input))
    {
      let _ = tx.rollback().await;
      audit_rejected(
        &inner,
        Some(id),
        actor,
        "patch",
        input.source.as_deref().unwrap_or(&existing.source),
        input.name.as_deref().unwrap_or(&existing.name),
        &error,
      )
      .await;
      return Err(error);
    }
    let source = input.source.as_deref().unwrap_or(&existing.source);
    let enabled = input.enabled.unwrap_or(existing.enabled);
    if let Err(error) = enforce_policy_quotas(&mut tx, &inner, source, Some(id), enabled).await {
      let _ = tx.rollback().await;
      audit_rejected(
        &inner,
        Some(id),
        actor,
        "patch",
        source,
        input.name.as_deref().unwrap_or(&existing.name),
        &error,
      )
      .await;
      return Err(error);
    }
    update_policy(&mut tx, &inner.namespace, actor, id, &input).await?;
    sign_policy(&mut tx, &inner, id).await?;
    bump_generation_tx(&mut tx, &inner.namespace).await?;
    audit_tx(
      &mut tx,
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
    tx.commit().await?;
    select_admin_record(&inner.pool, &inner.namespace, id).await
  }

  pub async fn admin_delete(
    &self,
    actor: &str,
    id: i64,
    if_match: Option<&str>,
  ) -> anyhow::Result<bool> {
    let inner = self.admin_inner()?;
    let mut tx = begin_admin_write(&inner).await?;
    check_if_match_tx(
      &mut tx,
      &inner.namespace,
      if_match,
      DynamicPolicyPreconditionMode::Required,
    )
    .await?;
    let Some(existing) = select_admin_record_tx(&mut tx, &inner.namespace, id).await? else {
      return Ok(false);
    };
    let result = sqlx::query(
      "UPDATE oxibelt_dynamic_policies
          SET enabled = false, writer_identity = $3, signature_version = NULL,
              row_signature = NULL, updated_at = now()
        WHERE namespace = $1 AND id = $2",
    )
    .bind(inner.namespace.as_ref())
    .bind(id)
    .bind(actor)
    .execute(&mut *tx)
    .await?;
    if result.rows_affected() == 0 {
      return Ok(false);
    }
    bump_generation_tx(&mut tx, &inner.namespace).await?;
    audit_tx(
      &mut tx,
      &inner.namespace,
      Some(id),
      actor,
      "delete",
      &existing.source,
      &existing.name,
      "applied",
      None,
    )
    .await?;
    tx.commit().await?;
    Ok(true)
  }

  pub async fn admin_export(&self) -> anyhow::Result<Vec<DynamicPolicyAdminRecord>> {
    self.admin_list().await
  }

  pub async fn admin_import(
    &self,
    actor: &str,
    input: DynamicPolicyAdminImport,
    if_match: Option<&str>,
  ) -> anyhow::Result<Vec<DynamicPolicyAdminRecord>> {
    let inner = self.admin_inner()?;
    let mut tx = begin_admin_write(&inner).await?;
    check_if_match_tx(
      &mut tx,
      &inner.namespace,
      if_match,
      DynamicPolicyPreconditionMode::Required,
    )
    .await?;
    let mut ids = Vec::with_capacity(input.policies.len());
    for policy in input.policies {
      if let Err(error) = validate_create(&inner, &policy) {
        let _ = tx.rollback().await;
        audit_rejected(
          &inner,
          None,
          actor,
          "import",
          &policy.source,
          &policy.name,
          &error,
        )
        .await;
        return Err(error);
      }
      let existing =
        policy_ids_by_source_name_tx(&mut tx, &inner.namespace, &policy.source, &policy.name)
          .await?;
      let id = if let Some((&id, duplicates)) = existing.split_first() {
        if let Err(error) = enforce_policy_quotas(
          &mut tx,
          &inner,
          &policy.source,
          Some(id),
          policy.enabled.unwrap_or(true),
        )
        .await
        {
          let _ = tx.rollback().await;
          audit_rejected(
            &inner,
            Some(id),
            actor,
            "import",
            &policy.source,
            &policy.name,
            &error,
          )
          .await;
          return Err(error);
        }
        replace_policy(&mut tx, &inner.namespace, actor, id, &policy).await?;
        if !duplicates.is_empty() {
          sqlx::query("UPDATE oxibelt_dynamic_policies SET enabled = false, updated_at = now(), writer_identity = $3, signature_version = NULL, row_signature = NULL WHERE namespace = $1 AND id = ANY($2)")
            .bind(inner.namespace.as_ref())
            .bind(duplicates)
            .bind(actor)
            .execute(&mut *tx)
            .await?;
        }
        id
      } else {
        if let Err(error) = enforce_policy_quotas(
          &mut tx,
          &inner,
          &policy.source,
          None,
          policy.enabled.unwrap_or(true),
        )
        .await
        {
          let _ = tx.rollback().await;
          audit_rejected(
            &inner,
            None,
            actor,
            "import",
            &policy.source,
            &policy.name,
            &error,
          )
          .await;
          return Err(error);
        }
        insert_policy(&mut tx, &inner.namespace, actor, &policy).await?
      };
      sign_policy(&mut tx, &inner, id).await?;
      ids.push(id);
      audit_tx(
        &mut tx,
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
    bump_generation_tx(&mut tx, &inner.namespace).await?;
    tx.commit().await?;
    let mut records = Vec::with_capacity(ids.len());
    for id in ids {
      records.push(
        select_admin_record(&inner.pool, &inner.namespace, id)
          .await?
          .context("imported dynamic policy disappeared")?,
      );
    }
    Ok(records)
  }

  pub async fn admin_audit(
    &self,
    policy_id: Option<i64>,
    limit: i64,
  ) -> anyhow::Result<Vec<DynamicPolicyAdminAuditRecord>> {
    let inner = self.admin_inner()?;
    select_audit_records(&inner.pool, &inner.namespace, policy_id, limit).await
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

async fn audit_rejected(
  inner: &super::DynamicPolicyInner,
  policy_id: Option<i64>,
  actor: &str,
  operation: &str,
  source: &str,
  name: &str,
  error: &anyhow::Error,
) {
  let error = error.to_string();
  let _ = audit(
    &inner.pool,
    &inner.namespace,
    policy_id,
    actor,
    operation,
    source,
    name,
    "rejected",
    Some(&error),
  )
  .await;
}

async fn sign_policy(
  tx: &mut Transaction<'_, Postgres>,
  inner: &super::DynamicPolicyInner,
  id: i64,
) -> anyhow::Result<()> {
  let key = inner
    .signature_key
    .as_ref()
    .context("dynamic policy automation API signature key is unavailable")?;
  let row = select_policy_row_tx(tx, &inner.namespace, id)
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
  .execute(&mut **tx)
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

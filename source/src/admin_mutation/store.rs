//! PostgreSQL-backed mutation claims, logical revisions, and break-glass leases.

use anyhow::{Context, ensure};
use serde::Serialize;
use sqlx::{Pool, Postgres, Row, Transaction};

use super::ledger::{
  ClaimOutcome, MutationClaim, MutationRecord, MutationState, TerminalMutation, validate_identifier,
};

#[path = "store_schema.rs"]
mod schema;

#[derive(Clone)]
pub(crate) struct MutationStore {
  pool: Pool<Postgres>,
  namespace: String,
}

impl MutationStore {
  pub(crate) fn new(pool: Pool<Postgres>, namespace: String) -> anyhow::Result<Self> {
    validate_identifier("namespace", &namespace, 256)?;
    Ok(Self { pool, namespace })
  }

  pub(crate) fn pool(&self) -> &Pool<Postgres> {
    &self.pool
  }

  pub(crate) fn namespace(&self) -> &str {
    &self.namespace
  }

  pub(crate) async fn initialize_revision(
    &self,
    resource: &str,
    revision: &str,
    content_digest: &str,
    cluster_id: Option<&str>,
    membership_revision: Option<&str>,
  ) -> anyhow::Result<()> {
    validate_identifier("resource", resource, 256)?;
    validate_identifier("revision", revision, 256)?;
    validate_identifier("content_digest", content_digest, 256)?;
    if let Some(value) = cluster_id {
      validate_identifier("cluster_id", value, 256)?;
    }
    if let Some(value) = membership_revision {
      validate_identifier("membership_revision", value, 256)?;
    }
    ensure!(
      cluster_id.is_some() == membership_revision.is_some(),
      "cluster_id and membership_revision must be provided together"
    );
    let mut tx = self.pool.begin().await?;
    sqlx::query(
      "INSERT INTO oxibelt_admin_mutation_revisions
         (namespace, resource, committed_revision, content_digest, cluster_id,
          membership_revision)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (namespace, resource) DO NOTHING",
    )
    .bind(&self.namespace)
    .bind(resource)
    .bind(revision)
    .bind(content_digest)
    .bind(cluster_id)
    .bind(membership_revision)
    .execute(&mut *tx)
    .await?;
    let existing = sqlx::query(
      "SELECT committed_revision, content_digest, cluster_id, membership_revision
         FROM oxibelt_admin_mutation_revisions
        WHERE namespace = $1 AND resource = $2 FOR UPDATE",
    )
    .bind(&self.namespace)
    .bind(resource)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(
      existing.try_get::<String, _>("committed_revision")? == revision
        && existing.try_get::<String, _>("content_digest")? == content_digest
        && existing
          .try_get::<Option<String>, _>("cluster_id")?
          .as_deref()
          == cluster_id
        && existing
          .try_get::<Option<String>, _>("membership_revision")?
          .as_deref()
          == membership_revision,
      "configured runtime does not match the durable mutation head"
    );
    tx.commit().await?;
    Ok(())
  }

  pub(crate) async fn load_revision(
    &self,
    resource: &str,
  ) -> anyhow::Result<Option<LogicalRevision>> {
    validate_identifier("resource", resource, 256)?;
    let row = sqlx::query(
      "SELECT resource, committed_revision, content_digest, cluster_id, membership_revision,
              pending_request_id, pending_revision, updated_at::text AS updated_at
         FROM oxibelt_admin_mutation_revisions
        WHERE namespace = $1 AND resource = $2",
    )
    .bind(&self.namespace)
    .bind(resource)
    .fetch_optional(&self.pool)
    .await?;
    row.as_ref().map(logical_revision_from_row).transpose()
  }

  pub(crate) async fn claim(&self, claim: &MutationClaim) -> anyhow::Result<ClaimOutcome> {
    claim.validate()?;
    let mut tx = self.pool.begin().await?;
    let result = claim_tx(&mut tx, &self.namespace, claim).await?;
    tx.commit().await?;
    Ok(result)
  }

  #[allow(dead_code)]
  pub(crate) async fn transition(
    &self,
    request_id: &str,
    next: MutationState,
  ) -> anyhow::Result<MutationRecord> {
    let mut tx = self.pool.begin().await?;
    let record = transition_tx(&mut tx, &self.namespace, request_id, next).await?;
    tx.commit().await?;
    Ok(record)
  }

  pub(crate) async fn finish(
    &self,
    request_id: &str,
    terminal: &TerminalMutation,
  ) -> anyhow::Result<MutationRecord> {
    terminal.validate()?;
    let mut tx = self.pool.begin().await?;
    let record = finish_tx(&mut tx, &self.namespace, request_id, terminal).await?;
    tx.commit().await?;
    Ok(record)
  }

  pub(crate) async fn load_mutation(
    &self,
    request_id: &str,
  ) -> anyhow::Result<Option<MutationRecord>> {
    validate_identifier("request_id", request_id, 256)?;
    let row = select_mutation(&self.pool, &self.namespace, request_id, false).await?;
    row.as_ref().map(mutation_from_row).transpose()
  }

  pub(crate) async fn delete_expired_terminal_records(&self, limit: i64) -> anyhow::Result<u64> {
    ensure!(
      (1..=10_000).contains(&limit),
      "cleanup limit must be between 1 and 10000"
    );
    let result = sqlx::query(
      "DELETE FROM oxibelt_admin_mutations
        WHERE (namespace, request_id) IN (
          SELECT namespace, request_id
            FROM oxibelt_admin_mutations
           WHERE namespace = $1
             AND retention_until < now()
             AND state IN ('committed', 'failed', 'rolled_back')
             AND NOT EXISTS (
               SELECT 1 FROM oxibelt_admin_break_glass_activations activation
                WHERE activation.namespace = oxibelt_admin_mutations.namespace
                  AND activation.mutation_request_id = oxibelt_admin_mutations.request_id
                  AND activation.expires_at >= now()
             )
           ORDER BY retention_until ASC
           LIMIT $2
        )",
    )
    .bind(&self.namespace)
    .bind(limit)
    .execute(&self.pool)
    .await?;
    Ok(result.rows_affected())
  }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct LogicalRevision {
  pub(crate) resource: String,
  pub(crate) committed_revision: String,
  pub(crate) content_digest: String,
  pub(crate) cluster_id: Option<String>,
  pub(crate) membership_revision: Option<String>,
  pub(crate) pending_request_id: Option<String>,
  pub(crate) pending_revision: Option<String>,
  pub(crate) updated_at: String,
}

pub(crate) async fn init_postgres(pool: &Pool<Postgres>) -> anyhow::Result<()> {
  for &statement in schema::statements() {
    sqlx::query(statement).execute(pool).await?;
  }
  Ok(())
}

pub(crate) async fn claim_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  claim: &MutationClaim,
) -> anyhow::Result<ClaimOutcome> {
  claim.validate()?;
  if let Some(row) = select_mutation(&mut **tx, namespace, &claim.request_id, true).await? {
    let record = mutation_from_row(&row)?;
    return Ok(record.classify_existing_claim(claim));
  }

  let unexpired: bool = sqlx::query_scalar(
    "SELECT now() + make_interval(secs => $3::double precision) >= $1::timestamptz
            AND now() < $2::timestamptz",
  )
  .bind(&claim.issued_at)
  .bind(&claim.expires_at)
  .bind(claim.allowed_clock_skew_seconds as f64)
  .fetch_one(&mut **tx)
  .await
  .context("failed to validate mutation lifetime against database time")?;
  if !unexpired {
    return Ok(ClaimOutcome::Expired);
  }

  let revision = sqlx::query(
    "SELECT committed_revision, cluster_id, membership_revision, pending_request_id
       FROM oxibelt_admin_mutation_revisions
      WHERE namespace = $1 AND resource = $2
      FOR UPDATE",
  )
  .bind(namespace)
  .bind(&claim.resource)
  .fetch_optional(&mut **tx)
  .await?;
  let Some(revision) = revision else {
    return Ok(ClaimOutcome::RevisionConflict {
      actual_revision: None,
    });
  };
  // A concurrent claim for the same request can commit its mutation row while
  // this transaction waits for the logical-revision lock. Re-check after the
  // lock so an exact duplicate is reported as in progress/replay rather than
  // as an unrelated busy resource.
  if let Some(row) = select_mutation(&mut **tx, namespace, &claim.request_id, true).await? {
    let record = mutation_from_row(&row)?;
    return Ok(record.classify_existing_claim(claim));
  }
  let actual_revision: String = revision.try_get("committed_revision")?;
  if actual_revision != claim.expected_previous_revision {
    return Ok(ClaimOutcome::RevisionConflict {
      actual_revision: Some(actual_revision),
    });
  }
  let cluster_id: Option<String> = revision.try_get("cluster_id")?;
  let membership_revision: Option<String> = revision.try_get("membership_revision")?;
  if cluster_id != claim.cluster_id || membership_revision != claim.membership_revision {
    return Ok(ClaimOutcome::TargetConflict);
  }
  if let Some(request_id) = revision.try_get::<Option<String>, _>("pending_request_id")? {
    return Ok(ClaimOutcome::RevisionBusy { request_id });
  }

  let inserted = sqlx::query(
    "INSERT INTO oxibelt_admin_mutations
       (namespace, request_id, fingerprint, principal, signer_id, action, resource,
        expected_previous_revision, new_revision, content_digest, cluster_id,
        membership_revision, audit_record_id, issued_at, expires_at, retention_until)
     VALUES
       ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
        $14::timestamptz, $15::timestamptz,
        $15::timestamptz + make_interval(secs => $16::double precision))
     ON CONFLICT (namespace, request_id) DO NOTHING",
  )
  .bind(namespace)
  .bind(&claim.request_id)
  .bind(&claim.fingerprint)
  .bind(&claim.principal)
  .bind(&claim.signer_id)
  .bind(&claim.action)
  .bind(&claim.resource)
  .bind(&claim.expected_previous_revision)
  .bind(&claim.new_revision)
  .bind(&claim.content_digest)
  .bind(&claim.cluster_id)
  .bind(&claim.membership_revision)
  .bind(claim.audit_record_id)
  .bind(&claim.issued_at)
  .bind(&claim.expires_at)
  .bind(claim.retention_seconds as f64)
  .execute(&mut **tx)
  .await?;

  if inserted.rows_affected() == 0 {
    let row = select_mutation(&mut **tx, namespace, &claim.request_id, true)
      .await?
      .context("conflicting mutation disappeared during claim")?;
    let record = mutation_from_row(&row)?;
    return Ok(record.classify_existing_claim(claim));
  }

  let reserved = sqlx::query(
    "UPDATE oxibelt_admin_mutation_revisions
        SET pending_request_id = $3, pending_revision = $4, updated_at = now()
      WHERE namespace = $1 AND resource = $2
        AND committed_revision = $5 AND pending_request_id IS NULL",
  )
  .bind(namespace)
  .bind(&claim.resource)
  .bind(&claim.request_id)
  .bind(&claim.new_revision)
  .bind(&claim.expected_previous_revision)
  .execute(&mut **tx)
  .await?;
  ensure!(
    reserved.rows_affected() == 1,
    "mutation revision reservation was lost"
  );

  let row = select_mutation(&mut **tx, namespace, &claim.request_id, false)
    .await?
    .context("claimed mutation record is missing")?;
  Ok(ClaimOutcome::Claimed(mutation_from_row(&row)?))
}

#[allow(dead_code)]
pub(crate) async fn transition_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  request_id: &str,
  next: MutationState,
) -> anyhow::Result<MutationRecord> {
  let row = select_mutation(&mut **tx, namespace, request_id, true)
    .await?
    .context("mutation record not found")?;
  let current = mutation_from_row(&row)?;
  ensure!(
    current.state.may_transition_to(next),
    "invalid mutation state transition"
  );
  ensure!(
    !next.is_terminal(),
    "use finish_tx for terminal transitions"
  );
  sqlx::query(
    "UPDATE oxibelt_admin_mutations SET state = $3, updated_at = now()
      WHERE namespace = $1 AND request_id = $2",
  )
  .bind(namespace)
  .bind(request_id)
  .bind(next.as_str())
  .execute(&mut **tx)
  .await?;
  let row = select_mutation(&mut **tx, namespace, request_id, false)
    .await?
    .context("transitioned mutation record is missing")?;
  mutation_from_row(&row)
}

pub(crate) async fn finish_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  request_id: &str,
  terminal: &TerminalMutation,
) -> anyhow::Result<MutationRecord> {
  terminal.validate()?;
  let row = select_mutation(&mut **tx, namespace, request_id, true)
    .await?
    .context("mutation record not found")?;
  let current = mutation_from_row(&row)?;
  if current.state.is_terminal() {
    ensure!(
      current.state == terminal.state,
      "terminal mutation result conflicts"
    );
    ensure!(
      current.http_status == Some(i32::from(terminal.http_status))
        && current.safe_response == terminal.safe_response
        && current.error_code == terminal.error_code
        && current.terminal_audit_record_id == Some(terminal.terminal_audit_record_id),
      "terminal mutation payload conflicts"
    );
    return Ok(current);
  }
  ensure!(
    current.state.may_transition_to(terminal.state),
    "invalid mutation terminal transition"
  );

  if terminal.state == MutationState::Committed {
    let advanced = sqlx::query(
      "UPDATE oxibelt_admin_mutation_revisions
          SET committed_revision = $4, content_digest = $5,
              membership_revision = COALESCE($6, membership_revision),
              pending_request_id = NULL, pending_revision = NULL, updated_at = now()
        WHERE namespace = $1 AND resource = $2
          AND committed_revision = $3 AND pending_request_id = $7 AND pending_revision = $4",
    )
    .bind(namespace)
    .bind(&current.resource)
    .bind(&current.expected_previous_revision)
    .bind(&current.new_revision)
    .bind(&current.content_digest)
    .bind(&current.membership_revision)
    .bind(request_id)
    .execute(&mut **tx)
    .await?;
    ensure!(
      advanced.rows_affected() == 1,
      "logical revision commit conflict"
    );
  } else if !terminal.state.blocks_resource() {
    release_revision_reservation(tx, namespace, &current.resource, request_id).await?;
  }

  let safe_response = terminal
    .safe_response
    .as_ref()
    .map(serde_json::to_string)
    .transpose()?;
  sqlx::query(
    "UPDATE oxibelt_admin_mutations
        SET state = $3, http_status = $4, safe_response = $5::jsonb,
            error_code = $6, terminal_audit_record_id = $7,
            coordinator_instance_id = NULL, coordinator_lease_expires_at = NULL,
            updated_at = now()
      WHERE namespace = $1 AND request_id = $2",
  )
  .bind(namespace)
  .bind(request_id)
  .bind(terminal.state.as_str())
  .bind(i32::from(terminal.http_status))
  .bind(safe_response)
  .bind(&terminal.error_code)
  .bind(terminal.terminal_audit_record_id)
  .execute(&mut **tx)
  .await?;
  let row = select_mutation(&mut **tx, namespace, request_id, false)
    .await?
    .context("finished mutation record is missing")?;
  mutation_from_row(&row)
}

async fn release_revision_reservation(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  resource: &str,
  request_id: &str,
) -> anyhow::Result<()> {
  let released = sqlx::query(
    "UPDATE oxibelt_admin_mutation_revisions
        SET pending_request_id = NULL, pending_revision = NULL, updated_at = now()
      WHERE namespace = $1 AND resource = $2 AND pending_request_id = $3",
  )
  .bind(namespace)
  .bind(resource)
  .bind(request_id)
  .execute(&mut **tx)
  .await?;
  ensure!(
    released.rows_affected() == 1,
    "logical revision reservation conflict"
  );
  Ok(())
}

async fn select_mutation<'e, E>(
  executor: E,
  namespace: &str,
  request_id: &str,
  for_update: bool,
) -> anyhow::Result<Option<sqlx::postgres::PgRow>>
where
  E: sqlx::Executor<'e, Database = Postgres>,
{
  let row = if for_update {
    sqlx::query(
      "SELECT request_id, fingerprint, principal, signer_id, action, resource,
            expected_previous_revision, new_revision, content_digest, cluster_id,
            membership_revision, state, http_status, safe_response::text AS safe_response,
            error_code, audit_record_id, terminal_audit_record_id,
            issued_at::text AS issued_at, expires_at::text AS expires_at,
            created_at::text AS created_at, updated_at::text AS updated_at
       FROM oxibelt_admin_mutations
      WHERE namespace = $1 AND request_id = $2 FOR UPDATE",
    )
    .bind(namespace)
    .bind(request_id)
    .fetch_optional(executor)
    .await?
  } else {
    sqlx::query(
      "SELECT request_id, fingerprint, principal, signer_id, action, resource,
              expected_previous_revision, new_revision, content_digest, cluster_id,
              membership_revision, state, http_status, safe_response::text AS safe_response,
              error_code, audit_record_id, terminal_audit_record_id,
              issued_at::text AS issued_at, expires_at::text AS expires_at,
              created_at::text AS created_at, updated_at::text AS updated_at
         FROM oxibelt_admin_mutations
        WHERE namespace = $1 AND request_id = $2",
    )
    .bind(namespace)
    .bind(request_id)
    .fetch_optional(executor)
    .await?
  };
  Ok(row)
}

fn mutation_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<MutationRecord> {
  let safe_response = row
    .try_get::<Option<String>, _>("safe_response")?
    .map(|value| serde_json::from_str(&value))
    .transpose()?;
  Ok(MutationRecord {
    request_id: row.try_get("request_id")?,
    fingerprint: row.try_get("fingerprint")?,
    principal: row.try_get("principal")?,
    signer_id: row.try_get("signer_id")?,
    action: row.try_get("action")?,
    resource: row.try_get("resource")?,
    expected_previous_revision: row.try_get("expected_previous_revision")?,
    new_revision: row.try_get("new_revision")?,
    content_digest: row.try_get("content_digest")?,
    cluster_id: row.try_get("cluster_id")?,
    membership_revision: row.try_get("membership_revision")?,
    state: MutationState::parse(&row.try_get::<String, _>("state")?)?,
    http_status: row.try_get("http_status")?,
    safe_response,
    error_code: row.try_get("error_code")?,
    audit_record_id: row.try_get("audit_record_id")?,
    terminal_audit_record_id: row.try_get("terminal_audit_record_id")?,
    issued_at: row.try_get("issued_at")?,
    expires_at: row.try_get("expires_at")?,
    created_at: row.try_get("created_at")?,
    updated_at: row.try_get("updated_at")?,
  })
}

fn logical_revision_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<LogicalRevision> {
  Ok(LogicalRevision {
    resource: row.try_get("resource")?,
    committed_revision: row.try_get("committed_revision")?,
    content_digest: row.try_get("content_digest")?,
    cluster_id: row.try_get("cluster_id")?,
    membership_revision: row.try_get("membership_revision")?,
    pending_request_id: row.try_get("pending_request_id")?,
    pending_revision: row.try_get("pending_revision")?,
    updated_at: row.try_get("updated_at")?,
  })
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct BreakGlassActivation {
  pub(crate) activation_id: String,
  pub(crate) principal: String,
  pub(crate) scopes: Vec<String>,
  pub(crate) mutation_request_id: String,
  pub(crate) expires_at: String,
  pub(crate) revoked_at: Option<String>,
  pub(crate) created_at: String,
}

pub(crate) async fn create_break_glass_activation_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  activation_id: &str,
  principal: &str,
  scopes: &[String],
  mutation_request_id: &str,
  expires_at: &str,
) -> anyhow::Result<BreakGlassActivation> {
  for (name, value) in [
    ("activation_id", activation_id),
    ("principal", principal),
    ("mutation_request_id", mutation_request_id),
  ] {
    validate_identifier(name, value, 256)?;
  }
  ensure!(
    !scopes.is_empty(),
    "break-glass activation requires at least one scope"
  );
  ensure!(scopes.len() <= 128, "too many break-glass scopes");
  for scope in scopes {
    validate_identifier("scope", scope, 256)?;
  }
  let inserted = sqlx::query(
    "INSERT INTO oxibelt_admin_break_glass_activations
       (namespace, activation_id, principal, scopes, mutation_request_id, expires_at)
     SELECT $1, $2, $3, $4, $5, $6::timestamptz
      WHERE now() < $6::timestamptz
     ON CONFLICT (namespace, activation_id) DO NOTHING",
  )
  .bind(namespace)
  .bind(activation_id)
  .bind(principal)
  .bind(scopes)
  .bind(mutation_request_id)
  .bind(expires_at)
  .execute(&mut **tx)
  .await?;
  ensure!(
    inserted.rows_affected() == 1,
    "break-glass activation conflict or expiry"
  );
  let row = sqlx::query(
    "SELECT activation_id, principal, scopes, mutation_request_id,
            expires_at::text AS expires_at, revoked_at::text AS revoked_at,
            created_at::text AS created_at
       FROM oxibelt_admin_break_glass_activations
      WHERE namespace = $1 AND activation_id = $2 AND principal = $3",
  )
  .bind(namespace)
  .bind(activation_id)
  .bind(principal)
  .fetch_one(&mut **tx)
  .await?;
  break_glass_from_row(&row)
}

pub(crate) async fn revoke_break_glass_activation_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  activation_id: &str,
  principal: &str,
) -> anyhow::Result<bool> {
  let result = sqlx::query(
    "UPDATE oxibelt_admin_break_glass_activations
        SET revoked_at = COALESCE(revoked_at, now())
      WHERE namespace = $1 AND activation_id = $2 AND principal = $3
        AND revoked_at IS NULL AND expires_at > now()",
  )
  .bind(namespace)
  .bind(activation_id)
  .bind(principal)
  .execute(&mut **tx)
  .await?;
  Ok(result.rows_affected() == 1)
}

#[allow(dead_code)]
pub(crate) async fn load_active_break_glass_activation(
  store: &MutationStore,
  activation_id: &str,
  principal: &str,
) -> anyhow::Result<Option<BreakGlassActivation>> {
  let row = sqlx::query(
    "SELECT activation.activation_id, activation.principal, activation.scopes,
            activation.mutation_request_id,
            activation.expires_at::text AS expires_at,
            activation.revoked_at::text AS revoked_at,
            activation.created_at::text AS created_at
       FROM oxibelt_admin_break_glass_activations activation
       JOIN oxibelt_admin_mutations mutation
         ON mutation.namespace = activation.namespace
        AND mutation.request_id = activation.mutation_request_id
        AND mutation.state = 'committed'
      WHERE activation.namespace = $1 AND activation.activation_id = $2
        AND activation.principal = $3 AND activation.revoked_at IS NULL
        AND activation.expires_at > now()",
  )
  .bind(store.namespace())
  .bind(activation_id)
  .bind(principal)
  .fetch_optional(store.pool())
  .await?;
  row.as_ref().map(break_glass_from_row).transpose()
}

pub(crate) async fn load_active_break_glass_for_principal(
  store: &MutationStore,
  principal: &str,
) -> anyhow::Result<Option<BreakGlassActivation>> {
  validate_identifier("principal", principal, 256)?;
  let row = sqlx::query(
    "SELECT activation.activation_id, activation.principal, activation.scopes,
            activation.mutation_request_id,
            activation.expires_at::text AS expires_at,
            activation.revoked_at::text AS revoked_at,
            activation.created_at::text AS created_at
       FROM oxibelt_admin_break_glass_activations activation
       JOIN oxibelt_admin_mutations mutation
         ON mutation.namespace = activation.namespace
        AND mutation.request_id = activation.mutation_request_id
        AND mutation.state = 'committed'
      WHERE activation.namespace = $1 AND activation.principal = $2
        AND activation.revoked_at IS NULL AND activation.expires_at > now()
      ORDER BY activation.expires_at DESC LIMIT 1",
  )
  .bind(store.namespace())
  .bind(principal)
  .fetch_optional(store.pool())
  .await?;
  row.as_ref().map(break_glass_from_row).transpose()
}

fn break_glass_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<BreakGlassActivation> {
  Ok(BreakGlassActivation {
    activation_id: row.try_get("activation_id")?,
    principal: row.try_get("principal")?,
    scopes: row.try_get("scopes")?,
    mutation_request_id: row.try_get("mutation_request_id")?,
    expires_at: row.try_get("expires_at")?,
    revoked_at: row.try_get("revoked_at")?,
    created_at: row.try_get("created_at")?,
  })
}

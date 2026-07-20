use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, ensure};
use serde_json::Value;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Pool, Postgres, Row, Transaction};

use crate::audit_verify::{ExpectedStream, ExpectedStreamsManifest};
use crate::audit_verify_evidence::{
  AuthorityHead, LocalAuditRow, StreamEvidence, VerificationEvidence,
};
use crate::cli::AdminAuditVerifyArgs;

const QUERY_PAGE_SIZE: i64 = 10_000;
const MAX_PAGE_EVIDENCE_BYTES: u64 = 64 * 1024 * 1024;

struct EvidenceBudget {
  remaining_events: u64,
  remaining_checkpoints: u64,
  remaining_bytes: u64,
  max_event_bytes: i64,
  max_checkpoint_bytes: i64,
}

pub(crate) async fn load_verification_evidence(
  args: &AdminAuditVerifyArgs,
  manifest: &ExpectedStreamsManifest,
) -> anyhow::Result<VerificationEvidence> {
  let local_pool = connect_read_only(
    &args.local_postgres_url_env,
    "oxibeltctl-audit-local-verifier",
  )
  .await?;
  let anchor_pool = connect_read_only(
    &args.anchor_postgres_url_env,
    "oxibeltctl-audit-anchor-verifier",
  )
  .await?;
  let mut streams = Vec::with_capacity(manifest.streams.len());
  let mut budget = EvidenceBudget {
    remaining_events: args.max_events,
    remaining_checkpoints: args.max_checkpoints,
    remaining_bytes: args.max_evidence_bytes,
    max_event_bytes: i64::try_from(args.max_event_bytes)
      .context("--max-event-bytes is too large")?,
    max_checkpoint_bytes: i64::try_from(args.max_checkpoint_bytes)
      .context("--max-checkpoint-bytes is too large")?,
  };
  for expected in &manifest.streams {
    streams.push(
      load_stream(
        &local_pool,
        &anchor_pool,
        &manifest.namespace,
        expected,
        &mut budget,
      )
      .await?,
    );
  }
  local_pool.close().await;
  anchor_pool.close().await;
  Ok(VerificationEvidence { streams })
}

async fn connect_read_only(
  environment_name: &str,
  application_name: &str,
) -> anyhow::Result<Pool<Postgres>> {
  ensure!(
    !environment_name.is_empty() && environment_name.trim() == environment_name,
    "PostgreSQL URL environment name must not be empty or padded"
  );
  ensure!(
    environment_name
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
    "PostgreSQL URL environment name contains unsupported characters"
  );
  let connection_url = std::env::var(environment_name)
    .with_context(|| format!("failed to read PostgreSQL URL from {environment_name}"))?;
  let options = PgConnectOptions::from_str(&connection_url)
    .with_context(|| format!("invalid PostgreSQL URL in {environment_name}"))?
    .application_name(application_name)
    .options([
      ("default_transaction_read_only", "on"),
      ("statement_timeout", "30s"),
      ("lock_timeout", "5s"),
    ]);
  let pool = PgPoolOptions::new()
    .max_connections(1)
    .acquire_timeout(Duration::from_secs(10))
    .connect_with(options)
    .await
    .with_context(|| format!("failed to connect using PostgreSQL URL from {environment_name}"))?;
  Ok(pool)
}

async fn load_stream(
  local_pool: &Pool<Postgres>,
  anchor_pool: &Pool<Postgres>,
  namespace: &str,
  expected: &ExpectedStream,
  budget: &mut EvidenceBudget,
) -> anyhow::Result<StreamEvidence> {
  // Capture the authority first. A later local snapshot can contain a newly
  // unanchored suffix (reported as incomplete), but it cannot be older than a
  // checkpoint that the authority snapshot already exposed.
  let mut anchor_tx = repeatable_read_transaction(anchor_pool).await?;
  let checkpoints = load_checkpoints(
    &mut anchor_tx,
    namespace,
    &expected.stream_id,
    &mut budget.remaining_checkpoints,
    &mut budget.remaining_bytes,
    budget.max_checkpoint_bytes,
  )
  .await?;
  let authority_head = load_authority_head(&mut anchor_tx, namespace, &expected.stream_id).await?;
  anchor_tx
    .commit()
    .await
    .context("failed to finish the external authority verification snapshot")?;

  let mut local_tx = repeatable_read_transaction(local_pool).await?;
  let local_rows = load_local_rows(
    &mut local_tx,
    namespace,
    &expected.instance_id,
    &mut budget.remaining_events,
    &mut budget.remaining_bytes,
    budget.max_event_bytes,
  )
  .await?;
  local_tx
    .commit()
    .await
    .context("failed to finish the local Admin audit verification snapshot")?;
  Ok(StreamEvidence {
    expected: expected.clone(),
    local_rows,
    checkpoints,
    authority_head,
  })
}

async fn repeatable_read_transaction(
  pool: &Pool<Postgres>,
) -> anyhow::Result<Transaction<'_, Postgres>> {
  let mut tx = pool.begin().await?;
  sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
    .execute(&mut *tx)
    .await
    .context("failed to establish a read-only repeatable-read verification snapshot")?;
  Ok(tx)
}

async fn load_local_rows(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  instance_id: &str,
  remaining: &mut u64,
  remaining_bytes: &mut u64,
  max_event_bytes: i64,
) -> anyhow::Result<Vec<LocalAuditRow>> {
  let mut output = Vec::new();
  let mut after_id = 0_i64;
  loop {
    let page_limit = page_limit(
      *remaining,
      *remaining_bytes,
      u64::try_from(max_event_bytes)?,
    );
    let transfer_limit = effective_transfer_limit(max_event_bytes, *remaining_bytes);
    let rows = sqlx::query(
      "SELECT id,
              CASE WHEN event_payload IS NULL
                         OR octet_length(event_payload::text) <= $5
                   THEN event_payload::text END AS event_payload,
              octet_length(event_payload::text)::bigint AS event_payload_bytes
         FROM oxibelt_admin_audit
        WHERE namespace = $1 AND instance_id = $2 AND id > $3
        ORDER BY id ASC
        LIMIT $4",
    )
    .bind(namespace)
    .bind(instance_id)
    .bind(after_id)
    .bind(page_limit)
    .bind(transfer_limit)
    .fetch_all(&mut **tx)
    .await
    .context("failed to read local Admin audit evidence")?;
    if rows.is_empty() {
      break;
    }
    let row_count = rows.len();
    let row_count_u64 = u64::try_from(row_count)?;
    ensure!(
      row_count_u64 <= *remaining,
      "local Admin audit evidence exceeds --max-events"
    );
    *remaining -= row_count_u64;
    for row in rows {
      let id: i64 = row.try_get("id")?;
      consume_evidence_bytes(
        row.try_get("event_payload_bytes")?,
        max_event_bytes,
        remaining_bytes,
        "local Admin audit event",
      )?;
      let payload = row
        .try_get::<Option<String>, _>("event_payload")?
        .map(|payload| serde_json::from_str::<Value>(&payload))
        .transpose()
        .context("local Admin audit event_payload is not valid JSON")?;
      output.push(LocalAuditRow { id, payload });
      after_id = id;
    }
    if row_count < usize::try_from(page_limit)? {
      break;
    }
  }
  Ok(output)
}

async fn load_checkpoints(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  stream_id: &str,
  remaining: &mut u64,
  remaining_bytes: &mut u64,
  max_checkpoint_bytes: i64,
) -> anyhow::Result<Vec<Value>> {
  let mut output = Vec::new();
  let mut after_ordinal = 0_i64;
  loop {
    let page_limit = page_limit(
      *remaining,
      *remaining_bytes,
      u64::try_from(max_checkpoint_bytes)?,
    );
    let transfer_limit = effective_transfer_limit(max_checkpoint_bytes, *remaining_bytes);
    let rows = sqlx::query(
      "SELECT checkpoint_ordinal,
              CASE WHEN octet_length(checkpoint::text) <= $5
                   THEN checkpoint::text END AS checkpoint,
              octet_length(checkpoint::text)::bigint AS checkpoint_bytes
         FROM oxibelt_audit_anchor_v1.checkpoints($1, $2)
        WHERE checkpoint_ordinal > $3
        ORDER BY checkpoint_ordinal ASC
        LIMIT $4",
    )
    .bind(namespace)
    .bind(stream_id)
    .bind(after_ordinal)
    .bind(page_limit)
    .bind(transfer_limit)
    .fetch_all(&mut **tx)
    .await
    .context("failed to read external Admin audit checkpoints")?;
    if rows.is_empty() {
      break;
    }
    let row_count = rows.len();
    let row_count_u64 = u64::try_from(row_count)?;
    ensure!(
      row_count_u64 <= *remaining,
      "external checkpoint evidence exceeds --max-checkpoints"
    );
    *remaining -= row_count_u64;
    for row in rows {
      let ordinal: i64 = row.try_get("checkpoint_ordinal")?;
      consume_evidence_bytes(
        row.try_get("checkpoint_bytes")?,
        max_checkpoint_bytes,
        remaining_bytes,
        "external checkpoint",
      )?;
      ensure!(
        ordinal > after_ordinal,
        "external checkpoint authority returned non-increasing ordinals"
      );
      let checkpoint: String = row
        .try_get::<Option<String>, _>("checkpoint")?
        .context("external checkpoint exceeds its per-row evidence bound")?;
      output
        .push(serde_json::from_str(&checkpoint).context("external checkpoint is not valid JSON")?);
      after_ordinal = ordinal;
    }
    if row_count < usize::try_from(page_limit)? {
      break;
    }
  }
  Ok(output)
}

fn page_limit(remaining_rows: u64, remaining_bytes: u64, per_row_limit: u64) -> i64 {
  let by_rows = remaining_rows.saturating_add(1);
  let by_global_bytes = remaining_bytes
    .checked_div(per_row_limit)
    .unwrap_or(0)
    .saturating_add(1);
  let by_page_bytes = MAX_PAGE_EVIDENCE_BYTES
    .checked_div(per_row_limit)
    .unwrap_or(0)
    .max(1);
  i64::try_from(
    by_rows
      .min(by_global_bytes)
      .min(by_page_bytes)
      .min(QUERY_PAGE_SIZE as u64)
      .max(1),
  )
  .unwrap_or(1)
}

fn effective_transfer_limit(per_row_limit: i64, remaining_bytes: u64) -> i64 {
  let remaining_bytes = remaining_bytes.min(MAX_PAGE_EVIDENCE_BYTES);
  per_row_limit.min(i64::try_from(remaining_bytes).unwrap_or(i64::MAX))
}

fn consume_evidence_bytes(
  bytes: Option<i64>,
  per_row_limit: i64,
  remaining: &mut u64,
  label: &str,
) -> anyhow::Result<()> {
  let Some(bytes) = bytes else {
    return Ok(());
  };
  ensure!(
    bytes >= 0 && bytes <= per_row_limit,
    "{label} exceeds its per-row evidence bound"
  );
  let bytes = u64::try_from(bytes)?;
  ensure!(bytes <= *remaining, "evidence exceeds --max-evidence-bytes");
  *remaining -= bytes;
  Ok(())
}

async fn load_authority_head(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  stream_id: &str,
) -> anyhow::Result<Option<AuthorityHead>> {
  let row = sqlx::query(
    "SELECT checkpoint_ordinal, checkpoint_digest
       FROM oxibelt_audit_anchor_v1.head($1, $2)",
  )
  .bind(namespace)
  .bind(stream_id)
  .fetch_optional(&mut **tx)
  .await
  .context("failed to read external Admin audit checkpoint head")?;
  row
    .map(|row| {
      let checkpoint_ordinal: i64 = row.try_get("checkpoint_ordinal")?;
      Ok(AuthorityHead {
        checkpoint_ordinal: u64::try_from(checkpoint_ordinal)
          .context("external checkpoint ordinal is negative")?,
        checkpoint_digest: row.try_get("checkpoint_digest")?,
      })
    })
    .transpose()
}

#[cfg(test)]
mod tests {
  use super::{MAX_PAGE_EVIDENCE_BYTES, effective_transfer_limit, page_limit};

  #[test]
  fn page_limit_reserves_one_row_to_detect_exhausted_budgets() {
    assert_eq!(page_limit(0, 0, 128 * 1024), 1);
    assert_eq!(page_limit(5, 0, 128 * 1024), 1);
  }

  #[test]
  fn page_limit_caps_worst_case_page_bytes() {
    let per_row = 128 * 1024;
    let limit = page_limit(u64::MAX, u64::MAX, per_row);
    assert_eq!(
      u64::try_from(limit).unwrap() * per_row,
      MAX_PAGE_EVIDENCE_BYTES
    );
  }

  #[test]
  fn transfer_limit_never_exceeds_remaining_global_budget() {
    assert_eq!(effective_transfer_limit(128 * 1024, 4_096), 4_096);
    assert_eq!(effective_transfer_limit(128 * 1024, 0), 0);
  }

  #[test]
  fn transfer_limit_defensively_caps_an_invalid_internal_row_limit() {
    assert_eq!(
      effective_transfer_limit(256 * 1024 * 1024, u64::MAX),
      i64::try_from(MAX_PAGE_EVIDENCE_BYTES).unwrap()
    );
  }
}

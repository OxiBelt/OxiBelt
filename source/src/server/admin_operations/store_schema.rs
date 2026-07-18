//! PostgreSQL schema owned by the durable Admin-operation journal.

use anyhow::Context as _;

use super::OperationJournal;

impl OperationJournal {
  pub async fn initialize(&self) -> anyhow::Result<()> {
    let mut tx = self.pool.begin().await?;
    sqlx::query(
      "SELECT pg_advisory_xact_lock(hashtextextended('oxibelt-admin-operations-schema-v1', 0))",
    )
    .execute(&mut *tx)
    .await
    .context("failed to acquire Admin operation schema migration lock")?;
    let statements = statements();
    sqlx::query(statements[0]).execute(&mut *tx).await?;
    let applied: bool = sqlx::query_scalar(
      "SELECT EXISTS(SELECT 1 FROM oxibelt_admin_schema_migrations
        WHERE component = 'admin_operations' AND version = 1)",
    )
    .fetch_one(&mut *tx)
    .await?;
    if !applied {
      for statement in &statements[1..] {
        sqlx::query(*statement).execute(&mut *tx).await?;
      }
    }
    let upgraded: bool = sqlx::query_scalar(
      "SELECT EXISTS(SELECT 1 FROM oxibelt_admin_schema_migrations
        WHERE component = 'admin_operations' AND version = 2)",
    )
    .fetch_one(&mut *tx)
    .await?;
    if !upgraded {
      for statement in upgrade_statements() {
        sqlx::query(*statement).execute(&mut *tx).await?;
      }
    }
    tx.commit().await?;
    Ok(())
  }
}

pub(super) fn statements() -> &'static [&'static str] {
  &[
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_schema_migrations (
       component text NOT NULL,
       version integer NOT NULL,
       applied_at timestamptz NOT NULL DEFAULT now(),
       PRIMARY KEY(component, version)
     )",
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_operations (
       namespace text NOT NULL,
       operation_id text NOT NULL,
       actor text NOT NULL,
       request_id text NOT NULL,
       submitter_worker_id text NULL,
       submitter_boot_id text NULL,
       principal text NOT NULL,
       permission_action text NOT NULL,
       redacted_resource text NULL,
       resource_digest text NOT NULL,
       idempotency_key_digest text NULL,
       request_fingerprint text NOT NULL,
       kind text NOT NULL,
       schema_version integer NOT NULL,
       recovery_class text NOT NULL,
       state text NOT NULL DEFAULT 'accepted',
       revision bigint NOT NULL DEFAULT 1,
       owner_worker_id text NULL,
       owner_boot_id text NULL,
       lease_epoch bigint NOT NULL DEFAULT 0,
       lease_expires_at timestamptz NULL,
       progress jsonb NULL,
       checkpoint_artifact_id text NULL,
       terminal_result jsonb NULL,
       terminal_receipt bytea NULL,
       terminal_audit_record_id bigint NULL,
       safe_error_class text NULL,
       error_code text NULL,
       retention_seconds integer NOT NULL,
       created_at timestamptz NOT NULL DEFAULT now(),
       updated_at timestamptz NOT NULL DEFAULT now(),
       expires_at timestamptz NOT NULL,
       retention_until timestamptz NOT NULL,
       PRIMARY KEY(namespace, operation_id),
       CHECK (schema_version > 0),
       CHECK (revision > 0),
       CHECK (lease_epoch >= 0),
       CHECK (expires_at > created_at),
       CHECK (retention_until > created_at),
       CHECK (retention_seconds BETWEEN 1 AND 2592000),
       CHECK ((owner_worker_id IS NULL) = (owner_boot_id IS NULL)),
       CHECK ((owner_worker_id IS NULL) = (lease_expires_at IS NULL)),
       CHECK (terminal_audit_record_id IS NULL OR terminal_audit_record_id > 0),
       CHECK (recovery_class IN ('resumable', 'restartable', 'compensatable', 'non_resumable')),
       CHECK (state IN ('accepted', 'queued', 'claimed', 'running',
         'cancellation_requested', 'compensating', 'succeeded', 'failed',
         'cancelled', 'indeterminate')),
       CHECK ((state IN ('succeeded', 'failed', 'cancelled', 'indeterminate'))
         = (terminal_receipt IS NOT NULL)),
       CHECK ((state IN ('succeeded', 'failed', 'cancelled', 'indeterminate'))
         = (terminal_audit_record_id IS NOT NULL))
     )",
    "CREATE UNIQUE INDEX IF NOT EXISTS oxibelt_admin_operations_idempotency_idx
       ON oxibelt_admin_operations
         (namespace, actor, principal, permission_action, idempotency_key_digest)
       WHERE idempotency_key_digest IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS oxibelt_admin_operations_queue_idx
       ON oxibelt_admin_operations (namespace, created_at, operation_id)
       WHERE state IN ('queued', 'compensating')",
    "CREATE INDEX IF NOT EXISTS oxibelt_admin_operations_list_idx
       ON oxibelt_admin_operations (namespace, created_at DESC, operation_id DESC)",
    "CREATE INDEX IF NOT EXISTS oxibelt_admin_operations_lease_idx
       ON oxibelt_admin_operations (namespace, lease_expires_at)
       WHERE state IN ('claimed', 'running', 'cancellation_requested', 'compensating')",
    "CREATE INDEX IF NOT EXISTS oxibelt_admin_operations_retention_idx
       ON oxibelt_admin_operations (namespace, retention_until)
       WHERE state IN ('succeeded', 'failed', 'cancelled', 'indeterminate')",
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_operation_events (
       namespace text NOT NULL,
       operation_id text NOT NULL,
       revision bigint NOT NULL,
       event text NOT NULL,
       state text NOT NULL,
       progress jsonb NULL,
       payload jsonb NULL,
       created_at timestamptz NOT NULL DEFAULT now(),
       PRIMARY KEY(namespace, operation_id, revision),
       FOREIGN KEY(namespace, operation_id)
         REFERENCES oxibelt_admin_operations(namespace, operation_id) ON DELETE CASCADE,
       CHECK (revision > 0),
       CHECK (state IN ('accepted', 'queued', 'claimed', 'running',
         'cancellation_requested', 'compensating', 'succeeded', 'failed',
         'cancelled', 'indeterminate'))
     )",
    "CREATE INDEX IF NOT EXISTS oxibelt_admin_operation_events_time_idx
       ON oxibelt_admin_operation_events (namespace, created_at, operation_id, revision)",
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_operation_artifacts (
       namespace text NOT NULL,
       operation_id text NOT NULL,
       artifact_id text NOT NULL,
       artifact_kind text NOT NULL,
       operation_kind text NOT NULL,
       schema_version integer NOT NULL,
       principal text NOT NULL,
       permission_action text NOT NULL,
       resource_digest text NOT NULL,
       request_fingerprint text NOT NULL,
       algorithm text NOT NULL,
       key_fingerprint text NOT NULL,
       nonce bytea NOT NULL,
       ciphertext bytea NOT NULL,
       ciphertext_digest text NOT NULL,
       plaintext_len integer NOT NULL,
       created_at timestamptz NOT NULL DEFAULT now(),
       PRIMARY KEY(namespace, operation_id, artifact_id),
       UNIQUE(namespace, nonce),
       FOREIGN KEY(namespace, operation_id)
         REFERENCES oxibelt_admin_operations(namespace, operation_id) ON DELETE CASCADE,
       CHECK (schema_version > 0),
       CHECK (algorithm = 'aes-256-gcm-v1'),
       CHECK (octet_length(nonce) = 12),
       CHECK (plaintext_len BETWEEN 0 AND 16777216),
       CHECK (octet_length(ciphertext) = plaintext_len + 16)
     )",
    "INSERT INTO oxibelt_admin_schema_migrations(component, version)
       VALUES ('admin_operations', 1) ON CONFLICT DO NOTHING",
  ]
}

pub(super) fn upgrade_statements() -> &'static [&'static str] {
  &[
    "ALTER TABLE oxibelt_admin_operations
       ADD COLUMN IF NOT EXISTS submitter_worker_id text NULL",
    "ALTER TABLE oxibelt_admin_operations
       ADD COLUMN IF NOT EXISTS submitter_boot_id text NULL",
    "CREATE INDEX IF NOT EXISTS oxibelt_admin_operations_submitter_idx
       ON oxibelt_admin_operations
         (namespace, submitter_worker_id, submitter_boot_id, updated_at, operation_id)
       WHERE owner_worker_id IS NULL
         AND state IN ('accepted','queued','cancellation_requested')",
    "INSERT INTO oxibelt_admin_schema_migrations(component, version)
       VALUES ('admin_operations', 2) ON CONFLICT DO NOTHING",
  ]
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn schema_contains_durable_authority_and_fencing_fields() {
    let schema = statements().join("\n").to_ascii_lowercase();
    for field in [
      "idempotency_key_digest",
      "request_fingerprint",
      "recovery_class",
      "owner_worker_id",
      "owner_boot_id",
      "submitter_worker_id",
      "submitter_boot_id",
      "lease_epoch",
      "checkpoint_artifact_id",
      "terminal_receipt",
      "terminal_audit_record_id",
      "retention_until",
      "retention_seconds",
    ] {
      assert!(schema.contains(field), "missing durable field: {field}");
    }
    assert!(schema.contains("operation_id, revision"));
    assert!(schema.contains("state in ('succeeded', 'failed', 'cancelled', 'indeterminate')"));
  }

  #[test]
  fn artifact_schema_never_contains_plaintext_request_material() {
    let schema = statements().join("\n").to_ascii_lowercase();
    assert!(schema.contains("ciphertext bytea not null"));
    assert!(schema.contains("key_fingerprint text not null"));
    for forbidden in [
      "plaintext bytea",
      "request_body",
      "raw_headers",
      "idempotency_key text",
    ] {
      assert!(!schema.contains(forbidden), "schema persisted {forbidden}");
    }
  }

  #[test]
  fn migration_completion_is_recorded_last() {
    assert!(
      statements()
        .last()
        .is_some_and(|statement| statement.contains("admin_operations', 1"))
    );
    assert!(
      upgrade_statements()
        .last()
        .is_some_and(|statement| statement.contains("admin_operations', 2"))
    );
  }
}

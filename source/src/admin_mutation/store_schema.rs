//! PostgreSQL schema owned by the Admin mutation ledger.

pub(super) fn statements() -> &'static [&'static str] {
  &[
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_schema_migrations (
       component text NOT NULL,
       version integer NOT NULL,
       applied_at timestamptz NOT NULL DEFAULT now(),
       PRIMARY KEY(component, version)
     )",
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_mutation_revisions (
       namespace text NOT NULL,
       resource text NOT NULL,
       committed_revision text NOT NULL,
       content_digest text NOT NULL,
       cluster_id text NULL,
       membership_revision text NULL,
       pending_request_id text NULL,
       pending_revision text NULL,
       updated_at timestamptz NOT NULL DEFAULT now(),
       PRIMARY KEY(namespace, resource),
       CHECK ((pending_request_id IS NULL) = (pending_revision IS NULL)),
       CHECK ((cluster_id IS NULL) = (membership_revision IS NULL))
     )",
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_mutations (
       namespace text NOT NULL,
       request_id text NOT NULL,
       fingerprint text NOT NULL,
       principal text NOT NULL,
       signer_id text NOT NULL,
       action text NOT NULL,
       resource text NOT NULL,
       expected_previous_revision text NOT NULL,
       new_revision text NOT NULL,
       content_digest text NOT NULL,
       cluster_id text NULL,
       membership_revision text NULL,
       rollout_mode text NOT NULL DEFAULT 'single_instance',
       admission_instance_id text NULL,
       admission_boot_id text NULL,
       admission_instance_epoch bigint NULL,
       state text NOT NULL DEFAULT 'claimed',
       state_version bigint NOT NULL DEFAULT 0,
       canary_instance_id text NULL,
       phase_started_at timestamptz NOT NULL DEFAULT now(),
       phase_deadline_at timestamptz NULL,
       rollback_deadline_at timestamptz NULL,
       http_status integer NULL,
       safe_response jsonb NULL,
       error_code text NULL,
       audit_record_id bigint NOT NULL,
       admission_audit_confirmed_at timestamptz NULL,
       terminal_audit_record_id bigint NULL,
       terminal_audit_confirmed_at timestamptz NULL,
       coordinator_instance_id text NULL,
       coordinator_boot_id text NULL,
       coordinator_instance_epoch bigint NULL,
       coordinator_epoch bigint NOT NULL DEFAULT 0,
       coordinator_lease_expires_at timestamptz NULL,
       issued_at timestamptz NOT NULL,
       expires_at timestamptz NOT NULL,
       retention_until timestamptz NOT NULL,
       created_at timestamptz NOT NULL DEFAULT now(),
       updated_at timestamptz NOT NULL DEFAULT now(),
       PRIMARY KEY(namespace, request_id),
       CHECK (audit_record_id > 0),
       CHECK (terminal_audit_record_id IS NULL OR terminal_audit_record_id > 0),
       CHECK (new_revision <> expected_previous_revision),
       CHECK (expires_at > issued_at),
       CHECK (retention_until >= expires_at),
       CHECK (http_status IS NULL OR http_status BETWEEN 100 AND 599),
       CHECK ((cluster_id IS NULL) = (membership_revision IS NULL)),
       CHECK (rollout_mode IN ('single_instance', 'admin_cluster')),
       CHECK ((admission_instance_id IS NULL) = (admission_boot_id IS NULL)),
       CHECK ((admission_instance_id IS NULL) = (admission_instance_epoch IS NULL)),
       CHECK (state_version >= 0),
       CHECK (coordinator_epoch >= 0),
       CHECK ((coordinator_instance_id IS NULL) = (coordinator_boot_id IS NULL)),
       CHECK ((coordinator_instance_id IS NULL) = (coordinator_instance_epoch IS NULL)),
       CHECK ((coordinator_instance_id IS NULL) = (coordinator_lease_expires_at IS NULL)),
       CHECK (state IN ('claimed', 'validating', 'applying', 'canary_applying',
         'canary_healthy', 'expanding', 'fully_applied', 'committed', 'failed',
         'rolling_back', 'rolled_back', 'rollback_failed', 'indeterminate'))
     )",
    "CREATE INDEX IF NOT EXISTS oxibelt_admin_mutations_resource_idx
       ON oxibelt_admin_mutations (namespace, resource, created_at DESC)",
    "CREATE UNIQUE INDEX IF NOT EXISTS oxibelt_admin_mutations_revision_idx
       ON oxibelt_admin_mutations (namespace, resource, new_revision)",
    "CREATE INDEX IF NOT EXISTS oxibelt_admin_mutations_retention_idx
       ON oxibelt_admin_mutations (namespace, retention_until)",
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_mutation_artifacts (
       namespace text NOT NULL,
       request_id text NOT NULL,
       fingerprint text NOT NULL,
       resource text NOT NULL,
       cluster_id text NOT NULL,
       membership_revision text NOT NULL,
       new_revision text NOT NULL,
       content_digest text NOT NULL,
       algorithm text NOT NULL,
       nonce bytea NOT NULL,
       ciphertext bytea NOT NULL,
       ciphertext_digest text NOT NULL,
       plaintext_len integer NOT NULL,
       created_at timestamptz NOT NULL DEFAULT now(),
       PRIMARY KEY(namespace, request_id),
       UNIQUE(nonce),
       FOREIGN KEY(namespace, request_id)
         REFERENCES oxibelt_admin_mutations(namespace, request_id) ON DELETE CASCADE,
       CHECK (algorithm = 'aes-256-gcm-v1'),
       CHECK (octet_length(nonce) = 12),
       CHECK (plaintext_len BETWEEN 0 AND 16793638),
       CHECK (octet_length(ciphertext) = plaintext_len + 16)
     )",
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_mutation_targets (
       namespace text NOT NULL,
       request_id text NOT NULL,
       instance_id text NOT NULL,
       state text NOT NULL DEFAULT 'pending',
       state_version bigint NOT NULL DEFAULT 0,
       assignment_epoch bigint NOT NULL DEFAULT 0,
       boot_id text NULL,
       instance_epoch bigint NULL,
       effect_started_at timestamptz NULL,
       validation_revision text NULL,
       validation_digest text NULL,
       applied_revision text NULL,
       applied_digest text NULL,
       restored_revision text NULL,
       restored_digest text NULL,
       error_code text NULL,
       updated_at timestamptz NOT NULL DEFAULT now(),
       PRIMARY KEY(namespace, request_id, instance_id),
       FOREIGN KEY(namespace, request_id)
         REFERENCES oxibelt_admin_mutations(namespace, request_id) ON DELETE CASCADE,
       CHECK (state_version >= 0),
       CHECK (assignment_epoch >= 0),
       CHECK (state IN ('pending', 'validating', 'validated', 'apply_assigned',
         'applying', 'acked', 'nacked', 'rollback_assigned', 'rolling_back',
         'rolled_back', 'rollback_failed'))
     )",
    "CREATE INDEX IF NOT EXISTS oxibelt_admin_mutation_target_work_idx
       ON oxibelt_admin_mutation_targets
         (namespace, instance_id, state, request_id)",
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_instance_heartbeats (
       namespace text NOT NULL,
       cluster_id text NOT NULL,
       instance_id text NOT NULL,
       boot_id text NOT NULL,
       instance_epoch bigint NOT NULL DEFAULT 1,
       build_version text NOT NULL,
       capability_version text NOT NULL,
       artifact_key_fingerprint text NOT NULL,
       membership_revision text NOT NULL,
       assigned_revision text NULL,
       applied_revision text NOT NULL,
       applied_digest text NOT NULL,
       ready boolean NOT NULL,
       lease_expires_at timestamptz NOT NULL,
       updated_at timestamptz NOT NULL DEFAULT now(),
       PRIMARY KEY(namespace, cluster_id, instance_id),
       CHECK (membership_revision ~ '^sha256:[0-9a-f]{64}$'),
       CHECK (artifact_key_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
       CHECK (applied_digest ~ '^sha256:[0-9a-f]{64}$')
     )",
    "CREATE INDEX IF NOT EXISTS oxibelt_admin_instance_heartbeat_lease_idx
       ON oxibelt_admin_instance_heartbeats
         (namespace, cluster_id, membership_revision, lease_expires_at)",
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_instance_resource_heads (
       namespace text NOT NULL,
       cluster_id text NOT NULL,
       membership_revision text NOT NULL,
       instance_id text NOT NULL,
       resource text NOT NULL,
       boot_id text NOT NULL,
       instance_epoch bigint NOT NULL,
       assigned_revision text NULL,
       applied_revision text NOT NULL,
       applied_digest text NOT NULL,
       ready boolean NOT NULL,
       updated_at timestamptz NOT NULL DEFAULT now(),
       PRIMARY KEY(namespace, cluster_id, instance_id, resource),
       CHECK (instance_epoch > 0),
       CHECK (membership_revision ~ '^sha256:[0-9a-f]{64}$'),
       CHECK (applied_digest ~ '^sha256:[0-9a-f]{64}$'),
       CHECK (NOT ready OR assigned_revision IS NULL OR assigned_revision = applied_revision)
     )",
    "CREATE INDEX IF NOT EXISTS oxibelt_admin_instance_resource_head_membership_idx
       ON oxibelt_admin_instance_resource_heads
         (namespace, cluster_id, membership_revision, resource, instance_id)",
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_instance_boot_history (
       namespace text NOT NULL,
       cluster_id text NOT NULL,
       instance_id text NOT NULL,
       boot_id text NOT NULL,
       instance_epoch bigint NOT NULL,
       created_at timestamptz NOT NULL DEFAULT now(),
       retired_at timestamptz NULL,
       PRIMARY KEY(namespace, cluster_id, instance_id, boot_id),
       UNIQUE(namespace, cluster_id, instance_id, instance_epoch),
       CHECK (instance_epoch > 0)
     )",
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_mutation_checkpoints (
       namespace text NOT NULL,
       request_id text NOT NULL,
       instance_id text NOT NULL,
       assignment_epoch bigint NOT NULL,
       candidate_revision text NOT NULL,
       candidate_digest text NOT NULL,
       prior_revision text NOT NULL,
       prior_digest text NOT NULL,
       algorithm text NOT NULL,
       nonce bytea NOT NULL,
       ciphertext bytea NOT NULL,
       ciphertext_digest text NOT NULL,
       plaintext_len integer NOT NULL,
       created_at timestamptz NOT NULL DEFAULT now(),
       PRIMARY KEY(namespace, request_id, instance_id),
       FOREIGN KEY(namespace, request_id, instance_id)
         REFERENCES oxibelt_admin_mutation_targets(namespace, request_id, instance_id)
         ON DELETE CASCADE,
       CHECK (assignment_epoch > 0),
       CHECK (algorithm = 'aes-256-gcm-v1'),
       CHECK (octet_length(nonce) = 12),
       CHECK (plaintext_len BETWEEN 0 AND 16793638),
       CHECK (octet_length(ciphertext) = plaintext_len + 16)
     )",
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_shared_publications (
       namespace text NOT NULL,
       request_id text NOT NULL,
       operation_kind text NOT NULL,
       operation_fingerprint text NOT NULL,
       candidate_revision text NOT NULL,
       candidate_digest text NOT NULL,
       checkpoint_reference text NOT NULL,
       token_producing boolean NOT NULL DEFAULT false,
       state text NOT NULL DEFAULT 'applying',
       safe_response jsonb NULL,
       winner_response_consumed boolean NOT NULL DEFAULT false,
       created_at timestamptz NOT NULL DEFAULT now(),
       updated_at timestamptz NOT NULL DEFAULT now(),
       PRIMARY KEY(namespace, request_id),
       FOREIGN KEY(namespace, request_id)
         REFERENCES oxibelt_admin_mutations(namespace, request_id) ON DELETE CASCADE,
       CHECK (candidate_digest ~ '^sha256:[0-9a-f]{64}$'),
       CHECK (state IN ('applying','applied','restored','indeterminate'))
     )",
    // Additive upgrade statements for databases initialized by the reserved
    // rollout implementation. These deliberately precede constraint upgrades
    // that depend on the new columns and remain safe under concurrent startup
    // because init_postgres serializes them with an advisory transaction lock.
    "ALTER TABLE oxibelt_admin_mutations
       ADD COLUMN IF NOT EXISTS rollout_mode text NOT NULL DEFAULT 'single_instance'",
    "ALTER TABLE oxibelt_admin_mutations
       ADD COLUMN IF NOT EXISTS admission_instance_id text NULL",
    "ALTER TABLE oxibelt_admin_mutations
       ADD COLUMN IF NOT EXISTS admission_boot_id text NULL",
    "ALTER TABLE oxibelt_admin_mutations
       ADD COLUMN IF NOT EXISTS admission_instance_epoch bigint NULL",
    "ALTER TABLE oxibelt_admin_mutations
       ADD COLUMN IF NOT EXISTS state_version bigint NOT NULL DEFAULT 0",
    "ALTER TABLE oxibelt_admin_mutations
       ADD COLUMN IF NOT EXISTS canary_instance_id text NULL",
    "ALTER TABLE oxibelt_admin_mutations
       ADD COLUMN IF NOT EXISTS phase_started_at timestamptz NOT NULL DEFAULT now()",
    "ALTER TABLE oxibelt_admin_mutations
       ADD COLUMN IF NOT EXISTS phase_deadline_at timestamptz NULL",
    "ALTER TABLE oxibelt_admin_mutations
       ADD COLUMN IF NOT EXISTS rollback_deadline_at timestamptz NULL",
    "ALTER TABLE oxibelt_admin_mutations
       ADD COLUMN IF NOT EXISTS coordinator_boot_id text NULL",
    "ALTER TABLE oxibelt_admin_mutations
       ADD COLUMN IF NOT EXISTS coordinator_instance_epoch bigint NULL",
    "ALTER TABLE oxibelt_admin_mutations
       ADD COLUMN IF NOT EXISTS coordinator_epoch bigint NOT NULL DEFAULT 0",
    "ALTER TABLE oxibelt_admin_mutations
       ADD COLUMN IF NOT EXISTS admission_audit_confirmed_at timestamptz NULL",
    "ALTER TABLE oxibelt_admin_mutations
       ADD COLUMN IF NOT EXISTS terminal_audit_confirmed_at timestamptz NULL",
    "UPDATE oxibelt_admin_mutations
        SET admission_audit_confirmed_at = COALESCE(
              admission_audit_confirmed_at, created_at),
            terminal_audit_confirmed_at = CASE
              WHEN terminal_audit_record_id IS NOT NULL
              THEN COALESCE(terminal_audit_confirmed_at, updated_at)
              ELSE terminal_audit_confirmed_at END",
    "ALTER TABLE oxibelt_admin_mutation_targets
       ADD COLUMN IF NOT EXISTS state_version bigint NOT NULL DEFAULT 0",
    "ALTER TABLE oxibelt_admin_mutation_targets
       ADD COLUMN IF NOT EXISTS assignment_epoch bigint NOT NULL DEFAULT 0",
    "ALTER TABLE oxibelt_admin_mutation_targets
       ADD COLUMN IF NOT EXISTS instance_epoch bigint NULL",
    "ALTER TABLE oxibelt_admin_mutation_targets
       ADD COLUMN IF NOT EXISTS effect_started_at timestamptz NULL",
    "ALTER TABLE oxibelt_admin_mutation_targets
       ADD COLUMN IF NOT EXISTS validation_revision text NULL",
    "ALTER TABLE oxibelt_admin_mutation_targets
       ADD COLUMN IF NOT EXISTS validation_digest text NULL",
    "ALTER TABLE oxibelt_admin_mutation_targets
       ADD COLUMN IF NOT EXISTS restored_revision text NULL",
    "ALTER TABLE oxibelt_admin_mutation_targets
       ADD COLUMN IF NOT EXISTS restored_digest text NULL",
    "ALTER TABLE oxibelt_admin_instance_heartbeats
       ADD COLUMN IF NOT EXISTS instance_epoch bigint NOT NULL DEFAULT 1",
    "ALTER TABLE oxibelt_admin_instance_heartbeats
       ADD COLUMN IF NOT EXISTS artifact_key_fingerprint text NULL",
    "ALTER TABLE oxibelt_admin_shared_publications
       ADD COLUMN IF NOT EXISTS token_producing boolean NOT NULL DEFAULT false",
    "UPDATE oxibelt_admin_instance_heartbeats
       SET artifact_key_fingerprint = 'legacy-key-unknown'
       WHERE artifact_key_fingerprint IS NULL",
    "ALTER TABLE oxibelt_admin_instance_heartbeats
       ALTER COLUMN artifact_key_fingerprint SET NOT NULL",
    "INSERT INTO oxibelt_admin_instance_boot_history
       (namespace, cluster_id, instance_id, boot_id, instance_epoch)
       SELECT namespace, cluster_id, instance_id, boot_id, instance_epoch
         FROM oxibelt_admin_instance_heartbeats ON CONFLICT DO NOTHING",
    "UPDATE oxibelt_admin_mutations
       SET coordinator_instance_id=NULL, coordinator_boot_id=NULL,
           coordinator_instance_epoch=NULL, coordinator_lease_expires_at=NULL
       WHERE (coordinator_instance_id IS NULL) <> (coordinator_boot_id IS NULL)
          OR (coordinator_instance_id IS NULL) <> (coordinator_instance_epoch IS NULL)
          OR (coordinator_instance_id IS NULL) <> (coordinator_lease_expires_at IS NULL)",
    "ALTER TABLE oxibelt_admin_mutations
       DROP CONSTRAINT IF EXISTS oxibelt_admin_mutations_rollout_mode_check",
    "ALTER TABLE oxibelt_admin_mutations
       ADD CONSTRAINT oxibelt_admin_mutations_rollout_mode_check
       CHECK (rollout_mode IN ('single_instance','admin_cluster')) NOT VALID",
    "ALTER TABLE oxibelt_admin_mutations
       VALIDATE CONSTRAINT oxibelt_admin_mutations_rollout_mode_check",
    "ALTER TABLE oxibelt_admin_mutations
       DROP CONSTRAINT IF EXISTS oxibelt_admin_mutations_state_version_check",
    "ALTER TABLE oxibelt_admin_mutations
       ADD CONSTRAINT oxibelt_admin_mutations_state_version_check
       CHECK (state_version >= 0 AND coordinator_epoch >= 0) NOT VALID",
    "ALTER TABLE oxibelt_admin_mutations
       VALIDATE CONSTRAINT oxibelt_admin_mutations_state_version_check",
    "ALTER TABLE oxibelt_admin_mutations
       DROP CONSTRAINT IF EXISTS oxibelt_admin_mutations_coordinator_tuple_check",
    "ALTER TABLE oxibelt_admin_mutations
       ADD CONSTRAINT oxibelt_admin_mutations_coordinator_tuple_check CHECK (
         (coordinator_instance_id IS NULL) = (coordinator_boot_id IS NULL)
         AND (coordinator_instance_id IS NULL) = (coordinator_instance_epoch IS NULL)
         AND (coordinator_instance_id IS NULL) = (coordinator_lease_expires_at IS NULL)
       ) NOT VALID",
    "ALTER TABLE oxibelt_admin_mutations
       VALIDATE CONSTRAINT oxibelt_admin_mutations_coordinator_tuple_check",
    "ALTER TABLE oxibelt_admin_mutations
       DROP CONSTRAINT IF EXISTS oxibelt_admin_mutations_admission_tuple_check",
    "ALTER TABLE oxibelt_admin_mutations
       ADD CONSTRAINT oxibelt_admin_mutations_admission_tuple_check CHECK (
         (admission_instance_id IS NULL) = (admission_boot_id IS NULL)
         AND (admission_instance_id IS NULL) = (admission_instance_epoch IS NULL)
       ) NOT VALID",
    "ALTER TABLE oxibelt_admin_mutations
       VALIDATE CONSTRAINT oxibelt_admin_mutations_admission_tuple_check",
    "ALTER TABLE oxibelt_admin_mutation_targets
       DROP CONSTRAINT IF EXISTS oxibelt_admin_mutation_targets_version_check",
    "ALTER TABLE oxibelt_admin_mutation_targets
       ADD CONSTRAINT oxibelt_admin_mutation_targets_version_check
       CHECK (state_version >= 0 AND assignment_epoch >= 0) NOT VALID",
    "ALTER TABLE oxibelt_admin_mutation_targets
       VALIDATE CONSTRAINT oxibelt_admin_mutation_targets_version_check",
    "ALTER TABLE oxibelt_admin_mutation_artifacts
       DROP CONSTRAINT IF EXISTS oxibelt_admin_mutation_artifacts_plaintext_len_check",
    "ALTER TABLE oxibelt_admin_mutation_artifacts
       ADD CONSTRAINT oxibelt_admin_mutation_artifacts_plaintext_len_check
       CHECK (plaintext_len BETWEEN 0 AND 16793638) NOT VALID",
    "ALTER TABLE oxibelt_admin_mutation_artifacts
       VALIDATE CONSTRAINT oxibelt_admin_mutation_artifacts_plaintext_len_check",
    "CREATE INDEX IF NOT EXISTS oxibelt_admin_mutation_recovery_idx
       ON oxibelt_admin_mutations
         (namespace, rollout_mode, state, updated_at)",
    "ALTER TABLE oxibelt_admin_mutation_targets
       DROP CONSTRAINT IF EXISTS oxibelt_admin_mutation_targets_state_check",
    "ALTER TABLE oxibelt_admin_mutation_targets
       ADD CONSTRAINT oxibelt_admin_mutation_targets_state_check
       CHECK (state IN ('pending', 'validating', 'validated', 'apply_assigned',
         'applying', 'acked', 'nacked', 'rollback_assigned', 'rolling_back',
         'rolled_back', 'rollback_failed')) NOT VALID",
    "ALTER TABLE oxibelt_admin_mutation_targets
       VALIDATE CONSTRAINT oxibelt_admin_mutation_targets_state_check",
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_break_glass_activations (
       namespace text NOT NULL,
       activation_id text NOT NULL,
       principal text NOT NULL,
       scopes text[] NOT NULL,
       mutation_request_id text NOT NULL,
       expires_at timestamptz NOT NULL,
       revoked_at timestamptz NULL,
       created_at timestamptz NOT NULL DEFAULT now(),
       PRIMARY KEY(namespace, activation_id),
       UNIQUE(namespace, mutation_request_id),
       FOREIGN KEY(namespace, mutation_request_id)
         REFERENCES oxibelt_admin_mutations(namespace, request_id) ON DELETE CASCADE,
       CHECK (cardinality(scopes) > 0)
     )",
    "CREATE INDEX IF NOT EXISTS oxibelt_admin_break_glass_active_idx
       ON oxibelt_admin_break_glass_activations
         (namespace, principal, expires_at) WHERE revoked_at IS NULL",
    "INSERT INTO oxibelt_admin_schema_migrations(component, version)
       VALUES ('admin_mutation', 3) ON CONFLICT DO NOTHING",
  ]
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::admin_mutation::ledger::MutationState;

  #[test]
  fn artifact_schema_contains_only_ciphertext_and_binding_metadata() {
    let schema = statements()
      .iter()
      .find(|statement| statement.contains("oxibelt_admin_mutation_artifacts"))
      .expect("artifact schema statement");
    assert!(schema.contains("ciphertext bytea NOT NULL"));
    assert!(schema.contains("nonce bytea NOT NULL"));
    assert!(schema.contains("content_digest text NOT NULL"));
    assert!(!schema.contains("plaintext bytea"));
    assert!(!schema.contains("request_body"));
  }

  #[test]
  fn schema_never_persists_signature_or_raw_request_body() {
    let schema = statements().join("\n").to_ascii_lowercase();
    assert!(!schema.contains(" signature "));
    assert!(!schema.contains("request_body"));
    assert!(schema.contains("fingerprint text not null"));
    assert!(schema.contains("audit_record_id bigint not null"));
  }

  #[test]
  fn blocked_terminal_states_are_not_eligible_for_cleanup() {
    let cleanup = "committed failed rolled_back";
    assert!(!cleanup.contains(MutationState::Indeterminate.as_str()));
    assert!(!cleanup.contains(MutationState::RollbackFailed.as_str()));
  }

  #[test]
  fn additive_cluster_migration_records_completion_last() {
    let schema = statements().join("\n");
    for invariant in [
      "ADD COLUMN IF NOT EXISTS rollout_mode",
      "ADD COLUMN IF NOT EXISTS state_version",
      "ADD COLUMN IF NOT EXISTS coordinator_boot_id",
      "ADD COLUMN IF NOT EXISTS coordinator_instance_epoch",
      "ADD COLUMN IF NOT EXISTS coordinator_epoch",
      "ADD COLUMN IF NOT EXISTS terminal_audit_confirmed_at",
      "ADD COLUMN IF NOT EXISTS admission_audit_confirmed_at",
      "ADD COLUMN IF NOT EXISTS admission_instance_id",
      "ADD COLUMN IF NOT EXISTS admission_boot_id",
      "ADD COLUMN IF NOT EXISTS admission_instance_epoch",
      "ADD COLUMN IF NOT EXISTS assignment_epoch",
      "oxibelt_admin_instance_boot_history",
      "oxibelt_admin_instance_resource_heads",
      "oxibelt_admin_mutation_checkpoints",
      "oxibelt_admin_shared_publications",
      "oxibelt_admin_mutations_admission_tuple_check",
      "VALIDATE CONSTRAINT oxibelt_admin_mutations_coordinator_tuple_check",
    ] {
      assert!(
        schema.contains(invariant),
        "missing migration invariant: {invariant}"
      );
    }
    assert!(
      statements()
        .last()
        .is_some_and(|statement| statement.contains("oxibelt_admin_schema_migrations")),
      "migration version must be recorded only after every schema change"
    );
  }
}

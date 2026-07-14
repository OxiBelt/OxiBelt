//! PostgreSQL schema owned by the Admin mutation ledger.

pub(super) fn statements() -> &'static [&'static str] {
  &[
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
       state text NOT NULL DEFAULT 'claimed',
       http_status integer NULL,
       safe_response jsonb NULL,
       error_code text NULL,
       audit_record_id bigint NOT NULL,
       terminal_audit_record_id bigint NULL,
       coordinator_instance_id text NULL,
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
       CHECK (plaintext_len BETWEEN 0 AND 16777216),
       CHECK (octet_length(ciphertext) = plaintext_len + 16)
     )",
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_mutation_targets (
       namespace text NOT NULL,
       request_id text NOT NULL,
       instance_id text NOT NULL,
       state text NOT NULL DEFAULT 'pending',
       boot_id text NULL,
       applied_revision text NULL,
       applied_digest text NULL,
       error_code text NULL,
       updated_at timestamptz NOT NULL DEFAULT now(),
       PRIMARY KEY(namespace, request_id, instance_id),
       FOREIGN KEY(namespace, request_id)
         REFERENCES oxibelt_admin_mutations(namespace, request_id) ON DELETE CASCADE,
       CHECK (state IN ('pending', 'validating', 'applying', 'acked', 'nacked',
         'rolling_back', 'rolled_back', 'rollback_failed'))
     )",
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_instance_heartbeats (
       namespace text NOT NULL,
       cluster_id text NOT NULL,
       instance_id text NOT NULL,
       boot_id text NOT NULL,
       build_version text NOT NULL,
       capability_version text NOT NULL,
       membership_revision text NOT NULL,
       assigned_revision text NULL,
       applied_revision text NOT NULL,
       applied_digest text NOT NULL,
       ready boolean NOT NULL,
       lease_expires_at timestamptz NOT NULL,
       updated_at timestamptz NOT NULL DEFAULT now(),
       PRIMARY KEY(namespace, cluster_id, instance_id)
     )",
    "CREATE INDEX IF NOT EXISTS oxibelt_admin_instance_heartbeat_lease_idx
       ON oxibelt_admin_instance_heartbeats
         (namespace, cluster_id, membership_revision, lease_expires_at)",
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
}

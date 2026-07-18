//! Transaction-scoped IPM Admin mutations for fixed-member cluster rollout.
//!
//! The caller owns the PostgreSQL transaction and is responsible for fencing
//! the coordinator immediately before committing it. This module deliberately
//! does not commit or refresh after the mutation.

use std::fmt;

use anyhow::{Context, bail, ensure};
use sqlx::{Postgres, Row, Transaction};
use zeroize::Zeroizing;

use crate::config::{IpmPolicyConfig, validate_runtime_identifier};

use super::admin_references::{ensure_policy_unreferenced_tx, ensure_principal_unreferenced_tx};
use super::admin_support::*;
use super::{
  IpmActor, IpmBindingCreate, IpmCredentialCreate, IpmCredentialPatch, IpmCredentialRevoke,
  IpmCredentialRotate, IpmEntrySource, IpmPolicyCreate, IpmPolicyPatch, IpmPrincipalCreate,
  IpmPrincipalPatch, IpmRuntime, RedactedIpmCredential, token,
};

#[path = "admin_transaction_checkpoint.rs"]
mod checkpoint;
pub(crate) use checkpoint::IpmMutationCheckpoint;
use checkpoint::{capture_checkpoint, restore_checkpoint_row};

#[derive(Debug, Clone)]
pub(crate) enum IpmAdminMutation {
  PrincipalCreate(IpmPrincipalCreate),
  PrincipalPatch(String, IpmPrincipalPatch),
  PrincipalDelete(String),
  CredentialCreate(IpmCredentialCreate),
  CredentialPatch(String, IpmCredentialPatch),
  CredentialRotate(String, IpmCredentialRotate),
  CredentialRevoke(String, IpmCredentialRevoke),
  CredentialDelete(String),
  PolicyCreate(IpmPolicyCreate),
  PolicyPatch(String, IpmPolicyPatch),
  PolicyDelete(String),
  BindingCreate(IpmBindingCreate),
  BindingDelete(String),
}

pub(crate) struct IpmTransactionalMutationResult {
  pub(crate) target_kind: &'static str,
  pub(crate) target_id: String,
  /// Plaintext is attached only to the winning request and must not be placed
  /// in a replayable receipt. Dropping the result zeroizes it.
  pub(crate) one_time_token: Option<Zeroizing<String>>,
  /// Captured in the publishing transaction so a post-commit refresh failure
  /// cannot strand the winning one-time response.
  pub(crate) winner_credential: Option<RedactedIpmCredential>,
  pub(crate) checkpoint: IpmMutationCheckpoint,
}

impl fmt::Debug for IpmTransactionalMutationResult {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("IpmTransactionalMutationResult")
      .field("target_kind", &self.target_kind)
      .field("target_id", &self.target_id)
      .field("has_one_time_token", &self.one_time_token.is_some())
      .field("has_winner_credential", &self.winner_credential.is_some())
      .field("checkpoint", &self.checkpoint)
      .finish()
  }
}

impl IpmRuntime {
  pub(crate) async fn refresh_after_shared_commit(&self) -> anyhow::Result<()> {
    self.refresh_store().await
  }

  /// Applies one typed Admin mutation inside a caller-owned transaction.
  ///
  /// The table lock is acquired before refreshing the merged snapshot, making
  /// authority, static-entry, reference, and last-admin checks describe the
  /// same committed state that the SQL mutation changes. The caller must use a
  /// transaction from the IPM/control-plane PostgreSQL backend and perform its
  /// coordinator-fence recheck immediately before commit.
  pub(crate) async fn apply_admin_mutation_tx(
    &self,
    tx: &mut Transaction<'_, Postgres>,
    actor: &IpmActor,
    expected_precondition_revision: &str,
    mutation: IpmAdminMutation,
  ) -> anyhow::Result<IpmTransactionalMutationResult> {
    let store = self.admin_store()?;
    self
      .validate_admin_mutation_tx_precondition(tx, expected_precondition_revision)
      .await?;
    let namespace = store.namespace();
    let checkpoint = capture_checkpoint(tx, namespace, &mutation).await?;

    match mutation {
      IpmAdminMutation::PrincipalCreate(input) => {
        validate_runtime_identifier("ipm principal id", &input.id)?;
        validate_non_empty("ipm principal subject", &input.subject)?;
        validate_groups(&input.groups)?;
        self.ensure_actor_may_create_principal(actor, &input.id, &input.subject, &input.groups)?;
        ensure_not_static_principal(self, &input.id)?;
        sqlx::query(
          "INSERT INTO oxibelt_ipm_principals
             (namespace, principal_id, subject, groups, enabled)
           VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(namespace)
        .bind(&input.id)
        .bind(&input.subject)
        .bind(&input.groups)
        .bind(input.enabled.unwrap_or(true))
        .execute(&mut **tx)
        .await?;
        finish_tx(tx, namespace, actor, "create", "principal", &input.id).await?;
        result("principal", input.id, None, checkpoint)
      }
      IpmAdminMutation::PrincipalPatch(id, input) => {
        ensure_store_principal(self, &id)?;
        if let Some(subject) = &input.subject {
          validate_non_empty("ipm principal subject", subject)?;
        }
        if let Some(groups) = &input.groups {
          validate_groups(groups)?;
        }
        self.ensure_actor_may_patch_principal(
          actor,
          &id,
          input.subject.as_deref(),
          input.groups.as_deref(),
        )?;
        if input.enabled == Some(false) {
          self.ensure_not_last_admin_principal(&id)?;
        }
        sqlx::query(
          "UPDATE oxibelt_ipm_principals
              SET subject = COALESCE($3, subject), groups = COALESCE($4, groups),
                  enabled = COALESCE($5, enabled), updated_at = now()
            WHERE namespace = $1 AND principal_id = $2",
        )
        .bind(namespace)
        .bind(&id)
        .bind(&input.subject)
        .bind(&input.groups)
        .bind(input.enabled)
        .execute(&mut **tx)
        .await?;
        finish_tx(tx, namespace, actor, "patch", "principal", &id).await?;
        result("principal", id, None, checkpoint)
      }
      IpmAdminMutation::PrincipalDelete(id) => {
        ensure_store_principal(self, &id)?;
        self.ensure_not_last_admin_principal(&id)?;
        ensure_principal_unreferenced_tx(tx, namespace, &id).await?;
        sqlx::query(
          "DELETE FROM oxibelt_ipm_principals WHERE namespace = $1 AND principal_id = $2",
        )
        .bind(namespace)
        .bind(&id)
        .execute(&mut **tx)
        .await?;
        finish_tx(tx, namespace, actor, "delete", "principal", &id).await?;
        result("principal", id, None, checkpoint)
      }
      IpmAdminMutation::CredentialCreate(input) => {
        validate_runtime_identifier("ipm credential id", &input.id)?;
        validate_runtime_identifier("ipm credential principal", &input.principal)?;
        token::require_expiry(input.ttl_seconds, &input.expires_at, input.no_expiry)?;
        ensure_not_static_credential(self, &input.id)?;
        ensure_principal_exists(self, &input.principal)?;
        self.ensure_actor_may_assign_credential_principal(actor, None, &input.principal)?;
        let generated = token::generate_token()?;
        sqlx::query(
          "INSERT INTO oxibelt_ipm_credentials
             (namespace, credential_id, principal_id, subject, token_prefix, token_hash,
              token_hash_alg, enabled, revoked, expires_at, created_by)
           VALUES ($1, $2, $3, $3, $4, $5, $6, true, false,
             CASE WHEN $7::bigint IS NOT NULL THEN now() + ($7::bigint * interval '1 second')
                  WHEN $8::text IS NOT NULL THEN $8::timestamptz ELSE NULL END, $9)",
        )
        .bind(namespace)
        .bind(&input.id)
        .bind(&input.principal)
        .bind(&generated.prefix)
        .bind(&generated.hash)
        .bind(token::TOKEN_HASH_ALG)
        .bind(input.ttl_seconds)
        .bind(&input.expires_at)
        .bind(&actor.name)
        .execute(&mut **tx)
        .await?;
        finish_tx(tx, namespace, actor, "create", "credential", &input.id).await?;
        let winner = load_redacted_credential_tx(tx, namespace, &input.id).await?;
        let mut result = result(
          "credential",
          input.id,
          Some(Zeroizing::new(generated.token)),
          checkpoint,
        )?;
        result.winner_credential = Some(winner);
        Ok(result)
      }
      IpmAdminMutation::CredentialPatch(id, input) => {
        ensure_store_credential(self, &id)?;
        if let Some(principal) = &input.principal {
          validate_runtime_identifier("ipm credential principal", principal)?;
          ensure_principal_exists(self, principal)?;
          self.ensure_actor_may_assign_credential_principal(actor, Some(&id), principal)?;
        }
        token::expires_clause(input.ttl_seconds, &input.expires_at)?;
        if input.enabled == Some(false) {
          self.ensure_not_last_admin_credential(&id)?;
        }
        sqlx::query(
          "UPDATE oxibelt_ipm_credentials
              SET principal_id = COALESCE($3, principal_id), subject = COALESCE($3, subject),
                  enabled = COALESCE($4, enabled),
                  expires_at = CASE
                    WHEN $5::bigint IS NOT NULL THEN now() + ($5::bigint * interval '1 second')
                    WHEN $6::text IS NOT NULL THEN $6::timestamptz ELSE expires_at END,
                  updated_at = now()
            WHERE namespace = $1 AND credential_id = $2",
        )
        .bind(namespace)
        .bind(&id)
        .bind(&input.principal)
        .bind(input.enabled)
        .bind(input.ttl_seconds)
        .bind(&input.expires_at)
        .execute(&mut **tx)
        .await?;
        finish_tx(tx, namespace, actor, "patch", "credential", &id).await?;
        result("credential", id, None, checkpoint)
      }
      IpmAdminMutation::CredentialRotate(id, input) => {
        ensure_store_credential(self, &id)?;
        if input.overlap_seconds <= 0 {
          bail!("overlap_seconds must be greater than 0");
        }
        token::require_expiry(input.ttl_seconds, &input.expires_at, input.no_expiry)?;
        let generated = token::generate_token()?;
        sqlx::query(
          "UPDATE oxibelt_ipm_credentials
              SET previous_token_prefix = token_prefix, previous_token_hash = token_hash,
                  previous_token_overlap_until = now() + ($3::bigint * interval '1 second'),
                  token_prefix = $4, token_hash = $5, token_hash_alg = $6,
                  revoked = false, revoked_at = NULL, revoked_by = NULL, revoke_reason = NULL,
                  expires_at = CASE
                    WHEN $7::bigint IS NOT NULL THEN now() + ($7::bigint * interval '1 second')
                    WHEN $8::text IS NOT NULL THEN $8::timestamptz ELSE NULL END,
                  updated_at = now()
            WHERE namespace = $1 AND credential_id = $2",
        )
        .bind(namespace)
        .bind(&id)
        .bind(input.overlap_seconds)
        .bind(&generated.prefix)
        .bind(&generated.hash)
        .bind(token::TOKEN_HASH_ALG)
        .bind(input.ttl_seconds)
        .bind(&input.expires_at)
        .execute(&mut **tx)
        .await?;
        finish_tx(tx, namespace, actor, "rotate", "credential", &id).await?;
        let winner = load_redacted_credential_tx(tx, namespace, &id).await?;
        let mut result = result(
          "credential",
          id,
          Some(Zeroizing::new(generated.token)),
          checkpoint,
        )?;
        result.winner_credential = Some(winner);
        Ok(result)
      }
      IpmAdminMutation::CredentialRevoke(id, input) => {
        ensure_store_credential(self, &id)?;
        self.ensure_not_last_admin_credential(&id)?;
        sqlx::query(
          "UPDATE oxibelt_ipm_credentials
              SET revoked = true, revoked_at = now(), revoked_by = $3, revoke_reason = $4,
                  previous_token_prefix = NULL, previous_token_hash = NULL,
                  previous_token_overlap_until = NULL, updated_at = now()
            WHERE namespace = $1 AND credential_id = $2",
        )
        .bind(namespace)
        .bind(&id)
        .bind(&actor.name)
        .bind(&input.reason)
        .execute(&mut **tx)
        .await?;
        finish_tx(tx, namespace, actor, "revoke", "credential", &id).await?;
        result("credential", id, None, checkpoint)
      }
      IpmAdminMutation::CredentialDelete(id) => {
        ensure_store_credential(self, &id)?;
        self.ensure_not_last_admin_credential(&id)?;
        sqlx::query(
          "DELETE FROM oxibelt_ipm_credentials WHERE namespace = $1 AND credential_id = $2",
        )
        .bind(namespace)
        .bind(&id)
        .execute(&mut **tx)
        .await?;
        finish_tx(tx, namespace, actor, "delete", "credential", &id).await?;
        result("credential", id, None, checkpoint)
      }
      IpmAdminMutation::PolicyCreate(input) => {
        let policy = input.policy()?;
        ensure_not_static_policy(self, &policy.name)?;
        self.ensure_actor_may_create_policy(actor, &policy)?;
        let document = serde_json::to_string(&policy)?;
        sqlx::query(
          "INSERT INTO oxibelt_ipm_policies (namespace, policy_id, document, enabled)
           VALUES ($1, $2, $3::jsonb, $4)",
        )
        .bind(namespace)
        .bind(&policy.name)
        .bind(document)
        .bind(input.enabled.unwrap_or(true))
        .execute(&mut **tx)
        .await?;
        finish_tx(tx, namespace, actor, "create", "policy", &policy.name).await?;
        result("policy", policy.name, None, checkpoint)
      }
      IpmAdminMutation::PolicyPatch(id, input) => {
        let current = ensure_store_policy(self, &id)?;
        if input.enabled == Some(false) {
          self.ensure_not_last_admin_policy(&id)?;
        }
        let policy = IpmPolicyConfig {
          name: id.clone(),
          version: input.version.unwrap_or_else(|| current.version.clone()),
          statements: input
            .statements
            .unwrap_or_else(|| current.statements.clone()),
        };
        validate_policy(&policy)?;
        self.ensure_actor_may_patch_policy(actor, &current, &policy)?;
        let document = serde_json::to_string(&policy)?;
        sqlx::query(
          "UPDATE oxibelt_ipm_policies
              SET document = $3::jsonb, enabled = COALESCE($4, enabled), updated_at = now()
            WHERE namespace = $1 AND policy_id = $2",
        )
        .bind(namespace)
        .bind(&id)
        .bind(document)
        .bind(input.enabled)
        .execute(&mut **tx)
        .await?;
        finish_tx(tx, namespace, actor, "patch", "policy", &id).await?;
        result("policy", id, None, checkpoint)
      }
      IpmAdminMutation::PolicyDelete(id) => {
        ensure_store_policy(self, &id)?;
        self.ensure_not_last_admin_policy(&id)?;
        ensure_policy_unreferenced_tx(tx, namespace, &id).await?;
        sqlx::query("DELETE FROM oxibelt_ipm_policies WHERE namespace = $1 AND policy_id = $2")
          .bind(namespace)
          .bind(&id)
          .execute(&mut **tx)
          .await?;
        finish_tx(tx, namespace, actor, "delete", "policy", &id).await?;
        result("policy", id, None, checkpoint)
      }
      IpmAdminMutation::BindingCreate(input) => {
        let id = input.id.clone().unwrap_or_else(|| {
          generated_binding_id(
            input.principal.as_deref(),
            input.group.as_deref(),
            &input.policy,
          )
        });
        validate_runtime_identifier("ipm binding id", &id)?;
        validate_binding(&input)?;
        ensure_policy_exists(self, &input.policy)?;
        if let Some(principal) = &input.principal {
          ensure_principal_exists(self, principal)?;
        }
        self.ensure_actor_may_create_binding(actor, &input)?;
        sqlx::query(
          "INSERT INTO oxibelt_ipm_policy_bindings
             (namespace, binding_id, principal_id, group_name, policy_id, enabled)
           VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(namespace)
        .bind(&id)
        .bind(&input.principal)
        .bind(&input.group)
        .bind(&input.policy)
        .bind(input.enabled.unwrap_or(true))
        .execute(&mut **tx)
        .await?;
        finish_tx(tx, namespace, actor, "create", "binding", &id).await?;
        result("binding", id, None, checkpoint)
      }
      IpmAdminMutation::BindingDelete(id) => {
        ensure_store_binding(self, &id)?;
        self.ensure_not_last_admin_binding(&id)?;
        sqlx::query(
          "DELETE FROM oxibelt_ipm_policy_bindings WHERE namespace = $1 AND binding_id = $2",
        )
        .bind(namespace)
        .bind(&id)
        .execute(&mut **tx)
        .await?;
        finish_tx(tx, namespace, actor, "delete", "binding", &id).await?;
        result("binding", id, None, checkpoint)
      }
    }
  }

  pub(crate) async fn validate_admin_mutation_tx_precondition(
    &self,
    tx: &mut Transaction<'_, Postgres>,
    expected_precondition_revision: &str,
  ) -> anyhow::Result<()> {
    lock_ipm_write_tx(tx).await?;
    self
      .refresh_store()
      .await
      .context("failed to refresh the post-lock IPM validation snapshot")?;
    ensure!(
      self.admin_status().etag.trim_matches('"') == expected_precondition_revision,
      "IPM operational precondition changed before shared publication"
    );
    Ok(())
  }

  /// Restores the exact protected row and generation captured before an
  /// applied shared mutation. The coordinator must fence and commit the wider
  /// transaction. A generation mismatch fails closed rather than overwriting
  /// an intervening protected write.
  pub(crate) async fn restore_admin_mutation_tx(
    &self,
    tx: &mut Transaction<'_, Postgres>,
    actor: &IpmActor,
    checkpoint: &IpmMutationCheckpoint,
  ) -> anyhow::Result<()> {
    let store = self.admin_store()?;
    lock_ipm_write_tx(tx).await?;
    self
      .refresh_store()
      .await
      .context("failed to refresh the post-lock IPM rollback snapshot")?;
    let namespace = store.namespace();
    checkpoint.validate_namespace(namespace)?;
    let prior_generation = checkpoint.prior_generation_value()?;
    let current_generation: Option<i64> = sqlx::query_scalar(
      "SELECT generation FROM oxibelt_ipm_generation WHERE namespace=$1 FOR UPDATE",
    )
    .bind(namespace)
    .fetch_optional(&mut **tx)
    .await?;
    ensure!(
      current_generation == Some(prior_generation.unwrap_or(0) + 1),
      "IPM rollback generation does not immediately follow its checkpoint"
    );
    restore_checkpoint_row(tx, namespace, checkpoint).await?;
    sqlx::query("DELETE FROM oxibelt_ipm_generation WHERE namespace=$1")
      .bind(namespace)
      .execute(&mut **tx)
      .await?;
    if let Some(generation) = &checkpoint.prior_generation {
      let generation = std::str::from_utf8(generation)?;
      sqlx::query(
        "INSERT INTO oxibelt_ipm_generation
         SELECT (jsonb_populate_record(NULL::oxibelt_ipm_generation,$1::jsonb)).*",
      )
      .bind(generation)
      .execute(&mut **tx)
      .await?;
    }
    audit_tx(
      tx,
      namespace,
      actor,
      "rollback",
      checkpoint.target_kind(),
      checkpoint.target_id(),
      "restored",
      None,
    )
    .await
  }
}

async fn finish_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  actor: &IpmActor,
  operation: &str,
  target_kind: &str,
  target_id: &str,
) -> anyhow::Result<()> {
  bump_generation_tx(tx, namespace).await?;
  audit_tx(
    tx,
    namespace,
    actor,
    operation,
    target_kind,
    target_id,
    "applied",
    None,
  )
  .await
}

fn result(
  target_kind: &'static str,
  target_id: String,
  one_time_token: Option<Zeroizing<String>>,
  checkpoint: IpmMutationCheckpoint,
) -> anyhow::Result<IpmTransactionalMutationResult> {
  Ok(IpmTransactionalMutationResult {
    target_kind,
    target_id,
    one_time_token,
    winner_credential: None,
    checkpoint,
  })
}

async fn load_redacted_credential_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  id: &str,
) -> anyhow::Result<RedactedIpmCredential> {
  let row = sqlx::query(
    "SELECT credential_id,principal_id,enabled,revoked,expires_at::text AS expires_at,
            token_prefix,previous_token_prefix,
            previous_token_overlap_until::text AS previous_token_overlap_until
       FROM oxibelt_ipm_credentials WHERE namespace=$1 AND credential_id=$2",
  )
  .bind(namespace)
  .bind(id)
  .fetch_one(&mut **tx)
  .await?;
  Ok(RedactedIpmCredential {
    name: row.try_get("credential_id")?,
    principal: row.try_get("principal_id")?,
    source: IpmEntrySource::Store,
    enabled: row.try_get("enabled")?,
    revoked: row.try_get("revoked")?,
    bearer_token_env: String::new(),
    break_glass_access: false,
    expires_at: row.try_get("expires_at")?,
    token_prefix: row.try_get("token_prefix")?,
    previous_token_prefix: row.try_get("previous_token_prefix")?,
    previous_token_overlap_until: row.try_get("previous_token_overlap_until")?,
  })
}

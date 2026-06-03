//! Admin-facing IPM read and mutation methods.
//! Store mutations refresh snapshots so authorization observes committed state.

use anyhow::{Context, bail};

use crate::config::{IpmPolicyConfig, validate_runtime_identifier};

use super::admin_references::*;
use super::admin_support::*;
use super::admin_types::*;
use super::{IpmActor, IpmRuntime, RedactedIpmCredential, RedactedIpmPolicy, token};

impl IpmRuntime {
  pub fn admin_status(&self) -> IpmAdminStatus {
    let snapshot = self.snapshot();
    let refresh = self
      .inner
      .last_refresh
      .read()
      .expect("IPM refresh state lock poisoned")
      .clone();
    IpmAdminStatus {
      enabled: true,
      store_enabled: self.inner.store.is_some(),
      namespace: self.inner.namespace.clone(),
      generation: snapshot.generation,
      etag: ipm_etag(snapshot.generation, snapshot.fingerprint),
      counts: snapshot.counts.clone(),
      last_refresh: IpmAdminRefreshStatus {
        ok: refresh.ok,
        generation: refresh.generation,
        error: refresh.error,
      },
    }
  }

  pub fn check_if_match(&self, if_match: Option<&str>) -> Result<(), IpmPreconditionError> {
    let expected = self.admin_status().etag;
    match if_match {
      Some(value) if value == expected => Ok(()),
      Some(_) => Err(IpmPreconditionError::Stale),
      None => Err(IpmPreconditionError::Missing),
    }
  }

  pub fn admin_list_principals(&self) -> Vec<IpmPrincipalRecord> {
    let snapshot = self.snapshot();
    let mut principals = snapshot
      .principals
      .values()
      .map(|principal| IpmPrincipalRecord {
        id: principal.actor.principal.clone(),
        subject: principal.actor.subject.clone(),
        groups: principal.actor.groups.clone(),
        enabled: principal.enabled,
        source: principal.source,
      })
      .collect::<Vec<_>>();
    principals.sort_by(|left, right| left.id.cmp(&right.id));
    principals
  }

  pub fn admin_get_principal(&self, id: &str) -> Option<IpmPrincipalRecord> {
    self
      .admin_list_principals()
      .into_iter()
      .find(|principal| principal.id == id)
  }

  pub fn admin_get_credential(&self, id: &str) -> Option<RedactedIpmCredential> {
    self
      .list_credentials()
      .into_iter()
      .find(|credential| credential.name == id)
  }

  pub fn admin_get_policy(&self, id: &str) -> Option<RedactedIpmPolicy> {
    self
      .list_policies()
      .into_iter()
      .find(|policy| policy.name == id)
  }

  pub async fn admin_create_principal(
    &self,
    actor: &IpmActor,
    input: IpmPrincipalCreate,
  ) -> anyhow::Result<IpmPrincipalRecord> {
    let store = self.admin_store()?;
    let result = async {
      validate_runtime_identifier("ipm principal id", &input.id)?;
      validate_non_empty("ipm principal subject", &input.subject)?;
      validate_groups(&input.groups)?;
      self.ensure_actor_may_create_principal(actor, &input.id, &input.subject, &input.groups)?;
      ensure_not_static_principal(self, &input.id)?;
      let mut tx = begin_ipm_write(&store).await?;
      sqlx::query(
        "INSERT INTO oxibelt_ipm_principals
           (namespace, principal_id, subject, groups, enabled)
         VALUES ($1, $2, $3, $4, $5)",
      )
      .bind(store.namespace())
      .bind(&input.id)
      .bind(&input.subject)
      .bind(&input.groups)
      .bind(input.enabled.unwrap_or(true))
      .execute(&mut *tx)
      .await?;
      bump_generation_tx(&mut tx, store.namespace()).await?;
      audit_tx(
        &mut tx,
        store.namespace(),
        actor,
        "create",
        "principal",
        &input.id,
        "applied",
        None,
      )
      .await?;
      tx.commit().await?;
      Ok(())
    }
    .await;
    self
      .finish_mutation_audit(actor, "create", "principal", &input.id, result)
      .await?;
    self
      .admin_get_principal(&input.id)
      .context("created IPM principal disappeared")
  }

  pub async fn admin_patch_principal(
    &self,
    actor: &IpmActor,
    id: &str,
    input: IpmPrincipalPatch,
  ) -> anyhow::Result<IpmPrincipalRecord> {
    let store = self.admin_store()?;
    let id = id.to_string();
    let result = async {
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
      let mut tx = begin_ipm_write(&store).await?;
      sqlx::query(
        "UPDATE oxibelt_ipm_principals
            SET subject = COALESCE($3, subject),
                groups = COALESCE($4, groups),
                enabled = COALESCE($5, enabled),
                updated_at = now()
          WHERE namespace = $1 AND principal_id = $2",
      )
      .bind(store.namespace())
      .bind(&id)
      .bind(&input.subject)
      .bind(&input.groups)
      .bind(input.enabled)
      .execute(&mut *tx)
      .await?;
      bump_generation_tx(&mut tx, store.namespace()).await?;
      audit_tx(
        &mut tx,
        store.namespace(),
        actor,
        "patch",
        "principal",
        &id,
        "applied",
        None,
      )
      .await?;
      tx.commit().await?;
      Ok(())
    }
    .await;
    self
      .finish_mutation_audit(actor, "patch", "principal", &id, result)
      .await?;
    self
      .admin_get_principal(&id)
      .context("patched IPM principal disappeared")
  }

  pub async fn admin_delete_principal(&self, actor: &IpmActor, id: &str) -> anyhow::Result<()> {
    let store = self.admin_store()?;
    let id = id.to_string();
    let result = async {
      ensure_store_principal(self, &id)?;
      self.ensure_not_last_admin_principal(&id)?;
      ensure_principal_unreferenced(&store, &id).await?;
      let mut tx = begin_ipm_write(&store).await?;
      sqlx::query("DELETE FROM oxibelt_ipm_principals WHERE namespace = $1 AND principal_id = $2")
        .bind(store.namespace())
        .bind(&id)
        .execute(&mut *tx)
        .await?;
      bump_generation_tx(&mut tx, store.namespace()).await?;
      audit_tx(
        &mut tx,
        store.namespace(),
        actor,
        "delete",
        "principal",
        &id,
        "applied",
        None,
      )
      .await?;
      tx.commit().await?;
      Ok(())
    }
    .await;
    self
      .finish_mutation_audit(actor, "delete", "principal", &id, result)
      .await
  }

  pub async fn admin_create_credential(
    &self,
    actor: &IpmActor,
    input: IpmCredentialCreate,
  ) -> anyhow::Result<IpmCredentialCreateResponse> {
    let store = self.admin_store()?;
    let generated = token::generate_token()?;
    let result = async {
      validate_runtime_identifier("ipm credential id", &input.id)?;
      validate_runtime_identifier("ipm credential principal", &input.principal)?;
      token::require_expiry(input.ttl_seconds, &input.expires_at, input.no_expiry)?;
      ensure_not_static_credential(self, &input.id)?;
      ensure_principal_exists(self, &input.principal)?;
      self.ensure_actor_may_assign_credential_principal(actor, None, &input.principal)?;
      let mut tx = begin_ipm_write(&store).await?;
      sqlx::query(
        "INSERT INTO oxibelt_ipm_credentials
           (namespace, credential_id, principal_id, subject, token_prefix, token_hash,
            token_hash_alg, enabled, revoked, expires_at, created_by)
         VALUES
           ($1, $2, $3, $3, $4, $5, $6, true, false,
            CASE
              WHEN $7::bigint IS NOT NULL THEN now() + ($7::bigint * interval '1 second')
              WHEN $8::text IS NOT NULL THEN $8::timestamptz
              ELSE NULL
            END,
            $9)",
      )
      .bind(store.namespace())
      .bind(&input.id)
      .bind(&input.principal)
      .bind(&generated.prefix)
      .bind(&generated.hash)
      .bind(token::TOKEN_HASH_ALG)
      .bind(input.ttl_seconds)
      .bind(&input.expires_at)
      .bind(&actor.name)
      .execute(&mut *tx)
      .await?;
      bump_generation_tx(&mut tx, store.namespace()).await?;
      audit_tx(
        &mut tx,
        store.namespace(),
        actor,
        "create",
        "credential",
        &input.id,
        "applied",
        None,
      )
      .await?;
      tx.commit().await?;
      Ok(())
    }
    .await;
    self
      .finish_mutation_audit(actor, "create", "credential", &input.id, result)
      .await?;
    let credential = self
      .admin_get_credential(&input.id)
      .context("created IPM credential disappeared")?;
    Ok(IpmCredentialCreateResponse {
      credential,
      token: generated.token,
    })
  }

  pub async fn admin_patch_credential(
    &self,
    actor: &IpmActor,
    id: &str,
    input: IpmCredentialPatch,
  ) -> anyhow::Result<RedactedIpmCredential> {
    let store = self.admin_store()?;
    let id = id.to_string();
    let result = async {
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
      let mut tx = begin_ipm_write(&store).await?;
      sqlx::query(
        "UPDATE oxibelt_ipm_credentials
            SET principal_id = COALESCE($3, principal_id),
                subject = COALESCE($3, subject),
                enabled = COALESCE($4, enabled),
                expires_at = CASE
                  WHEN $5::bigint IS NOT NULL THEN now() + ($5::bigint * interval '1 second')
                  WHEN $6::text IS NOT NULL THEN $6::timestamptz
                  ELSE expires_at
                END,
                updated_at = now()
          WHERE namespace = $1 AND credential_id = $2",
      )
      .bind(store.namespace())
      .bind(&id)
      .bind(&input.principal)
      .bind(input.enabled)
      .bind(input.ttl_seconds)
      .bind(&input.expires_at)
      .execute(&mut *tx)
      .await?;
      bump_generation_tx(&mut tx, store.namespace()).await?;
      audit_tx(
        &mut tx,
        store.namespace(),
        actor,
        "patch",
        "credential",
        &id,
        "applied",
        None,
      )
      .await?;
      tx.commit().await?;
      Ok(())
    }
    .await;
    self
      .finish_mutation_audit(actor, "patch", "credential", &id, result)
      .await?;
    self
      .admin_get_credential(&id)
      .context("patched IPM credential disappeared")
  }

  pub async fn admin_rotate_credential(
    &self,
    actor: &IpmActor,
    id: &str,
    input: IpmCredentialRotate,
  ) -> anyhow::Result<IpmCredentialRotateResponse> {
    let store = self.admin_store()?;
    let id = id.to_string();
    let generated = token::generate_token()?;
    let result = async {
      ensure_store_credential(self, &id)?;
      if input.overlap_seconds <= 0 {
        bail!("overlap_seconds must be greater than 0");
      }
      token::require_expiry(input.ttl_seconds, &input.expires_at, input.no_expiry)?;
      let mut tx = begin_ipm_write(&store).await?;
      sqlx::query(
        "UPDATE oxibelt_ipm_credentials
            SET previous_token_prefix = token_prefix,
                previous_token_hash = token_hash,
                previous_token_overlap_until = now() + ($3::bigint * interval '1 second'),
                token_prefix = $4,
                token_hash = $5,
                token_hash_alg = $6,
                revoked = false,
                revoked_at = NULL,
                revoked_by = NULL,
                revoke_reason = NULL,
                expires_at = CASE
                  WHEN $7::bigint IS NOT NULL THEN now() + ($7::bigint * interval '1 second')
                  WHEN $8::text IS NOT NULL THEN $8::timestamptz
                  ELSE NULL
                END,
                updated_at = now()
          WHERE namespace = $1 AND credential_id = $2",
      )
      .bind(store.namespace())
      .bind(&id)
      .bind(input.overlap_seconds)
      .bind(&generated.prefix)
      .bind(&generated.hash)
      .bind(token::TOKEN_HASH_ALG)
      .bind(input.ttl_seconds)
      .bind(&input.expires_at)
      .execute(&mut *tx)
      .await?;
      bump_generation_tx(&mut tx, store.namespace()).await?;
      audit_tx(
        &mut tx,
        store.namespace(),
        actor,
        "rotate",
        "credential",
        &id,
        "applied",
        None,
      )
      .await?;
      tx.commit().await?;
      Ok(())
    }
    .await;
    self
      .finish_mutation_audit(actor, "rotate", "credential", &id, result)
      .await?;
    let credential = self
      .admin_get_credential(&id)
      .context("rotated IPM credential disappeared")?;
    Ok(IpmCredentialRotateResponse {
      credential,
      token: generated.token,
    })
  }

  pub async fn admin_revoke_credential(
    &self,
    actor: &IpmActor,
    id: &str,
    input: IpmCredentialRevoke,
  ) -> anyhow::Result<RedactedIpmCredential> {
    let store = self.admin_store()?;
    let id = id.to_string();
    let result = async {
      ensure_store_credential(self, &id)?;
      self.ensure_not_last_admin_credential(&id)?;
      let mut tx = begin_ipm_write(&store).await?;
      sqlx::query(
        "UPDATE oxibelt_ipm_credentials
            SET revoked = true,
                revoked_at = now(),
                revoked_by = $3,
                revoke_reason = $4,
                previous_token_prefix = NULL,
                previous_token_hash = NULL,
                previous_token_overlap_until = NULL,
                updated_at = now()
          WHERE namespace = $1 AND credential_id = $2",
      )
      .bind(store.namespace())
      .bind(&id)
      .bind(&actor.name)
      .bind(&input.reason)
      .execute(&mut *tx)
      .await?;
      bump_generation_tx(&mut tx, store.namespace()).await?;
      audit_tx(
        &mut tx,
        store.namespace(),
        actor,
        "revoke",
        "credential",
        &id,
        "applied",
        None,
      )
      .await?;
      tx.commit().await?;
      Ok(())
    }
    .await;
    self
      .finish_mutation_audit(actor, "revoke", "credential", &id, result)
      .await?;
    self
      .admin_get_credential(&id)
      .context("revoked IPM credential disappeared")
  }

  pub async fn admin_delete_credential(&self, actor: &IpmActor, id: &str) -> anyhow::Result<()> {
    let store = self.admin_store()?;
    let id = id.to_string();
    let result = async {
      ensure_store_credential(self, &id)?;
      self.ensure_not_last_admin_credential(&id)?;
      let mut tx = begin_ipm_write(&store).await?;
      sqlx::query(
        "DELETE FROM oxibelt_ipm_credentials WHERE namespace = $1 AND credential_id = $2",
      )
      .bind(store.namespace())
      .bind(&id)
      .execute(&mut *tx)
      .await?;
      bump_generation_tx(&mut tx, store.namespace()).await?;
      audit_tx(
        &mut tx,
        store.namespace(),
        actor,
        "delete",
        "credential",
        &id,
        "applied",
        None,
      )
      .await?;
      tx.commit().await?;
      Ok(())
    }
    .await;
    self
      .finish_mutation_audit(actor, "delete", "credential", &id, result)
      .await
  }

  pub async fn admin_create_policy(
    &self,
    actor: &IpmActor,
    input: IpmPolicyCreate,
  ) -> anyhow::Result<RedactedIpmPolicy> {
    let store = self.admin_store()?;
    let result = async {
      let policy = input.policy()?;
      ensure_not_static_policy(self, &policy.name)?;
      self.ensure_actor_may_create_policy(actor, &policy)?;
      let document = serde_json::to_string(&policy)?;
      let mut tx = begin_ipm_write(&store).await?;
      sqlx::query(
        "INSERT INTO oxibelt_ipm_policies (namespace, policy_id, document, enabled)
         VALUES ($1, $2, $3::jsonb, $4)",
      )
      .bind(store.namespace())
      .bind(&policy.name)
      .bind(document)
      .bind(input.enabled.unwrap_or(true))
      .execute(&mut *tx)
      .await?;
      bump_generation_tx(&mut tx, store.namespace()).await?;
      audit_tx(
        &mut tx,
        store.namespace(),
        actor,
        "create",
        "policy",
        &policy.name,
        "applied",
        None,
      )
      .await?;
      tx.commit().await?;
      Ok(policy.name)
    }
    .await;
    let name = self
      .finish_mutation_audit_value(actor, "create", "policy", &input.name, result)
      .await?;
    self
      .admin_get_policy(&name)
      .context("created IPM policy disappeared")
  }

  pub async fn admin_patch_policy(
    &self,
    actor: &IpmActor,
    id: &str,
    input: IpmPolicyPatch,
  ) -> anyhow::Result<RedactedIpmPolicy> {
    let store = self.admin_store()?;
    let id = id.to_string();
    let result = async {
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
      let mut tx = begin_ipm_write(&store).await?;
      sqlx::query(
        "UPDATE oxibelt_ipm_policies
            SET document = $3::jsonb,
                enabled = COALESCE($4, enabled),
                updated_at = now()
          WHERE namespace = $1 AND policy_id = $2",
      )
      .bind(store.namespace())
      .bind(&id)
      .bind(document)
      .bind(input.enabled)
      .execute(&mut *tx)
      .await?;
      bump_generation_tx(&mut tx, store.namespace()).await?;
      audit_tx(
        &mut tx,
        store.namespace(),
        actor,
        "patch",
        "policy",
        &id,
        "applied",
        None,
      )
      .await?;
      tx.commit().await?;
      Ok(())
    }
    .await;
    self
      .finish_mutation_audit(actor, "patch", "policy", &id, result)
      .await?;
    self
      .admin_get_policy(&id)
      .context("patched IPM policy disappeared")
  }

  pub async fn admin_delete_policy(&self, actor: &IpmActor, id: &str) -> anyhow::Result<()> {
    let store = self.admin_store()?;
    let id = id.to_string();
    let result = async {
      ensure_store_policy(self, &id)?;
      self.ensure_not_last_admin_policy(&id)?;
      ensure_policy_unreferenced(&store, &id).await?;
      let mut tx = begin_ipm_write(&store).await?;
      sqlx::query("DELETE FROM oxibelt_ipm_policies WHERE namespace = $1 AND policy_id = $2")
        .bind(store.namespace())
        .bind(&id)
        .execute(&mut *tx)
        .await?;
      bump_generation_tx(&mut tx, store.namespace()).await?;
      audit_tx(
        &mut tx,
        store.namespace(),
        actor,
        "delete",
        "policy",
        &id,
        "applied",
        None,
      )
      .await?;
      tx.commit().await?;
      Ok(())
    }
    .await;
    self
      .finish_mutation_audit(actor, "delete", "policy", &id, result)
      .await
  }
}

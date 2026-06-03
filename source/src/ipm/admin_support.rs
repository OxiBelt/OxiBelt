//! Admin helpers for IPM mutation, audit, and bootstrap authority.

use anyhow::{Context, bail};
use sqlx::{Postgres, Row, Transaction};

use crate::config::{
  IpmPolicyConfig, IpmPolicyEffect, IpmPolicyStatementConfig, validate_ipm_statement,
  validate_runtime_identifier,
};

use super::admin_types::{IpmAuditQuery, IpmAuditRecord, IpmBindingCreate, IpmPolicyCreate};
use super::{
  IpmActor, IpmCredentialRuntime, IpmDecision, IpmEntrySource, IpmRequestContext, IpmRuntime,
  RedactedIpmPolicy, now_unix, resource,
};

const ADMIN_GROUP: &str = "ipm-admin";
const ADMIN_MARKER_ACTIONS: &[&str] = &["admin:UpdateConfig", "ipm:UpdateConfig"];
const ADMIN_GRANT_ACTIONS: &[&str] = &[
  "admin:UpdateConfig",
  "ipm:UpdateConfig",
  "ipm:CreatePrincipal",
  "ipm:UpdatePrincipal",
  "ipm:DeletePrincipal",
  "ipm:CreateCredential",
  "ipm:UpdateCredential",
  "ipm:RotateCredential",
  "ipm:RevokeCredential",
  "ipm:DeleteCredential",
  "ipm:CreatePolicy",
  "ipm:UpdatePolicy",
  "ipm:DeletePolicy",
  "ipm:CreateBinding",
  "ipm:DeleteBinding",
];

fn admin_authority_resource(namespace: &str, action: &str) -> String {
  match action {
    "admin:UpdateConfig" => resource(namespace, "admin", "config"),
    _ => resource(namespace, "ipm", "config"),
  }
}

impl IpmRuntime {
  pub(crate) fn admin_store(&self) -> anyhow::Result<super::store::IpmStore> {
    self
      .inner
      .store
      .clone()
      .context("IPM store is not configured")
  }

  pub async fn admin_audit(&self, query: IpmAuditQuery) -> anyhow::Result<Vec<IpmAuditRecord>> {
    let store = self.admin_store()?;
    select_audit(&store, query).await
  }

  pub(crate) async fn finish_mutation_audit(
    &self,
    actor: &IpmActor,
    operation: &'static str,
    target_kind: &'static str,
    target_id: &str,
    result: anyhow::Result<()>,
  ) -> anyhow::Result<()> {
    self
      .finish_mutation_audit_value(
        actor,
        operation,
        target_kind,
        target_id,
        result.map(|_| target_id.to_string()),
      )
      .await
      .map(|_| ())
  }

  pub(crate) async fn finish_mutation_audit_value<T: AsRef<str>>(
    &self,
    actor: &IpmActor,
    operation: &'static str,
    target_kind: &'static str,
    target_id: &str,
    result: anyhow::Result<T>,
  ) -> anyhow::Result<T> {
    match result {
      Ok(value) => {
        self.refresh_store().await?;
        Ok(value)
      }
      Err(error) => {
        if let Some(store) = &self.inner.store {
          let _ = audit(
            store,
            actor,
            operation,
            target_kind,
            target_id,
            "rejected",
            Some(&error.to_string()),
          )
          .await;
        }
        Err(error)
      }
    }
  }

  fn admin_regular_credentials(&self) -> Vec<IpmCredentialRuntime> {
    let snapshot = self.snapshot();
    let now = now_unix().ok();
    snapshot
      .credentials
      .iter()
      .filter(|credential| {
        credential.break_glass_access_token_hash.is_none()
          && credential.is_active_at(now)
          && snapshot
            .principals
            .get(&credential.principal)
            .is_some_and(|principal| principal.enabled)
      })
      .cloned()
      .collect()
  }

  fn admin_capable_regular_credentials(&self) -> Vec<IpmCredentialRuntime> {
    let snapshot = self.snapshot();
    self
      .admin_regular_credentials()
      .into_iter()
      .filter(|credential| {
        snapshot
          .principals
          .get(&credential.principal)
          .is_some_and(|principal| {
            let mut actor = principal.actor.clone();
            actor.name = credential.name.clone();
            self.actor_has_admin_authority(&actor)
          })
      })
      .collect()
  }

  pub(crate) fn ensure_not_last_admin_credential(&self, id: &str) -> anyhow::Result<()> {
    let admins = self.admin_capable_regular_credentials();
    if admins.len() <= 1 && admins.iter().any(|credential| credential.name == id) {
      bail!("cannot remove or disable the last admin-capable regular IPM credential");
    }
    Ok(())
  }

  pub(crate) fn ensure_not_last_admin_principal(&self, id: &str) -> anyhow::Result<()> {
    let admins = self.admin_capable_regular_credentials();
    if admins.len() <= 1 && admins.iter().any(|credential| credential.principal == id) {
      bail!(
        "cannot remove or disable the principal for the last admin-capable regular IPM credential"
      );
    }
    Ok(())
  }

  pub(crate) fn ensure_not_last_admin_policy(&self, policy_id: &str) -> anyhow::Result<()> {
    let admins = self.admin_capable_regular_credentials();
    if admins.len() <= 1 && policy_is_bound_to_admin(self, policy_id, &admins) {
      bail!(
        "cannot remove or disable policy used by the last admin-capable regular IPM credential"
      );
    }
    Ok(())
  }

  pub(crate) fn ensure_not_last_admin_binding(&self, binding_id: &str) -> anyhow::Result<()> {
    let snapshot = self.snapshot();
    let Some(binding) = snapshot
      .bindings
      .iter()
      .find(|binding| binding.id == binding_id)
    else {
      return Ok(());
    };
    let admins = self.admin_capable_regular_credentials();
    if admins.len() <= 1 && binding_is_used_by_admin(self, binding, &admins) {
      bail!("cannot remove binding used by the last admin-capable regular IPM credential");
    }
    Ok(())
  }

  pub(crate) fn ensure_actor_may_create_principal(
    &self,
    actor: &IpmActor,
    id: &str,
    subject: &str,
    groups: &[String],
  ) -> anyhow::Result<()> {
    let candidate = IpmActor {
      name: id.to_string(),
      principal: id.to_string(),
      subject: subject.to_string(),
      groups: groups.to_vec(),
    };
    if self.actor_has_admin_authority(&candidate) {
      self.ensure_actor_can_grant_admin(actor, "create admin-capable IPM principal")?;
    }
    Ok(())
  }

  pub(crate) fn ensure_actor_may_patch_principal(
    &self,
    actor: &IpmActor,
    id: &str,
    subject: Option<&str>,
    groups: Option<&[String]>,
  ) -> anyhow::Result<()> {
    if subject.is_none() && groups.is_none() {
      return Ok(());
    }
    let snapshot = self.snapshot();
    let current = snapshot
      .principals
      .get(id)
      .ok_or_else(|| anyhow::anyhow!("unknown IPM principal {id}"))?;
    let current_admin = self.actor_has_admin_authority(&current.actor);
    let mut candidate = current.actor.clone();
    if let Some(subject) = subject {
      candidate.subject = subject.to_string();
    }
    if let Some(groups) = groups {
      candidate.groups = groups.to_vec();
    }
    let candidate_admin = self.actor_has_admin_authority(&candidate);
    if candidate_admin {
      self.ensure_actor_can_grant_admin(actor, "grant admin-capable IPM principal attributes")?;
    }
    if current_admin && !candidate_admin {
      self.ensure_not_last_admin_principal(id)?;
    }
    Ok(())
  }

  pub(crate) fn ensure_actor_may_assign_credential_principal(
    &self,
    actor: &IpmActor,
    credential_id: Option<&str>,
    principal: &str,
  ) -> anyhow::Result<()> {
    if self.principal_has_admin_authority(principal)? {
      self
        .ensure_actor_can_grant_admin(actor, "assign credential to admin-capable IPM principal")?;
    }
    if let Some(credential_id) = credential_id
      && let Some(current) = self
        .snapshot()
        .credentials
        .iter()
        .find(|credential| credential.name == credential_id)
      && self.principal_has_admin_authority(&current.principal)?
      && current.principal != principal
    {
      self
        .ensure_actor_can_grant_admin(actor, "move credential from admin-capable IPM principal")?;
    }
    Ok(())
  }

  pub(crate) fn ensure_actor_may_create_policy(
    &self,
    actor: &IpmActor,
    policy: &IpmPolicyConfig,
  ) -> anyhow::Result<()> {
    if policy_grants_admin_authority(policy) {
      self.ensure_actor_can_grant_admin(actor, "create admin-capable IPM policy")?;
    }
    Ok(())
  }

  pub(crate) fn ensure_actor_may_patch_policy(
    &self,
    actor: &IpmActor,
    current: &RedactedIpmPolicy,
    next: &IpmPolicyConfig,
  ) -> anyhow::Result<()> {
    let current_policy = IpmPolicyConfig {
      name: current.name.clone(),
      version: current.version.clone(),
      statements: current.statements.clone(),
    };
    let current_admin = policy_grants_admin_authority(&current_policy);
    let next_admin = policy_grants_admin_authority(next);
    if current_admin || next_admin {
      self.ensure_actor_can_grant_admin(actor, "mutate admin-capable IPM policy")?;
    }
    if current_admin && !next_admin {
      self.ensure_not_last_admin_policy(&current.name)?;
    }
    Ok(())
  }

  pub(crate) fn ensure_actor_may_create_binding(
    &self,
    actor: &IpmActor,
    input: &IpmBindingCreate,
  ) -> anyhow::Result<()> {
    if let Some(principal) = &input.principal
      && self.principal_has_admin_authority(principal)?
    {
      self.ensure_actor_can_grant_admin(actor, "bind policy to admin-capable IPM principal")?;
    }
    if let Some(group) = &input.group {
      ensure_group_exists(self, group)?;
      if self.group_has_admin_authority(group) {
        self.ensure_actor_can_grant_admin(actor, "bind policy to admin-capable IPM group")?;
      }
    }
    let snapshot = self.snapshot();
    let policy = snapshot
      .policies
      .get(&input.policy)
      .ok_or_else(|| anyhow::anyhow!("unknown IPM policy {}", input.policy))?;
    if policy_grants_admin_authority(&policy.policy) {
      self.ensure_actor_can_grant_admin(actor, "bind admin-capable IPM policy")?;
    }
    Ok(())
  }

  pub(crate) fn actor_has_admin_authority(&self, actor: &IpmActor) -> bool {
    if actor.groups.iter().any(|group| group == ADMIN_GROUP) {
      return true;
    }
    if ADMIN_MARKER_ACTIONS.iter().any(|action| {
      self.authorize(
        actor,
        action,
        &admin_authority_resource(self.namespace(), action),
        &IpmRequestContext::default(),
      ) == IpmDecision::Allow
    }) {
      return true;
    }
    ADMIN_GRANT_ACTIONS.iter().all(|action| {
      self.authorize(
        actor,
        action,
        &admin_authority_resource(self.namespace(), action),
        &IpmRequestContext::default(),
      ) == IpmDecision::Allow
    })
  }

  fn ensure_actor_can_grant_admin(&self, actor: &IpmActor, operation: &str) -> anyhow::Result<()> {
    if self.actor_has_admin_authority(actor) {
      Ok(())
    } else {
      bail!("{operation} requires an admin-capable IPM actor");
    }
  }

  fn principal_has_admin_authority(&self, principal: &str) -> anyhow::Result<bool> {
    let snapshot = self.snapshot();
    let principal = snapshot
      .principals
      .get(principal)
      .ok_or_else(|| anyhow::anyhow!("unknown IPM principal {principal}"))?;
    Ok(self.actor_has_admin_authority(&principal.actor))
  }

  fn group_has_admin_authority(&self, group: &str) -> bool {
    if group == ADMIN_GROUP {
      return true;
    }
    let actor = IpmActor {
      name: "ipm-group-check".to_string(),
      principal: "ipm-group-check".to_string(),
      subject: "ipm-group-check".to_string(),
      groups: vec![group.to_string()],
    };
    self.actor_has_admin_authority(&actor)
  }
}

impl IpmPolicyCreate {
  pub(super) fn policy(&self) -> anyhow::Result<IpmPolicyConfig> {
    let policy = IpmPolicyConfig {
      name: self.name.clone(),
      version: self.version.clone(),
      statements: self.statements.clone(),
    };
    validate_policy(&policy)?;
    Ok(policy)
  }
}

pub(super) fn ipm_etag(generation: i64, fingerprint: u64) -> String {
  format!("\"oxibelt-ipm-{generation}-{fingerprint:x}\"")
}

pub(super) fn validate_policy(policy: &IpmPolicyConfig) -> anyhow::Result<()> {
  validate_runtime_identifier("ipm policy name", &policy.name)?;
  validate_non_empty("ipm policy version", &policy.version)?;
  if policy.statements.is_empty() {
    bail!(
      "ipm policy {} must include at least one statement",
      policy.name
    );
  }
  for statement in &policy.statements {
    validate_ipm_statement(&policy.name, statement)?;
  }
  Ok(())
}

pub(super) fn validate_groups(groups: &[String]) -> anyhow::Result<()> {
  for group in groups {
    validate_runtime_identifier("ipm principal group", group)?;
  }
  Ok(())
}

pub(super) fn validate_non_empty(field: &str, value: &str) -> anyhow::Result<()> {
  if value.trim().is_empty() {
    bail!("{field} must not be empty");
  }
  Ok(())
}

pub(super) fn validate_binding(input: &IpmBindingCreate) -> anyhow::Result<()> {
  if input.principal.is_some() == input.group.is_some() {
    bail!("ipm binding must set exactly one of principal or group");
  }
  if let Some(principal) = &input.principal {
    validate_runtime_identifier("ipm binding principal", principal)?;
  }
  if let Some(group) = &input.group {
    validate_runtime_identifier("ipm binding group", group)?;
  }
  validate_runtime_identifier("ipm binding policy", &input.policy)
}

pub(super) fn ensure_group_exists(runtime: &IpmRuntime, group: &str) -> anyhow::Result<()> {
  if runtime.snapshot().principals.values().any(|principal| {
    principal
      .actor
      .groups
      .iter()
      .any(|candidate| candidate == group)
  }) {
    Ok(())
  } else {
    bail!("unknown IPM group {group}")
  }
}

pub(super) fn policy_grants_admin_authority(policy: &IpmPolicyConfig) -> bool {
  policy
    .statements
    .iter()
    .any(statement_grants_admin_authority)
}

fn statement_grants_admin_authority(statement: &IpmPolicyStatementConfig) -> bool {
  statement.effect == IpmPolicyEffect::Allow
    && statement
      .actions
      .iter()
      .any(|action| action_grants_admin_authority(action))
}

fn action_grants_admin_authority(action: &str) -> bool {
  action == "*" || action == "admin:*" || action == "ipm:*" || ADMIN_GRANT_ACTIONS.contains(&action)
}

pub(super) fn generated_binding_id(
  principal: Option<&str>,
  group: Option<&str>,
  policy: &str,
) -> String {
  match (principal, group) {
    (Some(principal), None) => format!("principal.{principal}.{policy}"),
    (None, Some(group)) => format!("group.{group}.{policy}"),
    _ => format!("binding.{policy}"),
  }
}

pub(super) fn ensure_not_static_principal(runtime: &IpmRuntime, id: &str) -> anyhow::Result<()> {
  if runtime
    .snapshot()
    .principals
    .get(id)
    .is_some_and(|principal| principal.source == IpmEntrySource::Config)
  {
    bail!("static TOML principal {id} is read-only");
  }
  Ok(())
}

pub(super) fn ensure_store_principal(runtime: &IpmRuntime, id: &str) -> anyhow::Result<()> {
  match runtime.snapshot().principals.get(id) {
    Some(principal) if principal.source == IpmEntrySource::Store => Ok(()),
    Some(_) => bail!("static TOML principal {id} is read-only"),
    None => bail!("unknown IPM principal {id}"),
  }
}

pub(super) fn ensure_not_static_credential(runtime: &IpmRuntime, id: &str) -> anyhow::Result<()> {
  if runtime
    .snapshot()
    .credentials
    .iter()
    .any(|credential| credential.name == id && credential.source == IpmEntrySource::Config)
  {
    bail!("static TOML credential {id} is read-only");
  }
  Ok(())
}

pub(super) fn ensure_store_credential(runtime: &IpmRuntime, id: &str) -> anyhow::Result<()> {
  match runtime
    .snapshot()
    .credentials
    .iter()
    .find(|credential| credential.name == id)
  {
    Some(credential) if credential.source == IpmEntrySource::Store => Ok(()),
    Some(_) => bail!("static TOML credential {id} is read-only"),
    None => bail!("unknown IPM credential {id}"),
  }
}

pub(super) fn ensure_not_static_policy(runtime: &IpmRuntime, id: &str) -> anyhow::Result<()> {
  if runtime
    .snapshot()
    .policies
    .get(id)
    .is_some_and(|policy| policy.source == IpmEntrySource::Config)
  {
    bail!("static TOML policy {id} is read-only");
  }
  Ok(())
}

pub(super) fn ensure_store_policy(
  runtime: &IpmRuntime,
  id: &str,
) -> anyhow::Result<RedactedIpmPolicy> {
  match runtime.admin_get_policy(id) {
    Some(policy) if policy.source == IpmEntrySource::Store => Ok(policy),
    Some(_) => bail!("static TOML policy {id} is read-only"),
    None => bail!("unknown IPM policy {id}"),
  }
}

pub(super) fn ensure_store_binding(runtime: &IpmRuntime, id: &str) -> anyhow::Result<()> {
  match runtime
    .list_bindings()
    .into_iter()
    .find(|binding| binding.id == id)
  {
    Some(binding) if binding.source == IpmEntrySource::Store => Ok(()),
    Some(_) => bail!("static TOML binding {id} is read-only"),
    None => bail!("unknown IPM binding {id}"),
  }
}

pub(super) fn ensure_principal_exists(runtime: &IpmRuntime, id: &str) -> anyhow::Result<()> {
  if runtime.snapshot().principals.contains_key(id) {
    Ok(())
  } else {
    bail!("unknown IPM principal {id}")
  }
}

pub(super) fn ensure_policy_exists(runtime: &IpmRuntime, id: &str) -> anyhow::Result<()> {
  if runtime.snapshot().policies.contains_key(id) {
    Ok(())
  } else {
    bail!("unknown IPM policy {id}")
  }
}

fn policy_is_bound_to_admin(
  runtime: &IpmRuntime,
  policy_id: &str,
  admins: &[IpmCredentialRuntime],
) -> bool {
  runtime.snapshot().bindings.iter().any(|binding| {
    binding.policy == policy_id && binding_is_used_by_admin(runtime, binding, admins)
  })
}

fn binding_is_used_by_admin(
  runtime: &IpmRuntime,
  binding: &super::IpmBindingRuntime,
  admins: &[IpmCredentialRuntime],
) -> bool {
  let snapshot = runtime.snapshot();
  admins.iter().any(|credential| {
    binding.principal.as_deref() == Some(credential.principal.as_str())
      || binding.group.as_ref().is_some_and(|group| {
        snapshot
          .principals
          .get(&credential.principal)
          .is_some_and(|principal| principal.actor.groups.contains(group))
      })
  })
}

pub(super) async fn begin_ipm_write(
  store: &super::store::IpmStore,
) -> anyhow::Result<Transaction<'static, Postgres>> {
  let mut tx = store.pool().begin().await?;
  sqlx::query(
    "LOCK TABLE oxibelt_ipm_principals, oxibelt_ipm_credentials,
                oxibelt_ipm_policies, oxibelt_ipm_policy_bindings
       IN SHARE ROW EXCLUSIVE MODE",
  )
  .execute(&mut *tx)
  .await?;
  Ok(tx)
}

pub(super) async fn bump_generation_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
) -> anyhow::Result<()> {
  sqlx::query(
    "INSERT INTO oxibelt_ipm_generation (namespace, generation, updated_at)
     VALUES ($1, 1, now())
     ON CONFLICT (namespace)
     DO UPDATE SET generation = oxibelt_ipm_generation.generation + 1,
                   updated_at = now()",
  )
  .bind(namespace)
  .execute(&mut **tx)
  .await?;
  Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn audit_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  actor: &IpmActor,
  operation: &str,
  target_kind: &str,
  target_id: &str,
  outcome: &str,
  error: Option<&str>,
) -> anyhow::Result<()> {
  sqlx::query(
    "INSERT INTO oxibelt_ipm_audit
       (namespace, actor, operation, target_kind, target_id, resource, outcome, error)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
  )
  .bind(namespace)
  .bind(&actor.name)
  .bind(operation)
  .bind(target_kind)
  .bind(target_id)
  .bind(format!("{target_kind}/{target_id}"))
  .bind(outcome)
  .bind(error)
  .execute(&mut **tx)
  .await?;
  Ok(())
}

async fn audit(
  store: &super::store::IpmStore,
  actor: &IpmActor,
  operation: &str,
  target_kind: &str,
  target_id: &str,
  outcome: &str,
  error: Option<&str>,
) -> anyhow::Result<()> {
  sqlx::query(
    "INSERT INTO oxibelt_ipm_audit
       (namespace, actor, operation, target_kind, target_id, resource, outcome, error)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
  )
  .bind(store.namespace())
  .bind(&actor.name)
  .bind(operation)
  .bind(target_kind)
  .bind(target_id)
  .bind(format!("{target_kind}/{target_id}"))
  .bind(outcome)
  .bind(error)
  .execute(store.pool())
  .await?;
  Ok(())
}

pub(super) async fn select_audit(
  store: &super::store::IpmStore,
  query: IpmAuditQuery,
) -> anyhow::Result<Vec<IpmAuditRecord>> {
  let limit = if query.limit == 0 { 100 } else { query.limit };
  if !(1..=1000).contains(&limit) {
    bail!("limit must be between 1 and 1000");
  }
  let rows = sqlx::query(
    "SELECT id, namespace, actor, operation, target_kind, target_id, resource,
            outcome, error, created_at::text AS created_at
       FROM oxibelt_ipm_audit
      WHERE namespace = $1
        AND ($2::text IS NULL OR target_kind = $2)
        AND ($3::text IS NULL OR target_id = $3)
        AND ($4::text IS NULL OR outcome = $4)
        AND ($5::text IS NULL OR actor = $5)
      ORDER BY id DESC
      LIMIT $6",
  )
  .bind(store.namespace())
  .bind(&query.target_kind)
  .bind(&query.target_id)
  .bind(&query.outcome)
  .bind(&query.actor)
  .bind(limit)
  .fetch_all(store.pool())
  .await?;
  rows
    .iter()
    .map(|row| {
      Ok(IpmAuditRecord {
        id: row.try_get("id")?,
        namespace: row.try_get("namespace")?,
        actor: row.try_get("actor")?,
        operation: row.try_get("operation")?,
        target_kind: row.try_get("target_kind")?,
        target_id: row.try_get("target_id")?,
        resource: row.try_get("resource")?,
        outcome: row.try_get("outcome")?,
        error: row.try_get("error")?,
        created_at: row.try_get("created_at")?,
      })
    })
    .collect()
}

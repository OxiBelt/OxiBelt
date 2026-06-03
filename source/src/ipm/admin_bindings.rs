//! IPM binding mutation helpers.
//! Binding changes are validated against principals and policies before persistence.

use anyhow::Context;

use crate::config::validate_runtime_identifier;

use super::admin_support::*;
use super::admin_types::IpmBindingCreate;
use super::{IpmActor, IpmRuntime, RedactedIpmBinding};

impl IpmRuntime {
  pub async fn admin_create_binding(
    &self,
    actor: &IpmActor,
    input: IpmBindingCreate,
  ) -> anyhow::Result<RedactedIpmBinding> {
    let store = self.admin_store()?;
    let id = input.id.clone().unwrap_or_else(|| {
      generated_binding_id(
        input.principal.as_deref(),
        input.group.as_deref(),
        &input.policy,
      )
    });
    let result = async {
      validate_runtime_identifier("ipm binding id", &id)?;
      validate_binding(&input)?;
      ensure_policy_exists(self, &input.policy)?;
      if let Some(principal) = &input.principal {
        ensure_principal_exists(self, principal)?;
      }
      self.ensure_actor_may_create_binding(actor, &input)?;
      let mut tx = begin_ipm_write(&store).await?;
      sqlx::query(
        "INSERT INTO oxibelt_ipm_policy_bindings
           (namespace, binding_id, principal_id, group_name, policy_id, enabled)
         VALUES ($1, $2, $3, $4, $5, $6)",
      )
      .bind(store.namespace())
      .bind(&id)
      .bind(&input.principal)
      .bind(&input.group)
      .bind(&input.policy)
      .bind(input.enabled.unwrap_or(true))
      .execute(&mut *tx)
      .await?;
      bump_generation_tx(&mut tx, store.namespace()).await?;
      audit_tx(
        &mut tx,
        store.namespace(),
        actor,
        "create",
        "binding",
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
      .finish_mutation_audit(actor, "create", "binding", &id, result)
      .await?;
    self
      .list_bindings()
      .into_iter()
      .find(|binding| binding.id == id)
      .context("created IPM binding disappeared")
  }

  pub async fn admin_delete_binding(&self, actor: &IpmActor, id: &str) -> anyhow::Result<()> {
    let store = self.admin_store()?;
    let id = id.to_string();
    let result = async {
      ensure_store_binding(self, &id)?;
      self.ensure_not_last_admin_binding(&id)?;
      let mut tx = begin_ipm_write(&store).await?;
      sqlx::query(
        "DELETE FROM oxibelt_ipm_policy_bindings WHERE namespace = $1 AND binding_id = $2",
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
        "binding",
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
      .finish_mutation_audit(actor, "delete", "binding", &id, result)
      .await
  }
}

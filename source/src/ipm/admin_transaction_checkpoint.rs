//! Encrypted-checkpoint-safe IPM row before-images and compensating restore.

use std::fmt;

use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Row, Transaction};
use zeroize::Zeroizing;

use crate::config::validate_runtime_identifier;

use super::super::admin_support::generated_binding_id;
use super::IpmAdminMutation;

#[derive(Clone)]
pub(crate) struct IpmMutationCheckpoint {
  table: IpmMutationTable,
  target_id: String,
  prior_row: Option<Zeroizing<Vec<u8>>>,
  pub(super) prior_generation: Option<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for IpmMutationCheckpoint {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("IpmMutationCheckpoint")
      .field("table", &self.table)
      .field("target_id", &self.target_id)
      .field("had_prior_row", &self.prior_row.is_some())
      .field("had_prior_generation", &self.prior_generation.is_some())
      .finish()
  }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum IpmMutationTable {
  Principal,
  Credential,
  Policy,
  Binding,
}

#[derive(Deserialize, Serialize)]
struct IpmMutationCheckpointWire {
  format: String,
  table: IpmMutationTable,
  target_id: String,
  prior_row: Option<serde_json::Value>,
  prior_generation: Option<serde_json::Value>,
}

impl IpmMutationCheckpoint {
  pub(crate) fn encode_plaintext(&self) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let wire = IpmMutationCheckpointWire {
      format: "oxibelt-ipm-mutation-checkpoint-v1".to_string(),
      table: self.table,
      target_id: self.target_id.clone(),
      prior_row: decode_json(&self.prior_row)?,
      prior_generation: decode_json(&self.prior_generation)?,
    };
    Ok(Zeroizing::new(serde_json::to_vec(&wire)?))
  }

  pub(crate) fn decode_plaintext(encoded: &[u8]) -> anyhow::Result<Self> {
    let wire: IpmMutationCheckpointWire = serde_json::from_slice(encoded)?;
    ensure!(
      wire.format == "oxibelt-ipm-mutation-checkpoint-v1",
      "unsupported IPM mutation checkpoint format"
    );
    validate_runtime_identifier("ipm checkpoint target", &wire.target_id)?;
    Ok(Self {
      table: wire.table,
      target_id: wire.target_id,
      prior_row: encode_json(wire.prior_row)?,
      prior_generation: encode_json(wire.prior_generation)?,
    })
  }

  pub(super) fn prior_generation_value(&self) -> anyhow::Result<Option<i64>> {
    decode_json(&self.prior_generation)?.map_or(Ok(None), |value| {
      value
        .get("generation")
        .and_then(serde_json::Value::as_i64)
        .map(Some)
        .context("IPM checkpoint generation is invalid")
    })
  }

  pub(super) fn validate_namespace(&self, namespace: &str) -> anyhow::Result<()> {
    validate_runtime_identifier("ipm checkpoint target", &self.target_id)?;
    for encoded in [&self.prior_row, &self.prior_generation]
      .into_iter()
      .flatten()
    {
      let value: serde_json::Value = serde_json::from_slice(encoded)?;
      ensure!(
        value.get("namespace").and_then(serde_json::Value::as_str) == Some(namespace),
        "IPM checkpoint namespace mismatch"
      );
    }
    if let Some(row) = decode_json(&self.prior_row)? {
      let id_field = match self.table {
        IpmMutationTable::Principal => "principal_id",
        IpmMutationTable::Credential => "credential_id",
        IpmMutationTable::Policy => "policy_id",
        IpmMutationTable::Binding => "binding_id",
      };
      ensure!(
        row.get(id_field).and_then(serde_json::Value::as_str) == Some(&self.target_id),
        "IPM checkpoint target mismatch"
      );
    }
    Ok(())
  }

  pub(super) fn target_kind(&self) -> &'static str {
    match self.table {
      IpmMutationTable::Principal => "principal",
      IpmMutationTable::Credential => "credential",
      IpmMutationTable::Policy => "policy",
      IpmMutationTable::Binding => "binding",
    }
  }

  pub(super) fn target_id(&self) -> &str {
    &self.target_id
  }
}

pub(super) async fn capture_checkpoint(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  mutation: &IpmAdminMutation,
) -> anyhow::Result<IpmMutationCheckpoint> {
  let (table, target_id) = mutation_target(mutation);
  let query = match table {
    IpmMutationTable::Principal => {
      "SELECT to_jsonb(row_value)::text AS value FROM oxibelt_ipm_principals row_value
       WHERE namespace=$1 AND principal_id=$2"
    }
    IpmMutationTable::Credential => {
      "SELECT to_jsonb(row_value)::text AS value FROM oxibelt_ipm_credentials row_value
       WHERE namespace=$1 AND credential_id=$2"
    }
    IpmMutationTable::Policy => {
      "SELECT to_jsonb(row_value)::text AS value FROM oxibelt_ipm_policies row_value
       WHERE namespace=$1 AND policy_id=$2"
    }
    IpmMutationTable::Binding => {
      "SELECT to_jsonb(row_value)::text AS value FROM oxibelt_ipm_policy_bindings row_value
       WHERE namespace=$1 AND binding_id=$2"
    }
  };
  let prior_row = row_json(tx, query, namespace, &target_id).await?;
  let prior_generation = sqlx::query(
    "SELECT to_jsonb(row_value)::text AS value FROM oxibelt_ipm_generation row_value
     WHERE namespace=$1 FOR UPDATE",
  )
  .bind(namespace)
  .fetch_optional(&mut **tx)
  .await?
  .map(|row| row.try_get::<String, _>("value"))
  .transpose()?
  .map(|value| serde_json::from_str(&value))
  .transpose()?;
  let checkpoint = IpmMutationCheckpoint {
    table,
    target_id,
    prior_row: encode_json(prior_row)?,
    prior_generation: encode_json(prior_generation)?,
  };
  checkpoint.validate_namespace(namespace)?;
  Ok(checkpoint)
}

pub(super) async fn restore_checkpoint_row(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  checkpoint: &IpmMutationCheckpoint,
) -> anyhow::Result<()> {
  let (delete, insert) = match checkpoint.table {
    IpmMutationTable::Principal => (
      "DELETE FROM oxibelt_ipm_principals WHERE namespace=$1 AND principal_id=$2",
      "INSERT INTO oxibelt_ipm_principals SELECT
       (jsonb_populate_record(NULL::oxibelt_ipm_principals,$1::jsonb)).*",
    ),
    IpmMutationTable::Credential => (
      "DELETE FROM oxibelt_ipm_credentials WHERE namespace=$1 AND credential_id=$2",
      "INSERT INTO oxibelt_ipm_credentials SELECT
       (jsonb_populate_record(NULL::oxibelt_ipm_credentials,$1::jsonb)).*",
    ),
    IpmMutationTable::Policy => (
      "DELETE FROM oxibelt_ipm_policies WHERE namespace=$1 AND policy_id=$2",
      "INSERT INTO oxibelt_ipm_policies SELECT
       (jsonb_populate_record(NULL::oxibelt_ipm_policies,$1::jsonb)).*",
    ),
    IpmMutationTable::Binding => (
      "DELETE FROM oxibelt_ipm_policy_bindings WHERE namespace=$1 AND binding_id=$2",
      "INSERT INTO oxibelt_ipm_policy_bindings SELECT
       (jsonb_populate_record(NULL::oxibelt_ipm_policy_bindings,$1::jsonb)).*",
    ),
  };
  let credential_use = if checkpoint.table == IpmMutationTable::Credential {
    sqlx::query(
      "SELECT last_used_at::text AS at,last_used_source_ip::text AS source
       FROM oxibelt_ipm_credentials WHERE namespace=$1 AND credential_id=$2",
    )
    .bind(namespace)
    .bind(&checkpoint.target_id)
    .fetch_optional(&mut **tx)
    .await?
    .map(|row| {
      Ok::<_, sqlx::Error>((
        row.try_get::<Option<String>, _>("at")?,
        row.try_get::<Option<String>, _>("source")?,
      ))
    })
    .transpose()?
  } else {
    None
  };
  sqlx::query(delete)
    .bind(namespace)
    .bind(&checkpoint.target_id)
    .execute(&mut **tx)
    .await?;
  if let Some(row) = &checkpoint.prior_row {
    let row = std::str::from_utf8(row)?;
    sqlx::query(insert).bind(row).execute(&mut **tx).await?;
    preserve_credential_use(tx, namespace, checkpoint, credential_use).await?;
  }
  Ok(())
}

async fn preserve_credential_use(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  checkpoint: &IpmMutationCheckpoint,
  credential_use: Option<(Option<String>, Option<String>)>,
) -> anyhow::Result<()> {
  let Some((last_used_at, source)) = credential_use else {
    return Ok(());
  };
  sqlx::query(
    "UPDATE oxibelt_ipm_credentials SET
       last_used_at=GREATEST(last_used_at,$3::timestamptz),
       last_used_source_ip=CASE WHEN $3::timestamptz IS NOT NULL
         AND (last_used_at IS NULL OR $3::timestamptz>=last_used_at)
         THEN $4::inet ELSE last_used_source_ip END
     WHERE namespace=$1 AND credential_id=$2",
  )
  .bind(namespace)
  .bind(&checkpoint.target_id)
  .bind(last_used_at)
  .bind(source)
  .execute(&mut **tx)
  .await?;
  Ok(())
}

fn mutation_target(mutation: &IpmAdminMutation) -> (IpmMutationTable, String) {
  match mutation {
    IpmAdminMutation::PrincipalCreate(input) => (IpmMutationTable::Principal, input.id.clone()),
    IpmAdminMutation::PrincipalPatch(id, _) | IpmAdminMutation::PrincipalDelete(id) => {
      (IpmMutationTable::Principal, id.clone())
    }
    IpmAdminMutation::CredentialCreate(input) => (IpmMutationTable::Credential, input.id.clone()),
    IpmAdminMutation::CredentialPatch(id, _)
    | IpmAdminMutation::CredentialRotate(id, _)
    | IpmAdminMutation::CredentialRevoke(id, _)
    | IpmAdminMutation::CredentialDelete(id) => (IpmMutationTable::Credential, id.clone()),
    IpmAdminMutation::PolicyCreate(input) => (IpmMutationTable::Policy, input.name.clone()),
    IpmAdminMutation::PolicyPatch(id, _) | IpmAdminMutation::PolicyDelete(id) => {
      (IpmMutationTable::Policy, id.clone())
    }
    IpmAdminMutation::BindingCreate(input) => (
      IpmMutationTable::Binding,
      input.id.clone().unwrap_or_else(|| {
        generated_binding_id(
          input.principal.as_deref(),
          input.group.as_deref(),
          &input.policy,
        )
      }),
    ),
    IpmAdminMutation::BindingDelete(id) => (IpmMutationTable::Binding, id.clone()),
  }
}

async fn row_json(
  tx: &mut Transaction<'_, Postgres>,
  query: &'static str,
  namespace: &str,
  target_id: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
  sqlx::query(query)
    .bind(namespace)
    .bind(target_id)
    .fetch_optional(&mut **tx)
    .await?
    .map(|row| row.try_get::<String, _>("value"))
    .transpose()?
    .map(|value| serde_json::from_str(&value))
    .transpose()
    .map_err(Into::into)
}

fn encode_json(value: Option<serde_json::Value>) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
  value
    .map(|value| serde_json::to_vec(&value).map(Zeroizing::new))
    .transpose()
    .map_err(Into::into)
}

fn decode_json(value: &Option<Zeroizing<Vec<u8>>>) -> anyhow::Result<Option<serde_json::Value>> {
  value
    .as_ref()
    .map(|value| serde_json::from_slice(value))
    .transpose()
    .map_err(Into::into)
}

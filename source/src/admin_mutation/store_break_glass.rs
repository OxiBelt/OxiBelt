//! Transactional break-glass activation helpers.

use anyhow::ensure;
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Row, Transaction};
use zeroize::Zeroizing;

use super::{MutationStore, validate_identifier};

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

#[derive(Clone)]
pub(crate) struct BreakGlassMutationCheckpoint {
  activation_id: String,
  prior_row: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for BreakGlassMutationCheckpoint {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("BreakGlassMutationCheckpoint")
      .field("activation_id", &self.activation_id)
      .field("had_prior_row", &self.prior_row.is_some())
      .finish()
  }
}

#[derive(Deserialize, Serialize)]
struct BreakGlassMutationCheckpointWire {
  format: String,
  activation_id: String,
  prior_row: Option<serde_json::Value>,
}

impl BreakGlassMutationCheckpoint {
  pub(crate) fn encode_plaintext(&self) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let prior_row = self
      .prior_row
      .as_ref()
      .map(|row| serde_json::from_slice(row))
      .transpose()?;
    Ok(Zeroizing::new(serde_json::to_vec(
      &BreakGlassMutationCheckpointWire {
        format: "oxibelt-break-glass-checkpoint-v1".to_string(),
        activation_id: self.activation_id.clone(),
        prior_row,
      },
    )?))
  }

  pub(crate) fn decode_plaintext(encoded: &[u8]) -> anyhow::Result<Self> {
    let wire: BreakGlassMutationCheckpointWire = serde_json::from_slice(encoded)?;
    ensure!(
      wire.format == "oxibelt-break-glass-checkpoint-v1",
      "unsupported break-glass checkpoint format"
    );
    validate_identifier("activation_id", &wire.activation_id, 256)?;
    Ok(Self {
      activation_id: wire.activation_id,
      prior_row: wire
        .prior_row
        .map(|row| serde_json::to_vec(&row).map(Zeroizing::new))
        .transpose()?,
    })
  }
}

pub(crate) async fn capture_break_glass_checkpoint_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  activation_id: &str,
) -> anyhow::Result<BreakGlassMutationCheckpoint> {
  validate_identifier("activation_id", activation_id, 256)?;
  let prior_row = sqlx::query_scalar::<_, String>(
    "SELECT to_jsonb(row_value)::text FROM oxibelt_admin_break_glass_activations row_value
     WHERE namespace=$1 AND activation_id=$2 FOR UPDATE",
  )
  .bind(namespace)
  .bind(activation_id)
  .fetch_optional(&mut **tx)
  .await?
  .map(|row| Zeroizing::new(row.into_bytes()));
  Ok(BreakGlassMutationCheckpoint {
    activation_id: activation_id.to_string(),
    prior_row,
  })
}

pub(crate) async fn restore_break_glass_checkpoint_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  checkpoint: &BreakGlassMutationCheckpoint,
) -> anyhow::Result<()> {
  validate_identifier("activation_id", &checkpoint.activation_id, 256)?;
  if let Some(row) = &checkpoint.prior_row {
    let value: serde_json::Value = serde_json::from_slice(row)?;
    ensure!(
      value.get("namespace").and_then(serde_json::Value::as_str) == Some(namespace)
        && value
          .get("activation_id")
          .and_then(serde_json::Value::as_str)
          == Some(&checkpoint.activation_id),
      "break-glass checkpoint binding mismatch"
    );
  }
  sqlx::query(
    "DELETE FROM oxibelt_admin_break_glass_activations
     WHERE namespace=$1 AND activation_id=$2",
  )
  .bind(namespace)
  .bind(&checkpoint.activation_id)
  .execute(&mut **tx)
  .await?;
  if let Some(row) = &checkpoint.prior_row {
    let row = std::str::from_utf8(row)?;
    sqlx::query(
      "INSERT INTO oxibelt_admin_break_glass_activations SELECT
       (jsonb_populate_record(NULL::oxibelt_admin_break_glass_activations,$1::jsonb)).*",
    )
    .bind(row)
    .execute(&mut **tx)
    .await?;
  }
  Ok(())
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
       (namespace,activation_id,principal,scopes,mutation_request_id,expires_at)
     SELECT $1,$2,$3,$4,$5,$6::timestamptz WHERE now()<$6::timestamptz
     ON CONFLICT(namespace,activation_id) DO NOTHING",
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
    "SELECT activation_id,principal,scopes,mutation_request_id,expires_at::text AS expires_at,
            revoked_at::text AS revoked_at,created_at::text AS created_at
       FROM oxibelt_admin_break_glass_activations
      WHERE namespace=$1 AND activation_id=$2 AND principal=$3",
  )
  .bind(namespace)
  .bind(activation_id)
  .bind(principal)
  .fetch_one(&mut **tx)
  .await?;
  from_row(&row)
}

pub(crate) async fn revoke_break_glass_activation_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  activation_id: &str,
  principal: &str,
) -> anyhow::Result<bool> {
  let result = sqlx::query(
    "UPDATE oxibelt_admin_break_glass_activations SET revoked_at=COALESCE(revoked_at,now())
      WHERE namespace=$1 AND activation_id=$2 AND principal=$3 AND revoked_at IS NULL
        AND expires_at>now()",
  )
  .bind(namespace)
  .bind(activation_id)
  .bind(principal)
  .execute(&mut **tx)
  .await?;
  Ok(result.rows_affected() == 1)
}

pub(crate) async fn load_active_break_glass_for_principal(
  store: &MutationStore,
  principal: &str,
) -> anyhow::Result<Option<BreakGlassActivation>> {
  validate_identifier("principal", principal, 256)?;
  load_active(store, None, principal).await
}

async fn load_active(
  store: &MutationStore,
  activation_id: Option<&str>,
  principal: &str,
) -> anyhow::Result<Option<BreakGlassActivation>> {
  let row = sqlx::query(
    "SELECT activation.activation_id,activation.principal,activation.scopes,
            activation.mutation_request_id,activation.expires_at::text AS expires_at,
            activation.revoked_at::text AS revoked_at,activation.created_at::text AS created_at
       FROM oxibelt_admin_break_glass_activations activation
       JOIN oxibelt_admin_mutations mutation ON mutation.namespace=activation.namespace
        AND mutation.request_id=activation.mutation_request_id AND mutation.state='committed'
      WHERE activation.namespace=$1 AND activation.principal=$2 AND ($3::text IS NULL
        OR activation.activation_id=$3) AND activation.revoked_at IS NULL
        AND activation.expires_at>now() ORDER BY activation.expires_at DESC LIMIT 1",
  )
  .bind(store.namespace())
  .bind(principal)
  .bind(activation_id)
  .fetch_optional(store.pool())
  .await?;
  row.as_ref().map(from_row).transpose()
}

fn from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<BreakGlassActivation> {
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

use std::str::FromStr;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{Pool, Postgres, Row};

use crate::config::{DatabaseTlsMode, SharedStateBackendConfig};

use super::{
  IpmActor, IpmBindingRuntime, IpmCredentialRuntime, IpmEntrySource, IpmPolicyRuntime,
  IpmPrincipalRuntime, IpmSnapshot, merge_store_snapshot, token,
};

#[derive(Clone)]
pub(crate) struct IpmStore {
  pool: Pool<Postgres>,
  namespace: String,
}

pub(crate) struct IpmStoreSnapshotParts {
  pub(crate) generation: i64,
  pub(crate) principals: Vec<(String, IpmPrincipalRuntime)>,
  pub(crate) credentials: Vec<IpmCredentialRuntime>,
  pub(crate) policies: Vec<(String, IpmPolicyRuntime)>,
  pub(crate) bindings: Vec<IpmBindingRuntime>,
}

impl IpmStore {
  pub(crate) fn new(pool: Pool<Postgres>, namespace: String) -> Self {
    Self { pool, namespace }
  }

  pub(crate) fn pool(&self) -> &Pool<Postgres> {
    &self.pool
  }

  pub(crate) fn namespace(&self) -> &str {
    &self.namespace
  }

  pub(crate) async fn load_snapshot(
    &self,
    static_snapshot: &IpmSnapshot,
  ) -> anyhow::Result<IpmSnapshot> {
    let generation = load_generation(&self.pool, &self.namespace).await?;
    let principals = load_principals(&self.pool, &self.namespace).await?;
    let credentials = load_credentials(&self.pool, &self.namespace).await?;
    let policies = load_policies(&self.pool, &self.namespace).await?;
    let bindings = load_bindings(&self.pool, &self.namespace).await?;
    merge_store_snapshot(
      static_snapshot,
      IpmStoreSnapshotParts {
        generation,
        principals,
        credentials,
        policies,
        bindings,
      },
    )
  }

  pub(crate) async fn record_credential_use(&self, credential_id: &str) -> anyhow::Result<()> {
    sqlx::query(
      "UPDATE oxibelt_ipm_credentials
          SET last_used_at = now(), updated_at = updated_at
        WHERE namespace = $1 AND credential_id = $2",
    )
    .bind(&self.namespace)
    .bind(credential_id)
    .execute(&self.pool)
    .await?;
    Ok(())
  }
}

pub(crate) async fn connect_postgres_pool(
  config: &SharedStateBackendConfig,
) -> anyhow::Result<Pool<Postgres>> {
  let connection_url =
    config.connection_url_with_prefix(&format!("shared_state.backends.{}", config.name))?;
  let mut options = PgConnectOptions::from_str(&connection_url)?
    .application_name("oxibelt-ipm")
    .ssl_mode(match config.tls.mode {
      DatabaseTlsMode::Off => PgSslMode::Disable,
      DatabaseTlsMode::VerifyFull => PgSslMode::VerifyFull,
    });
  if let Some(ca_cert) = &config.tls.ca_cert {
    options = options.ssl_root_cert(ca_cert);
  }
  if let (Some(client_cert), Some(client_key)) = (&config.tls.client_cert, &config.tls.client_key) {
    options = options
      .ssl_client_cert(client_cert)
      .ssl_client_key(client_key);
  }
  PgPoolOptions::new()
    .max_connections(config.max_connections)
    .acquire_timeout(Duration::from_millis(config.connect_timeout_ms))
    .connect_with(options)
    .await
    .map_err(Into::into)
}

pub(crate) async fn init_postgres(pool: &Pool<Postgres>) -> anyhow::Result<()> {
  for statement in [
    "CREATE TABLE IF NOT EXISTS oxibelt_ipm_principals (
       id bigserial PRIMARY KEY,
       namespace text NOT NULL,
       principal_id text NOT NULL,
       subject text NOT NULL,
       groups text[] NOT NULL DEFAULT ARRAY[]::text[],
       enabled boolean NOT NULL DEFAULT true,
       created_at timestamptz NOT NULL DEFAULT now(),
       updated_at timestamptz NOT NULL DEFAULT now(),
       UNIQUE(namespace, principal_id)
     )",
    "CREATE TABLE IF NOT EXISTS oxibelt_ipm_credentials (
       id bigserial PRIMARY KEY,
       namespace text NOT NULL,
       credential_id text NOT NULL,
       principal_id text NOT NULL,
       subject text NOT NULL,
       token_prefix text NULL,
       token_hash text NULL,
       token_hash_alg text NULL,
       previous_token_prefix text NULL,
       previous_token_hash text NULL,
       previous_token_overlap_until timestamptz NULL,
       enabled boolean NOT NULL DEFAULT true,
       revoked boolean NOT NULL DEFAULT false,
       expires_at timestamptz NULL,
       created_at timestamptz NOT NULL DEFAULT now(),
       updated_at timestamptz NOT NULL DEFAULT now(),
       revoked_at timestamptz NULL,
       last_used_at timestamptz NULL,
       last_used_source_ip inet NULL,
       created_by text NULL,
       revoked_by text NULL,
       revoke_reason text NULL,
       UNIQUE(namespace, credential_id)
     )",
    "CREATE TABLE IF NOT EXISTS oxibelt_ipm_policies (
       id bigserial PRIMARY KEY,
       namespace text NOT NULL,
       policy_id text NOT NULL,
       document jsonb NOT NULL,
       enabled boolean NOT NULL DEFAULT true,
       created_at timestamptz NOT NULL DEFAULT now(),
       updated_at timestamptz NOT NULL DEFAULT now(),
       UNIQUE(namespace, policy_id)
     )",
    "CREATE TABLE IF NOT EXISTS oxibelt_ipm_policy_bindings (
       id bigserial PRIMARY KEY,
       namespace text NOT NULL,
       binding_id text NOT NULL,
       principal_id text NULL,
       group_name text NULL,
       policy_id text NOT NULL,
       enabled boolean NOT NULL DEFAULT true,
       created_at timestamptz NOT NULL DEFAULT now(),
       updated_at timestamptz NOT NULL DEFAULT now(),
       UNIQUE(namespace, binding_id),
       CHECK ((principal_id IS NULL) <> (group_name IS NULL))
     )",
    "CREATE TABLE IF NOT EXISTS oxibelt_ipm_generation (
       namespace text PRIMARY KEY,
       generation bigint NOT NULL DEFAULT 0,
       updated_at timestamptz NOT NULL DEFAULT now()
     )",
    "CREATE TABLE IF NOT EXISTS oxibelt_ipm_audit (
       id bigserial PRIMARY KEY,
       namespace text NOT NULL,
       actor text NOT NULL,
       operation text NOT NULL,
       target_kind text NULL,
       target_id text NULL,
       resource text NULL,
       outcome text NOT NULL,
       error text NULL,
       created_at timestamptz NOT NULL DEFAULT now()
     )",
    "CREATE INDEX IF NOT EXISTS oxibelt_ipm_principals_active_idx
       ON oxibelt_ipm_principals (namespace, enabled)",
    "CREATE INDEX IF NOT EXISTS oxibelt_ipm_credentials_active_idx
       ON oxibelt_ipm_credentials (namespace, enabled, revoked, expires_at)",
    "CREATE INDEX IF NOT EXISTS oxibelt_ipm_policy_bindings_subject_idx
       ON oxibelt_ipm_policy_bindings (namespace, principal_id, group_name, enabled)",
  ] {
    sqlx::query(statement).execute(pool).await?;
  }
  for statement in [
    "ALTER TABLE oxibelt_ipm_credentials ADD COLUMN IF NOT EXISTS token_prefix text NULL",
    "ALTER TABLE oxibelt_ipm_credentials ADD COLUMN IF NOT EXISTS token_hash text NULL",
    "ALTER TABLE oxibelt_ipm_credentials ADD COLUMN IF NOT EXISTS token_hash_alg text NULL",
    "ALTER TABLE oxibelt_ipm_credentials ADD COLUMN IF NOT EXISTS previous_token_prefix text NULL",
    "ALTER TABLE oxibelt_ipm_credentials ADD COLUMN IF NOT EXISTS previous_token_hash text NULL",
    "ALTER TABLE oxibelt_ipm_credentials ADD COLUMN IF NOT EXISTS previous_token_overlap_until timestamptz NULL",
    "ALTER TABLE oxibelt_ipm_credentials ADD COLUMN IF NOT EXISTS last_used_at timestamptz NULL",
    "ALTER TABLE oxibelt_ipm_credentials ADD COLUMN IF NOT EXISTS last_used_source_ip inet NULL",
    "ALTER TABLE oxibelt_ipm_credentials ADD COLUMN IF NOT EXISTS created_by text NULL",
    "ALTER TABLE oxibelt_ipm_credentials ADD COLUMN IF NOT EXISTS revoked_by text NULL",
    "ALTER TABLE oxibelt_ipm_credentials ADD COLUMN IF NOT EXISTS revoke_reason text NULL",
    "ALTER TABLE oxibelt_ipm_audit ADD COLUMN IF NOT EXISTS target_kind text NULL",
    "ALTER TABLE oxibelt_ipm_audit ADD COLUMN IF NOT EXISTS target_id text NULL",
    "CREATE INDEX IF NOT EXISTS oxibelt_ipm_audit_filter_idx
       ON oxibelt_ipm_audit (namespace, target_kind, target_id, outcome, id DESC)",
  ] {
    sqlx::query(statement).execute(pool).await?;
  }
  Ok(())
}

async fn load_generation(pool: &Pool<Postgres>, namespace: &str) -> anyhow::Result<i64> {
  let generation =
    sqlx::query_scalar("SELECT generation FROM oxibelt_ipm_generation WHERE namespace = $1")
      .bind(namespace)
      .fetch_optional(pool)
      .await?;
  Ok(generation.unwrap_or(0))
}

async fn load_principals(
  pool: &Pool<Postgres>,
  namespace: &str,
) -> anyhow::Result<Vec<(String, IpmPrincipalRuntime)>> {
  let rows = sqlx::query(
    "SELECT principal_id, subject, groups, enabled
       FROM oxibelt_ipm_principals
      WHERE namespace = $1
      ORDER BY principal_id ASC",
  )
  .bind(namespace)
  .fetch_all(pool)
  .await?;
  rows
    .iter()
    .map(|row| {
      let id: String = row.try_get("principal_id")?;
      let groups: Vec<String> = row.try_get("groups")?;
      Ok((
        id.clone(),
        IpmPrincipalRuntime {
          actor: IpmActor {
            name: id.clone(),
            principal: id,
            subject: row.try_get("subject")?,
            groups,
          },
          enabled: row.try_get("enabled")?,
          source: IpmEntrySource::Store,
        },
      ))
    })
    .collect()
}

async fn load_credentials(
  pool: &Pool<Postgres>,
  namespace: &str,
) -> anyhow::Result<Vec<IpmCredentialRuntime>> {
  let rows = sqlx::query(
    "SELECT credential_id, principal_id, enabled, revoked, expires_at::text AS expires_at,
            extract(epoch from expires_at)::bigint AS expires_at_unix,
            token_prefix, token_hash, COALESCE(token_hash_alg, 'sha256-v1') AS token_hash_alg,
            previous_token_prefix, previous_token_hash,
            previous_token_overlap_until::text AS previous_token_overlap_until,
            extract(epoch from previous_token_overlap_until)::bigint AS previous_token_overlap_until_unix
       FROM oxibelt_ipm_credentials
      WHERE namespace = $1
      ORDER BY credential_id ASC",
  )
  .bind(namespace)
  .fetch_all(pool)
  .await?;
  rows
    .iter()
    .map(|row| {
      let alg: String = row.try_get("token_hash_alg")?;
      token::validate_hash_alg(&alg)?;
      Ok(IpmCredentialRuntime {
        name: row.try_get("credential_id")?,
        principal: row.try_get("principal_id")?,
        source: IpmEntrySource::Store,
        bearer_token_env: String::new(),
        break_glass_access_token_hash: None,
        enabled: row.try_get("enabled")?,
        revoked: row.try_get("revoked")?,
        expires_at: row.try_get("expires_at")?,
        expires_at_unix: row.try_get("expires_at_unix")?,
        token_prefix: row.try_get("token_prefix")?,
        token_hash: row.try_get("token_hash")?,
        token_hash_alg: Some(alg),
        previous_token_prefix: row.try_get("previous_token_prefix")?,
        previous_token_hash: row.try_get("previous_token_hash")?,
        previous_token_overlap_until: row.try_get("previous_token_overlap_until")?,
        previous_token_overlap_until_unix: row.try_get("previous_token_overlap_until_unix")?,
      })
    })
    .collect()
}

async fn load_policies(
  pool: &Pool<Postgres>,
  namespace: &str,
) -> anyhow::Result<Vec<(String, IpmPolicyRuntime)>> {
  let rows = sqlx::query(
    "SELECT policy_id, document::text AS document, enabled
       FROM oxibelt_ipm_policies
      WHERE namespace = $1
      ORDER BY policy_id ASC",
  )
  .bind(namespace)
  .fetch_all(pool)
  .await?;
  rows
    .iter()
    .map(|row| {
      let document: String = row.try_get("document")?;
      let policy: crate::config::IpmPolicyConfig = serde_json::from_str(&document)?;
      let id: String = row.try_get("policy_id")?;
      if policy.name != id {
        anyhow::bail!("IPM store policy {id} document name does not match policy_id");
      }
      Ok((
        id,
        IpmPolicyRuntime {
          policy,
          enabled: row.try_get("enabled")?,
          source: IpmEntrySource::Store,
        },
      ))
    })
    .collect()
}

async fn load_bindings(
  pool: &Pool<Postgres>,
  namespace: &str,
) -> anyhow::Result<Vec<IpmBindingRuntime>> {
  let rows = sqlx::query(
    "SELECT binding_id, principal_id, group_name, policy_id, enabled
       FROM oxibelt_ipm_policy_bindings
      WHERE namespace = $1
      ORDER BY binding_id ASC",
  )
  .bind(namespace)
  .fetch_all(pool)
  .await?;
  rows
    .iter()
    .map(|row| {
      Ok(IpmBindingRuntime {
        id: row.try_get("binding_id")?,
        principal: row.try_get("principal_id")?,
        group: row.try_get("group_name")?,
        policy: row.try_get("policy_id")?,
        enabled: row.try_get("enabled")?,
        source: IpmEntrySource::Store,
      })
    })
    .collect()
}

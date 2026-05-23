use std::str::FromStr;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{Pool, Postgres};

use crate::config::{DatabaseTlsMode, SharedStateBackendConfig};

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
       enabled boolean NOT NULL DEFAULT true,
       revoked boolean NOT NULL DEFAULT false,
       expires_at timestamptz NULL,
       created_at timestamptz NOT NULL DEFAULT now(),
       updated_at timestamptz NOT NULL DEFAULT now(),
       revoked_at timestamptz NULL,
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
  Ok(())
}

//! Persistent dynamic policy store access.
//! Store rows are parsed into validated records before they reach runtime state.

use std::str::FromStr;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{Pool, Postgres};

use crate::config::{DatabaseTlsMode, SharedStateBackendConfig};

pub async fn connect_postgres_pool(
  config: &SharedStateBackendConfig,
) -> anyhow::Result<Pool<Postgres>> {
  let connection_url =
    config.connection_url_with_prefix(&format!("shared_state.backends.{}", config.name))?;
  let mut options = PgConnectOptions::from_str(&connection_url)?
    .application_name("oxibelt-dynamic-policy")
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

pub async fn init_postgres(pool: &Pool<Postgres>) -> anyhow::Result<()> {
  sqlx::query(
    "CREATE TABLE IF NOT EXISTS oxibelt_dynamic_policies (
       id bigserial PRIMARY KEY,
       namespace text NOT NULL,
       enabled boolean NOT NULL DEFAULT true,
       priority integer NOT NULL DEFAULT 100,
       name text NOT NULL,
       source text NOT NULL DEFAULT 'external',
       action text NOT NULL,
       subject_type text NOT NULL,
       subject text NOT NULL,
       route_name text NULL,
       method text NULL,
       path_prefix text NULL,
       rate text NULL,
       burst integer NULL,
       status integer NULL,
       body text NULL,
       reason text NULL,
       code text NULL,
       mode text NOT NULL DEFAULT 'enforce',
       writer_identity text NULL,
       signature_version text NULL,
       row_signature text NULL,
       created_at timestamptz NOT NULL DEFAULT now(),
       updated_at timestamptz NOT NULL DEFAULT now(),
       expires_at timestamptz NULL
     )",
  )
  .execute(pool)
  .await?;
  for statement in [
    "ALTER TABLE oxibelt_dynamic_policies ADD COLUMN IF NOT EXISTS code text NULL",
    "ALTER TABLE oxibelt_dynamic_policies ADD COLUMN IF NOT EXISTS mode text NOT NULL DEFAULT 'enforce'",
    "ALTER TABLE oxibelt_dynamic_policies ADD COLUMN IF NOT EXISTS writer_identity text NULL",
    "ALTER TABLE oxibelt_dynamic_policies ADD COLUMN IF NOT EXISTS signature_version text NULL",
    "ALTER TABLE oxibelt_dynamic_policies ADD COLUMN IF NOT EXISTS row_signature text NULL",
  ] {
    sqlx::query(statement).execute(pool).await?;
  }
  sqlx::query(
    "CREATE INDEX IF NOT EXISTS oxibelt_dynamic_policies_active_idx
       ON oxibelt_dynamic_policies (namespace, enabled, expires_at, priority)",
  )
  .execute(pool)
  .await?;
  sqlx::query(
    "CREATE INDEX IF NOT EXISTS oxibelt_dynamic_policies_subject_idx
       ON oxibelt_dynamic_policies (namespace, subject_type, subject)",
  )
  .execute(pool)
  .await?;
  sqlx::query(
    "CREATE INDEX IF NOT EXISTS oxibelt_dynamic_policies_source_name_idx
       ON oxibelt_dynamic_policies (namespace, source, name)",
  )
  .execute(pool)
  .await?;
  sqlx::query(
    "CREATE TABLE IF NOT EXISTS oxibelt_dynamic_policy_generation (
       namespace text PRIMARY KEY,
       generation bigint NOT NULL DEFAULT 0,
       updated_at timestamptz NOT NULL DEFAULT now()
     )",
  )
  .execute(pool)
  .await?;
  sqlx::query(
    "CREATE TABLE IF NOT EXISTS oxibelt_dynamic_policy_audit (
       id bigserial PRIMARY KEY,
       namespace text NOT NULL,
       policy_id bigint NULL,
       actor text NOT NULL,
       operation text NOT NULL,
       source text NULL,
       name text NULL,
       outcome text NOT NULL,
       error text NULL,
       created_at timestamptz NOT NULL DEFAULT now()
     )",
  )
  .execute(pool)
  .await?;
  Ok(())
}

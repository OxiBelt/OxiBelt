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
    .application_name("oxibelt-admin-tokens")
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
  sqlx::query(
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_tokens (
       id bigserial PRIMARY KEY,
       namespace text NOT NULL,
       token_id text NOT NULL,
       subject text NOT NULL,
       name text NOT NULL,
       enabled boolean NOT NULL DEFAULT true,
       revoked boolean NOT NULL DEFAULT false,
       roles text[] NOT NULL DEFAULT ARRAY[]::text[],
       permissions text[] NOT NULL DEFAULT ARRAY[]::text[],
       deny_permissions text[] NOT NULL DEFAULT ARRAY[]::text[],
       row_version bigint NOT NULL DEFAULT 0,
       writer_identity text NULL,
       created_at timestamptz NOT NULL DEFAULT now(),
       updated_at timestamptz NOT NULL DEFAULT now(),
       expires_at timestamptz NULL,
       revoked_at timestamptz NULL,
       UNIQUE(namespace, token_id)
     )",
  )
  .execute(pool)
  .await?;
  for statement in [
    "ALTER TABLE oxibelt_admin_tokens ADD COLUMN IF NOT EXISTS revoked boolean NOT NULL DEFAULT false",
    "ALTER TABLE oxibelt_admin_tokens ADD COLUMN IF NOT EXISTS row_version bigint NOT NULL DEFAULT 0",
    "ALTER TABLE oxibelt_admin_tokens ADD COLUMN IF NOT EXISTS revoked_at timestamptz NULL",
  ] {
    sqlx::query(statement).execute(pool).await?;
  }
  sqlx::query(
    "CREATE INDEX IF NOT EXISTS oxibelt_admin_tokens_active_idx
       ON oxibelt_admin_tokens (namespace, enabled, revoked, expires_at)",
  )
  .execute(pool)
  .await?;
  sqlx::query(
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_token_generation (
       namespace text PRIMARY KEY,
       generation bigint NOT NULL DEFAULT 0,
       updated_at timestamptz NOT NULL DEFAULT now()
     )",
  )
  .execute(pool)
  .await?;
  sqlx::query(
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_token_audit (
       id bigserial PRIMARY KEY,
       namespace text NOT NULL,
       token_id text NULL,
       actor text NOT NULL,
       operation text NOT NULL,
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

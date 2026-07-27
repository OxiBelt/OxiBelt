//! PostgreSQL backend connection, schema, and health mechanics.

use super::*;

impl PostgresBackend {
  pub(super) async fn take_key(&self, key: &str) -> anyhow::Result<bool> {
    let result = sqlx::query(
      "DELETE FROM oxibelt_shared_state WHERE key = $1 AND (expires_at_ms IS NULL OR expires_at_ms > $2)",
    )
    .bind(key)
    .bind(now_unix_ms())
    .execute(&self.pool)
    .await?;
    Ok(result.rows_affected() > 0)
  }

  pub(super) async fn put(
    &self,
    key: &str,
    value: &[u8],
    ttl: Option<Duration>,
  ) -> anyhow::Result<()> {
    let now = now_unix_ms();
    let expires = ttl.map(|ttl| atomic_updates::expiry_after(now, ttl));
    sqlx::query(
      "INSERT INTO oxibelt_shared_state (key, value, expires_at_ms) VALUES ($1, $2, $3)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at_ms = EXCLUDED.expires_at_ms",
    )
    .bind(key)
    .bind(value)
    .bind(expires)
    .execute(&self.pool)
    .await?;
    Ok(())
  }

  pub(super) async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let value: Option<Vec<u8>> = sqlx::query_scalar(
      "SELECT value FROM oxibelt_shared_state WHERE key = $1 AND (expires_at_ms IS NULL OR expires_at_ms > $2)",
    )
    .bind(key)
    .bind(now_unix_ms())
    .fetch_optional(&self.pool)
    .await?;
    Ok(value)
  }

  pub(super) async fn delete(&self, key: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM oxibelt_shared_state WHERE key = $1")
      .bind(key)
      .execute(&self.pool)
      .await?;
    Ok(())
  }

  pub(super) async fn unlock(&self, key: &str, token: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM oxibelt_shared_state WHERE key = $1 AND value = $2")
      .bind(key)
      .bind(token.as_bytes())
      .execute(&self.pool)
      .await?;
    Ok(())
  }

  pub(super) async fn health_get(&self, key: &str) -> anyhow::Result<Option<HealthRecord>> {
    let raw: Option<Vec<u8>> =
      sqlx::query_scalar("SELECT value FROM oxibelt_shared_state WHERE key = $1")
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
    raw
      .map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
      .transpose()
  }

  pub(super) async fn counter_get(&self, key: &str) -> anyhow::Result<usize> {
    let value: Option<i64> = sqlx::query_scalar(
      "SELECT counter FROM oxibelt_shared_counters WHERE key = $1 AND (expires_at_ms IS NULL OR expires_at_ms > $2)",
    )
    .bind(key)
    .bind(now_unix_ms())
    .fetch_optional(&self.pool)
    .await?;
    Ok(value.unwrap_or(0).max(0) as usize)
  }
}

pub(super) async fn connect_postgres_pool(
  config: &SharedStateBackendConfig,
  connection_url: &str,
  connect_timeout: Duration,
) -> anyhow::Result<Pool<Postgres>> {
  let mut options = PgConnectOptions::from_str(connection_url)?
    .application_name("oxibelt-shared-state")
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
    .acquire_timeout(connect_timeout)
    .connect_with(options)
    .await
    .map_err(Into::into)
}

pub(super) async fn init_postgres(pool: &Pool<Postgres>) -> anyhow::Result<()> {
  sqlx::query(
    "CREATE TABLE IF NOT EXISTS oxibelt_shared_state (
       key text PRIMARY KEY,
       value bytea NOT NULL,
       expires_at_ms bigint NULL
     )",
  )
  .execute(pool)
  .await?;
  sqlx::query(
    "CREATE TABLE IF NOT EXISTS oxibelt_shared_counters (
       key text PRIMARY KEY,
       counter bigint NOT NULL,
       expires_at_ms bigint NULL
     )",
  )
  .execute(pool)
  .await?;
  sqlx::query(
    "CREATE TABLE IF NOT EXISTS oxibelt_shared_idempotency (
       record_key text PRIMARY KEY,
       fingerprint bytea NOT NULL,
       result bytea NOT NULL,
       expires_at_ms bigint NOT NULL
     )",
  )
  .execute(pool)
  .await?;
  sqlx::query(
    "CREATE INDEX IF NOT EXISTS oxibelt_shared_idempotency_expires
     ON oxibelt_shared_idempotency (expires_at_ms)",
  )
  .execute(pool)
  .await?;
  sqlx::query(
    "CREATE TABLE IF NOT EXISTS oxibelt_shared_rate_limit_locks (
       limit_name text PRIMARY KEY
     )",
  )
  .execute(pool)
  .await?;
  sqlx::query(
    "CREATE TABLE IF NOT EXISTS oxibelt_shared_rate_buckets (
       limit_name text NOT NULL,
       bucket_key text NOT NULL,
       expires_at_ms bigint NOT NULL,
       PRIMARY KEY (limit_name, bucket_key)
     )",
  )
  .execute(pool)
  .await?;
  sqlx::query(
    "CREATE INDEX IF NOT EXISTS oxibelt_shared_rate_buckets_expires
     ON oxibelt_shared_rate_buckets (limit_name, expires_at_ms)",
  )
  .execute(pool)
  .await?;
  udp_flows::init_postgres_udp_flows(pool).await?;
  Ok(())
}

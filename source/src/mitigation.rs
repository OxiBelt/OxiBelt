use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use serde_json::Value as JsonValue;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{Pool, Postgres, QueryBuilder};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::config::{
  Config, DatabaseMitigationConfig, DatabaseMitigationMode, DatabaseTlsMode,
  MitigationFailurePolicy, SharedStateBackendConfig,
};
use crate::metrics::Metrics;

#[derive(Clone, Debug)]
pub struct MitigationSink {
  inner: Option<Arc<MitigationSinkInner>>,
  defaults: MitigationDefaults,
}

#[derive(Debug)]
struct MitigationSinkInner {
  sender: mpsc::Sender<MitigationEvent>,
  metrics: Arc<Metrics>,
}

#[derive(Clone, Copy, Debug)]
pub struct MitigationDefaults {
  pub dedupe_window_ms: u64,
  pub ttl_seconds: u64,
  pub failure_policy: MitigationFailurePolicy,
}

#[derive(Debug, Clone)]
pub struct MitigationEvent {
  pub intent: String,
  pub provider: Option<String>,
  pub target: String,
  pub target_ip: Option<IpAddr>,
  pub target_cidr: Option<String>,
  pub transport_network: String,
  pub remote_ip: IpAddr,
  pub remote_port: u16,
  pub dedupe_key: String,
  pub occurred_at_unix_ms: u64,
  pub expires_at_unix_ms: u64,
  pub min_count: u64,
  pub record: JsonValue,
}

#[derive(Debug, Clone, Copy)]
pub enum MitigationEmitError {
  Disabled,
  QueueFull,
  WriterClosed,
}

#[derive(Clone, Debug)]
struct MitigationWriterConfig {
  namespace: String,
  table: String,
  shape: MitigationTableShape,
}

#[derive(Clone, Copy, Debug)]
enum MitigationTableShape {
  Managed,
  Existing,
}

impl MitigationSink {
  pub fn disabled() -> Self {
    Self {
      inner: None,
      defaults: MitigationDefaults {
        dedupe_window_ms: 60_000,
        ttl_seconds: 300,
        failure_policy: MitigationFailurePolicy::Open,
      },
    }
  }

  pub async fn new(config: &Config, metrics: Arc<Metrics>) -> anyhow::Result<Self> {
    let mitigation = &config.database.mitigation;
    let defaults = MitigationDefaults {
      dedupe_window_ms: mitigation.dedupe_window_ms,
      ttl_seconds: mitigation.ttl_seconds,
      failure_policy: mitigation.failure_policy,
    };
    if !mitigation.enabled {
      return Ok(Self {
        inner: None,
        defaults,
      });
    }

    let pool = connect_pool(config)
      .await
      .context("failed to connect mitigation PostgreSQL pool")?;
    let table = mitigation.table_name_with_prefix("database.mitigation")?;
    let writer_config = MitigationWriterConfig {
      namespace: mitigation.namespace.clone(),
      table: table.clone(),
      shape: match mitigation.mode {
        DatabaseMitigationMode::Managed => MitigationTableShape::Managed,
        DatabaseMitigationMode::Existing => MitigationTableShape::Existing,
      },
    };
    match mitigation.mode {
      DatabaseMitigationMode::Managed => {
        init_managed_schema(&pool, &table)
          .await
          .with_context(|| format!("failed to initialize mitigation table {}", mitigation.table))?;
      }
      DatabaseMitigationMode::Existing => {
        validate_existing_table(&pool, &table)
          .await
          .with_context(|| format!("failed to validate mitigation table {}", mitigation.table))?;
      }
    }

    let (sender, receiver) = mpsc::channel(mitigation.queue_capacity);
    tokio::spawn(run_writer(pool, writer_config, metrics.clone(), receiver));
    metrics.set_mitigation_writer_healthy(true);
    info!("mitigation PostgreSQL sink initialized");

    Ok(Self {
      inner: Some(Arc::new(MitigationSinkInner { sender, metrics })),
      defaults,
    })
  }

  pub fn defaults(&self) -> MitigationDefaults {
    self.defaults
  }

  pub fn emit(&self, event: MitigationEvent) -> Result<(), MitigationEmitError> {
    let Some(inner) = &self.inner else {
      inner_record_disabled();
      return Err(MitigationEmitError::Disabled);
    };
    match inner.sender.try_send(event) {
      Ok(()) => {
        inner.metrics.record_mitigation_queued();
        inner.metrics.add_mitigation_queue_depth(1);
        Ok(())
      }
      Err(mpsc::error::TrySendError::Full(_)) => {
        inner.metrics.record_mitigation_dropped();
        warn!("mitigation queue is full; dropping mitigation event");
        Err(MitigationEmitError::QueueFull)
      }
      Err(mpsc::error::TrySendError::Closed(_)) => {
        inner.metrics.record_mitigation_dropped();
        warn!("mitigation writer is closed; dropping mitigation event");
        Err(MitigationEmitError::WriterClosed)
      }
    }
  }

  pub fn record_fail_closed(&self) {
    if let Some(inner) = &self.inner {
      inner.metrics.record_mitigation_fail_closed();
    }
  }
}

fn inner_record_disabled() {
  warn!("mitigation sink is disabled; dropping mitigation event");
}

async fn connect_pool(config: &Config) -> anyhow::Result<Pool<Postgres>> {
  let mitigation = &config.database.mitigation;
  if let Some(backend_name) = mitigation.backend.as_deref() {
    let backend = config
      .shared_state
      .backends
      .iter()
      .find(|backend| backend.name == backend_name)
      .ok_or_else(|| anyhow!("database.mitigation.backend references unknown backend"))?;
    let connection_url =
      backend.connection_url_with_prefix(&format!("shared_state.backends.{}", backend.name))?;
    return connect_pool_from_backend(backend, &connection_url).await;
  }

  let connection_url = mitigation
    .connection_url_with_prefix("database.mitigation")?
    .ok_or_else(|| anyhow!("database.mitigation connection URL is required when enabled"))?;
  connect_pool_from_mitigation(mitigation, &connection_url).await
}

async fn connect_pool_from_mitigation(
  config: &DatabaseMitigationConfig,
  connection_url: &str,
) -> anyhow::Result<Pool<Postgres>> {
  let mut options = PgConnectOptions::from_str(connection_url)
    .context("failed to parse database.mitigation PostgreSQL connection URL")?
    .application_name("oxibelt-mitigation")
    .ssl_mode(pg_ssl_mode(config.tls.mode));
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

async fn connect_pool_from_backend(
  config: &SharedStateBackendConfig,
  connection_url: &str,
) -> anyhow::Result<Pool<Postgres>> {
  let mut options = PgConnectOptions::from_str(connection_url)
    .context("failed to parse database.mitigation shared_state PostgreSQL connection URL")?
    .application_name("oxibelt-mitigation")
    .ssl_mode(pg_ssl_mode(config.tls.mode));
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

fn pg_ssl_mode(mode: DatabaseTlsMode) -> PgSslMode {
  match mode {
    DatabaseTlsMode::Off => PgSslMode::Disable,
    DatabaseTlsMode::VerifyFull => PgSslMode::VerifyFull,
  }
}

async fn init_managed_schema(pool: &Pool<Postgres>, table: &str) -> anyhow::Result<()> {
  let mut query = QueryBuilder::<Postgres>::new("CREATE TABLE IF NOT EXISTS ");
  query.push(table);
  query.push(
    " (
       id bigserial PRIMARY KEY,
       namespace text NOT NULL,
       dedupe_key text NOT NULL,
       status text NOT NULL DEFAULT 'pending',
       intent text NOT NULL,
       provider text NULL,
       target text NOT NULL,
       target_ip inet NULL,
       target_cidr cidr NULL,
       transport_network text NOT NULL,
       remote_ip inet NOT NULL,
       remote_port integer NOT NULL,
       count bigint NOT NULL DEFAULT 0,
       first_seen timestamptz NOT NULL,
       last_seen timestamptz NOT NULL,
       expires_at timestamptz NOT NULL,
       record jsonb NOT NULL,
       UNIQUE (namespace, dedupe_key)
     )",
  );
  query.build().execute(pool).await?;

  let mut index = QueryBuilder::<Postgres>::new("CREATE INDEX IF NOT EXISTS ");
  index.push(index_name_for_table(table, "status_expires_idx")?);
  index.push(" ON ");
  index.push(table);
  index.push(" (namespace, status, expires_at)");
  index.build().execute(pool).await?;

  let mut target = QueryBuilder::<Postgres>::new("CREATE INDEX IF NOT EXISTS ");
  target.push(index_name_for_table(table, "target_idx")?);
  target.push(" ON ");
  target.push(table);
  target.push(" (namespace, intent, target)");
  target.build().execute(pool).await?;
  Ok(())
}

async fn validate_existing_table(pool: &Pool<Postgres>, table: &str) -> anyhow::Result<()> {
  let event = MitigationEvent {
    intent: "observe".to_string(),
    provider: None,
    target: "127.0.0.1".to_string(),
    target_ip: Some(IpAddr::from([127, 0, 0, 1])),
    target_cidr: None,
    transport_network: "tcp".to_string(),
    remote_ip: IpAddr::from([127, 0, 0, 1]),
    remote_port: 0,
    dedupe_key: "validation".to_string(),
    occurred_at_unix_ms: 0,
    expires_at_unix_ms: 1_000,
    min_count: 1,
    record: JsonValue::Object(Default::default()),
  };
  let mut query = upsert_query(
    table,
    "oxibelt",
    &event,
    true,
    MitigationTableShape::Existing,
  )?;
  query.build().execute(pool).await?;
  Ok(())
}

async fn run_writer(
  pool: Pool<Postgres>,
  config: MitigationWriterConfig,
  metrics: Arc<Metrics>,
  mut receiver: mpsc::Receiver<MitigationEvent>,
) {
  while let Some(event) = receiver.recv().await {
    metrics.add_mitigation_queue_depth(-1);
    if let Err(error) = insert_event(&pool, &config, &event).await {
      metrics.record_mitigation_write_error();
      metrics.set_mitigation_writer_healthy(false);
      warn!(error = %error, "failed to write mitigation event to PostgreSQL");
    } else {
      metrics.set_mitigation_writer_healthy(true);
    }
  }
}

async fn insert_event(
  pool: &Pool<Postgres>,
  config: &MitigationWriterConfig,
  event: &MitigationEvent,
) -> anyhow::Result<()> {
  let mut query = upsert_query(&config.table, &config.namespace, event, false, config.shape)?;
  query.build().execute(pool).await?;
  Ok(())
}

fn upsert_query<'a>(
  table: &'a str,
  namespace: &'a str,
  event: &'a MitigationEvent,
  validate_only: bool,
  shape: MitigationTableShape,
) -> anyhow::Result<QueryBuilder<'a, Postgres>> {
  let initial_status = if event.min_count <= 1 {
    "pending"
  } else {
    "observing"
  };
  let occurred = i64::try_from(event.occurred_at_unix_ms).unwrap_or(i64::MAX);
  let expires = i64::try_from(event.expires_at_unix_ms).unwrap_or(i64::MAX);
  let remote_port = i32::from(event.remote_port);
  let mut query = QueryBuilder::<Postgres>::new("INSERT INTO ");
  query.push(table);
  query.push(" AS existing");
  match shape {
    MitigationTableShape::Managed => query.push(
      " (
         namespace, dedupe_key, status, intent, provider, target, target_ip, target_cidr,
         transport_network, remote_ip, remote_port, count, first_seen, last_seen, expires_at, record
       ) ",
    ),
    MitigationTableShape::Existing => query.push(
      " (
         namespace, dedupe_key, status, count, first_seen, last_seen, expires_at, record
       ) ",
    ),
  };
  if validate_only {
    query.push("SELECT ");
  } else {
    query.push("VALUES (");
  }
  query.push_bind(namespace);
  query.push(", ");
  query.push_bind(&event.dedupe_key);
  query.push(", ");
  query.push_bind(initial_status);
  if matches!(shape, MitigationTableShape::Managed) {
    query.push(", ");
    query.push_bind(&event.intent);
    query.push(", ");
    query.push_bind(event.provider.as_deref());
    query.push(", ");
    query.push_bind(&event.target);
    query.push(", ");
    query.push_bind(event.target_ip.map(|ip| ip.to_string()));
    query.push("::inet, ");
    query.push_bind(event.target_cidr.as_deref());
    query.push("::cidr, ");
    query.push_bind(&event.transport_network);
    query.push(", ");
    query.push_bind(event.remote_ip.to_string());
    query.push("::inet, ");
    query.push_bind(remote_port);
  }
  query.push(", 1, to_timestamp(");
  query.push_bind(occurred);
  query.push("::double precision / 1000.0), to_timestamp(");
  query.push_bind(occurred);
  query.push("::double precision / 1000.0), to_timestamp(");
  query.push_bind(expires);
  query.push("::double precision / 1000.0), ");
  query.push_bind(event.record.to_string());
  query.push("::jsonb");
  if validate_only {
    query.push(" WHERE false ");
  } else {
    query.push(") ");
  }
  query.push("ON CONFLICT (namespace, dedupe_key) DO UPDATE SET ");
  query.push("count = existing.count + 1, last_seen = EXCLUDED.last_seen, expires_at = EXCLUDED.expires_at, ");
  query.push("record = EXCLUDED.record, status = CASE WHEN ");
  query.push("existing.status = 'observing' AND existing.count + 1 >= ");
  query.push_bind(i64::try_from(event.min_count).unwrap_or(i64::MAX));
  query.push(" THEN 'pending' ELSE existing.status END");
  if validate_only {
    query.push(" WHERE false");
  }
  Ok(query)
}

fn index_name_for_table(table: &str, suffix: &str) -> anyhow::Result<String> {
  let unquoted = table
    .replace('"', "")
    .replace('.', "_")
    .chars()
    .map(|ch| {
      if ch.is_ascii_alphanumeric() || ch == '_' {
        ch
      } else {
        '_'
      }
    })
    .collect::<String>();
  let mut name = format!("{unquoted}_{suffix}");
  if name.len() > 63 {
    name.truncate(63);
  }
  if name.is_empty() {
    bail!("mitigation table index name cannot be empty");
  }
  Ok(format!("\"{name}\""))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn managed_index_names_are_bounded() {
    let table =
      "\"really_long_schema\".\"really_long_mitigation_table_name_that_needs_truncation\"";
    let name = index_name_for_table(table, "status_expires_idx").unwrap();

    assert!(name.len() <= 65);
    assert!(name.starts_with('"'));
  }

  #[test]
  fn upsert_preserves_controller_owned_statuses() {
    let event = MitigationEvent {
      intent: "rtbh".to_string(),
      provider: Some("isp".to_string()),
      target: "203.0.113.10".to_string(),
      target_ip: Some("203.0.113.10".parse().unwrap()),
      target_cidr: None,
      transport_network: "tcp".to_string(),
      remote_ip: "203.0.113.10".parse().unwrap(),
      remote_port: 443,
      dedupe_key: "key".to_string(),
      occurred_at_unix_ms: 1_700_000_000_000,
      expires_at_unix_ms: 1_700_000_300_000,
      min_count: 3,
      record: JsonValue::Object(Default::default()),
    };
    let query = upsert_query(
      "\"oxibelt_mitigation_events\"",
      "oxibelt",
      &event,
      false,
      MitigationTableShape::Managed,
    )
    .unwrap();
    let sql = query.sql();

    assert!(sql.contains("status = CASE WHEN"));
    assert!(sql.contains(".status = 'observing'"));
    assert!(sql.contains("THEN 'pending' ELSE"));
  }

  #[test]
  fn existing_upsert_uses_minimum_contract_columns() {
    let event = MitigationEvent {
      intent: "rtbh".to_string(),
      provider: Some("isp".to_string()),
      target: "203.0.113.10".to_string(),
      target_ip: Some("203.0.113.10".parse().unwrap()),
      target_cidr: None,
      transport_network: "tcp".to_string(),
      remote_ip: "203.0.113.10".parse().unwrap(),
      remote_port: 443,
      dedupe_key: "key".to_string(),
      occurred_at_unix_ms: 1_700_000_000_000,
      expires_at_unix_ms: 1_700_000_300_000,
      min_count: 1,
      record: JsonValue::Object(Default::default()),
    };
    let query = upsert_query(
      "\"existing_mitigation_events\"",
      "oxibelt",
      &event,
      false,
      MitigationTableShape::Existing,
    )
    .unwrap();
    let sql = query.sql();

    assert!(sql.contains("namespace, dedupe_key, status, count"));
    assert!(!sql.contains("intent, provider, target"));
    assert!(sql.contains("ON CONFLICT (namespace, dedupe_key)"));
  }
}

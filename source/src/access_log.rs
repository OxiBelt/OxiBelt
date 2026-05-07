use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, anyhow};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{Pool, Postgres, QueryBuilder};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::config::{DatabaseAccessLogConfig, DatabaseTlsMode, LoggingAccessLogConfig};
use crate::waf::{
  AccessLogRecord, CompiledAccessLogFields, WafEngine, WafResponseInput, compile_access_log_fields,
};

#[derive(Clone)]
pub struct AccessLogSinks {
  stdout: bool,
  database: Option<DatabaseAccessLogSink>,
}

impl AccessLogSinks {
  pub fn disabled() -> Self {
    Self {
      stdout: false,
      database: None,
    }
  }

  pub async fn new(config: &DatabaseAccessLogConfig) -> anyhow::Result<Self> {
    Self::new_with_options(config, true, "OxiRule access log", "database.access_log").await
  }

  pub async fn new_with_options(
    config: &DatabaseAccessLogConfig,
    stdout: bool,
    label: &'static str,
    config_prefix: &'static str,
  ) -> anyhow::Result<Self> {
    let database = if config.enabled {
      Some(DatabaseAccessLogSink::connect(config, label, config_prefix).await?)
    } else {
      None
    };

    Ok(Self { stdout, database })
  }

  pub fn emit(&self, record: &AccessLogRecord) {
    if self.stdout {
      record.emit_stdout();
    }

    if let Some(database) = &self.database {
      database.enqueue(record.clone());
    }
  }
}

#[derive(Clone)]
struct DatabaseAccessLogSink {
  sender: mpsc::Sender<AccessLogRecord>,
}

impl DatabaseAccessLogSink {
  async fn connect(
    config: &DatabaseAccessLogConfig,
    label: &'static str,
    config_prefix: &'static str,
  ) -> anyhow::Result<Self> {
    let connection_url = config
      .connection_url_with_prefix(config_prefix)?
      .ok_or_else(|| anyhow!("{label} connection URL is required when enabled"))?;
    let table = config
      .table_name_with_prefix(config_prefix)?
      .ok_or_else(|| anyhow!("{label} table is required when enabled"))?;
    let pool = connect_pool(config, &connection_url)
      .await
      .with_context(|| format!("failed to connect {label} PostgreSQL pool"))?;

    validate_table(&pool, &table).await.with_context(|| {
      format!(
        "failed to validate {label} table {}",
        config.table.as_deref().unwrap_or("<missing>")
      )
    })?;

    let (sender, receiver) = mpsc::channel(config.queue_capacity);
    tokio::spawn(run_database_writer(pool, table, label, receiver));
    info!(label, "database access log sink initialized");

    Ok(Self { sender })
  }

  fn enqueue(&self, record: AccessLogRecord) {
    match self.sender.try_send(record) {
      Ok(()) => {}
      Err(mpsc::error::TrySendError::Full(_)) => {
        warn!("database access log queue is full; dropping access log record");
      }
      Err(mpsc::error::TrySendError::Closed(_)) => {
        warn!("database access log writer is closed; dropping access log record");
      }
    }
  }
}

async fn connect_pool(
  config: &DatabaseAccessLogConfig,
  connection_url: &str,
) -> anyhow::Result<Pool<Postgres>> {
  let mut options = PgConnectOptions::from_str(connection_url)
    .context("failed to parse database.access_log PostgreSQL connection URL")?
    .application_name("oxibelt-access-log")
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

async fn validate_table(pool: &Pool<Postgres>, table: &str) -> anyhow::Result<()> {
  let mut query = QueryBuilder::<Postgres>::new("INSERT INTO ");
  query.push(table);
  query.push(" (event, timestamp_unix_ms, record) SELECT ");
  query.push_bind(AccessLogRecord::EVENT);
  query.push(", ");
  query.push_bind(0_i64);
  query.push(", ");
  query.push_bind("{}");
  query.push("::jsonb WHERE false");
  query.build().execute(pool).await?;
  Ok(())
}

async fn run_database_writer(
  pool: Pool<Postgres>,
  table: String,
  label: &'static str,
  mut receiver: mpsc::Receiver<AccessLogRecord>,
) {
  while let Some(record) = receiver.recv().await {
    if let Err(error) = insert_record(&pool, &table, &record).await {
      warn!(error = %error, label, "failed to write access log to PostgreSQL");
    }
  }
}

#[derive(Clone)]
pub struct SystemAccessLog {
  enabled: bool,
  fields: CompiledAccessLogFields,
  sinks: AccessLogSinks,
}

impl SystemAccessLog {
  pub async fn new(config: &LoggingAccessLogConfig) -> anyhow::Result<Self> {
    let fields = compile_access_log_fields("logging.access_log", &config.fields)?;
    let sinks = if config.enabled {
      AccessLogSinks::new_with_options(
        &config.database,
        config.stdout,
        "system access log",
        "logging.access_log.database",
      )
      .await?
    } else {
      AccessLogSinks::disabled()
    };

    Ok(Self {
      enabled: config.enabled,
      fields,
      sinks,
    })
  }

  pub fn enabled(&self) -> bool {
    self.enabled
  }

  pub fn emit(&self, waf: &WafEngine, input: WafResponseInput<'_>) {
    if !self.enabled {
      return;
    }
    match waf.build_system_access_log(&self.fields, input) {
      Ok(record) => self.sinks.emit(&record),
      Err(error) => warn!(error = %error, "failed to build system access log record"),
    }
  }
}

async fn insert_record(
  pool: &Pool<Postgres>,
  table: &str,
  record: &AccessLogRecord,
) -> anyhow::Result<()> {
  let timestamp_unix_ms = i64::try_from(record.timestamp_unix_ms()).unwrap_or(i64::MAX);
  let json_line = record.to_json_line();
  let mut query = QueryBuilder::<Postgres>::new("INSERT INTO ");
  query.push(table);
  query.push(" (event, timestamp_unix_ms, record) VALUES (");
  query.push_bind(AccessLogRecord::EVENT);
  query.push(", ");
  query.push_bind(timestamp_unix_ms);
  query.push(", ");
  query.push_bind(json_line);
  query.push("::jsonb)");
  query.build().execute(pool).await?;
  Ok(())
}

#[cfg(test)]
mod tests {
  use crate::config::quote_postgres_identifier_path;

  #[test]
  fn postgres_identifier_path_is_quoted() {
    let quoted = quote_postgres_identifier_path("database.access_log.table", "audit.access_log")
      .expect("identifier should quote");

    assert_eq!(quoted, "\"audit\".\"access_log\"");
  }

  #[test]
  fn postgres_identifier_path_rejects_injection_punctuation() {
    let error =
      quote_postgres_identifier_path("database.access_log.table", "audit.access_log;DROP")
        .expect_err("unsafe identifier should fail");

    assert!(
      error
        .to_string()
        .contains("must contain only ASCII letters"),
      "unexpected error: {error}"
    );
  }
}

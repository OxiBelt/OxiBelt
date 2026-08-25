use std::path::Path;
use std::str::FromStr as _;
use std::time::Duration;

use anyhow::{Context, bail};
use oxibelt::ct_runtime::{CT_POSTGRES_SCHEMA_VERSION, CtPostgresStore};
use sqlx::Executor as _;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::cli::{CtPostgresArgs, CtPostgresSubcommand, DEFAULT_CT_POSTGRES_URL_ENV};
use crate::ct_io::read_bounded;

const MAX_DATABASE_URL_BYTES: u64 = 64 * 1024;

pub(crate) async fn run(command: &CtPostgresSubcommand) -> anyhow::Result<i32> {
  match command {
    CtPostgresSubcommand::Migrate(args) => {
      let url = database_url(args)?;
      CtPostgresStore::migrate(&url).await?;
      println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
          "component": "certificate_transparency",
          "schema_version": CT_POSTGRES_SCHEMA_VERSION,
          "migrated": true,
        }))?
      );
      Ok(0)
    }
    CtPostgresSubcommand::StorageCheck(args) => storage_check(args).await,
  }
}

async fn storage_check(args: &CtPostgresArgs) -> anyhow::Result<i32> {
  let url = database_url(args)?;
  let options = PgConnectOptions::from_str(&url)
    .context("invalid CT PostgreSQL URL")?
    .application_name("oxibeltctl-ct-storage-check")
    .options([
      ("default_transaction_read_only", "on"),
      ("statement_timeout", "30s"),
      ("lock_timeout", "5s"),
    ]);
  let pool = PgPoolOptions::new()
    .max_connections(1)
    .acquire_timeout(Duration::from_secs(10))
    .connect_with(options)
    .await
    .context("failed to connect for CT PostgreSQL storage check")?;
  let mut transaction = pool
    .begin()
    .await
    .context("failed to begin CT storage check")?;
  transaction
    .execute("SET TRANSACTION READ ONLY")
    .await
    .context("failed to make CT storage check read-only")?;
  let schema_version: Option<i32> = sqlx::query_scalar(
    "SELECT version FROM oxibelt_ct_schema_migrations WHERE component='certificate_transparency'",
  )
  .fetch_optional(&mut *transaction)
  .await
  .context("failed to read CT schema version; run `oxibeltctl ct postgres migrate` first")?;
  if schema_version != Some(CT_POSTGRES_SCHEMA_VERSION) {
    bail!(
      "CT PostgreSQL schema version is {:?}, expected {}",
      schema_version,
      CT_POSTGRES_SCHEMA_VERSION
    );
  }
  const TABLES: [&str; 4] = [
    "oxibelt_ct_logs",
    "oxibelt_ct_entries",
    "oxibelt_ct_nodes",
    "oxibelt_ct_frontier",
  ];
  for table in TABLES {
    let present: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
      .bind(format!("public.{table}"))
      .fetch_one(&mut *transaction)
      .await
      .with_context(|| format!("failed to inspect CT table {table}"))?;
    if !present {
      bail!("CT PostgreSQL table {table} is missing");
    }
    let selectable: bool =
      sqlx::query_scalar("SELECT has_table_privilege(current_user, $1, 'SELECT')")
        .bind(format!("public.{table}"))
        .fetch_one(&mut *transaction)
        .await
        .with_context(|| format!("failed to inspect SELECT privilege for CT table {table}"))?;
    if !selectable {
      bail!("current PostgreSQL role lacks SELECT on CT table {table}");
    }
  }
  let server_version: String = sqlx::query_scalar("SHOW server_version")
    .fetch_one(&mut *transaction)
    .await
    .context("failed to read PostgreSQL server version")?;
  transaction
    .rollback()
    .await
    .context("failed to close CT storage check")?;
  println!(
    "{}",
    serde_json::to_string_pretty(&serde_json::json!({
      "component": "certificate_transparency",
      "schema_version": schema_version,
      "server_version": server_version,
      "tables": TABLES,
      "read_only_check": true,
    }))?
  );
  Ok(0)
}

fn database_url(args: &CtPostgresArgs) -> anyhow::Result<String> {
  let value = match &args.database_url_file {
    Some(path) => {
      validate_secret_file_permissions(path)?;
      String::from_utf8(read_bounded(
        path,
        MAX_DATABASE_URL_BYTES,
        "CT PostgreSQL URL file",
      )?)
      .context("CT PostgreSQL URL file is not UTF-8")?
    }
    None => {
      let environment = args
        .database_url_env
        .as_deref()
        .unwrap_or(DEFAULT_CT_POSTGRES_URL_ENV);
      validate_environment_name(environment)?;
      std::env::var(environment).with_context(|| {
        format!("CT PostgreSQL URL environment variable {environment} is not set")
      })?
    }
  };
  let value = value.trim();
  if value.is_empty() || value.len() > MAX_DATABASE_URL_BYTES as usize {
    bail!("CT PostgreSQL URL is empty or too large");
  }
  if !value.starts_with("postgres://") && !value.starts_with("postgresql://") {
    bail!("CT PostgreSQL URL must use postgres:// or postgresql://");
  }
  Ok(value.to_string())
}

fn validate_environment_name(value: &str) -> anyhow::Result<()> {
  if value.is_empty()
    || value.len() > 128
    || !value.bytes().enumerate().all(|(index, byte)| {
      byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
    })
  {
    bail!("CT PostgreSQL URL environment variable name is invalid");
  }
  Ok(())
}

#[cfg(unix)]
fn validate_secret_file_permissions(path: &Path) -> anyhow::Result<()> {
  use std::os::unix::fs::MetadataExt as _;

  let metadata = std::fs::metadata(path)?;
  if metadata.mode() & 0o077 != 0 {
    bail!(
      "CT PostgreSQL URL file {} must not be accessible by group or other",
      path.display()
    );
  }
  Ok(())
}

#[cfg(not(unix))]
fn validate_secret_file_permissions(_path: &Path) -> anyhow::Result<()> {
  Ok(())
}

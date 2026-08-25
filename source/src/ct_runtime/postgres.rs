//! PostgreSQL linearization, append-only entry state, and fenced publisher leases.

use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use sha2::{Digest as _, Sha256};
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{Postgres, Row, Transaction};

pub const CT_POSTGRES_SCHEMA_VERSION: i32 = 3;
const MAX_ENTRY_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECEIPT_BYTES: usize = 1024 * 1024;
const MAX_LEASE_MILLIS: i64 = 60_000;

pub const CT_POSTGRES_MIGRATION_V1: &[&str] = &[
  "CREATE TABLE IF NOT EXISTS oxibelt_ct_schema_migrations (component TEXT PRIMARY KEY, version INTEGER NOT NULL CHECK (version > 0), applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())",
  "CREATE TABLE IF NOT EXISTS oxibelt_ct_logs (log_name TEXT PRIMARY KEY, protocol TEXT NOT NULL, public_identity BYTEA NOT NULL, log_identifier TEXT NOT NULL, mmd_millis BIGINT NOT NULL CHECK (mmd_millis > 0), next_leaf_index BIGINT NOT NULL DEFAULT 0 CHECK (next_leaf_index >= 0), last_timestamp_millis BIGINT NOT NULL DEFAULT 0 CHECK (last_timestamp_millis >= 0), last_sth_timestamp_millis BIGINT NOT NULL DEFAULT 0 CHECK (last_sth_timestamp_millis >= 0), tree_size BIGINT NOT NULL DEFAULT 0 CHECK (tree_size >= 0), tree_root BYTEA NOT NULL DEFAULT decode('', 'hex'), published_tree_size BIGINT NOT NULL DEFAULT 0 CHECK (published_tree_size >= 0), checkpoint_etag TEXT, checkpoint_version TEXT, checkpoint_published_at TIMESTAMPTZ, frozen_reason TEXT, publisher_holder TEXT, publisher_epoch BIGINT NOT NULL DEFAULT 0 CHECK (publisher_epoch >= 0), publisher_lease_until TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())",
  "CREATE TABLE IF NOT EXISTS oxibelt_ct_entries (log_name TEXT NOT NULL REFERENCES oxibelt_ct_logs(log_name), leaf_index BIGINT NOT NULL CHECK (leaf_index >= 0), entry_key BYTEA NOT NULL, timestamp_millis BIGINT NOT NULL CHECK (timestamp_millis >= 0), leaf_input BYTEA NOT NULL, extra_data BYTEA NOT NULL, leaf_hash BYTEA NOT NULL, receipt BYTEA, integrated BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY (log_name, leaf_index), UNIQUE (log_name, entry_key))",
  "CREATE TABLE IF NOT EXISTS oxibelt_ct_nodes (log_name TEXT NOT NULL REFERENCES oxibelt_ct_logs(log_name), level INTEGER NOT NULL CHECK (level >= 0 AND level <= 63), node_index BIGINT NOT NULL CHECK (node_index >= 0), hash BYTEA NOT NULL, PRIMARY KEY (log_name, level, node_index))",
  "CREATE TABLE IF NOT EXISTS oxibelt_ct_frontier (log_name TEXT NOT NULL REFERENCES oxibelt_ct_logs(log_name), level INTEGER NOT NULL CHECK (level >= 0 AND level <= 63), hash BYTEA NOT NULL, PRIMARY KEY (log_name, level))",
  "CREATE INDEX IF NOT EXISTS oxibelt_ct_entries_publish_idx ON oxibelt_ct_entries(log_name, integrated, leaf_index)",
  "INSERT INTO oxibelt_ct_schema_migrations(component, version) VALUES ('certificate_transparency', 1) ON CONFLICT (component) DO UPDATE SET version = EXCLUDED.version, applied_at = clock_timestamp()",
];

pub const CT_POSTGRES_MIGRATION_V2: &[&str] = &[
  "ALTER TABLE oxibelt_ct_logs ADD COLUMN IF NOT EXISTS last_sth_timestamp_millis BIGINT NOT NULL DEFAULT 0 CHECK (last_sth_timestamp_millis >= 0)",
  "INSERT INTO oxibelt_ct_schema_migrations(component, version) VALUES ('certificate_transparency', 2) ON CONFLICT (component) DO UPDATE SET version = EXCLUDED.version, applied_at = clock_timestamp()",
];

pub const CT_POSTGRES_MIGRATION_V3: &[&str] = &[
  "ALTER TABLE oxibelt_ct_logs ADD COLUMN IF NOT EXISTS checkpoint_published_at TIMESTAMPTZ",
  "INSERT INTO oxibelt_ct_schema_migrations(component, version) VALUES ('certificate_transparency', 3) ON CONFLICT (component) DO UPDATE SET version = EXCLUDED.version, applied_at = clock_timestamp()",
];

#[derive(Clone, Debug)]
pub struct CtLogBinding {
  pub log_name: String,
  pub protocol: String,
  pub public_identity: Vec<u8>,
  pub log_identifier: String,
  pub mmd_millis: u64,
}

#[derive(Clone, Debug)]
pub struct CtReservedEntry {
  pub leaf_index: u64,
  pub timestamp_millis: u64,
  pub receipt: Option<Vec<u8>>,
  pub newly_reserved: bool,
}

#[derive(Clone, Debug)]
pub struct CtStoredEntry {
  pub leaf_index: u64,
  pub timestamp_millis: u64,
  pub leaf_input: Vec<u8>,
  pub extra_data: Vec<u8>,
  pub leaf_hash: [u8; 32],
  pub receipt: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct CtTreeState {
  pub tree_size: u64,
  pub root_hash: [u8; 32],
  pub published_tree_size: u64,
  pub checkpoint_etag: Option<String>,
  pub checkpoint_version: Option<String>,
  pub checkpoint_published_millis: Option<u64>,
  pub frozen_reason: Option<String>,
}

#[derive(Clone)]
pub struct CtPostgresStore {
  pool: PgPool,
  log_name: String,
}

impl CtPostgresStore {
  pub async fn connect_checked(
    database_url: &str,
    max_connections: u32,
    binding: &CtLogBinding,
  ) -> anyhow::Result<Self> {
    validate_binding(binding)?;
    if max_connections == 0 || max_connections > 64 {
      bail!("CT PostgreSQL max_connections must be within 1..=64");
    }
    let pool = PgPoolOptions::new()
      .max_connections(max_connections)
      .acquire_timeout(Duration::from_secs(5))
      .connect(database_url)
      .await
      .context("failed to connect to CT PostgreSQL store")?;
    verify_schema(&pool).await?;
    bind_log_identity(&pool, binding).await?;
    Ok(Self {
      pool,
      log_name: binding.log_name.clone(),
    })
  }

  pub async fn migrate(database_url: &str) -> anyhow::Result<()> {
    let pool = PgPoolOptions::new()
      .max_connections(1)
      .acquire_timeout(Duration::from_secs(10))
      .connect(database_url)
      .await
      .context("failed to connect for CT PostgreSQL migration")?;
    let mut transaction = pool.begin().await.context("failed to begin CT migration")?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
      .bind(stable_lock_id("oxibelt-certificate-transparency-schema"))
      .execute(&mut *transaction)
      .await
      .context("failed to acquire CT schema migration lock")?;
    for statement in CT_POSTGRES_MIGRATION_V1 {
      sqlx::query(*statement)
        .execute(&mut *transaction)
        .await
        .context("failed to apply CT schema migration")?;
    }
    for statement in CT_POSTGRES_MIGRATION_V2 {
      sqlx::query(*statement)
        .execute(&mut *transaction)
        .await
        .context("failed to apply CT schema migration v2")?;
    }
    for statement in CT_POSTGRES_MIGRATION_V3 {
      sqlx::query(*statement)
        .execute(&mut *transaction)
        .await
        .context("failed to apply CT schema migration v3")?;
    }
    transaction
      .commit()
      .await
      .context("failed to commit CT schema migration")?;
    verify_schema(&pool).await
  }

  pub async fn reserve_entry(
    &self,
    entry_key: &[u8; 32],
    leaf_input: &[u8],
    extra_data: &[u8],
    leaf_hash: &[u8; 32],
  ) -> anyhow::Result<CtReservedEntry> {
    self
      .reserve_entry_with(entry_key, |_, _| {
        Ok((leaf_input.to_vec(), extra_data.to_vec(), *leaf_hash))
      })
      .await
  }

  /// Atomically assigns the durable index and database timestamp before the caller builds the
  /// protocol leaf. Static CT binds both values into the signed receipt and Merkle leaf, so the
  /// builder must run while the sequencer row is locked.
  pub async fn reserve_entry_with<F>(
    &self,
    entry_key: &[u8; 32],
    build: F,
  ) -> anyhow::Result<CtReservedEntry>
  where
    F: FnOnce(u64, u64) -> anyhow::Result<(Vec<u8>, Vec<u8>, [u8; 32])>,
  {
    self
      .reserve_entry_with_limit(entry_key, usize::MAX, build)
      .await
  }

  pub async fn reserve_entry_with_limit<F>(
    &self,
    entry_key: &[u8; 32],
    max_pending_entries: usize,
    build: F,
  ) -> anyhow::Result<CtReservedEntry>
  where
    F: FnOnce(u64, u64) -> anyhow::Result<(Vec<u8>, Vec<u8>, [u8; 32])>,
  {
    let mut transaction = self
      .pool
      .begin()
      .await
      .context("failed to begin CT append")?;
    let log = lock_log(&mut transaction, &self.log_name).await?;
    ensure_not_frozen(&log)?;
    if let Some(existing) = sqlx::query(
      "SELECT leaf_index, timestamp_millis, receipt FROM oxibelt_ct_entries WHERE log_name=$1 AND entry_key=$2",
    )
    .bind(&self.log_name)
    .bind(entry_key.as_slice())
    .fetch_optional(&mut *transaction)
    .await
    .context("failed to check CT duplicate entry")?
    {
      transaction.commit().await.context("failed to finish CT duplicate lookup")?;
      return Ok(CtReservedEntry {
        leaf_index: to_u64(existing.try_get::<i64, _>("leaf_index")?, "leaf index")?,
        timestamp_millis: to_u64(
          existing.try_get::<i64, _>("timestamp_millis")?,
          "timestamp",
        )?,
        receipt: existing.try_get("receipt")?,
        newly_reserved: false,
      });
    }
    let has_unsigned_reservation: bool = sqlx::query_scalar(
      "SELECT EXISTS(SELECT 1 FROM oxibelt_ct_entries WHERE log_name=$1 AND receipt IS NULL)",
    )
    .bind(&self.log_name)
    .fetch_one(&mut *transaction)
    .await
    .context("failed to check CT unsigned reservations")?;
    if has_unsigned_reservation {
      bail!("CT has an unsigned reservation; retry that exact submission first");
    }
    let next_leaf_index = log.try_get::<i64, _>("next_leaf_index")?;
    let tree_size = log.try_get::<i64, _>("tree_size")?;
    let maximum_pending = i64::try_from(max_pending_entries).unwrap_or(i64::MAX);
    if next_leaf_index.saturating_sub(tree_size) >= maximum_pending {
      bail!("CT pending-entry limit is exhausted");
    }
    let last_timestamp = log.try_get::<i64, _>("last_timestamp_millis")?;
    let database_now = sqlx::query_scalar::<_, i64>(
      "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
    )
    .fetch_one(&mut *transaction)
    .await
    .context("failed to read CT database clock")?;
    let timestamp = database_now.max(last_timestamp.saturating_add(1));
    let leaf_index = to_u64(next_leaf_index, "leaf index")?;
    let timestamp_millis = to_u64(timestamp, "timestamp")?;
    let (leaf_input, extra_data, leaf_hash) = build(leaf_index, timestamp_millis)?;
    validate_entry_bytes(&leaf_input, &extra_data)?;
    sqlx::query(
      "INSERT INTO oxibelt_ct_entries(log_name,leaf_index,entry_key,timestamp_millis,leaf_input,extra_data,leaf_hash) VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(&self.log_name)
    .bind(next_leaf_index)
    .bind(entry_key.as_slice())
    .bind(timestamp)
    .bind(&leaf_input)
    .bind(&extra_data)
    .bind(leaf_hash.as_slice())
    .execute(&mut *transaction)
    .await
    .context("failed to reserve CT entry")?;
    sqlx::query(
      "UPDATE oxibelt_ct_logs SET next_leaf_index=$2,last_timestamp_millis=$3 WHERE log_name=$1",
    )
    .bind(&self.log_name)
    .bind(next_leaf_index.saturating_add(1))
    .bind(timestamp)
    .execute(&mut *transaction)
    .await
    .context("failed to advance CT sequencer")?;
    transaction
      .commit()
      .await
      .context("failed to commit CT reservation")?;
    Ok(CtReservedEntry {
      leaf_index,
      timestamp_millis,
      receipt: None,
      newly_reserved: true,
    })
  }

  pub async fn record_receipt(&self, leaf_index: u64, receipt: &[u8]) -> anyhow::Result<()> {
    if receipt.is_empty() || receipt.len() > MAX_RECEIPT_BYTES {
      bail!("CT receipt length is outside 1..={MAX_RECEIPT_BYTES}");
    }
    let leaf_index = to_i64(leaf_index, "leaf index")?;
    let result = sqlx::query(
      "UPDATE oxibelt_ct_entries SET receipt=$3 WHERE log_name=$1 AND leaf_index=$2 AND (receipt IS NULL OR receipt=$3)",
    )
    .bind(&self.log_name)
    .bind(leaf_index)
    .bind(receipt)
    .execute(&self.pool)
    .await
    .context("failed to persist CT receipt")?;
    if result.rows_affected() != 1 {
      bail!("CT receipt is missing or differs from the durable receipt");
    }
    Ok(())
  }

  pub async fn discard_unsigned_tail(&self, leaf_index: u64) -> anyhow::Result<()> {
    let leaf_index = to_i64(leaf_index, "leaf index")?;
    let mut transaction = self
      .pool
      .begin()
      .await
      .context("failed to begin CT unsigned-reservation cleanup")?;
    let log = lock_log(&mut transaction, &self.log_name).await?;
    let next_leaf_index = log.try_get::<i64, _>("next_leaf_index")?;
    let tree_size = log.try_get::<i64, _>("tree_size")?;
    if next_leaf_index != leaf_index.saturating_add(1) || tree_size > leaf_index {
      bail!("CT unsigned cleanup is not the unintegrated sequencer tail");
    }
    let deleted = sqlx::query(
      "DELETE FROM oxibelt_ct_entries WHERE log_name=$1 AND leaf_index=$2 AND receipt IS NULL AND integrated=FALSE",
    )
    .bind(&self.log_name)
    .bind(leaf_index)
    .execute(&mut *transaction)
    .await
    .context("failed to delete CT unsigned tail reservation")?;
    if deleted.rows_affected() == 0 {
      transaction
        .rollback()
        .await
        .context("failed to finish no-op CT unsigned cleanup")?;
      return Ok(());
    }
    if deleted.rows_affected() != 1 {
      bail!("CT unsigned cleanup deleted an unexpected number of rows");
    }
    sqlx::query("UPDATE oxibelt_ct_logs SET next_leaf_index=$2 WHERE log_name=$1")
      .bind(&self.log_name)
      .bind(leaf_index)
      .execute(&mut *transaction)
      .await
      .context("failed to rewind CT sequencer after unsigned cleanup")?;
    transaction
      .commit()
      .await
      .context("failed to commit CT unsigned-reservation cleanup")
  }

  pub async fn reserve_sth_timestamp(&self) -> anyhow::Result<u64> {
    let mut transaction = self
      .pool
      .begin()
      .await
      .context("failed to begin CT STH timestamp reservation")?;
    let log = lock_log(&mut transaction, &self.log_name).await?;
    ensure_not_frozen(&log)?;
    let last_entry = log.try_get::<i64, _>("last_timestamp_millis")?;
    let last_sth = log.try_get::<i64, _>("last_sth_timestamp_millis")?;
    let database_now = sqlx::query_scalar::<_, i64>(
      "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
    )
    .fetch_one(&mut *transaction)
    .await
    .context("failed to read CT database clock for STH")?;
    let timestamp = database_now.max(last_entry).max(last_sth.saturating_add(1));
    sqlx::query("UPDATE oxibelt_ct_logs SET last_sth_timestamp_millis=$2 WHERE log_name=$1")
      .bind(&self.log_name)
      .bind(timestamp)
      .execute(&mut *transaction)
      .await
      .context("failed to reserve CT STH timestamp")?;
    transaction
      .commit()
      .await
      .context("failed to commit CT STH timestamp reservation")?;
    to_u64(timestamp, "STH timestamp")
  }

  pub async fn next_unintegrated(&self) -> anyhow::Result<Option<CtStoredEntry>> {
    let row = sqlx::query(
      "SELECT leaf_index,timestamp_millis,leaf_input,extra_data,leaf_hash,receipt FROM oxibelt_ct_entries WHERE log_name=$1 AND integrated=FALSE AND receipt IS NOT NULL ORDER BY leaf_index LIMIT 1",
    )
    .bind(&self.log_name)
    .fetch_optional(&self.pool)
    .await
    .context("failed to load next CT entry")?;
    row.map(|row| stored_entry_from_row(&row)).transpose()
  }

  pub async fn integrate_next(
    &self,
    expected_leaf_index: u64,
    leaf_hash: [u8; 32],
    holder: &str,
    epoch: u64,
  ) -> anyhow::Result<CtTreeState> {
    let expected_leaf_index_i64 = to_i64(expected_leaf_index, "leaf index")?;
    let epoch_i64 = to_i64(epoch, "publisher epoch")?;
    let mut transaction = self
      .pool
      .begin()
      .await
      .context("failed to begin CT integration")?;
    let log = lock_log(&mut transaction, &self.log_name).await?;
    ensure_not_frozen(&log)?;
    assert_publisher(&log, holder, epoch_i64)?;
    let tree_size = log.try_get::<i64, _>("tree_size")?;
    if tree_size != expected_leaf_index_i64 {
      bail!("CT integration must advance exactly the current tree size");
    }
    let entry_hash = sqlx::query_scalar::<_, Vec<u8>>(
      "SELECT leaf_hash FROM oxibelt_ct_entries WHERE log_name=$1 AND leaf_index=$2 AND receipt IS NOT NULL AND integrated=FALSE FOR UPDATE",
    )
    .bind(&self.log_name)
    .bind(expected_leaf_index_i64)
    .fetch_optional(&mut *transaction)
    .await
    .context("failed to lock CT entry for integration")?
    .ok_or_else(|| anyhow!("CT entry is not ready for integration"))?;
    if entry_hash.as_slice() != leaf_hash {
      bail!("CT entry leaf hash changed before integration");
    }

    sqlx::query(
      "INSERT INTO oxibelt_ct_nodes(log_name,level,node_index,hash) VALUES ($1,0,$2,$3) ON CONFLICT DO NOTHING",
    )
    .bind(&self.log_name)
    .bind(expected_leaf_index_i64)
    .bind(leaf_hash.as_slice())
    .execute(&mut *transaction)
    .await
    .context("failed to persist CT leaf node")?;

    let mut carry = leaf_hash;
    let mut level = 0_i32;
    let mut cursor = expected_leaf_index;
    while cursor & 1 == 1 {
      let left = sqlx::query_scalar::<_, Vec<u8>>(
        "DELETE FROM oxibelt_ct_frontier WHERE log_name=$1 AND level=$2 RETURNING hash",
      )
      .bind(&self.log_name)
      .bind(level)
      .fetch_one(&mut *transaction)
      .await
      .context("CT frontier is missing a required left subtree")?;
      let left = digest_from_vec(left, "frontier hash")?;
      carry = hash_node(&left, &carry);
      level += 1;
      cursor >>= 1;
      let result = sqlx::query(
        "INSERT INTO oxibelt_ct_nodes(log_name,level,node_index,hash) VALUES ($1,$2,$3,$4) ON CONFLICT (log_name,level,node_index) DO UPDATE SET hash=EXCLUDED.hash WHERE oxibelt_ct_nodes.hash=EXCLUDED.hash",
      )
      .bind(&self.log_name)
      .bind(level)
      .bind(to_i64(expected_leaf_index >> u32::try_from(level).unwrap_or(63), "node index")?)
      .bind(carry.as_slice())
      .execute(&mut *transaction)
      .await
      .context("failed to persist CT parent node")?;
      if result.rows_affected() != 1 {
        bail!("CT durable node conflicts with the reconstructed tree");
      }
    }
    sqlx::query(
      "INSERT INTO oxibelt_ct_frontier(log_name,level,hash) VALUES ($1,$2,$3) ON CONFLICT (log_name,level) DO UPDATE SET hash=EXCLUDED.hash",
    )
    .bind(&self.log_name)
    .bind(level)
    .bind(carry.as_slice())
    .execute(&mut *transaction)
    .await
    .context("failed to update CT frontier")?;
    let root_hash = load_frontier_root(&mut transaction, &self.log_name).await?;
    sqlx::query(
      "UPDATE oxibelt_ct_entries SET integrated=TRUE WHERE log_name=$1 AND leaf_index=$2",
    )
    .bind(&self.log_name)
    .bind(expected_leaf_index_i64)
    .execute(&mut *transaction)
    .await
    .context("failed to mark CT entry integrated")?;
    sqlx::query("UPDATE oxibelt_ct_logs SET tree_size=$2,tree_root=$3 WHERE log_name=$1")
      .bind(&self.log_name)
      .bind(tree_size.saturating_add(1))
      .bind(root_hash.as_slice())
      .execute(&mut *transaction)
      .await
      .context("failed to advance CT tree state")?;
    transaction
      .commit()
      .await
      .context("failed to commit CT integration")?;
    self.tree_state().await
  }

  pub async fn try_acquire_publisher_lease(
    &self,
    holder: &str,
    lease_millis: u64,
  ) -> anyhow::Result<Option<u64>> {
    validate_identifier(holder, "publisher holder")?;
    let lease_millis = to_i64(lease_millis, "lease milliseconds")?;
    if lease_millis == 0 || lease_millis > MAX_LEASE_MILLIS {
      bail!("CT publisher lease must be within 1..={MAX_LEASE_MILLIS} milliseconds");
    }
    let mut transaction = self
      .pool
      .begin()
      .await
      .context("failed to begin CT lease")?;
    let log = lock_log(&mut transaction, &self.log_name).await?;
    ensure_not_frozen(&log)?;
    let existing_holder: Option<String> = log.try_get("publisher_holder")?;
    let lease_active = log.try_get::<bool, _>("publisher_lease_active")?;
    if lease_active && existing_holder.as_deref() != Some(holder) {
      transaction
        .rollback()
        .await
        .context("failed to finish CT standby lease observation")?;
      return Ok(None);
    }
    let prior_epoch = log.try_get::<i64, _>("publisher_epoch")?;
    let epoch = if existing_holder.as_deref() == Some(holder) && lease_active {
      prior_epoch
    } else {
      prior_epoch
        .checked_add(1)
        .ok_or_else(|| anyhow!("CT publisher epoch exhausted"))?
    };
    sqlx::query(
      "UPDATE oxibelt_ct_logs SET publisher_holder=$2,publisher_epoch=$3,publisher_lease_until=clock_timestamp()+($4::BIGINT * interval '1 millisecond') WHERE log_name=$1",
    )
    .bind(&self.log_name)
    .bind(holder)
    .bind(epoch)
    .bind(lease_millis)
    .execute(&mut *transaction)
    .await
    .context("failed to publish CT lease")?;
    transaction
      .commit()
      .await
      .context("failed to commit CT lease")?;
    Ok(Some(to_u64(epoch, "publisher epoch")?))
  }

  pub async fn renew_publisher_lease(
    &self,
    holder: &str,
    epoch: u64,
    lease_millis: u64,
  ) -> anyhow::Result<()> {
    validate_identifier(holder, "publisher holder")?;
    let epoch = to_i64(epoch, "publisher epoch")?;
    let lease_millis = to_i64(lease_millis, "lease milliseconds")?;
    if lease_millis == 0 || lease_millis > MAX_LEASE_MILLIS {
      bail!("CT publisher lease must be within 1..={MAX_LEASE_MILLIS} milliseconds");
    }
    let result = sqlx::query(
      "UPDATE oxibelt_ct_logs SET publisher_lease_until=clock_timestamp()+($4::BIGINT * interval '1 millisecond') WHERE log_name=$1 AND publisher_holder=$2 AND publisher_epoch=$3 AND publisher_lease_until > clock_timestamp() AND frozen_reason IS NULL",
    )
    .bind(&self.log_name)
    .bind(holder)
    .bind(epoch)
    .bind(lease_millis)
    .execute(&self.pool)
    .await
    .context("failed to renew CT publisher lease")?;
    if result.rows_affected() != 1 {
      bail!("CT publisher lost its fenced lease before checkpoint publication");
    }
    Ok(())
  }

  pub async fn tree_state(&self) -> anyhow::Result<CtTreeState> {
    let row = sqlx::query(
      "SELECT tree_size,tree_root,published_tree_size,checkpoint_etag,checkpoint_version,floor(extract(epoch FROM checkpoint_published_at) * 1000)::BIGINT AS checkpoint_published_millis,frozen_reason FROM oxibelt_ct_logs WHERE log_name=$1",
    )
    .bind(&self.log_name)
    .fetch_one(&self.pool)
    .await
    .context("failed to load CT tree state")?;
    tree_state_from_row(&row)
  }

  pub async fn record_published_checkpoint(
    &self,
    tree_size: u64,
    root_hash: [u8; 32],
    etag: Option<&str>,
    version: Option<&str>,
    holder: &str,
    epoch: u64,
  ) -> anyhow::Result<()> {
    let tree_size = to_i64(tree_size, "tree size")?;
    let epoch = to_i64(epoch, "publisher epoch")?;
    let mut transaction = self
      .pool
      .begin()
      .await
      .context("failed to begin CT publish record")?;
    let log = lock_log(&mut transaction, &self.log_name).await?;
    ensure_not_frozen(&log)?;
    assert_publisher(&log, holder, epoch)?;
    if log.try_get::<i64, _>("tree_size")? != tree_size
      || log.try_get::<Vec<u8>, _>("tree_root")?.as_slice() != root_hash.as_slice()
    {
      bail!("CT checkpoint does not match the current durable tree");
    }
    let prior = log.try_get::<i64, _>("published_tree_size")?;
    if tree_size < prior {
      bail!("CT checkpoint publication cannot roll back tree size");
    }
    sqlx::query(
      "UPDATE oxibelt_ct_logs SET published_tree_size=$2,checkpoint_etag=$3,checkpoint_version=$4,checkpoint_published_at=clock_timestamp() WHERE log_name=$1",
    )
    .bind(&self.log_name)
    .bind(tree_size)
    .bind(etag)
    .bind(version)
    .execute(&mut *transaction)
    .await
    .context("failed to persist CT checkpoint version")?;
    transaction
      .commit()
      .await
      .context("failed to commit CT checkpoint record")?;
    Ok(())
  }

  pub async fn entries(
    &self,
    start: u64,
    end_inclusive: u64,
  ) -> anyhow::Result<Vec<CtStoredEntry>> {
    if end_inclusive < start || end_inclusive.saturating_sub(start) > 1023 {
      bail!("CT entry range must contain 1..=1024 entries");
    }
    let rows = sqlx::query(
      "SELECT leaf_index,timestamp_millis,leaf_input,extra_data,leaf_hash,receipt FROM oxibelt_ct_entries WHERE log_name=$1 AND integrated=TRUE AND leaf_index BETWEEN $2 AND $3 ORDER BY leaf_index",
    )
    .bind(&self.log_name)
    .bind(to_i64(start, "entry start")?)
    .bind(to_i64(end_inclusive, "entry end")?)
    .fetch_all(&self.pool)
    .await
    .context("failed to load CT entries")?;
    rows.iter().map(stored_entry_from_row).collect()
  }

  /// Loads a contiguous range of durable Merkle nodes at one binary-tree
  /// level. Complete 256-way Static CT subtrees are stored at levels 8, 16,
  /// and so on, so publication can remain proportional to changed tiles.
  pub async fn node_hashes(
    &self,
    level: u8,
    start: u64,
    end_inclusive: u64,
  ) -> anyhow::Result<Vec<[u8; 32]>> {
    if level > 63 || end_inclusive < start || end_inclusive.saturating_sub(start) > 1023 {
      bail!("CT node range must contain 1..=1024 nodes at a supported level");
    }
    let rows = sqlx::query(
      "SELECT node_index,hash FROM oxibelt_ct_nodes WHERE log_name=$1 AND level=$2 AND node_index BETWEEN $3 AND $4 ORDER BY node_index",
    )
    .bind(&self.log_name)
    .bind(i32::from(level))
    .bind(to_i64(start, "node start")?)
    .bind(to_i64(end_inclusive, "node end")?)
    .fetch_all(&self.pool)
    .await
    .context("failed to load CT Merkle nodes")?;
    let expected_len =
      usize::try_from(end_inclusive - start + 1).context("CT node range length overflow")?;
    if rows.len() != expected_len {
      bail!("CT durable Merkle node range is incomplete");
    }
    rows
      .iter()
      .enumerate()
      .map(|(offset, row)| {
        let expected = start
          .checked_add(u64::try_from(offset).context("CT node offset overflow")?)
          .ok_or_else(|| anyhow!("CT node index overflow"))?;
        let actual = to_u64(row.try_get::<i64, _>("node_index")?, "node index")?;
        if actual != expected {
          bail!("CT durable Merkle node range is not contiguous");
        }
        digest_from_vec(row.try_get("hash")?, "node hash")
      })
      .collect()
  }

  pub async fn node_hash(&self, level: u8, node_index: u64) -> anyhow::Result<[u8; 32]> {
    self
      .node_hashes(level, node_index, node_index)
      .await?
      .pop()
      .ok_or_else(|| anyhow!("CT durable Merkle node is missing"))
  }

  pub async fn leaf_index_by_hash(
    &self,
    leaf_hash: &[u8; 32],
    tree_size: u64,
  ) -> anyhow::Result<Option<u64>> {
    let row = sqlx::query_scalar::<_, i64>(
      "SELECT leaf_index FROM oxibelt_ct_entries WHERE log_name=$1 AND integrated=TRUE AND leaf_index < $2 AND leaf_hash=$3 ORDER BY leaf_index LIMIT 1",
    )
    .bind(&self.log_name)
    .bind(to_i64(tree_size, "tree size")?)
    .bind(leaf_hash.as_slice())
    .fetch_optional(&self.pool)
    .await
    .context("failed to locate CT leaf hash")?;
    row.map(|index| to_u64(index, "leaf index")).transpose()
  }

  pub async fn leaf_hashes(&self, tree_size: u64) -> anyhow::Result<Vec<[u8; 32]>> {
    let rows = sqlx::query_scalar::<_, Vec<u8>>(
      "SELECT leaf_hash FROM oxibelt_ct_entries WHERE log_name=$1 AND integrated=TRUE AND leaf_index < $2 ORDER BY leaf_index",
    )
    .bind(&self.log_name)
    .bind(to_i64(tree_size, "tree size")?)
    .fetch_all(&self.pool)
    .await
    .context("failed to load CT leaf hashes")?;
    rows
      .into_iter()
      .map(|value| digest_from_vec(value, "leaf hash"))
      .collect()
  }

  pub async fn freeze(&self, reason: &str) -> anyhow::Result<()> {
    if reason.is_empty() || reason.len() > 256 {
      bail!("CT freeze reason must be within 1..=256 bytes");
    }
    sqlx::query(
      "UPDATE oxibelt_ct_logs SET frozen_reason=COALESCE(frozen_reason,$2),publisher_lease_until=NULL WHERE log_name=$1",
    )
    .bind(&self.log_name)
    .bind(reason)
    .execute(&self.pool)
    .await
    .context("failed to freeze CT log")?;
    Ok(())
  }

  pub fn pool(&self) -> &PgPool {
    &self.pool
  }
}

async fn verify_schema(pool: &PgPool) -> anyhow::Result<()> {
  let version = sqlx::query_scalar::<_, i32>(
    "SELECT version FROM oxibelt_ct_schema_migrations WHERE component='certificate_transparency'",
  )
  .fetch_optional(pool)
  .await
  .context("CT PostgreSQL schema is unavailable; run oxibeltctl ct storage migrate")?;
  if version != Some(CT_POSTGRES_SCHEMA_VERSION) {
    bail!(
      "CT PostgreSQL schema version is {:?}; expected {} (run oxibeltctl ct storage migrate)",
      version,
      CT_POSTGRES_SCHEMA_VERSION
    );
  }
  Ok(())
}

async fn bind_log_identity(pool: &PgPool, binding: &CtLogBinding) -> anyhow::Result<()> {
  sqlx::query(
    "INSERT INTO oxibelt_ct_logs(log_name,protocol,public_identity,log_identifier,mmd_millis) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (log_name) DO NOTHING",
  )
  .bind(&binding.log_name)
  .bind(&binding.protocol)
  .bind(&binding.public_identity)
  .bind(&binding.log_identifier)
  .bind(to_i64(binding.mmd_millis, "MMD")?)
  .execute(pool)
  .await
  .context("failed to bind CT log identity")?;
  let row = sqlx::query(
    "SELECT protocol,public_identity,log_identifier,mmd_millis FROM oxibelt_ct_logs WHERE log_name=$1",
  )
  .bind(&binding.log_name)
  .fetch_one(pool)
  .await
  .context("failed to read back CT log identity")?;
  if row.try_get::<String, _>("protocol")? != binding.protocol
    || row.try_get::<Vec<u8>, _>("public_identity")? != binding.public_identity
    || row.try_get::<String, _>("log_identifier")? != binding.log_identifier
    || row.try_get::<i64, _>("mmd_millis")? != to_i64(binding.mmd_millis, "MMD")?
  {
    bail!("configured CT log identity differs from durable PostgreSQL state");
  }
  Ok(())
}

async fn lock_log<'a>(
  transaction: &mut Transaction<'a, Postgres>,
  log_name: &str,
) -> anyhow::Result<sqlx::postgres::PgRow> {
  sqlx::query("SELECT *, COALESCE(publisher_lease_until > clock_timestamp(), FALSE) AS publisher_lease_active FROM oxibelt_ct_logs WHERE log_name=$1 FOR UPDATE")
    .bind(log_name)
    .fetch_one(&mut **transaction)
    .await
    .context("failed to lock CT log state")
}

async fn load_frontier_root(
  transaction: &mut Transaction<'_, Postgres>,
  log_name: &str,
) -> anyhow::Result<[u8; 32]> {
  let rows =
    sqlx::query("SELECT level,hash FROM oxibelt_ct_frontier WHERE log_name=$1 ORDER BY level")
      .bind(log_name)
      .fetch_all(&mut **transaction)
      .await
      .context("failed to load CT frontier")?;
  let mut root: Option<[u8; 32]> = None;
  for row in rows {
    let left = digest_from_vec(row.try_get("hash")?, "frontier hash")?;
    root = Some(root.map_or(left, |right| hash_node(&left, &right)));
  }
  root.ok_or_else(|| anyhow!("CT frontier is empty after integration"))
}

fn stored_entry_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<CtStoredEntry> {
  let receipt: Option<Vec<u8>> = row.try_get("receipt")?;
  Ok(CtStoredEntry {
    leaf_index: to_u64(row.try_get("leaf_index")?, "leaf index")?,
    timestamp_millis: to_u64(row.try_get("timestamp_millis")?, "timestamp")?,
    leaf_input: row.try_get("leaf_input")?,
    extra_data: row.try_get("extra_data")?,
    leaf_hash: digest_from_vec(row.try_get("leaf_hash")?, "leaf hash")?,
    receipt: receipt.ok_or_else(|| anyhow!("CT integrated entry is missing its receipt"))?,
  })
}

fn tree_state_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<CtTreeState> {
  let tree_size = to_u64(row.try_get("tree_size")?, "tree size")?;
  let root = row.try_get::<Vec<u8>, _>("tree_root")?;
  let root_hash = if tree_size == 0 && root.is_empty() {
    Sha256::digest([]).into()
  } else {
    digest_from_vec(root, "tree root")?
  };
  Ok(CtTreeState {
    tree_size,
    root_hash,
    published_tree_size: to_u64(row.try_get("published_tree_size")?, "published tree size")?,
    checkpoint_etag: row.try_get("checkpoint_etag")?,
    checkpoint_version: row.try_get("checkpoint_version")?,
    checkpoint_published_millis: row
      .try_get::<Option<i64>, _>("checkpoint_published_millis")?
      .map(|value| to_u64(value, "checkpoint publication timestamp"))
      .transpose()?,
    frozen_reason: row.try_get("frozen_reason")?,
  })
}

fn assert_publisher(row: &sqlx::postgres::PgRow, holder: &str, epoch: i64) -> anyhow::Result<()> {
  if row
    .try_get::<Option<String>, _>("publisher_holder")?
    .as_deref()
    != Some(holder)
    || row.try_get::<i64, _>("publisher_epoch")? != epoch
  {
    bail!("stale CT publisher fencing token");
  }
  let active = row.try_get::<bool, _>("publisher_lease_active")?;
  if !active {
    bail!("CT publisher lease expired");
  }
  Ok(())
}

fn ensure_not_frozen(row: &sqlx::postgres::PgRow) -> anyhow::Result<()> {
  if let Some(reason) = row.try_get::<Option<String>, _>("frozen_reason")? {
    bail!("CT log is frozen: {reason}");
  }
  Ok(())
}

fn validate_binding(binding: &CtLogBinding) -> anyhow::Result<()> {
  validate_identifier(&binding.log_name, "log name")?;
  validate_identifier(&binding.protocol, "protocol")?;
  if binding.public_identity.is_empty() || binding.public_identity.len() > 8192 {
    bail!("CT public identity length is outside 1..=8192");
  }
  if binding.log_identifier.is_empty() || binding.log_identifier.len() > 256 {
    bail!("CT log identifier length is outside 1..=256");
  }
  if binding.mmd_millis == 0 || binding.mmd_millis > 24 * 60 * 60 * 1000 {
    bail!("CT MMD is outside 1 millisecond..=24 hours");
  }
  Ok(())
}

fn validate_identifier(value: &str, label: &str) -> anyhow::Result<()> {
  if value.is_empty()
    || value.len() > 128
    || !value
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
  {
    bail!("CT {label} is not a bounded portable identifier");
  }
  Ok(())
}

fn validate_entry_bytes(leaf_input: &[u8], extra_data: &[u8]) -> anyhow::Result<()> {
  if leaf_input.is_empty()
    || leaf_input.len() > MAX_ENTRY_BYTES
    || extra_data.len() > MAX_ENTRY_BYTES
    || leaf_input.len().saturating_add(extra_data.len()) > MAX_ENTRY_BYTES
  {
    bail!("CT entry exceeds its bounded durable representation");
  }
  Ok(())
}

fn digest_from_vec(value: Vec<u8>, label: &str) -> anyhow::Result<[u8; 32]> {
  value
    .try_into()
    .map_err(|_| anyhow!("CT {label} must contain exactly 32 bytes"))
}

fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
  let mut digest = Sha256::new();
  digest.update([1]);
  digest.update(left);
  digest.update(right);
  digest.finalize().into()
}

fn stable_lock_id(label: &str) -> i64 {
  let digest = Sha256::digest(label.as_bytes());
  i64::from_be_bytes(digest[..8].try_into().unwrap_or_default())
}

fn to_i64(value: u64, label: &str) -> anyhow::Result<i64> {
  i64::try_from(value).with_context(|| format!("CT {label} exceeds PostgreSQL BIGINT"))
}

fn to_u64(value: i64, label: &str) -> anyhow::Result<u64> {
  u64::try_from(value).with_context(|| format!("CT {label} is negative"))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn node_hash_is_domain_separated() {
    let left = [1_u8; 32];
    let right = [2_u8; 32];
    let undomained: [u8; 32] = Sha256::digest([left, right].concat()).into();
    assert_ne!(hash_node(&left, &right), undomained);
  }

  #[test]
  fn binding_rejects_unbounded_or_ambiguous_identity() {
    let binding = CtLogBinding {
      log_name: "bad/name".to_string(),
      protocol: "rfc6962_v1".to_string(),
      public_identity: vec![1],
      log_identifier: "id".to_string(),
      mmd_millis: 60_000,
    };
    assert!(validate_binding(&binding).is_err());
  }

  #[tokio::test]
  async fn postgres_sequencing_limits_publication_and_fencing_are_atomic() {
    let required = std::env::var("OXIBELT_REQUIRE_CT_POSTGRES_TESTS").as_deref() == Ok("1");
    let database_url = match std::env::var("OXIBELT_TEST_CT_POSTGRES_URL") {
      Ok(value) if !value.trim().is_empty() => value,
      _ if required => panic!("required CT PostgreSQL test URL is missing"),
      _ => return,
    };
    CtPostgresStore::migrate(&database_url).await.unwrap();
    let unique = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_nanos();
    let log_name = format!("ct_test_{}_{}", std::process::id(), unique);
    let store = CtPostgresStore::connect_checked(
      &database_url,
      4,
      &CtLogBinding {
        log_name: log_name.clone(),
        protocol: "static_rfc6962_v1".to_string(),
        public_identity: vec![1, 2, 3],
        log_identifier: "test-log-id".to_string(),
        mmd_millis: 60_000,
      },
    )
    .await
    .unwrap();

    let first_hash: [u8; 32] = Sha256::digest([0, 1]).into();
    let first = store
      .reserve_entry_with_limit(&[1; 32], 1, |_, _| Ok((vec![1], Vec::new(), first_hash)))
      .await
      .unwrap();
    let duplicate = store
      .reserve_entry_with_limit(&[1; 32], 1, |_, _| unreachable!())
      .await
      .unwrap();
    assert_eq!(duplicate.leaf_index, first.leaf_index);
    let error = store
      .reserve_entry_with_limit(&[2; 32], 1, |_, _| Ok((vec![2], Vec::new(), [2; 32])))
      .await
      .unwrap_err();
    assert!(error.to_string().contains("unsigned reservation"));

    store.discard_unsigned_tail(first.leaf_index).await.unwrap();
    let first = store
      .reserve_entry_with_limit(&[1; 32], 1, |_, _| Ok((vec![1], Vec::new(), first_hash)))
      .await
      .unwrap();
    assert_eq!(first.leaf_index, 0);
    store.record_receipt(first.leaf_index, &[1]).await.unwrap();
    let alpha_epoch = store
      .try_acquire_publisher_lease("alpha", 60_000)
      .await
      .unwrap()
      .unwrap();
    assert_eq!(
      store
        .try_acquire_publisher_lease("beta", 60_000)
        .await
        .unwrap(),
      None
    );
    store
      .integrate_next(first.leaf_index, first_hash, "alpha", alpha_epoch)
      .await
      .unwrap();

    let second_hash: [u8; 32] = Sha256::digest([0, 2]).into();
    let second = store
      .reserve_entry_with_limit(&[2; 32], 1, |_, _| Ok((vec![2], Vec::new(), second_hash)))
      .await
      .unwrap();
    store.record_receipt(second.leaf_index, &[2]).await.unwrap();
    let integrated = store
      .integrate_next(second.leaf_index, second_hash, "alpha", alpha_epoch)
      .await
      .unwrap();
    assert_eq!(integrated.tree_size, 2);
    assert_eq!(
      store.node_hash(1, 0).await.unwrap(),
      hash_node(&first_hash, &second_hash)
    );
    store
      .record_published_checkpoint(
        integrated.tree_size,
        integrated.root_hash,
        Some("etag-1"),
        Some("version-1"),
        "alpha",
        alpha_epoch,
      )
      .await
      .unwrap();
    let published = store.tree_state().await.unwrap();
    assert_eq!(published.published_tree_size, 2);
    assert_eq!(published.checkpoint_version.as_deref(), Some("version-1"));
    assert!(published.checkpoint_published_millis.is_some());
    let timestamp_one = store.reserve_sth_timestamp().await.unwrap();
    let timestamp_two = store.reserve_sth_timestamp().await.unwrap();
    assert!(timestamp_two > timestamp_one);

    sqlx::query(
      "UPDATE oxibelt_ct_logs SET publisher_lease_until=clock_timestamp()-interval '1 second' WHERE log_name=$1",
    )
    .bind(&log_name)
    .execute(&store.pool)
    .await
    .unwrap();
    let beta_epoch = store
      .try_acquire_publisher_lease("beta", 60_000)
      .await
      .unwrap()
      .unwrap();
    assert!(beta_epoch > alpha_epoch);
    assert!(
      store
        .renew_publisher_lease("alpha", alpha_epoch, 60_000)
        .await
        .is_err()
    );

    for statement in [
      "DELETE FROM oxibelt_ct_frontier WHERE log_name=$1",
      "DELETE FROM oxibelt_ct_nodes WHERE log_name=$1",
      "DELETE FROM oxibelt_ct_entries WHERE log_name=$1",
      "DELETE FROM oxibelt_ct_logs WHERE log_name=$1",
    ] {
      sqlx::query(statement)
        .bind(&log_name)
        .execute(&store.pool)
        .await
        .unwrap();
    }
  }
}

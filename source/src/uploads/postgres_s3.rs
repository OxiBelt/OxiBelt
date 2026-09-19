//! PostgreSQL-authoritative S3-compatible managed-upload store.
//!
//! PostgreSQL owns bindings, quotas, offsets, leases, and fencing. Object-store
//! I/O never occurs inside a SQL transaction; a crashed/fenced writer can leave
//! only an unreferenced immutable object, never an advanced durable offset.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, bail};
use bytes::{Bytes, BytesMut};
use futures_util::{StreamExt, TryStreamExt};
use object_store::{
  Certificate, ClientOptions, GetOptions, ObjectStore, ObjectStoreExt, PutMode, PutPayload,
  PutResult,
  aws::{AmazonS3, AmazonS3Builder},
  multipart::{MultipartStore, PartId},
  path::Path as ObjectPath,
};
use sha2::{Digest as _, Sha256};
use sqlx::{
  AssertSqlSafe, Row, Transaction,
  postgres::{PgPool, PgPoolOptions, PgRow},
};

use super::{
  AppendReservation, DispatchClaim, DispatchTerminal, InspectedPart, UploadByteStream,
  UploadCreate, UploadObject, UploadOwner, UploadRejection, UploadRequestMetadata, UploadState,
  UploadStatus, is_sha256_hex,
};
use crate::config::{
  PostgresS3UploadStoreConfig, UploadDestinationConfig, UploadProfileConfig, UploadStoreConfig,
  UploadStoreKind,
};

const LEASE_SECONDS: i64 = 300;
const RENEW_SECONDS: u64 = 60;
const ORPHAN_GRACE_SECONDS: i64 = LEASE_SECONDS * 2;
const MAX_GC_LIMIT: usize = 1_000;
const MIN_MULTIPART_CHUNK_BYTES: u64 = 5 * 1024 * 1024;
const MAX_MULTIPART_PARTS: u64 = 10_000;
const MULTIPART_ABORT_SECONDS: u64 = 30;

pub const UPLOAD_POSTGRES_MIGRATION_V1: &[&str] = &[
  "CREATE TABLE IF NOT EXISTS oxibelt_upload_schema_migrations (component TEXT PRIMARY KEY, version INTEGER NOT NULL CHECK (version > 0), applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())",
  "CREATE TABLE IF NOT EXISTS oxibelt_uploads (id TEXT PRIMARY KEY, profile_name TEXT NOT NULL, profile_json JSONB NOT NULL, owner_json JSONB NOT NULL, binding_json JSONB NOT NULL, method TEXT NOT NULL, uri TEXT NOT NULL, safe_headers JSONB NOT NULL, offset_bytes BIGINT NOT NULL DEFAULT 0 CHECK (offset_bytes >= 0), declared_total_bytes BIGINT, expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms > 0), state TEXT NOT NULL, fence_epoch BIGINT NOT NULL DEFAULT 1 CHECK (fence_epoch > 0), lease_holder TEXT, lease_until TIMESTAMPTZ, reservation_token TEXT, reservation_offset_bytes BIGINT, reservation_bytes BIGINT, object_key TEXT, object_sha256 TEXT, object_bytes BIGINT, object_version TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())",
  "CREATE TABLE IF NOT EXISTS oxibelt_upload_parts (upload_id TEXT NOT NULL REFERENCES oxibelt_uploads(id), offset_bytes BIGINT NOT NULL CHECK (offset_bytes >= 0), bytes BIGINT NOT NULL CHECK (bytes > 0), sha256 TEXT NOT NULL, object_key TEXT NOT NULL UNIQUE, object_version TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY (upload_id, offset_bytes))",
  "CREATE INDEX IF NOT EXISTS oxibelt_uploads_expiry_idx ON oxibelt_uploads(expires_at_ms)",
  "CREATE INDEX IF NOT EXISTS oxibelt_uploads_profile_state_idx ON oxibelt_uploads(profile_name,state)",
  "CREATE INDEX IF NOT EXISTS oxibelt_upload_parts_upload_idx ON oxibelt_upload_parts(upload_id,offset_bytes)",
  "INSERT INTO oxibelt_upload_schema_migrations(component,version) VALUES ('managed_uploads',1) ON CONFLICT(component) DO UPDATE SET version=GREATEST(oxibelt_upload_schema_migrations.version,EXCLUDED.version),applied_at=clock_timestamp()",
];

pub const UPLOAD_POSTGRES_MIGRATION_V2: &[&str] = &[
  "ALTER TABLE oxibelt_uploads ADD COLUMN IF NOT EXISTS object_expires_at_ms BIGINT",
  "ALTER TABLE oxibelt_upload_parts ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()",
  "CREATE TABLE IF NOT EXISTS oxibelt_upload_gc_state (component TEXT PRIMARY KEY, cursor TEXT)",
  "CREATE TABLE IF NOT EXISTS oxibelt_upload_orphan_objects (object_key TEXT PRIMARY KEY, profile_name TEXT NOT NULL, bytes BIGINT NOT NULL CHECK (bytes >= 0), object_version TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())",
  "CREATE INDEX IF NOT EXISTS oxibelt_uploads_object_expiry_idx ON oxibelt_uploads(object_expires_at_ms) WHERE object_expires_at_ms IS NOT NULL",
  "CREATE INDEX IF NOT EXISTS oxibelt_uploads_deleted_idx ON oxibelt_uploads(state) WHERE state='deleted'",
  "INSERT INTO oxibelt_upload_schema_migrations(component,version) VALUES ('managed_uploads',2) ON CONFLICT(component) DO UPDATE SET version=GREATEST(oxibelt_upload_schema_migrations.version,EXCLUDED.version),applied_at=clock_timestamp()",
];

pub const UPLOAD_POSTGRES_MIGRATION_V3: &[&str] = &[
  "ALTER TABLE oxibelt_upload_orphan_objects ADD COLUMN IF NOT EXISTS intent_state TEXT NOT NULL DEFAULT 'completed' CHECK (intent_state IN ('pending','completed'))",
  "ALTER TABLE oxibelt_upload_orphan_objects ADD COLUMN IF NOT EXISTS multipart_id TEXT",
  "INSERT INTO oxibelt_upload_schema_migrations(component,version) VALUES ('managed_uploads',3) ON CONFLICT(component) DO UPDATE SET version=GREATEST(oxibelt_upload_schema_migrations.version,EXCLUDED.version),applied_at=clock_timestamp()",
];

/// Persists immutable RFC 9842 session pins independently of mutable headers
/// and profile reloads.
pub const UPLOAD_POSTGRES_MIGRATION_V4: &[&str] = &[
  "ALTER TABLE oxibelt_uploads ADD COLUMN IF NOT EXISTS dictionary_pin_json JSONB",
  "UPDATE oxibelt_uploads SET state='validation_failed',reservation_token=NULL,reservation_offset_bytes=NULL,reservation_bytes=NULL,lease_holder=NULL,lease_until=NULL,fence_epoch=fence_epoch+1 WHERE state='validating' AND dictionary_pin_json IS NULL",
  "INSERT INTO oxibelt_upload_schema_migrations(component,version) VALUES ('managed_uploads',4) ON CONFLICT(component) DO UPDATE SET version=GREATEST(oxibelt_upload_schema_migrations.version,EXCLUDED.version),applied_at=clock_timestamp()",
];

pub struct PostgresS3UploadStore {
  pool: PgPool,
  objects: Arc<AmazonS3>,
  prefix: String,
}

#[derive(Clone, Debug)]
struct StoredPart {
  key: String,
  offset: u64,
  bytes: u64,
  sha256: String,
  version: Option<String>,
}

trait ManagedMultipartApi: Send + Sync {
  fn put_part<'a>(
    &'a self,
    path: &'a ObjectPath,
    id: &'a str,
    part_index: usize,
    data: PutPayload,
  ) -> futures_util::future::BoxFuture<'a, object_store::Result<PartId>>;
  fn complete<'a>(
    &'a self,
    path: &'a ObjectPath,
    id: &'a str,
    parts: Vec<PartId>,
  ) -> futures_util::future::BoxFuture<'a, object_store::Result<PutResult>>;
  fn abort<'a>(
    &'a self,
    path: &'a ObjectPath,
    id: &'a str,
  ) -> futures_util::future::BoxFuture<'a, object_store::Result<()>>;
}

impl ManagedMultipartApi for AmazonS3 {
  fn put_part<'a>(
    &'a self,
    path: &'a ObjectPath,
    id: &'a str,
    part_index: usize,
    data: PutPayload,
  ) -> futures_util::future::BoxFuture<'a, object_store::Result<PartId>> {
    let id = id.to_string();
    Box::pin(async move { MultipartStore::put_part(self, path, &id, part_index, data).await })
  }

  fn complete<'a>(
    &'a self,
    path: &'a ObjectPath,
    id: &'a str,
    parts: Vec<PartId>,
  ) -> futures_util::future::BoxFuture<'a, object_store::Result<PutResult>> {
    let id = id.to_string();
    Box::pin(async move { MultipartStore::complete_multipart(self, path, &id, parts).await })
  }

  fn abort<'a>(
    &'a self,
    path: &'a ObjectPath,
    id: &'a str,
  ) -> futures_util::future::BoxFuture<'a, object_store::Result<()>> {
    let id = id.to_string();
    Box::pin(async move { MultipartStore::abort_multipart(self, path, &id).await })
  }
}

/// Cancellation-safe low-level multipart writer. The multipart identifier is
/// persisted before the first part, so another replica can abort after a hard
/// crash; Drop covers ordinary future/task cancellation.
struct ManagedMultipartWriter {
  api: Arc<dyn ManagedMultipartApi>,
  multipart: Option<(ObjectPath, String)>,
  parts: Vec<PartId>,
  buffer: BytesMut,
  chunk_size: usize,
  intent_pool: Option<PgPool>,
  intent_key: String,
}

impl ManagedMultipartWriter {
  fn new(
    api: Arc<dyn ManagedMultipartApi>,
    path: ObjectPath,
    multipart_id: String,
    total_bytes: u64,
    intent_pool: PgPool,
    intent_key: String,
  ) -> anyhow::Result<Self> {
    let chunk_size = multipart_chunk_bytes(total_bytes)?;
    Ok(Self {
      api,
      multipart: Some((path, multipart_id)),
      parts: Vec::new(),
      buffer: BytesMut::new(),
      chunk_size,
      intent_pool: Some(intent_pool),
      intent_key,
    })
  }

  #[cfg(test)]
  fn new_without_intent(
    api: Arc<dyn ManagedMultipartApi>,
    total_bytes: u64,
  ) -> anyhow::Result<Self> {
    let chunk_size = multipart_chunk_bytes(total_bytes)?;
    Ok(Self {
      api,
      multipart: Some((ObjectPath::from("test"), "test-upload".to_string())),
      parts: Vec::new(),
      buffer: BytesMut::new(),
      chunk_size,
      intent_pool: None,
      intent_key: String::new(),
    })
  }

  async fn put(&mut self, mut bytes: Bytes) -> anyhow::Result<()> {
    while !bytes.is_empty() {
      let remaining = self.chunk_size - self.buffer.len();
      if bytes.len() < remaining {
        self.buffer.extend_from_slice(&bytes);
        return Ok(());
      }
      self.buffer.extend_from_slice(&bytes.split_to(remaining));
      self.flush_part().await?;
    }
    Ok(())
  }

  async fn flush_part(&mut self) -> anyhow::Result<()> {
    let part = std::mem::take(&mut self.buffer).freeze();
    let (path, multipart_id) = self
      .multipart
      .as_ref()
      .ok_or_else(|| anyhow::anyhow!("managed upload multipart writer is closed"))?;
    let part_index = self.parts.len();
    let part = tokio::time::timeout(
      Duration::from_secs(RENEW_SECONDS),
      self
        .api
        .put_part(path, multipart_id, part_index, part.into()),
    )
    .await
    .context("managed upload multipart part timed out")??;
    self.parts.push(part);
    Ok(())
  }

  async fn finish(mut self) -> anyhow::Result<PutResult> {
    if !self.buffer.is_empty()
      && let Err(error) = self.flush_part().await
    {
      self.abort_in_place().await;
      return Err(error);
    }
    let (path, multipart_id) = self
      .multipart
      .as_ref()
      .ok_or_else(|| anyhow::anyhow!("managed upload multipart writer is closed"))?;
    let result = tokio::time::timeout(
      Duration::from_secs(RENEW_SECONDS),
      self
        .api
        .complete(path, multipart_id, std::mem::take(&mut self.parts)),
    )
    .await;
    match result {
      Ok(Ok(result)) => {
        self.multipart = None;
        Ok(result)
      }
      Ok(Err(error)) => {
        self.abort_in_place().await;
        Err(error.into())
      }
      Err(error) => {
        self.abort_in_place().await;
        Err(error).context("managed upload multipart completion timed out")
      }
    }
  }

  async fn abort(mut self) {
    self.abort_in_place().await;
  }

  async fn abort_in_place(&mut self) {
    if let Some((path, multipart_id)) = self.multipart.take() {
      let aborted = tokio::time::timeout(
        Duration::from_secs(MULTIPART_ABORT_SECONDS),
        self.api.abort(&path, &multipart_id),
      )
      .await;
      if matches!(aborted, Ok(Ok(())))
        && let Some(pool) = &self.intent_pool
      {
        let _ = untrack_orphan_pool(pool, &self.intent_key).await;
      }
    }
  }
}

impl Drop for ManagedMultipartWriter {
  fn drop(&mut self) {
    let Some((path, multipart_id)) = self.multipart.take() else {
      return;
    };
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
      return;
    };
    let pool = self.intent_pool.clone();
    let key = self.intent_key.clone();
    let api = Arc::clone(&self.api);
    runtime.spawn(async move {
      let aborted = tokio::time::timeout(
        Duration::from_secs(MULTIPART_ABORT_SECONDS),
        api.abort(&path, &multipart_id),
      )
      .await;
      if matches!(aborted, Ok(Ok(())))
        && let Some(pool) = pool
      {
        let _ = untrack_orphan_pool(&pool, &key).await;
      }
    });
  }
}

impl PostgresS3UploadStore {
  pub async fn open(config: &UploadStoreConfig) -> anyhow::Result<Self> {
    if config.kind != UploadStoreKind::PostgresS3 {
      bail!("postgres_s3 upload store opened with a non-postgres_s3 configuration");
    }
    let settings = config
      .postgres_s3
      .as_ref()
      .ok_or_else(|| anyhow::anyhow!("postgres_s3 upload store settings are missing"))?;
    // A store owns a private, deterministic PostgreSQL schema. This keeps
    // quotas, GC, tombstones, and object keys isolated even when several
    // configured stores share one database. Credentials are intentionally not
    // part of the identity so rotation does not strand durable state.
    let schema = store_schema(config, settings);
    let connection_schema = schema.clone();
    let pool = PgPoolOptions::new()
      .max_connections(settings.max_connections)
      .acquire_timeout(Duration::from_secs(5))
      .after_connect(move |connection, _metadata| {
        let statement = format!("SET search_path TO {}", connection_schema);
        Box::pin(async move {
          sqlx::query(AssertSqlSafe(statement))
            .execute(connection)
            .await?;
          Ok(())
        })
      })
      .connect(&required_env(&settings.postgres_url_env)?)
      .await
      .context("failed to connect to managed upload PostgreSQL store")?;
    // `schema` contains only our fixed prefix and lowercase hex.
    sqlx::query(AssertSqlSafe(format!(
      "CREATE SCHEMA IF NOT EXISTS {schema}"
    )))
    .execute(&pool)
    .await
    .context("failed to create managed upload PostgreSQL schema")?;
    migrate(&pool).await?;
    let base_prefix = settings.s3_prefix.trim_matches('/');
    let prefix = if base_prefix.is_empty() {
      format!("stores/{schema}")
    } else {
      format!("{base_prefix}/stores/{schema}")
    };
    Ok(Self {
      pool,
      objects: build_object_store(settings)?,
      prefix,
    })
  }

  pub async fn create(&self, request: UploadCreate) -> anyhow::Result<UploadStatus> {
    if request.profile.max_upload_bytes == 0
      || request
        .declared_total
        .is_some_and(|n| n > request.profile.max_upload_bytes)
    {
      bail!("managed upload declared length exceeds its profile maximum");
    }
    let id = random_id()?;
    let mut tx = self.pool.begin().await?;
    lock_profile(&mut tx, &request.profile.name).await?;
    // Retained terminal rows and deletion tombstones still consume durable
    // metadata (and can still reference billable S3 storage). Capacity is
    // released only after cleanup removes the authoritative row.
    let sessions = profile_sessions(&mut tx, &request.profile.name).await?;
    if sessions >= u64::from(request.profile.max_sessions) {
      return Err(UploadRejection::Capacity.into());
    }
    let row = sqlx::query("INSERT INTO oxibelt_uploads(id,profile_name,profile_json,owner_json,binding_json,method,uri,safe_headers,dictionary_pin_json,declared_total_bytes,expires_at_ms,state) VALUES($1,$2,$3::jsonb,$4::jsonb,$5::jsonb,$6,$7,$8::jsonb,$9::jsonb,$10,db_now_ms()+$11*1000,'active') RETURNING id,profile_name,offset_bytes,declared_total_bytes,expires_at_ms,state,object_key,object_sha256,object_bytes,object_version")
      .bind(&id).bind(&request.profile.name).bind(serde_json::to_string(&request.profile)?)
      .bind(serde_json::to_string(&request.owner)?).bind(request.binding.to_string()).bind(request.method.as_str())
      .bind(request.uri.to_string()).bind(request.safe_headers.to_string())
      .bind(request.dictionary.as_ref().map(serde_json::to_string).transpose()?)
      .bind(request.declared_total.map(to_i64).transpose()?).bind(to_i64(request.profile.ttl_seconds)?)
      .fetch_one(&mut *tx).await?;
    let status = status_row(&row)?;
    tx.commit().await?;
    Ok(status)
  }

  pub async fn lookup(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
  ) -> anyhow::Result<UploadStatus> {
    // Draft 12 offset discovery is an exclusive recovery point: fence any
    // in-flight append before returning an offset that the client may reuse.
    let row = sqlx::query("UPDATE oxibelt_uploads SET state=CASE WHEN state='dispatching' AND lease_until<=clock_timestamp() THEN 'indeterminate' WHEN state='validating' AND (lease_until IS NULL OR lease_until<=clock_timestamp()) THEN 'validation_failed' ELSE state END,fence_epoch=fence_epoch+CASE WHEN reservation_token IS NOT NULL OR (state='dispatching' AND lease_until<=clock_timestamp()) OR (state='validating' AND (lease_until IS NULL OR lease_until<=clock_timestamp())) THEN 1 ELSE 0 END,lease_holder=CASE WHEN reservation_token IS NOT NULL OR (state='dispatching' AND lease_until<=clock_timestamp()) OR (state='validating' AND (lease_until IS NULL OR lease_until<=clock_timestamp())) THEN NULL ELSE lease_holder END,lease_until=CASE WHEN reservation_token IS NOT NULL OR (state='dispatching' AND lease_until<=clock_timestamp()) OR (state='validating' AND (lease_until IS NULL OR lease_until<=clock_timestamp())) THEN NULL ELSE lease_until END,reservation_bytes=CASE WHEN state='validating' AND (lease_until IS NULL OR lease_until<=clock_timestamp()) THEN NULL WHEN reservation_token IS NULL THEN reservation_bytes ELSE NULL END,reservation_token=NULL,reservation_offset_bytes=NULL WHERE id=$1 AND owner_json=$2::jsonb AND binding_json=$3::jsonb AND state<>'deleted' AND expires_at_ms>db_now_ms() RETURNING id,profile_name,offset_bytes,declared_total_bytes,expires_at_ms,state,object_key,object_sha256,object_bytes,object_version")
      .bind(id).bind(serde_json::to_string(owner)?).bind(binding.to_string()).fetch_optional(&self.pool).await?
      .ok_or(UploadRejection::NotFound)?;
    status_row(&row)
  }

  pub async fn declare_length(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
    total: u64,
  ) -> anyhow::Result<UploadStatus> {
    let row = sqlx::query("UPDATE oxibelt_uploads SET declared_total_bytes=$4 WHERE id=$1 AND owner_json=$2::jsonb AND binding_json=$3::jsonb AND state='active' AND expires_at_ms>db_now_ms() AND reservation_token IS NULL AND (declared_total_bytes IS NULL OR declared_total_bytes=$4) AND offset_bytes<=$4 AND $4<=(profile_json->>'max_upload_bytes')::bigint RETURNING id,profile_name,offset_bytes,declared_total_bytes,expires_at_ms,state,object_key,object_sha256,object_bytes,object_version")
      .bind(id).bind(serde_json::to_string(owner)?).bind(binding.to_string()).bind(to_i64(total)?)
      .fetch_optional(&self.pool).await?.ok_or(UploadRejection::Conflict)?;
    status_row(&row)
  }

  pub async fn begin_append(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
    expected_offset: u64,
    length: u64,
  ) -> anyhow::Result<AppendReservation> {
    if length == 0 {
      bail!("managed upload part length must be nonzero");
    }
    let token = random_id()?;
    let mut tx = self.pool.begin().await?;
    let row = sqlx::query("SELECT profile_json::text AS profile_json_text,offset_bytes,declared_total_bytes,state,fence_epoch,reservation_token,(lease_until IS NOT NULL AND lease_until>clock_timestamp()) lease_valid FROM oxibelt_uploads WHERE id=$1 AND owner_json=$2::jsonb AND binding_json=$3::jsonb AND expires_at_ms>db_now_ms() FOR UPDATE")
      .bind(id).bind(serde_json::to_string(owner)?).bind(binding.to_string()).fetch_optional(&mut *tx).await?
      .ok_or(UploadRejection::NotFound)?;
    let profile: UploadProfileConfig =
      serde_json::from_str(&row.try_get::<String, _>("profile_json_text")?)?;
    lock_profile(&mut tx, &profile.name).await?;
    let reserved = row
      .try_get::<Option<String>, _>("reservation_token")?
      .is_some();
    if reserved && row.try_get::<bool, _>("lease_valid")? {
      return Err(UploadRejection::Conflict.into());
    }
    let offset = from_i64(row.try_get("offset_bytes")?)?;
    let end = expected_offset
      .checked_add(length)
      .ok_or_else(|| anyhow::anyhow!("managed upload part length overflow"))?;
    let declared = row
      .try_get::<Option<i64>, _>("declared_total_bytes")?
      .map(from_i64)
      .transpose()?;
    if row.try_get::<String, _>("state")? != "active"
      || offset != expected_offset
      || length > profile.max_part_bytes
      || end > profile.max_upload_bytes
      || declared.is_some_and(|n| end > n)
    {
      return Err(UploadRejection::Conflict.into());
    }
    let parts: i64 =
      sqlx::query_scalar("SELECT count(*) FROM oxibelt_upload_parts WHERE upload_id=$1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    if parts >= i64::from(profile.max_parts) {
      return Err(UploadRejection::Capacity.into());
    }
    let concurrent: i64 = sqlx::query_scalar("SELECT count(*) FROM oxibelt_uploads WHERE profile_name=$1 AND reservation_token IS NOT NULL AND lease_until>clock_timestamp()")
      .bind(&profile.name).fetch_one(&mut *tx).await?;
    if concurrent >= i64::from(profile.max_concurrent_parts) {
      return Err(UploadRejection::Capacity.into());
    }
    if profile_usage(&mut tx, &profile.name)
      .await?
      .saturating_add(length)
      > profile.max_storage_bytes
    {
      return Err(UploadRejection::Capacity.into());
    }
    let epoch = from_i64(row.try_get::<i64, _>("fence_epoch")?)?
      .checked_add(if reserved { 2 } else { 1 })
      .ok_or_else(|| anyhow::anyhow!("managed upload fence epoch overflow"))?;
    let claimed = sqlx::query("UPDATE oxibelt_uploads SET reservation_token=$2,reservation_offset_bytes=$3,reservation_bytes=$4,fence_epoch=$5,lease_holder=$2,lease_until=clock_timestamp()+make_interval(secs=>$6) WHERE id=$1 AND state='active' AND expires_at_ms>db_now_ms()")
      .bind(id).bind(&token).bind(to_i64(expected_offset)?).bind(to_i64(length)?).bind(to_i64(epoch)?).bind(LEASE_SECONDS).execute(&mut *tx).await?;
    if claimed.rows_affected() != 1 {
      return Err(UploadRejection::Conflict.into());
    }
    tx.commit().await?;
    Ok(AppendReservation {
      id: id.to_string(),
      expected_offset,
      length,
      fence_epoch: epoch,
      backend_token: token,
    })
  }

  pub async fn commit_fully_inspected_part(
    &self,
    reservation: &AppendReservation,
    inspected: &InspectedPart,
    mut body: UploadByteStream,
  ) -> anyhow::Result<UploadStatus> {
    if inspected.bytes == 0
      || inspected.bytes > reservation.length
      || !is_sha256_hex(&inspected.sha256)
    {
      bail!("managed upload inspection evidence does not match reserved part");
    }
    self.renew_append(reservation).await?;
    let profile_name = self.reservation_profile(reservation).await?;
    let key = self.object_key("chunks", &reservation.id)?;
    self
      .track_orphan_intent(&key, &profile_name, reservation.length)
      .await?;
    let (path, multipart_id) = self.begin_multipart(&key).await?;
    let api: Arc<dyn ManagedMultipartApi> = self.objects.clone();
    let mut writer = Some(ManagedMultipartWriter::new(
      api,
      path,
      multipart_id,
      inspected.bytes,
      self.pool.clone(),
      key.clone(),
    )?);
    let mut digest = Sha256::new();
    let mut written = 0_u64;
    let mut renew = tokio::time::interval(Duration::from_secs(RENEW_SECONDS));
    renew.tick().await;
    loop {
      tokio::select! {
        frame = body.next() => match frame {
          Some(Ok(bytes)) => { written = written.checked_add(u64::try_from(bytes.len())?).ok_or_else(|| anyhow::anyhow!("managed upload chunk length overflow"))?;
            if written > reservation.length { abort_writer(writer.take()).await; bail!("managed upload body exceeds its reservation"); }
            digest.update(&bytes);
            let put = writer.as_mut().ok_or_else(|| anyhow::anyhow!("managed upload writer disappeared"))?.put(bytes).await;
            if let Err(error) = put { abort_writer(writer.take()).await; return Err(error); } }
          Some(Err(error)) => { abort_writer(writer.take()).await; return Err(error).context("managed upload body stream failed"); }
          None => break,
        },
        _ = renew.tick() => {
          if let Err(error) = self.renew_append(reservation).await {
            abort_writer(writer.take()).await;
            return Err(error);
          }
          if let Err(error) = self.refresh_orphan_intent(&key).await {
            abort_writer(writer.take()).await;
            return Err(error);
          }
        },
      }
    }
    let actual = hex_digest(digest.finalize());
    if written != inspected.bytes || actual != inspected.sha256 {
      abort_writer(writer.take()).await;
      bail!("managed upload stream differs from whole-part inspection evidence");
    }
    if let Err(error) = self.renew_append(reservation).await {
      abort_writer(writer.take()).await;
      return Err(error);
    }
    if let Err(error) = self.refresh_orphan_intent(&key).await {
      abort_writer(writer.take()).await;
      return Err(error);
    }
    let put = writer
      .take()
      .ok_or_else(|| anyhow::anyhow!("managed upload writer disappeared"))?
      .finish()
      .await?;
    self
      .complete_orphan_intent(&key, written, put.version.as_deref())
      .await?;
    let mut tx = self.pool.begin().await?;
    let row = sqlx::query("UPDATE oxibelt_uploads SET offset_bytes=offset_bytes+$6,reservation_token=NULL,reservation_offset_bytes=NULL,reservation_bytes=NULL,lease_holder=NULL,lease_until=NULL,fence_epoch=fence_epoch+1 WHERE id=$1 AND state='active' AND fence_epoch=$2 AND reservation_token=$3 AND lease_holder=$3 AND reservation_offset_bytes=$4 AND reservation_bytes=$5 AND lease_until>clock_timestamp() AND expires_at_ms>db_now_ms() RETURNING id,profile_name,offset_bytes,declared_total_bytes,expires_at_ms,state,object_key,object_sha256,object_bytes,object_version")
      .bind(&reservation.id).bind(to_i64(reservation.fence_epoch)?).bind(reservation.backend_token()).bind(to_i64(reservation.expected_offset)?).bind(to_i64(reservation.length)?).bind(to_i64(written)?)
      .fetch_optional(&mut *tx).await?.ok_or(UploadRejection::Conflict)?;
    sqlx::query("INSERT INTO oxibelt_upload_parts(upload_id,offset_bytes,bytes,sha256,object_key,object_version) VALUES($1,$2,$3,$4,$5,$6)")
      .bind(&reservation.id).bind(to_i64(reservation.expected_offset)?).bind(to_i64(written)?).bind(&actual).bind(&key).bind(put.version).execute(&mut *tx).await?;
    let status = status_row(&row)?;
    tx.commit().await?;
    self.untrack_orphan(&key).await?;
    Ok(status)
  }

  pub async fn abort_append(&self, reservation: &AppendReservation) -> anyhow::Result<()> {
    sqlx::query("UPDATE oxibelt_uploads SET reservation_token=NULL,reservation_offset_bytes=NULL,reservation_bytes=NULL,lease_holder=NULL,lease_until=NULL,fence_epoch=fence_epoch+1 WHERE id=$1 AND fence_epoch=$2 AND reservation_token=$3")
      .bind(&reservation.id).bind(to_i64(reservation.fence_epoch)?).bind(reservation.backend_token()).execute(&self.pool).await?;
    Ok(())
  }

  pub async fn request_metadata(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
  ) -> anyhow::Result<UploadRequestMetadata> {
    let row = sqlx::query("SELECT method,uri,safe_headers::text AS safe_headers_text,dictionary_pin_json::text AS dictionary_pin_json_text FROM oxibelt_uploads WHERE id=$1 AND owner_json=$2::jsonb AND binding_json=$3::jsonb AND state<>'deleted' AND expires_at_ms>db_now_ms()")
      .bind(id).bind(serde_json::to_string(owner)?).bind(binding.to_string()).fetch_optional(&self.pool).await?.ok_or(UploadRejection::NotFound)?;
    Ok(UploadRequestMetadata {
      method: row.try_get::<String, _>("method")?.parse()?,
      uri: row.try_get::<String, _>("uri")?.parse()?,
      safe_headers: serde_json::from_str(&row.try_get::<String, _>("safe_headers_text")?)?,
      dictionary: row
        .try_get::<Option<String>, _>("dictionary_pin_json_text")?
        .map(|value| serde_json::from_str(&value))
        .transpose()?,
    })
  }

  pub async fn read_object(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
  ) -> anyhow::Result<UploadByteStream> {
    let status = self.lookup(id, owner, binding).await?;
    if !matches!(status.state, UploadState::Ready | UploadState::Complete) {
      return Err(UploadRejection::Conflict.into());
    }
    let object = status
      .object
      .ok_or_else(|| anyhow::anyhow!("managed upload object is not published"))?;
    verified_stream(
      self.objects.clone(),
      object.key,
      object.version,
      object.bytes,
      object.sha256,
    )
    .await
  }

  pub async fn read_assembled(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
  ) -> anyhow::Result<UploadByteStream> {
    let state: Option<String> = sqlx::query_scalar(
      "SELECT state FROM oxibelt_uploads WHERE id=$1 AND owner_json=$2::jsonb AND binding_json=$3::jsonb AND state<>'deleted' AND expires_at_ms>db_now_ms()",
    )
    .bind(id)
    .bind(serde_json::to_string(owner)?)
    .bind(binding.to_string())
    .fetch_optional(&self.pool)
    .await?;
    let Some(state) = state else {
      return Err(UploadRejection::NotFound.into());
    };
    if !matches!(
      state.as_str(),
      "active" | "completing" | "validating" | "ready"
    ) {
      return Err(UploadRejection::Conflict.into());
    }
    let parts = load_parts(&self.pool, id).await?;
    validate_layout(&parts)?;
    let stream = futures_util::stream::try_unfold(
      (
        Arc::clone(&self.objects),
        parts,
        0_usize,
        None::<UploadByteStream>,
        Sha256::new(),
        0_u64,
      ),
      |(objects, parts, mut index, mut current, mut digest, mut seen)| async move {
        loop {
          if current.is_none() {
            let Some(part) = parts.get(index) else {
              return Ok(None);
            };
            let result = objects
              .get_opts(
                &object_path(&part.key)?,
                GetOptions::new().with_version(part.version.clone()),
              )
              .await?;
            if result.meta.size != part.bytes {
              bail!("managed upload stored chunk length mismatch");
            }
            current = Some(Box::pin(result.into_stream().map_err(anyhow::Error::from)));
            digest = Sha256::new();
            seen = 0;
          }
          match current
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("managed upload reader disappeared"))?
            .next()
            .await
          {
            Some(Ok(bytes)) => {
              seen = seen
                .checked_add(u64::try_from(bytes.len())?)
                .ok_or_else(|| anyhow::anyhow!("managed upload chunk length overflow"))?;
              digest.update(&bytes);
              return Ok(Some((
                bytes,
                (objects, parts, index, current, digest, seen),
              )));
            }
            Some(Err(error)) => return Err(error),
            None => {
              let part = &parts[index];
              if seen != part.bytes
                || hex_digest(std::mem::take(&mut digest).finalize()) != part.sha256
              {
                bail!("managed upload stored chunk digest mismatch");
              }
              index += 1;
              current = None;
            }
          }
        }
      },
    );
    Ok(Box::pin(stream))
  }

  pub async fn claim_complete(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
    expected_offset: u64,
  ) -> anyhow::Result<UploadStatus> {
    let row = sqlx::query("UPDATE oxibelt_uploads SET state=CASE WHEN dictionary_pin_json IS NULL THEN 'completing' ELSE 'validating' END,fence_epoch=fence_epoch+1,lease_holder=CASE WHEN dictionary_pin_json IS NULL THEN lease_holder ELSE 'dictionary-validation' END,lease_until=CASE WHEN dictionary_pin_json IS NULL THEN lease_until ELSE clock_timestamp()+make_interval(secs=>$5) END WHERE id=$1 AND owner_json=$2::jsonb AND binding_json=$3::jsonb AND state='active' AND expires_at_ms>db_now_ms() AND reservation_token IS NULL AND offset_bytes=$4 AND (declared_total_bytes IS NULL OR declared_total_bytes=$4) RETURNING id,profile_name,offset_bytes,declared_total_bytes,expires_at_ms,state,object_key,object_sha256,object_bytes,object_version")
      .bind(id).bind(serde_json::to_string(owner)?).bind(binding.to_string()).bind(to_i64(expected_offset)?).bind(LEASE_SECONDS).fetch_optional(&self.pool).await?
      .ok_or(UploadRejection::Conflict)?;
    status_row(&row)
  }

  pub async fn publish_object(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
  ) -> anyhow::Result<UploadStatus> {
    let token = random_id()?;
    let (profile, epoch, parts, total) = self.claim_publish(id, owner, binding, &token).await?;
    let key = self.object_key("objects", id)?;
    let path = object_path(&key)?;
    self.track_orphan_intent(&key, &profile.name, total).await?;
    let mut digest = Sha256::new();
    let mut renew = tokio::time::interval(Duration::from_secs(RENEW_SECONDS));
    renew.tick().await;
    let put = if parts.is_empty() {
      self
        .objects
        .put_opts(&path, Bytes::new().into(), PutMode::Create.into())
        .await?
    } else {
      let (multipart_path, multipart_id) = self.begin_multipart(&key).await?;
      let api: Arc<dyn ManagedMultipartApi> = self.objects.clone();
      let mut writer = Some(ManagedMultipartWriter::new(
        api,
        multipart_path,
        multipart_id,
        total,
        self.pool.clone(),
        key.clone(),
      )?);
      for part in &parts {
        if let Err(error) = self.renew_publish(id, epoch, &token).await {
          abort_writer(writer.take()).await;
          return Err(error);
        }
        if let Err(error) = self.refresh_orphan_intent(&key).await {
          abort_writer(writer.take()).await;
          return Err(error);
        }
        let result = match self
          .objects
          .get_opts(
            &object_path(&part.key)?,
            GetOptions::new().with_version(part.version.clone()),
          )
          .await
        {
          Ok(result) => result,
          Err(error) => {
            abort_writer(writer.take()).await;
            return Err(error.into());
          }
        };
        if result.meta.size != part.bytes {
          abort_writer(writer.take()).await;
          bail!("managed upload chunk changed before object publication");
        }
        let mut stream = result.into_stream();
        let mut part_digest = Sha256::new();
        let mut seen = 0_u64;
        'stream: loop {
          let bytes = loop {
            tokio::select! {
              result = stream.try_next() => match result {
                Ok(Some(bytes)) => break bytes,
                Ok(None) => break 'stream,
                Err(error) => {
                  abort_writer(writer.take()).await;
                  return Err(error.into());
                }
              },
              _ = renew.tick() => {
                if let Err(error) = self.renew_publish(id, epoch, &token).await {
                  abort_writer(writer.take()).await;
                  return Err(error);
                }
                if let Err(error) = self.refresh_orphan_intent(&key).await {
                  abort_writer(writer.take()).await;
                  return Err(error);
                }
              }
            }
          };
          seen = seen
            .checked_add(u64::try_from(bytes.len())?)
            .ok_or_else(|| anyhow::anyhow!("managed upload object length overflow"))?;
          part_digest.update(&bytes);
          digest.update(&bytes);
          let put = writer
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("managed upload writer disappeared"))?
            .put(bytes)
            .await;
          if let Err(error) = put {
            abort_writer(writer.take()).await;
            return Err(error);
          }
        }
        if seen != part.bytes || hex_digest(part_digest.finalize()) != part.sha256 {
          abort_writer(writer.take()).await;
          bail!("managed upload chunk changed before object publication");
        }
      }
      if let Err(error) = self.renew_publish(id, epoch, &token).await {
        abort_writer(writer.take()).await;
        return Err(error);
      }
      if let Err(error) = self.refresh_orphan_intent(&key).await {
        abort_writer(writer.take()).await;
        return Err(error);
      }
      writer
        .take()
        .ok_or_else(|| anyhow::anyhow!("managed upload writer disappeared"))?
        .finish()
        .await?
    };
    let sha = hex_digest(digest.finalize());
    self
      .complete_orphan_intent(&key, total, put.version.as_deref())
      .await?;
    let published_state = match profile.destination {
      UploadDestinationConfig::Object => "complete",
      UploadDestinationConfig::Upstream { .. } => "ready",
    };
    let status = self
      .finalize_publish(
        id,
        epoch,
        &token,
        published_state,
        &key,
        &sha,
        total,
        put.version.as_deref(),
        profile.object_ttl_seconds,
      )
      .await?;
    self.untrack_orphan(&key).await?;
    Ok(status)
  }

  pub async fn publish_decoded_object(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
    expected_bytes: u64,
    expected_sha256: &str,
    mut body: UploadByteStream,
  ) -> anyhow::Result<UploadStatus> {
    let token = random_id()?;
    let key = self.object_key("objects", id)?;
    let (profile, epoch) = self
      .claim_decoded_publish(id, owner, binding, expected_bytes, (&token, &key))
      .await?;
    let (path, multipart_id) = self.begin_multipart(&key).await?;
    let api: Arc<dyn ManagedMultipartApi> = self.objects.clone();
    let mut writer = Some(ManagedMultipartWriter::new(
      api,
      path,
      multipart_id,
      expected_bytes,
      self.pool.clone(),
      key.clone(),
    )?);
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut renew = tokio::time::interval(Duration::from_secs(RENEW_SECONDS));
    renew.tick().await;
    loop {
      tokio::select! {
        frame = body.next() => match frame {
          Some(Ok(bytes)) => {
            total = total.checked_add(u64::try_from(bytes.len())?).ok_or_else(|| anyhow::anyhow!("managed decoded object length overflow"))?;
            if total > expected_bytes { abort_writer(writer.take()).await; bail!("managed decoded object exceeds inspected size"); }
            digest.update(&bytes);
            if let Err(error) = writer.as_mut().ok_or_else(|| anyhow::anyhow!("managed upload writer disappeared"))?.put(bytes).await {
              abort_writer(writer.take()).await; return Err(error);
            }
          }
          Some(Err(error)) => { abort_writer(writer.take()).await; return Err(error).context("managed decoded object stream failed"); }
          None => break,
        },
        _ = renew.tick() => {
          if let Err(error) = self.renew_publish(id, epoch, &token).await { abort_writer(writer.take()).await; return Err(error); }
          if let Err(error) = self.refresh_orphan_intent(&key).await { abort_writer(writer.take()).await; return Err(error); }
        },
      }
    }
    let actual = hex_digest(digest.finalize());
    if total != expected_bytes || actual != expected_sha256 {
      abort_writer(writer.take()).await;
      bail!("managed decoded object differs from inspected representation");
    }
    self.renew_publish(id, epoch, &token).await?;
    self.refresh_orphan_intent(&key).await?;
    let put = writer
      .take()
      .ok_or_else(|| anyhow::anyhow!("managed upload writer disappeared"))?
      .finish()
      .await?;
    self
      .complete_orphan_intent(&key, total, put.version.as_deref())
      .await?;
    let published_state = match profile.destination {
      UploadDestinationConfig::Object => "complete",
      UploadDestinationConfig::Upstream { .. } => "ready",
    };
    let status = self
      .finalize_publish(
        id,
        epoch,
        &token,
        published_state,
        &key,
        &actual,
        total,
        put.version.as_deref(),
        profile.object_ttl_seconds,
      )
      .await?;
    self.untrack_orphan(&key).await?;
    Ok(status)
  }

  pub async fn fail_validation(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
  ) -> anyhow::Result<UploadStatus> {
    let row = sqlx::query("UPDATE oxibelt_uploads SET state='validation_failed',reservation_token=NULL,reservation_offset_bytes=NULL,reservation_bytes=NULL,lease_holder=NULL,lease_until=NULL,fence_epoch=fence_epoch+1 WHERE id=$1 AND owner_json=$2::jsonb AND binding_json=$3::jsonb AND state IN ('active','validating') AND dictionary_pin_json IS NOT NULL AND expires_at_ms>db_now_ms() RETURNING id,profile_name,offset_bytes,declared_total_bytes,expires_at_ms,state,object_key,object_sha256,object_bytes,object_version")
      .bind(id)
      .bind(serde_json::to_string(owner)?)
      .bind(binding.to_string())
      .fetch_optional(&self.pool)
      .await?
      .ok_or(UploadRejection::Conflict)?;
    status_row(&row)
  }

  pub async fn begin_dispatch(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
  ) -> anyhow::Result<DispatchClaim> {
    let row=sqlx::query("UPDATE oxibelt_uploads SET state='dispatching',fence_epoch=fence_epoch+1,lease_until=clock_timestamp()+make_interval(secs=>$4) WHERE id=$1 AND owner_json=$2::jsonb AND binding_json=$3::jsonb AND state='ready' AND expires_at_ms>db_now_ms() AND object_key IS NOT NULL RETURNING fence_epoch,method,uri,safe_headers::text AS safe_headers_text,object_key,object_sha256,object_bytes,object_version")
      .bind(id).bind(serde_json::to_string(owner)?).bind(binding.to_string()).bind(LEASE_SECONDS).fetch_optional(&self.pool).await?.ok_or_else(||anyhow::anyhow!("managed upload is not ready for dispatch"))?;
    let fence_epoch = from_i64(row.try_get("fence_epoch")?)?;
    // Keep persisted metadata validation at the dispatch boundary without
    // exposing unused copies in the fencing token.
    let _: http::Method = row.try_get::<String, _>("method")?.parse()?;
    let _: http::Uri = row.try_get::<String, _>("uri")?.parse()?;
    let _: serde_json::Value =
      serde_json::from_str(&row.try_get::<String, _>("safe_headers_text")?)?;
    let _ = object_from_row(&row)?;
    Ok(DispatchClaim {
      id: id.to_string(),
      fence_epoch,
    })
  }

  pub async fn finish_dispatch(
    &self,
    claim: &DispatchClaim,
    terminal: DispatchTerminal,
  ) -> anyhow::Result<UploadStatus> {
    let state = match terminal {
      DispatchTerminal::Complete => "complete",
      DispatchTerminal::Indeterminate => "indeterminate",
    };
    let row=sqlx::query("UPDATE oxibelt_uploads SET state=$3,fence_epoch=fence_epoch+1,lease_until=NULL WHERE id=$1 AND state='dispatching' AND fence_epoch=$2 AND expires_at_ms>db_now_ms() RETURNING id,profile_name,offset_bytes,declared_total_bytes,expires_at_ms,state,object_key,object_sha256,object_bytes,object_version")
      .bind(&claim.id).bind(to_i64(claim.fence_epoch)?).bind(state).fetch_optional(&self.pool).await?.ok_or_else(||anyhow::anyhow!("managed upload dispatch claim is fenced"))?;
    status_row(&row)
  }

  pub async fn delete(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
  ) -> anyhow::Result<()> {
    let result=sqlx::query("UPDATE oxibelt_uploads SET state='deleted',reservation_token=NULL,reservation_offset_bytes=NULL,reservation_bytes=NULL,lease_holder=NULL,lease_until=NULL,fence_epoch=fence_epoch+1 WHERE id=$1 AND owner_json=$2::jsonb AND binding_json=$3::jsonb AND state<>'dispatching'")
      .bind(id).bind(serde_json::to_string(owner)?).bind(binding.to_string()).execute(&self.pool).await?;
    if result.rows_affected() != 1 {
      bail!("managed upload cannot be deleted in its current state");
    }
    self.cleanup_deleted(id).await
  }

  pub async fn collect_garbage(&self, _now_ms: u64, limit: usize) -> anyhow::Result<usize> {
    let limit = limit.min(MAX_GC_LIMIT);
    if limit == 0 {
      return Ok(0);
    }
    let rows=sqlx::query("WITH c AS (SELECT id FROM oxibelt_uploads WHERE state='deleted' OR expires_at_ms<=db_now_ms() ORDER BY expires_at_ms,id FOR UPDATE SKIP LOCKED LIMIT $1) UPDATE oxibelt_uploads u SET state='deleted',reservation_token=NULL,reservation_offset_bytes=NULL,reservation_bytes=NULL,lease_holder=NULL,lease_until=NULL,fence_epoch=fence_epoch+1 FROM c WHERE u.id=c.id RETURNING u.id")
      .bind(i64::try_from(limit)?).fetch_all(&self.pool).await?;
    let mut removed = 0;
    for row in rows {
      self.cleanup_deleted(row.try_get("id")?).await?;
      removed += 1;
    }
    if removed < limit {
      removed += self.collect_orphans(limit - removed).await?;
    }
    Ok(removed)
  }

  async fn claim_publish(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
    token: &str,
  ) -> anyhow::Result<(UploadProfileConfig, u64, Vec<StoredPart>, u64)> {
    let mut tx = self.pool.begin().await?;
    let row=sqlx::query("SELECT profile_json::text AS profile_json_text,offset_bytes,fence_epoch,lease_holder,(lease_until IS NOT NULL AND lease_until>clock_timestamp()) lease_valid FROM oxibelt_uploads WHERE id=$1 AND owner_json=$2::jsonb AND binding_json=$3::jsonb AND state='completing' AND expires_at_ms>db_now_ms() FOR UPDATE")
      .bind(id).bind(serde_json::to_string(owner)?).bind(binding.to_string()).fetch_optional(&mut *tx).await?.ok_or(UploadRejection::Conflict)?;
    let profile: UploadProfileConfig =
      serde_json::from_str(&row.try_get::<String, _>("profile_json_text")?)?;
    lock_profile(&mut tx, &profile.name).await?;
    if row.try_get::<Option<String>, _>("lease_holder")?.is_some()
      && row.try_get::<bool, _>("lease_valid")?
    {
      return Err(UploadRejection::Conflict.into());
    }
    let concurrent:i64=sqlx::query_scalar("SELECT count(*) FROM oxibelt_uploads WHERE profile_name=$1 AND state='completing' AND lease_holder IS NOT NULL AND lease_until>clock_timestamp()")
      .bind(&profile.name).fetch_one(&mut *tx).await?;
    if concurrent >= i64::from(profile.max_concurrent_uploads) {
      return Err(UploadRejection::Capacity.into());
    }
    let total = from_i64(row.try_get("offset_bytes")?)?;
    if profile_usage(&mut tx, &profile.name)
      .await?
      .saturating_add(total)
      > profile.max_storage_bytes
    {
      return Err(UploadRejection::Capacity.into());
    }
    let epoch = from_i64(row.try_get::<i64, _>("fence_epoch")?)?
      .checked_add(1)
      .ok_or_else(|| anyhow::anyhow!("managed upload fence epoch overflow"))?;
    let claimed = sqlx::query("UPDATE oxibelt_uploads SET fence_epoch=$2,lease_holder=$3,lease_until=clock_timestamp()+make_interval(secs=>$4),reservation_bytes=offset_bytes WHERE id=$1 AND state='completing' AND expires_at_ms>db_now_ms()")
      .bind(id).bind(to_i64(epoch)?).bind(token).bind(LEASE_SECONDS).execute(&mut *tx).await?;
    if claimed.rows_affected() != 1 {
      return Err(UploadRejection::Conflict.into());
    }
    let parts = load_parts_tx(&mut tx, id).await?;
    validate_layout(&parts)?;
    let sum = parts
      .iter()
      .try_fold(0_u64, |sum, p| sum.checked_add(p.bytes))
      .ok_or_else(|| anyhow::anyhow!("managed upload object length overflow"))?;
    if sum != total {
      bail!("managed upload durable parts do not match its offset");
    }
    tx.commit().await?;
    Ok((profile, epoch, parts, total))
  }

  async fn claim_decoded_publish(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
    decoded_bytes: u64,
    publication: (&str, &str),
  ) -> anyhow::Result<(UploadProfileConfig, u64)> {
    let (token, object_key) = publication;
    let mut tx = self.pool.begin().await?;
    let row = sqlx::query("SELECT profile_json::text AS profile_json_text,fence_epoch,lease_holder,(lease_until IS NOT NULL AND lease_until>clock_timestamp()) lease_valid FROM oxibelt_uploads WHERE id=$1 AND owner_json=$2::jsonb AND binding_json=$3::jsonb AND state='validating' AND dictionary_pin_json IS NOT NULL AND expires_at_ms>db_now_ms() FOR UPDATE")
      .bind(id).bind(serde_json::to_string(owner)?).bind(binding.to_string()).fetch_optional(&mut *tx).await?
      .ok_or(UploadRejection::Conflict)?;
    let profile: UploadProfileConfig =
      serde_json::from_str(&row.try_get::<String, _>("profile_json_text")?)?;
    lock_profile(&mut tx, &profile.name).await?;
    if row.try_get::<Option<String>, _>("lease_holder")?.as_deref() != Some("dictionary-validation")
      || !row.try_get::<bool, _>("lease_valid")?
    {
      return Err(UploadRejection::Conflict.into());
    }
    if profile_usage(&mut tx, &profile.name)
      .await?
      .saturating_add(decoded_bytes)
      > profile.max_storage_bytes
    {
      return Err(UploadRejection::Capacity.into());
    }
    let epoch = from_i64(row.try_get::<i64, _>("fence_epoch")?)?
      .checked_add(1)
      .ok_or_else(|| anyhow::anyhow!("managed upload fence epoch overflow"))?;
    let updated = sqlx::query("UPDATE oxibelt_uploads SET fence_epoch=$2,lease_holder=$3,lease_until=clock_timestamp()+make_interval(secs=>$4),reservation_bytes=NULL WHERE id=$1 AND state='validating' AND dictionary_pin_json IS NOT NULL AND lease_holder='dictionary-validation' AND lease_until>clock_timestamp() AND expires_at_ms>db_now_ms()")
      .bind(id).bind(to_i64(epoch)?).bind(token).bind(LEASE_SECONDS).execute(&mut *tx).await?;
    if updated.rows_affected() != 1 {
      return Err(UploadRejection::Conflict.into());
    }
    // Reserve physical output through the orphan ledger in this same
    // profile-locked transaction. The charge must survive lease expiry and
    // cancellation before the S3 writer has even been constructed.
    sqlx::query("INSERT INTO oxibelt_upload_orphan_objects(object_key,profile_name,bytes,intent_state) VALUES($1,$2,$3,'pending')")
      .bind(object_key).bind(&profile.name).bind(to_i64(decoded_bytes)?).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok((profile, epoch))
  }

  async fn renew_append(&self, r: &AppendReservation) -> anyhow::Result<()> {
    let result=sqlx::query("UPDATE oxibelt_uploads SET lease_until=clock_timestamp()+make_interval(secs=>$4) WHERE id=$1 AND state='active' AND fence_epoch=$2 AND reservation_token=$3 AND lease_holder=$3 AND lease_until>clock_timestamp() AND expires_at_ms>db_now_ms()")
      .bind(&r.id).bind(to_i64(r.fence_epoch)?).bind(r.backend_token()).bind(LEASE_SECONDS).execute(&self.pool).await?;
    if result.rows_affected() != 1 {
      return Err(UploadRejection::Conflict.into());
    }
    Ok(())
  }

  async fn reservation_profile(&self, r: &AppendReservation) -> anyhow::Result<String> {
    let profile=sqlx::query_scalar("SELECT profile_name FROM oxibelt_uploads WHERE id=$1 AND state='active' AND fence_epoch=$2 AND reservation_token=$3 AND lease_until>clock_timestamp() AND expires_at_ms>db_now_ms()")
      .bind(&r.id).bind(to_i64(r.fence_epoch)?).bind(r.backend_token())
      .fetch_optional(&self.pool).await?;
    profile.ok_or_else(|| anyhow::Error::new(UploadRejection::Conflict))
  }

  async fn track_orphan_intent(&self, key: &str, profile: &str, bytes: u64) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO oxibelt_upload_orphan_objects(object_key,profile_name,bytes,intent_state) VALUES($1,$2,$3,'pending')")
      .bind(key).bind(profile).bind(to_i64(bytes)?).execute(&self.pool).await?;
    Ok(())
  }

  async fn begin_multipart(&self, key: &str) -> anyhow::Result<(ObjectPath, String)> {
    let path = object_path(key)?;
    let multipart_id = MultipartStore::create_multipart(self.objects.as_ref(), &path).await?;
    let persisted = sqlx::query("UPDATE oxibelt_upload_orphan_objects SET multipart_id=$2,created_at=clock_timestamp() WHERE object_key=$1 AND intent_state='pending' AND multipart_id IS NULL")
      .bind(key).bind(&multipart_id).execute(&self.pool).await;
    match persisted {
      Ok(result) if result.rows_affected() == 1 => Ok((path, multipart_id)),
      Ok(_) => {
        let _ = MultipartStore::abort_multipart(self.objects.as_ref(), &path, &multipart_id).await;
        bail!("managed upload cleanup intent disappeared before multipart write")
      }
      Err(error) => {
        let _ = MultipartStore::abort_multipart(self.objects.as_ref(), &path, &multipart_id).await;
        Err(error.into())
      }
    }
  }

  async fn refresh_orphan_intent(&self, key: &str) -> anyhow::Result<()> {
    let result = sqlx::query("UPDATE oxibelt_upload_orphan_objects SET created_at=clock_timestamp() WHERE object_key=$1 AND intent_state='pending'")
      .bind(key).execute(&self.pool).await?;
    if result.rows_affected() != 1 {
      bail!("managed upload cleanup intent disappeared during S3 write");
    }
    Ok(())
  }

  async fn complete_orphan_intent(
    &self,
    key: &str,
    bytes: u64,
    version: Option<&str>,
  ) -> anyhow::Result<()> {
    let result = sqlx::query("UPDATE oxibelt_upload_orphan_objects SET bytes=$2,object_version=$3,intent_state='completed',multipart_id=NULL,created_at=clock_timestamp() WHERE object_key=$1 AND intent_state='pending'")
      .bind(key).bind(to_i64(bytes)?).bind(version).execute(&self.pool).await?;
    if result.rows_affected() != 1 {
      bail!("managed upload cleanup intent disappeared after S3 write");
    }
    Ok(())
  }

  async fn untrack_orphan(&self, key: &str) -> anyhow::Result<()> {
    untrack_orphan_pool(&self.pool, key).await
  }

  async fn renew_publish(&self, id: &str, epoch: u64, token: &str) -> anyhow::Result<()> {
    let result=sqlx::query("UPDATE oxibelt_uploads SET lease_until=clock_timestamp()+make_interval(secs=>$4) WHERE id=$1 AND state IN ('completing','validating') AND fence_epoch=$2 AND lease_holder=$3 AND lease_until>clock_timestamp() AND expires_at_ms>db_now_ms()")
      .bind(id).bind(to_i64(epoch)?).bind(token).bind(LEASE_SECONDS).execute(&self.pool).await?;
    if result.rows_affected() != 1 {
      return Err(UploadRejection::Conflict.into());
    }
    Ok(())
  }

  #[allow(clippy::too_many_arguments)]
  async fn finalize_publish(
    &self,
    id: &str,
    epoch: u64,
    token: &str,
    state: &str,
    key: &str,
    sha256: &str,
    bytes: u64,
    version: Option<&str>,
    object_ttl_seconds: u64,
  ) -> anyhow::Result<UploadStatus> {
    let row=sqlx::query("UPDATE oxibelt_uploads SET state=$4,object_key=$5,object_sha256=$6,object_bytes=$7,object_version=$8,object_expires_at_ms=db_now_ms()+$9*1000,expires_at_ms=db_now_ms()+$9*1000,lease_holder=NULL,lease_until=NULL,reservation_bytes=NULL,fence_epoch=fence_epoch+1 WHERE id=$1 AND state IN ('completing','validating') AND fence_epoch=$2 AND lease_holder=$3 AND lease_until>clock_timestamp() AND expires_at_ms>db_now_ms() RETURNING id,profile_name,offset_bytes,declared_total_bytes,expires_at_ms,state,object_key,object_sha256,object_bytes,object_version")
      .bind(id).bind(to_i64(epoch)?).bind(token).bind(state).bind(key).bind(sha256).bind(to_i64(bytes)?).bind(version).bind(to_i64(object_ttl_seconds)?)
      .fetch_optional(&self.pool).await?.ok_or(UploadRejection::Conflict)?;
    status_row(&row)
  }

  async fn cleanup_deleted(&self, id: &str) -> anyhow::Result<()> {
    let object: Option<String> =
      sqlx::query_scalar("SELECT object_key FROM oxibelt_uploads WHERE id=$1 AND state='deleted'")
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .flatten();
    let mut keys = load_parts(&self.pool, id)
      .await?
      .into_iter()
      .map(|p| p.key)
      .collect::<Vec<_>>();
    if let Some(key) = object {
      keys.push(key);
    }
    for key in keys {
      match self.objects.delete(&object_path(&key)?).await {
        Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
        Err(error) => return Err(error).context("failed to delete managed upload object"),
      }
    }
    let mut tx = self.pool.begin().await?;
    sqlx::query("DELETE FROM oxibelt_upload_parts WHERE upload_id=$1 AND EXISTS(SELECT 1 FROM oxibelt_uploads WHERE id=$1 AND state='deleted')").bind(id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM oxibelt_uploads WHERE id=$1 AND state='deleted'")
      .bind(id)
      .execute(&mut *tx)
      .await?;
    tx.commit().await?;
    Ok(())
  }

  async fn collect_orphans(&self, limit: usize) -> anyhow::Result<usize> {
    let prefix = self.prefix.trim_matches('/');
    let parsed_prefix = if prefix.is_empty() {
      None
    } else {
      Some(object_path(prefix)?)
    };
    let database_now: i64 =
      sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        .fetch_one(&self.pool)
        .await?;
    let cutoff = database_now.saturating_sub(ORPHAN_GRACE_SECONDS);
    let tracked=sqlx::query("SELECT object_key,intent_state,multipart_id FROM oxibelt_upload_orphan_objects WHERE created_at<=to_timestamp($1) ORDER BY created_at,object_key LIMIT $2")
      .bind(cutoff).bind(i64::try_from(limit)?).fetch_all(&self.pool).await?;
    let mut removed = 0_usize;
    for row in tracked {
      let key: String = row.try_get("object_key")?;
      let intent_state: String = row.try_get("intent_state")?;
      let multipart_id: Option<String> = row.try_get("multipart_id")?;
      let referenced:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM oxibelt_upload_parts WHERE object_key=$1 UNION ALL SELECT 1 FROM oxibelt_uploads WHERE object_key=$1)").bind(&key).fetch_one(&self.pool).await?;
      if !referenced {
        let path = object_path(&key)?;
        if intent_state == "pending"
          && let Some(multipart_id) = multipart_id
        {
          match MultipartStore::abort_multipart(self.objects.as_ref(), &path, &multipart_id).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
            Err(error) => {
              return Err(error).context("failed to abort tracked managed multipart upload");
            }
          }
        }
        match self.objects.delete(&path).await {
          Ok(()) | Err(object_store::Error::NotFound { .. }) => removed += 1,
          Err(error) => {
            return Err(error).context("failed to delete tracked orphan managed upload object");
          }
        }
      }
      self.untrack_orphan(&key).await?;
    }
    if removed >= limit {
      return Ok(removed);
    }
    let cursor: Option<String> =
      sqlx::query_scalar("SELECT cursor FROM oxibelt_upload_gc_state WHERE component='objects'")
        .fetch_optional(&self.pool)
        .await?
        .flatten();
    let parsed_cursor = cursor.as_deref().map(object_path).transpose()?;
    let mut listed = if let Some(cursor) = parsed_cursor.as_ref() {
      self
        .objects
        .list_with_offset(parsed_prefix.as_ref(), cursor)
    } else {
      self.objects.list(parsed_prefix.as_ref())
    };
    let mut visited = 0_usize;
    let mut last = None;
    let mut reached_end = false;
    while visited < limit - removed {
      let Some(meta) = listed.try_next().await? else {
        reached_end = true;
        break;
      };
      visited += 1;
      last = Some(meta.location.to_string());
      if meta.last_modified.timestamp() > cutoff {
        continue;
      }
      let key = meta.location.to_string();
      let referenced:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM oxibelt_upload_parts WHERE object_key=$1 UNION ALL SELECT 1 FROM oxibelt_uploads WHERE object_key=$1 UNION ALL SELECT 1 FROM oxibelt_upload_orphan_objects WHERE object_key=$1)").bind(&key).fetch_one(&self.pool).await?;
      if referenced {
        continue;
      }
      match self.objects.delete(&meta.location).await {
        Ok(()) | Err(object_store::Error::NotFound { .. }) => removed += 1,
        Err(error) => return Err(error).context("failed to delete orphaned managed upload object"),
      }
    }
    let next_cursor = if reached_end { None } else { last };
    sqlx::query("INSERT INTO oxibelt_upload_gc_state(component,cursor) VALUES('objects',$1) ON CONFLICT(component) DO UPDATE SET cursor=EXCLUDED.cursor")
      .bind(next_cursor)
      .execute(&self.pool)
      .await?;
    Ok(removed)
  }

  fn object_key(&self, category: &str, id: &str) -> anyhow::Result<String> {
    let suffix = random_id()?;
    let prefix = self.prefix.trim_matches('/');
    Ok(if prefix.is_empty() {
      format!("{category}/{id}/{suffix}")
    } else {
      format!("{prefix}/{category}/{id}/{suffix}")
    })
  }
}

async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
  const LATEST_SCHEMA_VERSION: i32 = 4;
  let mut tx = pool.begin().await?;
  sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('oxibelt-managed-upload-schema',0))")
    .execute(&mut *tx)
    .await?;
  sqlx::query(UPLOAD_POSTGRES_MIGRATION_V1[0])
    .execute(&mut *tx)
    .await?;
  let existing: Option<i32> = sqlx::query_scalar(
    "SELECT version FROM oxibelt_upload_schema_migrations WHERE component='managed_uploads'",
  )
  .fetch_optional(&mut *tx)
  .await?;
  if existing.is_some_and(|version| version > LATEST_SCHEMA_VERSION) {
    bail!(
      "managed upload PostgreSQL schema is newer than this binary (supported through version {LATEST_SCHEMA_VERSION})"
    );
  }
  sqlx::query("CREATE OR REPLACE FUNCTION db_now_ms() RETURNS BIGINT LANGUAGE SQL VOLATILE PARALLEL SAFE AS $$ SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint $$").execute(&mut *tx).await?;
  for statement in UPLOAD_POSTGRES_MIGRATION_V1
    .iter()
    .skip(1)
    .chain(UPLOAD_POSTGRES_MIGRATION_V2.iter())
    .chain(UPLOAD_POSTGRES_MIGRATION_V3.iter())
    .chain(UPLOAD_POSTGRES_MIGRATION_V4.iter())
  {
    sqlx::query(*statement).execute(&mut *tx).await?;
  }
  tx.commit().await?;
  Ok(())
}

async fn lock_profile(
  tx: &mut Transaction<'_, sqlx::Postgres>,
  profile: &str,
) -> anyhow::Result<()> {
  sqlx::query(
    "SELECT pg_advisory_xact_lock(hashtextextended('oxibelt-managed-upload-profile:'||$1,0))",
  )
  .bind(profile)
  .execute(&mut **tx)
  .await?;
  Ok(())
}

async fn profile_usage(
  tx: &mut Transaction<'_, sqlx::Postgres>,
  profile: &str,
) -> anyhow::Result<u64> {
  let n:i64=sqlx::query_scalar("SELECT (COALESCE((SELECT sum(offset_bytes+CASE WHEN lease_until>clock_timestamp() THEN COALESCE(reservation_bytes,0) ELSE 0 END+COALESCE(object_bytes,0)) FROM oxibelt_uploads WHERE profile_name=$1),0)+COALESCE((SELECT sum(bytes) FROM oxibelt_upload_orphan_objects WHERE profile_name=$1),0))::bigint").bind(profile).fetch_one(&mut **tx).await?;
  from_i64(n)
}

async fn profile_sessions(
  tx: &mut Transaction<'_, sqlx::Postgres>,
  profile: &str,
) -> anyhow::Result<u64> {
  let count: i64 = sqlx::query_scalar("SELECT (COALESCE((SELECT count(*) FROM oxibelt_uploads WHERE profile_name=$1),0)+COALESCE((SELECT count(*) FROM oxibelt_upload_orphan_objects WHERE profile_name=$1),0))::bigint")
    .bind(profile).fetch_one(&mut **tx).await?;
  from_i64(count)
}

async fn load_parts(pool: &PgPool, id: &str) -> anyhow::Result<Vec<StoredPart>> {
  let rows=sqlx::query("SELECT offset_bytes,bytes,sha256,object_key,object_version FROM oxibelt_upload_parts WHERE upload_id=$1 ORDER BY offset_bytes").bind(id).fetch_all(pool).await?;
  rows.iter().map(part_row).collect()
}
async fn load_parts_tx(
  tx: &mut Transaction<'_, sqlx::Postgres>,
  id: &str,
) -> anyhow::Result<Vec<StoredPart>> {
  let rows=sqlx::query("SELECT offset_bytes,bytes,sha256,object_key,object_version FROM oxibelt_upload_parts WHERE upload_id=$1 ORDER BY offset_bytes").bind(id).fetch_all(&mut **tx).await?;
  rows.iter().map(part_row).collect()
}
fn part_row(row: &PgRow) -> anyhow::Result<StoredPart> {
  Ok(StoredPart {
    key: row.try_get("object_key")?,
    offset: from_i64(row.try_get("offset_bytes")?)?,
    bytes: from_i64(row.try_get("bytes")?)?,
    sha256: row.try_get("sha256")?,
    version: row.try_get("object_version")?,
  })
}
fn validate_layout(parts: &[StoredPart]) -> anyhow::Result<()> {
  let mut expected = 0;
  for part in parts {
    if part.offset != expected || part.bytes == 0 || !is_sha256_hex(&part.sha256) {
      bail!("managed upload durable part layout is invalid");
    }
    expected = expected
      .checked_add(part.bytes)
      .ok_or_else(|| anyhow::anyhow!("managed upload durable part layout overflow"))?;
  }
  Ok(())
}

async fn verified_stream(
  objects: Arc<dyn ObjectStore>,
  key: String,
  version: Option<String>,
  expected: u64,
  sha: String,
) -> anyhow::Result<UploadByteStream> {
  let result = objects
    .get_opts(&object_path(&key)?, GetOptions::new().with_version(version))
    .await?;
  if result.meta.size != expected {
    bail!("managed upload stored object length mismatch");
  }
  let inner: UploadByteStream = Box::pin(result.into_stream().map_err(anyhow::Error::from));
  let stream = futures_util::stream::try_unfold(
    (inner, Sha256::new(), 0_u64),
    move |(mut inner, mut digest, mut seen)| {
      let sha = sha.clone();
      async move {
        match inner.next().await {
          Some(Ok(bytes)) => {
            seen = seen
              .checked_add(u64::try_from(bytes.len())?)
              .ok_or_else(|| anyhow::anyhow!("managed upload object length overflow"))?;
            digest.update(&bytes);
            Ok(Some((bytes, (inner, digest, seen))))
          }
          Some(Err(e)) => Err(e),
          None => {
            if seen != expected || hex_digest(digest.finalize()) != sha {
              bail!("managed upload stored object digest mismatch");
            }
            Ok(None)
          }
        }
      }
    },
  );
  Ok(Box::pin(stream))
}

async fn abort_writer(writer: Option<ManagedMultipartWriter>) {
  if let Some(writer) = writer {
    writer.abort().await;
  }
}
async fn untrack_orphan_pool(pool: &PgPool, key: &str) -> anyhow::Result<()> {
  sqlx::query("DELETE FROM oxibelt_upload_orphan_objects WHERE object_key=$1")
    .bind(key)
    .execute(pool)
    .await?;
  Ok(())
}
fn required_env(name: &str) -> anyhow::Result<String> {
  std::env::var(name)
    .with_context(|| format!("managed upload required environment variable {name} is unavailable"))
}
fn store_schema(config: &UploadStoreConfig, settings: &PostgresS3UploadStoreConfig) -> String {
  let mut digest = Sha256::new();
  for value in [
    config.name.as_str(),
    settings.s3_bucket.as_str(),
    settings.s3_region.as_str(),
    settings.s3_endpoint.as_str(),
    settings.s3_prefix.as_str(),
  ] {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value.as_bytes());
  }
  let digest = digest.finalize();
  format!("oxibelt_upload_{}", hex_digest(&digest[..16]))
}
fn build_object_store(s: &PostgresS3UploadStoreConfig) -> anyhow::Result<Arc<AmazonS3>> {
  let mut b = AmazonS3Builder::new()
    .with_bucket_name(&s.s3_bucket)
    .with_region(&s.s3_region)
    .with_endpoint(&s.s3_endpoint)
    .with_access_key_id(required_env(&s.s3_access_key_env)?)
    .with_secret_access_key(required_env(&s.s3_secret_key_env)?)
    .with_virtual_hosted_style_request(s.s3_virtual_hosted_style);
  if let Some(name) = &s.s3_session_token_env {
    b = b.with_token(required_env(name)?);
  }
  if let Some(path) = &s.s3_root_certificate {
    const MAX_ROOT_CERTIFICATE_BYTES: u64 = 1024 * 1024;
    let metadata = std::fs::metadata(path).with_context(|| {
      format!(
        "failed to inspect managed upload S3 root {}",
        path.display()
      )
    })?;
    if metadata.len() == 0 || metadata.len() > MAX_ROOT_CERTIFICATE_BYTES {
      bail!("managed upload S3 root certificate is empty or exceeds 1 MiB");
    }
    let bytes = std::fs::read(path)
      .with_context(|| format!("failed to read managed upload S3 root {}", path.display()))?;
    let certificate = Certificate::from_pem(&bytes)
      .context("managed upload S3 root certificate is not valid PEM")?;
    b = b.with_client_options(ClientOptions::new().with_root_certificate(certificate));
  }
  Ok(Arc::new(b.build().map_err(|_| {
    anyhow::anyhow!("failed to build managed upload S3 object store")
  })?))
}
fn object_path(key: &str) -> anyhow::Result<ObjectPath> {
  ObjectPath::parse(key).context("managed upload object key is invalid")
}
fn multipart_chunk_bytes(total_bytes: u64) -> anyhow::Result<usize> {
  usize::try_from(
    total_bytes
      .div_ceil(MAX_MULTIPART_PARTS)
      .max(MIN_MULTIPART_CHUNK_BYTES),
  )
  .context("managed upload multipart chunk size exceeds this platform")
}
fn random_id() -> anyhow::Result<String> {
  let mut bytes = [0_u8; 32];
  crate::crypto::random_fill(&mut bytes)
    .map_err(|_| anyhow::anyhow!("managed upload identifier generation failed"))?;
  Ok(hex_digest(bytes))
}
fn to_i64(n: u64) -> anyhow::Result<i64> {
  i64::try_from(n).map_err(|_| anyhow::anyhow!("managed upload integer overflow"))
}
fn from_i64(n: i64) -> anyhow::Result<u64> {
  u64::try_from(n).map_err(|_| anyhow::anyhow!("managed upload durable integer is invalid"))
}
fn hex_digest(v: impl AsRef<[u8]>) -> String {
  v.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}
fn object_from_row(row: &PgRow) -> anyhow::Result<UploadObject> {
  Ok(UploadObject {
    key: row
      .try_get::<Option<String>, _>("object_key")?
      .ok_or_else(|| anyhow::anyhow!("managed upload object key is missing"))?,
    sha256: row
      .try_get::<Option<String>, _>("object_sha256")?
      .ok_or_else(|| anyhow::anyhow!("managed upload object digest is missing"))?,
    bytes: from_i64(
      row
        .try_get::<Option<i64>, _>("object_bytes")?
        .ok_or_else(|| anyhow::anyhow!("managed upload object bytes are missing"))?,
    )?,
    version: row.try_get("object_version")?,
  })
}
fn status_row(row: &PgRow) -> anyhow::Result<UploadStatus> {
  let state = match row.try_get::<String, _>("state")?.as_str() {
    "active" => UploadState::Active,
    "completing" => UploadState::Completing,
    "validating" => UploadState::Validating,
    "validation_failed" => UploadState::ValidationFailed,
    "ready" => UploadState::Ready,
    "dispatching" => UploadState::Dispatching,
    "complete" => UploadState::Complete,
    "indeterminate" => UploadState::Indeterminate,
    "deleted" => UploadState::Deleted,
    _ => bail!("managed upload has invalid durable state"),
  };
  let object = if row.try_get::<Option<String>, _>("object_key")?.is_some() {
    Some(object_from_row(row)?)
  } else {
    None
  };
  Ok(UploadStatus {
    id: row.try_get("id")?,
    profile: row.try_get("profile_name")?,
    offset: from_i64(row.try_get("offset_bytes")?)?,
    declared_total: row
      .try_get::<Option<i64>, _>("declared_total_bytes")?
      .map(from_i64)
      .transpose()?,
    state,
    expires_at_ms: from_i64(row.try_get("expires_at_ms")?)?,
    object,
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::atomic::{AtomicUsize, Ordering};

  #[derive(Debug)]
  struct AbortSpy {
    aborts: Arc<AtomicUsize>,
  }

  impl ManagedMultipartApi for AbortSpy {
    fn put_part<'a>(
      &'a self,
      _path: &'a ObjectPath,
      _id: &'a str,
      _part_index: usize,
      _data: PutPayload,
    ) -> futures_util::future::BoxFuture<'a, object_store::Result<PartId>> {
      Box::pin(async {
        Ok(PartId {
          content_id: "test".to_string(),
        })
      })
    }

    fn complete<'a>(
      &'a self,
      _path: &'a ObjectPath,
      _id: &'a str,
      _parts: Vec<PartId>,
    ) -> futures_util::future::BoxFuture<'a, object_store::Result<PutResult>> {
      Box::pin(std::future::pending())
    }

    fn abort<'a>(
      &'a self,
      _path: &'a ObjectPath,
      _id: &'a str,
    ) -> futures_util::future::BoxFuture<'a, object_store::Result<()>> {
      let aborts = Arc::clone(&self.aborts);
      Box::pin(async move {
        aborts.fetch_add(1, Ordering::SeqCst);
        Ok(())
      })
    }
  }

  fn integration_env(name: &str, required: bool) -> Option<String> {
    match std::env::var(name) {
      Ok(value) if !value.trim().is_empty() => Some(value),
      _ if required => panic!("required managed-upload integration variable {name} is missing"),
      _ => None,
    }
  }

  #[tokio::test]
  async fn postgres_s3_lifecycle_fences_discovery_and_enforces_session_quota() {
    let required = std::env::var("OXIBELT_REQUIRE_UPLOAD_POSTGRES_S3_TESTS").as_deref() == Ok("1");
    let Some(_) = integration_env("TEST_UPLOAD_POSTGRES_URL", required) else {
      return;
    };
    let Some(endpoint) = integration_env("TEST_UPLOAD_S3_ENDPOINT", required) else {
      return;
    };
    let Some(bucket) = integration_env("TEST_UPLOAD_S3_BUCKET", required) else {
      return;
    };
    let Some(region) = integration_env("TEST_UPLOAD_S3_REGION", required) else {
      return;
    };
    if integration_env("TEST_UPLOAD_S3_ACCESS_KEY", required).is_none()
      || integration_env("TEST_UPLOAD_S3_SECRET_KEY", required).is_none()
    {
      return;
    }
    let unique = random_id().unwrap();
    let config = UploadStoreConfig {
      name: format!("test-{unique}"),
      kind: UploadStoreKind::PostgresS3,
      local: None,
      postgres_s3: Some(PostgresS3UploadStoreConfig {
        postgres_url_env: "TEST_UPLOAD_POSTGRES_URL".to_string(),
        max_connections: 4,
        s3_bucket: bucket,
        s3_region: region,
        s3_endpoint: endpoint,
        s3_root_certificate: std::env::var("TEST_UPLOAD_S3_ROOT_CERTIFICATE")
          .ok()
          .filter(|value| !value.is_empty())
          .map(std::path::PathBuf::from),
        s3_prefix: format!("oxibelt-upload-tests/{unique}"),
        s3_access_key_env: "TEST_UPLOAD_S3_ACCESS_KEY".to_string(),
        s3_secret_key_env: "TEST_UPLOAD_S3_SECRET_KEY".to_string(),
        s3_session_token_env: std::env::var("TEST_UPLOAD_S3_SESSION_TOKEN")
          .ok()
          .filter(|value| !value.is_empty())
          .map(|_| "TEST_UPLOAD_S3_SESSION_TOKEN".to_string()),
        s3_virtual_hosted_style: false,
      }),
    };
    let store = PostgresS3UploadStore::open(&config).await.unwrap();
    let replica = PostgresS3UploadStore::open(&config).await.unwrap();
    let mut second_config = config.clone();
    second_config.name = format!("test-second-{unique}");
    second_config.postgres_s3.as_mut().unwrap().s3_prefix =
      format!("oxibelt-upload-tests/{unique}-second");
    if let Ok(second_bucket) = std::env::var("TEST_UPLOAD_S3_BUCKET_2")
      && !second_bucket.trim().is_empty()
    {
      second_config.postgres_s3.as_mut().unwrap().s3_bucket = second_bucket;
    }
    let second_store = PostgresS3UploadStore::open(&second_config).await.unwrap();
    let profile = UploadProfileConfig {
      name: format!("profile-{unique}"),
      store: config.name.clone(),
      public_base_url: url::Url::parse("https://uploads.example.test/").unwrap(),
      staging_dir: std::path::PathBuf::from("/tmp/oxibelt-upload-test"),
      max_staging_bytes: 1_024,
      control_path_prefix: "/uploads".to_string(),
      object_path_prefix: "/objects".to_string(),
      destination: UploadDestinationConfig::Object,
      identity: crate::config::UploadIdentityConfig {
        kind: crate::config::UploadIdentityKind::Ipm,
        source: "test".to_string(),
        subject_field: None,
      },
      max_upload_bytes: 1_024,
      max_part_bytes: 1_024,
      max_storage_bytes: 4_096,
      max_sessions: 1,
      max_parts: 4,
      inspection_bytes: 1_024,
      ttl_seconds: 300,
      object_ttl_seconds: 300,
      max_concurrent_uploads: 1,
      max_concurrent_parts: 1,
      compression_dictionary: None,
    };
    let owner = UploadOwner {
      kind: crate::config::UploadIdentityKind::Ipm,
      source: "test".to_string(),
      subject: format!("owner-{unique}"),
    };
    let binding = serde_json::json!({"route": unique});
    let create = || UploadCreate {
      profile: profile.clone(),
      owner: owner.clone(),
      binding: binding.clone(),
      method: http::Method::POST,
      uri: "https://origin.example.test/upload".parse().unwrap(),
      safe_headers: serde_json::json!({"content-type": "text/plain"}),
      declared_total: Some(5),
      dictionary: None,
    };
    let status = store.create(create()).await.unwrap();
    let mut second_request = create();
    second_request.profile.store = second_config.name.clone();
    let second_status = second_store.create(second_request).await.unwrap();
    let quota = store.create(create()).await.unwrap_err();
    assert!(matches!(
      quota.downcast_ref(),
      Some(&UploadRejection::Capacity)
    ));
    let pending_key = store.object_key("chunks", &status.id).unwrap();
    store
      .track_orphan_intent(&pending_key, &profile.name, profile.max_storage_bytes)
      .await
      .unwrap();
    let mut pending_usage_tx = store.pool.begin().await.unwrap();
    assert_eq!(
      profile_sessions(&mut pending_usage_tx, &profile.name)
        .await
        .unwrap(),
      2
    );
    assert_eq!(
      profile_usage(&mut pending_usage_tx, &profile.name)
        .await
        .unwrap(),
      profile.max_storage_bytes
    );
    pending_usage_tx.rollback().await.unwrap();
    let intent_capacity = store
      .begin_append(&status.id, &owner, &binding, 0, 5)
      .await
      .unwrap_err();
    assert!(matches!(
      intent_capacity.downcast_ref(),
      Some(&UploadRejection::Capacity)
    ));
    let (pending_path, pending_multipart_id) = store.begin_multipart(&pending_key).await.unwrap();
    MultipartStore::put_part(
      store.objects.as_ref(),
      &pending_path,
      &pending_multipart_id,
      0,
      Bytes::from_static(b"pending").into(),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE oxibelt_upload_orphan_objects SET created_at=clock_timestamp()-interval '1 hour' WHERE object_key=$1")
      .bind(&pending_key).execute(&store.pool).await.unwrap();
    store.refresh_orphan_intent(&pending_key).await.unwrap();
    store.collect_orphans(1).await.unwrap();
    let intent_retained: bool = sqlx::query_scalar(
      "SELECT EXISTS(SELECT 1 FROM oxibelt_upload_orphan_objects WHERE object_key=$1)",
    )
    .bind(&pending_key)
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert!(intent_retained);
    sqlx::query("UPDATE oxibelt_upload_orphan_objects SET created_at=clock_timestamp()-interval '1 hour' WHERE object_key=$1")
      .bind(&pending_key).execute(&store.pool).await.unwrap();
    store.collect_orphans(1).await.unwrap();
    let intent_cleaned: bool = sqlx::query_scalar(
      "SELECT EXISTS(SELECT 1 FROM oxibelt_upload_orphan_objects WHERE object_key=$1)",
    )
    .bind(&pending_key)
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert!(!intent_cleaned);

    let crashed = store
      .begin_append(&status.id, &owner, &binding, 0, 5)
      .await
      .unwrap();
    sqlx::query("UPDATE oxibelt_uploads SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1 AND reservation_token=$2")
      .bind(&status.id).bind(crashed.backend_token()).execute(&store.pool).await.unwrap();
    let recovered = replica
      .begin_append(&status.id, &owner, &binding, 0, 5)
      .await
      .unwrap();
    replica.abort_append(&recovered).await.unwrap();
    let fenced = replica
      .begin_append(&status.id, &owner, &binding, 0, 5)
      .await
      .unwrap();
    assert_eq!(
      store
        .lookup(&status.id, &owner, &binding)
        .await
        .unwrap()
        .offset,
      0
    );
    let fence_error = store.renew_append(&fenced).await.unwrap_err();
    assert!(matches!(
      fence_error.downcast_ref(),
      Some(&UploadRejection::Conflict)
    ));

    let expired_append = replica
      .begin_append(&status.id, &owner, &binding, 0, 5)
      .await
      .unwrap();
    sqlx::query("UPDATE oxibelt_uploads SET expires_at_ms=db_now_ms()-1 WHERE id=$1")
      .bind(&status.id)
      .execute(&store.pool)
      .await
      .unwrap();
    let renew_expired = replica.renew_append(&expired_append).await.unwrap_err();
    assert!(matches!(
      renew_expired.downcast_ref(),
      Some(&UploadRejection::Conflict)
    ));
    let commit_expired = replica
      .commit_fully_inspected_part(
        &expired_append,
        &InspectedPart {
          bytes: 5,
          sha256: hex_digest(Sha256::digest(b"hello")),
        },
        Box::pin(futures_util::stream::once(async {
          Ok(Bytes::from_static(b"hello"))
        })),
      )
      .await
      .unwrap_err();
    assert!(matches!(
      commit_expired.downcast_ref(),
      Some(&UploadRejection::Conflict)
    ));
    replica.abort_append(&expired_append).await.unwrap();
    sqlx::query("UPDATE oxibelt_uploads SET expires_at_ms=db_now_ms()+300000 WHERE id=$1")
      .bind(&status.id)
      .execute(&store.pool)
      .await
      .unwrap();

    let reservation = replica
      .begin_append(&status.id, &owner, &binding, 0, 5)
      .await
      .unwrap();
    let digest = hex_digest(Sha256::digest(b"hello"));
    let appended = replica
      .commit_fully_inspected_part(
        &reservation,
        &InspectedPart {
          bytes: 5,
          sha256: digest,
        },
        Box::pin(futures_util::stream::once(async {
          Ok(Bytes::from_static(b"hello"))
        })),
      )
      .await
      .unwrap();
    assert_eq!(appended.offset, 5);
    store
      .claim_complete(&status.id, &owner, &binding, 5)
      .await
      .unwrap();
    sqlx::query("UPDATE oxibelt_uploads SET expires_at_ms=db_now_ms()-1 WHERE id=$1")
      .bind(&status.id)
      .execute(&store.pool)
      .await
      .unwrap();
    let claim_expired = store
      .claim_publish(&status.id, &owner, &binding, "expired-claim")
      .await
      .unwrap_err();
    assert!(matches!(
      claim_expired.downcast_ref(),
      Some(&UploadRejection::Conflict)
    ));
    sqlx::query("UPDATE oxibelt_uploads SET expires_at_ms=db_now_ms()+300000 WHERE id=$1")
      .bind(&status.id)
      .execute(&store.pool)
      .await
      .unwrap();
    let (_, publish_epoch, _, _) = store
      .claim_publish(&status.id, &owner, &binding, "expiring-publish")
      .await
      .unwrap();
    sqlx::query("UPDATE oxibelt_uploads SET expires_at_ms=db_now_ms()-1 WHERE id=$1")
      .bind(&status.id)
      .execute(&store.pool)
      .await
      .unwrap();
    let renew_publish_expired = store
      .renew_publish(&status.id, publish_epoch, "expiring-publish")
      .await
      .unwrap_err();
    assert!(matches!(
      renew_publish_expired.downcast_ref(),
      Some(&UploadRejection::Conflict)
    ));
    let finalize_expired = store
      .finalize_publish(
        &status.id,
        publish_epoch,
        "expiring-publish",
        "complete",
        "not-published",
        &hex_digest(Sha256::digest(b"hello")),
        5,
        None,
        300,
      )
      .await
      .unwrap_err();
    assert!(matches!(
      finalize_expired.downcast_ref(),
      Some(&UploadRejection::Conflict)
    ));
    sqlx::query("UPDATE oxibelt_uploads SET expires_at_ms=db_now_ms()+300000,lease_holder=NULL,lease_until=NULL,reservation_bytes=NULL,fence_epoch=fence_epoch+1 WHERE id=$1")
      .bind(&status.id)
      .execute(&store.pool)
      .await
      .unwrap();
    let published = store
      .publish_object(&status.id, &owner, &binding)
      .await
      .unwrap();
    assert_eq!(published.state, UploadState::Complete);
    let cleanup_intents: i64 =
      sqlx::query_scalar("SELECT count(*) FROM oxibelt_upload_orphan_objects")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(cleanup_intents, 0);
    let bytes = store
      .read_object(&status.id, &owner, &binding)
      .await
      .unwrap()
      .try_collect::<Vec<_>>()
      .await
      .unwrap()
      .concat();
    assert_eq!(bytes, b"hello");
    let completed_quota = store.create(create()).await.unwrap_err();
    assert!(matches!(
      completed_quota.downcast_ref(),
      Some(&UploadRejection::Capacity)
    ));
    sqlx::query("UPDATE oxibelt_uploads SET expires_at_ms=db_now_ms()-1 WHERE id=$1")
      .bind(&status.id)
      .execute(&store.pool)
      .await
      .unwrap();
    let expired_complete_quota = store.create(create()).await.unwrap_err();
    assert!(matches!(
      expired_complete_quota.downcast_ref(),
      Some(&UploadRejection::Capacity)
    ));
    sqlx::query("UPDATE oxibelt_uploads SET state='deleted' WHERE id=$1")
      .bind(&status.id)
      .execute(&store.pool)
      .await
      .unwrap();
    let mut usage_tx = store.pool.begin().await.unwrap();
    assert_eq!(
      profile_usage(&mut usage_tx, &profile.name).await.unwrap(),
      10
    );
    usage_tx.rollback().await.unwrap();
    let tombstone_quota = store.create(create()).await.unwrap_err();
    assert!(matches!(
      tombstone_quota.downcast_ref(),
      Some(&UploadRejection::Capacity)
    ));
    store.cleanup_deleted(&status.id).await.unwrap();
    let replacement = store.create(create()).await.unwrap();
    store
      .delete(&replacement.id, &owner, &binding)
      .await
      .unwrap();
    // An interrupted initial claim, or an expired decoded publisher, must
    // never leave a reusable validation fence or release physical output debt.
    for publication_claimed in [false, true] {
      let mut request = create();
      request.declared_total = Some(0);
      request.dictionary = Some(crate::uploads::UploadDictionaryPin {
        coding: crate::uploads::UploadDictionaryCoding::Dcz,
        profile: "decode".into(),
        dictionary: "public".into(),
        hash: crate::compression_dictionary::fields::DictionaryHash::from_slice(&[7; 32]).unwrap(),
      });
      let pinned = store.create(request).await.unwrap();
      store
        .claim_complete(&pinned.id, &owner, &binding, 0)
        .await
        .unwrap();
      assert_eq!(
        store
          .lookup(&pinned.id, &owner, &binding)
          .await
          .unwrap()
          .state,
        UploadState::Validating
      );
      let key = store.object_key("objects", &pinned.id).unwrap();
      if publication_claimed {
        store
          .claim_decoded_publish(&pinned.id, &owner, &binding, 5, ("test-publisher", &key))
          .await
          .unwrap();
      }
      sqlx::query(
        "UPDATE oxibelt_uploads SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1",
      )
      .bind(&pinned.id)
      .execute(&store.pool)
      .await
      .unwrap();
      assert_eq!(
        store
          .lookup(&pinned.id, &owner, &binding)
          .await
          .unwrap()
          .state,
        UploadState::ValidationFailed
      );
      assert!(
        store
          .claim_decoded_publish(&pinned.id, &owner, &binding, 5, ("stale-publisher", &key))
          .await
          .is_err()
      );
      let mut tx = store.pool.begin().await.unwrap();
      assert_eq!(
        profile_usage(&mut tx, &profile.name).await.unwrap(),
        if publication_claimed { 5 } else { 0 }
      );
      tx.rollback().await.unwrap();
      // No S3 write was started by this fixture, so this test-owned intent
      // can be removed directly after proving its retained quota charge.
      if publication_claimed {
        store.untrack_orphan(&key).await.unwrap();
      }
      store.delete(&pinned.id, &owner, &binding).await.unwrap();
    }
    second_store
      .delete(&second_status.id, &owner, &binding)
      .await
      .unwrap();
    let missing = store
      .lookup(&status.id, &owner, &binding)
      .await
      .unwrap_err();
    assert!(matches!(
      missing.downcast_ref(),
      Some(&UploadRejection::NotFound)
    ));
    sqlx::query(
      "UPDATE oxibelt_upload_schema_migrations SET version=5 WHERE component='managed_uploads'",
    )
    .execute(&store.pool)
    .await
    .unwrap();
    let future_schema = migrate(&store.pool).await.unwrap_err();
    assert!(future_schema.to_string().contains("newer than this binary"));
    sqlx::query(
      "UPDATE oxibelt_upload_schema_migrations SET version=4 WHERE component='managed_uploads'",
    )
    .execute(&store.pool)
    .await
    .unwrap();
    let first_schema = store_schema(&config, config.postgres_s3.as_ref().unwrap());
    let second_schema = store_schema(&second_config, second_config.postgres_s3.as_ref().unwrap());
    sqlx::query(AssertSqlSafe(format!("DROP SCHEMA {first_schema} CASCADE")))
      .execute(&store.pool)
      .await
      .unwrap();
    sqlx::query(AssertSqlSafe(format!(
      "DROP SCHEMA {second_schema} CASCADE"
    )))
    .execute(&second_store.pool)
    .await
    .unwrap();
  }

  #[test]
  fn migrations_cover_fencing_and_gc() {
    let sql = UPLOAD_POSTGRES_MIGRATION_V1
      .iter()
      .chain(UPLOAD_POSTGRES_MIGRATION_V2)
      .chain(UPLOAD_POSTGRES_MIGRATION_V3)
      .chain(UPLOAD_POSTGRES_MIGRATION_V4)
      .copied()
      .collect::<Vec<_>>()
      .join("\n");
    assert!(sql.contains("lease_until"));
    assert!(sql.contains("fence_epoch"));
    assert!(sql.contains("object_expires_at_ms"));
    assert!(sql.contains("intent_state"));
    assert!(sql.contains("dictionary_pin_json"));
  }

  #[test]
  fn multipart_chunk_size_respects_s3_part_limit() {
    let max_upload = 1024_u64 * 1024 * 1024 * 1024;
    let chunk = u64::try_from(multipart_chunk_bytes(max_upload).unwrap()).unwrap();
    assert!(chunk >= MIN_MULTIPART_CHUNK_BYTES);
    assert!(max_upload.div_ceil(chunk) <= MAX_MULTIPART_PARTS);
  }

  #[tokio::test]
  async fn cancelling_multipart_completion_schedules_abort() {
    let aborts = Arc::new(AtomicUsize::new(0));
    let writer = ManagedMultipartWriter::new_without_intent(
      Arc::new(AbortSpy {
        aborts: Arc::clone(&aborts),
      }),
      0,
    )
    .unwrap();
    let completion = tokio::spawn(writer.finish());
    tokio::task::yield_now().await;
    completion.abort();
    let _ = completion.await;
    tokio::time::timeout(Duration::from_secs(1), async {
      while aborts.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
      }
    })
    .await
    .unwrap();
    assert_eq!(aborts.load(Ordering::SeqCst), 1);
  }
  #[test]
  fn store_schema_isolates_noncredential_store_identity() {
    let base = UploadStoreConfig {
      name: "store-a".to_string(),
      kind: UploadStoreKind::PostgresS3,
      local: None,
      postgres_s3: Some(PostgresS3UploadStoreConfig {
        postgres_url_env: "DATABASE_URL_A".to_string(),
        max_connections: 1,
        s3_bucket: "bucket-a".to_string(),
        s3_region: "region-1".to_string(),
        s3_endpoint: "https://s3.example.test".to_string(),
        s3_root_certificate: None,
        s3_prefix: "uploads".to_string(),
        s3_access_key_env: "ACCESS_A".to_string(),
        s3_secret_key_env: "SECRET_A".to_string(),
        s3_session_token_env: None,
        s3_virtual_hosted_style: false,
      }),
    };
    let mut other = base.clone();
    other.postgres_s3.as_mut().unwrap().s3_prefix = "other".to_string();
    assert_ne!(
      store_schema(&base, base.postgres_s3.as_ref().unwrap()),
      store_schema(&other, other.postgres_s3.as_ref().unwrap())
    );
    let mut rotated = base.clone();
    rotated.postgres_s3.as_mut().unwrap().s3_access_key_env = "ACCESS_B".to_string();
    assert_eq!(
      store_schema(&base, base.postgres_s3.as_ref().unwrap()),
      store_schema(&rotated, rotated.postgres_s3.as_ref().unwrap())
    );
  }
  #[test]
  fn layouts_reject_gaps() {
    let p = StoredPart {
      key: "x".into(),
      offset: 1,
      bytes: 1,
      sha256: "a".repeat(64),
      version: None,
    };
    assert!(validate_layout(&[p]).is_err());
  }
  #[test]
  fn paths_reject_escape() {
    assert!(object_path("safe/x").is_ok());
    assert!(object_path("../x").is_err());
  }
}

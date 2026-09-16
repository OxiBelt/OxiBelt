use super::*;

impl PostgresBackend {
  pub(super) async fn query_cache_publish(
    &self,
    expiry_key: &str,
    target_key: &str,
    member: &QueryCacheIndexMember,
    entry_value: &[u8],
  ) -> anyhow::Result<()> {
    validate_target_namespace(expiry_key, target_key)?;
    let namespace_key = query_cache_namespace(expiry_key)?;
    validate_member_keys(target_key, member)?;
    let epoch =
      i64::try_from(member.epoch).context("QUERY cache epoch exceeds PostgreSQL bigint")?;
    let chunk_count = i64::try_from(member.chunk_count)
      .context("QUERY cache chunk count exceeds PostgreSQL bigint")?;
    let encoded = serde_json::to_vec(member)?;
    let mut tx = self.pool.begin().await?;
    // Cleanup locks the target row before touching the generic value rows.
    // Publishing uses the same order to avoid a target/value lock inversion.
    sqlx::query(
      "INSERT INTO oxibelt_shared_cache_query_targets
         (namespace_key, target_key, entry_epoch, storage_variant, member, chunk_count, expires_at_ms)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (namespace_key, target_key, storage_variant) DO UPDATE SET
         entry_epoch = EXCLUDED.entry_epoch,
         member = EXCLUDED.member,
         chunk_count = EXCLUDED.chunk_count,
         expires_at_ms = EXCLUDED.expires_at_ms",
    )
    .bind(namespace_key)
    .bind(target_key)
    .bind(epoch)
    .bind(&member.storage_variant)
    .bind(&encoded)
    .bind(chunk_count)
    .bind(member.expires_at_ms)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
      "INSERT INTO oxibelt_shared_state (key, value, expires_at_ms) VALUES ($1, $2, $3)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at_ms = EXCLUDED.expires_at_ms",
    )
    .bind(&member.entry_key)
    .bind(entry_value)
    .bind(member.expires_at_ms)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
      "INSERT INTO oxibelt_shared_state (key, value, expires_at_ms) VALUES ($1, $2, $3)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at_ms = EXCLUDED.expires_at_ms",
    )
    .bind(&member.lookup_index_key)
    .bind(member.storage_variant.as_bytes())
    .bind(member.expires_at_ms)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
  }

  pub(super) async fn query_cache_cleanup_before(
    &self,
    expiry_key: &str,
    target_key: &str,
    before_epoch: u64,
    limit: usize,
  ) -> anyhow::Result<QueryCacheCleanupBatch> {
    validate_target_namespace(expiry_key, target_key)?;
    let namespace_key = query_cache_namespace(expiry_key)?;
    let before = i64::try_from(before_epoch).unwrap_or(i64::MAX);
    self
      .query_cache_cleanup_rows(
        "SELECT target_key, storage_variant, member FROM oxibelt_shared_cache_query_targets
         WHERE namespace_key = $1 AND target_key = $2 AND entry_epoch < $3
         ORDER BY entry_epoch, storage_variant LIMIT $4 FOR UPDATE SKIP LOCKED",
        namespace_key,
        Some(target_key),
        before,
        limit,
      )
      .await
  }

  pub(super) async fn query_cache_cleanup_expired(
    &self,
    expiry_key: &str,
    limit: usize,
  ) -> anyhow::Result<QueryCacheCleanupBatch> {
    let namespace_key = query_cache_namespace(expiry_key)?;
    self
      .query_cache_cleanup_rows(
        "SELECT target_key, storage_variant, member FROM oxibelt_shared_cache_query_targets
         WHERE namespace_key = $1 AND $2::text IS NOT NULL AND expires_at_ms <= $3
         ORDER BY expires_at_ms, target_key, storage_variant LIMIT $4 FOR UPDATE SKIP LOCKED",
        namespace_key,
        None,
        now_unix_ms(),
        limit,
      )
      .await
  }

  async fn query_cache_cleanup_rows(
    &self,
    statement: &'static str,
    namespace_key: &str,
    target_key: Option<&str>,
    boundary: i64,
    limit: usize,
  ) -> anyhow::Result<QueryCacheCleanupBatch> {
    let fetch_limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut tx = self.pool.begin().await?;
    let rows: Vec<(String, String, Vec<u8>)> = sqlx::query_as(statement)
      .bind(namespace_key)
      .bind(target_key.unwrap_or_default())
      .bind(boundary)
      .bind(fetch_limit)
      .fetch_all(&mut *tx)
      .await?;
    let mut removed = 0usize;
    for (row_target_key, storage_variant, encoded) in &rows {
      let Ok(member) = serde_json::from_slice::<QueryCacheIndexMember>(encoded) else {
        sqlx::query(
          "DELETE FROM oxibelt_shared_cache_query_targets
           WHERE namespace_key = $1 AND target_key = $2 AND storage_variant = $3 AND member = $4",
        )
        .bind(namespace_key)
        .bind(row_target_key)
        .bind(storage_variant)
        .bind(encoded)
        .execute(&mut *tx)
        .await?;
        continue;
      };
      if member.version != QUERY_CACHE_INDEX_VERSION
        || member.storage_variant != *storage_variant
        || target_key.is_some_and(|expected| expected != row_target_key)
        || validate_target_logical_namespace(namespace_key, row_target_key).is_err()
        || validate_member_keys(row_target_key, &member).is_err()
      {
        sqlx::query(
          "DELETE FROM oxibelt_shared_cache_query_targets
           WHERE namespace_key = $1 AND target_key = $2 AND storage_variant = $3 AND member = $4",
        )
        .bind(namespace_key)
        .bind(row_target_key)
        .bind(storage_variant)
        .bind(encoded)
        .execute(&mut *tx)
        .await?;
        continue;
      }
      sqlx::query("DELETE FROM oxibelt_shared_state WHERE key = $1")
        .bind(&member.entry_key)
        .execute(&mut *tx)
        .await?;
      for index in 0..member.chunk_count {
        sqlx::query("DELETE FROM oxibelt_shared_state WHERE key = $1")
          .bind(format!("{}{index}", member.chunk_key_prefix))
          .execute(&mut *tx)
          .await?;
      }
      sqlx::query("DELETE FROM oxibelt_shared_state WHERE key = $1 AND value = $2")
        .bind(&member.lookup_index_key)
        .bind(member.storage_variant.as_bytes())
        .execute(&mut *tx)
        .await?;
      sqlx::query(
        "DELETE FROM oxibelt_shared_cache_query_targets
         WHERE namespace_key = $1 AND target_key = $2 AND storage_variant = $3 AND member = $4",
      )
      .bind(namespace_key)
      .bind(row_target_key)
      .bind(storage_variant)
      .bind(encoded)
      .execute(&mut *tx)
      .await?;
      removed = removed.saturating_add(1);
    }
    let remaining: bool = if let Some(target_key) = target_key {
      sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM oxibelt_shared_cache_query_targets
         WHERE namespace_key = $1 AND target_key = $2 AND entry_epoch < $3)",
      )
      .bind(namespace_key)
      .bind(target_key)
      .bind(boundary)
      .fetch_one(&mut *tx)
      .await?
    } else {
      sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM oxibelt_shared_cache_query_targets
         WHERE namespace_key = $1 AND expires_at_ms <= $2)",
      )
      .bind(namespace_key)
      .bind(boundary)
      .fetch_one(&mut *tx)
      .await?
    };
    tx.commit().await?;
    Ok(QueryCacheCleanupBatch { removed, remaining })
  }
}

use super::*;

impl SharedState {
  pub(in crate::shared_state) fn start_query_cache_expiry_worker(self: &Arc<Self>) {
    if self.cache.is_none() {
      return;
    }
    let weak = Arc::downgrade(self);
    tokio::spawn(async move {
      loop {
        tokio::time::sleep(QUERY_CACHE_EXPIRY_INTERVAL).await;
        let Some(shared) = weak.upgrade() else {
          return;
        };
        shared.schedule_query_cache_expiry_cleanup(true);
      }
    });
  }

  pub(super) fn schedule_query_cache_expiry_cleanup(&self, force: bool) {
    if !force {
      let writes = self
        .query_cache_expiry_scheduler
        .writes_since_cleanup
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
      if writes < QUERY_CACHE_EXPIRY_TRIGGER_WRITES {
        return;
      }
    }
    if self
      .query_cache_expiry_scheduler
      .running
      .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
      .is_err()
    {
      return;
    }
    let Some(backend) = self.cache.clone() else {
      self
        .query_cache_expiry_scheduler
        .running
        .store(false, Ordering::Release);
      return;
    };
    let expiry_key = self.query_cache_expiry_key();
    let timeout = self.operation_timeout;
    let scheduler = self.query_cache_expiry_scheduler.clone();
    let failure_registry = self.failure_registry.clone();
    scheduler.writes_since_cleanup.swap(0, Ordering::AcqRel);
    tokio::spawn(async move {
      let cleanup = async {
        for _ in 0..QUERY_CACHE_EXPIRY_MAX_PAGES {
          let batch = backend
            .query_cache_cleanup_expired(&expiry_key, QUERY_CACHE_EXPIRY_BATCH)
            .await?;
          if !batch.remaining {
            break;
          }
          tokio::task::yield_now().await;
        }
        Ok::<(), anyhow::Error>(())
      };
      let result = match tokio::time::timeout(timeout, cleanup).await {
        Ok(result) => result,
        Err(_) => Err(anyhow!("shared QUERY cache expiry cleanup timed out")),
      };
      if result.is_ok() {
        failure_registry.record_success(SharedStateFeature::Cache);
      } else {
        failure_registry.record_failure(SharedStateFeature::Cache);
      }
      scheduler.running.store(false, Ordering::Release);
    });
  }

  pub(in crate::shared_state) fn query_cache_target_key(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    uri: &str,
  ) -> String {
    let digest = crate::crypto::sha256(format!("{policy}\n{scheme}\n{host}\n{uri}").as_bytes());
    self.key(&format!("cache:q1-target-v1:{}", hex_encode(&digest)))
  }

  fn query_cache_expiry_key(&self) -> String {
    self.key("cache:q1-expiry-v1")
  }

  pub(in crate::shared_state) fn query_cache_index_member(
    &self,
    entry: &SharedCacheEntry,
  ) -> Option<QueryCacheIndexMember> {
    let epoch = entry.query_target_epoch?;
    if !crate::cache::is_query_v1_base_key(&entry.base_key) {
      return None;
    }
    let storage_variant = self.shared_cache_storage_variant_key(entry);
    let chunk_key_prefix = if entry.body_chunks.is_empty() {
      String::new()
    } else {
      self.key(&format!(
        "cache:chunk:{}:",
        shared_cache_chunk_stem(&storage_variant)
      ))
    };
    Some(QueryCacheIndexMember {
      version: QUERY_CACHE_INDEX_VERSION,
      epoch,
      entry_key: self.shared_cache_entry_key_from_storage(&storage_variant),
      lookup_index_key: self.shared_cache_index_key(entry),
      chunk_key_prefix,
      chunk_count: entry.body_chunks.len(),
      expires_at_ms: shared_cache_retention_until_ms(entry),
      storage_variant,
    })
  }

  pub(in crate::shared_state) async fn cache_publish_query_indexed(
    &self,
    backend: &Backend,
    entry: &SharedCacheEntry,
    value: &[u8],
    ttl: Option<Duration>,
  ) -> anyhow::Result<bool> {
    let Some(member) = self.query_cache_index_member(entry) else {
      return Ok(false);
    };
    if ttl.is_none() {
      bail!("refusing to publish an already-expired indexed QUERY cache entry");
    }
    let target_key =
      self.query_cache_target_key(&entry.policy, &entry.scheme, &entry.host, &entry.uri);
    backend
      .query_cache_publish(
        &target_key,
        &self.query_cache_expiry_key(),
        &member,
        value,
        ttl,
      )
      .await?;
    self.schedule_query_cache_expiry_cleanup(false);
    Ok(true)
  }

  /// Deletes at most `limit` indexed QUERY variants older than `before_epoch`.
  /// This path never falls back to generic backend enumeration.
  pub async fn cache_cleanup_query_target_before(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    uri: &str,
    before_epoch: u64,
    limit: usize,
  ) -> anyhow::Result<QueryCacheCleanupBatch> {
    let Some(backend) = &self.cache else {
      return Ok(QueryCacheCleanupBatch::default());
    };
    let target_key = self.query_cache_target_key(policy, scheme, host, uri);
    let result = match tokio::time::timeout(
      self.operation_timeout,
      backend.query_cache_cleanup_before(
        &target_key,
        &self.query_cache_expiry_key(),
        before_epoch,
        limit.max(1),
      ),
    )
    .await
    {
      Ok(result) => result,
      Err(_) => Err(anyhow!("shared QUERY cache cleanup timed out")),
    };
    self.observe_backend_result(SharedStateFeature::Cache, &result);
    result
  }

  /// Reclaims a bounded page of physically expired indexed QUERY objects.
  /// Redis prunes its dedicated expiry ZSET while component keys expire by
  /// TTL; PostgreSQL deletes component rows through its dedicated B-tree.
  pub async fn cache_cleanup_expired_query_entries(
    &self,
    limit: usize,
  ) -> anyhow::Result<QueryCacheCleanupBatch> {
    let Some(backend) = &self.cache else {
      return Ok(QueryCacheCleanupBatch::default());
    };
    let result = match tokio::time::timeout(
      self.operation_timeout,
      backend.query_cache_cleanup_expired(&self.query_cache_expiry_key(), limit.max(1)),
    )
    .await
    {
      Ok(result) => result,
      Err(_) => Err(anyhow!("shared QUERY cache expiry cleanup timed out")),
    };
    self.observe_backend_result(SharedStateFeature::Cache, &result);
    result
  }
}

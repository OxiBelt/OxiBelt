use super::*;

impl Backend {
  pub(super) async fn query_cache_publish(
    &self,
    target_key: &str,
    expiry_key: &str,
    member: &QueryCacheIndexMember,
    entry_value: &[u8],
    ttl: Option<Duration>,
  ) -> anyhow::Result<()> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("cache_query_publish", || {
            redis.query_cache_publish(target_key, expiry_key, member, entry_value, ttl)
          })
          .await
      }
      Self::Postgres(postgres) => {
        postgres
          .runtime
          .execute("cache_query_publish", || {
            postgres.query_cache_publish(expiry_key, target_key, member, entry_value)
          })
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => {
        if memory.take_forced_failure() {
          bail!("injected shared-state memory backend failure");
        }
        memory.query_cache_publish(target_key, member, entry_value)
      }
    }
  }

  pub(super) async fn query_cache_cleanup_before(
    &self,
    target_key: &str,
    expiry_key: &str,
    before_epoch: u64,
    limit: usize,
  ) -> anyhow::Result<QueryCacheCleanupBatch> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("cache_query_cleanup", || {
            redis.query_cache_cleanup_before(target_key, expiry_key, before_epoch, limit)
          })
          .await
      }
      Self::Postgres(postgres) => {
        postgres
          .runtime
          .execute("cache_query_cleanup", || {
            postgres.query_cache_cleanup_before(expiry_key, target_key, before_epoch, limit)
          })
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => {
        if memory.take_forced_failure() {
          bail!("injected shared-state memory backend failure");
        }
        memory.query_cache_cleanup_before(target_key, before_epoch, limit)
      }
    }
  }

  pub(super) async fn query_cache_cleanup_expired(
    &self,
    expiry_key: &str,
    limit: usize,
  ) -> anyhow::Result<QueryCacheCleanupBatch> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("cache_query_expiry_cleanup", || {
            redis.query_cache_cleanup_expired(expiry_key, limit)
          })
          .await
      }
      Self::Postgres(postgres) => {
        postgres
          .runtime
          .execute("cache_query_expiry_cleanup", || {
            postgres.query_cache_cleanup_expired(expiry_key, limit)
          })
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => {
        if memory.take_forced_failure() {
          bail!("injected shared-state memory backend failure");
        }
        memory.query_cache_cleanup_expired(limit)
      }
    }
  }
}

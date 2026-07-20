//! Backend construction and narrow operation dispatch.

use super::*;

pub(super) fn connection_lease_fingerprint(
  keys: &[String],
  limits: &[usize],
  ttl: Duration,
) -> String {
  let mut entries = keys
    .iter()
    .zip(limits)
    .map(|(key, limit)| (key.as_str(), *limit))
    .collect::<Vec<_>>();
  entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
  let mut material = format!("connection-lease:{}\n", atomic_updates::ttl_millis(ttl));
  for (key, limit) in entries {
    material.push_str(key);
    material.push(':');
    material.push_str(&limit.to_string());
    material.push('\n');
  }
  hex_encode(&crate::crypto::sha256(material.as_bytes()))
}

pub(super) fn counter_lease_fingerprint(key: &str, ttl: Duration) -> String {
  let material = format!("counter-lease:{}:{key}", atomic_updates::ttl_millis(ttl));
  hex_encode(&crate::crypto::sha256(material.as_bytes()))
}

/// Runs a one-shot Redis health probe through the same URL validation,
/// authentication, TLS, and server-verification path used by the runtime.
pub(crate) async fn probe_redis_backend(
  config: &Config,
  backend: &SharedStateBackendConfig,
) -> anyhow::Result<()> {
  let pool = RedisPool::new(
    backend,
    Duration::from_millis(config.shared_state.operation_timeout_ms),
    &config.crypto,
    config.shared_state.redis_plaintext_policy,
    Metrics::new(),
  )?;
  match pool.command(&[b"PING".to_vec()]).await? {
    Resp::Simple(value) if value == "PONG" => Ok(()),
    _ => bail!("unexpected Redis PING response"),
  }
}

impl Backend {
  pub(super) async fn connect(
    config: &SharedStateBackendConfig,
    timeout_ms: u64,
    crypto: &CryptoConfig,
    plaintext_policy: RedisPlaintextPolicy,
    metrics: Arc<Metrics>,
    previous: Option<&Arc<Backend>>,
  ) -> anyhow::Result<Self> {
    let operation_timeout = Duration::from_millis(timeout_ms);
    match config.kind {
      SharedStateBackendKind::Redis => {
        let runtime = BackendRuntime::new(config, "redis", operation_timeout, metrics.clone());
        let reused = if let Some(Self::Redis(previous)) = previous.map(Arc::as_ref) {
          previous
            .pool
            .matches_config(config, operation_timeout, crypto, plaintext_policy)?
            .then(|| previous.pool.clone())
        } else {
          None
        };
        let pool = if let Some(pool) = reused {
          pool
        } else {
          RedisPool::new(config, operation_timeout, crypto, plaintext_policy, metrics)?
        };
        // A positive minimum-idle setting is an activation requirement even
        // when an unchanged pool is retained over reload.
        pool.prewarm().await?;
        Ok(Self::Redis(RedisBackend { pool, runtime }))
      }
      SharedStateBackendKind::Postgres => {
        let connection_url =
          config.connection_url_with_prefix(&format!("shared_state.backends.{}", config.name))?;
        let runtime = BackendRuntime::new(config, "postgres", operation_timeout, metrics);
        let pool = runtime
          .connect(|| connect_postgres_pool(config, &connection_url, runtime.connect_timeout))
          .await
          .with_context(|| {
            format!(
              "failed to connect shared_state PostgreSQL backend {}",
              config.name
            )
          })?;
        runtime.execute("startup", || init_postgres(&pool)).await?;
        Ok(Self::Postgres(PostgresBackend { pool, runtime }))
      }
    }
  }

  pub(super) fn runtime(&self) -> Option<&BackendRuntime> {
    match self {
      Self::Redis(redis) => Some(&redis.runtime),
      Self::Postgres(postgres) => Some(&postgres.runtime),
      #[cfg(test)]
      Self::Memory(_) => None,
    }
  }

  pub(super) fn failure_identity(&self) -> (Arc<str>, &'static str) {
    match self {
      Self::Redis(redis) => (redis.runtime.name.clone(), redis.runtime.kind),
      Self::Postgres(postgres) => (postgres.runtime.name.clone(), postgres.runtime.kind),
      #[cfg(test)]
      Self::Memory(_) => (Arc::from("memory"), "memory"),
    }
  }

  pub(super) fn operation_timeout(&self) -> Option<Duration> {
    self.runtime().map(|runtime| runtime.operation_timeout)
  }

  pub(super) fn record_cleanup_drop(&self) {
    if let Some(runtime) = self.runtime() {
      runtime
        .metrics
        .record_shared_state_deferred_cleanup_dropped(runtime.name.as_ref(), runtime.kind);
    }
  }

  pub(super) async fn rate_take(
    &self,
    limit_name: &str,
    key: &str,
    rate_per_second: f64,
    burst: u32,
    max_buckets: usize,
    bucket_ttl: Duration,
  ) -> anyhow::Result<SharedRateLimitOutcome> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("rate_limit", || {
            redis.rate_take(
              limit_name,
              key,
              rate_per_second,
              burst,
              max_buckets,
              bucket_ttl,
            )
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("rate_limit", || {
            pg.rate_take(
              limit_name,
              key,
              rate_per_second,
              burst,
              max_buckets,
              bucket_ttl,
            )
          })
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => {
        if memory.take_forced_failure() {
          bail!("injected shared-state memory backend failure");
        }
        memory.rate_take(
          limit_name,
          key,
          rate_per_second,
          burst,
          max_buckets,
          bucket_ttl,
        )
      }
    }
  }

  pub(super) async fn rate_take_bucket(
    &self,
    key: &str,
    rate_per_second: f64,
    burst: u32,
    bucket_ttl: Duration,
  ) -> anyhow::Result<SharedRateLimitOutcome> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("rate_limit", || {
            redis.rate_take_bucket(key, rate_per_second, burst, bucket_ttl)
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("rate_limit", || {
            pg.rate_take_bucket(key, rate_per_second, burst, bucket_ttl)
          })
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => {
        if memory.take_forced_failure() {
          bail!("injected shared-state memory backend failure");
        }
        memory.rate_take_bucket(key, rate_per_second, burst, bucket_ttl)
      }
    }
  }

  pub(super) async fn connection_acquire(
    &self,
    keys: &[String],
    limits: &[usize],
    ttl: Duration,
    lease: &SharedCounterLease,
  ) -> anyhow::Result<Option<usize>> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("connection_acquire", || {
            redis.connection_acquire_atomic(keys, limits, ttl, lease)
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("connection_acquire", || {
            pg.connection_acquire_atomic(keys, limits, ttl, lease)
          })
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => {
        if memory.take_forced_failure() {
          bail!("injected shared-state memory backend failure");
        }
        memory.connection_acquire_atomic(keys, limits, ttl, lease)
      }
    }
  }

  pub(super) async fn connection_release(&self, lease: &SharedCounterLease) -> anyhow::Result<()> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("connection_release", || {
            redis.connection_release_atomic(lease)
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("connection_release", || pg.connection_release_atomic(lease))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.connection_release_atomic(lease),
    }
  }

  pub(super) async fn counter_lease_acquire(
    &self,
    key: &str,
    ttl: Duration,
    lease: &SharedCounterLease,
  ) -> anyhow::Result<()> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("counter_update", || {
            redis.counter_lease_acquire_atomic(key, ttl, lease)
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("counter_update", || {
            pg.counter_lease_acquire_atomic(key, ttl, lease)
          })
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.counter_lease_acquire_atomic(key, ttl, lease),
    }
  }

  pub(super) async fn counter_lease_release(
    &self,
    lease: &SharedCounterLease,
  ) -> anyhow::Result<()> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("counter_update", || redis.connection_release_atomic(lease))
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("counter_update", || pg.connection_release_atomic(lease))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.connection_release_atomic(lease),
    }
  }

  pub(super) async fn get_or_init_bytes(
    &self,
    key: &str,
    len: usize,
    ttl: Option<Duration>,
  ) -> anyhow::Result<Vec<u8>> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("value_get_or_init", || {
            redis.get_or_init_bytes_atomic(key, len, ttl)
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("value_get_or_init", || {
            pg.get_or_init_bytes_atomic(key, len, ttl)
          })
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.get_or_init_bytes(key, len, ttl),
    }
  }

  pub(super) async fn put_if_absent(
    &self,
    key: &str,
    value: &[u8],
    ttl: Option<Duration>,
  ) -> anyhow::Result<bool> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("value_put_if_absent", || {
            redis.put_if_absent(key, value, ttl)
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("value_put_if_absent", || {
            pg.put_if_absent_atomic(key, value, ttl)
          })
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.put_if_absent(key, value, ttl),
    }
  }

  pub(super) async fn take_key(&self, key: &str) -> anyhow::Result<bool> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("value_take", || redis.take_key(key))
          .await
      }
      Self::Postgres(pg) => pg.runtime.execute("value_take", || pg.take_key(key)).await,
      #[cfg(test)]
      Self::Memory(memory) => memory.take_key(key),
    }
  }

  pub(super) async fn put(
    &self,
    key: &str,
    value: &[u8],
    ttl: Option<Duration>,
  ) -> anyhow::Result<()> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("value_put", || redis.put(key, value, ttl))
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("value_put", || pg.put(key, value, ttl))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.put(key, value, ttl),
    }
  }

  pub(super) async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
    match self {
      Self::Redis(redis) => redis.runtime.execute("value_get", || redis.get(key)).await,
      Self::Postgres(pg) => pg.runtime.execute("value_get", || pg.get(key)).await,
      #[cfg(test)]
      Self::Memory(memory) => memory.get(key),
    }
  }

  pub(super) async fn delete(&self, key: &str) -> anyhow::Result<()> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("value_delete", || redis.delete(key))
          .await
      }
      Self::Postgres(pg) => pg.runtime.execute("value_delete", || pg.delete(key)).await,
      #[cfg(test)]
      Self::Memory(memory) => memory.delete(key),
    }
  }

  pub(super) async fn unlock(&self, key: &str, token: &str) -> anyhow::Result<()> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("cache_unlock", || redis.unlock(key, token))
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("cache_unlock", || pg.unlock(key, token))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.unlock(key, token),
    }
  }

  pub(super) async fn health_get(&self, key: &str) -> anyhow::Result<Option<HealthRecord>> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("health_read", || redis.health_get(key))
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("health_read", || pg.health_get(key))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.health_get(key),
    }
  }

  pub(super) async fn health_report(
    &self,
    key: &str,
    success: bool,
    enabled: bool,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
  ) -> anyhow::Result<bool> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("health_update", || {
            redis.health_report_atomic(
              key,
              success,
              enabled,
              healthy_threshold,
              unhealthy_threshold,
            )
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("health_update", || {
            pg.health_report_atomic(
              key,
              success,
              enabled,
              healthy_threshold,
              unhealthy_threshold,
            )
          })
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.health_report(
        key,
        success,
        enabled,
        healthy_threshold,
        unhealthy_threshold,
      ),
    }
  }

  pub(super) async fn counter_get(&self, key: &str) -> anyhow::Result<usize> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("counter_read", || redis.counter_get(key))
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("counter_read", || pg.counter_get(key))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.counter_get(key),
    }
  }

  pub(super) async fn counter_add(
    &self,
    key: &str,
    delta: i64,
    ttl: Option<Duration>,
  ) -> anyhow::Result<usize> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("counter_update", || {
            redis.counter_add_atomic(key, delta, ttl)
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("counter_update", || pg.counter_add_atomic(key, delta, ttl))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.counter_add(key, delta, ttl),
    }
  }
}

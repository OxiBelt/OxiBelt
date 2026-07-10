use std::time::Duration;

use anyhow::bail;
use sqlx::Postgres;

use super::{
  PostgresBackend, RedisBackend, SharedRateLimitOutcome, now_unix_ms, parse_rate_bucket,
};

#[cfg(test)]
use std::collections::HashMap;

#[cfg(test)]
use super::{MemoryBackend, MemoryValue, purge_expired_values};

#[cfg(test)]
impl MemoryBackend {
  pub(super) fn rate_take(
    &self,
    limit_name: &str,
    key: &str,
    rate: f64,
    burst: u32,
    max_buckets: usize,
    bucket_ttl: Duration,
  ) -> anyhow::Result<SharedRateLimitOutcome> {
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    let mut rate_indexes = self
      .rate_indexes
      .lock()
      .expect("memory shared rate index lock poisoned");
    let now = now_unix_ms();
    purge_expired_values(&mut values, now);
    purge_expired_rate_indexes(&mut rate_indexes, now);
    let index = rate_indexes.entry(limit_name.to_string()).or_default();
    if !index.contains_key(key) && index.len() >= max_buckets.max(1) {
      return Ok(SharedRateLimitOutcome::BucketCapExceeded);
    }
    let expires_at_ms = expires_at_ms(now, bucket_ttl);
    index.insert(key.to_string(), expires_at_ms);
    drop(rate_indexes);
    Ok(memory_rate_take_value(
      &mut values,
      key,
      rate,
      burst,
      now,
      expires_at_ms,
    ))
  }

  pub(super) fn rate_take_bucket(
    &self,
    key: &str,
    rate: f64,
    burst: u32,
    bucket_ttl: Duration,
  ) -> anyhow::Result<SharedRateLimitOutcome> {
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    let now = now_unix_ms();
    purge_expired_values(&mut values, now);
    let expires_at_ms = expires_at_ms(now, bucket_ttl);
    Ok(memory_rate_take_value(
      &mut values,
      key,
      rate,
      burst,
      now,
      expires_at_ms,
    ))
  }
}

impl RedisBackend {
  pub(super) async fn rate_take(
    &self,
    limit_name: &str,
    key: &str,
    rate: f64,
    burst: u32,
    max_buckets: usize,
    bucket_ttl: Duration,
  ) -> anyhow::Result<SharedRateLimitOutcome> {
    let script = r#"
local raw = redis.call('GET', KEYS[1])
local now = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local burst = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local max_buckets = tonumber(ARGV[5])
local member = ARGV[6]
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
local known = redis.call('ZSCORE', KEYS[2], member)
if not known and redis.call('ZCARD', KEYS[2]) >= max_buckets then
  return 2
end
local tokens = burst
local last = now
if raw then
  local sep = string.find(raw, ':')
  if sep then
    tokens = tonumber(string.sub(raw, 1, sep - 1)) or burst
    last = tonumber(string.sub(raw, sep + 1)) or now
  end
end
local elapsed = math.max(0, now - last)
tokens = math.min(burst, tokens + (elapsed / 1000.0) * rate)
if tokens < 1.0 then
  redis.call('PSETEX', KEYS[1], ttl, tostring(tokens) .. ':' .. tostring(now))
  redis.call('ZADD', KEYS[2], now + ttl, member)
  redis.call('PEXPIRE', KEYS[2], ttl)
  return 0
end
tokens = tokens - 1.0
redis.call('PSETEX', KEYS[1], ttl, tostring(tokens) .. ':' .. tostring(now))
redis.call('ZADD', KEYS[2], now + ttl, member)
redis.call('PEXPIRE', KEYS[2], ttl)
return 1
"#;
    let ttl = ttl_ms(bucket_ttl);
    let resp = self
      .command(&[
        b"EVAL".to_vec(),
        script.as_bytes().to_vec(),
        b"2".to_vec(),
        key.as_bytes().to_vec(),
        limit_name.as_bytes().to_vec(),
        now_unix_ms().to_string().into_bytes(),
        rate.to_string().into_bytes(),
        burst.to_string().into_bytes(),
        ttl.to_string().into_bytes(),
        max_buckets.max(1).to_string().into_bytes(),
        key.as_bytes().to_vec(),
      ])
      .await?;
    shared_rate_limit_outcome(resp.into_i64()?)
  }

  pub(super) async fn rate_take_bucket(
    &self,
    key: &str,
    rate: f64,
    burst: u32,
    bucket_ttl: Duration,
  ) -> anyhow::Result<SharedRateLimitOutcome> {
    let script = r#"
local raw = redis.call('GET', KEYS[1])
local now = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local burst = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local tokens = burst
local last = now
if raw then
  local sep = string.find(raw, ':')
  if sep then
    tokens = tonumber(string.sub(raw, 1, sep - 1)) or burst
    last = tonumber(string.sub(raw, sep + 1)) or now
  end
end
local elapsed = math.max(0, now - last)
tokens = math.min(burst, tokens + (elapsed / 1000.0) * rate)
if tokens < 1.0 then
  redis.call('PSETEX', KEYS[1], ttl, tostring(tokens) .. ':' .. tostring(now))
  return 0
end
tokens = tokens - 1.0
redis.call('PSETEX', KEYS[1], ttl, tostring(tokens) .. ':' .. tostring(now))
return 1
"#;
    let ttl = ttl_ms(bucket_ttl);
    let resp = self
      .command(&[
        b"EVAL".to_vec(),
        script.as_bytes().to_vec(),
        b"1".to_vec(),
        key.as_bytes().to_vec(),
        now_unix_ms().to_string().into_bytes(),
        rate.to_string().into_bytes(),
        burst.to_string().into_bytes(),
        ttl.to_string().into_bytes(),
      ])
      .await?;
    shared_rate_limit_outcome(resp.into_i64()?)
  }
}

impl PostgresBackend {
  pub(super) async fn rate_take(
    &self,
    limit_name: &str,
    key: &str,
    rate: f64,
    burst: u32,
    max_buckets: usize,
    bucket_ttl: Duration,
  ) -> anyhow::Result<SharedRateLimitOutcome> {
    let mut tx = self.pool.begin().await?;
    let now = now_unix_ms();
    let expires_at_ms = expires_at_ms(now, bucket_ttl);
    let max_buckets = i64::try_from(max_buckets.max(1)).unwrap_or(i64::MAX);
    postgres_lock_rate_limit(&mut tx, limit_name).await?;
    sqlx::query(
      "DELETE FROM oxibelt_shared_rate_buckets WHERE limit_name = $1 AND expires_at_ms <= $2",
    )
    .bind(limit_name)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    let existing: Option<i64> = sqlx::query_scalar(
      "SELECT expires_at_ms FROM oxibelt_shared_rate_buckets
       WHERE limit_name = $1 AND bucket_key = $2 AND expires_at_ms > $3",
    )
    .bind(limit_name)
    .bind(key)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?;
    if existing.is_none() {
      let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM oxibelt_shared_rate_buckets WHERE limit_name = $1",
      )
      .bind(limit_name)
      .fetch_one(&mut *tx)
      .await?;
      if active >= max_buckets {
        tx.rollback().await?;
        return Ok(SharedRateLimitOutcome::BucketCapExceeded);
      }
    }
    let outcome = postgres_rate_take_in_tx(&mut tx, key, rate, burst, now, expires_at_ms).await?;
    sqlx::query(
      "INSERT INTO oxibelt_shared_rate_buckets (limit_name, bucket_key, expires_at_ms)
       VALUES ($1, $2, $3)
       ON CONFLICT (limit_name, bucket_key)
       DO UPDATE SET expires_at_ms = EXCLUDED.expires_at_ms",
    )
    .bind(limit_name)
    .bind(key)
    .bind(expires_at_ms)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(outcome)
  }

  pub(super) async fn rate_take_bucket(
    &self,
    key: &str,
    rate: f64,
    burst: u32,
    bucket_ttl: Duration,
  ) -> anyhow::Result<SharedRateLimitOutcome> {
    let mut tx = self.pool.begin().await?;
    let now = now_unix_ms();
    postgres_lock_rate_limit(&mut tx, key).await?;
    let outcome = postgres_rate_take_in_tx(
      &mut tx,
      key,
      rate,
      burst,
      now,
      expires_at_ms(now, bucket_ttl),
    )
    .await?;
    tx.commit().await?;
    Ok(outcome)
  }
}

async fn postgres_lock_rate_limit(
  tx: &mut sqlx::Transaction<'_, Postgres>,
  lock_name: &str,
) -> anyhow::Result<()> {
  sqlx::query(
    "INSERT INTO oxibelt_shared_rate_limit_locks (limit_name) VALUES ($1)
     ON CONFLICT (limit_name) DO NOTHING",
  )
  .bind(lock_name)
  .execute(&mut **tx)
  .await?;
  let _: String = sqlx::query_scalar(
    "SELECT limit_name FROM oxibelt_shared_rate_limit_locks WHERE limit_name = $1 FOR UPDATE",
  )
  .bind(lock_name)
  .fetch_one(&mut **tx)
  .await?;
  Ok(())
}

async fn postgres_rate_take_in_tx(
  tx: &mut sqlx::Transaction<'_, Postgres>,
  key: &str,
  rate: f64,
  burst: u32,
  now: i64,
  expires_at_ms: i64,
) -> anyhow::Result<SharedRateLimitOutcome> {
  let raw: Option<Vec<u8>> = sqlx::query_scalar(
    "SELECT value FROM oxibelt_shared_state
     WHERE key = $1 AND (expires_at_ms IS NULL OR expires_at_ms > $2) FOR UPDATE",
  )
  .bind(key)
  .bind(now)
  .fetch_optional(&mut **tx)
  .await?;
  let (mut tokens, last) = raw
    .as_deref()
    .and_then(parse_rate_bucket)
    .unwrap_or((f64::from(burst), now));
  tokens = (tokens + ((now - last).max(0) as f64 / 1000.0) * rate).min(f64::from(burst));
  let allowed = tokens >= 1.0;
  if allowed {
    tokens -= 1.0;
  }
  let value = format!("{tokens}:{now}").into_bytes();
  sqlx::query(
    "INSERT INTO oxibelt_shared_state (key, value, expires_at_ms) VALUES ($1, $2, $3)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at_ms = EXCLUDED.expires_at_ms",
  )
  .bind(key)
  .bind(value)
  .bind(expires_at_ms)
  .execute(&mut **tx)
  .await?;
  Ok(if allowed {
    SharedRateLimitOutcome::Allowed
  } else {
    SharedRateLimitOutcome::RateLimited
  })
}

fn shared_rate_limit_outcome(value: i64) -> anyhow::Result<SharedRateLimitOutcome> {
  match value {
    0 => Ok(SharedRateLimitOutcome::RateLimited),
    1 => Ok(SharedRateLimitOutcome::Allowed),
    2 => Ok(SharedRateLimitOutcome::BucketCapExceeded),
    other => bail!("unexpected shared rate limit outcome {other}"),
  }
}

fn expires_at_ms(now: i64, ttl: Duration) -> i64 {
  now.saturating_add(ttl_ms(ttl))
}

fn ttl_ms(ttl: Duration) -> i64 {
  ttl
    .max(Duration::from_secs(1))
    .as_millis()
    .min(i64::MAX as u128) as i64
}

#[cfg(test)]
fn purge_expired_rate_indexes(indexes: &mut HashMap<String, HashMap<String, i64>>, now: i64) {
  indexes.retain(|_, buckets| {
    buckets.retain(|_, expires| *expires > now);
    !buckets.is_empty()
  });
}

#[cfg(test)]
fn memory_rate_take_value(
  values: &mut HashMap<String, MemoryValue>,
  key: &str,
  rate: f64,
  burst: u32,
  now: i64,
  expires_at_ms: i64,
) -> SharedRateLimitOutcome {
  let (mut tokens, last) = values
    .get(key)
    .and_then(|value| parse_rate_bucket(&value.value))
    .unwrap_or((f64::from(burst), now));
  tokens = (tokens + ((now - last).max(0) as f64 / 1000.0) * rate).min(f64::from(burst));
  let allowed = tokens >= 1.0;
  if allowed {
    tokens -= 1.0;
  }
  values.insert(
    key.to_string(),
    MemoryValue {
      value: format!("{tokens}:{now}").into_bytes(),
      expires_at_ms: Some(expires_at_ms),
    },
  );
  if allowed {
    SharedRateLimitOutcome::Allowed
  } else {
    SharedRateLimitOutcome::RateLimited
  }
}

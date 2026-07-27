//! Atomic shared-state mutations backed by Redis scripts or PostgreSQL transactions.
//!
//! These operations own transitions that must not be split across backend calls:
//! health-report merges, counters with TTLs, and value initialization. The
//! rate-limit state machine remains in `rate_limits.rs` because it already has
//! its own atomic backend implementations.

use std::time::Duration;

use anyhow::{anyhow, bail};

use super::{HealthRecord, RedisBackend, Resp, SharedCounterLease};
#[cfg(feature = "admin-runtime")]
use super::{PersonProofIdempotencyConflict, PersonProofRevocationResult};

const HEALTH_RECORD_TTL: Duration = Duration::from_secs(60 * 60);

mod postgres;

#[cfg(test)]
mod memory;
#[cfg(test)]
mod tests;

pub(super) fn expiry_after(now: i64, ttl: Duration) -> i64 {
  now.saturating_add(ttl.as_millis().min(i64::MAX as u128) as i64)
}

pub(super) fn ttl_millis(ttl: Duration) -> i64 {
  ttl.as_millis().min(i64::MAX as u128).max(1) as i64
}

pub(super) fn apply_health_report(
  mut record: HealthRecord,
  success: bool,
  enabled: bool,
  healthy_threshold: u32,
  unhealthy_threshold: u32,
) -> HealthRecord {
  if !enabled {
    record.healthy = true;
    record.consecutive_successes = 0;
    record.consecutive_failures = 0;
    return record;
  }

  if success {
    record.consecutive_successes = record.consecutive_successes.saturating_add(1);
    record.consecutive_failures = 0;
    if record.consecutive_successes >= healthy_threshold.max(1) {
      record.healthy = true;
    }
  } else {
    record.consecutive_failures = record.consecutive_failures.saturating_add(1);
    record.consecutive_successes = 0;
    if record.consecutive_failures >= unhealthy_threshold.max(1) {
      record.healthy = false;
    }
  }
  record
}

fn validate_lease_inputs(keys: &[String], limits: &[usize]) -> anyhow::Result<()> {
  if keys.is_empty() || keys.len() != limits.len() {
    bail!("shared connection lease keys and limits must be non-empty and aligned");
  }
  if limits.contains(&0) {
    bail!("shared connection lease limits must be greater than zero");
  }
  let mut sorted = keys.iter().map(String::as_str).collect::<Vec<_>>();
  sorted.sort_unstable();
  if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
    bail!("shared connection lease keys must be unique");
  }
  Ok(())
}

impl RedisBackend {
  pub(super) async fn get_or_init_bytes_atomic(
    &self,
    key: &str,
    len: usize,
    ttl: Option<Duration>,
  ) -> anyhow::Result<Vec<u8>> {
    let mut value = vec![0u8; len];
    crate::crypto::random_fill(&mut value)
      .map_err(|_| anyhow!("failed to generate shared state random bytes"))?;
    let script = r#"
local existing = redis.call('GET', KEYS[1])
if existing then
  return existing
end
if ARGV[2] == '1' then
  redis.call('PSETEX', KEYS[1], ARGV[1], ARGV[3])
else
  redis.call('SET', KEYS[1], ARGV[3])
end
return ARGV[3]
"#;
    let ttl = ttl.map(ttl_millis).unwrap_or_default();
    match self
      .command(&[
        b"EVAL".to_vec(),
        script.as_bytes().to_vec(),
        b"1".to_vec(),
        key.as_bytes().to_vec(),
        ttl.to_string().into_bytes(),
        u8::from(ttl > 0).to_string().into_bytes(),
        value,
      ])
      .await?
    {
      Resp::Bulk(Some(value)) => Ok(value),
      Resp::Error(error) => bail!("Redis error: {error}"),
      other => bail!("unexpected Redis get-or-init response: {other:?}"),
    }
  }

  pub(super) async fn health_report_atomic(
    &self,
    key: &str,
    success: bool,
    enabled: bool,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
  ) -> anyhow::Result<bool> {
    let script = r#"
local raw = redis.call('GET', KEYS[1])
local record = { healthy = true, consecutive_successes = 0, consecutive_failures = 0 }
local max_streak = 4294967295
if raw then
  local ok, decoded = pcall(cjson.decode, raw)
  if not ok or type(decoded) ~= 'table' then
    return redis.error_reply('invalid OxiBelt shared health record')
  end
  if type(decoded.healthy) ~= 'boolean'
    or type(decoded.consecutive_successes) ~= 'number'
    or type(decoded.consecutive_failures) ~= 'number'
    or decoded.consecutive_successes < 0
    or decoded.consecutive_failures < 0
    or decoded.consecutive_successes ~= math.floor(decoded.consecutive_successes)
    or decoded.consecutive_failures ~= math.floor(decoded.consecutive_failures)
    or decoded.consecutive_successes > max_streak
    or decoded.consecutive_failures > max_streak then
    return redis.error_reply('invalid OxiBelt shared health record')
  end
  record.healthy = decoded.healthy
  record.consecutive_successes = decoded.consecutive_successes
  record.consecutive_failures = decoded.consecutive_failures
end
local success = ARGV[1] == '1'
local enabled = ARGV[2] == '1'
local healthy_threshold = math.max(tonumber(ARGV[3]) or 1, 1)
local unhealthy_threshold = math.max(tonumber(ARGV[4]) or 1, 1)
if not enabled then
  record.healthy = true
  record.consecutive_successes = 0
  record.consecutive_failures = 0
elseif success then
  record.consecutive_successes = math.min(max_streak, record.consecutive_successes + 1)
  record.consecutive_failures = 0
  if record.consecutive_successes >= healthy_threshold then
    record.healthy = true
  end
else
  record.consecutive_failures = math.min(max_streak, record.consecutive_failures + 1)
  record.consecutive_successes = 0
  if record.consecutive_failures >= unhealthy_threshold then
    record.healthy = false
  end
end
redis.call('PSETEX', KEYS[1], ARGV[5], cjson.encode(record))
if record.healthy then
  return 1
end
return 0
"#;
    let value = self
      .command(&[
        b"EVAL".to_vec(),
        script.as_bytes().to_vec(),
        b"1".to_vec(),
        key.as_bytes().to_vec(),
        u8::from(success).to_string().into_bytes(),
        u8::from(enabled).to_string().into_bytes(),
        healthy_threshold.max(1).to_string().into_bytes(),
        unhealthy_threshold.max(1).to_string().into_bytes(),
        ttl_millis(HEALTH_RECORD_TTL).to_string().into_bytes(),
      ])
      .await?
      .into_i64()?;
    match value {
      0 => Ok(false),
      1 => Ok(true),
      other => bail!("unexpected Redis health update outcome {other}"),
    }
  }

  pub(super) async fn counter_add_atomic(
    &self,
    key: &str,
    delta: i64,
    ttl: Option<Duration>,
  ) -> anyhow::Result<usize> {
    let script = r#"
local previous_ttl = redis.call('PTTL', KEYS[1])
local value = redis.call('INCRBY', KEYS[1], ARGV[1])
if value < 0 then
  redis.call('SET', KEYS[1], '0')
  value = 0
  if previous_ttl > 0 then
    redis.call('PEXPIRE', KEYS[1], previous_ttl)
  end
end
if ARGV[2] == '1' then
  redis.call('PEXPIRE', KEYS[1], ARGV[3])
end
return value
"#;
    let ttl = ttl.map(ttl_millis).unwrap_or_default();
    let value = self
      .command(&[
        b"EVAL".to_vec(),
        script.as_bytes().to_vec(),
        b"1".to_vec(),
        key.as_bytes().to_vec(),
        delta.to_string().into_bytes(),
        u8::from(ttl > 0).to_string().into_bytes(),
        ttl.to_string().into_bytes(),
      ])
      .await?
      .into_i64()?;
    Ok(value.max(0) as usize)
  }

  pub(super) async fn connection_acquire_atomic(
    &self,
    keys: &[String],
    limits: &[usize],
    ttl: Duration,
    lease: &SharedCounterLease,
  ) -> anyhow::Result<Option<usize>> {
    validate_lease_inputs(keys, limits)?;
    let script = r#"
local marker = redis.call('GET', KEYS[1])
local ttl = tonumber(ARGV[#ARGV - 3])
local fingerprint = ARGV[#ARGV - 2]
local configuration = ARGV[#ARGV - 1]
local adoptable = ARGV[#ARGV] == '1'
if marker then
  if adoptable then
    if string.len(marker) ~= 129
      or string.sub(marker, 65, 65) ~= ':'
      or not string.match(marker, '^[0-9a-f]+:[0-9a-f]+$')
      or string.sub(marker, 1, 64) ~= configuration then
      return -1
    end
    for i = 2, #KEYS do
      local current = tonumber(redis.call('GET', KEYS[i]) or '0')
      local counter_ttl = redis.call('PTTL', KEYS[i])
      if current < 1 or counter_ttl < 1 then
        return -2
      end
    end
    for i = 2, #KEYS do
      redis.call('PEXPIRE', KEYS[i], ttl)
    end
    redis.call('PSETEX', KEYS[1], ttl, fingerprint)
    return 0
  end
  if marker == fingerprint then
    return 0
  end
  return -1
end
for i = 2, #KEYS do
  local current = tonumber(redis.call('GET', KEYS[i]) or '0')
  local limit = tonumber(ARGV[i - 1])
  if current >= limit then
    return i - 1
  end
end
for i = 2, #KEYS do
  redis.call('INCR', KEYS[i])
  redis.call('PEXPIRE', KEYS[i], ttl)
end
redis.call('PSETEX', KEYS[1], ttl, fingerprint)
return 0
"#;
    let mut args = vec![
      b"EVAL".to_vec(),
      script.as_bytes().to_vec(),
      (keys.len() + 1).to_string().into_bytes(),
      lease.marker_key.as_bytes().to_vec(),
    ];
    args.extend(keys.iter().map(|key| key.as_bytes().to_vec()));
    args.extend(limits.iter().map(|limit| limit.to_string().into_bytes()));
    args.push(ttl_millis(ttl).to_string().into_bytes());
    args.push(lease.fingerprint.as_bytes().to_vec());
    args.push(lease.configuration_fingerprint.as_bytes().to_vec());
    args.push(u8::from(lease.adoptable).to_string().into_bytes());
    let value = self.command(&args).await?.into_i64()?;
    match value {
      -2 => bail!("shared connection lease adoption found a missing counter"),
      -1 => bail!("shared connection lease idempotency fingerprint mismatch"),
      0 => Ok(None),
      value if value > 0 => Ok(Some(value as usize - 1)),
      value => bail!("unexpected Redis connection lease outcome {value}"),
    }
  }

  pub(super) async fn connection_release_atomic(
    &self,
    lease: &SharedCounterLease,
  ) -> anyhow::Result<()> {
    let script = r#"
local marker = redis.call('GET', KEYS[1])
if not marker then
  return 0
end
if marker ~= ARGV[1] and ARGV[2] == '1' then
  return 0
end
if marker ~= ARGV[1] then
  return -1
end
redis.call('DEL', KEYS[1])
for i = 2, #KEYS do
  local current = tonumber(redis.call('GET', KEYS[i]) or '0')
  if current <= 1 then
    redis.call('DEL', KEYS[i])
  else
    redis.call('DECR', KEYS[i])
  end
end
return 1
"#;
    let mut args = vec![
      b"EVAL".to_vec(),
      script.as_bytes().to_vec(),
      (lease.keys.len() + 1).to_string().into_bytes(),
      lease.marker_key.as_bytes().to_vec(),
    ];
    args.extend(lease.keys.iter().map(|key| key.as_bytes().to_vec()));
    args.push(lease.fingerprint.as_bytes().to_vec());
    args.push(u8::from(lease.adoptable).to_string().into_bytes());
    match self.command(&args).await?.into_i64()? {
      -1 => bail!("shared connection lease release fingerprint mismatch"),
      0 | 1 => Ok(()),
      value => bail!("unexpected Redis connection release outcome {value}"),
    }
  }

  pub(super) async fn counter_lease_acquire_atomic(
    &self,
    key: &str,
    ttl: Duration,
    lease: &SharedCounterLease,
  ) -> anyhow::Result<()> {
    let script = r#"
local marker = redis.call('GET', KEYS[1])
if marker then
  if marker == ARGV[2] then
    return 0
  end
  return -1
end
redis.call('INCR', KEYS[2])
redis.call('PEXPIRE', KEYS[2], ARGV[1])
redis.call('PSETEX', KEYS[1], ARGV[1], ARGV[2])
return 1
"#;
    match self
      .command(&[
        b"EVAL".to_vec(),
        script.as_bytes().to_vec(),
        b"2".to_vec(),
        lease.marker_key.as_bytes().to_vec(),
        key.as_bytes().to_vec(),
        ttl_millis(ttl).to_string().into_bytes(),
        lease.fingerprint.as_bytes().to_vec(),
      ])
      .await?
      .into_i64()?
    {
      -1 => bail!("shared counter lease idempotency fingerprint mismatch"),
      0 | 1 => Ok(()),
      value => bail!("unexpected Redis counter lease outcome {value}"),
    }
  }

  pub(super) async fn person_proof_mark_challenge_used_atomic(
    &self,
    legacy_key: &str,
    hash_key: &str,
    ttl: Option<Duration>,
  ) -> anyhow::Result<bool> {
    let script = r#"
if redis.call('GET', KEYS[1]) then
  return 0
end
local set_result
if ARGV[1] == '1' then
  set_result = redis.call('SET', KEYS[2], '1', 'NX', 'PX', ARGV[2])
else
  set_result = redis.call('SET', KEYS[2], '1', 'NX')
end
if set_result then
  return 1
end
return 0
"#;
    let ttl_ms = ttl.map(ttl_millis).unwrap_or_default();
    Ok(
      self
        .command(&[
          b"EVAL".to_vec(),
          script.as_bytes().to_vec(),
          b"2".to_vec(),
          legacy_key.as_bytes().to_vec(),
          hash_key.as_bytes().to_vec(),
          u8::from(ttl_ms > 0).to_string().into_bytes(),
          ttl_ms.to_string().into_bytes(),
        ])
        .await?
        .into_i64()?
        == 1,
    )
  }

  pub(super) async fn person_proof_consume_clearance_atomic(
    &self,
    revoked_key: &str,
    hash_key: &str,
    legacy_key: &str,
  ) -> anyhow::Result<bool> {
    let script = r#"
if redis.call('GET', KEYS[1]) then
  return 0
end
if redis.call('DEL', KEYS[2]) > 0 then
  return 1
end
return redis.call('DEL', KEYS[3])
"#;
    Ok(
      self
        .command(&[
          b"EVAL".to_vec(),
          script.as_bytes().to_vec(),
          b"3".to_vec(),
          revoked_key.as_bytes().to_vec(),
          hash_key.as_bytes().to_vec(),
          legacy_key.as_bytes().to_vec(),
        ])
        .await?
        .into_i64()?
        == 1,
    )
  }

  #[cfg(feature = "admin-runtime")]
  #[allow(clippy::too_many_arguments)]
  pub(super) async fn person_proof_revoke_clearance_atomic(
    &self,
    tombstone_key: &str,
    active_key: &str,
    ttl: Duration,
    expires_at_ms: i64,
    idempotency_key: Option<&str>,
    request_fingerprint: Option<&str>,
  ) -> anyhow::Result<PersonProofRevocationResult> {
    let request_fingerprint = match (idempotency_key, request_fingerprint) {
      (Some(_), Some(fingerprint)) => fingerprint,
      (None, None) => "",
      _ => bail!("person proof idempotency inputs must be supplied together"),
    };
    let script = r#"
if #KEYS == 3 then
  local raw = redis.call('GET', KEYS[3])
  if raw then
    local ok, record = pcall(cjson.decode, raw)
    if not ok or type(record) ~= 'table'
      or type(record.fingerprint) ~= 'string'
      or type(record.result) ~= 'table'
      or type(record.result.removed_active) ~= 'boolean'
      or tonumber(record.result.expires_at_ms) == nil then
      return redis.error_reply('invalid OxiBelt Person proof idempotency record')
    end
    if record.fingerprint ~= ARGV[2] then
      return {-1, 0, 0}
    end
    return {0, record.result.removed_active and 1 or 0, record.result.expires_at_ms}
  end
end
local removed_active = redis.call('DEL', KEYS[2]) > 0
redis.call('PSETEX', KEYS[1], ARGV[1], '1')
if #KEYS == 3 then
  local record = cjson.encode({
    fingerprint = ARGV[2],
    result = {
      removed_active = removed_active,
      expires_at_ms = tonumber(ARGV[3]),
    },
  })
  redis.call('PSETEX', KEYS[3], ARGV[1], record)
end
return {1, removed_active and 1 or 0, tonumber(ARGV[3])}
"#;
    let mut args = vec![
      b"EVAL".to_vec(),
      script.as_bytes().to_vec(),
      if idempotency_key.is_some() {
        b"3".to_vec()
      } else {
        b"2".to_vec()
      },
      tombstone_key.as_bytes().to_vec(),
      active_key.as_bytes().to_vec(),
    ];
    if let Some(key) = idempotency_key {
      args.push(key.as_bytes().to_vec());
    }
    args.extend([
      ttl_millis(ttl).to_string().into_bytes(),
      request_fingerprint.as_bytes().to_vec(),
      expires_at_ms.to_string().into_bytes(),
    ]);
    let response = self.command(&args).await?;
    let Resp::Array(values) = response else {
      bail!("unexpected Redis Person proof revocation response: {response:?}");
    };
    let [outcome, removed_active, expires_at_ms] = values
      .try_into()
      .map_err(|_| anyhow!("unexpected Redis Person proof revocation response length"))?;
    match outcome.into_i64()? {
      -1 => Err(anyhow::Error::new(PersonProofIdempotencyConflict)),
      0 | 1 => Ok(PersonProofRevocationResult {
        removed_active: removed_active.into_i64()? == 1,
        expires_at_ms: expires_at_ms.into_i64()?,
      }),
      outcome => bail!("unexpected Redis Person proof revocation outcome {outcome}"),
    }
  }
}

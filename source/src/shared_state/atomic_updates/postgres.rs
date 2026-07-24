//! PostgreSQL transactions for atomic shared-state updates.
//!
//! Kept separate from the Redis scripts so each backend implementation remains
//! small enough to audit independently.

use std::time::Duration;

use anyhow::bail;
use sqlx::Row;

use super::super::{HealthRecord, PostgresBackend, SharedCounterLease, now_unix_ms};
#[cfg(feature = "admin-runtime")]
use super::super::{PersonProofIdempotencyConflict, PersonProofRevocationResult};
use super::{apply_health_report, expiry_after, validate_lease_inputs};

impl PostgresBackend {
  pub(in super::super) async fn get_or_init_bytes_atomic(
    &self,
    key: &str,
    len: usize,
    ttl: Option<Duration>,
  ) -> anyhow::Result<Vec<u8>> {
    let mut candidate = vec![0u8; len];
    crate::crypto::random_fill(&mut candidate)
      .map_err(|_| anyhow::anyhow!("failed to generate shared state random bytes"))?;
    let now = now_unix_ms();
    let expires = ttl.map(|ttl| expiry_after(now, ttl));
    let mut tx = self.pool.begin().await?;
    sqlx::query(
      "INSERT INTO oxibelt_shared_state (key, value, expires_at_ms) VALUES ($1, $2, $3)
       ON CONFLICT (key) DO NOTHING",
    )
    .bind(key)
    .bind(&candidate)
    .bind(expires)
    .execute(&mut *tx)
    .await?;
    let row = sqlx::query(
      "SELECT value, expires_at_ms FROM oxibelt_shared_state WHERE key = $1 FOR UPDATE",
    )
    .bind(key)
    .fetch_one(&mut *tx)
    .await?;
    let active = row
      .try_get::<Option<i64>, _>("expires_at_ms")?
      .is_none_or(|expiry| expiry > now);
    let value = if active {
      row.try_get("value")?
    } else {
      sqlx::query("UPDATE oxibelt_shared_state SET value = $2, expires_at_ms = $3 WHERE key = $1")
        .bind(key)
        .bind(&candidate)
        .bind(expires)
        .execute(&mut *tx)
        .await?;
      candidate
    };
    tx.commit().await?;
    Ok(value)
  }

  pub(in super::super) async fn put_if_absent_atomic(
    &self,
    key: &str,
    value: &[u8],
    ttl: Option<Duration>,
  ) -> anyhow::Result<bool> {
    let now = now_unix_ms();
    let expires = ttl.map(|ttl| expiry_after(now, ttl));
    let mut tx = self.pool.begin().await?;
    let inserted = sqlx::query(
      "INSERT INTO oxibelt_shared_state (key, value, expires_at_ms) VALUES ($1, $2, $3)
       ON CONFLICT (key) DO NOTHING",
    )
    .bind(key)
    .bind(value)
    .bind(expires)
    .execute(&mut *tx)
    .await?
    .rows_affected()
      == 1;
    if inserted {
      tx.commit().await?;
      return Ok(true);
    }
    let expiry: Option<i64> = sqlx::query_scalar(
      "SELECT expires_at_ms FROM oxibelt_shared_state WHERE key = $1 FOR UPDATE",
    )
    .bind(key)
    .fetch_one(&mut *tx)
    .await?;
    if expiry.is_some_and(|value| value <= now) {
      sqlx::query("UPDATE oxibelt_shared_state SET value = $2, expires_at_ms = $3 WHERE key = $1")
        .bind(key)
        .bind(value)
        .bind(expires)
        .execute(&mut *tx)
        .await?;
      tx.commit().await?;
      return Ok(true);
    }
    tx.commit().await?;
    Ok(false)
  }

  pub(in super::super) async fn health_report_atomic(
    &self,
    key: &str,
    success: bool,
    enabled: bool,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
  ) -> anyhow::Result<bool> {
    let mut tx = self.pool.begin().await?;
    let default = serde_json::to_vec(&HealthRecord::default())?;
    sqlx::query(
      "INSERT INTO oxibelt_shared_state (key, value, expires_at_ms) VALUES ($1, $2, NULL)
       ON CONFLICT (key) DO NOTHING",
    )
    .bind(key)
    .bind(default)
    .execute(&mut *tx)
    .await?;
    let raw: Vec<u8> =
      sqlx::query_scalar("SELECT value FROM oxibelt_shared_state WHERE key = $1 FOR UPDATE")
        .bind(key)
        .fetch_one(&mut *tx)
        .await?;
    let record = apply_health_report(
      serde_json::from_slice(&raw)?,
      success,
      enabled,
      healthy_threshold,
      unhealthy_threshold,
    );
    let healthy = record.healthy;
    sqlx::query("UPDATE oxibelt_shared_state SET value = $2, expires_at_ms = NULL WHERE key = $1")
      .bind(key)
      .bind(serde_json::to_vec(&record)?)
      .execute(&mut *tx)
      .await?;
    tx.commit().await?;
    Ok(healthy)
  }

  pub(in super::super) async fn counter_add_atomic(
    &self,
    key: &str,
    delta: i64,
    ttl: Option<Duration>,
  ) -> anyhow::Result<usize> {
    let now = now_unix_ms();
    let expires = ttl.map(|ttl| expiry_after(now, ttl));
    let mut tx = self.pool.begin().await?;
    sqlx::query(
      "INSERT INTO oxibelt_shared_counters (key, counter, expires_at_ms) VALUES ($1, 0, NULL)
       ON CONFLICT (key) DO NOTHING",
    )
    .bind(key)
    .execute(&mut *tx)
    .await?;
    let row = sqlx::query(
      "SELECT counter, expires_at_ms FROM oxibelt_shared_counters WHERE key = $1 FOR UPDATE",
    )
    .bind(key)
    .fetch_one(&mut *tx)
    .await?;
    let previous: i64 = row.try_get("counter")?;
    let previous_expiry: Option<i64> = row.try_get("expires_at_ms")?;
    let expired = previous_expiry.is_some_and(|value| value <= now);
    let next = (if expired { 0 } else { previous })
      .saturating_add(delta)
      .max(0);
    let next_expiry = expires.or_else(|| (!expired).then_some(previous_expiry).flatten());
    sqlx::query(
      "UPDATE oxibelt_shared_counters SET counter = $2, expires_at_ms = $3 WHERE key = $1",
    )
    .bind(key)
    .bind(next)
    .bind(next_expiry)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(next as usize)
  }

  pub(in super::super) async fn connection_acquire_atomic(
    &self,
    keys: &[String],
    limits: &[usize],
    ttl: Duration,
    lease: &SharedCounterLease,
  ) -> anyhow::Result<Option<usize>> {
    validate_lease_inputs(keys, limits)?;
    let now = now_unix_ms();
    let expires_at_ms = expiry_after(now, ttl);
    let mut tx = self.pool.begin().await?;
    cleanup_expired_idempotency(&mut tx, now).await?;

    let inserted = sqlx::query(
      "INSERT INTO oxibelt_shared_idempotency (record_key, fingerprint, result, expires_at_ms)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (record_key) DO NOTHING",
    )
    .bind(&lease.marker_key)
    .bind(lease.fingerprint.as_bytes())
    .bind(b"lease".as_slice())
    .bind(expires_at_ms)
    .execute(&mut *tx)
    .await?
    .rows_affected()
      == 1;

    if !inserted {
      let row = sqlx::query(
        "SELECT fingerprint, expires_at_ms FROM oxibelt_shared_idempotency
         WHERE record_key = $1 FOR UPDATE",
      )
      .bind(&lease.marker_key)
      .fetch_one(&mut *tx)
      .await?;
      let fingerprint: Vec<u8> = row.try_get("fingerprint")?;
      let expiry: i64 = row.try_get("expires_at_ms")?;
      if expiry > now {
        if fingerprint.as_slice() != lease.fingerprint.as_bytes() {
          bail!("shared connection lease idempotency fingerprint mismatch");
        }
        tx.commit().await?;
        return Ok(None);
      }
      sqlx::query(
        "UPDATE oxibelt_shared_idempotency
         SET fingerprint = $2, result = $3, expires_at_ms = $4 WHERE record_key = $1",
      )
      .bind(&lease.marker_key)
      .bind(lease.fingerprint.as_bytes())
      .bind(b"lease".as_slice())
      .bind(expires_at_ms)
      .execute(&mut *tx)
      .await?;
    }

    let mut ordered = keys
      .iter()
      .enumerate()
      .map(|(index, key)| (key.as_str(), index))
      .collect::<Vec<_>>();
    ordered.sort_unstable_by(|left, right| left.0.cmp(right.0));
    for (key, _) in &ordered {
      sqlx::query(
        "INSERT INTO oxibelt_shared_counters (key, counter, expires_at_ms) VALUES ($1, 0, NULL)
         ON CONFLICT (key) DO NOTHING",
      )
      .bind(*key)
      .execute(&mut *tx)
      .await?;
    }

    let mut current = vec![0_i64; keys.len()];
    for (key, index) in &ordered {
      let row = sqlx::query(
        "SELECT counter, expires_at_ms FROM oxibelt_shared_counters WHERE key = $1 FOR UPDATE",
      )
      .bind(*key)
      .fetch_one(&mut *tx)
      .await?;
      let counter: i64 = row.try_get("counter")?;
      let expiry: Option<i64> = row.try_get("expires_at_ms")?;
      current[*index] = if expiry.is_some_and(|value| value <= now) {
        0
      } else {
        counter.max(0)
      };
    }
    if let Some(index) = current
      .iter()
      .zip(limits)
      .position(|(value, limit)| *value >= i64::try_from(*limit).unwrap_or(i64::MAX))
    {
      tx.rollback().await?;
      return Ok(Some(index));
    }
    for (key, index) in &ordered {
      sqlx::query(
        "UPDATE oxibelt_shared_counters
         SET counter = $2, expires_at_ms = $3 WHERE key = $1",
      )
      .bind(*key)
      .bind(current[*index].saturating_add(1))
      .bind(expires_at_ms)
      .execute(&mut *tx)
      .await?;
    }
    tx.commit().await?;
    Ok(None)
  }

  pub(in super::super) async fn connection_release_atomic(
    &self,
    lease: &SharedCounterLease,
  ) -> anyhow::Result<()> {
    let now = now_unix_ms();
    let mut tx = self.pool.begin().await?;
    let row = sqlx::query(
      "SELECT fingerprint, expires_at_ms FROM oxibelt_shared_idempotency
       WHERE record_key = $1 FOR UPDATE",
    )
    .bind(&lease.marker_key)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
      tx.commit().await?;
      return Ok(());
    };
    let fingerprint: Vec<u8> = row.try_get("fingerprint")?;
    if fingerprint.as_slice() != lease.fingerprint.as_bytes() {
      bail!("shared connection lease release fingerprint mismatch");
    }
    let expires_at_ms: i64 = row.try_get("expires_at_ms")?;
    sqlx::query("DELETE FROM oxibelt_shared_idempotency WHERE record_key = $1")
      .bind(&lease.marker_key)
      .execute(&mut *tx)
      .await?;
    if expires_at_ms > now {
      let mut keys = lease.keys.iter().map(String::as_str).collect::<Vec<_>>();
      keys.sort_unstable();
      keys.dedup();
      for key in keys {
        sqlx::query(
          "UPDATE oxibelt_shared_counters
           SET counter = GREATEST(counter - 1, 0) WHERE key = $1",
        )
        .bind(key)
        .execute(&mut *tx)
        .await?;
      }
    }
    tx.commit().await?;
    Ok(())
  }

  pub(in super::super) async fn counter_lease_acquire_atomic(
    &self,
    key: &str,
    ttl: Duration,
    lease: &SharedCounterLease,
  ) -> anyhow::Result<()> {
    let now = now_unix_ms();
    let expires_at_ms = expiry_after(now, ttl);
    let mut tx = self.pool.begin().await?;
    cleanup_expired_idempotency(&mut tx, now).await?;
    let inserted = sqlx::query(
      "INSERT INTO oxibelt_shared_idempotency (record_key, fingerprint, result, expires_at_ms)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (record_key) DO NOTHING",
    )
    .bind(&lease.marker_key)
    .bind(lease.fingerprint.as_bytes())
    .bind(b"counter-lease".as_slice())
    .bind(expires_at_ms)
    .execute(&mut *tx)
    .await?
    .rows_affected()
      == 1;
    if !inserted {
      let row = sqlx::query(
        "SELECT fingerprint, expires_at_ms FROM oxibelt_shared_idempotency
         WHERE record_key = $1 FOR UPDATE",
      )
      .bind(&lease.marker_key)
      .fetch_one(&mut *tx)
      .await?;
      let fingerprint: Vec<u8> = row.try_get("fingerprint")?;
      let expiry: i64 = row.try_get("expires_at_ms")?;
      if expiry > now {
        if fingerprint.as_slice() != lease.fingerprint.as_bytes() {
          bail!("shared counter lease idempotency fingerprint mismatch");
        }
        tx.commit().await?;
        return Ok(());
      }
      sqlx::query(
        "UPDATE oxibelt_shared_idempotency
         SET fingerprint = $2, result = $3, expires_at_ms = $4 WHERE record_key = $1",
      )
      .bind(&lease.marker_key)
      .bind(lease.fingerprint.as_bytes())
      .bind(b"counter-lease".as_slice())
      .bind(expires_at_ms)
      .execute(&mut *tx)
      .await?;
    }
    sqlx::query(
      "INSERT INTO oxibelt_shared_counters (key, counter, expires_at_ms) VALUES ($1, 0, NULL)
       ON CONFLICT (key) DO NOTHING",
    )
    .bind(key)
    .execute(&mut *tx)
    .await?;
    let row = sqlx::query(
      "SELECT counter, expires_at_ms FROM oxibelt_shared_counters WHERE key = $1 FOR UPDATE",
    )
    .bind(key)
    .fetch_one(&mut *tx)
    .await?;
    let previous: i64 = row.try_get("counter")?;
    let previous_expiry: Option<i64> = row.try_get("expires_at_ms")?;
    let next = if previous_expiry.is_some_and(|value| value <= now) {
      1
    } else {
      previous.max(0).saturating_add(1)
    };
    sqlx::query(
      "UPDATE oxibelt_shared_counters SET counter = $2, expires_at_ms = $3 WHERE key = $1",
    )
    .bind(key)
    .bind(next)
    .bind(expires_at_ms)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
  }

  pub(in super::super) async fn person_proof_mark_challenge_used_atomic(
    &self,
    legacy_key: &str,
    hash_key: &str,
    ttl: Option<Duration>,
  ) -> anyhow::Result<bool> {
    let now = now_unix_ms();
    let expires_at_ms = ttl.map(|ttl| expiry_after(now, ttl));
    let mut tx = self.pool.begin().await?;
    let legacy_expiry: Option<Option<i64>> = sqlx::query_scalar(
      "SELECT expires_at_ms FROM oxibelt_shared_state WHERE key = $1 FOR UPDATE",
    )
    .bind(legacy_key)
    .fetch_optional(&mut *tx)
    .await?;
    if legacy_expiry.is_some_and(|expiry| expiry.is_none_or(|expiry| expiry > now)) {
      tx.commit().await?;
      return Ok(false);
    }
    let inserted = sqlx::query(
      "INSERT INTO oxibelt_shared_state AS current (key, value, expires_at_ms)
       VALUES ($1, $2, $3)
       ON CONFLICT (key) DO UPDATE
       SET value = EXCLUDED.value, expires_at_ms = EXCLUDED.expires_at_ms
       WHERE current.expires_at_ms IS NOT NULL AND current.expires_at_ms <= $4
       RETURNING key",
    )
    .bind(hash_key)
    .bind(b"1".as_slice())
    .bind(expires_at_ms)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?
    .is_some();
    tx.commit().await?;
    Ok(inserted)
  }

  pub(in super::super) async fn person_proof_consume_clearance_atomic(
    &self,
    revoked_key: &str,
    hash_key: &str,
    legacy_key: &str,
  ) -> anyhow::Result<bool> {
    let now = now_unix_ms();
    let mut tx = self.pool.begin().await?;
    lock_person_proof_clearance(&mut tx, revoked_key).await?;
    let revoked = sqlx::query_scalar::<_, i64>(
      "SELECT 1 FROM oxibelt_shared_state
       WHERE key = $1 AND (expires_at_ms IS NULL OR expires_at_ms > $2)",
    )
    .bind(revoked_key)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?
    .is_some();
    if revoked {
      tx.commit().await?;
      return Ok(false);
    }
    let removed_hash = sqlx::query(
      "DELETE FROM oxibelt_shared_state
       WHERE key = $1 AND (expires_at_ms IS NULL OR expires_at_ms > $2)",
    )
    .bind(hash_key)
    .bind(now)
    .execute(&mut *tx)
    .await?
    .rows_affected()
      > 0;
    let removed = if removed_hash {
      true
    } else {
      sqlx::query(
        "DELETE FROM oxibelt_shared_state
         WHERE key = $1 AND (expires_at_ms IS NULL OR expires_at_ms > $2)",
      )
      .bind(legacy_key)
      .bind(now)
      .execute(&mut *tx)
      .await?
      .rows_affected()
        > 0
    };
    tx.commit().await?;
    Ok(removed)
  }

  #[cfg(feature = "admin-runtime")]
  #[allow(clippy::too_many_arguments)]
  pub(in super::super) async fn person_proof_revoke_clearance_atomic(
    &self,
    tombstone_key: &str,
    active_key: &str,
    _ttl: Duration,
    expires_at_ms: i64,
    idempotency_key: Option<&str>,
    request_fingerprint: Option<&str>,
  ) -> anyhow::Result<PersonProofRevocationResult> {
    let request_fingerprint = match (idempotency_key, request_fingerprint) {
      (Some(_), Some(fingerprint)) => fingerprint,
      (None, None) => "",
      _ => bail!("person proof idempotency inputs must be supplied together"),
    };
    let now = now_unix_ms();
    let mut tx = self.pool.begin().await?;
    cleanup_expired_idempotency(&mut tx, now).await?;

    if let Some(record_key) = idempotency_key {
      let inserted = sqlx::query(
        "INSERT INTO oxibelt_shared_idempotency (record_key, fingerprint, result, expires_at_ms)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (record_key) DO NOTHING",
      )
      .bind(record_key)
      .bind(request_fingerprint.as_bytes())
      .bind(Vec::<u8>::new())
      .bind(expires_at_ms)
      .execute(&mut *tx)
      .await?
      .rows_affected()
        == 1;
      if !inserted {
        let row = sqlx::query(
          "SELECT fingerprint, result, expires_at_ms FROM oxibelt_shared_idempotency
           WHERE record_key = $1 FOR UPDATE",
        )
        .bind(record_key)
        .fetch_one(&mut *tx)
        .await?;
        let fingerprint: Vec<u8> = row.try_get("fingerprint")?;
        let stored_expires_at_ms: i64 = row.try_get("expires_at_ms")?;
        if stored_expires_at_ms > now {
          if fingerprint.as_slice() != request_fingerprint.as_bytes() {
            return Err(anyhow::Error::new(PersonProofIdempotencyConflict));
          }
          let result: PersonProofRevocationResult =
            serde_json::from_slice(&row.try_get::<Vec<u8>, _>("result")?)?;
          tx.commit().await?;
          return Ok(result);
        }
        sqlx::query(
          "UPDATE oxibelt_shared_idempotency
           SET fingerprint = $2, result = $3, expires_at_ms = $4 WHERE record_key = $1",
        )
        .bind(record_key)
        .bind(request_fingerprint.as_bytes())
        .bind(Vec::<u8>::new())
        .bind(expires_at_ms)
        .execute(&mut *tx)
        .await?;
      }
    }

    lock_person_proof_clearance(&mut tx, tombstone_key).await?;
    let removed_active = sqlx::query(
      "DELETE FROM oxibelt_shared_state
       WHERE key = $1 AND (expires_at_ms IS NULL OR expires_at_ms > $2)",
    )
    .bind(active_key)
    .bind(now)
    .execute(&mut *tx)
    .await?
    .rows_affected()
      > 0;
    sqlx::query(
      "INSERT INTO oxibelt_shared_state (key, value, expires_at_ms) VALUES ($1, $2, $3)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at_ms = EXCLUDED.expires_at_ms",
    )
    .bind(tombstone_key)
    .bind(b"1".as_slice())
    .bind(expires_at_ms)
    .execute(&mut *tx)
    .await?;
    let result = PersonProofRevocationResult {
      removed_active,
      expires_at_ms,
    };
    if let Some(record_key) = idempotency_key {
      sqlx::query("UPDATE oxibelt_shared_idempotency SET result = $2 WHERE record_key = $1")
        .bind(record_key)
        .bind(serde_json::to_vec(&result)?)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(result)
  }
}

async fn lock_person_proof_clearance(
  tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
  key: &str,
) -> anyhow::Result<()> {
  sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
    .bind(key)
    .execute(&mut **tx)
    .await?;
  Ok(())
}

async fn cleanup_expired_idempotency(
  tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
  now: i64,
) -> anyhow::Result<()> {
  sqlx::query(
    "DELETE FROM oxibelt_shared_idempotency
     WHERE ctid IN (
       SELECT ctid FROM oxibelt_shared_idempotency
       WHERE expires_at_ms <= $1
       ORDER BY expires_at_ms
       LIMIT 128
       FOR UPDATE SKIP LOCKED
     )",
  )
  .bind(now)
  .execute(&mut **tx)
  .await?;
  Ok(())
}

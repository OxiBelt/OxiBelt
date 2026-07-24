//! In-memory test backend for atomic shared-state transitions.

use std::time::Duration;

use anyhow::bail;
#[cfg(feature = "admin-runtime")]
use serde::{Deserialize, Serialize};

use super::super::{
  MemoryBackend, MemoryCounter, MemoryLease, MemoryValue, SharedCounterLease, now_unix_ms,
  purge_expired_counters, purge_expired_values,
};
#[cfg(feature = "admin-runtime")]
use super::super::{PersonProofIdempotencyConflict, PersonProofRevocationResult};
use super::{expiry_after, validate_lease_inputs};

#[cfg(feature = "admin-runtime")]
#[derive(Debug, Serialize, Deserialize)]
struct PersonProofIdempotencyRecord {
  fingerprint: String,
  result: PersonProofRevocationResult,
}

impl MemoryBackend {
  pub(in super::super) fn connection_acquire_atomic(
    &self,
    keys: &[String],
    limits: &[usize],
    ttl: Duration,
    lease: &SharedCounterLease,
  ) -> anyhow::Result<Option<usize>> {
    validate_lease_inputs(keys, limits)?;
    let mut counters = self
      .counters
      .lock()
      .expect("memory shared counter lock poisoned");
    let mut leases = self
      .leases
      .lock()
      .expect("memory shared lease lock poisoned");
    let now = now_unix_ms();
    purge_expired_counters(&mut counters, now);
    leases.retain(|_, lease| lease.expires_at_ms > now);
    if let Some(existing) = leases.get(&lease.marker_key) {
      if existing.fingerprint != lease.fingerprint {
        bail!("shared connection lease idempotency fingerprint mismatch");
      }
      return Ok(None);
    }
    for (index, key) in keys.iter().enumerate() {
      if counters.get(key).map(|item| item.counter).unwrap_or(0) >= limits[index] as i64 {
        return Ok(Some(index));
      }
    }
    let expires_at_ms = expiry_after(now, ttl);
    for key in keys {
      let entry = counters.entry(key.clone()).or_insert(MemoryCounter {
        counter: 0,
        expires_at_ms: Some(expires_at_ms),
      });
      entry.counter = entry.counter.saturating_add(1);
      entry.expires_at_ms = Some(expires_at_ms);
    }
    leases.insert(
      lease.marker_key.clone(),
      MemoryLease {
        fingerprint: lease.fingerprint.clone(),
        expires_at_ms,
      },
    );
    Ok(None)
  }

  pub(in super::super) fn connection_release_atomic(
    &self,
    lease: &SharedCounterLease,
  ) -> anyhow::Result<()> {
    let mut counters = self
      .counters
      .lock()
      .expect("memory shared counter lock poisoned");
    let mut leases = self
      .leases
      .lock()
      .expect("memory shared lease lock poisoned");
    let now = now_unix_ms();
    purge_expired_counters(&mut counters, now);
    let Some(marker) = leases.remove(&lease.marker_key) else {
      return Ok(());
    };
    if marker.fingerprint != lease.fingerprint {
      leases.insert(lease.marker_key.clone(), marker);
      bail!("shared connection lease release fingerprint mismatch");
    }
    if marker.expires_at_ms <= now {
      return Ok(());
    }
    for key in &lease.keys {
      if let Some(entry) = counters.get_mut(key) {
        entry.counter = entry.counter.saturating_sub(1);
        if entry.counter == 0 {
          counters.remove(key);
        }
      }
    }
    Ok(())
  }

  pub(in super::super) fn counter_lease_acquire_atomic(
    &self,
    key: &str,
    ttl: Duration,
    lease: &SharedCounterLease,
  ) -> anyhow::Result<()> {
    let mut counters = self
      .counters
      .lock()
      .expect("memory shared counter lock poisoned");
    let mut leases = self
      .leases
      .lock()
      .expect("memory shared lease lock poisoned");
    let now = now_unix_ms();
    purge_expired_counters(&mut counters, now);
    leases.retain(|_, lease| lease.expires_at_ms > now);
    if let Some(existing) = leases.get(&lease.marker_key) {
      if existing.fingerprint != lease.fingerprint {
        bail!("shared counter lease idempotency fingerprint mismatch");
      }
      return Ok(());
    }
    let expires_at_ms = expiry_after(now, ttl);
    let entry = counters.entry(key.to_string()).or_insert(MemoryCounter {
      counter: 0,
      expires_at_ms: Some(expires_at_ms),
    });
    entry.counter = entry.counter.saturating_add(1);
    entry.expires_at_ms = Some(expires_at_ms);
    leases.insert(
      lease.marker_key.clone(),
      MemoryLease {
        fingerprint: lease.fingerprint.clone(),
        expires_at_ms,
      },
    );
    Ok(())
  }

  pub(in super::super) fn person_proof_mark_challenge_used_atomic(
    &self,
    legacy_key: &str,
    hash_key: &str,
    ttl: Option<Duration>,
  ) -> anyhow::Result<bool> {
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    let now = now_unix_ms();
    purge_expired_values(&mut values, now);
    if values.contains_key(legacy_key) || values.contains_key(hash_key) {
      return Ok(false);
    }
    values.insert(
      hash_key.to_string(),
      MemoryValue {
        value: b"1".to_vec(),
        expires_at_ms: ttl.map(|ttl| expiry_after(now, ttl)),
      },
    );
    Ok(true)
  }

  pub(in super::super) fn person_proof_consume_clearance_atomic(
    &self,
    revoked_key: &str,
    hash_key: &str,
    legacy_key: &str,
  ) -> anyhow::Result<bool> {
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    purge_expired_values(&mut values, now_unix_ms());
    if values.contains_key(revoked_key) {
      return Ok(false);
    }
    Ok(values.remove(hash_key).is_some() || values.remove(legacy_key).is_some())
  }

  #[cfg(feature = "admin-runtime")]
  #[allow(clippy::too_many_arguments)]
  pub(in super::super) fn person_proof_revoke_clearance_atomic(
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
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    let now = now_unix_ms();
    purge_expired_values(&mut values, now);
    if let Some(record_key) = idempotency_key
      && let Some(existing) = values.get(record_key)
    {
      let record: PersonProofIdempotencyRecord = serde_json::from_slice(&existing.value)?;
      if record.fingerprint != request_fingerprint {
        return Err(anyhow::Error::new(PersonProofIdempotencyConflict));
      }
      return Ok(record.result);
    }
    let removed_active = values.remove(active_key).is_some();
    let expiry = expiry_after(now, ttl);
    values.insert(
      tombstone_key.to_string(),
      MemoryValue {
        value: b"1".to_vec(),
        expires_at_ms: Some(expiry),
      },
    );
    let result = PersonProofRevocationResult {
      removed_active,
      expires_at_ms,
    };
    if let Some(record_key) = idempotency_key {
      values.insert(
        record_key.to_string(),
        MemoryValue {
          value: serde_json::to_vec(&PersonProofIdempotencyRecord {
            fingerprint: request_fingerprint.to_string(),
            result,
          })?,
          expires_at_ms: Some(expiry),
        },
      );
    }
    Ok(result)
  }
}

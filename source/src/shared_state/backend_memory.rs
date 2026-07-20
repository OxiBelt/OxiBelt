//! In-memory backend mechanics used by deterministic tests.

use super::*;

#[cfg(test)]
impl MemoryBackend {
  pub(super) fn inject_failure_once(&self) {
    self.fail_next_operation.store(true, Ordering::Release);
  }

  pub(super) fn take_forced_failure(&self) -> bool {
    self.fail_next_operation.swap(false, Ordering::AcqRel)
  }

  pub(super) fn get_or_init_bytes(
    &self,
    key: &str,
    len: usize,
    ttl: Option<Duration>,
  ) -> anyhow::Result<Vec<u8>> {
    let mut random = vec![0u8; len];
    crate::crypto::random_fill(&mut random)
      .map_err(|_| anyhow!("failed to generate shared state random bytes"))?;
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    let now = now_unix_ms();
    purge_expired_values(&mut values, now);
    let value = values
      .entry(key.to_string())
      .or_insert_with(|| MemoryValue {
        value: random,
        expires_at_ms: ttl.map(|ttl| atomic_updates::expiry_after(now, ttl)),
      });
    Ok(value.value.clone())
  }

  pub(super) fn put_if_absent(
    &self,
    key: &str,
    value: &[u8],
    ttl: Option<Duration>,
  ) -> anyhow::Result<bool> {
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    let now = now_unix_ms();
    purge_expired_values(&mut values, now);
    if values.contains_key(key) {
      return Ok(false);
    }
    values.insert(
      key.to_string(),
      MemoryValue {
        value: value.to_vec(),
        expires_at_ms: ttl.map(|ttl| atomic_updates::expiry_after(now, ttl)),
      },
    );
    Ok(true)
  }

  pub(super) fn take_key(&self, key: &str) -> anyhow::Result<bool> {
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    let now = now_unix_ms();
    purge_expired_values(&mut values, now);
    Ok(values.remove(key).is_some())
  }

  pub(super) fn put(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> anyhow::Result<()> {
    self
      .values
      .lock()
      .expect("memory shared state lock poisoned")
      .insert(
        key.to_string(),
        MemoryValue {
          value: value.to_vec(),
          expires_at_ms: ttl.map(|ttl| atomic_updates::expiry_after(now_unix_ms(), ttl)),
        },
      );
    Ok(())
  }

  pub(super) fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    purge_expired_values(&mut values, now_unix_ms());
    Ok(values.get(key).map(|value| value.value.clone()))
  }

  pub(super) fn delete(&self, key: &str) -> anyhow::Result<()> {
    self
      .values
      .lock()
      .expect("memory shared state lock poisoned")
      .remove(key);
    Ok(())
  }

  pub(super) fn unlock(&self, key: &str, token: &str) -> anyhow::Result<()> {
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    if values
      .get(key)
      .map(|value| value.value == token.as_bytes())
      .unwrap_or(false)
    {
      values.remove(key);
    }
    Ok(())
  }

  pub(super) fn update_bytes<F>(
    &self,
    key: &str,
    ttl: Option<Duration>,
    update: F,
  ) -> anyhow::Result<Vec<u8>>
  where
    F: FnOnce(Option<&[u8]>) -> anyhow::Result<Vec<u8>>,
  {
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    let now = now_unix_ms();
    purge_expired_values(&mut values, now);
    let current = values.get(key).map(|value| value.value.as_slice());
    let next = update(current)?;
    values.insert(
      key.to_string(),
      MemoryValue {
        value: next.clone(),
        expires_at_ms: ttl.map(|ttl| atomic_updates::expiry_after(now, ttl)),
      },
    );
    Ok(next)
  }

  pub(super) fn counter_get(&self, key: &str) -> anyhow::Result<usize> {
    let mut counters = self
      .counters
      .lock()
      .expect("memory shared counter lock poisoned");
    purge_expired_counters(&mut counters, now_unix_ms());
    Ok(
      counters
        .get(key)
        .map(|item| item.counter.max(0) as usize)
        .unwrap_or(0),
    )
  }

  pub(super) fn counter_add(
    &self,
    key: &str,
    delta: i64,
    ttl: Option<Duration>,
  ) -> anyhow::Result<usize> {
    let mut counters = self
      .counters
      .lock()
      .expect("memory shared counter lock poisoned");
    let now = now_unix_ms();
    purge_expired_counters(&mut counters, now);
    let entry = counters.entry(key.to_string()).or_insert(MemoryCounter {
      counter: 0,
      expires_at_ms: None,
    });
    entry.counter = (entry.counter + delta).max(0);
    if let Some(ttl) = ttl {
      entry.expires_at_ms = Some(atomic_updates::expiry_after(now, ttl));
    }
    Ok(entry.counter as usize)
  }

  pub(super) fn health_get(&self, key: &str) -> anyhow::Result<Option<HealthRecord>> {
    Ok(
      self
        .get(key)?
        .and_then(|value| serde_json::from_slice(&value).ok()),
    )
  }

  pub(super) fn health_report(
    &self,
    key: &str,
    success: bool,
    enabled: bool,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
  ) -> anyhow::Result<bool> {
    let value = self.update_bytes(key, None, |current| {
      let record: HealthRecord = current
        .and_then(|bytes| serde_json::from_slice(bytes).ok())
        .unwrap_or_default();
      let record = atomic_updates::apply_health_report(
        record,
        success,
        enabled,
        healthy_threshold,
        unhealthy_threshold,
      );
      serde_json::to_vec(&record).map_err(Into::into)
    })?;
    let record: HealthRecord = serde_json::from_slice(&value)?;
    Ok(record.healthy)
  }

  pub(super) fn raw_entries(&self, prefix: &str) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    let now = now_unix_ms();
    purge_expired_values(&mut values, now);
    Ok(
      values
        .iter()
        .filter(|(key, _)| key.starts_with(prefix))
        .map(|(key, value)| (key.clone(), value.value.clone()))
        .collect(),
    )
  }
}

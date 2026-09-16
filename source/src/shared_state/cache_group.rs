//! Durable, per-cache-group coherence records.
//!
//! The record layout is owned by the cache runtime. This module only provides
//! bounded opaque bytes with an atomic replace-if-current transition, so a
//! group can keep its member index and state in one backend value.

use anyhow::{bail, ensure};

use super::{SharedState, SharedStateFeature};

const CACHE_GROUP_COHERENCE_PREFIX: &str = "cache:group-coherence-v1";
const MAX_CACHE_GROUP_KEY_BYTES: usize = 256;
const MAX_CACHE_GROUP_VALUE_BYTES: usize = 16 * 1024 * 1024;

impl SharedState {
  /// Reads one durable cache-group coherence record.
  ///
  /// `key` is an opaque, caller-hashed scope. It is placed below the fixed
  /// `group-coherence-v1` namespace and is never interpreted as cache data.
  pub(crate) async fn cache_group_read(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let key = self.cache_group_key(key)?;
    let Some(backend) = &self.cache else {
      return Ok(None);
    };
    let result = match tokio::time::timeout(self.operation_timeout, backend.get(&key)).await {
      Ok(result) => result,
      Err(_) => Err(anyhow::anyhow!("shared cache group read timed out")),
    };
    self.observe_backend_result(SharedStateFeature::Cache, &result);
    result
  }

  /// Atomically inserts or replaces one durable cache-group coherence record.
  ///
  /// `expected = None` inserts only when no active record exists. A present
  /// `expected` must byte-for-byte equal the stored record. Successful writes
  /// deliberately have no TTL so cache-group coherence cannot reset by expiry.
  pub(crate) async fn cache_group_compare_exchange(
    &self,
    key: &str,
    expected: Option<&[u8]>,
    replacement: &[u8],
  ) -> anyhow::Result<bool> {
    let key = self.cache_group_key(key)?;
    validate_value("expected cache group record", expected.unwrap_or_default())?;
    validate_value("replacement cache group record", replacement)?;
    let Some(backend) = &self.cache else {
      return Ok(false);
    };
    let result = match tokio::time::timeout(
      self.operation_timeout,
      backend.compare_exchange(&key, expected, replacement),
    )
    .await
    {
      Ok(result) => result,
      Err(_) => Err(anyhow::anyhow!(
        "shared cache group compare-exchange timed out"
      )),
    };
    self.observe_backend_result(SharedStateFeature::Cache, &result);
    result
  }

  /// The single absolute budget that callers must carry across a group
  /// read/modify/CAS retry loop. Individual backend calls use this same limit.
  pub(crate) fn cache_group_operation_timeout(&self) -> std::time::Duration {
    self.operation_timeout
  }

  /// Maximum records a group implementation may retain in its one authority
  /// value before rejecting an update. It mirrors the configured shared-state
  /// enumeration limit without requiring group-specific backend scans.
  pub(crate) fn cache_group_enumeration_max_items(&self) -> usize {
    self.enumeration.max_items
  }

  fn cache_group_key(&self, scope: &str) -> anyhow::Result<String> {
    ensure!(
      !scope.is_empty() && scope.len() <= MAX_CACHE_GROUP_KEY_BYTES,
      "cache group scope must be between 1 and {MAX_CACHE_GROUP_KEY_BYTES} bytes"
    );
    ensure!(
      !scope.bytes().any(|byte| byte.is_ascii_control()),
      "cache group scope must not contain control bytes"
    );
    Ok(self.key(&format!("{CACHE_GROUP_COHERENCE_PREFIX}:{scope}")))
  }
}

fn validate_value(name: &str, value: &[u8]) -> anyhow::Result<()> {
  if value.len() > MAX_CACHE_GROUP_VALUE_BYTES {
    bail!("{name} exceeds the {MAX_CACHE_GROUP_VALUE_BYTES}-byte cache group limit");
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use tokio::sync::Barrier;

  use super::*;

  #[tokio::test]
  async fn compare_exchange_is_byte_exact_and_durable() {
    let state = SharedState::test_memory("cache-group-cas");
    let scope = "group-scope-digest";

    assert_eq!(state.cache_group_read(scope).await.unwrap(), None);
    assert!(
      !state
        .cache_group_compare_exchange(scope, Some(b"missing"), b"first")
        .await
        .unwrap()
    );
    assert!(
      state
        .cache_group_compare_exchange(scope, None, b"first")
        .await
        .unwrap()
    );
    assert_eq!(
      state.cache_group_read(scope).await.unwrap(),
      Some(b"first".to_vec())
    );
    assert!(
      !state
        .cache_group_compare_exchange(scope, Some(b"FIRST"), b"second")
        .await
        .unwrap()
    );
    assert!(
      state
        .cache_group_compare_exchange(scope, Some(b"first"), b"second")
        .await
        .unwrap()
    );
    assert_eq!(
      state.cache_group_read(scope).await.unwrap(),
      Some(b"second".to_vec())
    );
    assert_eq!(
      state
        .test_cache_raw_keys("cache:group-coherence-v1:group-scope-digest")
        .len(),
      1
    );
  }

  #[tokio::test]
  async fn concurrent_absent_compare_exchange_has_one_winner() {
    let state = SharedState::test_memory("cache-group-cas-concurrent");
    let barrier = Arc::new(Barrier::new(33));
    let mut tasks = tokio::task::JoinSet::new();
    for contender in 0..32 {
      let state = state.clone();
      let barrier = barrier.clone();
      tasks.spawn(async move {
        barrier.wait().await;
        state
          .cache_group_compare_exchange(
            "shared-group-scope",
            None,
            format!("contender-{contender}").as_bytes(),
          )
          .await
      });
    }
    barrier.wait().await;

    let mut winners = 0;
    while let Some(result) = tasks.join_next().await {
      winners += usize::from(result.unwrap().unwrap());
    }
    assert_eq!(winners, 1);
    assert!(
      state
        .cache_group_read("shared-group-scope")
        .await
        .unwrap()
        .is_some()
    );
  }

  #[tokio::test]
  async fn group_inputs_are_bounded() {
    let state = SharedState::test_memory("cache-group-cas-bounds");
    assert!(state.cache_group_read("").await.is_err());
    assert!(
      state
        .cache_group_compare_exchange("scope", None, &vec![0; MAX_CACHE_GROUP_VALUE_BYTES + 1])
        .await
        .is_err()
    );
  }
}

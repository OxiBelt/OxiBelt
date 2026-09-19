//! Bounded storage mechanics for the independently versioned dictionary ledger.
//! Dictionary policy, freshness, and publication remain owned by its runtime.

use anyhow::{Context, ensure};
use std::time::Duration;

use super::SharedState;

const MAX_VALUE_BYTES: usize = 16 * 1024 * 1024;

impl SharedState {
  fn dictionary_key(&self, key: &str) -> anyhow::Result<String> {
    ensure!(
      !key.is_empty()
        && key.len() <= 256
        && key
          .bytes()
          .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'-')),
      "invalid dictionary storage key"
    );
    Ok(self.key(&format!("compression-dictionaries-v1:{key}")))
  }

  pub(crate) async fn dictionary_read(
    &self,
    backend: &str,
    key: &str,
  ) -> anyhow::Result<Option<Vec<u8>>> {
    let key = self.dictionary_key(key)?;
    let backend = self
      .backends
      .get(backend)
      .context("dictionary backend unavailable")?;
    let value = tokio::time::timeout(self.operation_timeout, backend.get(&key))
      .await
      .context("dictionary read timed out")??;
    ensure!(
      value.as_ref().is_none_or(|v| v.len() <= MAX_VALUE_BYTES),
      "dictionary storage value exceeds limit"
    );
    Ok(value)
  }

  pub(crate) async fn dictionary_compare_exchange(
    &self,
    backend: &str,
    key: &str,
    expected: Option<&[u8]>,
    replacement: &[u8],
  ) -> anyhow::Result<bool> {
    ensure!(
      replacement.len() <= MAX_VALUE_BYTES && expected.is_none_or(|v| v.len() <= MAX_VALUE_BYTES),
      "dictionary ledger exceeds limit"
    );
    let key = self.dictionary_key(key)?;
    let backend = self
      .backends
      .get(backend)
      .context("dictionary backend unavailable")?;
    tokio::time::timeout(
      self.operation_timeout,
      backend.compare_exchange(&key, expected, replacement),
    )
    .await
    .context("dictionary publication timed out")?
  }

  pub(crate) async fn dictionary_write_if_manifest_matches(
    &self,
    backend: &str,
    fence: (&str, &[u8]),
    key: &str,
    value: &[u8],
    ttl: Duration,
  ) -> anyhow::Result<bool> {
    let (manifest_key, expected) = fence;
    ensure!(
      manifest_key != key && expected.len() <= MAX_VALUE_BYTES,
      "invalid dictionary manifest fence"
    );
    let manifest_key = self.dictionary_key(manifest_key)?;
    ensure!(
      value.len() <= MAX_VALUE_BYTES && !ttl.is_zero(),
      "invalid dictionary chunk size or lifetime"
    );
    let key = self.dictionary_key(key)?;
    let backend = self
      .backends
      .get(backend)
      .context("dictionary backend unavailable")?;
    tokio::time::timeout(
      self.operation_timeout,
      backend.put_if_manifest_matches(&manifest_key, expected, &key, value, ttl),
    )
    .await
    .context("dictionary chunk write timed out")?
  }

  pub(crate) async fn dictionary_delete(&self, backend: &str, key: &str) -> anyhow::Result<()> {
    let key = self.dictionary_key(key)?;
    let backend = self
      .backends
      .get(backend)
      .context("dictionary backend unavailable")?;
    tokio::time::timeout(self.operation_timeout, backend.delete(&key))
      .await
      .context("dictionary chunk deletion timed out")?
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::shared_state::{Backend, MemoryBackend};
  use std::sync::Arc;

  #[tokio::test]
  async fn shared_chunk_write_is_fenced_by_byte_exact_manifest() {
    let mut state = SharedState::test_memory("dictionary-fence");
    Arc::get_mut(&mut state).unwrap().backends.insert(
      "dictionary".to_owned(),
      Arc::new(Backend::Memory(MemoryBackend::default())),
    );
    assert!(
      state
        .dictionary_compare_exchange("dictionary", "manifest", None, b"pending")
        .await
        .unwrap()
    );
    assert!(
      !state
        .dictionary_write_if_manifest_matches(
          "dictionary",
          ("manifest", b"PENDING"),
          "chunk",
          b"body",
          Duration::from_secs(60)
        )
        .await
        .unwrap()
    );
    assert!(
      state
        .dictionary_write_if_manifest_matches(
          "dictionary",
          ("manifest", b"pending"),
          "chunk",
          b"body",
          Duration::from_secs(60)
        )
        .await
        .unwrap()
    );
    assert!(
      state
        .dictionary_compare_exchange("dictionary", "manifest", Some(b"pending"), b"reclaimed")
        .await
        .unwrap()
    );
    state
      .dictionary_delete("dictionary", "chunk")
      .await
      .unwrap();
    assert!(
      !state
        .dictionary_write_if_manifest_matches(
          "dictionary",
          ("manifest", b"pending"),
          "chunk",
          b"body",
          Duration::from_secs(60)
        )
        .await
        .unwrap()
    );
    assert!(
      state
        .dictionary_read("dictionary", "chunk")
        .await
        .unwrap()
        .is_none()
    );
  }
}

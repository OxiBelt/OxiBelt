//! Crash-consistent single-process CT storage for the explicit local profile.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::Mutex;

use super::postgres::{CtReservedEntry, CtStoredEntry, CtTreeState};

const LOCAL_SCHEMA_VERSION: u32 = 1;
const MAX_LOCAL_STATE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone)]
pub struct CtLocalStore {
  path: PathBuf,
  state: Arc<Mutex<LocalState>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LocalState {
  schema_version: u32,
  log_name: String,
  protocol: String,
  public_identity_sha256: String,
  last_timestamp_millis: u64,
  #[serde(default)]
  last_sth_timestamp_millis: u64,
  entries: Vec<LocalEntry>,
  published_tree_size: u64,
  frozen_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LocalEntry {
  entry_key: String,
  timestamp_millis: u64,
  leaf_input: String,
  extra_data: String,
  leaf_hash: String,
  receipt: Option<String>,
  integrated: bool,
}

impl CtLocalStore {
  pub fn open(
    root: &Path,
    log_name: &str,
    protocol: &str,
    public_identity: &[u8],
  ) -> anyhow::Result<Self> {
    if !root.is_absolute() {
      bail!("local CT storage root must be absolute");
    }
    std::fs::create_dir_all(root)
      .with_context(|| format!("failed to create local CT storage {}", root.display()))?;
    let path = root.join("ct-state-v1.json");
    let identity = encode_hex(&Sha256::digest(public_identity));
    let state = if path.exists() {
      let metadata = std::fs::metadata(&path).context("failed to inspect local CT state")?;
      if metadata.len() > MAX_LOCAL_STATE_BYTES {
        bail!("local CT state exceeds {MAX_LOCAL_STATE_BYTES} bytes");
      }
      let bytes = std::fs::read(&path).context("failed to read local CT state")?;
      let parsed: LocalState =
        serde_json::from_slice(&bytes).context("failed to parse local CT state")?;
      if parsed.schema_version != LOCAL_SCHEMA_VERSION
        || parsed.log_name != log_name
        || parsed.protocol != protocol
        || parsed.public_identity_sha256 != identity
      {
        bail!("local CT state identity differs from configured immutable log identity");
      }
      validate_state(&parsed)?;
      parsed
    } else {
      let state = LocalState {
        schema_version: LOCAL_SCHEMA_VERSION,
        log_name: log_name.to_string(),
        protocol: protocol.to_string(),
        public_identity_sha256: identity,
        last_timestamp_millis: 0,
        last_sth_timestamp_millis: 0,
        entries: Vec::new(),
        published_tree_size: 0,
        frozen_reason: None,
      };
      persist(&path, &state)?;
      state
    };
    Ok(Self {
      path,
      state: Arc::new(Mutex::new(state)),
    })
  }

  pub async fn reserve_entry_with<F>(
    &self,
    entry_key: &[u8; 32],
    build: F,
  ) -> anyhow::Result<CtReservedEntry>
  where
    F: FnOnce(u64, u64) -> anyhow::Result<(Vec<u8>, Vec<u8>, [u8; 32])>,
  {
    self
      .reserve_entry_with_limit(entry_key, usize::MAX, build)
      .await
  }

  pub async fn reserve_entry_with_limit<F>(
    &self,
    entry_key: &[u8; 32],
    max_pending_entries: usize,
    build: F,
  ) -> anyhow::Result<CtReservedEntry>
  where
    F: FnOnce(u64, u64) -> anyhow::Result<(Vec<u8>, Vec<u8>, [u8; 32])>,
  {
    let mut state = self.state.lock().await;
    if let Some(reason) = &state.frozen_reason {
      bail!("CT log is frozen: {reason}");
    }
    let encoded_key = encode_hex(entry_key);
    if let Some((leaf_index, entry)) = state
      .entries
      .iter()
      .enumerate()
      .find(|(_, entry)| entry.entry_key == encoded_key)
    {
      return Ok(CtReservedEntry {
        leaf_index: u64::try_from(leaf_index).context("local CT leaf index overflow")?,
        timestamp_millis: entry.timestamp_millis,
        receipt: entry.receipt.as_deref().map(decode_hex).transpose()?,
        newly_reserved: false,
      });
    }
    if state.entries.iter().any(|entry| entry.receipt.is_none()) {
      bail!("local CT has an unsigned reservation; retry that exact submission first");
    }
    let integrated = state
      .entries
      .iter()
      .take_while(|entry| entry.integrated)
      .count();
    if state.entries.len().saturating_sub(integrated) >= max_pending_entries {
      bail!("local CT pending-entry limit is exhausted");
    }
    let leaf_index = u64::try_from(state.entries.len()).context("local CT leaf index overflow")?;
    let wall_clock = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .context("system clock is before Unix epoch")?;
    let wall_clock = u64::try_from(wall_clock.as_millis()).context("system clock overflow")?;
    let timestamp_millis = wall_clock.max(state.last_timestamp_millis.saturating_add(1));
    let (leaf_input, extra_data, leaf_hash) = build(leaf_index, timestamp_millis)?;
    if leaf_input.is_empty() || leaf_input.len() > 16 * 1024 * 1024 {
      bail!("local CT leaf input has an invalid length");
    }
    state.entries.push(LocalEntry {
      entry_key: encoded_key,
      timestamp_millis,
      leaf_input: encode_hex(&leaf_input),
      extra_data: encode_hex(&extra_data),
      leaf_hash: encode_hex(&leaf_hash),
      receipt: None,
      integrated: false,
    });
    state.last_timestamp_millis = timestamp_millis;
    persist(&self.path, &state)?;
    Ok(CtReservedEntry {
      leaf_index,
      timestamp_millis,
      receipt: None,
      newly_reserved: true,
    })
  }

  pub async fn record_receipt(&self, leaf_index: u64, receipt: &[u8]) -> anyhow::Result<()> {
    if receipt.is_empty() || receipt.len() > 1024 * 1024 {
      bail!("local CT receipt has an invalid length");
    }
    let mut state = self.state.lock().await;
    let entry = state
      .entries
      .get_mut(usize::try_from(leaf_index).context("local CT leaf index overflow")?)
      .ok_or_else(|| anyhow!("local CT leaf is missing"))?;
    let encoded = encode_hex(receipt);
    if entry
      .receipt
      .as_deref()
      .is_some_and(|prior| prior != encoded)
    {
      bail!("local CT durable receipt differs from replacement");
    }
    entry.receipt = Some(encoded);
    persist(&self.path, &state)
  }

  pub async fn discard_unsigned_tail(&self, leaf_index: u64) -> anyhow::Result<()> {
    let mut state = self.state.lock().await;
    let index = usize::try_from(leaf_index).context("local CT leaf index overflow")?;
    if index.checked_add(1) != Some(state.entries.len()) {
      bail!("local CT unsigned cleanup is not the sequencer tail");
    }
    let entry = &state.entries[index];
    if entry.receipt.is_some() || entry.integrated {
      return Ok(());
    }
    let removed = state
      .entries
      .pop()
      .ok_or_else(|| anyhow::anyhow!("validated local CT tail disappeared"))?;
    if let Err(error) = persist(&self.path, &state) {
      state.entries.push(removed);
      return Err(error);
    }
    Ok(())
  }

  pub async fn reserve_sth_timestamp(&self) -> anyhow::Result<u64> {
    let mut state = self.state.lock().await;
    if let Some(reason) = &state.frozen_reason {
      bail!("CT log is frozen: {reason}");
    }
    let wall_clock = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .context("system clock is before Unix epoch")?;
    let wall_clock = u64::try_from(wall_clock.as_millis()).context("system clock overflow")?;
    let timestamp = wall_clock
      .max(state.last_timestamp_millis)
      .max(state.last_sth_timestamp_millis.saturating_add(1));
    state.last_sth_timestamp_millis = timestamp;
    persist(&self.path, &state)?;
    Ok(timestamp)
  }

  pub async fn integrate_ready(&self) -> anyhow::Result<CtTreeState> {
    let mut state = self.state.lock().await;
    if let Some(reason) = &state.frozen_reason {
      bail!("CT log is frozen: {reason}");
    }
    for entry in &mut state.entries {
      if entry.receipt.is_none() {
        break;
      }
      entry.integrated = true;
    }
    let integrated = state
      .entries
      .iter()
      .take_while(|entry| entry.integrated)
      .count();
    let hashes = state.entries[..integrated]
      .iter()
      .map(|entry| decode_hash(&entry.leaf_hash))
      .collect::<anyhow::Result<Vec<_>>>()?;
    let tree_size = u64::try_from(integrated).context("local CT tree size overflow")?;
    let root_hash = crate::ct::merkle::root_from_leaf_hashes(&hashes);
    persist(&self.path, &state)?;
    Ok(CtTreeState {
      tree_size,
      root_hash,
      published_tree_size: state.published_tree_size,
      checkpoint_etag: None,
      checkpoint_version: None,
      checkpoint_published_millis: None,
      frozen_reason: state.frozen_reason.clone(),
    })
  }

  pub async fn record_published_tree_size(&self, tree_size: u64) -> anyhow::Result<()> {
    let mut state = self.state.lock().await;
    let integrated = u64::try_from(
      state
        .entries
        .iter()
        .take_while(|entry| entry.integrated)
        .count(),
    )
    .context("local CT integrated size overflow")?;
    if tree_size < state.published_tree_size || tree_size > integrated {
      bail!("local CT published tree size is non-monotonic or not integrated");
    }
    state.published_tree_size = tree_size;
    persist(&self.path, &state)
  }

  pub async fn tree_state(&self) -> anyhow::Result<CtTreeState> {
    let state = self.state.lock().await;
    let integrated = state
      .entries
      .iter()
      .take_while(|entry| entry.integrated)
      .count();
    let hashes = state.entries[..integrated]
      .iter()
      .map(|entry| decode_hash(&entry.leaf_hash))
      .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(CtTreeState {
      tree_size: u64::try_from(integrated).context("local CT tree size overflow")?,
      root_hash: crate::ct::merkle::root_from_leaf_hashes(&hashes),
      published_tree_size: state.published_tree_size,
      checkpoint_etag: None,
      checkpoint_version: None,
      checkpoint_published_millis: None,
      frozen_reason: state.frozen_reason.clone(),
    })
  }

  pub async fn entries(&self, start: u64, end: u64) -> anyhow::Result<Vec<CtStoredEntry>> {
    if end < start || end.saturating_sub(start) > 1023 {
      bail!("local CT entry range must contain 1..=1024 entries");
    }
    let state = self.state.lock().await;
    let start = usize::try_from(start).context("local CT start overflow")?;
    let end = usize::try_from(end).context("local CT end overflow")?;
    if start >= state.entries.len() {
      return Ok(Vec::new());
    }
    state.entries[start..=end.min(state.entries.len() - 1)]
      .iter()
      .enumerate()
      .filter(|(_, entry)| entry.integrated)
      .map(|(offset, entry)| stored_entry(start + offset, entry))
      .collect()
  }

  pub async fn leaf_hashes(&self, tree_size: u64) -> anyhow::Result<Vec<[u8; 32]>> {
    let state = self.state.lock().await;
    let size = usize::try_from(tree_size).context("local CT tree size overflow")?;
    if size > state.entries.len() || state.entries[..size].iter().any(|entry| !entry.integrated) {
      bail!("local CT requested tree size is not integrated");
    }
    state.entries[..size]
      .iter()
      .map(|entry| decode_hash(&entry.leaf_hash))
      .collect()
  }

  pub async fn freeze(&self, reason: &str) -> anyhow::Result<()> {
    if reason.is_empty() || reason.len() > 256 {
      bail!("local CT freeze reason has an invalid length");
    }
    let mut state = self.state.lock().await;
    if state.frozen_reason.is_none() {
      state.frozen_reason = Some(reason.to_string());
      persist(&self.path, &state)?;
    }
    Ok(())
  }
}

fn stored_entry(index: usize, entry: &LocalEntry) -> anyhow::Result<CtStoredEntry> {
  Ok(CtStoredEntry {
    leaf_index: u64::try_from(index).context("local CT leaf index overflow")?,
    timestamp_millis: entry.timestamp_millis,
    leaf_input: decode_hex(&entry.leaf_input)?,
    extra_data: decode_hex(&entry.extra_data)?,
    leaf_hash: decode_hash(&entry.leaf_hash)?,
    receipt: decode_hex(
      entry
        .receipt
        .as_deref()
        .ok_or_else(|| anyhow!("local CT integrated entry lacks receipt"))?,
    )?,
  })
}

fn validate_state(state: &LocalState) -> anyhow::Result<()> {
  let mut found_unintegrated = false;
  for entry in &state.entries {
    if decode_hex(&entry.entry_key).map_or(true, |value| value.len() != 32)
      || decode_hex(&entry.leaf_hash).map_or(true, |value| value.len() != 32)
      || decode_hex(&entry.leaf_input).is_err()
      || decode_hex(&entry.extra_data).is_err()
      || entry
        .receipt
        .as_deref()
        .is_some_and(|value| decode_hex(value).is_err())
    {
      bail!("local CT state contains malformed hexadecimal fields");
    }
    if found_unintegrated && entry.integrated {
      bail!("local CT integrated prefix is not contiguous");
    }
    found_unintegrated |= !entry.integrated;
    if entry.integrated && entry.receipt.is_none() {
      bail!("local CT integrated entry lacks receipt");
    }
  }
  Ok(())
}

fn persist(path: &Path, state: &LocalState) -> anyhow::Result<()> {
  let bytes = serde_json::to_vec(state).context("failed to encode local CT state")?;
  if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_LOCAL_STATE_BYTES {
    bail!("local CT state exceeds {MAX_LOCAL_STATE_BYTES} bytes");
  }
  let temporary = path.with_extension("json.tmp");
  let mut file = std::fs::OpenOptions::new()
    .create(true)
    .truncate(true)
    .write(true)
    .open(&temporary)
    .context("failed to open temporary local CT state")?;
  file
    .write_all(&bytes)
    .context("failed to write local CT state")?;
  file
    .sync_all()
    .context("failed to flush temporary local CT state")?;
  drop(file);
  std::fs::rename(&temporary, path).context("failed to commit local CT state")?;
  sync_parent_directory(path)?;
  Ok(())
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> anyhow::Result<()> {
  let directory = path
    .parent()
    .ok_or_else(|| anyhow!("local CT state path has no parent directory"))?;
  std::fs::File::open(directory)
    .context("failed to open local CT state directory")?
    .sync_all()
    .context("failed to flush local CT state directory")
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> anyhow::Result<()> {
  Ok(())
}

fn decode_hex(value: &str) -> anyhow::Result<Vec<u8>> {
  if !value.len().is_multiple_of(2) {
    bail!("local CT state contains invalid hexadecimal");
  }
  value
    .as_bytes()
    .chunks_exact(2)
    .map(|pair| {
      let high = decode_nibble(pair[0])?;
      let low = decode_nibble(pair[1])?;
      Ok((high << 4) | low)
    })
    .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
  const DIGITS: &[u8; 16] = b"0123456789abcdef";
  let mut encoded = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
    encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
  }
  encoded
}

fn decode_nibble(value: u8) -> anyhow::Result<u8> {
  match value {
    b'0'..=b'9' => Ok(value - b'0'),
    b'a'..=b'f' => Ok(value - b'a' + 10),
    _ => bail!("local CT state contains invalid hexadecimal"),
  }
}

fn decode_hash(value: &str) -> anyhow::Result<[u8; 32]> {
  decode_hex(value)?
    .try_into()
    .map_err(|_| anyhow!("local CT state contains an invalid hash length"))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn unsigned_reservation_allows_only_its_exact_retry() {
    let directory = tempfile::tempdir().unwrap();
    let store = CtLocalStore::open(directory.path(), "test-log", "rfc6962", &[1, 2, 3]).unwrap();
    let first = store
      .reserve_entry_with_limit(&[1; 32], 8, |_, _| Ok((vec![1], Vec::new(), [2; 32])))
      .await
      .unwrap();
    let duplicate = store
      .reserve_entry_with_limit(&[1; 32], 8, |_, _| unreachable!())
      .await
      .unwrap();
    assert_eq!(duplicate.leaf_index, first.leaf_index);
    assert!(duplicate.receipt.is_none());
    let error = store
      .reserve_entry_with_limit(&[3; 32], 8, |_, _| Ok((vec![3], Vec::new(), [4; 32])))
      .await
      .unwrap_err();
    assert!(error.to_string().contains("unsigned reservation"));
    store.record_receipt(first.leaf_index, &[5]).await.unwrap();
    store
      .reserve_entry_with_limit(&[3; 32], 8, |_, _| Ok((vec![3], Vec::new(), [4; 32])))
      .await
      .unwrap();
  }

  #[tokio::test]
  async fn cancelled_unsigned_tail_is_removed_before_next_submission() {
    let directory = tempfile::tempdir().unwrap();
    let store = CtLocalStore::open(directory.path(), "test-log", "rfc6962", &[1, 2, 3]).unwrap();
    let first = store
      .reserve_entry_with_limit(&[1; 32], 8, |_, _| Ok((vec![1], Vec::new(), [2; 32])))
      .await
      .unwrap();
    store.discard_unsigned_tail(first.leaf_index).await.unwrap();
    let replacement = store
      .reserve_entry_with_limit(&[3; 32], 8, |_, _| Ok((vec![3], Vec::new(), [4; 32])))
      .await
      .unwrap();
    assert_eq!(replacement.leaf_index, first.leaf_index);
    assert!(replacement.timestamp_millis > first.timestamp_millis);
  }
}

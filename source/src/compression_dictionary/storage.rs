//! Opaque, bounded dictionary storage with atomic manifest replacement.
//! Only the dictionary runtime interprets values and authorizes publication.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::cache::external_handler::{
  DictionaryStorageOperation as Op, DictionaryStorageRequest, ExternalCacheHttpClient,
};
use crate::shared_state::SharedState;

const MAX_VALUE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone)]
pub(crate) enum DictionaryStorage {
  Memory(Arc<Mutex<HashMap<String, Vec<u8>>>>),
  Disk(Arc<PathBuf>),
  Shared {
    state: Arc<SharedState>,
    backend: String,
  },
  External {
    client: Box<ExternalCacheHttpClient>,
    permits: Arc<tokio::sync::Semaphore>,
  },
}

impl DictionaryStorage {
  pub(crate) fn memory() -> Self {
    Self::Memory(Arc::new(Mutex::new(HashMap::new())))
  }

  pub(crate) fn disk(root: &Path) -> anyhow::Result<Self> {
    ensure!(root.is_absolute(), "dictionary disk root must be absolute");
    std::fs::create_dir_all(root).context("create dictionary disk root")?;
    let root = root.canonicalize()?;
    ensure!(root.is_dir(), "dictionary root is not a directory");
    Ok(Self::Disk(Arc::new(root)))
  }

  pub(crate) async fn read(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
    validate_key(key)?;
    let value = match self {
      Self::Memory(values) => values
        .lock()
        .map_err(|_| anyhow::anyhow!("dictionary store poisoned"))?
        .get(key)
        .cloned(),
      Self::Disk(root) => {
        let root = root.clone();
        let key = key.to_owned();
        tokio::task::spawn_blocking(move || disk_operation(&root, &key, DiskOperation::Read))
          .await??
          .value
      }
      Self::Shared { state, backend } => state.dictionary_read(backend, key).await?,
      Self::External { client, permits } => {
        let _permit = permits
          .clone()
          .try_acquire_owned()
          .context("dictionary external store saturated")?;
        let reply = client
          .dictionary_storage(&DictionaryStorageRequest::new(Op::Read, key))
          .await?;
        reply.value_base64.map(|v| STANDARD.decode(v)).transpose()?
      }
    };
    ensure!(
      value.as_ref().is_none_or(|v| v.len() <= MAX_VALUE_BYTES),
      "dictionary value exceeds limit"
    );
    Ok(value)
  }

  pub(crate) async fn compare_exchange(
    &self,
    key: &str,
    expected: Option<&[u8]>,
    replacement: &[u8],
  ) -> anyhow::Result<bool> {
    validate_key(key)?;
    validate_value(replacement)?;
    if let Some(expected) = expected {
      validate_value(expected)?;
    }
    match self {
      Self::Memory(values) => {
        let mut values = values
          .lock()
          .map_err(|_| anyhow::anyhow!("dictionary store poisoned"))?;
        if values.get(key).map(Vec::as_slice) != expected {
          return Ok(false);
        }
        values.insert(key.to_owned(), replacement.to_vec());
        Ok(true)
      }
      Self::Disk(root) => {
        let root = root.clone();
        let key = key.to_owned();
        let operation = DiskOperation::CompareExchange {
          expected: expected.map(<[u8]>::to_vec),
          replacement: replacement.to_vec(),
        };
        Ok(
          tokio::task::spawn_blocking(move || disk_operation(&root, &key, operation))
            .await??
            .matched,
        )
      }
      Self::Shared { state, backend } => {
        state
          .dictionary_compare_exchange(backend, key, expected, replacement)
          .await
      }
      Self::External { client, permits } => {
        let _permit = permits
          .clone()
          .try_acquire_owned()
          .context("dictionary external store saturated")?;
        let mut request = DictionaryStorageRequest::new(Op::CompareExchange, key);
        request.expected_base64 = expected.map(|v| STANDARD.encode(v));
        request.value_base64 = Some(STANDARD.encode(replacement));
        Ok(client.dictionary_storage(&request).await?.matched)
      }
    }
  }

  /// Atomically validate the publication manifest and insert one chunk.
  /// Every backend serializes this comparison and write with manifest CAS.
  pub(crate) async fn write_if_manifest_matches(
    &self,
    manifest_key: &str,
    expected: &[u8],
    key: &str,
    value: &[u8],
    ttl: Duration,
  ) -> anyhow::Result<bool> {
    validate_key(key)?;
    validate_value(value)?;
    validate_key(manifest_key)?;
    validate_value(expected)?;
    ensure!(
      manifest_key != key,
      "dictionary chunk cannot replace its manifest"
    );
    ensure!(!ttl.is_zero(), "dictionary lifetime is zero");
    match self {
      Self::Memory(values) => {
        let mut values = values
          .lock()
          .map_err(|_| anyhow::anyhow!("dictionary store poisoned"))?;
        if values.get(manifest_key).map(Vec::as_slice) != Some(expected) {
          return Ok(false);
        }
        values.insert(key.to_owned(), value.to_vec());
        Ok(true)
      }
      Self::Disk(root) => {
        let root = root.clone();
        let key = key.to_owned();
        let value = value.to_vec();
        let manifest_key = manifest_key.to_owned();
        let expected = expected.to_vec();
        Ok(
          tokio::task::spawn_blocking(move || {
            disk_operation(
              &root,
              &key,
              DiskOperation::WriteIfManifestMatches {
                manifest_key,
                expected,
                value,
              },
            )
          })
          .await??
          .matched,
        )
      }
      Self::Shared { state, backend } => {
        state
          .dictionary_write_if_manifest_matches(backend, (manifest_key, expected), key, value, ttl)
          .await
      }
      Self::External { client, permits } => {
        let _permit = permits
          .clone()
          .try_acquire_owned()
          .context("dictionary external store saturated")?;
        let mut request = DictionaryStorageRequest::new(Op::WriteIfManifestMatches, key);
        request.manifest_key = Some(manifest_key);
        request.expected_base64 = Some(STANDARD.encode(expected));
        request.value_base64 = Some(STANDARD.encode(value));
        request.ttl_ms = Some(u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX));
        Ok(client.dictionary_storage(&request).await?.matched)
      }
    }
  }

  pub(crate) async fn delete(&self, key: &str) -> anyhow::Result<()> {
    validate_key(key)?;
    match self {
      Self::Memory(values) => {
        values
          .lock()
          .map_err(|_| anyhow::anyhow!("dictionary store poisoned"))?
          .remove(key);
        Ok(())
      }
      Self::Disk(root) => {
        let root = root.clone();
        let key = key.to_owned();
        tokio::task::spawn_blocking(move || disk_operation(&root, &key, DiskOperation::Delete))
          .await??;
        Ok(())
      }
      Self::Shared { state, backend } => state.dictionary_delete(backend, key).await,
      Self::External { client, permits } => {
        let _permit = permits
          .clone()
          .try_acquire_owned()
          .context("dictionary external store saturated")?;
        ensure!(
          client
            .dictionary_storage(&DictionaryStorageRequest::new(Op::Delete, key))
            .await?
            .matched,
          "dictionary chunk deletion rejected"
        );
        Ok(())
      }
    }
  }
}

fn validate_key(key: &str) -> anyhow::Result<()> {
  ensure!(
    !key.is_empty()
      && key.len() <= 256
      && key
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'-')),
    "invalid dictionary storage key"
  );
  Ok(())
}
fn validate_value(value: &[u8]) -> anyhow::Result<()> {
  ensure!(
    value.len() <= MAX_VALUE_BYTES,
    "dictionary storage value exceeds limit"
  );
  Ok(())
}

enum DiskOperation {
  Read,
  CompareExchange {
    expected: Option<Vec<u8>>,
    replacement: Vec<u8>,
  },
  WriteIfManifestMatches {
    manifest_key: String,
    expected: Vec<u8>,
    value: Vec<u8>,
  },
  Delete,
}
struct DiskResult {
  value: Option<Vec<u8>>,
  matched: bool,
}

fn disk_operation(root: &Path, key: &str, operation: DiskOperation) -> anyhow::Result<DiskResult> {
  use std::os::unix::fs::OpenOptionsExt;
  let lock = std::fs::OpenOptions::new()
    .read(true)
    .write(true)
    .create(true)
    .truncate(false)
    .mode(0o600)
    .custom_flags(libc::O_NOFOLLOW)
    .open(root.join("ledger.lock"))?;
  lock.lock()?;
  let path = root.join(key);
  let read = |path: &Path| -> anyhow::Result<Option<Vec<u8>>> {
    let file = match std::fs::OpenOptions::new()
      .read(true)
      .custom_flags(libc::O_NOFOLLOW)
      .open(path)
    {
      Ok(file) => file,
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
      Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    ensure!(
      metadata.is_file() && metadata.len() <= MAX_VALUE_BYTES as u64,
      "invalid dictionary disk record"
    );
    let mut bytes = Vec::new();
    file
      .take(MAX_VALUE_BYTES as u64 + 1)
      .read_to_end(&mut bytes)?;
    validate_value(&bytes)?;
    Ok(Some(bytes))
  };
  let write = |value: &[u8]| -> anyhow::Result<()> {
    // Fixed staging name under the store lock: crash recovery overwrites it,
    // so repeated process failures cannot accumulate untracked staging files.
    let staging = root.join("ledger-staging");
    let mut file = std::fs::OpenOptions::new()
      .write(true)
      .create(true)
      .truncate(true)
      .mode(0o600)
      .custom_flags(libc::O_NOFOLLOW)
      .open(&staging)?;
    file.write_all(value)?;
    file.sync_all()?;
    std::fs::rename(&staging, &path)?;
    std::fs::File::open(root)?.sync_all()?;
    Ok(())
  };
  let result = match operation {
    DiskOperation::Read => DiskResult {
      value: read(&path)?,
      matched: true,
    },
    DiskOperation::CompareExchange {
      expected,
      replacement,
    } => {
      let matched = read(&path)? == expected;
      if matched {
        write(&replacement)?;
      }
      DiskResult {
        value: None,
        matched,
      }
    }
    DiskOperation::WriteIfManifestMatches {
      manifest_key,
      expected,
      value,
    } => {
      let matched = read(&root.join(manifest_key))?.as_deref() == Some(expected.as_slice());
      if matched {
        // Chunks have unique reserved names. Write directly to that tracked
        // name so a crash during I/O leaves a collectable partial chunk.
        if let Some(existing) = read(&path)? {
          ensure!(
            existing == value,
            "dictionary chunk retry differs from stored bytes"
          );
        } else {
          let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
          file.write_all(&value)?;
          file.sync_all()?;
          std::fs::File::open(root)?.sync_all()?;
        }
      }
      DiskResult {
        value: None,
        matched,
      }
    }
    DiskOperation::Delete => {
      match std::fs::remove_file(path) {
        Ok(()) => std::fs::File::open(root)?.sync_all()?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
      }
      DiskResult {
        value: None,
        matched: true,
      }
    }
  };
  lock.unlock()?;
  Ok(result)
}

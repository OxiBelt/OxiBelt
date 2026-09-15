//! Bounded, atomic persistence of QUERY invalidation epochs and failure fences.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{CacheInner, QUERY_EPOCH_BUCKETS, ResponseCache};

const FILE: &str = ".oxibelt-query-epochs-v1";
const MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EpochVector {
  version: u8,
  buckets: Vec<EpochBucket>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EpochBucket {
  policy: String,
  bucket: u16,
  epoch: u64,
  failed: bool,
}

impl ResponseCache {
  pub(super) fn load_disk_query_epochs(&self, inner: &mut CacheInner, directory: &Path) {
    if !self
      .config
      .cache_methods
      .iter()
      .any(|method| method == "QUERY")
    {
      return;
    }
    if inner.disk_query_epochs_loaded {
      return;
    }
    inner.disk_query_epochs_loaded = true;
    match self.read_disk_query_epochs(directory) {
      Ok(Some(vector)) => {
        for entry in vector.buckets {
          if !self.policies.contains_key(&entry.policy) {
            continue;
          }
          let key = (entry.policy, entry.bucket);
          inner
            .query_invalidation_generations
            .insert(key.clone(), entry.epoch);
          if entry.failed {
            inner.failed_query_invalidations.insert(key);
          }
        }
      }
      Ok(None) => {
        // A new directory can initialize safely, but existing Q1 objects with
        // a missing vector cannot establish their invalidation history.
        inner.discard_recovered_query_entries = true;
        if self.persist_disk_query_epochs(inner).is_err() {
          self.fence_disk_query_epochs(inner);
        }
      }
      Err(_) => {
        inner.discard_recovered_query_entries = true;
        self.fence_disk_query_epochs(inner);
        tracing::warn!("QUERY disk epoch state is unavailable or invalid; QUERY reuse is disabled");
      }
    }
  }

  fn fence_disk_query_epochs(&self, inner: &mut CacheInner) {
    for policy in self.policies.keys() {
      for bucket in 0..QUERY_EPOCH_BUCKETS {
        inner
          .failed_query_invalidations
          .insert((policy.clone(), bucket));
      }
    }
  }

  fn read_disk_query_epochs(&self, directory: &Path) -> anyhow::Result<Option<EpochVector>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
      use std::os::unix::fs::OpenOptionsExt;
      options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(directory.join(FILE)) {
      Ok(file) => file,
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
      Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
      file.metadata()?.is_file(),
      "QUERY epoch vector must be a regular file"
    );
    let mut bytes = Vec::new();
    file.take((MAX_BYTES + 1) as u64).read_to_end(&mut bytes)?;
    anyhow::ensure!(
      bytes.len() <= MAX_BYTES,
      "QUERY epoch vector exceeds its bound"
    );
    let vector: EpochVector = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(
      vector.version == 1 && vector.buckets.len() <= 65_536,
      "invalid QUERY epoch vector"
    );
    let mut seen = HashSet::new();
    for entry in &vector.buckets {
      anyhow::ensure!(
        entry.bucket < QUERY_EPOCH_BUCKETS && entry.policy.len() <= 1024,
        "invalid QUERY epoch bucket"
      );
      anyhow::ensure!(
        seen.insert((&entry.policy, entry.bucket)),
        "duplicate QUERY epoch bucket"
      );
    }
    Ok(Some(vector))
  }

  pub(super) fn persist_disk_query_epochs(&self, inner: &CacheInner) -> anyhow::Result<()> {
    if !self
      .config
      .cache_methods
      .iter()
      .any(|method| method == "QUERY")
    {
      return Ok(());
    }
    let Some(directory) = self.disk_dir.as_ref() else {
      return Ok(());
    };
    let mut keys = inner
      .query_invalidation_generations
      .keys()
      .chain(inner.failed_query_invalidations.iter())
      .cloned()
      .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    anyhow::ensure!(
      keys.len() <= 65_536,
      "QUERY epoch vector exceeds its bucket bound"
    );
    let vector = EpochVector {
      version: 1,
      buckets: keys
        .into_iter()
        .map(|(policy, bucket)| {
          let key = (policy.clone(), bucket);
          EpochBucket {
            policy,
            bucket,
            epoch: inner
              .query_invalidation_generations
              .get(&key)
              .copied()
              .unwrap_or(0),
            failed: inner.failed_query_invalidations.contains(&key),
          }
        })
        .collect(),
    };
    let bytes = serde_json::to_vec(&vector)?;
    anyhow::ensure!(
      bytes.len() <= MAX_BYTES,
      "QUERY epoch vector exceeds its byte bound"
    );
    let mut temporary = tempfile::Builder::new()
      .prefix(".oxibelt-query-epochs-")
      .tempfile_in(directory)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(directory.join(FILE))?;
    std::fs::File::open(directory)?.sync_all()?;
    Ok(())
  }
}

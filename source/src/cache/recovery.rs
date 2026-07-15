//! Bounded recovery of disk-backed cache metadata after startup or lock poison.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::MutexGuard;
use std::sync::atomic::Ordering;
use std::time::SystemTime;

use tracing::warn;

use crate::runtime_health::{PROCESS_GENERATION, RuntimeSubsystem, RuntimeSubsystemState};

use super::{
  CacheInner, ResponseCache, StoredBody, add_size, decode_metadata, index_entry, remove_metadata,
};

pub(super) const DISK_REBUILD_BATCH_SIZE: usize = 256;
const DISK_REBUILD_MAX_SCANNED_FILES: usize = 16_384;

#[derive(Debug)]
pub(super) struct DiskRecoveryState {
  entries: std::fs::ReadDir,
  referenced_bodies: HashSet<PathBuf>,
  orphan_scan: bool,
  pub(super) scanned_files: usize,
}

impl ResponseCache {
  pub(super) fn rebuild_disk_entries_at_startup(&self) {
    if !self.config.enabled || self.disk_dir.is_none() {
      return;
    }
    self.disk_rebuild_requested.store(true, Ordering::Release);
    let max_batches = DISK_REBUILD_MAX_SCANNED_FILES.div_ceil(DISK_REBUILD_BATCH_SIZE) + 1;
    for _ in 0..max_batches {
      drop(self.inner_guard());
      if !self.disk_rebuild_in_progress() {
        break;
      }
    }
  }

  pub(super) fn disk_recovery_guard(&self) -> MutexGuard<'_, Option<DiskRecoveryState>> {
    match self.disk_recovery.lock() {
      Ok(recovery) => recovery,
      Err(poisoned) => {
        let mut recovery = poisoned.into_inner();
        *recovery = None;
        self.disk_recovery.clear_poison();
        self
          .runtime_health
          .record_lock_recovery(RuntimeSubsystem::ResponseCache);
        self.disk_rebuild_requested.store(true, Ordering::Release);
        recovery
      }
    }
  }

  pub(super) fn disk_rebuild_in_progress(&self) -> bool {
    self.disk_rebuild_requested.load(Ordering::Acquire) || self.disk_recovery_guard().is_some()
  }

  pub(super) fn advance_disk_rebuild(&self, inner: &mut CacheInner) {
    let Some(dir) = self.disk_dir.as_ref() else {
      return;
    };
    let mut recovery_guard = self.disk_recovery_guard();
    if self.disk_rebuild_requested.swap(false, Ordering::AcqRel) {
      *recovery_guard = std::fs::read_dir(dir)
        .ok()
        .map(|entries| DiskRecoveryState {
          entries,
          referenced_bodies: HashSet::new(),
          orphan_scan: false,
          scanned_files: 0,
        });
    }
    let Some(recovery) = recovery_guard.as_mut() else {
      self.runtime_health.set_subsystem_state(
        PROCESS_GENERATION,
        RuntimeSubsystem::ResponseCache,
        RuntimeSubsystemState::Healthy,
        false,
      );
      return;
    };

    let mut finished = false;
    for _ in 0..DISK_REBUILD_BATCH_SIZE {
      if recovery.scanned_files >= DISK_REBUILD_MAX_SCANNED_FILES {
        warn!(
          limit = DISK_REBUILD_MAX_SCANNED_FILES,
          "stopping bounded disk cache rebuild at scan limit"
        );
        finished = true;
        break;
      }
      let Some(entry) = recovery.entries.next() else {
        if recovery.orphan_scan {
          finished = true;
          break;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
          finished = true;
          break;
        };
        recovery.entries = entries;
        recovery.orphan_scan = true;
        continue;
      };
      recovery.scanned_files += 1;
      let Ok(entry) = entry else {
        inner.disk_recovery_errors_total += 1;
        continue;
      };
      let path = entry.path();

      if recovery.orphan_scan {
        if path.extension().and_then(|value| value.to_str()) == Some("body")
          && !recovery.referenced_bodies.contains(&path)
          && std::fs::remove_file(&path).is_ok()
        {
          inner.disk_recovery_removed_files_total += 1;
        }
        continue;
      }

      if path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| extension.ends_with("tmp"))
      {
        if std::fs::remove_file(&path).is_ok() {
          inner.disk_recovery_removed_files_total += 1;
        }
        continue;
      }
      if path.extension().and_then(|value| value.to_str()) != Some("meta") {
        continue;
      }
      match decode_metadata(&path, dir) {
        Ok(stored) => {
          if !stored.security_headers_neutral {
            remove_metadata(&stored);
            stored.remove_body();
            inner.disk_recovery_removed_files_total += 2;
            continue;
          }
          let now = SystemTime::now();
          if stored
            .stale_if_error_until
            .unwrap_or(stored.expires_at)
            .duration_since(now)
            .is_err()
          {
            remove_metadata(&stored);
            stored.remove_body();
            inner.disk_recovery_removed_files_total += 2;
            continue;
          }
          let StoredBody::Disk(body_path) = &stored.body else {
            continue;
          };
          if !body_path.is_file() {
            remove_metadata(&stored);
            inner.disk_recovery_errors_total += 1;
            inner.disk_recovery_removed_files_total += 1;
            continue;
          }
          recovery.referenced_bodies.insert(body_path.clone());
          add_size(inner, &stored);
          inner.order.push_back(stored.variant_key.clone());
          index_entry(inner, &stored);
          inner.entries.insert(stored.variant_key.clone(), stored);
          inner.disk_recovered_entries_total += 1;
        }
        Err(error) => {
          warn!(error = %error, path = %path.display(), "failed to load disk cache metadata");
          inner.disk_recovery_errors_total += 1;
          if std::fs::remove_file(path).is_ok() {
            inner.disk_recovery_removed_files_total += 1;
          }
        }
      }
    }
    if finished {
      *recovery_guard = None;
      self.runtime_health.set_subsystem_state(
        PROCESS_GENERATION,
        RuntimeSubsystem::ResponseCache,
        RuntimeSubsystemState::Healthy,
        false,
      );
    }
  }
}

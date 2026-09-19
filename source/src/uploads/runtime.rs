//! Snapshot-scoped managed-upload runtime.
//!
//! Stores are deliberately opened once per immutable application snapshot.
//! Exact storage configuration reuses the prior `Arc`, which is necessary for
//! the local store's process-exclusive lock. A changed local store cannot
//! silently take over the same root: existing sessions retain their old
//! binding and continuations are rejected by the new profile snapshot.

use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::{Config, UploadProfileConfig, UploadStoreConfig, UploadStoreKind};
use anyhow::{Context, bail};

use super::UploadStore;

const GC_INTERVAL: Duration = Duration::from_secs(60);
const GC_RUN_TIMEOUT: Duration = Duration::from_secs(30);
const GC_BATCH: usize = 64;

#[derive(Clone)]
pub struct UploadRuntime {
  inner: Arc<UploadRuntimeInner>,
}

struct UploadRuntimeInner {
  stores: BTreeMap<String, Arc<UploadStore>>,
  store_configs: BTreeMap<String, UploadStoreConfig>,
  store_retentions: BTreeMap<String, Duration>,
  profiles: BTreeMap<String, UploadProfileRuntime>,
  pending_retired: Mutex<Vec<RetiredStore>>,
  gc_started: AtomicBool,
}

struct RetiredStore {
  name: String,
  store: Arc<UploadStore>,
  retention: Duration,
}

#[derive(Clone)]
pub struct UploadProfileRuntime {
  config: UploadProfileConfig,
  store: Arc<UploadStore>,
  admission: Arc<UploadProfileAdmission>,
}

struct UploadProfileAdmission {
  state: Mutex<UploadProfileAdmissionState>,
}

struct UploadProfileAdmissionState {
  uploads: u64,
  parts: u64,
  staged_bytes: u64,
}

/// A bounded create admission. Dropping it releases the in-flight slot.
pub struct UploadCreateAdmission {
  admission: Arc<UploadProfileAdmission>,
}

impl Drop for UploadCreateAdmission {
  fn drop(&mut self) {
    let mut state = self
      .admission
      .state
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner);
    debug_assert!(
      state.uploads > 0,
      "managed upload admission counter underflow"
    );
    state.uploads = state.uploads.saturating_sub(1);
  }
}

/// A bounded part/staging admission. Dropping it releases both reservations.
pub struct UploadPartAdmission {
  admission: Arc<UploadProfileAdmission>,
  bytes: u64,
}

impl Drop for UploadPartAdmission {
  fn drop(&mut self) {
    let mut state = self
      .admission
      .state
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner);
    debug_assert!(state.parts > 0, "managed upload part counter underflow");
    debug_assert!(
      state.staged_bytes >= self.bytes,
      "managed upload staging counter underflow"
    );
    state.parts = state.parts.saturating_sub(1);
    state.staged_bytes = state.staged_bytes.saturating_sub(self.bytes);
  }
}

impl UploadRuntime {
  pub async fn new(config: &Config, previous: Option<&Self>) -> anyhow::Result<Self> {
    if let Some(previous) = previous
      && previous.store_configs_match(config)
      && previous.profiles_match(config)
    {
      return Ok(previous.clone());
    }

    let mut stores = BTreeMap::new();
    let mut store_configs = BTreeMap::new();
    for store_config in &config.upload_stores {
      let store = match previous.and_then(|runtime| runtime.reusable_store(store_config)) {
        Some(store) => store,
        None => {
          if let Some(previous) = previous {
            previous.reject_local_store_migration(store_config)?;
          }
          UploadStore::open(store_config)
            .await
            .with_context(|| format!("failed to open managed upload store {}", store_config.name))?
        }
      };
      stores.insert(store_config.name.clone(), store);
      store_configs.insert(store_config.name.clone(), store_config.clone());
    }

    let mut profiles = BTreeMap::new();
    for profile_config in &config.upload_profiles {
      let store = stores.get(&profile_config.store).cloned().ok_or_else(|| {
        anyhow::anyhow!(
          "managed upload profile {} has no opened store",
          profile_config.name
        )
      })?;
      let admission = previous
        .and_then(|previous| previous.inner.profiles.get(&profile_config.name))
        .map(|old| old.admission.clone())
        .unwrap_or_else(|| {
          Arc::new(UploadProfileAdmission {
            state: Mutex::new(UploadProfileAdmissionState {
              uploads: 0,
              parts: 0,
              staged_bytes: 0,
            }),
          })
        });
      profiles.insert(
        profile_config.name.clone(),
        UploadProfileRuntime {
          config: profile_config.clone(),
          store,
          admission,
        },
      );
    }
    let mut store_retentions = BTreeMap::new();
    if let Some(previous) = previous {
      for (name, store) in &stores {
        if previous
          .inner
          .stores
          .get(name)
          .is_some_and(|old| Arc::ptr_eq(old, store))
          && let Some(retention) = previous.inner.store_retentions.get(name)
        {
          store_retentions.insert(name.clone(), *retention);
        }
      }
    }
    for profile in profiles.values() {
      // An active upload can complete near the end of its upload TTL and then
      // retain the resulting object for its full object TTL.
      let retention = profile_retention(&profile.config);
      store_retentions
        .entry(profile.config.store.clone())
        .and_modify(|current| *current = (*current).max(retention))
        .or_insert(retention);
    }
    let mut pending_retired = Vec::new();
    if let Some(previous) = previous {
      for (name, store) in &previous.inner.stores {
        if stores
          .get(name)
          .is_some_and(|current| Arc::ptr_eq(current, store))
        {
          continue;
        }
        let retention = previous
          .inner
          .store_retentions
          .get(name)
          .copied()
          .unwrap_or_default();
        pending_retired.push(RetiredStore {
          name: name.clone(),
          store: store.clone(),
          retention,
        });
      }
    }
    let runtime = Self {
      inner: Arc::new(UploadRuntimeInner {
        stores,
        store_configs,
        store_retentions,
        profiles,
        pending_retired: Mutex::new(pending_retired),
        gc_started: AtomicBool::new(false),
      }),
    };
    Ok(runtime)
  }

  pub fn profile(&self, name: &str) -> anyhow::Result<&UploadProfileRuntime> {
    self
      .inner
      .profiles
      .get(name)
      .ok_or_else(|| anyhow::anyhow!("managed upload profile {name} is not active"))
  }

  /// Starts effects that are valid only after this candidate snapshot has
  /// become the published application generation.
  pub(crate) fn activate(&self) {
    if !self.inner.gc_started.swap(true, Ordering::AcqRel) {
      self.spawn_bounded_gc();
    }
    let retired = std::mem::take(
      &mut *self
        .inner
        .pending_retired
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    for retired in retired {
      spawn_retired_store_gc(retired.name, retired.store, retired.retention);
    }
  }

  fn reusable_store(&self, candidate: &UploadStoreConfig) -> Option<Arc<UploadStore>> {
    self
      .inner
      .store_configs
      .get(&candidate.name)
      .filter(|existing| *existing == candidate)
      .and_then(|_| self.inner.stores.get(&candidate.name))
      .cloned()
  }

  fn reject_local_store_migration(&self, candidate: &UploadStoreConfig) -> anyhow::Result<()> {
    let Some(candidate_root) = local_root(candidate) else {
      return Ok(());
    };
    if self
      .inner
      .store_configs
      .values()
      .filter_map(local_root)
      .any(|existing_root| existing_root == candidate_root)
    {
      bail!(
        "managed upload local store root {} is held by an incompatible previous snapshot; expire or remove old sessions before changing its store configuration",
        candidate_root.display()
      );
    }
    Ok(())
  }

  fn store_configs_match(&self, config: &Config) -> bool {
    self.inner.store_configs.len() == config.upload_stores.len()
      && config.upload_stores.iter().all(|candidate| {
        self
          .inner
          .store_configs
          .get(&candidate.name)
          .is_some_and(|existing| existing == candidate)
      })
  }

  fn profiles_match(&self, config: &Config) -> bool {
    self.inner.profiles.len() == config.upload_profiles.len()
      && config.upload_profiles.iter().all(|candidate| {
        self
          .inner
          .profiles
          .get(&candidate.name)
          .is_some_and(|existing| existing.config == *candidate)
      })
  }

  fn spawn_bounded_gc(&self) {
    if self.inner.stores.is_empty() {
      return;
    }
    let weak = Arc::downgrade(&self.inner);
    tokio::spawn(async move {
      let mut interval = tokio::time::interval(GC_INTERVAL);
      interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
      loop {
        interval.tick().await;
        let Some(inner) = weak.upgrade() else { return };
        let stores = inner.stores.values().cloned().collect::<Vec<_>>();
        drop(inner);
        if let Err(error) = collect_stores_garbage(&stores).await {
          tracing::warn!(error = %error, "managed upload garbage collection failed");
        }
      }
    });
  }
}

fn profile_retention(profile: &UploadProfileConfig) -> Duration {
  Duration::from_secs(
    profile
      .ttl_seconds
      .saturating_add(profile.object_ttl_seconds),
  )
}

fn spawn_retired_store_gc(name: String, store: Arc<UploadStore>, retention: Duration) {
  // This task is deliberately finite. Operators that need cleanup to survive
  // a process restart must keep the store configured through its drain window.
  tracing::warn!(store = %name, retention_seconds = retention.as_secs(),
    "managed upload store was removed; retaining it in memory for bounded garbage collection; keep the store configured until the drain window ends to preserve cleanup across restart");
  tokio::spawn(async move {
    let deadline = tokio::time::Instant::now() + retention + GC_INTERVAL;
    let mut interval = tokio::time::interval(GC_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
      interval.tick().await;
      if let Err(error) = collect_stores_garbage(std::slice::from_ref(&store)).await {
        tracing::warn!(store = %name, error = %error,
          "retired managed upload store garbage collection failed");
      }
      if tokio::time::Instant::now() >= deadline {
        return;
      }
    }
  });
}

async fn collect_stores_garbage(stores: &[Arc<UploadStore>]) -> anyhow::Result<usize> {
  let deadline = tokio::time::Instant::now() + GC_RUN_TIMEOUT;
  let now_ms = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .context("system clock predates Unix epoch")?
    .as_millis()
    .try_into()
    .context("managed upload GC timestamp overflow")?;
  let mut remaining = GC_BATCH;
  let mut collected = 0;
  let mut seen = HashSet::new();
  for store in stores {
    let identity = Arc::as_ptr(store) as usize;
    if !seen.insert(identity) || remaining == 0 {
      continue;
    }
    let removed = tokio::time::timeout_at(deadline, store.collect_garbage(now_ms, remaining))
      .await
      .context("managed upload garbage collection exceeded its bounded runtime")??;
    collected += removed;
    remaining = remaining.saturating_sub(removed);
  }
  Ok(collected)
}

impl UploadProfileRuntime {
  pub fn store(&self) -> &Arc<UploadStore> {
    &self.store
  }

  pub fn try_admit_create(&self) -> anyhow::Result<UploadCreateAdmission> {
    self
      .admission
      .try_admit_create(u64::from(self.config.max_concurrent_uploads))
  }

  pub fn try_admit_part(&self, staging_bytes: u64) -> anyhow::Result<UploadPartAdmission> {
    self.admission.try_admit_part(
      staging_bytes,
      u64::from(self.config.max_concurrent_parts),
      self.config.max_staging_bytes,
    )
  }
}

impl UploadProfileAdmission {
  fn try_admit_create(self: &Arc<Self>, max_uploads: u64) -> anyhow::Result<UploadCreateAdmission> {
    let mut state = self
      .state
      .lock()
      .map_err(|_| anyhow::anyhow!("managed upload admission accounting is poisoned"))?;
    if state.uploads >= max_uploads {
      bail!("managed upload concurrent-create limit is exhausted");
    }
    state.uploads += 1;
    drop(state);
    Ok(UploadCreateAdmission {
      admission: self.clone(),
    })
  }

  fn try_admit_part(
    self: &Arc<Self>,
    staging_bytes: u64,
    max_parts: u64,
    max_staging_bytes: u64,
  ) -> anyhow::Result<UploadPartAdmission> {
    let mut state = self
      .state
      .lock()
      .map_err(|_| anyhow::anyhow!("managed upload admission accounting is poisoned"))?;
    if staging_bytes > max_staging_bytes {
      bail!("managed upload part staging request exceeds its profile limit");
    }
    if state.parts >= max_parts {
      bail!("managed upload concurrent-part limit is exhausted");
    }
    let Some(next_staged_bytes) = state.staged_bytes.checked_add(staging_bytes) else {
      bail!("managed upload staging-byte limit is exhausted");
    };
    if next_staged_bytes > max_staging_bytes {
      bail!("managed upload staging-byte limit is exhausted");
    }
    state.parts += 1;
    state.staged_bytes = next_staged_bytes;
    drop(state);
    Ok(UploadPartAdmission {
      admission: self.clone(),
      bytes: staging_bytes,
    })
  }
}

fn local_root(config: &UploadStoreConfig) -> Option<&std::path::Path> {
  if config.kind == UploadStoreKind::Local {
    config.local.as_ref().map(|local| local.root.as_path())
  } else {
    None
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::{
    UploadDestinationConfig, UploadIdentityConfig, UploadIdentityKind, UploadProfileConfig,
  };

  fn profile(max_uploads: u32, max_parts: u32, max_staging_bytes: u64) -> UploadProfileConfig {
    UploadProfileConfig {
      name: "profile".to_string(),
      store: "local".to_string(),
      public_base_url: url::Url::parse("https://uploads.example.test").expect("valid URL"),
      staging_dir: std::path::PathBuf::from("/tmp/unused-managed-upload-runtime-tests"),
      max_staging_bytes,
      control_path_prefix: "/uploads".to_string(),
      object_path_prefix: "/objects".to_string(),
      destination: UploadDestinationConfig::Object,
      identity: UploadIdentityConfig {
        kind: UploadIdentityKind::Ipm,
        source: "test".to_string(),
        subject_field: None,
      },
      max_upload_bytes: 64,
      max_part_bytes: 32,
      max_storage_bytes: 128,
      max_sessions: 8,
      max_parts: 8,
      inspection_bytes: 32,
      ttl_seconds: 60,
      object_ttl_seconds: 60,
      max_concurrent_uploads: max_uploads,
      max_concurrent_parts: max_parts,
      compression_dictionary: None,
    }
  }

  fn admission() -> Arc<UploadProfileAdmission> {
    Arc::new(UploadProfileAdmission {
      state: Mutex::new(UploadProfileAdmissionState {
        uploads: 0,
        parts: 0,
        staged_bytes: 0,
      }),
    })
  }

  fn admit_create(
    admission: &Arc<UploadProfileAdmission>,
    profile: &UploadProfileConfig,
  ) -> anyhow::Result<UploadCreateAdmission> {
    admission.try_admit_create(u64::from(profile.max_concurrent_uploads))
  }

  fn admit_part(
    admission: &Arc<UploadProfileAdmission>,
    profile: &UploadProfileConfig,
    bytes: u64,
  ) -> anyhow::Result<UploadPartAdmission> {
    admission.try_admit_part(
      bytes,
      u64::from(profile.max_concurrent_parts),
      profile.max_staging_bytes,
    )
  }

  #[test]
  fn admissions_release_on_drop_and_preserve_limits_across_reload() {
    let original = profile(2, 2, 8);
    let admission = admission();
    let first_create = admit_create(&admission, &original).expect("first create");
    let second_create = admit_create(&admission, &original).expect("second create");
    assert!(admit_create(&admission, &original).is_err());

    let first_part = admit_part(&admission, &original, 4).expect("first part");
    let second_part = admit_part(&admission, &original, 4).expect("second part");
    assert!(admit_part(&admission, &original, 1).is_err());

    let lowered = profile(1, 1, 4);
    drop(first_create);
    drop(first_part);
    // A rejected candidate using lower limits cannot mutate the active
    // snapshot's view of these shared counters.
    assert!(admit_create(&admission, &lowered).is_err());
    assert!(admit_part(&admission, &lowered, 1).is_err());
    let active_create =
      admit_create(&admission, &original).expect("active snapshot keeps its original create limit");
    let active_part = admit_part(&admission, &original, 1)
      .expect("active snapshot keeps its original part and byte limits");
    drop(active_create);
    drop(active_part);

    drop(second_create);
    drop(second_part);
    let replacement_create =
      admit_create(&admission, &lowered).expect("lowered create limit recovers after drops");
    let replacement_part = admit_part(&admission, &lowered, 4)
      .expect("lowered part and byte limits recover after drops");
    assert!(admit_create(&admission, &lowered).is_err());
    assert!(admit_part(&admission, &lowered, 1).is_err());
    drop(replacement_create);
    drop(replacement_part);
  }

  #[test]
  fn retired_store_retention_covers_upload_then_object_lifetime() {
    let mut profile = profile(1, 1, 4);
    profile.ttl_seconds = 37;
    profile.object_ttl_seconds = 61;
    assert_eq!(profile_retention(&profile), Duration::from_secs(98));
  }
}

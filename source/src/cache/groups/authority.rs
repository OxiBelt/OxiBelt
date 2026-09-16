//! Bounded authority storage. Remote updates compare the complete previous
//! record atomically; local updates and durable replacement share one lock.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{Result, bail, ensure};

use super::model::{Authority, MAX_STATE_BYTES, digest};
use crate::cache::ResponseCache;

#[derive(Debug)]
pub(in crate::cache) struct GroupRuntime {
  state: Mutex<BTreeMap<String, Authority>>,
  failed: Mutex<BTreeMap<String, u64>>,
  external_modes: Mutex<BTreeMap<String, bool>>,
  directory: Option<PathBuf>,
}

impl GroupRuntime {
  pub fn new(config: &crate::config::CacheConfig, directory: Option<&Path>) -> Result<Self> {
    let runtime = Self {
      state: Mutex::new(BTreeMap::new()),
      failed: Mutex::new(BTreeMap::new()),
      external_modes: Mutex::new(BTreeMap::new()),
      directory: directory
        .filter(|path| config.enabled || path.is_dir())
        .map(Path::to_path_buf),
    };
    for (policy, enabled) in
      std::iter::once(("default", config.groups.enabled)).chain(config.policies.iter().map(|p| {
        (
          p.name.as_str(),
          p.groups
            .as_ref()
            .map_or(config.groups.enabled, |g| g.enabled),
        )
      }))
    {
      let mut states = runtime.guard()?;
      let mut state = Authority::new(incarnation()?);
      if let Some(path) = runtime.path(policy) {
        let loaded = (|| -> Result<Option<Authority>> {
          let file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
          };
          ensure!(
            file.metadata()?.is_file(),
            "cache group state must be a regular file"
          );
          let mut bytes = Vec::new();
          file
            .take((MAX_STATE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
          Ok(Some(Authority::decode(&bytes)?))
        })();
        match loaded {
          Ok(Some(loaded)) if enabled && loaded.enabled => state = loaded,
          Ok(_) => {}
          Err(error) => {
            tracing::warn!(error = %error, "cache group state unavailable; previous entries will not be reused");
          }
        }
      }
      // Disabling resets the durable incarnation as well, so re-enabling can
      // never recover entries from a previous enabled generation.
      state.enabled = config.enabled && enabled;
      ensure_state_budget(&states, policy, &state)?;
      runtime.persist(policy, &state)?;
      states.insert(policy.to_string(), state);
      if runtime.fence_path(policy).is_some_and(|path| path.exists()) {
        runtime
          .failed
          .lock()
          .map_err(|_| anyhow::anyhow!("cache group fence lock poisoned"))?
          .insert(policy.into(), 1);
      }
    }
    Ok(runtime)
  }

  fn guard(&self) -> Result<MutexGuard<'_, BTreeMap<String, Authority>>> {
    self
      .state
      .lock()
      .map_err(|_| anyhow::anyhow!("cache group authority lock poisoned"))
  }

  fn path(&self, policy: &str) -> Option<PathBuf> {
    Some(
      self
        .directory
        .as_ref()?
        .join(format!(".oxibelt-groups-{}-v1", digest(policy.as_bytes()))),
    )
  }

  fn persist(&self, policy: &str, state: &Authority) -> Result<()> {
    let Some(path) = self.path(policy) else {
      return Ok(());
    };
    let directory = self
      .directory
      .as_ref()
      .ok_or_else(|| anyhow::anyhow!("cache group directory missing"))?;
    let mut file = tempfile::Builder::new()
      .prefix(".oxibelt-groups-tmp-")
      .tempfile_in(directory)?;
    file.write_all(&state.encode()?)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|error| error.error)?;
    std::fs::File::open(directory)?.sync_all()?;
    Ok(())
  }

  pub fn observe(&self, policy: &str, state: Authority) -> Result<()> {
    let mut states = self.guard()?;
    let bytes = states
      .iter()
      .filter(|(name, _)| name.as_str() != policy)
      .try_fold(state.encode()?.len(), |sum, (_, state)| {
        state.encode().map(|bytes| sum.saturating_add(bytes.len()))
      })?;
    ensure!(
      bytes <= MAX_STATE_BYTES,
      "cache group local authority memory budget exhausted"
    );
    states.insert(policy.to_string(), state);
    Ok(())
  }

  /// Reconcile the shared local view before a reloaded snapshot is published.
  /// A disabled policy stays disabled for draining snapshots as well, so they
  /// cannot create a fill snapshot while the remote authority is retired.
  pub fn reconcile<'a>(&self, policies: impl IntoIterator<Item = (&'a str, bool)>) -> Result<()> {
    let mut states = self.guard()?;
    for (policy, enabled) in policies {
      let replacement = match states.get(policy) {
        None => {
          let mut state = Authority::new(incarnation()?);
          state.enabled = enabled;
          Some(state)
        }
        Some(state) if !enabled && state.enabled => {
          let mut state = Authority::new(incarnation()?);
          state.enabled = false;
          Some(state)
        }
        _ => None,
      };
      if let Some(state) = replacement {
        ensure_state_budget(&states, policy, &state)?;
        self.persist(policy, &state)?;
        states.insert(policy.to_string(), state);
      }
    }
    Ok(())
  }

  pub fn local_read(&self, policy: &str) -> Result<Authority> {
    self
      .guard()?
      .get(policy)
      .cloned()
      .ok_or_else(|| anyhow::anyhow!("cache group policy unavailable"))
  }

  pub fn local_current(&self, policy: &str, stamp: &super::CacheGroupStamp) -> bool {
    self
      .guard()
      .is_ok_and(|states| states.get(policy).is_some_and(|state| state.current(stamp)))
  }

  pub fn local_snapshot(
    &self,
    policy: &str,
    origin: &super::CacheGroupOrigin,
    partition: &str,
  ) -> Result<super::CacheGroupStamp> {
    {
      let mut states = self.guard()?;
      if let Some(state) = states.get_mut(policy)
        && state
          .scopes
          .contains_key(&super::model::scope_key(origin, partition))
      {
        return state.snapshot(policy, origin, partition);
      }
    }
    self.local_update(policy, |state| state.snapshot(policy, origin, partition))
  }

  pub fn external_mode(&self, policy: &str) -> Option<bool> {
    self.external_modes.lock().ok()?.get(policy).copied()
  }

  fn set_external_mode(&self, policy: &str, supported: bool) -> Result<()> {
    self
      .external_modes
      .lock()
      .map_err(|_| anyhow::anyhow!("cache group external capability lock poisoned"))?
      .insert(policy.to_string(), supported);
    Ok(())
  }

  pub fn local_update<T>(
    &self,
    policy: &str,
    update: impl Fn(&mut Authority) -> Result<T>,
  ) -> Result<T> {
    let mut states = self.guard()?;
    let mut candidate = states
      .get(policy)
      .cloned()
      .ok_or_else(|| anyhow::anyhow!("cache group policy unavailable"))?;
    let result = update(&mut candidate)?;
    let candidate_bytes = candidate.encode()?.len();
    let other_bytes = states
      .iter()
      .filter(|(name, _)| name.as_str() != policy)
      .try_fold(0usize, |sum, (_, state)| {
        state.encode().map(|bytes| sum.saturating_add(bytes.len()))
      })?;
    ensure!(
      other_bytes.saturating_add(candidate_bytes) <= MAX_STATE_BYTES,
      "cache group local authority memory budget exhausted"
    );
    self.persist(policy, &candidate)?;
    states.insert(policy.to_string(), candidate);
    Ok(result)
  }

  pub fn fence(&self, policy: &str) {
    match self.failed.lock() {
      Ok(mut failed) => {
        let generation = failed.entry(policy.to_string()).or_default();
        *generation = generation.saturating_add(1);
        if let Err(error) = self.persist_fence(policy) {
          tracing::error!(error = %error, "cache group failure fence could not be persisted");
        }
      }
      Err(_) => tracing::error!("cache group failure fence lock poisoned"),
    }
  }

  pub fn fenced(&self, policy: &str) -> bool {
    self
      .failed
      .lock()
      .map_or(true, |failed| failed.contains_key(policy))
  }

  fn fence_path(&self, policy: &str) -> Option<PathBuf> {
    Some(self.directory.as_ref()?.join(format!(
      ".oxibelt-groups-{}-fenced-v1",
      digest(policy.as_bytes())
    )))
  }

  fn persist_fence(&self, policy: &str) -> Result<()> {
    if let Some(path) = self.fence_path(policy) {
      let file = std::fs::File::create(path)?;
      file.sync_all()?;
      if let Some(directory) = &self.directory {
        std::fs::File::open(directory)?.sync_all()?;
      }
    }
    Ok(())
  }

  fn failure_generation(&self, policy: &str) -> Result<Option<u64>> {
    Ok(
      self
        .failed
        .lock()
        .map_err(|_| anyhow::anyhow!("cache group fence lock poisoned"))?
        .get(policy)
        .copied(),
    )
  }

  fn clear_fence(&self, policy: &str, generation: u64) -> Result<bool> {
    let mut failed = self
      .failed
      .lock()
      .map_err(|_| anyhow::anyhow!("cache group fence lock poisoned"))?;
    if failed.get(policy) != Some(&generation) {
      return Ok(false);
    }
    if let Some(path) = self.fence_path(policy) {
      match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
      }
      if let Some(directory) = &self.directory {
        std::fs::File::open(directory)?.sync_all()?;
      }
    }
    failed.remove(policy);
    Ok(true)
  }
}

pub(in crate::cache) fn incarnation() -> Result<String> {
  let mut bytes = [0u8; 32];
  crate::crypto::random_fill(&mut bytes)
    .map_err(|error| anyhow::anyhow!("cache group identity generation failed: {error}"))?;
  Ok(digest(&bytes))
}

fn ensure_state_budget(
  states: &BTreeMap<String, Authority>,
  policy: &str,
  candidate: &Authority,
) -> Result<()> {
  let bytes = states
    .iter()
    .filter(|(name, _)| name.as_str() != policy)
    .try_fold(candidate.encode()?.len(), |sum, (_, state)| {
      state.encode().map(|bytes| sum.saturating_add(bytes.len()))
    })?;
  ensure!(
    bytes <= MAX_STATE_BYTES,
    "cache group local authority memory budget exhausted"
  );
  Ok(())
}

impl ResponseCache {
  pub(crate) async fn initialize_group_activation(&self, previous: Option<&Self>) -> Result<()> {
    if let Some(previous) = previous {
      for policy in previous
        .policies
        .keys()
        .filter(|policy| !self.policies.contains_key(*policy))
      {
        previous
          .group_authority_activation_update(policy, |state| {
            let mut retired = Authority::new(incarnation()?);
            retired.enabled = false;
            *state = retired;
            Ok(())
          })
          .await?;
      }
    }
    let policies = self
      .policies
      .values()
      .map(|policy| (policy.name.as_str(), self.groups_enabled(&policy.name)))
      .collect::<Vec<_>>();
    self.groups.reconcile(policies.iter().copied())?;
    for (policy, enabled) in policies {
      let reenabled = enabled && previous.is_some_and(|old| !old.groups_enabled(policy));
      if !self.group_uses_remote(policy) && enabled && !reenabled {
        continue;
      }
      self
        .group_authority_activation_update(policy, |state| {
          if !enabled || reenabled || !state.enabled {
            let mut replacement = Authority::new(incarnation()?);
            replacement.enabled = enabled;
            *state = replacement;
          }
          Ok(())
        })
        .await?;
    }
    Ok(())
  }
  pub(in crate::cache) async fn recover_group_policy(&self, policy: &str) -> bool {
    let Ok(Some(generation)) = self.groups.failure_generation(policy) else {
      return !self.groups.fenced(policy);
    };
    // Recovery deliberately invalidates the whole policy. It never needs to
    // retain an unbounded queue of unsafe responses while an authority is down.
    let Ok(identity) = incarnation() else {
      return false;
    };
    if self
      .group_authority_update(policy, |state| {
        *state = Authority::new(identity.clone());
        Ok(())
      })
      .await
      .is_err()
    {
      return false;
    }
    let recovered = self.groups.clear_fence(policy, generation).unwrap_or(false);
    if recovered {
      self.group_metrics.record_cache_group_recovery();
    }
    recovered
  }
  pub(in crate::cache) fn group_uses_remote(&self, policy: &str) -> bool {
    self.shared_cache_enabled()
      || (self
        .policy(Some(policy))
        .is_some_and(|p| p.external_handler.is_some())
        && self.groups.external_mode(policy) != Some(false))
  }

  pub(in crate::cache) async fn groups_external_capable(&self, policy: &str) -> bool {
    if self.groups.external_mode(policy) == Some(false) {
      return false;
    }
    let Some(handler) = self
      .policy(Some(policy))
      .and_then(|p| p.external_handler.as_deref())
    else {
      return false;
    };
    match self
      .external_cache
      .group_read(handler, &digest(policy.as_bytes()))
      .await
    {
      Ok(_) => self.groups.set_external_mode(policy, true).is_ok(),
      Err(error) => {
        if self.groups.external_mode(policy).is_none()
          && error.is::<crate::cache::external_handler::UnsupportedCacheGroups>()
        {
          let _ = self.groups.set_external_mode(policy, false);
        }
        false
      }
    }
  }

  pub(in crate::cache) async fn group_authority_read(&self, policy: &str) -> Result<Authority> {
    let local = self.groups.local_read(policy)?;
    if !local.enabled {
      return Ok(local);
    }
    if let Some(shared) = self
      .shared_state
      .as_ref()
      .filter(|shared| shared.has_cache())
    {
      let key = digest(policy.as_bytes());
      if let Some(bytes) = shared.cache_group_read(&key).await? {
        let state = Authority::decode(&bytes)?;
        self.groups.observe(policy, state.clone())?;
        return Ok(state);
      }
      let state = Authority::new(incarnation()?);
      if shared
        .cache_group_compare_exchange(&key, None, &state.encode()?)
        .await?
      {
        self.groups.observe(policy, state.clone())?;
        return Ok(state);
      }
      let state = shared
        .cache_group_read(&key)
        .await?
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("cache group authority disappeared"))
        .and_then(Authority::decode)?;
      self.groups.observe(policy, state.clone())?;
      return Ok(state);
    }
    if let Some(handler) = self
      .policy(Some(policy))
      .and_then(|p| p.external_handler.as_deref())
      && self.groups.external_mode(policy) != Some(false)
    {
      let key = digest(policy.as_bytes());
      match self.external_cache.group_read(handler, &key).await {
        Ok(value) => {
          self.groups.set_external_mode(policy, true)?;
          let state = match value {
            Some(bytes) => Authority::decode(&bytes)?,
            None => {
              let state = Authority::new(incarnation()?);
              if self
                .external_cache
                .group_compare_exchange(handler, &key, None, &state.encode()?)
                .await?
              {
                state
              } else {
                Authority::decode(
                  &self
                    .external_cache
                    .group_read(handler, &key)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("external cache group authority disappeared"))?,
                )?
              }
            }
          };
          self.groups.observe(policy, state.clone())?;
          return Ok(state);
        }
        Err(error)
          if self.groups.external_mode(policy).is_none()
            && error.is::<crate::cache::external_handler::UnsupportedCacheGroups>() =>
        {
          self.groups.set_external_mode(policy, false)?
        }
        Err(error) => return Err(error),
      }
    }
    self.groups.local_read(policy)
  }

  async fn group_external_authority_capable(&self, policy: &str) -> Result<bool> {
    if self.groups.external_mode(policy) == Some(false) {
      return Ok(false);
    }
    let Some(handler) = self
      .policy(Some(policy))
      .and_then(|policy| policy.external_handler.as_deref())
    else {
      return Ok(false);
    };
    match self
      .external_cache
      .group_read(handler, &digest(policy.as_bytes()))
      .await
    {
      Ok(_) => {
        self.groups.set_external_mode(policy, true)?;
        Ok(true)
      }
      Err(error)
        if self.groups.external_mode(policy).is_none()
          && error.is::<crate::cache::external_handler::UnsupportedCacheGroups>() =>
      {
        self.groups.set_external_mode(policy, false)?;
        Ok(false)
      }
      Err(error) => Err(error),
    }
  }

  pub(in crate::cache) async fn group_authority_update<T>(
    &self,
    policy: &str,
    update: impl Fn(&mut Authority) -> Result<T>,
  ) -> Result<T> {
    self
      .group_authority_update_inner(policy, false, update)
      .await
  }

  async fn group_authority_activation_update<T>(
    &self,
    policy: &str,
    update: impl Fn(&mut Authority) -> Result<T>,
  ) -> Result<T> {
    self
      .group_authority_update_inner(policy, true, update)
      .await
  }

  async fn group_authority_update_inner<T>(
    &self,
    policy: &str,
    allow_disabled: bool,
    update: impl Fn(&mut Authority) -> Result<T>,
  ) -> Result<T> {
    if !allow_disabled && !self.groups.local_read(policy)?.enabled {
      bail!("cache group authority disabled");
    }
    let Some(shared) = self
      .shared_state
      .as_ref()
      .filter(|shared| shared.has_cache())
    else {
      if self.group_external_authority_capable(policy).await? {
        let handler = self
          .policy(Some(policy))
          .and_then(|p| p.external_handler.as_deref())
          .ok_or_else(|| anyhow::anyhow!("cache group external handler disappeared"))?;
        let deadline = self
          .config
          .external_handlers
          .iter()
          .find(|h| h.name == handler)
          .map_or(Duration::from_secs(1), |h| {
            Duration::from_millis(h.request_timeout_ms)
          });
        return tokio::time::timeout(deadline, async {
          let key = digest(policy.as_bytes());
          for _ in 0..16 {
            let previous = self.external_cache.group_read(handler, &key).await?;
            let mut state = match previous.as_deref() {
              Some(bytes) => Authority::decode(bytes)?,
              None => Authority::new(incarnation()?),
            };
            if !allow_disabled && !state.enabled {
              self.groups.observe(policy, state)?;
              bail!("cache group authority disabled");
            }
            let result = update(&mut state)?;
            if self
              .external_cache
              .group_compare_exchange(handler, &key, previous.as_deref(), &state.encode()?)
              .await?
            {
              self.groups.observe(policy, state)?;
              return Ok(result);
            }
            tokio::task::yield_now().await;
          }
          bail!("external cache group authority contention limit exceeded")
        })
        .await
        .map_err(|_| anyhow::anyhow!("external cache group operation deadline exceeded"))?;
      }
      return self.groups.local_update(policy, update);
    };
    let deadline = shared.cache_group_operation_timeout();
    tokio::time::timeout(deadline, async {
      let key = digest(policy.as_bytes());
      for _ in 0..16 {
        let previous = shared.cache_group_read(&key).await?;
        let mut state = match previous.as_deref() {
          Some(bytes) => Authority::decode(bytes)?,
          None => Authority::new(incarnation()?),
        };
        if !allow_disabled && !state.enabled {
          self.groups.observe(policy, state)?;
          bail!("cache group authority disabled");
        }
        let result = update(&mut state)?;
        if shared
          .cache_group_compare_exchange(&key, previous.as_deref(), &state.encode()?)
          .await?
        {
          self.groups.observe(policy, state)?;
          return Ok(result);
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
      }
      bail!("cache group authority contention limit exceeded")
    })
    .await
    .map_err(|_| anyhow::anyhow!("cache group operation deadline exceeded"))?
  }
}

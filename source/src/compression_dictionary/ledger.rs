//! Compare-and-swap manifest ledger for learned compression dictionaries.
//!
//! The manifest is the only enumerable record.  Chunks are opaque and become
//! reachable only after a generation-bound manifest CAS succeeds.

use std::{collections::HashMap, time::Duration};

use anyhow::{Context, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::compression_dictionary::{
  fields::{DictionaryHash, UseAsDictionary},
  storage::DictionaryStorage,
};

pub(super) const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
pub(super) const CHUNK_BYTES: usize = 64 * 1024;
const MANIFEST_FORMAT: u8 = 1;
const MAX_CAS_ATTEMPTS: usize = 8;
const PENDING_LEASE_MS: u64 = 5 * 60 * 1000;

#[derive(Clone)]
pub(super) struct Ledger {
  storage: DictionaryStorage,
  manifest_key: String,
  quota_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct LedgerEntry {
  pub profile: String,
  #[serde(default)]
  pub profile_generation: u64,
  pub scope: String,
  pub scope_generation: u64,
  pub hash: DictionaryHash,
  pub url: String,
  pub declaration: UseAsDictionary,
  pub expires_at_ms: u64,
  pub fetched_at: u64,
  pub bytes: u64,
  pub chunks: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct PurgeReport {
  pub entries: usize,
  pub bytes: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct Manifest {
  format: u8,
  generation: u64,
  profile_generations: HashMap<String, u64>,
  scope_generations: HashMap<String, u64>,
  entries: Vec<LedgerEntry>,
  #[serde(default)]
  pending: Vec<PendingPublication>,
  #[serde(default)]
  garbage: Vec<LedgerEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PendingPublication {
  id: String,
  entry: LedgerEntry,
  lease_until_ms: u64,
}

impl Ledger {
  pub(super) fn new(storage: DictionaryStorage, store_name: &str, quota_bytes: u64) -> Self {
    Self {
      storage,
      manifest_key: format!("cdl-manifest-{}", key_digest(store_name.as_bytes())),
      quota_bytes,
    }
  }

  pub(super) async fn entries(&self) -> anyhow::Result<Vec<LedgerEntry>> {
    self.recover().await?;
    Ok(self.read_manifest().await?.1.entries)
  }

  pub(super) async fn generations(&self, profile: &str, scope: &str) -> anyhow::Result<(u64, u64)> {
    self.recover().await?;
    let manifest = self.read_manifest().await?.1;
    Ok((
      manifest.scope_generations.get(scope).copied().unwrap_or(0),
      manifest
        .profile_generations
        .get(profile)
        .copied()
        .unwrap_or(0),
    ))
  }

  pub(super) async fn publish(
    &self,
    profile: &str,
    max_profile_bytes: u64,
    max_profile_entries: usize,
    entry: LedgerEntry,
    bytes: &[u8],
  ) -> anyhow::Result<()> {
    self.recover().await?;
    ensure!(
      entry.bytes == bytes.len() as u64,
      "dictionary byte length is inconsistent"
    );
    ensure!(
      entry.bytes <= max_profile_bytes,
      "dictionary exceeds profile storage limit"
    );
    ensure!(
      entry.profile == profile,
      "dictionary entry profile does not match publication profile"
    );
    let mut entry = entry;
    let mut nonce = [0_u8; 32];
    crate::crypto::random_fill(&mut nonce)
      .map_err(|_| anyhow::anyhow!("dictionary publication randomness unavailable"))?;
    let id = hex_encode(&nonce);
    entry.chunks = planned_chunks(&id, bytes.len());
    self
      .reserve(
        &id,
        entry.clone(),
        profile,
        max_profile_bytes,
        max_profile_entries,
      )
      .await?;
    if let Err(error) = self.write_chunks(&id, &entry, bytes).await {
      self.abandon(&id).await;
      return Err(error);
    }
    if let Err(error) = self.finalize(&id, entry).await {
      self.abandon(&id).await;
      return Err(error);
    }
    self.collect_garbage().await;
    Ok(())
  }

  pub(super) async fn purge(
    &self,
    profile: &str,
    scope: Option<&str>,
    origin: Option<&str>,
    hash: Option<DictionaryHash>,
  ) -> anyhow::Result<PurgeReport> {
    for _ in 0..MAX_CAS_ATTEMPTS {
      let (raw, mut manifest) = self.read_manifest().await?;
      reclaim_expired(&mut manifest, now_ms()?);
      let removed = manifest
        .entries
        .iter()
        .filter(|entry| matches_filter(entry, profile, scope, origin, hash))
        .cloned()
        .collect::<Vec<_>>();
      if let Some(scope) = scope {
        let generation = manifest
          .scope_generations
          .entry(scope.to_owned())
          .or_default();
        *generation = generation.saturating_add(1);
      } else {
        let generation = manifest
          .profile_generations
          .entry(profile.to_owned())
          .or_default();
        *generation = generation.saturating_add(1);
        for entry in &removed {
          let generation = manifest
            .scope_generations
            .entry(entry.scope.clone())
            .or_default();
          *generation = generation.saturating_add(1);
        }
      }
      manifest
        .entries
        .retain(|entry| !matches_filter(entry, profile, scope, origin, hash));
      for entry in &removed {
        manifest.garbage.push(entry.clone());
      }
      let pending = std::mem::take(&mut manifest.pending);
      for value in pending {
        if matches_filter(&value.entry, profile, scope, origin, hash) {
          manifest.garbage.push(value.entry);
        } else {
          manifest.pending.push(value);
        }
      }
      manifest.generation = manifest.generation.saturating_add(1);
      let replacement = encode_manifest(&manifest)?;
      if self
        .storage
        .compare_exchange(&self.manifest_key, raw.as_deref(), &replacement)
        .await?
      {
        self.collect_garbage().await;
        let bytes = removed
          .iter()
          .try_fold(0_u64, |sum, entry| sum.checked_add(entry.bytes))
          .context("dictionary purge byte accounting overflow")?;
        return Ok(PurgeReport {
          entries: removed.len(),
          bytes,
        });
      }
    }
    bail!("dictionary manifest purge conflicted repeatedly")
  }

  async fn reserve(
    &self,
    id: &str,
    entry: LedgerEntry,
    profile: &str,
    max_bytes: u64,
    max_entries: usize,
  ) -> anyhow::Result<()> {
    for _ in 0..MAX_CAS_ATTEMPTS {
      let (raw, mut manifest) = self.read_manifest().await?;
      reclaim_expired(&mut manifest, now_ms()?);
      ensure!(
        entry.scope_generation
          == manifest
            .scope_generations
            .get(&entry.scope)
            .copied()
            .unwrap_or(0),
        "dictionary scope generation changed before reservation"
      );
      ensure!(
        entry.profile_generation
          == manifest
            .profile_generations
            .get(profile)
            .copied()
            .unwrap_or(0),
        "dictionary profile generation changed before reservation"
      );
      ensure!(
        !manifest
          .pending
          .iter()
          .any(|value| value.entry.scope == entry.scope && value.entry.hash == entry.hash),
        "dictionary publication is already pending for this scope and hash"
      );
      enforce_quotas(
        &manifest,
        &entry,
        profile,
        max_bytes,
        max_entries,
        self.quota_bytes,
      )?;
      manifest.pending.push(PendingPublication {
        id: id.to_owned(),
        entry: entry.clone(),
        lease_until_ms: now_ms()?.saturating_add(PENDING_LEASE_MS),
      });
      manifest.generation = manifest.generation.saturating_add(1);
      if self
        .storage
        .compare_exchange(
          &self.manifest_key,
          raw.as_deref(),
          &encode_manifest(&manifest)?,
        )
        .await?
      {
        return Ok(());
      }
    }
    bail!("dictionary manifest reservation conflicted repeatedly")
  }

  async fn finalize(&self, id: &str, entry: LedgerEntry) -> anyhow::Result<()> {
    for _ in 0..MAX_CAS_ATTEMPTS {
      let (raw, mut manifest) = self.read_manifest().await?;
      let pending = manifest
        .pending
        .iter()
        .position(|value| value.id == id)
        .context("dictionary publication lease expired")?;
      ensure!(
        manifest.pending[pending].lease_until_ms > now_ms()?,
        "dictionary publication lease expired"
      );
      ensure!(
        entry.scope_generation
          == manifest
            .scope_generations
            .get(&entry.scope)
            .copied()
            .unwrap_or(0),
        "dictionary scope was purged during publication"
      );
      ensure!(
        entry.profile_generation
          == manifest
            .profile_generations
            .get(&entry.profile)
            .copied()
            .unwrap_or(0),
        "dictionary profile was purged during publication"
      );
      manifest.pending.swap_remove(pending);
      let old = manifest
        .entries
        .iter()
        .filter(|value| value.scope == entry.scope && value.hash == entry.hash)
        .cloned()
        .collect::<Vec<_>>();
      manifest
        .entries
        .retain(|value| !(value.scope == entry.scope && value.hash == entry.hash));
      manifest.garbage.extend(old);
      manifest.entries.push(entry.clone());
      manifest.generation = manifest.generation.saturating_add(1);
      if self
        .storage
        .compare_exchange(
          &self.manifest_key,
          raw.as_deref(),
          &encode_manifest(&manifest)?,
        )
        .await?
      {
        return Ok(());
      }
    }
    bail!("dictionary manifest publication conflicted repeatedly")
  }

  async fn abandon(&self, id: &str) {
    for _ in 0..MAX_CAS_ATTEMPTS {
      let Ok((raw, mut manifest)) = self.read_manifest().await else {
        return;
      };
      let Some(index) = manifest.pending.iter().position(|value| value.id == id) else {
        return;
      };
      let abandoned = manifest.pending.swap_remove(index).entry;
      manifest.garbage.push(abandoned);
      manifest.generation = manifest.generation.saturating_add(1);
      let Ok(replacement) = encode_manifest(&manifest) else {
        return;
      };
      if self
        .storage
        .compare_exchange(&self.manifest_key, raw.as_deref(), &replacement)
        .await
        .unwrap_or(false)
      {
        break;
      }
    }
    self.collect_garbage().await;
  }

  async fn collect_garbage(&self) {
    for _ in 0..MAX_CAS_ATTEMPTS {
      let Ok((raw, manifest)) = self.read_manifest().await else {
        return;
      };
      if manifest.garbage.is_empty() {
        return;
      }
      // Keep the entire reservation charged until every chunk is deleted.
      // All writes are fenced by the manifest that held the pending descriptor,
      // so after its removal no delayed writer can recreate collected chunks.
      let mut deleted = Vec::new();
      for (index, entry) in manifest.garbage.iter().enumerate() {
        if self.delete_chunks(&entry.chunks).await.len() == entry.chunks.len() {
          deleted.push(index);
        }
      }
      if deleted.is_empty() {
        return;
      }
      let Ok((current_raw, mut current)) = self.read_manifest().await else {
        return;
      };
      if current_raw != raw {
        continue;
      }
      current.garbage = current
        .garbage
        .into_iter()
        .enumerate()
        .filter_map(|(index, entry)| (!deleted.contains(&index)).then_some(entry))
        .collect();
      current.generation = current.generation.saturating_add(1);
      let Ok(replacement) = encode_manifest(&current) else {
        return;
      };
      if self
        .storage
        .compare_exchange(&self.manifest_key, current_raw.as_deref(), &replacement)
        .await
        .unwrap_or(false)
      {
        return;
      }
    }
  }

  async fn recover(&self) -> anyhow::Result<()> {
    for _ in 0..MAX_CAS_ATTEMPTS {
      let (raw, mut manifest) = self.read_manifest().await?;
      let before = (manifest.entries.len(), manifest.pending.len());
      reclaim_expired(&mut manifest, now_ms()?);
      if before == (manifest.entries.len(), manifest.pending.len()) {
        break;
      }
      manifest.generation = manifest.generation.saturating_add(1);
      if self
        .storage
        .compare_exchange(
          &self.manifest_key,
          raw.as_deref(),
          &encode_manifest(&manifest)?,
        )
        .await?
      {
        break;
      }
    }
    self.collect_garbage().await;
    Ok(())
  }

  pub(super) async fn read_entry_bytes(&self, entry: &LedgerEntry) -> anyhow::Result<Vec<u8>> {
    ensure!(
      !entry.chunks.is_empty() && entry.bytes > 0,
      "dictionary ledger entry is incomplete"
    );
    let mut bytes = Vec::with_capacity(
      usize::try_from(entry.bytes).context("dictionary size exceeds platform limit")?,
    );
    for key in &entry.chunks {
      let chunk = self
        .storage
        .read(key)
        .await?
        .context("dictionary ledger chunk is absent")?;
      ensure!(
        chunk.len() <= CHUNK_BYTES,
        "dictionary ledger chunk exceeds bound"
      );
      bytes.extend_from_slice(&chunk);
      ensure!(
        bytes.len() <= entry.bytes as usize,
        "dictionary ledger chunks exceed declared length"
      );
    }
    ensure!(
      bytes.len() == entry.bytes as usize,
      "dictionary ledger chunk length mismatch"
    );
    Ok(bytes)
  }

  async fn read_manifest(&self) -> anyhow::Result<(Option<Vec<u8>>, Manifest)> {
    let raw = self.storage.read(&self.manifest_key).await?;
    let manifest = match raw.as_deref() {
      Some(value) => {
        ensure!(
          value.len() <= MAX_MANIFEST_BYTES,
          "dictionary manifest exceeds bound"
        );
        let value: Manifest =
          serde_json::from_slice(value).context("dictionary manifest is invalid")?;
        ensure!(
          value.format == MANIFEST_FORMAT,
          "unsupported dictionary manifest version"
        );
        ensure!(
          serde_json::to_vec(&value)?.len() <= MAX_MANIFEST_BYTES,
          "dictionary manifest exceeds bound"
        );
        value
      }
      None => Manifest {
        format: MANIFEST_FORMAT,
        ..Manifest::default()
      },
    };
    Ok((raw, manifest))
  }

  async fn write_chunks(
    &self,
    id: &str,
    entry: &LedgerEntry,
    bytes: &[u8],
  ) -> anyhow::Result<Vec<String>> {
    ensure!(
      entry.chunks.len() == bytes.len().div_ceil(CHUNK_BYTES),
      "dictionary chunk plan is inconsistent"
    );
    let mut keys = Vec::new();
    for (key, chunk) in entry.chunks.iter().zip(bytes.chunks(CHUNK_BYTES)) {
      let mut written = false;
      for _ in 0..MAX_CAS_ATTEMPTS {
        let (raw, manifest) = self.read_manifest().await?;
        let pending = manifest
          .pending
          .iter()
          .find(|pending| pending.id == id)
          .context("dictionary publication was fenced before chunk write")?;
        ensure!(
          pending.lease_until_ms > now_ms()?,
          "dictionary publication lease expired"
        );
        let expected = raw.context("dictionary reservation manifest is absent")?;
        if self
          .storage
          .write_if_manifest_matches(
            &self.manifest_key,
            &expected,
            key,
            chunk,
            Duration::from_secs(24 * 60 * 60),
          )
          .await?
        {
          written = true;
          break;
        }
      }
      ensure!(written, "dictionary chunk write conflicted repeatedly");
      keys.push(key.clone());
    }
    Ok(keys)
  }

  async fn delete_chunks(&self, keys: &[String]) -> Vec<String> {
    let mut deleted = Vec::new();
    for key in keys {
      if self.storage.delete(key).await.is_ok() {
        deleted.push(key.clone());
      }
    }
    deleted
  }
}

fn enforce_quotas(
  manifest: &Manifest,
  entry: &LedgerEntry,
  profile: &str,
  max_profile_bytes: u64,
  max_profile_entries: usize,
  store_quota_bytes: u64,
) -> anyhow::Result<()> {
  let profile_entries = manifest
    .entries
    .iter()
    .chain(manifest.pending.iter().map(|value| &value.entry))
    .chain(manifest.garbage.iter())
    .filter(|value| value.profile == profile);
  let profile_bytes = profile_entries
    .clone()
    .try_fold(0_u64, |sum, value| sum.checked_add(value.bytes))
    .context("dictionary profile byte accounting overflow")?;
  let profile_count = profile_entries.count();
  let store_bytes = manifest
    .entries
    .iter()
    .chain(manifest.pending.iter().map(|value| &value.entry))
    .chain(manifest.garbage.iter())
    .try_fold(0_u64, |sum, value| sum.checked_add(value.bytes))
    .context("dictionary store byte accounting overflow")?;
  // Replacement needs room for both versions until old chunks are deleted.
  let next_profile_bytes = profile_bytes
    .checked_add(entry.bytes)
    .context("dictionary profile quota overflow")?;
  let next_store_bytes = store_bytes
    .checked_add(entry.bytes)
    .context("dictionary store quota overflow")?;
  let adds_entry = !manifest
    .entries
    .iter()
    .chain(manifest.pending.iter().map(|value| &value.entry))
    .any(|value| value.scope == entry.scope && value.hash == entry.hash);
  ensure!(
    next_profile_bytes <= max_profile_bytes,
    "dictionary profile quota exceeded"
  );
  ensure!(
    !adds_entry || profile_count < max_profile_entries,
    "dictionary profile entry quota exceeded"
  );
  ensure!(
    next_store_bytes <= store_quota_bytes,
    "dictionary store quota exceeded"
  );
  Ok(())
}

fn reclaim_expired(manifest: &mut Manifest, now: u64) {
  let mut retained = Vec::new();
  for pending in std::mem::take(&mut manifest.pending) {
    if pending.lease_until_ms <= now {
      manifest.garbage.push(pending.entry);
    } else {
      retained.push(pending);
    }
  }
  manifest.pending = retained;
  let mut retained = Vec::new();
  for entry in std::mem::take(&mut manifest.entries) {
    if entry.expires_at_ms <= now {
      manifest.garbage.push(entry);
    } else {
      retained.push(entry);
    }
  }
  manifest.entries = retained;
}

fn planned_chunks(id: &str, bytes: usize) -> Vec<String> {
  (0..bytes.div_ceil(CHUNK_BYTES))
    .map(|index| format!("cdl-chunk-{}-{}", id, index))
    .collect()
}

fn now_ms() -> anyhow::Result<u64> {
  Ok(u64::try_from(
    std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .context("system clock predates epoch")?
      .as_millis(),
  )?)
}

fn encode_manifest(value: &Manifest) -> anyhow::Result<Vec<u8>> {
  let bytes = serde_json::to_vec(value)?;
  ensure!(
    bytes.len() <= MAX_MANIFEST_BYTES,
    "dictionary manifest exceeds bound"
  );
  Ok(bytes)
}

fn matches_filter(
  entry: &LedgerEntry,
  profile: &str,
  scope: Option<&str>,
  origin: Option<&str>,
  hash: Option<DictionaryHash>,
) -> bool {
  entry.profile == profile
    && scope.is_none_or(|value| value == entry.scope)
    && hash.is_none_or(|value| value == entry.hash)
    && origin.is_none_or(|value| {
      url::Url::parse(&entry.url)
        .ok()
        .map(|url| url.origin().ascii_serialization() == value)
        .unwrap_or(false)
    })
}

pub(super) fn key_digest(value: &[u8]) -> String {
  use sha2::{Digest as _, Sha256};
  hex_encode(&Sha256::digest(value))
}

fn hex_encode(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut output = String::with_capacity(bytes.len().saturating_mul(2));
  for byte in bytes {
    output.push(HEX[(byte >> 4) as usize] as char);
    output.push(HEX[(byte & 0x0f) as usize] as char);
  }
  output
}

#[cfg(test)]
#[path = "runtime/ledger_tests.rs"]
mod tests;

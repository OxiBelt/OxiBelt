//! Disk-backed streaming cache fills for large cacheable responses.

use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::warn;

use crate::config::CacheStore;

use super::{
  CacheFileKind, CacheFillGuard, CacheInsertOutcome, CachePreparedInsert, PreparedBodyAdmission,
  ResponseCache, StoredBody, StoredEntry, add_size, admit_prepared_body, cache_file_path,
  detach_entry, extract_tags, index_entry, remove_entry, remove_replaced_entry_files, select_store,
  shared_cache_entry_metadata, total_size, variant_count_exceeded,
};

const STREAMING_FILL_CHANNEL_CAPACITY: usize = 64;

#[derive(Debug)]
pub(crate) enum CacheStreamingInsertDecision {
  Started(CacheStreamingInsert),
  NotEligible,
  Rejected(CacheInsertOutcome),
}

#[derive(Debug)]
pub(crate) struct CacheStreamingInsert {
  sender: Option<mpsc::Sender<CacheStreamingMessage>>,
}

#[derive(Debug)]
enum CacheStreamingMessage {
  Data(Bytes),
  Finish,
}

#[derive(Debug)]
struct StreamingDiskReservation {
  cache: Arc<ResponseCache>,
  size: usize,
  active: bool,
}

impl StreamingDiskReservation {
  fn new(cache: Arc<ResponseCache>, size: usize) -> Self {
    Self {
      cache,
      size,
      active: true,
    }
  }

  fn release_locked(&mut self, inner: &mut super::CacheInner) {
    if !self.active {
      return;
    }
    inner.disk_inflight_size = inner.disk_inflight_size.saturating_sub(self.size);
    self.active = false;
  }
}

impl Drop for StreamingDiskReservation {
  fn drop(&mut self) {
    if self.active {
      self.cache.release_streaming_disk_size(self.size);
      self.active = false;
    }
  }
}

impl CacheStreamingInsert {
  fn new(sender: mpsc::Sender<CacheStreamingMessage>) -> Self {
    Self {
      sender: Some(sender),
    }
  }

  pub(crate) fn write_data(&mut self, bytes: Bytes) -> bool {
    let Some(sender) = &self.sender else {
      return false;
    };
    if sender.try_send(CacheStreamingMessage::Data(bytes)).is_ok() {
      return true;
    }
    self.sender = None;
    false
  }

  pub(crate) fn finish(&mut self) {
    let Some(sender) = self.sender.take() else {
      return;
    };
    let _ = sender.try_send(CacheStreamingMessage::Finish);
  }
}

impl Drop for CacheStreamingInsert {
  fn drop(&mut self) {
    self.sender = None;
  }
}

impl ResponseCache {
  pub(crate) fn begin_streaming_insert(
    self: &Arc<Self>,
    prepared: CachePreparedInsert,
    body_len: usize,
    fill_guard: Option<CacheFillGuard>,
  ) -> CacheStreamingInsertDecision {
    if !self.config.stream_large_objects {
      return CacheStreamingInsertDecision::NotEligible;
    }
    let Some(size) = body_len.checked_add(prepared.header_bytes) else {
      return CacheStreamingInsertDecision::Rejected(CacheInsertOutcome::Rejected);
    };
    if size > self.config.max_size_bytes
      || self
        .config
        .disk_max_size_bytes
        .is_some_and(|limit| size > limit)
      || prepared
        .policy
        .disk_max_size_bytes
        .is_some_and(|limit| size > limit)
    {
      return CacheStreamingInsertDecision::NotEligible;
    }
    if !matches!(
      select_store(&prepared.policy, &prepared.stored_headers),
      CacheStore::Disk | CacheStore::MemoryThenDisk
    ) {
      return CacheStreamingInsertDecision::NotEligible;
    }
    let Some(dir) = self.disk_dir.clone() else {
      return CacheStreamingInsertDecision::Rejected(CacheInsertOutcome::StoreFailed);
    };
    let Some(body_path) = cache_file_path(&dir, &prepared.variant_key, CacheFileKind::Body) else {
      return CacheStreamingInsertDecision::Rejected(CacheInsertOutcome::StoreFailed);
    };
    let Some(tmp_path) = cache_file_path(&dir, &prepared.variant_key, CacheFileKind::BodyTmp)
    else {
      return CacheStreamingInsertDecision::Rejected(CacheInsertOutcome::StoreFailed);
    };
    {
      let mut inner = self.inner_guard();
      if variant_count_exceeded(
        &inner,
        &prepared.policy,
        &prepared.partition,
        &prepared.base_key,
        &prepared.variant_key,
      ) {
        return CacheStreamingInsertDecision::Rejected(CacheInsertOutcome::Rejected);
      }
      match admit_prepared_body(
        &mut inner,
        &prepared.policy,
        &prepared.variant_key,
        body_len,
      ) {
        PreparedBodyAdmission::Admitted => {}
        PreparedBodyAdmission::Warming => {
          return CacheStreamingInsertDecision::Rejected(CacheInsertOutcome::AdmissionWarming);
        }
        PreparedBodyAdmission::Rejected => {
          return CacheStreamingInsertDecision::Rejected(CacheInsertOutcome::Rejected);
        }
      }
    }
    if !self.reserve_streaming_disk_size(&prepared.policy, size) {
      return CacheStreamingInsertDecision::Rejected(CacheInsertOutcome::Rejected);
    }

    let (sender, receiver) = mpsc::channel(STREAMING_FILL_CHANNEL_CAPACITY);
    let cache = Arc::clone(self);
    let reservation = StreamingDiskReservation::new(Arc::clone(self), size);
    tokio::spawn(async move {
      let _fill_guard = fill_guard;
      cache
        .stream_body_to_disk(
          prepared,
          tmp_path,
          body_path,
          body_len,
          receiver,
          reservation,
        )
        .await;
    });
    CacheStreamingInsertDecision::Started(CacheStreamingInsert::new(sender))
  }

  fn reserve_streaming_disk_size(&self, policy: &super::CachePolicyRuntime, size: usize) -> bool {
    let mut inner = self.inner_guard();
    while !self.streaming_disk_reservation_fits(&inner, policy, size) {
      let Some(oldest) = inner.order.pop_front() else {
        break;
      };
      remove_entry(&mut inner, &oldest);
    }
    if !self.streaming_disk_reservation_fits(&inner, policy, size) {
      return false;
    }
    inner.disk_inflight_size = inner.disk_inflight_size.saturating_add(size);
    true
  }

  fn streaming_disk_reservation_fits(
    &self,
    inner: &super::CacheInner,
    policy: &super::CachePolicyRuntime,
    size: usize,
  ) -> bool {
    let Some(projected_disk_size) = inner
      .disk_size
      .checked_add(inner.disk_inflight_size)
      .and_then(|value| value.checked_add(size))
    else {
      return false;
    };
    if self
      .config
      .disk_max_size_bytes
      .is_some_and(|limit| projected_disk_size > limit)
      || policy
        .disk_max_size_bytes
        .is_some_and(|limit| projected_disk_size > limit)
    {
      return false;
    }
    let Some(projected_total_size) = total_size(inner)
      .checked_add(inner.disk_inflight_size)
      .and_then(|value| value.checked_add(size))
    else {
      return false;
    };
    projected_total_size <= self.config.max_size_bytes
  }

  fn release_streaming_disk_size(&self, size: usize) {
    let mut inner = self.inner_guard();
    inner.disk_inflight_size = inner.disk_inflight_size.saturating_sub(size);
  }

  async fn stream_body_to_disk(
    self: Arc<Self>,
    prepared: CachePreparedInsert,
    tmp_path: PathBuf,
    body_path: PathBuf,
    expected_body_len: usize,
    mut receiver: mpsc::Receiver<CacheStreamingMessage>,
    reservation: StreamingDiskReservation,
  ) {
    let mut file = match tokio::fs::File::create(&tmp_path).await {
      Ok(file) => file,
      Err(error) => {
        warn!(error = %error, path = %tmp_path.display(), "failed to create streaming cache file");
        return;
      }
    };
    let mut body_len = 0_usize;
    let mut finished = false;
    while let Some(message) = receiver.recv().await {
      match message {
        CacheStreamingMessage::Data(bytes) => {
          let Some(next_len) = body_len.checked_add(bytes.len()) else {
            remove_streaming_body(&tmp_path);
            return;
          };
          if next_len > expected_body_len {
            remove_streaming_body(&tmp_path);
            return;
          }
          if file.write_all(&bytes).await.is_err() {
            remove_streaming_body(&tmp_path);
            return;
          }
          body_len = next_len;
        }
        CacheStreamingMessage::Finish => {
          finished = true;
          break;
        }
      }
    }
    if !finished || body_len != expected_body_len {
      remove_streaming_body(&tmp_path);
      return;
    }
    if file.flush().await.is_err() {
      remove_streaming_body(&tmp_path);
      return;
    }
    drop(file);
    if tokio::fs::rename(&tmp_path, &body_path).await.is_err() {
      remove_streaming_body(&tmp_path);
      remove_streaming_body(&body_path);
      return;
    }
    if !matches!(
      self
        .insert_streamed_disk_file(prepared, body_path.clone(), body_len, reservation)
        .await,
      CacheInsertOutcome::Stored
    ) {
      remove_streaming_body(&body_path);
    }
  }

  async fn insert_streamed_disk_file(
    &self,
    prepared: CachePreparedInsert,
    body_path: PathBuf,
    body_len: usize,
    mut reservation: StreamingDiskReservation,
  ) -> CacheInsertOutcome {
    let size = match body_len.checked_add(prepared.header_bytes) {
      Some(size) if size <= self.config.max_size_bytes => size,
      _ => return CacheInsertOutcome::Rejected,
    };
    if self
      .config
      .disk_max_size_bytes
      .is_some_and(|limit| size > limit)
      || prepared
        .policy
        .disk_max_size_bytes
        .is_some_and(|limit| size > limit)
    {
      return CacheInsertOutcome::Rejected;
    }
    let variant_key = prepared.variant_key.clone();
    let tags = extract_tags(&prepared.stored_headers, &prepared.policy);
    let stored = StoredEntry {
      policy: prepared.policy.name.clone(),
      partition: prepared.partition,
      base_key: prepared.base_key,
      variant_key: variant_key.clone(),
      scheme: prepared.scheme,
      host: prepared.host,
      uri: prepared.uri,
      status: prepared.status,
      headers: prepared.stored_headers,
      security_headers_neutral: true,
      body: StoredBody::Disk(body_path.clone()),
      expires_at: prepared.metadata.expires_at,
      stale_if_error_until: prepared.metadata.stale_if_error_until,
      stale_while_revalidate_until: prepared.metadata.stale_while_revalidate_until,
      must_revalidate: prepared.metadata.must_revalidate,
      stored_at: prepared.metadata.stored_at,
      vary: prepared.metadata.vary,
      tags,
      size,
    };
    let (shared_entry, external_entry) = {
      let mut inner = self.inner_guard();
      if variant_count_exceeded(
        &inner,
        &prepared.policy,
        &stored.partition,
        &stored.base_key,
        &variant_key,
      ) {
        reservation.release_locked(&mut inner);
        return CacheInsertOutcome::Rejected;
      }
      if let Err(error) = self.persist_metadata(&stored) {
        warn!(error = %error, "failed to persist streaming cache metadata");
        reservation.release_locked(&mut inner);
        stored.remove_body_files();
        return CacheInsertOutcome::StoreFailed;
      }
      if let Some(existing) = detach_entry(&mut inner, &variant_key) {
        remove_replaced_entry_files(existing, &stored);
      }
      reservation.release_locked(&mut inner);
      add_size(&mut inner, &stored);
      inner.order.push_back(variant_key.clone());
      index_entry(&mut inner, &stored);
      let shared_entry = self
        .shared_state
        .as_ref()
        .filter(|shared| shared.has_cache())
        .map(|_| shared_cache_entry_metadata(&stored, body_len));
      let external_entry = self.external_entry_for_stored(&stored);
      inner.entries.insert(variant_key, stored);
      self.evict_if_needed(&mut inner, &prepared.policy);
      (shared_entry, external_entry)
    };
    if let Some(shared) = &self.shared_state
      && shared.has_cache()
      && let Some(shared_entry) = shared_entry
      && let Err(error) = shared
        .cache_put_file(&shared_entry, &body_path, body_len)
        .await
    {
      warn!(error = %error, "failed to write streaming cache entry to shared cache");
    }
    if let Some((handler, metadata, body)) = external_entry {
      self.spawn_external_fill(handler, metadata, body);
    }
    CacheInsertOutcome::Stored
  }
}

fn remove_streaming_body(path: &PathBuf) {
  let _ = std::fs::remove_file(path);
}

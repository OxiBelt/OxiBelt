use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

use anyhow::{Context, bail};
use bytes::Bytes;
use futures_util::StreamExt;
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::Mutex;

use super::{
  AppendReservation, DispatchClaim, DispatchTerminal, InspectedPart, UploadByteStream,
  UploadCreate, UploadObject, UploadOwner, UploadRejection, UploadRequestMetadata, UploadState,
  UploadStatus, is_sha256_hex,
};
use crate::config::{UploadDestinationConfig, UploadStoreConfig, UploadStoreKind};

const STATE_FILE: &str = "journal/upload-state-v1.json";
const LOCK_FILE: &str = ".oxibelt-upload-store.lock";
const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;
const RESERVATION_LEASE_MS: u64 = 60_000;
const STREAM_BUFFER_BYTES: usize = 64 * 1024;
const STARTUP_STAGING_CLEANUP_LIMIT: usize = 1_024;

pub struct LocalUploadStore {
  root: PathBuf,
  instance_id: String,
  _lock: Flock<std::fs::File>,
  state: Arc<Mutex<LocalState>>,
  assembly: Mutex<()>,
  poisoned: AtomicBool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct LocalState {
  schema_version: u32,
  uploads: BTreeMap<String, LocalUpload>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LocalUpload {
  profile: StoredProfile,
  owner: UploadOwner,
  binding: serde_json::Value,
  method: String,
  uri: String,
  safe_headers: serde_json::Value,
  offset: u64,
  declared_total: Option<u64>,
  expires_at_ms: u64,
  state: UploadState,
  parts: Vec<LocalPart>,
  reservation: Option<LocalReservation>,
  #[serde(default)]
  dispatch_expires_at_ms: Option<u64>,
  object: Option<UploadObject>,
  epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredProfile {
  name: String,
  destination: UploadDestinationConfig,
  max_upload_bytes: u64,
  max_part_bytes: u64,
  max_storage_bytes: u64,
  max_sessions: u32,
  max_parts: u32,
  max_concurrent_parts: u32,
  ttl_seconds: u64,
  object_ttl_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LocalPart {
  key: String,
  offset: u64,
  bytes: u64,
  sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LocalReservation {
  token: String,
  expected_offset: u64,
  bytes: u64,
  epoch: u64,
  expires_at_ms: u64,
}

#[derive(Debug)]
struct UncertainStatePublication(std::io::Error);

impl std::fmt::Display for UncertainStatePublication {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      formatter,
      "managed upload journal publication could not be made durable: {}",
      self.0
    )
  }
}

impl std::error::Error for UncertainStatePublication {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.0)
  }
}

impl LocalUploadStore {
  pub async fn open(config: &UploadStoreConfig) -> anyhow::Result<Self> {
    if config.kind != UploadStoreKind::Local {
      bail!("local upload store opened with a non-local configuration");
    }
    let root = config
      .local
      .as_ref()
      .ok_or_else(|| anyhow::anyhow!("local upload root is missing"))?
      .root
      .clone();
    if root.parent().is_none()
      || root.components().any(|component| {
        matches!(
          component,
          std::path::Component::CurDir | std::path::Component::ParentDir
        )
      })
    {
      bail!("managed upload local root must be a dedicated path without dot segments");
    }
    let root_for_create = root.clone();
    let (lock, state) = tokio::task::spawn_blocking(move || open_state(&root_for_create)).await??;
    Ok(Self {
      root,
      instance_id: random_id()?,
      _lock: lock,
      state: Arc::new(Mutex::new(state)),
      assembly: Mutex::new(()),
      poisoned: AtomicBool::new(false),
    })
  }

  pub async fn create(&self, request: UploadCreate) -> anyhow::Result<UploadStatus> {
    self.ensure_healthy()?;
    if request.profile.max_upload_bytes == 0
      || request
        .declared_total
        .is_some_and(|value| value > request.profile.max_upload_bytes)
    {
      return Err(UploadRejection::Conflict.into());
    }
    let now = now_ms()?;
    let expires_at_ms = now
      .checked_add(request.profile.ttl_seconds.saturating_mul(1000))
      .ok_or_else(|| anyhow::anyhow!("managed upload expiry overflow"))?;
    let mut state = self.state.lock().await;
    let mut next = state.clone();
    reap_expired_reservations(&mut next, now)?;
    let retained_sessions = next
      .uploads
      .values()
      .filter(|upload| upload.profile.name == request.profile.name)
      .count();
    if retained_sessions >= usize::try_from(request.profile.max_sessions).unwrap_or(usize::MAX) {
      return Err(UploadRejection::Capacity.into());
    }
    let id = unique_id(&next)?;
    let upload = LocalUpload {
      profile: StoredProfile::from_profile(&request.profile),
      owner: request.owner,
      binding: request.binding,
      method: request.method.as_str().to_string(),
      uri: request.uri.to_string(),
      safe_headers: request.safe_headers,
      offset: 0,
      declared_total: request.declared_total,
      expires_at_ms,
      state: UploadState::Active,
      parts: Vec::new(),
      reservation: None,
      dispatch_expires_at_ms: None,
      object: None,
      epoch: 1,
    };
    let status = status(&id, &upload);
    next.uploads.insert(id, upload);
    self.commit_locked(&mut state, next)?;
    Ok(status)
  }

  pub async fn lookup(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
  ) -> anyhow::Result<UploadStatus> {
    self.ensure_healthy()?;
    let mut state = self.state.lock().await;
    let mut next = state.clone();
    let mut changed = expire_dispatches(&mut next, now_ms()?)?;
    let upload = checked_mut(&mut next, id, owner, binding)?;
    if upload.reservation.take().is_some() {
      upload.epoch = upload
        .epoch
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("managed upload fence epoch overflow"))?;
      changed = true;
    }
    if changed {
      self.commit_locked(&mut state, next)?;
    }
    Ok(status(id, checked(&state, id, owner, binding)?))
  }

  pub async fn declare_length(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
    total: u64,
  ) -> anyhow::Result<UploadStatus> {
    self.ensure_healthy()?;
    let mut state = self.state.lock().await;
    let mut next = state.clone();
    let upload = checked_mut(&mut next, id, owner, binding)?;
    if upload.state != UploadState::Active
      || upload.reservation.is_some()
      || total < upload.offset
      || total > upload.profile.max_upload_bytes
    {
      return Err(UploadRejection::Conflict.into());
    }
    match upload.declared_total {
      Some(existing) if existing != total => return Err(UploadRejection::Conflict.into()),
      Some(_) => {}
      None => upload.declared_total = Some(total),
    }
    let result = status(id, upload);
    self.commit_locked(&mut state, next)?;
    Ok(result)
  }

  pub async fn begin_append(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
    expected_offset: u64,
    length: u64,
  ) -> anyhow::Result<AppendReservation> {
    self.ensure_healthy()?;
    let now = now_ms()?;
    let mut state = self.state.lock().await;
    let mut next = state.clone();
    reap_expired_reservations(&mut next, now)?;
    let (profile_name, max_concurrent_parts, max_storage_bytes) = {
      let upload = checked(&next, id, owner, binding)?;
      ensure_appendable(upload, now, expected_offset, length)?;
      (
        upload.profile.name.clone(),
        upload.profile.max_concurrent_parts,
        upload.profile.max_storage_bytes,
      )
    };
    let concurrent = next
      .uploads
      .values()
      .filter(|item| item.profile.name == profile_name && item.reservation.is_some())
      .count();
    if concurrent >= usize::try_from(max_concurrent_parts).unwrap_or(usize::MAX) {
      return Err(UploadRejection::Capacity.into());
    }
    if profile_usage(&next, &profile_name).saturating_add(length) > max_storage_bytes {
      return Err(UploadRejection::Capacity.into());
    }
    let upload = checked_mut(&mut next, id, owner, binding)?;
    let token = random_id()?;
    let expires_at_ms = now
      .saturating_add(RESERVATION_LEASE_MS)
      .min(upload.expires_at_ms);
    upload.reservation = Some(LocalReservation {
      token: token.clone(),
      expected_offset,
      bytes: length,
      epoch: upload.epoch,
      expires_at_ms,
    });
    let result = AppendReservation {
      id: id.to_string(),
      expected_offset,
      length,
      fence_epoch: upload.epoch,
      backend_token: token,
    };
    self.commit_locked(&mut state, next)?;
    Ok(result)
  }

  pub async fn commit_fully_inspected_part(
    &self,
    reservation: &AppendReservation,
    inspected: &InspectedPart,
    mut body: UploadByteStream,
  ) -> anyhow::Result<UploadStatus> {
    self.ensure_healthy()?;
    if inspected.bytes == 0
      || inspected.bytes > reservation.length
      || !is_sha256_hex(&inspected.sha256)
    {
      return Err(UploadRejection::Conflict.into());
    }
    {
      let state = self.state.lock().await;
      let upload = state
        .uploads
        .get(&reservation.id)
        .ok_or(UploadRejection::NotFound)?;
      check_reservation(upload, reservation, now_ms()?)?;
    }
    let temporary_path =
      self
        .root
        .join("staging")
        .join(format!("{}-{}.part", self.instance_id, random_id()?));
    let final_key = format!(
      "chunks/{}/{}-{}",
      reservation.id,
      reservation.expected_offset,
      random_id()?
    );
    let final_path = self.root.join(&final_key);
    let parent = final_path
      .parent()
      .ok_or_else(|| anyhow::anyhow!("managed upload chunk has no parent"))?
      .to_path_buf();
    ensure_private_directory(&parent)?;
    let (mut file, mut temporary) = create_private_temporary(temporary_path).await?;
    let staged = async {
      let mut digest = Sha256::new();
      let mut written = 0_u64;
      while let Some(frame) = body.next().await {
        let bytes = frame?;
        written = written
          .checked_add(u64::try_from(bytes.len()).context("managed upload chunk length overflow")?)
          .ok_or_else(|| anyhow::anyhow!("managed upload chunk length overflow"))?;
        if written > reservation.length {
          bail!("managed upload body exceeds its reservation");
        }
        digest.update(&bytes);
        tokio::io::AsyncWriteExt::write_all(&mut file, &bytes).await?;
      }
      tokio::io::AsyncWriteExt::flush(&mut file).await?;
      file.sync_all().await?;
      drop(file);
      Ok::<_, anyhow::Error>((written, hex_digest(digest.finalize())))
    }
    .await;
    let (written, actual) = match staged {
      Ok(staged) => staged,
      Err(error) => {
        return Err(error);
      }
    };
    if written != inspected.bytes || actual != inspected.sha256 {
      return Err(UploadRejection::Conflict.into());
    }
    let _filesystem = self.assembly.lock().await;
    ensure_private_directory(&parent)?;
    let mut final_cleanup = rename_with_cleanup(temporary.path().to_path_buf(), final_path).await?;
    temporary.disarm();
    sync_directory(&parent).await?;

    let now = now_ms()?;
    let mut state = self.state.lock().await;
    let mut next = state.clone();
    let update = (|| {
      let upload = next
        .uploads
        .get_mut(&reservation.id)
        .ok_or(UploadRejection::NotFound)?;
      check_reservation(upload, reservation, now)?;
      upload.parts.push(LocalPart {
        key: final_key,
        offset: reservation.expected_offset,
        bytes: written,
        sha256: actual,
      });
      upload.offset = upload
        .offset
        .checked_add(written)
        .ok_or_else(|| anyhow::anyhow!("managed upload offset overflow"))?;
      upload.reservation = None;
      upload.epoch = upload
        .epoch
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("managed upload fence epoch overflow"))?;
      Ok::<_, anyhow::Error>(status(&reservation.id, upload))
    })();
    match update {
      Ok(result) => {
        if let Err(error) = self.commit_locked(&mut state, next) {
          if is_uncertain_publication(&error) {
            final_cleanup.disarm();
          }
          return Err(error);
        }
        final_cleanup.disarm();
        Ok(result)
      }
      Err(error) => {
        drop(state);
        Err(error)
      }
    }
  }

  pub async fn claim_complete(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
    expected_offset: u64,
  ) -> anyhow::Result<UploadStatus> {
    self.ensure_healthy()?;
    let mut state = self.state.lock().await;
    let mut next = state.clone();
    reap_expired_reservations(&mut next, now_ms()?)?;
    let upload = checked_mut(&mut next, id, owner, binding)?;
    if upload.state == UploadState::Completing
      && upload.reservation.is_none()
      && upload.offset == expected_offset
      && upload
        .declared_total
        .is_none_or(|total| total == expected_offset)
    {
      return Ok(status(id, upload));
    }
    if upload.state != UploadState::Active
      || upload.reservation.is_some()
      || upload.offset != expected_offset
      || upload
        .declared_total
        .is_some_and(|total| total != expected_offset)
    {
      return Err(UploadRejection::Conflict.into());
    }
    let profile = upload.profile.name.clone();
    let assembly_bytes = upload.offset;
    let max_storage_bytes = upload.profile.max_storage_bytes;
    if profile_usage(&next, &profile).saturating_add(assembly_bytes) > max_storage_bytes {
      return Err(UploadRejection::Capacity.into());
    }
    let upload = checked_mut(&mut next, id, owner, binding)?;
    upload.state = UploadState::Completing;
    upload.epoch = upload
      .epoch
      .checked_add(1)
      .ok_or_else(|| anyhow::anyhow!("managed upload fence epoch overflow"))?;
    let result = status(id, upload);
    self.commit_locked(&mut state, next)?;
    Ok(result)
  }

  pub async fn abort_append(&self, reservation: &AppendReservation) -> anyhow::Result<()> {
    self.ensure_healthy()?;
    let mut state = self.state.lock().await;
    let mut next = state.clone();
    let upload = next
      .uploads
      .get_mut(&reservation.id)
      .ok_or(UploadRejection::NotFound)?;
    if matches!(upload.reservation.as_ref(), Some(value) if value.token == reservation.backend_token() && value.epoch == reservation.fence_epoch)
    {
      upload.reservation = None;
      upload.epoch = upload
        .epoch
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("managed upload fence epoch overflow"))?;
      self.commit_locked(&mut state, next)?;
    }
    Ok(())
  }

  pub async fn request_metadata(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
  ) -> anyhow::Result<UploadRequestMetadata> {
    self.ensure_healthy()?;
    let state = self.state.lock().await;
    let upload = checked(&state, id, owner, binding)?;
    Ok(UploadRequestMetadata {
      method: upload.method.parse()?,
      uri: upload.uri.parse()?,
      safe_headers: upload.safe_headers.clone(),
    })
  }

  pub async fn read_object(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
  ) -> anyhow::Result<UploadByteStream> {
    self.ensure_healthy()?;
    let (path, expected_bytes, expected_digest) = {
      let state = self.state.lock().await;
      let upload = checked(&state, id, owner, binding)?;
      let object = upload.object.as_ref().ok_or(UploadRejection::Conflict)?;
      (
        self.root.join(&object.key),
        object.bytes,
        object.sha256.clone(),
      )
    };
    verified_file_stream(path, expected_bytes, expected_digest).await
  }

  pub async fn read_assembled(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
  ) -> anyhow::Result<UploadByteStream> {
    self.ensure_healthy()?;
    let state = self.state.lock().await;
    let upload = checked(&state, id, owner, binding)?;
    if !matches!(
      upload.state,
      UploadState::Active | UploadState::Completing | UploadState::Ready
    ) {
      return Err(UploadRejection::Conflict.into());
    }
    let mut expected_offset = 0_u64;
    let mut parts = Vec::with_capacity(upload.parts.len());
    for part in &upload.parts {
      if part.offset != expected_offset || part.bytes == 0 {
        bail!("managed upload durable chunk sequence is not contiguous");
      }
      expected_offset = expected_offset
        .checked_add(part.bytes)
        .ok_or_else(|| anyhow::anyhow!("managed upload assembled length overflow"))?;
      parts.push((self.root.join(&part.key), part.bytes, part.sha256.clone()));
    }
    if expected_offset != upload.offset {
      bail!("managed upload durable offset does not match its chunks");
    }
    drop(state);
    let stream = futures_util::stream::try_unfold(
      (
        parts,
        0_usize,
        None::<tokio::fs::File>,
        None::<Sha256>,
        0_u64,
      ),
      |(parts, mut index, mut file, mut digest, mut part_bytes)| async move {
        loop {
          if file.is_none() {
            if index == parts.len() {
              return Ok(None);
            }
            file = Some(tokio::fs::File::open(&parts[index].0).await?);
            digest = Some(Sha256::new());
            part_bytes = 0;
          }
          let mut buffer = vec![0_u8; STREAM_BUFFER_BYTES];
          let read = tokio::io::AsyncReadExt::read(
            file
              .as_mut()
              .ok_or_else(|| anyhow::anyhow!("managed upload reader disappeared"))?,
            &mut buffer,
          )
          .await?;
          if read != 0 {
            buffer.truncate(read);
            part_bytes = part_bytes
              .checked_add(u64::try_from(read)?)
              .ok_or_else(|| anyhow::anyhow!("managed upload chunk length overflow"))?;
            if part_bytes > parts[index].1 {
              bail!("managed upload stored chunk length mismatch");
            }
            digest
              .as_mut()
              .ok_or_else(|| anyhow::anyhow!("managed upload digest disappeared"))?
              .update(&buffer);
            return Ok(Some((
              Bytes::from(buffer),
              (parts, index, file, digest, part_bytes),
            )));
          }
          let actual = hex_digest(
            digest
              .take()
              .ok_or_else(|| anyhow::anyhow!("managed upload digest disappeared"))?
              .finalize(),
          );
          if part_bytes != parts[index].1 || actual != parts[index].2 {
            bail!("managed upload stored chunk digest mismatch");
          }
          index += 1;
          file = None;
        }
      },
    );
    Ok(Box::pin(stream))
  }

  pub async fn publish_object(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
  ) -> anyhow::Result<UploadStatus> {
    self.ensure_healthy()?;
    // A completion reserves one additional object-sized copy. Serialize local
    // assembly so concurrent retries cannot each consume that single reserve.
    let _assembly = self.assembly.lock().await;
    let (parts, object_key, claimed_epoch, destination) = {
      let state = self.state.lock().await;
      let upload = checked(&state, id, owner, binding)?;
      if upload.state != UploadState::Completing {
        return Err(UploadRejection::Conflict.into());
      }
      let mut parts = Vec::with_capacity(upload.parts.len());
      let mut expected_offset = 0_u64;
      for part in &upload.parts {
        if part.offset != expected_offset || part.bytes == 0 {
          bail!("managed upload durable chunk sequence is not contiguous");
        }
        expected_offset = expected_offset
          .checked_add(part.bytes)
          .ok_or_else(|| anyhow::anyhow!("managed upload object length overflow"))?;
        parts.push((part.key.clone(), part.bytes, part.sha256.clone()));
      }
      if expected_offset != upload.offset {
        bail!("managed upload durable offset does not match its chunks");
      }
      (
        parts,
        format!("objects/{id}/{}", random_id()?),
        upload.epoch,
        upload.profile.destination.clone(),
      )
    };
    let temporary_path =
      self
        .root
        .join("staging")
        .join(format!("{}-{}.object", self.instance_id, random_id()?));
    let object_path = self.root.join(&object_key);
    let parent = object_path
      .parent()
      .ok_or_else(|| anyhow::anyhow!("managed upload object has no parent"))?
      .to_path_buf();
    ensure_private_directory(&parent)?;
    let (mut target, mut temporary) = create_private_temporary(temporary_path).await?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    for (key, expected_bytes, expected_digest) in parts {
      let mut source = tokio::fs::File::open(self.root.join(key)).await?;
      let mut part_digest = Sha256::new();
      let mut part_bytes = 0_u64;
      let mut buffer = vec![0_u8; STREAM_BUFFER_BYTES];
      loop {
        let read = tokio::io::AsyncReadExt::read(&mut source, &mut buffer).await?;
        if read == 0 {
          break;
        }
        let bytes = &buffer[..read];
        part_bytes = part_bytes
          .checked_add(u64::try_from(read)?)
          .ok_or_else(|| anyhow::anyhow!("managed upload chunk length overflow"))?;
        if part_bytes > expected_bytes {
          bail!("managed upload chunk changed before object publication");
        }
        part_digest.update(bytes);
        digest.update(bytes);
        tokio::io::AsyncWriteExt::write_all(&mut target, bytes).await?;
      }
      if part_bytes != expected_bytes || hex_digest(part_digest.finalize()) != expected_digest {
        bail!("managed upload chunk changed before object publication");
      }
      total = total
        .checked_add(part_bytes)
        .ok_or_else(|| anyhow::anyhow!("managed upload object length overflow"))?;
    }
    target.sync_all().await?;
    drop(target);
    let mut object_cleanup =
      rename_with_cleanup(temporary.path().to_path_buf(), object_path).await?;
    temporary.disarm();
    sync_directory(&parent).await?;
    let object = UploadObject {
      key: object_key,
      sha256: hex_digest(digest.finalize()),
      bytes: total,
      version: None,
    };
    let now = now_ms()?;
    let mut state = self.state.lock().await;
    let mut next = state.clone();
    let update = (|| {
      let upload = checked_mut(&mut next, id, owner, binding)?;
      if upload.state != UploadState::Completing || upload.epoch != claimed_epoch {
        return Err(UploadRejection::Conflict.into());
      }
      upload.object = Some(object);
      upload.state = match destination {
        UploadDestinationConfig::Object => UploadState::Complete,
        UploadDestinationConfig::Upstream { .. } => UploadState::Ready,
      };
      upload.expires_at_ms = retention_expiry(now, upload.profile.object_ttl_seconds)?;
      upload.epoch = upload
        .epoch
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("managed upload fence epoch overflow"))?;
      Ok::<_, anyhow::Error>(status(id, upload))
    })();
    match update {
      Ok(result) => {
        if let Err(error) = self.commit_locked(&mut state, next) {
          if is_uncertain_publication(&error) {
            object_cleanup.disarm();
          }
          return Err(error);
        }
        object_cleanup.disarm();
        Ok(result)
      }
      Err(error) => {
        drop(state);
        Err(error)
      }
    }
  }

  pub async fn begin_dispatch(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
  ) -> anyhow::Result<DispatchClaim> {
    self.ensure_healthy()?;
    let mut state = self.state.lock().await;
    let mut next = state.clone();
    let upload = checked_mut(&mut next, id, owner, binding)?;
    if upload.state != UploadState::Ready {
      return Err(UploadRejection::Conflict.into());
    }
    let _ = upload.object.as_ref().ok_or(UploadRejection::Conflict)?;
    upload.state = UploadState::Dispatching;
    upload.dispatch_expires_at_ms = Some(now_ms()?.saturating_add(RESERVATION_LEASE_MS));
    upload.epoch = upload
      .epoch
      .checked_add(1)
      .ok_or_else(|| anyhow::anyhow!("managed upload fence epoch overflow"))?;
    // Validate persisted metadata before publishing the dispatch fence. The
    // HTTP path obtains the metadata and object through their checked APIs.
    let _: http::Method = upload.method.parse()?;
    let _: http::Uri = upload.uri.parse()?;
    let claim = DispatchClaim {
      id: id.to_string(),
      fence_epoch: upload.epoch,
    };
    self.commit_locked(&mut state, next)?;
    Ok(claim)
  }

  pub async fn finish_dispatch(
    &self,
    claim: &DispatchClaim,
    terminal: DispatchTerminal,
  ) -> anyhow::Result<UploadStatus> {
    self.ensure_healthy()?;
    let mut state = self.state.lock().await;
    let mut next = state.clone();
    let upload = next
      .uploads
      .get_mut(&claim.id)
      .ok_or(UploadRejection::NotFound)?;
    if upload.state != UploadState::Dispatching || upload.epoch != claim.fence_epoch {
      return Err(UploadRejection::Conflict.into());
    }
    upload.state = match terminal {
      DispatchTerminal::Complete => UploadState::Complete,
      DispatchTerminal::Indeterminate => UploadState::Indeterminate,
    };
    upload.dispatch_expires_at_ms = None;
    upload.expires_at_ms = retention_expiry(now_ms()?, upload.profile.object_ttl_seconds)?;
    upload.epoch = upload
      .epoch
      .checked_add(1)
      .ok_or_else(|| anyhow::anyhow!("managed upload fence epoch overflow"))?;
    let result = status(&claim.id, upload);
    self.commit_locked(&mut state, next)?;
    Ok(result)
  }

  pub async fn delete(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &serde_json::Value,
  ) -> anyhow::Result<()> {
    self.ensure_healthy()?;
    let _filesystem = self.assembly.lock().await;
    let tombstone_epoch = {
      let mut state = self.state.lock().await;
      let mut next = state.clone();
      expire_dispatches(&mut next, now_ms()?)?;
      let upload = checked_mut(&mut next, id, owner, binding)?;
      if matches!(
        upload.state,
        UploadState::Completing | UploadState::Dispatching
      ) {
        return Err(UploadRejection::Conflict.into());
      }
      upload.state = UploadState::Deleted;
      upload.reservation = None;
      upload.epoch = upload
        .epoch
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("managed upload fence epoch overflow"))?;
      let epoch = upload.epoch;
      self.commit_locked(&mut state, next)?;
      epoch
    };
    remove_upload_files(&self.root, id)?;
    self.remove_tombstone(id, tombstone_epoch).await?;
    Ok(())
  }

  pub async fn collect_garbage(&self, now_ms: u64, limit: usize) -> anyhow::Result<usize> {
    self.ensure_healthy()?;
    if limit == 0 {
      return Ok(0);
    }
    let ids = {
      let mut state = self.state.lock().await;
      let mut next = state.clone();
      if expire_dispatches(&mut next, now_ms)? {
        self.commit_locked(&mut state, next)?;
      }
      state
        .uploads
        .iter()
        .filter(|(_, upload)| {
          upload.state == UploadState::Deleted
            || (upload.expires_at_ms <= now_ms && upload.state != UploadState::Dispatching)
        })
        .take(limit)
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>()
    };
    let mut removed = 0;
    for id in ids {
      let _filesystem = self.assembly.lock().await;
      let tombstone_epoch = {
        let mut state = self.state.lock().await;
        let mut next = state.clone();
        let Some(upload) = next.uploads.get_mut(&id) else {
          continue;
        };
        if upload.state != UploadState::Deleted
          && (upload.expires_at_ms > now_ms || upload.state == UploadState::Dispatching)
        {
          continue;
        }
        upload.state = UploadState::Deleted;
        upload.reservation = None;
        upload.epoch = upload
          .epoch
          .checked_add(1)
          .ok_or_else(|| anyhow::anyhow!("managed upload fence epoch overflow"))?;
        let epoch = upload.epoch;
        self.commit_locked(&mut state, next)?;
        epoch
      };
      remove_upload_files(&self.root, &id)?;
      self.remove_tombstone(&id, tombstone_epoch).await?;
      removed += 1;
    }
    let _filesystem = self.assembly.lock().await;
    let snapshot = self.state.lock().await.clone();
    cleanup_orphan_data(&self.root, &snapshot, limit)?;
    cleanup_staging(&self.root, limit, Some(&self.instance_id))?;
    cleanup_journal_temps(&self.root, limit)?;
    Ok(removed)
  }

  fn commit_locked(
    &self,
    current: &mut tokio::sync::MutexGuard<'_, LocalState>,
    next: LocalState,
  ) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(&next)?;
    match persist_state(&self.root, &bytes) {
      Ok(()) => {
        **current = next;
        Ok(())
      }
      Err(error) if is_uncertain_publication(&error) => {
        // The rename made this state visible, but a directory fsync failed.
        // Mirror it in memory and reject every further operation until reopen
        // validates whichever version survived the crash boundary.
        **current = next;
        self.poisoned.store(true, Ordering::Release);
        Err(error)
      }
      Err(error) => Err(error),
    }
  }

  fn ensure_healthy(&self) -> anyhow::Result<()> {
    if self.poisoned.load(Ordering::Acquire) {
      bail!("managed upload local store has an uncertain journal publication and must be reopened");
    }
    Ok(())
  }

  async fn remove_tombstone(&self, id: &str, epoch: u64) -> anyhow::Result<()> {
    let mut state = self.state.lock().await;
    let mut next = state.clone();
    if matches!(next.uploads.get(id), Some(upload) if upload.state == UploadState::Deleted && upload.epoch == epoch)
    {
      next.uploads.remove(id);
      self.commit_locked(&mut state, next)?;
    }
    Ok(())
  }
}

impl StoredProfile {
  fn from_profile(profile: &crate::config::UploadProfileConfig) -> Self {
    Self {
      name: profile.name.clone(),
      destination: profile.destination.clone(),
      max_upload_bytes: profile.max_upload_bytes,
      max_part_bytes: profile.max_part_bytes,
      max_storage_bytes: profile.max_storage_bytes,
      max_sessions: profile.max_sessions,
      max_parts: profile.max_parts,
      max_concurrent_parts: profile.max_concurrent_parts,
      ttl_seconds: profile.ttl_seconds,
      object_ttl_seconds: profile.object_ttl_seconds,
    }
  }
}

fn checked<'a>(
  state: &'a LocalState,
  id: &str,
  owner: &UploadOwner,
  binding: &serde_json::Value,
) -> anyhow::Result<&'a LocalUpload> {
  let upload = state.uploads.get(id).ok_or(UploadRejection::NotFound)?;
  if &upload.owner != owner
    || &upload.binding != binding
    || upload.state == UploadState::Deleted
    || upload.expires_at_ms <= now_ms()?
  {
    return Err(UploadRejection::NotFound.into());
  }
  Ok(upload)
}

fn checked_mut<'a>(
  state: &'a mut LocalState,
  id: &str,
  owner: &UploadOwner,
  binding: &serde_json::Value,
) -> anyhow::Result<&'a mut LocalUpload> {
  let upload = state.uploads.get_mut(id).ok_or(UploadRejection::NotFound)?;
  if &upload.owner != owner
    || &upload.binding != binding
    || upload.state == UploadState::Deleted
    || upload.expires_at_ms <= now_ms()?
  {
    return Err(UploadRejection::NotFound.into());
  }
  Ok(upload)
}

fn ensure_appendable(
  upload: &LocalUpload,
  now: u64,
  expected_offset: u64,
  length: u64,
) -> anyhow::Result<()> {
  if upload.state != UploadState::Active || upload.reservation.is_some() {
    return Err(UploadRejection::Conflict.into());
  }
  if upload.expires_at_ms <= now {
    return Err(UploadRejection::NotFound.into());
  }
  if upload.offset != expected_offset
    || length > upload.profile.max_part_bytes
    || upload.offset.saturating_add(length) > upload.profile.max_upload_bytes
    || upload
      .declared_total
      .is_some_and(|total| upload.offset.saturating_add(length) > total)
  {
    return Err(UploadRejection::Conflict.into());
  }
  if upload.parts.len() >= usize::try_from(upload.profile.max_parts).unwrap_or(usize::MAX) {
    return Err(UploadRejection::Capacity.into());
  }
  Ok(())
}

fn check_reservation(
  upload: &LocalUpload,
  reservation: &AppendReservation,
  now: u64,
) -> anyhow::Result<()> {
  let current = upload.reservation.as_ref();
  if upload.state != UploadState::Active
    || upload.expires_at_ms <= now
    || upload.epoch != reservation.fence_epoch
    || !matches!(current, Some(value)
      if value.token == reservation.backend_token()
        && value.expected_offset == reservation.expected_offset
        && value.bytes == reservation.length
        && value.epoch == reservation.fence_epoch
        && value.expires_at_ms > now)
  {
    if upload.expires_at_ms <= now {
      return Err(UploadRejection::NotFound.into());
    }
    return Err(UploadRejection::Conflict.into());
  }
  Ok(())
}

fn reap_expired_reservations(state: &mut LocalState, now: u64) -> anyhow::Result<()> {
  for upload in state.uploads.values_mut() {
    if upload
      .reservation
      .as_ref()
      .is_some_and(|reservation| reservation.expires_at_ms <= now)
    {
      upload.reservation = None;
      upload.epoch = upload
        .epoch
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("managed upload fence epoch overflow"))?;
    }
  }
  Ok(())
}

fn expire_dispatches(state: &mut LocalState, now: u64) -> anyhow::Result<bool> {
  let mut changed = false;
  for upload in state.uploads.values_mut() {
    if upload.state == UploadState::Dispatching
      && upload
        .dispatch_expires_at_ms
        .is_some_and(|expires| expires <= now)
    {
      upload.state = UploadState::Indeterminate;
      upload.dispatch_expires_at_ms = None;
      upload.expires_at_ms = retention_expiry(now, upload.profile.object_ttl_seconds)?;
      upload.epoch = upload
        .epoch
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("managed upload fence epoch overflow"))?;
      changed = true;
    }
  }
  Ok(changed)
}

fn profile_usage(state: &LocalState, profile: &str) -> u64 {
  state
    .uploads
    .values()
    .filter(|item| item.profile.name == profile)
    .fold(0_u64, |total, item| {
      total.saturating_add(
        item
          .offset
          .saturating_add(item.reservation.as_ref().map_or(0, |value| value.bytes))
          .saturating_add(item.object.as_ref().map_or(0, |object| object.bytes))
          .saturating_add(
            if item.state == UploadState::Completing && item.object.is_none() {
              item.offset
            } else {
              0
            },
          ),
      )
    })
}

fn status(id: &str, upload: &LocalUpload) -> UploadStatus {
  UploadStatus {
    id: id.to_string(),
    profile: upload.profile.name.clone(),
    offset: upload.offset,
    declared_total: upload.declared_total,
    state: upload.state.clone(),
    expires_at_ms: upload.expires_at_ms,
    object: upload.object.clone(),
  }
}

fn now_ms() -> anyhow::Result<u64> {
  u64::try_from(
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .context("system time is before Unix epoch")?
      .as_millis(),
  )
  .context("managed upload clock overflow")
}

fn random_id() -> anyhow::Result<String> {
  let mut bytes = [0_u8; 32];
  crate::crypto::random_fill(&mut bytes)
    .map_err(|_| anyhow::anyhow!("managed upload identifier generation failed"))?;
  Ok(hex_digest(bytes))
}

fn unique_id(state: &LocalState) -> anyhow::Result<String> {
  for _ in 0..8 {
    let id = random_id()?;
    if !state.uploads.contains_key(&id) {
      return Ok(id);
    }
  }
  bail!("managed upload identifier generation repeatedly collided")
}

fn retention_expiry(now: u64, ttl_seconds: u64) -> anyhow::Result<u64> {
  now
    .checked_add(ttl_seconds.saturating_mul(1_000))
    .ok_or_else(|| anyhow::anyhow!("managed upload retention expiry overflow"))
}

fn ensure_private_directory(path: &Path) -> anyhow::Result<()> {
  match std::fs::symlink_metadata(path) {
    Ok(metadata) => {
      if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
          "managed upload directory is not a private directory: {}",
          path.display()
        );
      }
      reject_broad_permissions(path, &metadata)?;
    }
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      let mut builder = std::fs::DirBuilder::new();
      builder.recursive(true);
      #[cfg(unix)]
      builder.mode(0o700);
      builder.create(path)?;
      let metadata = std::fs::symlink_metadata(path)?;
      if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
          "managed upload directory creation resolved to an unsafe target: {}",
          path.display()
        );
      }
      reject_broad_permissions(path, &metadata)?;
    }
    Err(error) => return Err(error.into()),
  }
  Ok(())
}

fn hex_digest(value: impl AsRef<[u8]>) -> String {
  value
    .as_ref()
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect()
}

fn open_state(root: &Path) -> anyhow::Result<(Flock<std::fs::File>, LocalState)> {
  ensure_private_directory(root)
    .with_context(|| format!("failed to create managed upload root {}", root.display()))?;
  for name in ["journal", "chunks", "objects", "staging"] {
    ensure_private_directory(&root.join(name))?;
  }
  reject_unsafe_existing_file(&root.join(LOCK_FILE))?;
  let lock_file = std::fs::OpenOptions::new()
    .read(true)
    .write(true)
    .create(true)
    .truncate(false)
    .mode(0o600)
    .open(root.join(LOCK_FILE))
    .context("failed to open managed upload local root lock")?;
  #[cfg(unix)]
  reject_broad_permissions(&root.join(LOCK_FILE), &lock_file.metadata()?)?;
  let lock = Flock::lock(lock_file, FlockArg::LockExclusiveNonblock)
    .map_err(|(_, error)| anyhow::anyhow!("managed upload local root is already owned: {error}"))?;
  let state_path = root.join(STATE_FILE);
  reject_unsafe_existing_file(&state_path)?;
  let mut state = if state_path.exists() {
    let metadata = std::fs::symlink_metadata(&state_path)?;
    reject_broad_permissions(&state_path, &metadata)?;
    if metadata.len() > MAX_STATE_BYTES {
      bail!("managed upload local journal exceeds its bound");
    }
    let state: LocalState = serde_json::from_slice(&std::fs::read(&state_path)?)?;
    if state.schema_version != 1 {
      bail!("managed upload local journal schema is unsupported");
    }
    state
  } else {
    let state = LocalState {
      schema_version: 1,
      uploads: BTreeMap::new(),
    };
    persist_state(root, &serde_json::to_vec(&state)?)?;
    state
  };
  recover_state(root, &mut state)?;
  validate_referenced_files(root, &state)?;
  cleanup_orphan_data(root, &state, STARTUP_STAGING_CLEANUP_LIMIT)?;
  cleanup_staging(root, STARTUP_STAGING_CLEANUP_LIMIT, None)?;
  cleanup_journal_temps(root, STARTUP_STAGING_CLEANUP_LIMIT)?;
  Ok((lock, state))
}

fn persist_state(root: &Path, bytes: &[u8]) -> anyhow::Result<()> {
  if u64::try_from(bytes.len())? > MAX_STATE_BYTES {
    bail!("managed upload local journal exceeds its bound");
  }
  let journal = root.join("journal");
  let temporary = journal.join(format!(".state-{}-{}", std::process::id(), random_id()?));
  let mut published = false;
  let result = (|| {
    let mut file = std::fs::OpenOptions::new()
      .write(true)
      .create_new(true)
      .mode(0o600)
      .open(&temporary)?;
    std::io::Write::write_all(&mut file, bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, root.join(STATE_FILE))?;
    published = true;
    std::fs::File::open(journal)?.sync_all()?;
    std::fs::File::open(root)?.sync_all()?;
    Ok::<(), anyhow::Error>(())
  })();
  if result.is_err() && !published {
    let _ = std::fs::remove_file(&temporary);
  }
  match result {
    Err(error) if published => {
      let source = error
        .downcast::<std::io::Error>()
        .unwrap_or_else(|error| std::io::Error::other(error.to_string()));
      Err(UncertainStatePublication(source).into())
    }
    other => other,
  }
}

fn is_uncertain_publication(error: &anyhow::Error) -> bool {
  error.downcast_ref::<UncertainStatePublication>().is_some()
}

fn recover_state(root: &Path, state: &mut LocalState) -> anyhow::Result<()> {
  let now = now_ms()?;
  let mut changed = false;
  for upload in state.uploads.values_mut() {
    if upload.state == UploadState::Dispatching {
      upload.state = UploadState::Indeterminate;
      upload.dispatch_expires_at_ms = None;
      upload.expires_at_ms = retention_expiry(now, upload.profile.object_ttl_seconds)?;
      upload.epoch = upload
        .epoch
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("managed upload fence epoch overflow"))?;
      changed = true;
    }
    if upload.reservation.is_some() {
      upload.reservation = None;
      upload.epoch = upload
        .epoch
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("managed upload fence epoch overflow"))?;
      changed = true;
    }
  }
  if changed {
    persist_state(root, &serde_json::to_vec(state)?)?;
  }

  let deleted = state
    .uploads
    .iter()
    .filter(|(_, upload)| upload.state == UploadState::Deleted)
    .map(|(id, _)| id.clone())
    .collect::<Vec<_>>();
  if !deleted.is_empty() {
    for id in &deleted {
      remove_upload_files(root, id)?;
      state.uploads.remove(id);
    }
    persist_state(root, &serde_json::to_vec(state)?)?;
  }
  Ok(())
}

fn remove_upload_files(root: &Path, id: &str) -> anyhow::Result<()> {
  for directory in ["chunks", "objects"] {
    let path = root.join(directory).join(id);
    match std::fs::remove_dir_all(&path) {
      Ok(()) => {}
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
      Err(error) => {
        return Err(error)
          .with_context(|| format!("failed to remove managed upload data {}", path.display()));
      }
    }
  }
  for directory in [root.join("chunks"), root.join("objects")] {
    std::fs::File::open(directory)?.sync_all()?;
  }
  Ok(())
}

fn validate_referenced_files(root: &Path, state: &LocalState) -> anyhow::Result<()> {
  for (id, upload) in &state.uploads {
    for part in &upload.parts {
      validate_stored_file(
        &stored_key_path(root, "chunks", id, &part.key)?,
        part.bytes,
        &part.sha256,
      )?;
    }
    if let Some(object) = &upload.object {
      validate_stored_file(
        &stored_key_path(root, "objects", id, &object.key)?,
        object.bytes,
        &object.sha256,
      )?;
    }
  }
  Ok(())
}

fn stored_key_path(root: &Path, kind: &str, id: &str, key: &str) -> anyhow::Result<PathBuf> {
  let prefix = format!("{kind}/{id}/");
  let name = key
    .strip_prefix(&prefix)
    .filter(|name| !name.is_empty() && !name.contains('/') && *name != "." && *name != "..")
    .ok_or_else(|| anyhow::anyhow!("managed upload journal contains an unsafe stored key"))?;
  Ok(root.join(kind).join(id).join(name))
}

fn validate_stored_file(
  path: &Path,
  expected_bytes: u64,
  expected_digest: &str,
) -> anyhow::Result<()> {
  let parent = path
    .parent()
    .ok_or_else(|| anyhow::anyhow!("managed upload stored file has no parent"))?;
  let parent_metadata = std::fs::symlink_metadata(parent).with_context(|| {
    format!(
      "managed upload journal references missing directory {}",
      parent.display()
    )
  })?;
  if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
    bail!(
      "managed upload journal references unsafe directory {}",
      parent.display()
    );
  }
  reject_broad_permissions(parent, &parent_metadata)?;
  let metadata = std::fs::symlink_metadata(path).with_context(|| {
    format!(
      "managed upload journal references missing data {}",
      path.display()
    )
  })?;
  if metadata.file_type().is_symlink() || !metadata.is_file() {
    bail!(
      "managed upload journal references unsafe data {}",
      path.display()
    );
  }
  reject_broad_permissions(path, &metadata)?;
  let mut file = std::fs::File::open(path)?;
  let mut digest = Sha256::new();
  let mut total = 0_u64;
  let mut buffer = vec![0_u8; STREAM_BUFFER_BYTES];
  loop {
    let read = std::io::Read::read(&mut file, &mut buffer)?;
    if read == 0 {
      break;
    }
    total = total
      .checked_add(u64::try_from(read)?)
      .ok_or_else(|| anyhow::anyhow!("managed upload stored length overflow"))?;
    if total > expected_bytes {
      bail!("managed upload stored data length mismatch");
    }
    digest.update(&buffer[..read]);
  }
  if total != expected_bytes || hex_digest(digest.finalize()) != expected_digest {
    bail!("managed upload stored data digest mismatch");
  }
  Ok(())
}

fn reject_unsafe_existing_file(path: &Path) -> anyhow::Result<()> {
  match std::fs::symlink_metadata(path) {
    Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
      bail!("managed upload file target is unsafe: {}", path.display())
    }
    Ok(metadata) => reject_broad_permissions(path, &metadata),
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
    Err(error) => Err(error.into()),
  }
}

fn reject_broad_permissions(path: &Path, metadata: &std::fs::Metadata) -> anyhow::Result<()> {
  #[cfg(unix)]
  if metadata.permissions().mode() & 0o077 != 0 {
    bail!(
      "managed upload path must not grant group or other permissions: {}",
      path.display()
    );
  }
  #[cfg(not(unix))]
  let _ = (path, metadata);
  Ok(())
}

fn cleanup_orphan_data(root: &Path, state: &LocalState, limit: usize) -> anyhow::Result<usize> {
  if limit == 0 {
    return Ok(0);
  }
  let referenced = state
    .uploads
    .values()
    .flat_map(|upload| {
      upload
        .parts
        .iter()
        .map(|part| part.key.clone())
        .chain(upload.object.iter().map(|object| object.key.clone()))
    })
    .collect::<BTreeSet<_>>();
  let mut removed = 0_usize;
  for kind in ["chunks", "objects"] {
    let base = root.join(kind);
    for upload_directory in std::fs::read_dir(&base)? {
      let upload_directory = upload_directory?;
      if !upload_directory.file_type()?.is_dir() {
        continue;
      }
      let id = upload_directory.file_name().to_string_lossy().into_owned();
      if !state.uploads.contains_key(&id) {
        std::fs::remove_dir_all(upload_directory.path())?;
        removed += 1;
      } else {
        for entry in std::fs::read_dir(upload_directory.path())? {
          let entry = entry?;
          if !entry.file_type()?.is_file() {
            continue;
          }
          let relative = format!("{kind}/{id}/{}", entry.file_name().to_string_lossy());
          if !referenced.contains(&relative) {
            std::fs::remove_file(entry.path())?;
            removed += 1;
          }
          if removed >= limit {
            break;
          }
        }
      }
      if removed >= limit {
        break;
      }
    }
    if removed >= limit {
      break;
    }
  }
  if removed != 0 {
    for kind in ["chunks", "objects"] {
      std::fs::File::open(root.join(kind))?.sync_all()?;
    }
  }
  Ok(removed)
}

fn cleanup_staging(
  root: &Path,
  limit: usize,
  current_instance: Option<&str>,
) -> anyhow::Result<()> {
  if limit == 0 {
    return Ok(());
  }
  let staging = root.join("staging");
  let mut removed = 0_usize;
  for entry in std::fs::read_dir(&staging)? {
    let entry = entry?;
    if current_instance
      .is_some_and(|instance| entry.file_name().to_string_lossy().starts_with(instance))
    {
      continue;
    }
    if entry.file_type()?.is_file() {
      match std::fs::remove_file(entry.path()) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
      }
      removed += 1;
      if removed >= limit {
        break;
      }
    }
  }
  std::fs::File::open(staging)?.sync_all()?;
  Ok(())
}

struct TemporaryPath {
  path: PathBuf,
  armed: bool,
}

impl TemporaryPath {
  fn new(path: PathBuf) -> Self {
    Self { path, armed: true }
  }

  fn path(&self) -> &Path {
    &self.path
  }

  fn disarm(&mut self) {
    self.armed = false;
  }
}

impl Drop for TemporaryPath {
  fn drop(&mut self) {
    if self.armed {
      let _ = std::fs::remove_file(&self.path);
    }
  }
}

fn cleanup_journal_temps(root: &Path, limit: usize) -> anyhow::Result<()> {
  if limit == 0 {
    return Ok(());
  }
  let journal = root.join("journal");
  let mut removed = 0_usize;
  for entry in std::fs::read_dir(&journal)? {
    let entry = entry?;
    if !entry.file_type()?.is_file() || !entry.file_name().to_string_lossy().starts_with(".state-")
    {
      continue;
    }
    match std::fs::remove_file(entry.path()) {
      Ok(()) => removed += 1,
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
      Err(error) => return Err(error.into()),
    }
    if removed >= limit {
      break;
    }
  }
  if removed != 0 {
    std::fs::File::open(journal)?.sync_all()?;
  }
  Ok(())
}

async fn verified_file_stream(
  path: PathBuf,
  expected_bytes: u64,
  expected_digest: String,
) -> anyhow::Result<UploadByteStream> {
  verify_file(&path, expected_bytes, &expected_digest).await?;
  let file = tokio::fs::File::open(path).await?;
  let stream = futures_util::stream::try_unfold(
    (file, Sha256::new(), 0_u64, false),
    move |(mut file, mut digest, mut total, finished)| {
      let expected_digest = expected_digest.clone();
      async move {
        if finished {
          return Ok(None);
        }
        let mut buffer = vec![0_u8; STREAM_BUFFER_BYTES];
        let read = tokio::io::AsyncReadExt::read(&mut file, &mut buffer).await?;
        if read == 0 {
          if total != expected_bytes || hex_digest(digest.finalize()) != expected_digest {
            bail!("managed upload stored object digest mismatch");
          }
          return Ok(None);
        }
        total = total
          .checked_add(u64::try_from(read)?)
          .ok_or_else(|| anyhow::anyhow!("managed upload object length overflow"))?;
        if total > expected_bytes {
          bail!("managed upload stored object length mismatch");
        }
        buffer.truncate(read);
        digest.update(&buffer);
        Ok(Some((Bytes::from(buffer), (file, digest, total, false))))
      }
    },
  );
  Ok(Box::pin(stream))
}

async fn verify_file(
  path: &Path,
  expected_bytes: u64,
  expected_digest: &str,
) -> anyhow::Result<()> {
  let mut file = tokio::fs::File::open(path).await?;
  let mut digest = Sha256::new();
  let mut total = 0_u64;
  let mut buffer = vec![0_u8; STREAM_BUFFER_BYTES];
  loop {
    let read = tokio::io::AsyncReadExt::read(&mut file, &mut buffer).await?;
    if read == 0 {
      break;
    }
    total = total
      .checked_add(u64::try_from(read)?)
      .ok_or_else(|| anyhow::anyhow!("managed upload object length overflow"))?;
    if total > expected_bytes {
      bail!("managed upload stored object length mismatch");
    }
    digest.update(&buffer[..read]);
  }
  if total != expected_bytes || hex_digest(digest.finalize()) != expected_digest {
    bail!("managed upload stored object digest mismatch");
  }
  Ok(())
}

async fn sync_directory(path: &Path) -> anyhow::Result<()> {
  let path = path.to_path_buf();
  tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
  })
  .await??;
  Ok(())
}

async fn create_private_temporary(
  path: PathBuf,
) -> anyhow::Result<(tokio::fs::File, TemporaryPath)> {
  create_private_temporary_with_observer(path, || {}).await
}

async fn create_private_temporary_with_observer<F>(
  path: PathBuf,
  on_created: F,
) -> anyhow::Result<(tokio::fs::File, TemporaryPath)>
where
  F: FnOnce() + Send + 'static,
{
  let (file, cleanup) =
    tokio::task::spawn_blocking(move || -> anyhow::Result<(std::fs::File, TemporaryPath)> {
      let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
      let cleanup = TemporaryPath::new(path);
      on_created();
      Ok((file, cleanup))
    })
    .await??;
  Ok((tokio::fs::File::from_std(file), cleanup))
}

async fn rename_with_cleanup(source: PathBuf, target: PathBuf) -> anyhow::Result<TemporaryPath> {
  tokio::task::spawn_blocking(move || -> anyhow::Result<TemporaryPath> {
    // Keep cleanup in the blocking task so cancellation of its async waiter
    // cannot remove the target before a detached filesystem rename creates it.
    let cleanup = TemporaryPath::new(target.clone());
    std::fs::rename(source, target)?;
    Ok(cleanup)
  })
  .await?
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use http::{Method, Uri};
  use serde_json::json;

  use super::*;
  use crate::config::{
    LocalUploadStoreConfig, UploadIdentityConfig, UploadIdentityKind, UploadProfileConfig,
  };

  fn store_config(root: &Path) -> UploadStoreConfig {
    UploadStoreConfig {
      name: "local".to_string(),
      kind: UploadStoreKind::Local,
      local: Some(LocalUploadStoreConfig {
        root: root.to_path_buf(),
      }),
      postgres_s3: None,
    }
  }

  fn new_store_config(parent: &Path) -> UploadStoreConfig {
    store_config(&parent.join("managed-upload-store"))
  }

  fn store_root(config: &UploadStoreConfig) -> &Path {
    &config.local.as_ref().expect("local store config").root
  }

  fn profile(destination: UploadDestinationConfig, max_storage_bytes: u64) -> UploadProfileConfig {
    UploadProfileConfig {
      name: "profile".to_string(),
      store: "local".to_string(),
      public_base_url: url::Url::parse("https://uploads.example.test").expect("valid URL"),
      staging_dir: PathBuf::from("/tmp/unused-managed-upload-tests"),
      max_staging_bytes: 64,
      control_path_prefix: "/uploads".to_string(),
      object_path_prefix: "/objects".to_string(),
      destination,
      identity: UploadIdentityConfig {
        kind: UploadIdentityKind::Ipm,
        source: "test".to_string(),
        subject_field: None,
      },
      max_upload_bytes: 64,
      max_part_bytes: 32,
      max_storage_bytes,
      max_sessions: 8,
      max_parts: 8,
      inspection_bytes: 32,
      ttl_seconds: 60,
      object_ttl_seconds: 60,
      max_concurrent_uploads: 4,
      max_concurrent_parts: 4,
    }
  }

  fn owner() -> UploadOwner {
    UploadOwner {
      kind: UploadIdentityKind::Ipm,
      source: "test".to_string(),
      subject: "alice".to_string(),
    }
  }

  fn binding() -> serde_json::Value {
    json!({"route":"upload"})
  }

  fn create_request(profile: UploadProfileConfig, total: Option<u64>) -> UploadCreate {
    UploadCreate {
      profile,
      owner: owner(),
      binding: binding(),
      method: Method::POST,
      uri: Uri::from_static("/target"),
      safe_headers: json!({"content-type":"application/octet-stream"}),
      declared_total: total,
    }
  }

  fn body(bytes: &'static [u8]) -> UploadByteStream {
    Box::pin(futures_util::stream::once(async move {
      Ok(Bytes::from_static(bytes))
    }))
  }

  fn evidence(bytes: &[u8]) -> InspectedPart {
    InspectedPart {
      bytes: u64::try_from(bytes.len()).expect("test body length fits u64"),
      sha256: hex_digest(Sha256::digest(bytes)),
    }
  }

  fn is_rejection(error: &anyhow::Error, expected: UploadRejection) -> bool {
    error
      .downcast_ref::<UploadRejection>()
      .is_some_and(|actual| *actual == expected)
  }

  async fn collect(mut stream: UploadByteStream) -> anyhow::Result<Vec<u8>> {
    let mut result = Vec::new();
    while let Some(frame) = stream.next().await {
      result.extend_from_slice(&frame?);
    }
    Ok(result)
  }

  #[tokio::test]
  async fn lock_is_restartable_and_ids_are_lower_hex() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let config = new_store_config(directory.path());
    let store = LocalUploadStore::open(&config).await.expect("open store");
    let upload = store
      .create(create_request(
        profile(UploadDestinationConfig::Object, 64),
        None,
      ))
      .await
      .expect("create upload");
    assert_eq!(upload.id.len(), 64);
    assert!(
      upload
        .id
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert!(LocalUploadStore::open(&config).await.is_err());

    drop(store);
    let reopened = LocalUploadStore::open(&config)
      .await
      .expect("reopen after lock release");
    assert_eq!(
      reopened
        .lookup(&upload.id, &owner(), &binding())
        .await
        .expect("durable upload")
        .offset,
      0
    );
  }

  #[tokio::test]
  async fn reopen_removes_unjournaled_chunk_and_object_orphans() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let config = new_store_config(directory.path());
    let store = LocalUploadStore::open(&config).await.expect("open store");
    drop(store);
    for kind in ["chunks", "objects"] {
      let orphan = store_root(&config).join(kind).join("orphan");
      std::fs::create_dir_all(&orphan).expect("create orphan directory");
      std::fs::write(orphan.join("uncommitted"), b"data").expect("write orphan");
    }
    let _reopened = LocalUploadStore::open(&config).await.expect("reopen store");
    assert!(!store_root(&config).join("chunks/orphan").exists());
    assert!(!store_root(&config).join("objects/orphan").exists());
  }

  #[tokio::test]
  async fn reopen_rejects_journal_metadata_with_missing_referenced_data() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let config = new_store_config(directory.path());
    let store = LocalUploadStore::open(&config).await.expect("open store");
    let upload = store
      .create(create_request(
        profile(UploadDestinationConfig::Object, 64),
        Some(4),
      ))
      .await
      .expect("create upload");
    let reservation = store
      .begin_append(&upload.id, &owner(), &binding(), 0, 4)
      .await
      .expect("reserve append");
    store
      .commit_fully_inspected_part(&reservation, &evidence(b"data"), body(b"data"))
      .await
      .expect("commit part");
    drop(store);
    let chunk = std::fs::read_dir(store_root(&config).join("chunks").join(upload.id))
      .unwrap()
      .next()
      .expect("chunk entry")
      .unwrap()
      .path();
    std::fs::remove_file(chunk).expect("remove referenced chunk");
    let error = match LocalUploadStore::open(&config).await {
      Ok(_) => panic!("missing referenced data must reject reopen"),
      Err(error) => error,
    };
    assert!(error.to_string().contains("references missing data"));
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn local_store_directories_and_published_files_are_private() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let config = store_config(&directory.path().join("private-store"));
    let store = LocalUploadStore::open(&config).await.expect("open store");
    let upload = store
      .create(create_request(
        profile(UploadDestinationConfig::Object, 64),
        Some(4),
      ))
      .await
      .expect("create upload");
    let reservation = store
      .begin_append(&upload.id, &owner(), &binding(), 0, 4)
      .await
      .expect("reserve append");
    store
      .commit_fully_inspected_part(&reservation, &evidence(b"data"), body(b"data"))
      .await
      .expect("commit part");
    store
      .claim_complete(&upload.id, &owner(), &binding(), 4)
      .await
      .expect("claim completion");
    let published = store
      .publish_object(&upload.id, &owner(), &binding())
      .await
      .expect("publish object");

    let root = config.local.as_ref().expect("local config").root.as_path();
    for path in [
      root.to_path_buf(),
      root.join("journal"),
      root.join("chunks"),
      root.join("chunks").join(&upload.id),
      root.join("objects"),
      root.join("objects").join(&upload.id),
      root.join("staging"),
    ] {
      assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o700
      );
    }
    let chunk = std::fs::read_dir(root.join("chunks").join(&upload.id))
      .unwrap()
      .next()
      .expect("chunk entry")
      .unwrap()
      .path();
    let object = root.join(published.object.expect("published object").key);
    for path in [root.join(LOCK_FILE), root.join(STATE_FILE), chunk, object] {
      assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
      );
    }
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn local_store_rejects_a_symlink_root() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let target = directory.path().join("target");
    std::fs::create_dir(&target).expect("create target");
    let linked = directory.path().join("linked");
    std::os::unix::fs::symlink(&target, &linked).expect("create symlink");
    let error = match LocalUploadStore::open(&store_config(&linked)).await {
      Ok(_) => panic!("symlink root must be rejected"),
      Err(error) => error,
    };
    assert!(format!("{error:#}").contains("not a private directory"));
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn local_store_rejects_broad_existing_root_without_chmod() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let shared = directory.path().join("shared");
    std::fs::create_dir(&shared).expect("create shared root");
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755))
      .expect("set broad mode");
    let error = match LocalUploadStore::open(&store_config(&shared)).await {
      Ok(_) => panic!("broad existing root must be rejected"),
      Err(error) => error,
    };
    assert!(format!("{error:#}").contains("group or other permissions"));
    assert_eq!(
      std::fs::metadata(shared).unwrap().permissions().mode() & 0o777,
      0o755
    );
  }

  #[test]
  fn cancelled_queued_rename_cleans_a_late_target() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let source = directory.path().join("source");
    let target = directory.path().join("target");
    std::fs::write(&source, b"data").expect("write rename source");
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let runtime = tokio::runtime::Builder::new_current_thread()
      .max_blocking_threads(1)
      .build()
      .expect("build single-worker runtime");

    runtime.block_on(async {
      let blocking_barrier = barrier.clone();
      let blocker = tokio::task::spawn_blocking(move || {
        blocking_barrier.wait();
        blocking_barrier.wait();
      });
      barrier.wait();

      let mut rename = Box::pin(rename_with_cleanup(source.clone(), target.clone()));
      assert!(futures_util::poll!(&mut rename).is_pending());
      drop(rename);

      barrier.wait();
      blocker.await.expect("release blocking worker");
    });
    // Runtime drop joins the detached blocking rename queued behind `blocker`.
    drop(runtime);
    assert!(!source.exists(), "detached rename did not execute");
    assert!(!target.exists(), "cancelled rename left a late target");
  }

  #[test]
  fn cancelled_queued_create_cleans_a_late_staging_file() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let target = directory.path().join("late.part");
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let created = Arc::new(AtomicBool::new(false));
    let runtime = tokio::runtime::Builder::new_current_thread()
      .enable_time()
      .max_blocking_threads(1)
      .build()
      .expect("build single-worker runtime");

    runtime.block_on(async {
      let blocking_barrier = barrier.clone();
      let blocker = tokio::task::spawn_blocking(move || {
        blocking_barrier.wait();
        blocking_barrier.wait();
      });
      barrier.wait();

      let created_by_task = created.clone();
      let mut create = Box::pin(create_private_temporary_with_observer(
        target.clone(),
        move || created_by_task.store(true, Ordering::Release),
      ));
      assert!(futures_util::poll!(&mut create).is_pending());
      drop(create);

      barrier.wait();
      blocker.await.expect("release blocking worker");
      tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
          if created.load(Ordering::Acquire) && !target.exists() {
            break;
          }
          tokio::task::yield_now().await;
        }
      })
      .await
      .expect("cancelled create cleanup completed");
    });
    drop(runtime);
    assert!(created.load(Ordering::Acquire));
    assert!(!target.exists(), "cancelled create left a staging file");
  }

  #[tokio::test]
  async fn cancelled_commit_removes_renamed_but_unjournaled_chunk() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let config = new_store_config(directory.path());
    let store = Arc::new(LocalUploadStore::open(&config).await.expect("open store"));
    let upload = store
      .create(create_request(
        profile(UploadDestinationConfig::Object, 64),
        Some(4),
      ))
      .await
      .expect("create upload");
    let reservation = store
      .begin_append(&upload.id, &owner(), &binding(), 0, 4)
      .await
      .expect("reserve append");
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    sender
      .send(Ok::<Bytes, anyhow::Error>(Bytes::from_static(b"data")))
      .await
      .unwrap();
    let stream = futures_util::stream::unfold(receiver, |mut receiver| async move {
      receiver.recv().await.map(|item| (item, receiver))
    });
    let commit_store = store.clone();
    let task = tokio::spawn(async move {
      commit_store
        .commit_fully_inspected_part(&reservation, &evidence(b"data"), Box::pin(stream))
        .await
    });
    let staging = store_root(&config).join("staging");
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
      loop {
        if std::fs::read_dir(&staging).unwrap().next().is_some() {
          break;
        }
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("commit reached staging");
    let state = store.state.lock().await;
    drop(sender);
    let chunks = store_root(&config).join("chunks").join(&upload.id);
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
      loop {
        if std::fs::read_dir(&chunks)
          .ok()
          .is_some_and(|mut entries| entries.next().is_some())
        {
          break;
        }
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("commit renamed chunk before journal lock");
    task.abort();
    let _ = task.await;
    drop(state);
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
      loop {
        if std::fs::read_dir(&chunks).unwrap().next().is_none() {
          break;
        }
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("cancelled rename cleanup completed");
  }

  #[tokio::test]
  async fn append_abort_owner_binding_and_reopen_are_durable() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let config = new_store_config(directory.path());
    let store = LocalUploadStore::open(&config).await.expect("open store");
    let upload = store
      .create(create_request(
        profile(UploadDestinationConfig::Object, 64),
        Some(4),
      ))
      .await
      .expect("create upload");
    let mut wrong_owner = owner();
    wrong_owner.subject = "mallory".to_string();
    let error = store
      .lookup(&upload.id, &wrong_owner, &binding())
      .await
      .expect_err("owner mismatch");
    assert!(is_rejection(&error, UploadRejection::NotFound));

    let aborted = store
      .begin_append(&upload.id, &owner(), &binding(), 0, 4)
      .await
      .expect("reserve append");
    store.abort_append(&aborted).await.expect("abort append");
    let reservation = store
      .begin_append(&upload.id, &owner(), &binding(), 0, 4)
      .await
      .expect("reserve replacement append");
    let committed = store
      .commit_fully_inspected_part(&reservation, &evidence(b"data"), body(b"data"))
      .await
      .expect("commit part");
    assert_eq!(committed.offset, 4);

    drop(store);
    let reopened = LocalUploadStore::open(&config).await.expect("reopen store");
    let durable = reopened
      .lookup(&upload.id, &owner(), &binding())
      .await
      .expect("lookup durable upload");
    assert_eq!(durable.offset, 4);
    assert_eq!(
      collect(
        reopened
          .read_assembled(&upload.id, &owner(), &binding())
          .await
          .expect("open assembled stream")
      )
      .await
      .expect("read assembled body"),
      b"data"
    );
    let chunk = {
      let state = reopened.state.lock().await;
      state.uploads[&upload.id].parts[0].key.clone()
    };
    std::fs::write(store_root(&config).join(chunk), b"evil").expect("corrupt test chunk");
    let corrupted = reopened
      .read_assembled(&upload.id, &owner(), &binding())
      .await
      .expect("open corrupt assembled stream");
    assert!(collect(corrupted).await.is_err());
  }

  #[tokio::test]
  async fn retained_tombstones_continue_to_consume_session_and_byte_quota() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = LocalUploadStore::open(&new_store_config(directory.path()))
      .await
      .expect("open store");
    let mut limited = profile(UploadDestinationConfig::Object, 64);
    limited.max_sessions = 1;
    let upload = store
      .create(create_request(limited.clone(), None))
      .await
      .expect("create upload");
    {
      let mut state = store.state.lock().await;
      let retained = state.uploads.get_mut(&upload.id).expect("retained upload");
      retained.state = UploadState::Deleted;
      retained.offset = 4;
      assert_eq!(profile_usage(&state, &limited.name), 4);
    }
    let error = store
      .create(create_request(limited, None))
      .await
      .expect_err("retained tombstone must consume session quota");
    assert!(is_rejection(&error, UploadRejection::Capacity));
  }

  #[tokio::test]
  async fn append_reservation_is_an_upper_bound_for_exact_inspection_evidence() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = LocalUploadStore::open(&new_store_config(directory.path()))
      .await
      .expect("open store");
    let upload = store
      .create(create_request(
        profile(UploadDestinationConfig::Object, 64),
        None,
      ))
      .await
      .expect("create upload");
    let reservation = store
      .begin_append(&upload.id, &owner(), &binding(), 0, 16)
      .await
      .expect("reserve upper bound");
    let committed = store
      .commit_fully_inspected_part(&reservation, &evidence(b"data"), body(b"data"))
      .await
      .expect("commit exact inspected bytes below reservation cap");
    assert_eq!(committed.offset, 4);
  }

  #[tokio::test]
  async fn lookup_fences_an_outstanding_append_without_advancing_offset() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = LocalUploadStore::open(&new_store_config(directory.path()))
      .await
      .expect("open store");
    let upload = store
      .create(create_request(
        profile(UploadDestinationConfig::Object, 64),
        Some(4),
      ))
      .await
      .expect("create upload");
    let reservation = store
      .begin_append(&upload.id, &owner(), &binding(), 0, 4)
      .await
      .expect("reserve append");
    assert_eq!(
      store
        .lookup(&upload.id, &owner(), &binding())
        .await
        .expect("fencing lookup")
        .offset,
      0
    );
    let error = store
      .commit_fully_inspected_part(&reservation, &evidence(b"data"), body(b"data"))
      .await
      .expect_err("fenced append cannot commit");
    assert!(is_rejection(&error, UploadRejection::Conflict));
    let replacement = store
      .begin_append(&upload.id, &owner(), &binding(), 0, 4)
      .await
      .expect("replacement append");
    store
      .abort_append(&replacement)
      .await
      .expect("abort replacement");
  }

  #[tokio::test]
  async fn object_assembly_is_quota_counted_and_digest_verified() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let config = new_store_config(directory.path());
    let store = LocalUploadStore::open(&config).await.expect("open store");
    let profile = profile(UploadDestinationConfig::Object, 8);
    let upload = store
      .create(create_request(profile.clone(), Some(4)))
      .await
      .expect("create upload");
    let reservation = store
      .begin_append(&upload.id, &owner(), &binding(), 0, 4)
      .await
      .expect("reserve append");
    store
      .commit_fully_inspected_part(&reservation, &evidence(b"data"), body(b"data"))
      .await
      .expect("commit part");
    store
      .claim_complete(&upload.id, &owner(), &binding(), 4)
      .await
      .expect("claim completion and assembly quota");

    let second = store
      .create(create_request(profile, None))
      .await
      .expect("create second upload");
    let error = store
      .begin_append(&second.id, &owner(), &binding(), 0, 1)
      .await
      .expect_err("assembly reserve consumes remaining capacity");
    assert!(is_rejection(&error, UploadRejection::Capacity));

    let complete = store
      .publish_object(&upload.id, &owner(), &binding())
      .await
      .expect("publish object");
    assert_eq!(complete.state, UploadState::Complete);
    assert_eq!(
      collect(
        store
          .read_object(&upload.id, &owner(), &binding())
          .await
          .expect("verified object stream")
      )
      .await
      .expect("read object"),
      b"data"
    );

    let object = complete.object.expect("published object metadata");
    std::fs::write(store_root(&config).join(object.key), b"evil").expect("corrupt test object");
    assert!(
      store
        .read_object(&upload.id, &owner(), &binding())
        .await
        .is_err()
    );
  }

  #[tokio::test]
  async fn completion_recovers_and_dispatch_crash_becomes_collectable_indeterminate() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let config = new_store_config(directory.path());
    let destination = UploadDestinationConfig::Upstream {
      upstream: "origin".to_string(),
    };
    let store = LocalUploadStore::open(&config).await.expect("open store");
    let upload = store
      .create(create_request(profile(destination, 8), Some(4)))
      .await
      .expect("create upload");
    let reservation = store
      .begin_append(&upload.id, &owner(), &binding(), 0, 4)
      .await
      .expect("reserve append");
    store
      .commit_fully_inspected_part(&reservation, &evidence(b"data"), body(b"data"))
      .await
      .expect("commit part");
    store
      .claim_complete(&upload.id, &owner(), &binding(), 4)
      .await
      .expect("claim completion");
    drop(store);

    let reopened = LocalUploadStore::open(&config)
      .await
      .expect("reopen completing upload");
    assert_eq!(
      reopened
        .claim_complete(&upload.id, &owner(), &binding(), 4)
        .await
        .expect("idempotent completion claim")
        .state,
      UploadState::Completing
    );
    assert_eq!(
      reopened
        .publish_object(&upload.id, &owner(), &binding())
        .await
        .expect("publish upstream object")
        .state,
      UploadState::Ready
    );
    assert_eq!(
      collect(
        reopened
          .read_assembled(&upload.id, &owner(), &binding())
          .await
          .expect("ready upload remains available for reinspection")
      )
      .await
      .expect("reinspect ready upload"),
      b"data"
    );
    assert_eq!(
      reopened
        .lookup(&upload.id, &owner(), &binding())
        .await
        .expect("ready object survives a continuation lookup")
        .state,
      UploadState::Ready
    );
    reopened
      .begin_dispatch(&upload.id, &owner(), &binding())
      .await
      .expect("durable dispatch claim");
    drop(reopened);

    let recovered = LocalUploadStore::open(&config)
      .await
      .expect("recover dispatch crash");
    assert_eq!(
      recovered
        .lookup(&upload.id, &owner(), &binding())
        .await
        .expect("lookup indeterminate upload")
        .state,
      UploadState::Indeterminate
    );
    assert_eq!(
      recovered
        .collect_garbage(u64::MAX, 1)
        .await
        .expect("collect retained indeterminate upload"),
      1
    );
    let error = recovered
      .lookup(&upload.id, &owner(), &binding())
      .await
      .expect_err("collected upload is absent");
    assert!(is_rejection(&error, UploadRejection::NotFound));
  }

  #[tokio::test]
  async fn expired_dispatch_lease_becomes_indeterminate_without_restart() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = LocalUploadStore::open(&new_store_config(directory.path()))
      .await
      .expect("open store");
    let destination = UploadDestinationConfig::Upstream {
      upstream: "origin".to_string(),
    };
    let upload = store
      .create(create_request(profile(destination, 8), Some(4)))
      .await
      .expect("create upload");
    let reservation = store
      .begin_append(&upload.id, &owner(), &binding(), 0, 4)
      .await
      .expect("reserve append");
    store
      .commit_fully_inspected_part(&reservation, &evidence(b"data"), body(b"data"))
      .await
      .expect("commit part");
    store
      .claim_complete(&upload.id, &owner(), &binding(), 4)
      .await
      .expect("claim complete");
    store
      .publish_object(&upload.id, &owner(), &binding())
      .await
      .expect("publish object");
    store
      .begin_dispatch(&upload.id, &owner(), &binding())
      .await
      .expect("begin dispatch");

    let after_lease = now_ms()
      .expect("current time")
      .saturating_add(RESERVATION_LEASE_MS)
      .saturating_add(1);
    assert_eq!(
      store
        .collect_garbage(after_lease, 1)
        .await
        .expect("expire lease"),
      0
    );
    assert_eq!(
      store
        .lookup(&upload.id, &owner(), &binding())
        .await
        .expect("lookup terminal upload")
        .state,
      UploadState::Indeterminate
    );
  }

  #[tokio::test]
  async fn restart_releases_an_abandoned_reservation() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let config = new_store_config(directory.path());
    let store = LocalUploadStore::open(&config).await.expect("open store");
    let upload = store
      .create(create_request(
        profile(UploadDestinationConfig::Object, 64),
        Some(4),
      ))
      .await
      .expect("create upload");
    let abandoned = store
      .begin_append(&upload.id, &owner(), &binding(), 0, 4)
      .await
      .expect("reserve append");
    drop(abandoned);
    drop(store);

    let reopened = LocalUploadStore::open(&config).await.expect("reopen store");
    let replacement = reopened
      .begin_append(&upload.id, &owner(), &binding(), 0, 4)
      .await
      .expect("restart releases abandoned reservation");
    reopened
      .abort_append(&replacement)
      .await
      .expect("abort replacement");
  }

  #[tokio::test]
  async fn inspection_evidence_must_cover_the_entire_stream() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = LocalUploadStore::open(&new_store_config(directory.path()))
      .await
      .expect("open store");
    let upload = store
      .create(create_request(
        profile(UploadDestinationConfig::Object, 64),
        Some(4),
      ))
      .await
      .expect("create upload");
    let reservation = store
      .begin_append(&upload.id, &owner(), &binding(), 0, 4)
      .await
      .expect("reserve append");
    let error = store
      .commit_fully_inspected_part(&reservation, &evidence(b"dat"), body(b"data"))
      .await
      .expect_err("stream bytes beyond inspected evidence cannot commit");
    assert!(is_rejection(&error, UploadRejection::Conflict));
  }

  #[tokio::test]
  async fn cancellation_never_exposes_an_undurable_offset() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let config = new_store_config(directory.path());
    let store = Arc::new(LocalUploadStore::open(&config).await.expect("open store"));
    let upload = store
      .create(create_request(
        profile(UploadDestinationConfig::Object, 64),
        Some(4),
      ))
      .await
      .expect("create upload");
    let reservation = store
      .begin_append(&upload.id, &owner(), &binding(), 0, 4)
      .await
      .expect("reserve append");
    let partial = futures_util::stream::once(async { Ok(Bytes::from_static(b"data")) })
      .chain(futures_util::stream::pending::<anyhow::Result<Bytes>>());
    let committing = {
      let store = store.clone();
      tokio::spawn(async move {
        store
          .commit_fully_inspected_part(&reservation, &evidence(b"data"), Box::pin(partial))
          .await
      })
    };
    for _ in 0..100 {
      if std::fs::read_dir(store_root(&config).join("staging"))
        .expect("read staging directory")
        .next()
        .is_some()
      {
        break;
      }
      tokio::task::yield_now().await;
    }
    committing.abort();
    let _ = committing.await;
    assert_eq!(
      store
        .lookup(&upload.id, &owner(), &binding())
        .await
        .expect("lookup after cancellation")
        .offset,
      0
    );
    drop(store);
    assert_eq!(
      LocalUploadStore::open(&config)
        .await
        .expect("reopen after cancellation")
        .lookup(&upload.id, &owner(), &binding())
        .await
        .expect("durable offset after cancellation")
        .offset,
      0
    );
  }
}

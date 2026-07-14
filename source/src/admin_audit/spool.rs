//! Crash-recoverable, bounded local spool for Admin audit events.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::config::AdminAuditSpoolConfig;
use crate::metrics::Metrics;

use super::event::{AdminAuditEvent, unsigned_event_value};
use super::integrity::{AuditHmacKey, IntegrityChain, IntegrityVerifier};

#[path = "spool_io.rs"]
mod spool_io;
use spool_io::{remove_uncommitted_temporary_files, secure_create_new, secure_open_read};

const HEAD_FILE: &str = "chain-head.json";
const LOCK_FILE: &str = ".writer.lock";
const RECORD_EXTENSION: &str = "audit";

#[derive(Clone)]
pub(super) struct AdminAuditSpool {
  inner: Arc<SpoolInner>,
}

struct SpoolInner {
  directory: PathBuf,
  directory_file: File,
  _lock_file: nix::fcntl::Flock<File>,
  max_bytes: u64,
  max_events: usize,
  max_event_bytes: usize,
  hmac_key: Option<AuditHmacKey>,
  metrics: Arc<Metrics>,
  state: Mutex<SpoolState>,
}

struct SpoolState {
  chain: IntegrityChain,
  replay_cursor: ReplayCursor,
  bytes: u64,
  events: usize,
  reserved_bytes: u64,
  reserved_events: usize,
  poisoned: bool,
}

struct ReplayCursor {
  chain_id: String,
  next_sequence: u64,
  previous_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChainHead {
  chain_id: String,
  next_sequence: u64,
  previous_hash: String,
}

#[derive(Debug)]
pub(super) struct SpoolEntry {
  pub path: PathBuf,
  pub event: AdminAuditEvent,
}

pub(super) struct AdminAuditSpoolReservation {
  inner: Arc<SpoolInner>,
  active: bool,
}

impl AdminAuditSpool {
  pub(super) fn new(
    config: &AdminAuditSpoolConfig,
    hmac_key: Option<AuditHmacKey>,
    metrics: Arc<Metrics>,
  ) -> anyhow::Result<Self> {
    let directory = config
      .directory
      .as_deref()
      .context("admin.audit.spool.directory is required")?;
    initialize_directory(directory)?;
    let directory_file = secure_open_read(directory)?;
    let lock_file = acquire_writer_lock(directory)?;
    remove_uncommitted_temporary_files(directory)?;
    let (chain, replay_cursor, bytes, events) = recover_state(directory, hmac_key.clone())?;
    metrics.set_admin_audit_spool_usage(events as u64, bytes);
    Ok(Self {
      inner: Arc::new(SpoolInner {
        directory: directory.to_path_buf(),
        directory_file,
        _lock_file: lock_file,
        max_bytes: config.max_bytes,
        max_events: config.max_events,
        max_event_bytes: config.max_event_bytes,
        hmac_key,
        metrics,
        state: Mutex::new(SpoolState {
          chain,
          replay_cursor,
          bytes,
          events,
          reserved_bytes: 0,
          reserved_events: 0,
          poisoned: false,
        }),
      }),
    })
  }

  pub(super) async fn append(&self, event: AdminAuditEvent) -> anyhow::Result<AdminAuditEvent> {
    let inner = Arc::clone(&self.inner);
    tokio::task::spawn_blocking(move || inner.append_sync(event))
      .await
      .context("Admin audit spool append task failed")?
  }

  pub(super) async fn append_with_terminal_reservation(
    &self,
    event: AdminAuditEvent,
  ) -> anyhow::Result<(AdminAuditEvent, AdminAuditSpoolReservation)> {
    let inner = Arc::clone(&self.inner);
    tokio::task::spawn_blocking(move || {
      SpoolInner::append_with_terminal_reservation_sync(inner, event)
    })
    .await
    .context("Admin audit spool intent append task failed")?
  }

  pub(super) async fn next_entry(&self) -> anyhow::Result<Option<SpoolEntry>> {
    let inner = Arc::clone(&self.inner);
    tokio::task::spawn_blocking(move || inner.next_entry_sync())
      .await
      .context("Admin audit spool read task failed")?
  }

  pub(super) async fn acknowledge(&self, path: PathBuf) -> anyhow::Result<()> {
    let inner = Arc::clone(&self.inner);
    tokio::task::spawn_blocking(move || inner.acknowledge_sync(&path))
      .await
      .context("Admin audit spool acknowledgement task failed")?
  }
}

impl AdminAuditSpoolReservation {
  pub(super) async fn commit(self, event: AdminAuditEvent) -> anyhow::Result<AdminAuditEvent> {
    tokio::task::spawn_blocking(move || {
      let mut reservation = self;
      let result = reservation.inner.append_reserved_sync(event);
      if result.is_ok() {
        reservation.active = false;
      }
      result
    })
    .await
    .context("Admin audit spool reserved append task failed")?
  }
}

impl Drop for AdminAuditSpoolReservation {
  fn drop(&mut self) {
    if self.active {
      self.inner.release_terminal_reservation_sync();
      self.active = false;
    }
  }
}

#[derive(Clone, Copy)]
enum AppendCapacity {
  Ordinary,
  ReserveTerminal,
  ConsumeReservation,
}

impl SpoolInner {
  fn append_sync(&self, event: AdminAuditEvent) -> anyhow::Result<AdminAuditEvent> {
    self.append_with_capacity_sync(event, AppendCapacity::Ordinary)
  }

  fn append_with_terminal_reservation_sync(
    inner: Arc<Self>,
    event: AdminAuditEvent,
  ) -> anyhow::Result<(AdminAuditEvent, AdminAuditSpoolReservation)> {
    let event = inner.append_with_capacity_sync(event, AppendCapacity::ReserveTerminal)?;
    Ok((
      event,
      AdminAuditSpoolReservation {
        inner,
        active: true,
      },
    ))
  }

  fn append_reserved_sync(&self, event: AdminAuditEvent) -> anyhow::Result<AdminAuditEvent> {
    self.append_with_capacity_sync(event, AppendCapacity::ConsumeReservation)
  }

  fn append_with_capacity_sync(
    &self,
    mut event: AdminAuditEvent,
    capacity: AppendCapacity,
  ) -> anyhow::Result<AdminAuditEvent> {
    let mut state = self.state.lock().expect("Admin audit spool lock poisoned");
    ensure!(!state.poisoned, "Admin audit spool requires recovery");
    ensure!(
      !event.event_id.is_empty() && !event.timestamp.is_empty(),
      "Admin audit event metadata is unavailable"
    );
    event.integrity = None;
    let payload = unsigned_event_value(&event)?;
    let restore = (
      state.chain.chain_id().to_string(),
      state.chain.next_sequence(),
      state.chain.previous_hash(),
    );
    event.integrity = Some(state.chain.seal(&payload)?);
    let encoded = serde_json::to_vec(&event).context("failed to encode Admin audit spool event")?;
    if encoded.len() > self.max_event_bytes {
      state.chain =
        IntegrityChain::restore(restore.0, restore.1, &restore.2, self.hmac_key.clone())?;
      bail!("Admin audit event exceeds the configured spool event limit");
    }
    let encoded_len = u64::try_from(encoded.len()).context("Admin audit event is too large")?;
    let max_event_bytes =
      u64::try_from(self.max_event_bytes).context("Admin audit event limit is too large")?;
    let capacity_available = match capacity {
      AppendCapacity::Ordinary => {
        state.events.saturating_add(state.reserved_events) < self.max_events
          && state
            .bytes
            .saturating_add(state.reserved_bytes)
            .saturating_add(encoded_len)
            <= self.max_bytes
      }
      AppendCapacity::ReserveTerminal => {
        state
          .events
          .saturating_add(state.reserved_events)
          .saturating_add(2)
          <= self.max_events
          && state
            .bytes
            .saturating_add(state.reserved_bytes)
            .saturating_add(encoded_len)
            .saturating_add(max_event_bytes)
            <= self.max_bytes
      }
      AppendCapacity::ConsumeReservation => {
        state.reserved_events > 0 && state.reserved_bytes >= max_event_bytes
      }
    };
    if !capacity_available {
      state.chain =
        IntegrityChain::restore(restore.0, restore.1, &restore.2, self.hmac_key.clone())?;
      bail!("Admin audit spool is full");
    }

    let envelope = event
      .integrity
      .as_ref()
      .context("sealed Admin audit event is missing integrity metadata")?;
    let final_name = format!(
      "{:020}-{}.{}",
      envelope.sequence, event.event_id, RECORD_EXTENSION
    );
    let temporary_name = format!(".tmp-{}", event.event_id);
    let temporary_path = self.directory.join(&temporary_name);
    let final_path = self.directory.join(final_name);
    let write_result = (|| -> anyhow::Result<()> {
      let mut file = secure_create_new(&temporary_path)?;
      file
        .write_all(&encoded)
        .context("failed to write Admin audit spool event")?;
      file
        .sync_all()
        .context("failed to fsync Admin audit spool event")?;
      fs::rename(&temporary_path, &final_path)
        .context("failed to commit Admin audit spool event")?;
      self
        .directory_file
        .sync_all()
        .context("failed to fsync Admin audit spool directory")?;
      write_chain_head(&self.directory, &self.directory_file, &state.chain)?;
      Ok(())
    })();
    if let Err(error) = write_result {
      let _ = fs::remove_file(&temporary_path);
      if final_path.exists() {
        state.poisoned = true;
      } else {
        state.chain =
          IntegrityChain::restore(restore.0, restore.1, &restore.2, self.hmac_key.clone())?;
      }
      return Err(error);
    }

    state.events = state.events.saturating_add(1);
    state.bytes = state.bytes.saturating_add(encoded_len);
    match capacity {
      AppendCapacity::Ordinary => {}
      AppendCapacity::ReserveTerminal => {
        state.reserved_events = state.reserved_events.saturating_add(1);
        state.reserved_bytes = state.reserved_bytes.saturating_add(max_event_bytes);
      }
      AppendCapacity::ConsumeReservation => {
        state.reserved_events = state.reserved_events.saturating_sub(1);
        state.reserved_bytes = state.reserved_bytes.saturating_sub(max_event_bytes);
      }
    }
    self
      .metrics
      .set_admin_audit_spool_usage(state.events as u64, state.bytes);
    Ok(event)
  }

  fn release_terminal_reservation_sync(&self) {
    let mut state = self.state.lock().expect("Admin audit spool lock poisoned");
    let max_event_bytes = u64::try_from(self.max_event_bytes).unwrap_or(u64::MAX);
    state.reserved_events = state.reserved_events.saturating_sub(1);
    state.reserved_bytes = state.reserved_bytes.saturating_sub(max_event_bytes);
  }

  fn next_entry_sync(&self) -> anyhow::Result<Option<SpoolEntry>> {
    let state = self.state.lock().expect("Admin audit spool lock poisoned");
    let paths = record_paths(&self.directory)?;
    ensure!(
      paths.len() == state.events,
      "Admin audit spool inventory changed outside the writer"
    );
    let Some(path) = paths.into_iter().next() else {
      return Ok(None);
    };
    let event = read_and_verify_record(&path, self.hmac_key.clone())?;
    verify_replay_cursor(&state.replay_cursor, &event)?;
    Ok(Some(SpoolEntry { path, event }))
  }

  fn acknowledge_sync(&self, path: &Path) -> anyhow::Result<()> {
    let mut state = self.state.lock().expect("Admin audit spool lock poisoned");
    ensure!(
      path.parent() == Some(self.directory.as_path()),
      "Admin audit spool acknowledgement escaped its directory"
    );
    let event = read_and_verify_record(path, self.hmac_key.clone())?;
    verify_replay_cursor(&state.replay_cursor, &event)?;
    let envelope = event
      .integrity
      .as_ref()
      .context("Admin audit spool event is missing integrity metadata")?;
    let metadata = fs::symlink_metadata(path).with_context(|| {
      format!(
        "failed to inspect Admin audit spool event {}",
        path.display()
      )
    })?;
    ensure!(
      metadata.file_type().is_file(),
      "Admin audit spool event is not a regular file"
    );
    let size = metadata.len();
    fs::remove_file(path).with_context(|| {
      format!(
        "failed to remove Admin audit spool event {}",
        path.display()
      )
    })?;
    self
      .directory_file
      .sync_all()
      .context("failed to fsync Admin audit spool acknowledgement")?;
    state.events = state.events.saturating_sub(1);
    state.bytes = state.bytes.saturating_sub(size);
    state.replay_cursor.next_sequence = envelope
      .sequence
      .checked_add(1)
      .context("Admin audit replay sequence is exhausted")?;
    state.replay_cursor.previous_hash = envelope.event_hash.clone();
    self
      .metrics
      .set_admin_audit_spool_usage(state.events as u64, state.bytes);
    Ok(())
  }
}

fn initialize_directory(path: &Path) -> anyhow::Result<()> {
  if !path.exists() {
    fs::create_dir_all(path)
      .with_context(|| format!("failed to create Admin audit spool {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
  }
  let metadata = fs::symlink_metadata(path)
    .with_context(|| format!("failed to inspect Admin audit spool {}", path.display()))?;
  ensure!(
    metadata.file_type().is_dir(),
    "Admin audit spool must be a directory"
  );
  ensure!(
    metadata.permissions().mode() & 0o022 == 0,
    "Admin audit spool must not be group- or world-writable"
  );
  Ok(())
}

fn acquire_writer_lock(directory: &Path) -> anyhow::Result<nix::fcntl::Flock<File>> {
  let path = directory.join(LOCK_FILE);
  let file = OpenOptions::new()
    .read(true)
    .write(true)
    .create(true)
    .mode(0o600)
    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
    .open(&path)
    .with_context(|| format!("failed to open Admin audit spool lock {}", path.display()))?;
  nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock).map_err(
    |(_, error)| anyhow::anyhow!("Admin audit spool is already owned by another writer: {error}"),
  )
}

fn recover_state(
  directory: &Path,
  hmac_key: Option<AuditHmacKey>,
) -> anyhow::Result<(IntegrityChain, ReplayCursor, u64, usize)> {
  let head_path = directory.join(HEAD_FILE);
  let head = if head_path.exists() {
    let mut encoded = Vec::new();
    secure_open_read(&head_path)?.read_to_end(&mut encoded)?;
    Some(serde_json::from_slice::<ChainHead>(&encoded).context("invalid Admin audit chain head")?)
  } else {
    None
  };
  let paths = record_paths(directory)?;
  let mut bytes = 0_u64;
  let mut first: Option<ReplayCursor> = None;
  let mut last: Option<(String, u64, String)> = None;
  for path in &paths {
    let metadata = fs::symlink_metadata(path)?;
    bytes = bytes.saturating_add(metadata.len());
    let event = read_and_verify_record(path, hmac_key.clone())?;
    let envelope = event
      .integrity
      .context("Admin audit spool event is not sealed")?;
    first.get_or_insert_with(|| ReplayCursor {
      chain_id: envelope.chain_id.clone(),
      next_sequence: envelope.sequence,
      previous_hash: envelope.previous_hash.clone(),
    });
    if let Some((chain_id, sequence, event_hash)) = &last {
      ensure!(
        envelope.chain_id == *chain_id,
        "Admin audit spool contains multiple chain IDs"
      );
      ensure!(
        envelope.sequence == sequence.saturating_add(1),
        "Admin audit spool contains a sequence gap"
      );
      ensure!(
        envelope.previous_hash == *event_hash,
        "Admin audit spool chain is discontinuous"
      );
    }
    last = Some((envelope.chain_id, envelope.sequence, envelope.event_hash));
  }

  let chain = match head {
    Some(head) => {
      if let Some((chain_id, sequence, event_hash)) = &last {
        ensure!(
          *chain_id == head.chain_id,
          "Admin audit chain head ID does not match spooled events"
        );
        ensure!(
          sequence.saturating_add(1) == head.next_sequence,
          "Admin audit spool tail does not match the chain head"
        );
        ensure!(
          *event_hash == head.previous_hash,
          "Admin audit chain head hash does not match"
        );
      }
      IntegrityChain::restore(
        head.chain_id,
        head.next_sequence,
        &head.previous_hash,
        hmac_key,
      )?
    }
    None if paths.is_empty() => IntegrityChain::new(hmac_key)?,
    None => bail!("Admin audit spool contains events without a chain head"),
  };
  let replay_cursor = first.unwrap_or_else(|| ReplayCursor {
    chain_id: chain.chain_id().to_string(),
    next_sequence: chain.next_sequence(),
    previous_hash: chain.previous_hash(),
  });
  Ok((chain, replay_cursor, bytes, paths.len()))
}

fn verify_replay_cursor(cursor: &ReplayCursor, event: &AdminAuditEvent) -> anyhow::Result<()> {
  let envelope = event
    .integrity
    .as_ref()
    .context("Admin audit spool event is missing integrity metadata")?;
  ensure!(
    envelope.chain_id == cursor.chain_id
      && envelope.sequence == cursor.next_sequence
      && envelope.previous_hash == cursor.previous_hash,
    "Admin audit spool replay order or chain continuity changed"
  );
  Ok(())
}

fn read_and_verify_record(
  path: &Path,
  hmac_key: Option<AuditHmacKey>,
) -> anyhow::Result<AdminAuditEvent> {
  let mut encoded = Vec::new();
  secure_open_read(path)?.read_to_end(&mut encoded)?;
  let event: AdminAuditEvent = serde_json::from_slice(&encoded)
    .with_context(|| format!("invalid Admin audit spool event {}", path.display()))?;
  let envelope = event
    .integrity
    .as_ref()
    .context("Admin audit spool event is missing integrity metadata")?;
  let payload = unsigned_event_value(&event)?;
  let mut verifier = IntegrityVerifier::restore(
    envelope.chain_id.clone(),
    envelope.sequence,
    &envelope.previous_hash,
    hmac_key,
  )?;
  verifier.verify_and_advance(&payload, envelope)?;
  Ok(event)
}

fn write_chain_head(
  directory: &Path,
  directory_file: &File,
  chain: &IntegrityChain,
) -> anyhow::Result<()> {
  let head = ChainHead {
    chain_id: chain.chain_id().to_string(),
    next_sequence: chain.next_sequence(),
    previous_hash: chain.previous_hash(),
  };
  let encoded = serde_json::to_vec(&head)?;
  let temporary = directory.join(".tmp-chain-head");
  let final_path = directory.join(HEAD_FILE);
  let mut file = secure_create_new(&temporary)?;
  file.write_all(&encoded)?;
  file.sync_all()?;
  fs::rename(&temporary, &final_path)?;
  directory_file.sync_all()?;
  Ok(())
}

fn record_paths(directory: &Path) -> anyhow::Result<Vec<PathBuf>> {
  let mut paths = Vec::new();
  for entry in fs::read_dir(directory)? {
    let entry = entry?;
    let path = entry.path();
    let name = entry.file_name();
    let name = name.to_string_lossy();
    if matches!(name.as_ref(), HEAD_FILE | LOCK_FILE) || name.starts_with(".tmp-") {
      continue;
    }
    let metadata = fs::symlink_metadata(&path)?;
    ensure!(
      metadata.file_type().is_file(),
      "Admin audit spool contains a non-regular entry"
    );
    ensure!(
      path.extension().and_then(|value| value.to_str()) == Some(RECORD_EXTENSION),
      "Admin audit spool contains an unexpected file"
    );
    paths.push(path);
  }
  paths.sort();
  Ok(paths)
}

#[cfg(test)]
mod tests {
  use http::{Method, StatusCode};
  use serde_json::Value;

  use super::*;
  use crate::admin_audit::AdminAuditHandle;

  fn config(path: &Path) -> AdminAuditSpoolConfig {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    AdminAuditSpoolConfig {
      enabled: true,
      directory: Some(path.to_path_buf()),
      max_bytes: 1024 * 1024,
      max_events: 2,
      max_event_bytes: 64 * 1024,
    }
  }

  fn event() -> AdminAuditEvent {
    AdminAuditHandle::new(
      "127.0.0.1:1234".parse().unwrap(),
      "https",
      &Method::POST,
      "/admin/v1/config/load",
      None,
    )
    .finish(StatusCode::OK)
  }

  #[tokio::test]
  async fn spooled_events_are_bounded_recoverable_and_acknowledged() {
    let temp = tempfile::tempdir().unwrap();
    let metrics = Arc::new(Metrics::default());
    let spool = AdminAuditSpool::new(&config(temp.path()), None, metrics.clone()).unwrap();
    let first = spool.append(event()).await.unwrap();
    let second = spool.append(event()).await.unwrap();
    assert!(first.integrity.is_some());
    assert!(second.integrity.is_some());
    assert!(
      spool
        .append(event())
        .await
        .unwrap_err()
        .to_string()
        .contains("full")
    );

    let entry = spool.next_entry().await.unwrap().unwrap();
    assert_eq!(entry.event.event_id, first.event_id);
    spool.acknowledge(entry.path).await.unwrap();
    assert!(spool.append(event()).await.is_ok());
  }

  #[tokio::test]
  async fn required_intent_reserves_terminal_capacity_before_the_handler() {
    let temp = tempfile::tempdir().unwrap();
    let spool =
      AdminAuditSpool::new(&config(temp.path()), None, Arc::new(Metrics::default())).unwrap();
    let (intent, reservation) = spool
      .append_with_terminal_reservation(event())
      .await
      .unwrap();
    assert!(intent.integrity.is_some());
    assert!(
      spool
        .append(event())
        .await
        .unwrap_err()
        .to_string()
        .contains("full"),
      "ordinary appends must not consume the reserved terminal slot"
    );
    let terminal = reservation.commit(event()).await.unwrap();
    assert_eq!(
      terminal.integrity.as_ref().unwrap().sequence,
      intent.integrity.as_ref().unwrap().sequence + 1
    );
    assert!(
      spool
        .append(event())
        .await
        .unwrap_err()
        .to_string()
        .contains("full"),
      "the committed intent and terminal should occupy both configured slots"
    );
  }

  #[tokio::test]
  async fn tampered_spool_event_fails_verification() {
    let temp = tempfile::tempdir().unwrap();
    let spool =
      AdminAuditSpool::new(&config(temp.path()), None, Arc::new(Metrics::default())).unwrap();
    spool.append(event()).await.unwrap();
    let path = record_paths(temp.path()).unwrap().remove(0);
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["action"] = Value::String("tampered".to_string());
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(
      spool
        .next_entry()
        .await
        .unwrap_err()
        .to_string()
        .contains("event hash")
    );
  }

  #[tokio::test]
  async fn missing_spool_tail_fails_startup_recovery() {
    let temp = tempfile::tempdir().unwrap();
    let mut spool_config = config(temp.path());
    spool_config.max_events = 4;
    let spool = AdminAuditSpool::new(&spool_config, None, Arc::new(Metrics::default())).unwrap();
    for _ in 0..3 {
      spool.append(event()).await.unwrap();
    }
    let tail = record_paths(temp.path()).unwrap().pop().unwrap();
    fs::remove_file(tail).unwrap();
    drop(spool);

    let error = AdminAuditSpool::new(&spool_config, None, Arc::new(Metrics::default()))
      .err()
      .expect("missing spool tail must fail recovery");
    assert!(error.to_string().contains("tail does not match"), "{error}");
  }

  #[tokio::test]
  async fn live_spool_inventory_deletion_blocks_replay() {
    let temp = tempfile::tempdir().unwrap();
    let mut spool_config = config(temp.path());
    spool_config.max_events = 4;
    let spool = AdminAuditSpool::new(&spool_config, None, Arc::new(Metrics::default())).unwrap();
    for _ in 0..3 {
      spool.append(event()).await.unwrap();
    }
    let removed = record_paths(temp.path()).unwrap().pop().unwrap();
    fs::remove_file(removed).unwrap();

    let error = spool.next_entry().await.unwrap_err();
    assert!(error.to_string().contains("inventory changed"), "{error}");
  }
}

//! Bounded QUIC Initial CRYPTO reassembly.
//!
//! This module owns only unauthenticated, pre-session state. It is deliberately
//! separate from established QUIC forwarding sessions so incomplete Initials
//! cannot evict a live local or forwarded connection.

use std::collections::{HashMap, hash_map::Entry};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::{debug, trace};

use crate::config::QuicInitialReassemblyConfig;
use crate::metrics::QuicInitialReassemblyOutcome;
use crate::sni_forward::client_hello::raw_client_hello_sni;

const QUIC_CID_MAX_LEN: usize = 20;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FixedCid {
  len: u8,
  bytes: [u8; QUIC_CID_MAX_LEN],
}

impl FixedCid {
  fn new(value: &[u8]) -> Self {
    let mut bytes = [0; QUIC_CID_MAX_LEN];
    let len = value.len().min(QUIC_CID_MAX_LEN);
    bytes[..len].copy_from_slice(&value[..len]);
    Self {
      len: len as u8,
      bytes,
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct InitialKey {
  peer: SocketAddr,
  version: u32,
  dcid: FixedCid,
  scid: FixedCid,
}

#[derive(Debug)]
pub(super) struct InspectedInitial {
  key: InitialKey,
  pub(super) client_scid: Vec<u8>,
  pub(super) version: u32,
  pub(super) header_bytes: usize,
  pub(super) decrypted_bytes: usize,
  frames: Vec<quic_parser::CryptoFrame>,
  datagram: Vec<u8>,
}

impl InspectedInitial {
  pub(super) fn frames_len(&self) -> usize {
    self.frames.len()
  }

  pub(super) fn crypto_frame_bytes(&self) -> usize {
    self.frames.iter().map(|frame| frame.data.len()).sum()
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InspectError {
  Header,
  Decrypt,
  CryptoFrames,
  EmptyCrypto,
}

impl InspectError {
  pub(super) const fn stage(self) -> &'static str {
    match self {
      Self::Header => "initial_header",
      Self::Decrypt => "initial_decrypt",
      Self::CryptoFrames => "crypto_frames",
      Self::EmptyCrypto => "crypto_frames",
    }
  }

  pub(super) const fn reason(self) -> &'static str {
    match self {
      Self::Header => "invalid_initial_header",
      Self::Decrypt => "initial_decryption_failed",
      Self::CryptoFrames => "invalid_crypto_frames",
      Self::EmptyCrypto => "empty_crypto",
    }
  }
}

pub(super) fn inspect_initial(
  datagram: &[u8],
  peer: SocketAddr,
) -> Result<InspectedInitial, InspectError> {
  let header = quic_parser::parse_initial(datagram).map_err(|_| InspectError::Header)?;
  let key = InitialKey {
    peer,
    version: header.version,
    dcid: FixedCid::new(header.dcid),
    scid: FixedCid::new(header.scid),
  };
  let header_bytes = header.header_bytes.len();
  let client_scid = header.scid.to_vec();
  let decrypted = quic_parser::decrypt_initial(&header).map_err(|_| InspectError::Decrypt)?;
  let decrypted_bytes = decrypted.len();
  let frames =
    quic_parser::parse_crypto_frames(&decrypted).map_err(|_| InspectError::CryptoFrames)?;
  if !frames.iter().any(|frame| !frame.data.is_empty()) {
    return Err(InspectError::EmptyCrypto);
  }
  Ok(InspectedInitial {
    key,
    client_scid,
    version: header.version,
    header_bytes,
    decrypted_bytes,
    frames,
    datagram: datagram.to_vec(),
  })
}

#[derive(Clone, Copy, Debug)]
pub(super) struct InitialReassemblyLimits {
  max_pending_sessions: usize,
  max_fragments_per_session: usize,
  max_datagrams_per_session: usize,
  max_buffered_datagram_bytes_per_session: usize,
  max_total_buffered_bytes: usize,
  pub(super) timeout: Duration,
  client_hello_max_bytes: usize,
}

impl InitialReassemblyLimits {
  pub(super) fn new(
    config: &QuicInitialReassemblyConfig,
    client_hello_max_bytes: usize,
    tls_handshake_timeout_ms: u64,
  ) -> Self {
    Self {
      max_pending_sessions: config.max_pending_sessions,
      max_fragments_per_session: config.max_fragments_per_session,
      max_datagrams_per_session: config.max_datagrams_per_session,
      max_buffered_datagram_bytes_per_session: config.max_buffered_datagram_bytes_per_session,
      max_total_buffered_bytes: config.max_total_buffered_bytes,
      timeout: Duration::from_millis(config.timeout_ms.min(tls_handshake_timeout_ms)),
      client_hello_max_bytes,
    }
  }
}

#[derive(Debug)]
struct PendingInitial {
  first_seen: Instant,
  crypto: Vec<CryptoSegment>,
  contributing_fragments: usize,
  datagrams: Vec<Vec<u8>>,
  raw_datagram_bytes: usize,
}

#[derive(Debug)]
struct CryptoSegment {
  offset: u64,
  data: Vec<u8>,
}

impl CryptoSegment {
  fn end(&self) -> u64 {
    self.offset.saturating_add(self.data.len() as u64)
  }
}

impl PendingInitial {
  fn reserved_bytes(&self) -> usize {
    self.raw_datagram_bytes.saturating_add(
      self
        .crypto
        .iter()
        .map(|segment| segment.data.len())
        .sum::<usize>(),
    )
  }

  fn contiguous_crypto(&self) -> Vec<u8> {
    let mut result = Vec::new();
    for segment in &self.crypto {
      if segment.offset != result.len() as u64 {
        break;
      }
      result.extend_from_slice(&segment.data);
    }
    result
  }
}

#[derive(Debug, Default)]
struct PendingState {
  entries: HashMap<InitialKey, PendingInitial>,
  reserved_bytes: usize,
}

/// State shared by every SO_REUSEPORT worker of one logical listener.
#[derive(Debug, Default)]
pub(super) struct SharedInitialReassembly {
  state: Mutex<PendingState>,
  diagnostics: Mutex<InitialDiagnosticSampler>,
}

#[derive(Debug, Default)]
struct InitialDiagnosticSampler {
  last_emitted: Option<Instant>,
  suppressed_since_last: u64,
}

#[derive(Clone, Copy)]
pub(super) struct InitialDiagnosticTrace {
  pub(super) version: Option<u32>,
  pub(super) header_bytes: usize,
  pub(super) decrypted_bytes: usize,
  pub(super) crypto_frame_bytes: usize,
  pub(super) crypto_frames: usize,
  pub(super) retained_pending_sessions: usize,
  pub(super) retained_crypto_bytes: usize,
  pub(super) retained_segments: usize,
  pub(super) retained_datagrams: usize,
  pub(super) retained_datagram_bytes: usize,
}

#[derive(Debug)]
pub(super) struct ReplayBatch {
  pub(super) datagrams: Vec<Vec<u8>>,
  _reservation: Option<ReplayReservation>,
}

#[cfg(test)]
impl ReplayBatch {
  pub(super) fn for_test(datagrams: Vec<Vec<u8>>) -> Self {
    Self {
      datagrams,
      _reservation: None,
    }
  }
}

#[derive(Debug)]
struct ReplayReservation {
  shared: Arc<SharedInitialReassembly>,
  bytes: usize,
}

impl Drop for ReplayReservation {
  fn drop(&mut self) {
    let mut state = lock_state(&self.shared.state);
    state.reserved_bytes = state.reserved_bytes.saturating_sub(self.bytes);
  }
}

#[derive(Debug)]
pub(super) struct CompletedInitial {
  pub(super) sni: Option<String>,
  pub(super) client_scid: Vec<u8>,
  pub(super) batch: ReplayBatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReassemblyReject {
  Expired,
  Capacity,
  Limit,
  OverlapConflict,
  ParseFailure,
}

impl ReassemblyReject {
  pub(super) const fn outcome(self) -> Option<QuicInitialReassemblyOutcome> {
    match self {
      Self::Expired => None,
      Self::Capacity => Some(QuicInitialReassemblyOutcome::CapacityRejected),
      Self::Limit => Some(QuicInitialReassemblyOutcome::LimitRejected),
      Self::OverlapConflict => Some(QuicInitialReassemblyOutcome::OverlapConflict),
      Self::ParseFailure => None,
    }
  }

  pub(super) const fn stage(self) -> &'static str {
    match self {
      Self::Expired => "reassembly_timeout",
      Self::Capacity => "reassembly_admission",
      Self::Limit => "reassembly_limits",
      Self::OverlapConflict => "crypto_reassembly",
      Self::ParseFailure => "client_hello",
    }
  }

  pub(super) const fn reason(self) -> &'static str {
    match self {
      Self::Expired => "absolute_deadline_elapsed",
      Self::Capacity => "pending_capacity",
      Self::Limit => "reassembly_limit",
      Self::OverlapConflict => "overlap_conflict",
      Self::ParseFailure => "invalid_client_hello",
    }
  }
}

pub(super) enum ReassemblyResult {
  Pending,
  Completed(CompletedInitial),
  Rejected(ReassemblyReject),
}

pub(super) struct IngestResult {
  pub(super) result: ReassemblyResult,
  pub(super) expired: usize,
}

impl SharedInitialReassembly {
  pub(super) fn emit_diagnostic(
    &self,
    peer: SocketAddr,
    classification_mode: &'static str,
    stage: &'static str,
    reason: &'static str,
    datagram_bytes: usize,
    details: InitialDiagnosticTrace,
  ) {
    let trace_enabled = tracing::enabled!(tracing::Level::TRACE);
    let debug_enabled = tracing::enabled!(tracing::Level::DEBUG);
    if !trace_enabled && !debug_enabled {
      return;
    }
    let now = Instant::now();
    let suppressed_since_last = {
      let mut sampler = self
        .diagnostics
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
      if sampler
        .last_emitted
        .is_some_and(|last| now.duration_since(last) < Duration::from_secs(1))
      {
        sampler.suppressed_since_last = sampler.suppressed_since_last.saturating_add(1);
        return;
      }
      sampler.last_emitted = Some(now);
      let suppressed = sampler.suppressed_since_last;
      sampler.suppressed_since_last = 0;
      suppressed
    };
    if trace_enabled {
      trace!(
        peer = %peer,
        classification_mode,
        stage,
        reason,
        datagram_bytes,
        suppressed_since_last,
        version = ?details.version,
        header_bytes = details.header_bytes,
        decrypted_bytes = details.decrypted_bytes,
        crypto_frame_bytes = details.crypto_frame_bytes,
        crypto_frames = details.crypto_frames,
        retained_pending_sessions = details.retained_pending_sessions,
        retained_crypto_bytes = details.retained_crypto_bytes,
        retained_segments = details.retained_segments,
        retained_datagrams = details.retained_datagrams,
        retained_datagram_bytes = details.retained_datagram_bytes,
        "QUIC Initial SNI inspection diagnostic"
      );
    } else {
      debug!(
        peer = %peer,
        classification_mode,
        stage,
        reason,
        datagram_bytes,
        suppressed_since_last,
        "QUIC Initial SNI inspection diagnostic"
      );
    }
  }

  pub(super) fn expire(&self, now: Instant, limits: InitialReassemblyLimits) -> usize {
    let mut state = lock_state(&self.state);
    let expired: Vec<_> = state
      .entries
      .iter()
      .filter_map(|(key, entry)| {
        (now.duration_since(entry.first_seen) >= limits.timeout).then_some(*key)
      })
      .collect();
    let count = expired.len();
    for key in expired {
      remove_entry(&mut state, key);
    }
    count
  }

  /// Drops only pending map entries. Replay batches retain their separate
  /// reservations until their owners complete or drop.
  pub(super) fn clear_pending(&self) {
    let mut state = lock_state(&self.state);
    let pending_bytes = state
      .entries
      .values()
      .map(PendingInitial::reserved_bytes)
      .sum::<usize>();
    state.entries.clear();
    state.reserved_bytes = state.reserved_bytes.saturating_sub(pending_bytes);
  }

  pub(super) fn diagnostic_aggregate(&self) -> ReassemblyDiagnosticAggregate {
    let state = lock_state(&self.state);
    ReassemblyDiagnosticAggregate {
      retained_pending_sessions: state.entries.len(),
      retained_crypto_bytes: state
        .entries
        .values()
        .map(|entry| {
          entry
            .crypto
            .iter()
            .map(|segment| segment.data.len())
            .sum::<usize>()
        })
        .sum(),
      retained_segments: state.entries.values().map(|entry| entry.crypto.len()).sum(),
      retained_datagrams: state
        .entries
        .values()
        .map(|entry| entry.datagrams.len())
        .sum(),
      retained_datagram_bytes: state
        .entries
        .values()
        .map(|entry| entry.raw_datagram_bytes)
        .sum(),
    }
  }

  pub(super) fn ingest(
    self: &Arc<Self>,
    initial: InspectedInitial,
    now: Instant,
    limits: InitialReassemblyLimits,
  ) -> IngestResult {
    let mut state = lock_state(&self.state);
    let expired: Vec<_> = state
      .entries
      .iter()
      .filter_map(|(key, entry)| {
        (now.duration_since(entry.first_seen) >= limits.timeout).then_some(*key)
      })
      .collect();
    let expired_count = expired.len();
    let expired_current = expired.contains(&initial.key);
    for key in expired {
      remove_entry(&mut state, key);
    }
    if expired_current {
      return IngestResult {
        result: ReassemblyResult::Rejected(ReassemblyReject::Expired),
        expired: expired_count,
      };
    }

    // Bound per-datagram overlap work as well as retained sparse segments.
    // Fully covered or empty CRYPTO frames do not consume retained bytes, but
    // they still cost parser and comparison work and therefore count here.
    if initial.frames.len() > limits.max_fragments_per_session {
      remove_entry(&mut state, initial.key);
      return IngestResult {
        result: ReassemblyResult::Rejected(ReassemblyReject::Limit),
        expired: expired_count,
      };
    }

    let pending_at_capacity = state.entries.len() >= limits.max_pending_sessions;
    let candidate_at_capacity = match state.entries.entry(initial.key) {
      Entry::Occupied(_) => false,
      Entry::Vacant(entry) => {
        // A new Initial can complete without retaining a pending slot. Keep an
        // at-capacity candidate under this same mutex so it uses the listener's
        // shared byte budget, then remove it if reconstruction remains pending;
        // every state observer takes this mutex and cannot see the extra entry.
        entry.insert(PendingInitial {
          first_seen: now,
          crypto: Vec::new(),
          contributing_fragments: 0,
          datagrams: Vec::new(),
          raw_datagram_bytes: 0,
        });
        pending_at_capacity
      }
    };

    let mut datagram_contributed = false;
    for frame in &initial.frames {
      if frame.data.is_empty() {
        continue;
      }
      let Some(end) = frame.offset.checked_add(frame.data.len() as u64) else {
        remove_entry(&mut state, initial.key);
        return IngestResult {
          result: ReassemblyResult::Rejected(ReassemblyReject::Limit),
          expired: expired_count,
        };
      };
      if end > limits.client_hello_max_bytes as u64 {
        remove_entry(&mut state, initial.key);
        return IngestResult {
          result: ReassemblyResult::Rejected(ReassemblyReject::Limit),
          expired: expired_count,
        };
      }

      let (new_bytes, conflict) = {
        let Some(entry) = state.entries.get(&initial.key) else {
          return IngestResult {
            result: ReassemblyResult::Rejected(ReassemblyReject::Limit),
            expired: expired_count,
          };
        };
        let mut conflict = false;
        let mut covered = 0usize;
        for segment in &entry.crypto {
          let overlap_start = frame.offset.max(segment.offset);
          let overlap_end = end.min(segment.end());
          if overlap_start < overlap_end {
            let frame_start = (overlap_start - frame.offset) as usize;
            let segment_start = (overlap_start - segment.offset) as usize;
            let overlap_len = (overlap_end - overlap_start) as usize;
            if frame.data[frame_start..frame_start + overlap_len]
              != segment.data[segment_start..segment_start + overlap_len]
            {
              conflict = true;
              break;
            }
            covered = covered.saturating_add(overlap_len);
          }
        }
        (frame.data.len().saturating_sub(covered), conflict)
      };
      if conflict {
        remove_entry(&mut state, initial.key);
        return IngestResult {
          result: ReassemblyResult::Rejected(ReassemblyReject::OverlapConflict),
          expired: expired_count,
        };
      }
      if new_bytes == 0 {
        continue;
      }
      let adds_datagram = !datagram_contributed;
      let raw_addition = usize::from(adds_datagram) * initial.datagram.len();
      let limits_rejected = {
        let Some(entry) = state.entries.get(&initial.key) else {
          return IngestResult {
            result: ReassemblyResult::Rejected(ReassemblyReject::Limit),
            expired: expired_count,
          };
        };
        entry.contributing_fragments >= limits.max_fragments_per_session
          || (adds_datagram
            && (entry.datagrams.len() >= limits.max_datagrams_per_session
              || entry
                .raw_datagram_bytes
                .saturating_add(initial.datagram.len())
                > limits.max_buffered_datagram_bytes_per_session))
      } || state
        .reserved_bytes
        .saturating_add(new_bytes)
        .saturating_add(raw_addition)
        > limits.max_total_buffered_bytes;
      if limits_rejected {
        remove_entry(&mut state, initial.key);
        return IngestResult {
          result: ReassemblyResult::Rejected(ReassemblyReject::Limit),
          expired: expired_count,
        };
      }

      {
        let Some(entry) = state.entries.get_mut(&initial.key) else {
          return IngestResult {
            result: ReassemblyResult::Rejected(ReassemblyReject::Limit),
            expired: expired_count,
          };
        };
        merge_crypto_segment(&mut entry.crypto, frame.offset, &frame.data);
        entry.contributing_fragments = entry.contributing_fragments.saturating_add(1);
        if adds_datagram {
          entry.raw_datagram_bytes = entry
            .raw_datagram_bytes
            .saturating_add(initial.datagram.len());
          entry.datagrams.push(initial.datagram.clone());
        }
      }
      state.reserved_bytes = state.reserved_bytes.saturating_add(new_bytes);
      if adds_datagram {
        state.reserved_bytes = state.reserved_bytes.saturating_add(initial.datagram.len());
        datagram_contributed = true;
      }
    }

    let Some(entry) = state.entries.get(&initial.key) else {
      return IngestResult {
        result: ReassemblyResult::Rejected(ReassemblyReject::Limit),
        expired: expired_count,
      };
    };
    let contiguous = entry.contiguous_crypto();
    if contiguous.len() < 4 {
      return pending_or_capacity(
        &mut state,
        initial.key,
        candidate_at_capacity,
        expired_count,
      );
    };
    let declared_len = 4usize.saturating_add(
      ((contiguous[1] as usize) << 16) | ((contiguous[2] as usize) << 8) | contiguous[3] as usize,
    );
    if contiguous[0] != 0x01 {
      remove_entry(&mut state, initial.key);
      return IngestResult {
        result: ReassemblyResult::Rejected(ReassemblyReject::ParseFailure),
        expired: expired_count,
      };
    }
    if declared_len > limits.client_hello_max_bytes {
      remove_entry(&mut state, initial.key);
      return IngestResult {
        result: ReassemblyResult::Rejected(ReassemblyReject::Limit),
        expired: expired_count,
      };
    }
    if contiguous.len() < declared_len {
      return pending_or_capacity(
        &mut state,
        initial.key,
        candidate_at_capacity,
        expired_count,
      );
    }
    let client_hello = contiguous[..declared_len].to_vec();
    let Some(entry) = state.entries.remove(&initial.key) else {
      return IngestResult {
        result: ReassemblyResult::Rejected(ReassemblyReject::Limit),
        expired: expired_count,
      };
    };
    let bytes = entry.reserved_bytes();
    let batch = ReplayBatch {
      datagrams: entry.datagrams,
      _reservation: Some(ReplayReservation {
        shared: self.clone(),
        bytes,
      }),
    };
    drop(state);
    let sni = match raw_client_hello_sni(&client_hello) {
      Ok(sni) => sni,
      Err(_) => {
        return IngestResult {
          result: ReassemblyResult::Rejected(ReassemblyReject::ParseFailure),
          expired: expired_count,
        };
      }
    };
    IngestResult {
      result: ReassemblyResult::Completed(CompletedInitial {
        sni,
        client_scid: initial.client_scid,
        batch,
      }),
      expired: expired_count,
    }
  }

  #[cfg(test)]
  pub(super) fn reserved_bytes(&self) -> usize {
    lock_state(&self.state).reserved_bytes
  }

  #[cfg(test)]
  pub(super) fn pending_len(&self) -> usize {
    lock_state(&self.state).entries.len()
  }
}

#[derive(Clone, Copy, Default)]
pub(super) struct ReassemblyDiagnosticAggregate {
  pub(super) retained_pending_sessions: usize,
  pub(super) retained_crypto_bytes: usize,
  pub(super) retained_segments: usize,
  pub(super) retained_datagrams: usize,
  pub(super) retained_datagram_bytes: usize,
}

fn remove_entry(state: &mut PendingState, key: InitialKey) {
  if let Some(entry) = state.entries.remove(&key) {
    state.reserved_bytes = state.reserved_bytes.saturating_sub(entry.reserved_bytes());
  }
}

fn pending_or_capacity(
  state: &mut PendingState,
  key: InitialKey,
  candidate_at_capacity: bool,
  expired: usize,
) -> IngestResult {
  let result = if candidate_at_capacity {
    remove_entry(state, key);
    ReassemblyResult::Rejected(ReassemblyReject::Capacity)
  } else {
    ReassemblyResult::Pending
  };
  IngestResult { result, expired }
}

/// Merges a verified-compatible CRYPTO range into sorted, non-overlapping
/// storage. Compatibility is checked before this function is called.
fn merge_crypto_segment(segments: &mut Vec<CryptoSegment>, offset: u64, data: &[u8]) {
  segments.push(CryptoSegment {
    offset,
    data: data.to_vec(),
  });
  segments.sort_by_key(|segment| segment.offset);
  let mut merged: Vec<CryptoSegment> = Vec::with_capacity(segments.len());
  for mut segment in segments.drain(..) {
    let Some(last) = merged.last_mut() else {
      merged.push(segment);
      continue;
    };
    let last_end = last.end();
    if segment.offset <= last_end {
      let overlap = (last_end - segment.offset) as usize;
      if overlap < segment.data.len() {
        last
          .data
          .extend_from_slice(&segment.data.split_off(overlap));
      }
    } else {
      merged.push(segment);
    }
  }
  *segments = merged;
}

/// Exercises the checked sparse-range merge used by the QUIC Initial path
/// without retaining live peer state.
#[cfg(feature = "fuzzing")]
pub(super) fn exercise_crypto_range_merge(data: &[u8]) {
  let mut segments = Vec::new();
  for chunk in data.chunks(9).take(64) {
    if chunk.len() < 2 {
      break;
    }
    let offset = u64::from(chunk[0]) << 8 | u64::from(chunk[1]);
    let payload = &chunk[2..];
    let Some(end) = offset.checked_add(payload.len() as u64) else {
      continue;
    };
    let compatible = segments.iter().all(|segment: &CryptoSegment| {
      let overlap_start = offset.max(segment.offset);
      let overlap_end = end.min(segment.end());
      overlap_start >= overlap_end
        || payload[(overlap_start - offset) as usize..(overlap_end - offset) as usize]
          == segment.data
            [(overlap_start - segment.offset) as usize..(overlap_end - segment.offset) as usize]
    });
    if compatible {
      merge_crypto_segment(&mut segments, offset, payload);
    }
  }
  let pending = PendingInitial {
    first_seen: Instant::now(),
    crypto: segments,
    contributing_fragments: 0,
    datagrams: Vec::new(),
    raw_datagram_bytes: 0,
  };
  let _ = pending.contiguous_crypto();
}

fn lock_state(state: &Mutex<PendingState>) -> std::sync::MutexGuard<'_, PendingState> {
  state
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
  use super::*;

  fn hello() -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0; 32]);
    body.push(0); // session ID
    body.extend_from_slice(&[0, 2, 0x13, 0x01]); // one cipher suite
    body.extend_from_slice(&[1, 0]); // null compression
    let len = body.len();
    let mut hello = vec![0x01, (len >> 16) as u8, (len >> 8) as u8, len as u8];
    hello.extend_from_slice(&body);
    hello
  }

  fn limits(configure: impl FnOnce(&mut QuicInitialReassemblyConfig)) -> InitialReassemblyLimits {
    let mut config = QuicInitialReassemblyConfig::default();
    configure(&mut config);
    InitialReassemblyLimits::new(&config, 1024, 10_000)
  }

  fn inspected(peer: SocketAddr, offset: u64, bytes: &[u8], datagram_tag: u8) -> InspectedInitial {
    InspectedInitial {
      key: InitialKey {
        peer,
        version: 1,
        dcid: FixedCid::new(&[1, datagram_tag]),
        scid: FixedCid::new(&[2, datagram_tag]),
      },
      client_scid: vec![2, datagram_tag],
      version: 1,
      header_bytes: 20,
      decrypted_bytes: bytes.len(),
      frames: vec![quic_parser::CryptoFrame {
        offset,
        data: bytes.to_vec(),
      }],
      datagram: vec![datagram_tag; bytes.len().max(1)],
    }
  }

  fn initial_reserved_bytes(initial: &InspectedInitial) -> usize {
    initial.datagram.len()
      + initial
        .frames
        .iter()
        .map(|frame| frame.data.len())
        .sum::<usize>()
  }

  fn pending(result: IngestResult) {
    assert!(matches!(result.result, ReassemblyResult::Pending));
  }

  #[test]
  fn completes_in_order_and_releases_replay_reservation_on_drop() {
    let shared = Arc::new(SharedInitialReassembly::default());
    let data = hello();
    let peer = "127.0.0.1:10001".parse().unwrap();
    let now = Instant::now();
    pending(shared.ingest(inspected(peer, 0, &data[..8], 1), now, limits(|_| {})));
    let complete = shared.ingest(inspected(peer, 8, &data[8..], 1), now, limits(|_| {}));
    let ReassemblyResult::Completed(completed) = complete.result else {
      panic!("contiguous ClientHello should complete");
    };
    assert_eq!(completed.sni, None);
    assert_eq!(completed.batch.datagrams.len(), 2);
    assert_eq!(shared.pending_len(), 0);
    assert!(
      shared.reserved_bytes() > 0,
      "batch still owns the reservation"
    );
    drop(completed);
    assert_eq!(shared.reserved_bytes(), 0);
  }

  #[test]
  fn completed_replay_batch_holds_the_global_budget_until_drop() {
    let shared = Arc::new(SharedInitialReassembly::default());
    let data = hello();
    let now = Instant::now();
    let first: SocketAddr = "127.0.0.1:10007".parse().unwrap();
    let second: SocketAddr = "127.0.0.1:10008".parse().unwrap();
    let generous = limits(|config| config.max_total_buffered_bytes = 1024);
    pending(shared.ingest(inspected(first, 0, &data[..8], 11), now, generous));
    let complete = shared.ingest(inspected(first, 8, &data[8..], 11), now, generous);
    let ReassemblyResult::Completed(completed) = complete.result else {
      panic!("first flow should complete");
    };
    let held_budget = shared.reserved_bytes();
    assert!(matches!(
      shared
        .ingest(
          inspected(second, 0, &[1, 0, 0, 16], 12),
          now,
          limits(|config| config.max_total_buffered_bytes = held_budget),
        )
        .result,
      ReassemblyResult::Rejected(ReassemblyReject::Limit)
    ));
    drop(completed);
    pending(shared.ingest(
      inspected(second, 0, &[1, 0, 0, 16], 12),
      now,
      limits(|config| config.max_total_buffered_bytes = held_budget),
    ));
  }

  #[test]
  fn completes_out_of_order_and_deduplicates_identical_retransmit() {
    let shared = Arc::new(SharedInitialReassembly::default());
    let data = hello();
    let peer = "127.0.0.1:10002".parse().unwrap();
    let now = Instant::now();
    pending(shared.ingest(inspected(peer, 8, &data[8..], 2), now, limits(|_| {})));
    let reserved = shared.reserved_bytes();
    pending(shared.ingest(inspected(peer, 8, &data[8..], 2), now, limits(|_| {})));
    assert_eq!(shared.reserved_bytes(), reserved);
    let complete = shared.ingest(inspected(peer, 0, &data[..8], 2), now, limits(|_| {}));
    assert!(matches!(complete.result, ReassemblyResult::Completed(_)));
  }

  #[test]
  fn conflicting_overlap_is_terminal() {
    let shared = Arc::new(SharedInitialReassembly::default());
    let peer = "127.0.0.1:10003".parse().unwrap();
    let now = Instant::now();
    pending(shared.ingest(inspected(peer, 0, &[1, 0, 0, 8], 3), now, limits(|_| {})));
    let result = shared.ingest(inspected(peer, 2, &[9, 8], 3), now, limits(|_| {}));
    assert!(matches!(
      result.result,
      ReassemblyResult::Rejected(ReassemblyReject::OverlapConflict)
    ));
    assert_eq!(shared.pending_len(), 0);
    assert_eq!(shared.reserved_bytes(), 0);
  }

  #[test]
  fn fragment_limit_bounds_duplicate_frames_within_one_datagram() {
    let shared = Arc::new(SharedInitialReassembly::default());
    let peer = "127.0.0.1:10009".parse().unwrap();
    let now = Instant::now();
    let mut packet = inspected(peer, 0, &[1, 0, 0, 16], 13);
    packet.frames.push(quic_parser::CryptoFrame {
      offset: 0,
      data: vec![1, 0, 0, 16],
    });

    let result = shared.ingest(
      packet,
      now,
      limits(|config| config.max_fragments_per_session = 1),
    );

    assert!(matches!(
      result.result,
      ReassemblyResult::Rejected(ReassemblyReject::Limit)
    ));
    assert_eq!(shared.pending_len(), 0);
    assert_eq!(shared.reserved_bytes(), 0);
  }

  #[test]
  fn full_pending_table_admits_complete_single_datagram_candidate() {
    let shared = Arc::new(SharedInitialReassembly::default());
    let now = Instant::now();
    let incumbent: SocketAddr = "127.0.0.1:10010".parse().unwrap();
    let candidate: SocketAddr = "127.0.0.1:10011".parse().unwrap();
    let limits = limits(|config| config.max_pending_sessions = 1);
    pending(shared.ingest(inspected(incumbent, 0, &[1, 0, 0, 16], 14), now, limits));
    let baseline = shared.reserved_bytes();

    let data = hello();
    let mut initial = inspected(candidate, 8, &data[8..], 15);
    initial.frames.push(quic_parser::CryptoFrame {
      offset: 0,
      data: data[..8].to_vec(),
    });
    let result = shared.ingest(initial, now, limits);
    let ReassemblyResult::Completed(completed) = result.result else {
      panic!("complete at-capacity candidate should not require a pending slot");
    };

    assert_eq!(completed.batch.datagrams.len(), 1);
    assert_eq!(shared.pending_len(), 1);
    assert!(shared.reserved_bytes() > baseline);
    drop(completed);
    assert_eq!(shared.pending_len(), 1);
    assert_eq!(shared.reserved_bytes(), baseline);
  }

  #[test]
  fn full_pending_table_rejects_incomplete_candidates_without_retention() {
    let shared = Arc::new(SharedInitialReassembly::default());
    let now = Instant::now();
    let incumbent: SocketAddr = "127.0.0.1:10012".parse().unwrap();
    let limits = limits(|config| config.max_pending_sessions = 1);
    pending(shared.ingest(inspected(incumbent, 0, &[1, 0, 0, 16], 16), now, limits));
    let baseline = shared.reserved_bytes();

    for (peer, bytes, tag) in [
      ("127.0.0.1:10013", &[1, 0, 0][..], 17),
      ("127.0.0.1:10014", &[1, 0, 0, 16][..], 18),
    ] {
      assert!(matches!(
        shared
          .ingest(inspected(peer.parse().unwrap(), 0, bytes, tag), now, limits)
          .result,
        ReassemblyResult::Rejected(ReassemblyReject::Capacity)
      ));
      assert_eq!(shared.pending_len(), 1);
      assert_eq!(shared.reserved_bytes(), baseline);
    }
  }

  #[test]
  fn at_capacity_candidates_share_the_global_replay_budget() {
    let shared = Arc::new(SharedInitialReassembly::default());
    let now = Instant::now();
    let incumbent: SocketAddr = "127.0.0.1:10015".parse().unwrap();
    pending(shared.ingest(
      inspected(incumbent, 0, &[1, 0, 0, 16], 19),
      now,
      limits(|config| config.max_pending_sessions = 1),
    ));
    let baseline = shared.reserved_bytes();
    let candidate = inspected("127.0.0.1:10016".parse().unwrap(), 0, &hello(), 20);
    let exact_budget = baseline.saturating_add(initial_reserved_bytes(&candidate));
    assert!(matches!(
      shared
        .ingest(
          candidate,
          now,
          limits(|config| {
            config.max_pending_sessions = 1;
            config.max_total_buffered_bytes = exact_budget.saturating_sub(1);
          }),
        )
        .result,
      ReassemblyResult::Rejected(ReassemblyReject::Limit)
    ));
    assert_eq!(shared.pending_len(), 1);
    assert_eq!(shared.reserved_bytes(), baseline);

    let start = Arc::new(std::sync::Barrier::new(3));
    let mut handles = Vec::new();
    for (peer, tag) in [("127.0.0.1:10017", 21), ("127.0.0.1:10018", 22)] {
      let shared = shared.clone();
      let start = start.clone();
      handles.push(std::thread::spawn(move || {
        let initial = inspected(peer.parse().unwrap(), 0, &hello(), tag);
        start.wait();
        shared.ingest(
          initial,
          now,
          limits(|config| {
            config.max_pending_sessions = 1;
            config.max_total_buffered_bytes = exact_budget;
          }),
        )
      }));
    }
    start.wait();
    let results: Vec<_> = handles
      .into_iter()
      .map(|handle| handle.join().expect("candidate thread should not panic"))
      .collect();

    assert_eq!(
      results
        .iter()
        .filter(|result| matches!(&result.result, ReassemblyResult::Completed(_)))
        .count(),
      1
    );
    assert_eq!(
      results
        .iter()
        .filter(|result| {
          matches!(
            &result.result,
            ReassemblyResult::Rejected(ReassemblyReject::Limit)
          )
        })
        .count(),
      1
    );
    assert_eq!(shared.pending_len(), 1);
    assert_eq!(shared.reserved_bytes(), exact_budget);
    drop(results);
    assert_eq!(shared.pending_len(), 1);
    assert_eq!(shared.reserved_bytes(), baseline);
  }

  #[test]
  fn enforces_pending_fragment_datagram_and_byte_limits() {
    let now = Instant::now();
    let first: SocketAddr = "127.0.0.1:10004".parse().unwrap();
    let second: SocketAddr = "127.0.0.1:10005".parse().unwrap();

    let shared = Arc::new(SharedInitialReassembly::default());
    pending(shared.ingest(
      inspected(first, 0, &[1, 0, 0, 16], 4),
      now,
      limits(|config| config.max_pending_sessions = 1),
    ));
    assert!(matches!(
      shared
        .ingest(
          inspected(second, 0, &[1, 0, 0, 16], 5),
          now,
          limits(|config| config.max_pending_sessions = 1)
        )
        .result,
      ReassemblyResult::Rejected(ReassemblyReject::Capacity)
    ));

    let shared = Arc::new(SharedInitialReassembly::default());
    pending(shared.ingest(
      inspected(first, 0, &[1, 0, 0, 16], 6),
      now,
      limits(|config| config.max_fragments_per_session = 1),
    ));
    assert!(matches!(
      shared
        .ingest(
          inspected(first, 8, &[0, 0], 6),
          now,
          limits(|config| config.max_fragments_per_session = 1)
        )
        .result,
      ReassemblyResult::Rejected(ReassemblyReject::Limit)
    ));

    let shared = Arc::new(SharedInitialReassembly::default());
    pending(shared.ingest(
      inspected(first, 0, &[1, 0, 0, 16], 7),
      now,
      limits(|config| config.max_datagrams_per_session = 1),
    ));
    assert!(matches!(
      shared
        .ingest(
          inspected(first, 8, &[0, 0], 7),
          now,
          limits(|config| config.max_datagrams_per_session = 1)
        )
        .result,
      ReassemblyResult::Rejected(ReassemblyReject::Limit)
    ));

    let shared = Arc::new(SharedInitialReassembly::default());
    assert!(matches!(
      shared
        .ingest(
          inspected(first, 0, &[1, 0, 0, 16], 8),
          now,
          limits(|config| config.max_buffered_datagram_bytes_per_session = 3),
        )
        .result,
      ReassemblyResult::Rejected(ReassemblyReject::Limit)
    ));
    let shared = Arc::new(SharedInitialReassembly::default());
    assert!(matches!(
      shared
        .ingest(
          inspected(first, 0, &[1, 0, 0, 16], 9),
          now,
          limits(|config| config.max_total_buffered_bytes = 3),
        )
        .result,
      ReassemblyResult::Rejected(ReassemblyReject::Limit)
    ));
  }

  #[test]
  fn ingress_expiry_preserves_absolute_deadline_and_rejects_that_packet() {
    let shared = Arc::new(SharedInitialReassembly::default());
    let peer = "127.0.0.1:10006".parse().unwrap();
    let now = Instant::now();
    let limits = limits(|config| config.timeout_ms = 1);
    pending(shared.ingest(inspected(peer, 0, &[1, 0, 0, 16], 10), now, limits));
    let expired = shared.ingest(
      inspected(peer, 4, &[0, 0], 10),
      now + Duration::from_millis(1),
      limits,
    );
    assert_eq!(expired.expired, 1);
    assert!(matches!(
      expired.result,
      ReassemblyResult::Rejected(ReassemblyReject::Expired)
    ));
    assert_eq!(shared.pending_len(), 0);
  }
}

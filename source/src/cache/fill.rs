use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime};

use tokio::sync::Notify;

use crate::shared_state::SharedCacheLock;

const FILL_SHARDS: usize = 64;
const SHORT_SUPPRESSION_TTL: Duration = Duration::from_secs(1);
const LONG_SUPPRESSION_TTL: Duration = Duration::from_secs(10);
const MAX_SUPPRESSIONS_PER_SHARD: usize = 256;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum CacheFillSuppressionReason {
  ResponseNoStore,
  ResponsePrivate,
  SetCookie,
  AdmissionRejected,
  TooLarge,
  VaryRejected,
  StoreFailed,
  Unknown,
}

impl CacheFillSuppressionReason {
  pub(crate) fn ttl(self) -> Duration {
    match self {
      Self::ResponseNoStore
      | Self::ResponsePrivate
      | Self::SetCookie
      | Self::AdmissionRejected
      | Self::TooLarge
      | Self::VaryRejected => LONG_SUPPRESSION_TTL,
      Self::StoreFailed | Self::Unknown => SHORT_SUPPRESSION_TTL,
    }
  }

  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::ResponseNoStore => "response_no_store",
      Self::ResponsePrivate => "response_private",
      Self::SetCookie => "set_cookie",
      Self::AdmissionRejected => "admission_rejected",
      Self::TooLarge => "too_large",
      Self::VaryRejected => "vary_rejected",
      Self::StoreFailed => "store_failed",
      Self::Unknown => "unknown",
    }
  }
}

#[derive(Debug)]
pub(crate) enum CacheFillDecision {
  Leader(CacheFillGuard),
  Follower(CacheFillWaiter),
  SharedConflict,
  Suppressed(CacheFillSuppressionReason),
}

#[derive(Debug)]
pub struct CacheFillGuard {
  coordinator: Weak<CacheFillCoordinator>,
  key: String,
  notify: Arc<Notify>,
  _shared_lock: Option<SharedCacheLock>,
}

impl CacheFillGuard {
  pub(crate) fn set_shared_lock(&mut self, shared_lock: SharedCacheLock) {
    self._shared_lock = Some(shared_lock);
  }
}

#[derive(Debug, Clone)]
pub struct CacheFillWaiter {
  notify: Arc<Notify>,
}

impl CacheFillWaiter {
  pub async fn wait(self) {
    self.notify.notified().await;
  }

  pub async fn wait_timeout(self, timeout: Duration) -> bool {
    tokio::time::timeout(timeout, self.notify.notified())
      .await
      .is_ok()
  }
}

impl Drop for CacheFillGuard {
  fn drop(&mut self) {
    let Some(coordinator) = self.coordinator.upgrade() else {
      self.notify.notify_waiters();
      return;
    };
    let notify = coordinator.finish(&self.key, &self.notify);
    notify.notify_waiters();
  }
}

#[derive(Debug)]
pub(crate) struct CacheFillCoordinator {
  shards: [Mutex<CacheFillShard>; FILL_SHARDS],
}

#[derive(Debug, Default)]
struct CacheFillShard {
  inflight: HashMap<String, Arc<Notify>>,
  suppressed_until: HashMap<String, SuppressedFill>,
  suppressed_order: VecDeque<String>,
}

#[derive(Debug, Clone, Copy)]
struct SuppressedFill {
  until: SystemTime,
  reason: CacheFillSuppressionReason,
}

impl CacheFillCoordinator {
  pub(crate) fn new() -> Arc<Self> {
    Arc::new(Self {
      shards: std::array::from_fn(|_| Mutex::new(CacheFillShard::default())),
    })
  }

  pub(crate) fn begin(self: &Arc<Self>, key: String) -> CacheFillDecision {
    let shard_index = shard_index(&key);
    let now = SystemTime::now();
    let mut shard = self.shards[shard_index]
      .lock()
      .expect("cache fill shard lock poisoned");
    prune_suppressions(&mut shard, now);
    if let Some(suppressed) = shard.suppressed_until.get(&key)
      && suppressed.until > now
    {
      return CacheFillDecision::Suppressed(suppressed.reason);
    }
    if let Some(notify) = shard.inflight.get(&key) {
      return CacheFillDecision::Follower(CacheFillWaiter {
        notify: notify.clone(),
      });
    }
    let notify = Arc::new(Notify::new());
    shard.inflight.insert(key.clone(), notify.clone());
    CacheFillDecision::Leader(CacheFillGuard {
      coordinator: Arc::downgrade(self),
      key,
      notify,
      _shared_lock: None,
    })
  }

  pub(crate) fn suppress(&self, key: String, reason: CacheFillSuppressionReason) {
    let shard_index = shard_index(&key);
    let now = SystemTime::now();
    let mut shard = self.shards[shard_index]
      .lock()
      .expect("cache fill shard lock poisoned");
    prune_suppressions(&mut shard, now);
    if !shard.suppressed_until.contains_key(&key) {
      shard.suppressed_order.push_back(key.clone());
    }
    shard.suppressed_until.insert(
      key,
      SuppressedFill {
        until: now + reason.ttl(),
        reason,
      },
    );
    while shard.suppressed_until.len() > MAX_SUPPRESSIONS_PER_SHARD {
      let Some(oldest) = shard.suppressed_order.pop_front() else {
        break;
      };
      shard.suppressed_until.remove(&oldest);
    }
  }

  fn finish(&self, key: &str, fallback: &Arc<Notify>) -> Arc<Notify> {
    let shard_index = shard_index(key);
    let mut shard = self.shards[shard_index]
      .lock()
      .expect("cache fill shard lock poisoned");
    shard
      .inflight
      .remove(key)
      .unwrap_or_else(|| fallback.clone())
  }
}

fn prune_suppressions(shard: &mut CacheFillShard, now: SystemTime) {
  while let Some(oldest) = shard.suppressed_order.front() {
    let expired = shard
      .suppressed_until
      .get(oldest)
      .is_none_or(|suppressed| suppressed.until <= now);
    if !expired {
      break;
    }
    if let Some(oldest) = shard.suppressed_order.pop_front() {
      shard.suppressed_until.remove(&oldest);
    }
  }
}

fn shard_index(key: &str) -> usize {
  let mut hasher = DefaultHasher::new();
  key.hash(&mut hasher);
  (hasher.finish() as usize) % FILL_SHARDS
}

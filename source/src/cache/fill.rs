//! Cache fill coordination.
//! One fill owner streams the upstream response while waiters observe the committed entry.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, SystemTime};

use tokio::sync::Notify;

use crate::overload::{OverloadRuntime, WorkKind, WorkLease};
use crate::runtime_health::{
  PROCESS_GENERATION, RuntimeHealth, RuntimeSubsystem, RuntimeSubsystemState,
};
use crate::shared_state::SharedCacheLock;

use super::{CacheLookupContext, ResponseCache, request_no_store};

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
  _overload_lease: Option<WorkLease>,
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
  runtime_health: Arc<RuntimeHealth>,
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
  pub(crate) fn new(runtime_health: Arc<RuntimeHealth>) -> Arc<Self> {
    Arc::new(Self {
      shards: std::array::from_fn(|_| Mutex::new(CacheFillShard::default())),
      runtime_health,
    })
  }

  fn shard_guard(&self, shard_index: usize) -> MutexGuard<'_, CacheFillShard> {
    match self.shards[shard_index].lock() {
      Ok(shard) => shard,
      Err(poisoned) => {
        let mut shard = poisoned.into_inner();
        for notify in shard.inflight.values() {
          notify.notify_waiters();
        }
        *shard = CacheFillShard::default();
        self.shards[shard_index].clear_poison();
        self
          .runtime_health
          .record_lock_recovery(RuntimeSubsystem::CacheFill);
        self.runtime_health.set_subsystem_state(
          PROCESS_GENERATION,
          RuntimeSubsystem::CacheFill,
          RuntimeSubsystemState::Healthy,
          false,
        );
        shard
      }
    }
  }

  pub(crate) fn begin(
    self: &Arc<Self>,
    key: String,
    overload: Option<Arc<OverloadRuntime>>,
  ) -> CacheFillDecision {
    let shard_index = shard_index(&key);
    let now = SystemTime::now();
    let mut shard = self.shard_guard(shard_index);
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
      _overload_lease: overload.map(|runtime| runtime.lease(WorkKind::CacheFillConcurrency, 1)),
    })
  }

  pub(crate) fn suppress(&self, key: String, reason: CacheFillSuppressionReason) {
    let shard_index = shard_index(&key);
    let now = SystemTime::now();
    let mut shard = self.shard_guard(shard_index);
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
    let mut shard = self.shard_guard(shard_index);
    match shard.inflight.get(key) {
      Some(current) if Arc::ptr_eq(current, fallback) => shard
        .inflight
        .remove(key)
        .unwrap_or_else(|| fallback.clone()),
      Some(_) | None => fallback.clone(),
    }
  }
}

impl ResponseCache {
  pub(crate) fn begin_fill_decision(
    self: &Arc<Self>,
    ctx: CacheLookupContext<'_>,
  ) -> Option<CacheFillDecision> {
    if !self.config.lock || !self.policy_enabled(ctx.policy_name, ctx.method) {
      return None;
    }
    if request_no_store(ctx.request_headers, &self.bypass_request_headers) {
      return None;
    }
    let overload = self.overload.load().clone();
    if overload
      .as_ref()
      .is_some_and(|runtime| runtime.cache_fill_disabled() || runtime.prefer_cached_or_stale())
    {
      return None;
    }
    let key = self
      .operation_context(
        ctx.policy_name,
        ctx.scheme,
        ctx.host,
        ctx.method,
        ctx.uri,
        ctx.request_headers,
      )?
      .fill_key;
    match self.fills.begin(key.clone(), overload) {
      CacheFillDecision::Leader(guard) => Some(CacheFillDecision::Leader(guard)),
      CacheFillDecision::Follower(waiter) => Some(CacheFillDecision::Follower(waiter)),
      CacheFillDecision::SharedConflict => Some(CacheFillDecision::SharedConflict),
      CacheFillDecision::Suppressed(reason) => Some(CacheFillDecision::Suppressed(reason)),
    }
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

#[cfg(test)]
mod tests {
  use std::panic::AssertUnwindSafe;
  use std::time::Duration;

  use super::*;

  #[tokio::test]
  async fn poisoned_fill_shard_wakes_waiters_without_evicting_replacement_leader() {
    let health = Arc::new(RuntimeHealth::default());
    let coordinator = CacheFillCoordinator::new(health.clone());
    let key = "https://example.test/stampede".to_string();
    let old_leader = match coordinator.begin(key.clone(), None) {
      CacheFillDecision::Leader(leader) => leader,
      other => panic!("first fill should lead, got {other:?}"),
    };
    let mut notifications = Vec::new();
    for _ in 0..16 {
      let waiter = match coordinator.begin(key.clone(), None) {
        CacheFillDecision::Follower(waiter) => waiter,
        other => panic!("concurrent fill should wait, got {other:?}"),
      };
      let mut notification = Box::pin(waiter.notify.clone().notified_owned());
      assert!(
        !notification.as_mut().enable(),
        "waiter should not observe a notification before recovery"
      );
      notifications.push(notification);
    }

    let shard_index = shard_index(&key);
    let poisoned = std::panic::catch_unwind(AssertUnwindSafe(|| {
      let _shard = coordinator.shards[shard_index]
        .lock()
        .expect("cache fill shard should start healthy");
      panic!("injected cache fill shard poison");
    }));
    assert!(poisoned.is_err(), "injected poison should panic");

    let replacement_leader = match coordinator.begin(key.clone(), None) {
      CacheFillDecision::Leader(leader) => leader,
      other => panic!("recovery should elect a replacement leader, got {other:?}"),
    };
    for notification in notifications {
      tokio::time::timeout(Duration::from_secs(1), notification)
        .await
        .expect("poison recovery should wake every registered waiter");
    }

    drop(old_leader);
    let replacement_waiter = match coordinator.begin(key.clone(), None) {
      CacheFillDecision::Follower(waiter) => waiter,
      other => panic!("stale leader drop must not evict replacement, got {other:?}"),
    };
    let mut replacement_notification = Box::pin(replacement_waiter.notify.notified_owned());
    assert!(!replacement_notification.as_mut().enable());
    drop(replacement_leader);
    tokio::time::timeout(Duration::from_secs(1), replacement_notification)
      .await
      .expect("replacement leader drop should wake its waiter");
    assert!(matches!(
      coordinator.begin(key, None),
      CacheFillDecision::Leader(_)
    ));

    let mut metrics = String::new();
    health.append_prometheus(&mut metrics);
    assert!(metrics.contains("oxibelt_runtime_lock_recoveries_total{subsystem=\"cache_fill\"} 1"));
  }
}

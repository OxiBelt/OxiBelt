//! Bounded physical reclamation after authoritative QUERY epoch fencing.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Weak};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinSet;

use crate::config::CacheQueryCleanupConfig;
use crate::metrics::Metrics;

use super::*;

#[derive(Debug)]
pub(super) struct QueryCleanupDispatcher {
  sender: mpsc::Sender<QueryCleanupRequest>,
  permits: Arc<Semaphore>,
  metrics: Arc<Metrics>,
  batch_size: usize,
  max_concurrent: usize,
}

#[derive(Debug)]
pub(super) struct QueryCleanupRequest {
  target: CacheQueryInvalidationTarget,
  before_epoch: u64,
  local_pending: bool,
  shared_pending: bool,
  shared_expiry_pending: bool,
  external_pending: bool,
  _permit: OwnedSemaphorePermit,
}

impl QueryCleanupRequest {
  fn merge(&mut self, newer: Self) {
    self.before_epoch = self.before_epoch.max(newer.before_epoch);
    self.local_pending |= newer.local_pending;
    self.shared_pending |= newer.shared_pending;
    self.shared_expiry_pending |= newer.shared_expiry_pending;
    self.external_pending |= newer.external_pending;
  }

  fn pending(&self) -> bool {
    self.local_pending || self.shared_pending || self.shared_expiry_pending || self.external_pending
  }
}

#[derive(Debug)]
struct QueryCleanupOutcome {
  request: QueryCleanupRequest,
  entries: usize,
  succeeded: bool,
}

impl QueryCleanupDispatcher {
  pub(super) fn new(
    config: &CacheQueryCleanupConfig,
    metrics: Arc<Metrics>,
  ) -> (Self, mpsc::Receiver<QueryCleanupRequest>) {
    let queue_capacity = config.queue_capacity.clamp(1, 1024);
    let (sender, receiver) = mpsc::channel(queue_capacity);
    (
      Self {
        sender,
        permits: Arc::new(Semaphore::new(queue_capacity)),
        metrics,
        batch_size: config.batch_size.clamp(1, 512),
        max_concurrent: config.max_concurrent.clamp(1, 4),
      },
      receiver,
    )
  }

  pub(super) fn start(
    &self,
    cache: Weak<ResponseCache>,
    receiver: mpsc::Receiver<QueryCleanupRequest>,
  ) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
      return;
    };
    handle.spawn(run_dispatcher(
      cache,
      receiver,
      self.metrics.clone(),
      self.batch_size,
      self.max_concurrent,
    ));
  }

  pub(super) fn enqueue(
    &self,
    target: CacheQueryInvalidationTarget,
    before_epoch: u64,
    shared_pending: bool,
    external_pending: bool,
  ) {
    let Ok(permit) = self.permits.clone().try_acquire_owned() else {
      self.metrics.record_cache_query_cleanup_enqueue_started();
      self.metrics.record_cache_query_cleanup_enqueue_failed();
      return;
    };
    let request = QueryCleanupRequest {
      target,
      before_epoch,
      local_pending: true,
      shared_pending,
      shared_expiry_pending: shared_pending,
      external_pending,
      _permit: permit,
    };
    self.metrics.record_cache_query_cleanup_enqueue_started();
    match self.sender.try_send(request) {
      Ok(()) => self.metrics.record_cache_query_cleanup_enqueued(),
      Err(_) => self.metrics.record_cache_query_cleanup_enqueue_failed(),
    }
  }
}

async fn run_dispatcher(
  cache: Weak<ResponseCache>,
  mut receiver: mpsc::Receiver<QueryCleanupRequest>,
  metrics: Arc<Metrics>,
  batch_size: usize,
  max_concurrent: usize,
) {
  let mut pending = HashMap::<CacheQueryInvalidationTarget, QueryCleanupRequest>::new();
  let mut ready = VecDeque::<CacheQueryInvalidationTarget>::new();
  let mut ready_set = HashSet::<CacheQueryInvalidationTarget>::new();
  let mut active = HashSet::<CacheQueryInvalidationTarget>::new();
  let mut tasks = JoinSet::new();
  let mut receiver_closed = false;

  loop {
    while tasks.len() < max_concurrent {
      let Some(target) = ready.pop_front() else {
        break;
      };
      ready_set.remove(&target);
      let Some(request) = pending.remove(&target) else {
        continue;
      };
      active.insert(target.clone());
      metrics.record_cache_query_cleanup_started();
      let cache = cache.clone();
      tasks.spawn(async move {
        let outcome = match cache.upgrade() {
          Some(cache) => {
            cache
              .cleanup_query_target_quantum(request, batch_size)
              .await
          }
          None => {
            let mut request = request;
            request.local_pending = false;
            request.shared_pending = false;
            request.shared_expiry_pending = false;
            request.external_pending = false;
            QueryCleanupOutcome {
              request,
              entries: 0,
              succeeded: false,
            }
          }
        };
        (target, outcome)
      });
    }

    if receiver_closed && pending.is_empty() && tasks.is_empty() {
      break;
    }

    tokio::select! {
      request = receiver.recv(), if !receiver_closed => {
        match request {
          Some(request) => {
            metrics.record_cache_query_cleanup_dequeued();
            let target = request.target.clone();
            if let Some(current) = pending.get_mut(&target) {
              current.merge(request);
              metrics.record_cache_query_cleanup_coalesced();
            } else {
              pending.insert(target.clone(), request);
            }
            if !active.contains(&target) && ready_set.insert(target.clone()) {
              ready.push_back(target);
            }
          }
          None => receiver_closed = true,
        }
      }
      completed = tasks.join_next(), if !tasks.is_empty() => {
        match completed {
          Some(Ok((target, outcome))) => {
            active.remove(&target);
            metrics.record_cache_query_cleanup_finished(outcome.entries, outcome.succeeded);
            if outcome.request.pending() {
              if let Some(current) = pending.get_mut(&target) {
                current.merge(outcome.request);
                metrics.record_cache_query_cleanup_coalesced();
              } else {
                pending.insert(target.clone(), outcome.request);
              }
            }
            if pending.contains_key(&target) && ready_set.insert(target.clone()) {
              ready.push_back(target);
            }
          }
          Some(Err(_)) => {
            active.clear();
            metrics.record_cache_query_cleanup_finished(0, false);
            for target in pending.keys() {
              if ready_set.insert(target.clone()) {
                ready.push_back(target.clone());
              }
            }
          }
          None => {}
        }
      }
    }
  }

  while receiver.try_recv().is_ok() {
    metrics.record_cache_query_cleanup_dequeued();
    metrics.record_cache_query_cleanup_dropped();
  }
}

impl ResponseCache {
  async fn cleanup_query_target_quantum(
    &self,
    mut request: QueryCleanupRequest,
    batch_size: usize,
  ) -> QueryCleanupOutcome {
    let mut entries = 0usize;
    let mut succeeded = true;

    if request.local_pending {
      let (removed, more) =
        self.cleanup_local_query_target_batch(&request.target, request.before_epoch, batch_size);
      entries = entries.saturating_add(removed);
      request.local_pending = more;
    }

    if request.shared_pending {
      match self
        .shared_state
        .as_ref()
        .filter(|shared| shared.has_cache())
      {
        Some(shared) => match shared
          .cache_cleanup_query_target_before(
            &request.target.policy,
            &request.target.scheme,
            &request.target.host,
            &request.target.uri,
            request.before_epoch,
            batch_size,
          )
          .await
        {
          Ok(batch) => {
            entries = entries.saturating_add(batch.removed);
            request.shared_pending = batch.remaining;
          }
          Err(_) => {
            request.shared_pending = false;
            succeeded = false;
          }
        },
        None => request.shared_pending = false,
      }
    }

    if request.shared_expiry_pending {
      match self
        .shared_state
        .as_ref()
        .filter(|shared| shared.has_cache())
      {
        Some(shared) => match shared.cache_cleanup_expired_query_entries(batch_size).await {
          Ok(batch) => {
            entries = entries.saturating_add(batch.removed);
            request.shared_expiry_pending = batch.remaining;
          }
          Err(_) => {
            request.shared_expiry_pending = false;
            succeeded = false;
          }
        },
        None => request.shared_expiry_pending = false,
      }
    }

    if request.external_pending {
      match self
        .cleanup_external_query_before_epoch(
          &request.target.policy,
          &request.target.scheme,
          &request.target.host,
          &request.target.uri,
          request.before_epoch,
          batch_size,
        )
        .await
      {
        Some(report) => {
          entries = entries.saturating_add(report.purged);
          request.external_pending = !report.complete && report.purged > 0;
          if !report.complete && report.purged == 0 {
            succeeded = false;
          }
        }
        None => {
          request.external_pending = false;
          succeeded = false;
        }
      }
    }

    QueryCleanupOutcome {
      request,
      entries,
      succeeded,
    }
  }

  pub(super) fn cleanup_local_query_target_batch(
    &self,
    target: &CacheQueryInvalidationTarget,
    before_epoch: u64,
    batch_size: usize,
  ) -> (usize, bool) {
    let target_key = CacheQueryTargetKey::from_target(target);
    let mut inner = self.inner_guard();
    let keys = inner
      .query_variants_by_target
      .get(&target_key)
      .into_iter()
      .flat_map(|partitions| partitions.iter())
      .filter(|(partition, _)| {
        target
          .partition
          .as_ref()
          .is_none_or(|expected| *partition == expected)
      })
      .flat_map(|(_, epochs)| epochs.range(..before_epoch))
      .flat_map(|(_, variants)| variants.iter())
      .take(batch_size)
      .cloned()
      .collect::<Vec<_>>();

    let mut removed = 0usize;
    for key in keys {
      let matches = inner.entries.get(&key).is_some_and(|entry| {
        entry
          .query_target_epoch
          .is_some_and(|epoch| epoch < before_epoch)
          && entry.policy == target.policy
          && entry.scheme == target.scheme
          && entry.host == target.host
          && entry.uri == target.uri
          && target
            .partition
            .as_ref()
            .is_none_or(|partition| entry.partition == *partition)
      });
      if matches {
        remove_entry(&mut inner, &key);
        removed = removed.saturating_add(1);
      }
    }

    let more = inner
      .query_variants_by_target
      .get(&target_key)
      .is_some_and(|partitions| {
        partitions.iter().any(|(partition, epochs)| {
          target
            .partition
            .as_ref()
            .is_none_or(|expected| partition == expected)
            && epochs.range(..before_epoch).next().is_some()
        })
      });
    (removed, more)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn target(uri: &str) -> CacheQueryInvalidationTarget {
    CacheQueryInvalidationTarget {
      policy: "default".to_string(),
      scheme: "https".to_string(),
      host: "example.test".to_string(),
      uri: uri.to_string(),
      partition: None,
    }
  }

  #[test]
  fn queue_capacity_bounds_all_outstanding_targets() {
    let config = CacheQueryCleanupConfig {
      queue_capacity: 1,
      ..CacheQueryCleanupConfig::default()
    };
    let (dispatcher, mut receiver) = QueryCleanupDispatcher::new(&config, Metrics::new());

    dispatcher.enqueue(target("/first"), 1, false, false);
    dispatcher.enqueue(target("/second"), 1, false, false);

    assert_eq!(dispatcher.permits.available_permits(), 0);
    let first = receiver.try_recv().expect("first target is queued");
    assert_eq!(first.target.uri, "/first");
    assert!(receiver.try_recv().is_err());

    drop(first);
    assert_eq!(dispatcher.permits.available_permits(), 1);
    dispatcher.enqueue(target("/second"), 1, false, false);
    assert_eq!(
      receiver.try_recv().expect("permit is reusable").target.uri,
      "/second"
    );
  }
}

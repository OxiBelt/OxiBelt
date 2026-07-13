//! Cancellation-safe ownership and compatible FIFO lanes for queued admissions.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use super::runtime::{CircuitBreakerRuntime, RuntimeState};
use super::types::{Allocation, ResourceKind, ScopeKey, Waiter};

/// Canonical allocation domain whose waiters must retain FIFO ordering.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct QueueKey(Vec<QueueAllocation>);

impl QueueKey {
  pub(super) fn from_allocations(allocations: &[Allocation]) -> Self {
    let mut entries = allocations
      .iter()
      .map(|allocation| QueueAllocation {
        scope: allocation.scope.clone(),
        resource: allocation.resource,
      })
      .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
      left
        .scope
        .kind()
        .cmp(right.scope.kind())
        .then(left.scope.label().cmp(right.scope.label()))
        .then((left.resource as u8).cmp(&(right.resource as u8)))
    });
    Self(entries)
  }

  fn overlaps(&self, other: &Self) -> bool {
    self.0.iter().any(|allocation| other.0.contains(allocation))
  }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct QueueAllocation {
  scope: ScopeKey,
  resource: ResourceKind,
}

/// Stable handle for one queued waiter and its original enqueue deadline.
#[derive(Clone, Debug)]
pub(super) struct WaiterTicket {
  id: u64,
  key: QueueKey,
  queued_at: Instant,
}

impl WaiterTicket {
  pub(super) fn new(id: u64, key: QueueKey, queued_at: Instant) -> Self {
    Self { id, key, queued_at }
  }

  pub(super) fn queued_at(&self) -> Instant {
    self.queued_at
  }

  pub(super) const fn id(&self) -> u64 {
    self.id
  }
}

/// FIFO queues partitioned by the complete resource allocation domain.
#[derive(Debug, Default)]
pub(super) struct AdmissionQueues {
  lanes: HashMap<QueueKey, VecDeque<Waiter>>,
}

impl AdmissionQueues {
  pub(super) fn is_empty(&self, key: &QueueKey) -> bool {
    self.lanes.get(key).is_none_or(VecDeque::is_empty)
  }

  pub(super) fn is_head(&self, ticket: &WaiterTicket) -> bool {
    self
      .lanes
      .get(&ticket.key)
      .and_then(VecDeque::front)
      .is_some_and(|waiter| waiter.id == ticket.id)
  }

  /// Returns the oldest eligible head that shares a resource with `key`.
  pub(super) fn oldest_admissible_overlap<F>(
    &self,
    key: &QueueKey,
    mut admissible: F,
  ) -> Option<u64>
  where
    F: FnMut(&[Allocation]) -> bool,
  {
    self
      .lanes
      .iter()
      .filter(|(candidate_key, _)| key.overlaps(candidate_key))
      .filter_map(|(_, lane)| lane.front())
      .filter(|waiter| admissible(&waiter.allocations))
      .min_by_key(|waiter| (waiter.queued_at, waiter.id))
      .map(|waiter| waiter.id)
  }

  pub(super) fn push(&mut self, ticket: &WaiterTicket, waiter: Waiter) {
    self
      .lanes
      .entry(ticket.key.clone())
      .or_default()
      .push_back(waiter);
  }

  pub(super) fn remove(&mut self, ticket: &WaiterTicket) -> Option<Waiter> {
    let lane = self.lanes.get_mut(&ticket.key)?;
    let index = lane.iter().position(|waiter| waiter.id == ticket.id)?;
    let waiter = lane.remove(index)?;
    let remove_lane = lane.is_empty();
    if remove_lane {
      self.lanes.remove(&ticket.key);
    }
    Some(waiter)
  }
}

impl RuntimeState {
  pub(super) fn enqueue(&mut self, ticket: &WaiterTicket, waiter: Waiter) {
    for allocation in &waiter.allocations {
      let scope = self
        .scopes
        .get_mut(&allocation.scope)
        .expect("configured circuit-breaker scope is present");
      scope.queued[allocation.resource as usize] += 1;
    }
    self.waiters.push(ticket, waiter);
  }

  pub(super) fn remove_waiter(&mut self, ticket: WaiterTicket) -> Option<Waiter> {
    let waiter = self.waiters.remove(&ticket)?;
    for allocation in &waiter.allocations {
      if let Some(scope) = self.scopes.get_mut(&allocation.scope) {
        scope.queued[allocation.resource as usize] =
          scope.queued[allocation.resource as usize].saturating_sub(1);
      }
    }
    Some(waiter)
  }
}

/// Removes a queued admission if its caller is cancelled while waiting.
pub(super) struct QueuedWaiter {
  runtime: Arc<CircuitBreakerRuntime>,
  ticket: Option<WaiterTicket>,
}

impl QueuedWaiter {
  pub(super) fn new(runtime: Arc<CircuitBreakerRuntime>) -> Self {
    Self {
      runtime,
      ticket: None,
    }
  }

  pub(super) fn ticket(&self) -> Option<&WaiterTicket> {
    self.ticket.as_ref()
  }

  pub(super) fn set(&mut self, ticket: WaiterTicket) {
    debug_assert!(
      self.ticket.is_none(),
      "queued waiter must have one queue entry"
    );
    self.ticket = Some(ticket);
  }

  pub(super) fn take(&mut self) -> Option<WaiterTicket> {
    self.ticket.take()
  }

  pub(super) fn remove(&mut self) {
    self.runtime.remove_waiter(self.ticket.take());
  }
}

impl Drop for QueuedWaiter {
  fn drop(&mut self) {
    self.remove();
  }
}

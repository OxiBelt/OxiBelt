//! Protocol-neutral Happy Eyeballs candidate scheduling.
//!
//! This module deliberately owns only candidate ordering, launch timing, and
//! cancellation by dropping losing futures.  Callers establish the transport
//! and decide what "ready" means: for example, TCP, TLS, HTTP/2, or QUIC/H3.
//! It has no pool, request replay, metrics, or protocol knowledge.

use std::collections::{HashSet, VecDeque};
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::sync::watch;
use tokio::time::Instant;

use super::EndpointAddressFamily;

/// The shortest permitted interval between launches in racing mode.
pub(crate) const MIN_CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(10);

/// A candidate identity is supplied by the owner of the endpoint plan.
///
/// The identity must remain stable across updates for the same endpoint.  It
/// prevents a late DNS update from launching an already-attempted candidate a
/// second time.
#[derive(Clone, Debug)]
pub(crate) struct HappyEyeballsCandidate<T> {
  id: u64,
  family: EndpointAddressFamily,
  value: T,
}

impl<T> HappyEyeballsCandidate<T> {
  pub(crate) fn new(id: u64, family: EndpointAddressFamily, value: T) -> Self {
    Self { id, family, value }
  }

  pub(crate) fn id(&self) -> u64 {
    self.id
  }

  pub(crate) fn family(&self) -> EndpointAddressFamily {
    self.family
  }

  pub(crate) fn into_value(self) -> T {
    self.value
  }

  pub(crate) fn value_ref(&self) -> &T {
    &self.value
  }
}

/// Selects racing or the compatibility sequential launch behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CandidateSchedulerMode {
  Enabled,
  LegacySequential,
}

/// Validated scheduler limits supplied by a caller's connection policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CandidateSchedulerConfig {
  mode: CandidateSchedulerMode,
  connection_attempt_delay: Duration,
  minimum_connection_attempt_delay: Duration,
  max_attempts: usize,
  max_concurrent_attempts: usize,
  first_family_count: usize,
}

impl CandidateSchedulerConfig {
  pub(crate) fn new(
    mode: CandidateSchedulerMode,
    connection_attempt_delay: Duration,
    minimum_connection_attempt_delay: Duration,
    max_attempts: usize,
    max_concurrent_attempts: usize,
    first_family_count: usize,
  ) -> Result<Self, CandidateSchedulerConfigError> {
    if minimum_connection_attempt_delay < MIN_CONNECTION_ATTEMPT_DELAY {
      return Err(CandidateSchedulerConfigError::MinimumLaunchDelay);
    }
    if max_attempts == 0 {
      return Err(CandidateSchedulerConfigError::MaxAttempts);
    }
    if max_concurrent_attempts == 0 {
      return Err(CandidateSchedulerConfigError::MaxConcurrentAttempts);
    }
    if first_family_count == 0 {
      return Err(CandidateSchedulerConfigError::FirstFamilyCount);
    }
    Ok(Self {
      mode,
      connection_attempt_delay,
      minimum_connection_attempt_delay,
      max_attempts,
      max_concurrent_attempts,
      first_family_count,
    })
  }

  pub(crate) fn mode(&self) -> CandidateSchedulerMode {
    self.mode
  }

  pub(crate) fn effective_connection_attempt_delay(&self) -> Duration {
    self
      .connection_attempt_delay
      .max(self.minimum_connection_attempt_delay)
  }

  pub(crate) fn max_attempts(&self) -> usize {
    self.max_attempts
  }

  pub(crate) fn max_concurrent_attempts(&self) -> usize {
    self.max_concurrent_attempts
  }

  pub(crate) fn first_family_count(&self) -> usize {
    self.first_family_count
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CandidateSchedulerConfigError {
  MinimumLaunchDelay,
  MaxAttempts,
  MaxConcurrentAttempts,
  FirstFamilyCount,
}

impl fmt::Display for CandidateSchedulerConfigError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(match self {
      Self::MinimumLaunchDelay => "minimum connection-attempt delay must be at least 10ms",
      Self::MaxAttempts => "maximum connection attempts must be greater than zero",
      Self::MaxConcurrentAttempts => {
        "maximum concurrent connection attempts must be greater than zero"
      }
      Self::FirstFamilyCount => "first-family candidate count must be greater than zero",
    })
  }
}

impl Error for CandidateSchedulerConfigError {}

/// Separates a local admission result from an endpoint/transport failure.
///
/// A local admission rejection suppresses additional launches but does not
/// cancel already in-flight attempts, allowing an established peer candidate
/// to win.  The scheduler never assigns endpoint health or cooldown state.
#[derive(Debug)]
pub(crate) enum CandidateAttemptError<E> {
  Endpoint(E),
  #[allow(
    dead_code,
    reason = "protocol adapters with per-candidate admission use this distinction"
  )]
  LocalAdmission(E),
}

/// Terminal result of the protocol-neutral scheduler.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum CandidateRaceError<E> {
  Deadline,
  NoCandidates,
  Exhausted {
    last_endpoint_error: Option<E>,
    admission_error: Option<E>,
  },
}

/// Race fully-ready connection candidates using the latest watched plan.
///
/// The callback must perform all caller-defined setup before returning `Ok`.
/// The scheduler cancels losing work by dropping its futures once a winner or
/// deadline is reached.  Updates replace only unstarted candidates; started
/// candidates remain in flight until they resolve, matching Happy Eyeballs
/// DNS-update behavior.
pub(crate) async fn race_happy_eyeballs_candidates<T, C, E, F, Fut>(
  updates: &mut watch::Receiver<std::sync::Arc<[HappyEyeballsCandidate<C>]>>,
  config: CandidateSchedulerConfig,
  deadline: Instant,
  connect: F,
) -> Result<T, CandidateRaceError<E>>
where
  C: Clone,
  F: Fn(HappyEyeballsCandidate<C>, Instant) -> Fut,
  Fut: Future<Output = Result<T, CandidateAttemptError<E>>>,
{
  let mut pending = VecDeque::new();
  let mut started = HashSet::new();
  let mut in_flight = FuturesUnordered::new();
  let mut attempts_started = 0usize;
  let mut next_launch = deadline;
  let mut updates_closed = false;
  let mut launches_suppressed = false;
  let mut last_endpoint_error = None;
  let mut admission_error = None;

  replace_pending(&mut pending, updates.borrow().as_ref(), &started, config);

  loop {
    let now = Instant::now();
    if now >= deadline {
      // Returning drops `in_flight`, which is the cancellation mechanism.
      return Err(CandidateRaceError::Deadline);
    }

    let racing = config.mode() == CandidateSchedulerMode::Enabled;
    let capacity = if racing {
      config.max_concurrent_attempts()
    } else {
      1
    };
    let ready_to_launch = !launches_suppressed
      && attempts_started < config.max_attempts()
      && !pending.is_empty()
      && in_flight.len() < capacity
      && (attempts_started == 0 || !racing || now >= next_launch);
    if ready_to_launch {
      let Some(candidate) = pending.pop_front() else {
        continue;
      };
      started.insert(candidate.id());
      attempts_started = attempts_started.saturating_add(1);
      next_launch = now
        .checked_add(config.effective_connection_attempt_delay())
        .unwrap_or(deadline)
        .min(deadline);
      in_flight.push(tagged_attempt(
        candidate.clone(),
        connect(candidate, deadline),
      ));
      continue;
    }

    if in_flight.is_empty() {
      if launches_suppressed {
        return Err(CandidateRaceError::Exhausted {
          last_endpoint_error,
          admission_error,
        });
      }
      if attempts_started >= config.max_attempts() || (pending.is_empty() && updates_closed) {
        return if last_endpoint_error.is_some() || admission_error.is_some() {
          Err(CandidateRaceError::Exhausted {
            last_endpoint_error,
            admission_error,
          })
        } else {
          Err(CandidateRaceError::NoCandidates)
        };
      }
    }

    let can_wait_for_launch = racing
      && !launches_suppressed
      && attempts_started < config.max_attempts()
      && !pending.is_empty()
      && in_flight.len() < capacity
      && next_launch < deadline;
    let has_in_flight = !in_flight.is_empty();
    tokio::select! {
      _ = tokio::time::sleep_until(deadline) => {
        return Err(CandidateRaceError::Deadline);
      }
      changed = updates.changed(), if !updates_closed => {
        match changed {
          Ok(()) => {
            let snapshot = updates.borrow_and_update().clone();
            replace_pending(&mut pending, snapshot.as_ref(), &started, config);
          }
          Err(_) => updates_closed = true,
        }
      }
      result = in_flight.next(), if has_in_flight => {
        let Some((_candidate_id, result)) = result else {
          continue;
        };
        match result {
          Ok(ready) => return Ok(ready),
          Err(CandidateAttemptError::Endpoint(error)) => {
            last_endpoint_error = Some(error);
          }
          Err(CandidateAttemptError::LocalAdmission(error)) => {
            admission_error = Some(error);
            // Do not consume more endpoint or connection capacity locally.
            // Existing attempts are still allowed to win.
            launches_suppressed = true;
          }
        }
      }
      _ = tokio::time::sleep_until(next_launch), if can_wait_for_launch => {
      }
    }
  }
}

async fn tagged_attempt<T, C, E, Fut>(
  candidate: HappyEyeballsCandidate<C>,
  future: Fut,
) -> (u64, Result<T, CandidateAttemptError<E>>)
where
  Fut: Future<Output = Result<T, CandidateAttemptError<E>>>,
{
  (candidate.id(), future.await)
}

fn replace_pending<C>(
  pending: &mut VecDeque<HappyEyeballsCandidate<C>>,
  candidates: &[HappyEyeballsCandidate<C>],
  started: &HashSet<u64>,
  config: CandidateSchedulerConfig,
) where
  C: Clone,
{
  let mut seen = HashSet::new();
  let mut fresh = Vec::new();
  for candidate in candidates {
    if seen.insert(candidate.id()) && !started.contains(&candidate.id()) {
      fresh.push(candidate.clone());
    }
  }
  *pending = match config.mode() {
    CandidateSchedulerMode::Enabled => {
      interleave_families(fresh, config.first_family_count()).into()
    }
    CandidateSchedulerMode::LegacySequential => fresh.into(),
  };
}

fn interleave_families<C>(
  candidates: Vec<HappyEyeballsCandidate<C>>,
  first_family_count: usize,
) -> Vec<HappyEyeballsCandidate<C>> {
  let Some(first_family) = candidates.first().map(HappyEyeballsCandidate::family) else {
    return Vec::new();
  };
  let mut first = VecDeque::new();
  let mut other = VecDeque::new();
  for candidate in candidates {
    if candidate.family() == first_family {
      first.push_back(candidate);
    } else {
      other.push_back(candidate);
    }
  }

  let mut ordered = Vec::with_capacity(first.len().saturating_add(other.len()));
  for _ in 0..first_family_count {
    let Some(candidate) = first.pop_front() else {
      break;
    };
    ordered.push(candidate);
  }
  let mut take_first = false;
  while !first.is_empty() || !other.is_empty() {
    let candidate = if take_first {
      first.pop_front().or_else(|| other.pop_front())
    } else {
      other.pop_front().or_else(|| first.pop_front())
    };
    if let Some(candidate) = candidate {
      ordered.push(candidate);
    }
    take_first = !take_first;
  }
  ordered
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;
  use std::sync::atomic::{AtomicUsize, Ordering};

  use tokio::sync::{Notify, watch};

  use super::*;

  fn candidate(id: u64, family: EndpointAddressFamily) -> HappyEyeballsCandidate<u64> {
    HappyEyeballsCandidate::new(id, family, id)
  }

  fn config(
    mode: CandidateSchedulerMode,
    delay: Duration,
    max_attempts: usize,
    max_concurrent: usize,
    first_family_count: usize,
  ) -> CandidateSchedulerConfig {
    CandidateSchedulerConfig::new(
      mode,
      delay,
      MIN_CONNECTION_ATTEMPT_DELAY,
      max_attempts,
      max_concurrent,
      first_family_count,
    )
    .expect("test scheduler config")
  }

  fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
  }

  #[test]
  fn rejects_a_launch_floor_below_ten_milliseconds() {
    assert_eq!(
      CandidateSchedulerConfig::new(
        CandidateSchedulerMode::Enabled,
        Duration::ZERO,
        Duration::from_millis(9),
        1,
        1,
        1,
      ),
      Err(CandidateSchedulerConfigError::MinimumLaunchDelay)
    );
  }

  #[test]
  fn enabled_mode_honors_the_first_family_count_then_interleaves() {
    let ordered = interleave_families(
      vec![
        candidate(1, EndpointAddressFamily::Ipv6),
        candidate(2, EndpointAddressFamily::Ipv6),
        candidate(3, EndpointAddressFamily::Ipv6),
        candidate(4, EndpointAddressFamily::Ipv4),
        candidate(5, EndpointAddressFamily::Ipv4),
      ],
      2,
    );
    let ids = ordered
      .into_iter()
      .map(HappyEyeballsCandidate::into_value)
      .collect::<Vec<_>>();
    assert_eq!(ids, [1, 2, 4, 3, 5]);
  }

  #[tokio::test(start_paused = true)]
  async fn endpoint_failure_still_observes_the_attempt_delay() {
    let (_sender, mut updates) = watch::channel(Arc::from([
      candidate(1, EndpointAddressFamily::Ipv6),
      candidate(2, EndpointAddressFamily::Ipv4),
    ]));
    let calls = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn({
      let calls = Arc::clone(&calls);
      async move {
        race_happy_eyeballs_candidates(
          &mut updates,
          config(
            CandidateSchedulerMode::Enabled,
            Duration::from_secs(1),
            2,
            2,
            1,
          ),
          deadline(),
          move |candidate, _| {
            let calls = Arc::clone(&calls);
            async move {
              calls.fetch_add(1, Ordering::AcqRel);
              if candidate.id() == 1 {
                Err(CandidateAttemptError::Endpoint("first failed"))
              } else {
                Ok(candidate.into_value())
              }
            }
          },
        )
        .await
      }
    });
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::Acquire), 1);
    tokio::time::advance(Duration::from_millis(999)).await;
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::Acquire), 1);
    tokio::time::advance(Duration::from_millis(1)).await;
    assert_eq!(task.await.expect("scheduler task"), Ok(2));
    assert_eq!(calls.load(Ordering::Acquire), 2);
  }

  #[tokio::test(start_paused = true)]
  async fn admission_rejection_does_not_cancel_an_in_flight_winner() {
    let (_sender, mut updates) = watch::channel(Arc::from([
      candidate(1, EndpointAddressFamily::Ipv6),
      candidate(2, EndpointAddressFamily::Ipv4),
      candidate(3, EndpointAddressFamily::Ipv6),
    ]));
    let winner = Arc::new(Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn({
      let winner = Arc::clone(&winner);
      let calls = Arc::clone(&calls);
      async move {
        race_happy_eyeballs_candidates(
          &mut updates,
          config(
            CandidateSchedulerMode::Enabled,
            Duration::from_millis(10),
            3,
            2,
            1,
          ),
          deadline(),
          move |candidate, _| {
            let winner = Arc::clone(&winner);
            let calls = Arc::clone(&calls);
            async move {
              calls.fetch_add(1, Ordering::AcqRel);
              if candidate.id() == 2 {
                Err(CandidateAttemptError::LocalAdmission("locally full"))
              } else {
                winner.notified().await;
                Ok(candidate.into_value())
              }
            }
          },
        )
        .await
      }
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(10)).await;
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::Acquire), 2);
    winner.notify_one();
    assert_eq!(task.await.expect("scheduler task"), Ok(1));
    assert_eq!(calls.load(Ordering::Acquire), 2);
  }

  #[tokio::test(start_paused = true)]
  async fn racing_never_exceeds_the_configured_concurrency() {
    let (_sender, mut updates) = watch::channel(Arc::from([
      candidate(1, EndpointAddressFamily::Ipv6),
      candidate(2, EndpointAddressFamily::Ipv4),
      candidate(3, EndpointAddressFamily::Ipv6),
    ]));
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn({
      let active = Arc::clone(&active);
      let peak = Arc::clone(&peak);
      async move {
        race_happy_eyeballs_candidates(
          &mut updates,
          config(
            CandidateSchedulerMode::Enabled,
            Duration::from_millis(10),
            3,
            2,
            1,
          ),
          deadline(),
          move |_candidate, _| {
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            async move {
              let now = active.fetch_add(1, Ordering::AcqRel) + 1;
              peak.fetch_max(now, Ordering::AcqRel);
              std::future::pending::<Result<u64, CandidateAttemptError<()>>>().await
            }
          },
        )
        .await
      }
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(10)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(100)).await;
    tokio::task::yield_now().await;
    assert_eq!(peak.load(Ordering::Acquire), 2);
    task.abort();
    let _ = task.await;
  }

  struct DropCounter(Arc<AtomicUsize>);

  impl Drop for DropCounter {
    fn drop(&mut self) {
      self.0.fetch_add(1, Ordering::AcqRel);
    }
  }

  #[tokio::test(start_paused = true)]
  async fn deadline_drops_in_flight_attempts() {
    let (_sender, mut updates) =
      watch::channel(Arc::from([candidate(1, EndpointAddressFamily::Ipv6)]));
    let drops = Arc::new(AtomicUsize::new(0));
    let scheduled_deadline = Instant::now() + Duration::from_millis(20);
    let task = tokio::spawn({
      let drops = Arc::clone(&drops);
      async move {
        race_happy_eyeballs_candidates(
          &mut updates,
          config(
            CandidateSchedulerMode::Enabled,
            Duration::from_millis(10),
            1,
            1,
            1,
          ),
          scheduled_deadline,
          move |_candidate, _| {
            let guard = DropCounter(Arc::clone(&drops));
            async move {
              let _guard = guard;
              std::future::pending::<Result<u64, CandidateAttemptError<()>>>().await
            }
          },
        )
        .await
      }
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(20)).await;
    assert_eq!(
      task.await.expect("scheduler task"),
      Err(CandidateRaceError::Deadline)
    );
    assert_eq!(drops.load(Ordering::Acquire), 1);
  }

  #[tokio::test(start_paused = true)]
  async fn one_family_preserves_all_candidates() {
    let (_sender, mut updates) = watch::channel(Arc::from([
      candidate(1, EndpointAddressFamily::Ipv6),
      candidate(2, EndpointAddressFamily::Ipv6),
      candidate(3, EndpointAddressFamily::Ipv6),
    ]));
    let result = race_happy_eyeballs_candidates(
      &mut updates,
      config(
        CandidateSchedulerMode::Enabled,
        Duration::from_millis(10),
        3,
        2,
        2,
      ),
      deadline(),
      move |candidate, _| async move {
        if candidate.id() == 3 {
          Ok(candidate.into_value())
        } else {
          Err(CandidateAttemptError::Endpoint("failed"))
        }
      },
    )
    .await;
    assert_eq!(result, Ok(3));
  }

  #[tokio::test(start_paused = true)]
  async fn legacy_sequential_mode_waits_for_each_failure() {
    let (_sender, mut updates) = watch::channel(Arc::from([
      candidate(1, EndpointAddressFamily::Ipv6),
      candidate(2, EndpointAddressFamily::Ipv4),
    ]));
    let first = Arc::new(Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn({
      let first = Arc::clone(&first);
      let calls = Arc::clone(&calls);
      async move {
        race_happy_eyeballs_candidates(
          &mut updates,
          config(
            CandidateSchedulerMode::LegacySequential,
            Duration::ZERO,
            2,
            8,
            1,
          ),
          deadline(),
          move |candidate, _| {
            let first = Arc::clone(&first);
            let calls = Arc::clone(&calls);
            async move {
              calls.fetch_add(1, Ordering::AcqRel);
              if candidate.id() == 1 {
                first.notified().await;
                Err(CandidateAttemptError::Endpoint("first failed"))
              } else {
                Ok(candidate.into_value())
              }
            }
          },
        )
        .await
      }
    });
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::Acquire), 1);
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(calls.load(Ordering::Acquire), 1);
    first.notify_one();
    assert_eq!(task.await.expect("scheduler task"), Ok(2));
    assert_eq!(calls.load(Ordering::Acquire), 2);
  }

  #[tokio::test(start_paused = true)]
  async fn late_candidates_are_ingested_before_a_winner_exists() {
    let (sender, mut updates) =
      watch::channel(Arc::from([candidate(1, EndpointAddressFamily::Ipv6)]));
    let first = Arc::new(Notify::new());
    let task = tokio::spawn({
      let first = Arc::clone(&first);
      async move {
        race_happy_eyeballs_candidates(
          &mut updates,
          config(
            CandidateSchedulerMode::Enabled,
            Duration::from_millis(10),
            2,
            2,
            1,
          ),
          deadline(),
          move |candidate, _| {
            let first = Arc::clone(&first);
            async move {
              if candidate.id() == 1 {
                first.notified().await;
                Err(CandidateAttemptError::Endpoint("first failed"))
              } else {
                Ok(candidate.into_value())
              }
            }
          },
        )
        .await
      }
    });
    tokio::task::yield_now().await;
    sender
      .send(Arc::from([
        candidate(1, EndpointAddressFamily::Ipv6),
        candidate(2, EndpointAddressFamily::Ipv4),
      ]))
      .expect("scheduler still subscribed");
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(10)).await;
    tokio::task::yield_now().await;
    assert_eq!(task.await.expect("scheduler task"), Ok(2));
  }
}

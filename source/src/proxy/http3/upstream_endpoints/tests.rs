use super::*;
use crate::circuit_breakers::{AdmissionRejection, AdmissionRejectionReason};
use crate::upstream_resolution::EndpointAddressFamily;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};

struct DropObservedPending {
  dropped: Arc<AtomicBool>,
}

fn scheduler_policy(
  mode: CandidateSchedulerMode,
  max_concurrent_attempts: usize,
  first_family_count: usize,
) -> CandidateSchedulerConfig {
  CandidateSchedulerConfig::new(
    mode,
    Duration::from_millis(10),
    Duration::from_millis(10),
    4,
    max_concurrent_attempts,
    first_family_count,
  )
  .unwrap()
}

impl Future for DropObservedPending {
  type Output = anyhow::Result<()>;

  fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
    Poll::Pending
  }
}

impl Drop for DropObservedPending {
  fn drop(&mut self) {
    self.dropped.store(true, Ordering::Release);
  }
}

#[test]
fn local_admission_rejections_are_not_endpoint_failures() {
  for reason in [
    AdmissionRejectionReason::ActiveLimit,
    AdmissionRejectionReason::QueueTimeout,
  ] {
    let rejection = AdmissionRejection {
      reason,
      retry_after: Duration::from_millis(25),
    };
    let error = anyhow::Error::new(rejection);
    assert_eq!(admission_rejection(&error), Some(rejection));
  }

  assert!(admission_rejection(&anyhow::anyhow!("connect failed")).is_none());
}

#[test]
fn family_interleave_preserves_bounded_rotation_order() {
  let addresses = vec![
    "[::1]:443".parse().unwrap(),
    "[::2]:443".parse().unwrap(),
    "127.0.0.1:443".parse().unwrap(),
    "127.0.0.2:443".parse().unwrap(),
  ];
  assert_eq!(
    interleave_families(addresses, 1),
    vec![
      "[::1]:443".parse().unwrap(),
      "127.0.0.1:443".parse().unwrap(),
      "[::2]:443".parse().unwrap(),
      "127.0.0.2:443".parse().unwrap(),
    ]
  );
}

#[test]
fn one_success_preference_then_rotation_reaches_every_candidate() {
  let candidates = vec![
    "127.0.0.1:443".parse().unwrap(),
    "127.0.0.2:443".parse().unwrap(),
    "127.0.0.3:443".parse().unwrap(),
  ];
  let mut health = EndpointSelectionState::default();
  let initial_winner = rotate_with_preference(candidates.clone(), &mut health).0[0];
  health.preferred = Some(PreferredEndpoint {
    address: initial_winner,
    remaining: RECENT_SUCCESS_PREFERENCE_USES,
  });
  let preferred_once = rotate_with_preference(candidates.clone(), &mut health).0[0];
  let next_rotated = rotate_with_preference(candidates.clone(), &mut health).0[0];
  let final_rotated = rotate_with_preference(candidates.clone(), &mut health).0[0];
  assert_eq!(initial_winner, candidates[0]);
  assert_eq!(preferred_once, candidates[0]);
  assert_eq!(next_rotated, candidates[1]);
  assert_eq!(final_rotated, candidates[2]);
}

#[tokio::test(start_paused = true)]
async fn race_candidates_spaces_failure_driven_launches_at_the_attempt_floor() {
  let policy = QuicUpstreamResolutionConfig {
    address_family_stagger_ms: 10,
    max_connect_attempts: 3,
    cooldown_base_ms: 1,
    cooldown_max_ms: 1,
    ..QuicUpstreamResolutionConfig::default()
  };
  let health = Arc::new(tokio::sync::Mutex::new(EndpointSelectionState::default()));
  let metrics = Metrics::new();
  let attempts = Arc::new(StdMutex::new(Vec::new()));
  let expected = vec![
    "127.0.0.1:443".parse().unwrap(),
    "127.0.0.2:443".parse().unwrap(),
    "127.0.0.3:443".parse().unwrap(),
  ];
  let started = tokio::time::Instant::now();
  let task = tokio::spawn({
    let health = Arc::clone(&health);
    let metrics = Arc::clone(&metrics);
    let attempts = Arc::clone(&attempts);
    async move {
      race_candidates::<(), _, _>(
        &policy,
        scheduler_policy(CandidateSchedulerMode::Enabled, 2, 1),
        &health,
        expected,
        None,
        started + Duration::from_millis(100),
        &metrics,
        move |address, _| {
          let attempts = Arc::clone(&attempts);
          async move {
            attempts
              .lock()
              .unwrap()
              .push((address, tokio::time::Instant::now()));
            Err(anyhow::anyhow!("candidate failed"))
          }
        },
      )
      .await
    }
  });

  tokio::task::yield_now().await;
  assert_eq!(attempts.lock().unwrap().len(), 1);
  tokio::time::advance(Duration::from_millis(9)).await;
  tokio::task::yield_now().await;
  assert_eq!(attempts.lock().unwrap().len(), 1);
  tokio::time::advance(Duration::from_millis(1)).await;
  tokio::task::yield_now().await;
  assert_eq!(attempts.lock().unwrap().len(), 2);
  tokio::time::advance(Duration::from_millis(10)).await;
  tokio::task::yield_now().await;
  assert_eq!(attempts.lock().unwrap().len(), 3);
  assert!(task.await.unwrap().is_err());

  let attempts = attempts.lock().unwrap();
  assert_eq!(
    attempts
      .iter()
      .map(|(address, _)| *address)
      .collect::<Vec<_>>(),
    [
      "127.0.0.1:443".parse().unwrap(),
      "127.0.0.2:443".parse().unwrap(),
      "127.0.0.3:443".parse().unwrap(),
    ]
  );
  assert_eq!(
    attempts[1].1.duration_since(attempts[0].1),
    Duration::from_millis(10)
  );
  assert_eq!(
    attempts[2].1.duration_since(attempts[1].1),
    Duration::from_millis(10)
  );
}

#[tokio::test(start_paused = true)]
async fn race_candidates_does_not_launch_after_a_deadline_shorter_than_the_stagger() {
  let policy = QuicUpstreamResolutionConfig {
    address_family_stagger_ms: 10,
    max_connect_attempts: 2,
    cooldown_base_ms: 1,
    cooldown_max_ms: 1,
    ..QuicUpstreamResolutionConfig::default()
  };
  let health = Arc::new(tokio::sync::Mutex::new(EndpointSelectionState::default()));
  let metrics = Metrics::new();
  let attempts = Arc::new(StdMutex::new(Vec::new()));
  let started = tokio::time::Instant::now();
  let task = tokio::spawn({
    let health = Arc::clone(&health);
    let metrics = Arc::clone(&metrics);
    let attempts = Arc::clone(&attempts);
    async move {
      race_candidates::<(), _, _>(
        &policy,
        scheduler_policy(CandidateSchedulerMode::Enabled, 2, 1),
        &health,
        vec![
          "127.0.0.1:443".parse().unwrap(),
          "127.0.0.2:443".parse().unwrap(),
        ],
        None,
        started + Duration::from_millis(9),
        &metrics,
        move |address, _| {
          let attempts = Arc::clone(&attempts);
          async move {
            attempts.lock().unwrap().push(address);
            Err(anyhow::anyhow!("candidate failed"))
          }
        },
      )
      .await
    }
  });

  tokio::task::yield_now().await;
  tokio::time::advance(Duration::from_millis(9)).await;
  assert!(task.await.unwrap().is_err());
  assert_eq!(
    attempts.lock().unwrap().as_slice(),
    ["127.0.0.1:443".parse().unwrap()]
  );
}

#[tokio::test(start_paused = true)]
async fn race_candidates_does_not_launch_when_the_deadline_is_already_expired() {
  let policy = QuicUpstreamResolutionConfig {
    address_family_stagger_ms: 10,
    max_connect_attempts: 1,
    cooldown_base_ms: 1,
    cooldown_max_ms: 1,
    ..QuicUpstreamResolutionConfig::default()
  };
  let health = tokio::sync::Mutex::new(EndpointSelectionState::default());
  let metrics = Metrics::new();
  let attempts = AtomicUsize::new(0);
  let deadline = tokio::time::Instant::now();

  let result = race_candidates::<(), _, _>(
    &policy,
    scheduler_policy(CandidateSchedulerMode::Enabled, 1, 1),
    &health,
    vec!["127.0.0.1:443".parse().unwrap()],
    None,
    deadline,
    &metrics,
    |_, _| {
      attempts.fetch_add(1, Ordering::Relaxed);
      async { Ok(()) }
    },
  )
  .await;

  assert!(result.is_err());
  assert_eq!(attempts.load(Ordering::Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn race_candidates_retains_an_in_flight_candidate_after_admission_rejection() {
  let policy = QuicUpstreamResolutionConfig {
    address_family_stagger_ms: 10,
    max_connect_attempts: 3,
    cooldown_base_ms: 1,
    cooldown_max_ms: 1,
    ..QuicUpstreamResolutionConfig::default()
  };
  let health = Arc::new(tokio::sync::Mutex::new(EndpointSelectionState::default()));
  let metrics = Metrics::new();
  let attempts = Arc::new(StdMutex::new(Vec::new()));
  let release_first = Arc::new(tokio::sync::Notify::new());
  let release_second = Arc::new(tokio::sync::Notify::new());
  let started = tokio::time::Instant::now();
  let first = "127.0.0.1:443".parse().unwrap();
  let second = "127.0.0.2:443".parse().unwrap();
  let third = "127.0.0.3:443".parse().unwrap();
  let task = tokio::spawn({
    let health = Arc::clone(&health);
    let metrics = Arc::clone(&metrics);
    let attempts = Arc::clone(&attempts);
    let release_first = Arc::clone(&release_first);
    let release_second = Arc::clone(&release_second);
    async move {
      race_candidates::<(), _, _>(
        &policy,
        scheduler_policy(CandidateSchedulerMode::Enabled, 2, 1),
        &health,
        vec![first, second, third],
        None,
        started + Duration::from_millis(100),
        &metrics,
        move |address, _| {
          let attempts = Arc::clone(&attempts);
          let release_first = Arc::clone(&release_first);
          let release_second = Arc::clone(&release_second);
          async move {
            attempts.lock().unwrap().push(address);
            if address == first {
              release_first.notified().await;
              Err(anyhow::Error::new(AdmissionRejection {
                reason: AdmissionRejectionReason::ActiveLimit,
                retry_after: Duration::from_millis(25),
              }))
            } else {
              release_second.notified().await;
              Ok(())
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
  assert_eq!(attempts.lock().unwrap().as_slice(), [first, second]);
  release_first.notify_one();
  tokio::task::yield_now().await;
  tokio::time::advance(Duration::from_millis(20)).await;
  tokio::task::yield_now().await;
  assert_eq!(attempts.lock().unwrap().as_slice(), [first, second]);
  release_second.notify_one();
  assert!(task.await.unwrap().is_ok());
}

#[tokio::test(start_paused = true)]
async fn race_candidates_deadline_drops_pending_work_without_launching_another_candidate() {
  let policy = QuicUpstreamResolutionConfig {
    address_family_stagger_ms: 10,
    max_connect_attempts: 2,
    cooldown_base_ms: 1,
    cooldown_max_ms: 1,
    ..QuicUpstreamResolutionConfig::default()
  };
  let health = Arc::new(tokio::sync::Mutex::new(EndpointSelectionState::default()));
  let metrics = Metrics::new();
  let dropped = Arc::new(AtomicBool::new(false));
  let attempts = Arc::new(StdMutex::new(Vec::new()));
  let started = tokio::time::Instant::now();
  let first = "127.0.0.1:443".parse().unwrap();
  let second = "127.0.0.2:443".parse().unwrap();
  let task = tokio::spawn({
    let health = Arc::clone(&health);
    let metrics = Arc::clone(&metrics);
    let dropped = Arc::clone(&dropped);
    let attempts = Arc::clone(&attempts);
    async move {
      race_candidates(
        &policy,
        scheduler_policy(CandidateSchedulerMode::Enabled, 2, 1),
        &health,
        vec![first, second],
        None,
        started + Duration::from_millis(9),
        &metrics,
        move |address, _| {
          attempts.lock().unwrap().push(address);
          DropObservedPending {
            dropped: Arc::clone(&dropped),
          }
        },
      )
      .await
    }
  });

  tokio::task::yield_now().await;
  tokio::time::advance(Duration::from_millis(9)).await;
  assert!(task.await.unwrap().is_err());
  assert!(dropped.load(Ordering::Acquire));
  assert_eq!(attempts.lock().unwrap().as_slice(), [first]);
}

#[tokio::test(start_paused = true)]
async fn legacy_mode_keeps_h3_attempts_sequential() {
  let policy = QuicUpstreamResolutionConfig {
    address_family_stagger_ms: 10,
    max_connect_attempts: 2,
    cooldown_base_ms: 1,
    cooldown_max_ms: 1,
    ..QuicUpstreamResolutionConfig::default()
  };
  let health = tokio::sync::Mutex::new(EndpointSelectionState::default());
  let metrics = Metrics::new();
  let attempts = Arc::new(StdMutex::new(Vec::new()));
  let release_first = Arc::new(tokio::sync::Notify::new());
  let first = "127.0.0.1:443".parse().unwrap();
  let second = "127.0.0.2:443".parse().unwrap();
  let started = tokio::time::Instant::now();
  let task = tokio::spawn({
    let attempts = Arc::clone(&attempts);
    let release_first = Arc::clone(&release_first);
    async move {
      race_candidates::<(), _, _>(
        &policy,
        scheduler_policy(CandidateSchedulerMode::LegacySequential, 2, 1),
        &health,
        vec![first, second],
        None,
        started + Duration::from_millis(100),
        &metrics,
        move |address, _| {
          let attempts = Arc::clone(&attempts);
          let release_first = Arc::clone(&release_first);
          async move {
            attempts.lock().unwrap().push(address);
            if address == first {
              release_first.notified().await;
              Err(anyhow::anyhow!("candidate failed"))
            } else {
              Ok(())
            }
          }
        },
      )
      .await
    }
  });

  tokio::task::yield_now().await;
  tokio::time::advance(Duration::from_millis(20)).await;
  tokio::task::yield_now().await;
  assert_eq!(attempts.lock().unwrap().as_slice(), [first]);
  release_first.notify_one();
  tokio::time::advance(Duration::from_millis(10)).await;
  tokio::task::yield_now().await;
  assert!(task.await.unwrap().is_ok());
  assert_eq!(attempts.lock().unwrap().as_slice(), [first, second]);
}

#[tokio::test(start_paused = true)]
async fn h3_race_admits_late_dns_candidates_without_restarting_the_first() {
  let policy = QuicUpstreamResolutionConfig {
    address_family_stagger_ms: 10,
    max_connect_attempts: 2,
    cooldown_base_ms: 1,
    cooldown_max_ms: 1,
    ..QuicUpstreamResolutionConfig::default()
  };
  let health = tokio::sync::Mutex::new(EndpointSelectionState::default());
  let metrics = Metrics::new();
  let attempts = Arc::new(StdMutex::new(Vec::new()));
  let first = "192.0.2.1:443".parse().unwrap();
  let second = "[2001:db8::1]:443".parse().unwrap();
  let initial = Arc::from(vec![HappyEyeballsCandidate::new(
    0,
    EndpointAddressFamily::Ipv4,
    first,
  )]);
  let (updates_tx, updates_rx) = tokio::sync::watch::channel(initial);
  let started = tokio::time::Instant::now();
  let task = tokio::spawn({
    let attempts = Arc::clone(&attempts);
    async move {
      race_candidates(
        &policy,
        scheduler_policy(CandidateSchedulerMode::Enabled, 2, 1),
        &health,
        vec![first],
        Some(updates_rx),
        started + Duration::from_millis(100),
        &metrics,
        move |address, _| {
          attempts.lock().unwrap().push(address);
          async move {
            if address == first {
              std::future::pending().await
            } else {
              Ok(())
            }
          }
        },
      )
      .await
    }
  });

  tokio::task::yield_now().await;
  tokio::time::advance(Duration::from_millis(5)).await;
  updates_tx
    .send(Arc::from(vec![
      HappyEyeballsCandidate::new(0, EndpointAddressFamily::Ipv4, first),
      HappyEyeballsCandidate::new(1, EndpointAddressFamily::Ipv6, second),
    ]))
    .unwrap();
  tokio::task::yield_now().await;
  assert_eq!(attempts.lock().unwrap().as_slice(), [first]);
  tokio::time::advance(Duration::from_millis(5)).await;
  tokio::task::yield_now().await;
  assert!(task.await.unwrap().is_ok());
  assert_eq!(attempts.lock().unwrap().as_slice(), [first, second]);
}

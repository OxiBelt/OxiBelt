use std::num::NonZeroU64;
use std::task::Poll;

use futures_util::poll;

use super::*;

fn limited(bytes_per_second: u64) -> BandwidthRate {
  BandwidthRate::BytesPerSecond(
    NonZeroU64::new(bytes_per_second).unwrap_or_else(|| panic!("test rate must be positive")),
  )
}

fn limiter(rate: u64) -> Arc<RouteBandwidthLimiter> {
  RouteBandwidthLimiter::new(BandwidthPolicy::new(limited(rate), limited(rate)))
}

#[tokio::test(start_paused = true)]
async fn initially_full_bucket_refills_with_integer_time() {
  let limiter = limiter(100);
  let mut flow = limiter.flow(BandwidthDirection::Upload);
  let initial = flow.acquire(100).await.unwrap();
  assert_eq!(initial.bytes(), 100);
  assert_eq!(initial.waited(), Duration::ZERO);

  let refill = flow.acquire(50);
  tokio::pin!(refill);
  assert!(matches!(poll!(refill.as_mut()), Poll::Pending));
  tokio::time::advance(Duration::from_millis(9)).await;
  assert!(matches!(poll!(refill.as_mut()), Poll::Pending));
  tokio::time::advance(Duration::from_millis(1)).await;
  let refilled = refill.await.unwrap();
  assert_eq!(refilled.bytes(), 1);
  assert_eq!(refilled.waited(), Duration::from_millis(10));
}

#[tokio::test(start_paused = true)]
async fn queues_share_aggregate_budget_in_fair_order() {
  let limiter = limiter(BANDWIDTH_QUANTUM_BYTES as u64);
  let mut drain = limiter.flow(BandwidthDirection::Download);
  assert_eq!(
    drain
      .acquire(BANDWIDTH_QUANTUM_BYTES)
      .await
      .unwrap()
      .bytes(),
    BANDWIDTH_QUANTUM_BYTES
  );

  let mut first = limiter.flow(BandwidthDirection::Download);
  let mut second = limiter.flow(BandwidthDirection::Download);
  let first_wait = first.acquire(BANDWIDTH_QUANTUM_BYTES);
  let second_wait = second.acquire(BANDWIDTH_QUANTUM_BYTES);
  tokio::pin!(first_wait);
  tokio::pin!(second_wait);
  assert!(matches!(poll!(first_wait.as_mut()), Poll::Pending));
  assert!(matches!(poll!(second_wait.as_mut()), Poll::Pending));

  tokio::time::advance(Duration::from_secs(1)).await;
  assert_eq!(first_wait.await.unwrap().bytes(), BANDWIDTH_QUANTUM_BYTES);
  assert!(matches!(poll!(second_wait.as_mut()), Poll::Pending));
  tokio::time::advance(Duration::from_secs(1)).await;
  assert_eq!(second_wait.await.unwrap().bytes(), BANDWIDTH_QUANTUM_BYTES);
}

#[tokio::test(start_paused = true)]
async fn cancelled_waiter_is_removed_without_consuming_credit() {
  let limiter = limiter(10);
  let mut drain = limiter.flow(BandwidthDirection::Upload);
  assert_eq!(drain.acquire(10).await.unwrap().bytes(), 10);

  let mut cancelled = limiter.flow(BandwidthDirection::Upload);
  let mut cancelled_wait = Box::pin(cancelled.acquire(10));
  assert!(matches!(poll!(cancelled_wait.as_mut()), Poll::Pending));
  drop(cancelled_wait);

  tokio::time::advance(Duration::from_secs(1)).await;
  let mut survivor = limiter.flow(BandwidthDirection::Upload);
  assert_eq!(survivor.acquire(10).await.unwrap().bytes(), 10);
}

#[tokio::test(start_paused = true)]
async fn refundable_grant_returns_exact_credit_unless_committed() {
  let limiter = limiter(10);
  let mut flow = limiter.flow(BandwidthDirection::Upload);
  let mut refundable = flow.acquire_refundable(4).await.unwrap();
  refundable
    .merge(flow.acquire_refundable(3).await.unwrap())
    .unwrap();
  assert_eq!(refundable.bytes(), 7);
  assert_eq!(refundable.waited(), Duration::ZERO);
  refundable.refund();
  assert_eq!(flow.acquire(10).await.unwrap().bytes(), 10);

  let committed = {
    let committed = flow.acquire_refundable(1);
    tokio::pin!(committed);
    assert!(matches!(poll!(committed.as_mut()), Poll::Pending));
    tokio::time::advance(Duration::from_millis(100)).await;
    committed.await.unwrap()
  };
  assert_eq!(committed.commit().bytes(), 1);

  let next = flow.acquire(1);
  tokio::pin!(next);
  assert!(matches!(poll!(next.as_mut()), Poll::Pending));
  tokio::time::advance(Duration::from_millis(100)).await;
  assert_eq!(next.await.unwrap().bytes(), 1);
}

#[tokio::test(start_paused = true)]
async fn pending_acquisition_queue_fails_closed_at_its_memory_bound() {
  let limiter = limiter(1);
  let mut drain = limiter.flow(BandwidthDirection::Upload);
  assert_eq!(drain.acquire(1).await.unwrap().bytes(), 1);

  let mut waiters = Vec::with_capacity(MAX_PENDING_BANDWIDTH_ACQUISITIONS);
  for _ in 0..MAX_PENDING_BANDWIDTH_ACQUISITIONS {
    let limiter = limiter.clone();
    waiters.push(tokio::spawn(async move {
      let mut flow = limiter.flow(BandwidthDirection::Upload);
      flow.acquire(1).await
    }));
  }
  for _ in 0..MAX_PENDING_BANDWIDTH_ACQUISITIONS {
    let pending = limiter.state_guard().unwrap().buckets[BandwidthDirection::Upload.index()]
      .queue
      .len();
    if pending == MAX_PENDING_BANDWIDTH_ACQUISITIONS {
      break;
    }
    tokio::task::yield_now().await;
  }
  assert_eq!(
    limiter.state_guard().unwrap().buckets[BandwidthDirection::Upload.index()]
      .queue
      .len(),
    MAX_PENDING_BANDWIDTH_ACQUISITIONS
  );

  let mut overflow = limiter.flow(BandwidthDirection::Upload);
  assert_eq!(
    overflow.acquire(1).await,
    Err(BandwidthError::QueueFull {
      max_pending: MAX_PENDING_BANDWIDTH_ACQUISITIONS,
    })
  );
  for waiter in waiters {
    waiter.abort();
  }
}

#[test]
fn refill_arithmetic_saturates_at_the_one_second_capacity() {
  let now = Instant::now();
  let mut bucket = BucketState::new(limited(u64::MAX), now);
  bucket.credit_units = 0;

  bucket.refill(now + Duration::from_secs(2));

  assert_eq!(bucket.credit_units, bucket.capacity_units());
  assert_eq!(bucket.capacity_bytes(), u64::MAX);
}

#[tokio::test(start_paused = true)]
async fn cancelling_an_assigned_reservation_refunds_it_to_the_next_flow() {
  let limiter = limiter(10);
  let mut drain = limiter.flow(BandwidthDirection::Upload);
  assert_eq!(drain.acquire(10).await.unwrap().bytes(), 10);

  let mut cancelled = limiter.flow(BandwidthDirection::Upload);
  let mut survivor = limiter.flow(BandwidthDirection::Upload);
  let mut cancelled_wait = Box::pin(cancelled.acquire(10));
  let survivor_wait = survivor.acquire(10);
  tokio::pin!(survivor_wait);
  assert!(matches!(poll!(cancelled_wait.as_mut()), Poll::Pending));
  assert!(matches!(poll!(survivor_wait.as_mut()), Poll::Pending));

  tokio::time::advance(Duration::from_secs(1)).await;
  // Polling the second waiter runs the scheduler and assigns the available
  // reservation to the older first waiter.
  assert!(matches!(poll!(survivor_wait.as_mut()), Poll::Pending));
  drop(cancelled_wait);
  assert_eq!(survivor_wait.await.unwrap().bytes(), 10);
}

#[tokio::test(start_paused = true)]
async fn upload_and_download_buckets_are_independent() {
  let limiter = limiter(10);
  let mut upload = limiter.flow(BandwidthDirection::Upload);
  let mut download = limiter.flow(BandwidthDirection::Download);
  assert_eq!(upload.acquire(10).await.unwrap().bytes(), 10);
  assert_eq!(download.acquire(10).await.unwrap().bytes(), 10);

  let upload_wait = upload.acquire(1);
  let download_wait = download.acquire(1);
  tokio::pin!(upload_wait);
  tokio::pin!(download_wait);
  assert!(matches!(poll!(upload_wait.as_mut()), Poll::Pending));
  assert!(matches!(poll!(download_wait.as_mut()), Poll::Pending));
  tokio::time::advance(Duration::from_millis(100)).await;
  assert_eq!(upload_wait.await.unwrap().bytes(), 1);
  assert_eq!(download_wait.await.unwrap().bytes(), 1);
}

#[tokio::test(start_paused = true)]
async fn rate_update_preserves_credit_without_minting_a_larger_burst() {
  let limiter = limiter(100);
  let mut flow = limiter.flow(BandwidthDirection::Upload);
  assert_eq!(flow.acquire(100).await.unwrap().bytes(), 100);
  tokio::time::advance(Duration::from_millis(500)).await;

  limiter
    .update(BandwidthPolicy::new(limited(200), limited(100)))
    .unwrap();
  assert_eq!(flow.acquire(100).await.unwrap().bytes(), 50);

  let last_byte = flow.acquire(1);
  tokio::pin!(last_byte);
  assert!(matches!(poll!(last_byte.as_mut()), Poll::Pending));
  tokio::time::advance(Duration::from_millis(4)).await;
  assert!(matches!(poll!(last_byte.as_mut()), Poll::Pending));
  tokio::time::advance(Duration::from_millis(1)).await;
  assert_eq!(last_byte.await.unwrap().bytes(), 1);
}

#[tokio::test(start_paused = true)]
async fn unchanged_policy_does_not_reset_credit() {
  let limiter = limiter(20);
  let mut flow = limiter.flow(BandwidthDirection::Upload);
  assert_eq!(flow.acquire(20).await.unwrap().bytes(), 20);
  limiter
    .update(BandwidthPolicy::new(limited(20), limited(20)))
    .unwrap();

  let wait = flow.acquire(1);
  tokio::pin!(wait);
  assert!(matches!(poll!(wait.as_mut()), Poll::Pending));
  tokio::time::advance(Duration::from_millis(49)).await;
  assert!(matches!(poll!(wait.as_mut()), Poll::Pending));
  tokio::time::advance(Duration::from_millis(1)).await;
  assert_eq!(wait.await.unwrap().bytes(), 1);
}

#[tokio::test(start_paused = true)]
async fn disabling_a_direction_releases_waiters() {
  let limiter = limiter(10);
  let mut flow = limiter.flow(BandwidthDirection::Download);
  assert_eq!(flow.acquire(10).await.unwrap().bytes(), 10);

  let wait = flow.acquire(7);
  tokio::pin!(wait);
  assert!(matches!(poll!(wait.as_mut()), Poll::Pending));
  limiter
    .update(BandwidthPolicy::new(limited(10), BandwidthRate::Unlimited))
    .unwrap();
  assert_eq!(wait.await.unwrap().bytes(), 7);
}

#[tokio::test(start_paused = true)]
async fn indivisible_item_uses_only_bounded_debt_then_repays_it() {
  let limiter = limiter(10);
  let mut datagram = limiter.flow(BandwidthDirection::Download);
  assert_eq!(
    datagram.acquire_indivisible(15, 5).await.unwrap().bytes(),
    15
  );

  let next = datagram.acquire(1);
  tokio::pin!(next);
  assert!(matches!(poll!(next.as_mut()), Poll::Pending));
  tokio::time::advance(Duration::from_millis(500)).await;
  assert!(matches!(poll!(next.as_mut()), Poll::Pending));
  tokio::time::advance(Duration::from_millis(99)).await;
  assert!(matches!(poll!(next.as_mut()), Poll::Pending));
  tokio::time::advance(Duration::from_millis(1)).await;
  assert_eq!(next.await.unwrap().bytes(), 1);
}

#[tokio::test(start_paused = true)]
async fn indivisible_item_rejects_debt_above_the_explicit_bound() {
  let limiter = limiter(10);
  let mut datagram = limiter.flow(BandwidthDirection::Download);
  assert_eq!(
    datagram.acquire_indivisible(15, 4).await,
    Err(BandwidthError::IndivisibleDebtLimit {
      bytes: 15,
      capacity_bytes: 10,
      max_debt_bytes: 4,
    })
  );
}

use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;

use crate::state::AppHandle;

pub(crate) async fn run_sampler(state: AppHandle, mut shutdown: watch::Receiver<bool>) {
  let mut previous = None;
  loop {
    let target = Duration::from_millis(state.snapshot().config.overload.sample_interval_ms);
    let Some((now, lag)) = wait_for_next_sample(previous, target, &mut shutdown).await else {
      return;
    };
    previous = Some(now);
    let snapshot = state.snapshot();
    snapshot
      .overload
      .sample(
        lag,
        snapshot.metrics.shared_state_waiters(),
        snapshot.lifecycle.as_ref(),
      )
      .await;
  }
}

async fn wait_for_next_sample(
  previous: Option<Instant>,
  target: Duration,
  shutdown: &mut watch::Receiver<bool>,
) -> Option<(Instant, Duration)> {
  let wait = previous
    .map(|started| target.saturating_sub(started.elapsed()))
    .unwrap_or_default();
  tokio::select! {
    _ = shutdown.changed() => None,
    _ = tokio::time::sleep(wait) => {
      let now = Instant::now();
      let lag = previous
        .map(|started| now.duration_since(started).saturating_sub(target))
        .unwrap_or_default();
      Some((now, lag))
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  use crate::config::{OverloadConfig, PriorityClass};
  use crate::lifecycle::LifecycleState;
  use crate::overload::{OverloadRuntime, OverloadState, PressureSample, WORK_KIND_COUNT};

  fn sample_for_lag(lag: Duration) -> PressureSample {
    PressureSample {
      memory_ratio: Some(0.1),
      fd_ratio: Some(0.1),
      cpu_ratio: Some(0.1),
      event_loop_lag_ms: lag.as_millis().min(u128::from(u64::MAX)) as u64,
      work: [0; WORK_KIND_COUNT],
    }
  }

  #[tokio::test(start_paused = true)]
  async fn default_interval_does_not_fabricate_soft_overload() {
    let config = OverloadConfig {
      enabled: true,
      ..Default::default()
    };
    let runtime = OverloadRuntime::new(&config);
    let lifecycle = LifecycleState::default();
    let (_shutdown_tx, mut shutdown) = watch::channel(false);
    let mut previous = None;

    for _ in 0..3 {
      let (now, lag) = wait_for_next_sample(
        previous,
        Duration::from_millis(config.sample_interval_ms),
        &mut shutdown,
      )
      .await
      .expect("live sampler should wake at the configured interval");
      assert_eq!(lag, Duration::ZERO);
      previous = Some(now);
      runtime.apply_pressure_sample(sample_for_lag(lag), &lifecycle);
    }

    assert_eq!(runtime.state(), OverloadState::Normal);
    assert!(!runtime.reject_priority(PriorityClass::Background));
  }

  #[tokio::test(start_paused = true)]
  async fn actual_sampler_overrun_still_triggers_soft_overload() {
    let config = OverloadConfig {
      enabled: true,
      ..Default::default()
    };
    let runtime = OverloadRuntime::new(&config);
    let lifecycle = LifecycleState::default();
    let (_shutdown_tx, mut shutdown) = watch::channel(false);

    for _ in 0..config.soft_enter_samples {
      let started = Instant::now()
        .checked_sub(Duration::from_millis(config.sample_interval_ms + 50))
        .expect("short test interval should be representable");
      let (_, lag) = wait_for_next_sample(
        Some(started),
        Duration::from_millis(config.sample_interval_ms),
        &mut shutdown,
      )
      .await
      .expect("live sampler should record an overdue wakeup");
      assert!(lag >= Duration::from_millis(50));
      runtime.apply_pressure_sample(sample_for_lag(lag), &lifecycle);
    }

    assert_eq!(runtime.state(), OverloadState::Soft);
    assert!(runtime.reject_priority(PriorityClass::Background));
  }

  #[tokio::test(start_paused = true)]
  async fn pending_sample_wait_returns_on_shutdown() {
    let (shutdown_tx, mut shutdown) = watch::channel(false);
    shutdown_tx
      .send(true)
      .expect("sampler shutdown receiver should stay subscribed");

    assert!(
      wait_for_next_sample(
        Some(Instant::now()),
        Duration::from_millis(250),
        &mut shutdown,
      )
      .await
      .is_none()
    );
  }
}

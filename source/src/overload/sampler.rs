use std::time::{Duration, Instant};

use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

use crate::state::AppHandle;

pub(crate) async fn run_sampler(state: AppHandle, mut shutdown: watch::Receiver<bool>) {
  let mut interval = tokio::time::interval(Duration::from_millis(100));
  interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
  let mut previous = None;
  loop {
    tokio::select! {
      _ = shutdown.changed() => return,
      _ = interval.tick() => {
        let snapshot = state.snapshot();
        let target = Duration::from_millis(snapshot.config.overload.sample_interval_ms);
        let now = Instant::now();
        let elapsed = previous.map(|started| now.duration_since(started));
        if elapsed.is_some_and(|elapsed| elapsed < target) {
          continue;
        }
        let lag = elapsed.map(|elapsed| elapsed.saturating_sub(target)).unwrap_or_default();
        previous = Some(now);
        snapshot
          .overload
          .sample(lag, snapshot.metrics.shared_state_waiters(), snapshot.lifecycle.as_ref())
          .await;
      }
    }
  }
}

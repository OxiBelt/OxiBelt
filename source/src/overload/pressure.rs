use crate::config::{OverloadConfig, OverloadThresholds};

use super::{OverloadState, SIGNAL_COUNT, STATE_COUNT, Signal, WORK_KIND_COUNT, WorkKind};

#[derive(Clone, Copy)]
pub(super) struct PressureSample {
  pub(super) memory_ratio: Option<f64>,
  pub(super) fd_ratio: Option<f64>,
  pub(super) cpu_ratio: Option<f64>,
  pub(super) event_loop_lag_ms: u64,
  pub(super) work: [u64; WORK_KIND_COUNT],
}

pub(super) fn threshold_signal(
  sample: &PressureSample,
  config: &OverloadConfig,
  hard: bool,
) -> Option<Signal> {
  let thresholds = &config.thresholds;
  let ratio = |value: Option<f64>, soft: f64, hard_value: f64| {
    value.is_some_and(|value| value >= if hard { hard_value } else { soft })
  };
  if ratio(
    sample.memory_ratio,
    thresholds.memory_soft_ratio,
    thresholds.memory_hard_ratio,
  ) {
    return Some(Signal::Memory);
  }
  if ratio(
    sample.fd_ratio,
    thresholds.fd_soft_ratio,
    thresholds.fd_hard_ratio,
  ) {
    return Some(Signal::FileDescriptors);
  }
  if ratio(
    sample.cpu_ratio,
    thresholds.cpu_soft_ratio,
    thresholds.cpu_hard_ratio,
  ) {
    return Some(Signal::Cpu);
  }
  if sample.event_loop_lag_ms
    >= if hard {
      thresholds.event_loop_lag_hard_ms
    } else {
      thresholds.event_loop_lag_soft_ms
    }
  {
    return Some(Signal::EventLoopLag);
  }
  if sample.work[WorkKind::SharedStateWaiters as usize]
    >= if hard {
      thresholds.shared_state_waiters_hard
    } else {
      thresholds.shared_state_waiters_soft
    }
  {
    return Some(Signal::SharedStateWaiters);
  }
  optional_work_thresholds(thresholds, hard)
    .into_iter()
    .find_map(|(kind, threshold)| {
      (sample.work[kind as usize] >= threshold).then(|| signal_for_work(kind))
    })
}

pub(super) fn below_recovery_thresholds(sample: &PressureSample, config: &OverloadConfig) -> bool {
  let thresholds = &config.thresholds;
  let ratio = config.recovery_ratio;
  let below = |value: Option<f64>, limit: f64| value.is_none_or(|value| value < limit * ratio);
  below(sample.memory_ratio, thresholds.memory_soft_ratio)
    && below(sample.fd_ratio, thresholds.fd_soft_ratio)
    && below(sample.cpu_ratio, thresholds.cpu_soft_ratio)
    && sample.event_loop_lag_ms < (thresholds.event_loop_lag_soft_ms as f64 * ratio) as u64
    && sample.work[WorkKind::SharedStateWaiters as usize]
      < (thresholds.shared_state_waiters_soft as f64 * ratio) as u64
    && optional_work_thresholds(thresholds, false)
      .into_iter()
      .all(|(kind, threshold)| sample.work[kind as usize] < (threshold as f64 * ratio) as u64)
}

fn optional_work_thresholds(thresholds: &OverloadThresholds, hard: bool) -> Vec<(WorkKind, u64)> {
  let choose = |soft, hard_value| if hard { hard_value } else { soft };
  [
    (
      WorkKind::DownstreamConnections,
      choose(
        thresholds.downstream_connections_soft,
        thresholds.downstream_connections_hard,
      ),
    ),
    (
      WorkKind::ActiveHttpRequests,
      choose(
        thresholds.active_requests_soft,
        thresholds.active_requests_hard,
      ),
    ),
    (
      WorkKind::H2Streams,
      choose(thresholds.h2_streams_soft, thresholds.h2_streams_hard),
    ),
    (
      WorkKind::H3Streams,
      choose(thresholds.h3_streams_soft, thresholds.h3_streams_hard),
    ),
    (
      WorkKind::PendingUpstreamRequests,
      choose(
        thresholds.pending_upstream_requests_soft,
        thresholds.pending_upstream_requests_hard,
      ),
    ),
    (
      WorkKind::RetryConcurrency,
      choose(
        thresholds.retry_concurrency_soft,
        thresholds.retry_concurrency_hard,
      ),
    ),
    (
      WorkKind::CacheFillConcurrency,
      choose(
        thresholds.cache_fill_concurrency_soft,
        thresholds.cache_fill_concurrency_hard,
      ),
    ),
    (
      WorkKind::WafBodyInspectionConcurrency,
      choose(
        thresholds.waf_body_inspection_concurrency_soft,
        thresholds.waf_body_inspection_concurrency_hard,
      ),
    ),
    (
      WorkKind::CompressionJobs,
      choose(
        thresholds.compression_jobs_soft,
        thresholds.compression_jobs_hard,
      ),
    ),
    (
      WorkKind::DecompressionJobs,
      choose(
        thresholds.decompression_jobs_soft,
        thresholds.decompression_jobs_hard,
      ),
    ),
    (
      WorkKind::RequestBodyBufferedBytes,
      choose(
        thresholds.request_body_buffered_bytes_soft,
        thresholds.request_body_buffered_bytes_hard,
      ),
    ),
  ]
  .into_iter()
  .filter_map(|(kind, threshold)| threshold.map(|threshold| (kind, threshold)))
  .collect()
}

pub(super) fn signal_for_work(kind: WorkKind) -> Signal {
  match kind {
    WorkKind::DownstreamConnections => Signal::DownstreamConnections,
    WorkKind::ActiveHttpRequests => Signal::ActiveRequests,
    WorkKind::H2Streams => Signal::H2Streams,
    WorkKind::H3Streams => Signal::H3Streams,
    WorkKind::PendingUpstreamRequests => Signal::PendingUpstreamRequests,
    WorkKind::RetryConcurrency => Signal::RetryConcurrency,
    WorkKind::CacheFillConcurrency => Signal::CacheFillConcurrency,
    WorkKind::WafBodyInspectionConcurrency => Signal::WafBodyInspectionConcurrency,
    WorkKind::CompressionJobs => Signal::CompressionJobs,
    WorkKind::DecompressionJobs => Signal::DecompressionJobs,
    WorkKind::SharedStateWaiters => Signal::SharedStateWaiters,
    WorkKind::RequestBodyBufferedBytes => Signal::RequestBodyBufferedBytes,
  }
}

pub(super) const fn transition_index(
  from: OverloadState,
  to: OverloadState,
  signal: Signal,
) -> usize {
  ((from as usize * STATE_COUNT) + to as usize) * SIGNAL_COUNT + signal as usize
}

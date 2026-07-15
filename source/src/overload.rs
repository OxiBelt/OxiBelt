//! Global overload detection, bounded admission, and recovery state.
//! The manager owns no client-derived labels and is shared across snapshot reloads.

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use arc_swap::ArcSwap;
use http::StatusCode;
use tracing::info;

use crate::config::{OverloadConfig, PriorityClass};
use crate::lifecycle::LifecycleState;
use crate::runtime_health::{
  PROCESS_GENERATION, RuntimeHealth, RuntimeSubsystem, RuntimeSubsystemState,
};
mod leases;
mod metrics;
mod pressure;
mod process;
mod sampler;
pub use leases::{ControlLease, ControlPlane, OverloadRejection, RequestLease, WorkLease};
use pressure::{
  PressureSample, below_recovery_thresholds, signal_for_work, threshold_signal, transition_index,
};
use process::{ProcessSample, read_process_sample};
pub(crate) use sampler::run_sampler;

const STATE_COUNT: usize = 3;
const SIGNAL_COUNT: usize = 17;
const WORK_KIND_COUNT: usize = 12;
const REJECTION_BOUNDARY_COUNT: usize = 4;
const CONTROL_PLANE_COUNT: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OverloadState {
  Normal = 0,
  Soft = 1,
  Hard = 2,
}

impl OverloadState {
  const ALL: [Self; STATE_COUNT] = [Self::Normal, Self::Soft, Self::Hard];

  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Normal => "normal",
      Self::Soft => "soft",
      Self::Hard => "hard",
    }
  }

  fn from_u8(value: u8) -> Self {
    match value {
      1 => Self::Soft,
      2 => Self::Hard,
      _ => Self::Normal,
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WorkKind {
  DownstreamConnections,
  ActiveHttpRequests,
  H2Streams,
  H3Streams,
  PendingUpstreamRequests,
  RetryConcurrency,
  CacheFillConcurrency,
  WafBodyInspectionConcurrency,
  CompressionJobs,
  DecompressionJobs,
  SharedStateWaiters,
  RequestBodyBufferedBytes,
}

impl WorkKind {
  const ALL: [Self; WORK_KIND_COUNT] = [
    Self::DownstreamConnections,
    Self::ActiveHttpRequests,
    Self::H2Streams,
    Self::H3Streams,
    Self::PendingUpstreamRequests,
    Self::RetryConcurrency,
    Self::CacheFillConcurrency,
    Self::WafBodyInspectionConcurrency,
    Self::CompressionJobs,
    Self::DecompressionJobs,
    Self::SharedStateWaiters,
    Self::RequestBodyBufferedBytes,
  ];

  const fn as_str(self) -> &'static str {
    match self {
      Self::DownstreamConnections => "downstream_connections",
      Self::ActiveHttpRequests => "active_http_requests",
      Self::H2Streams => "h2_streams",
      Self::H3Streams => "h3_streams",
      Self::PendingUpstreamRequests => "pending_upstream_requests",
      Self::RetryConcurrency => "retry_concurrency",
      Self::CacheFillConcurrency => "cache_fill_concurrency",
      Self::WafBodyInspectionConcurrency => "waf_body_inspection_concurrency",
      Self::CompressionJobs => "compression_jobs",
      Self::DecompressionJobs => "decompression_jobs",
      Self::SharedStateWaiters => "shared_state_waiters",
      Self::RequestBodyBufferedBytes => "request_body_buffered_bytes",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum Signal {
  Memory,
  FileDescriptors,
  Cpu,
  EventLoopLag,
  SharedStateWaiters,
  DownstreamConnections,
  ActiveRequests,
  H2Streams,
  H3Streams,
  PendingUpstreamRequests,
  RetryConcurrency,
  CacheFillConcurrency,
  WafBodyInspectionConcurrency,
  CompressionJobs,
  DecompressionJobs,
  RequestBodyBufferedBytes,
  Unavailable,
}

impl Signal {
  const ALL: [Self; SIGNAL_COUNT] = [
    Self::Memory,
    Self::FileDescriptors,
    Self::Cpu,
    Self::EventLoopLag,
    Self::SharedStateWaiters,
    Self::DownstreamConnections,
    Self::ActiveRequests,
    Self::H2Streams,
    Self::H3Streams,
    Self::PendingUpstreamRequests,
    Self::RetryConcurrency,
    Self::CacheFillConcurrency,
    Self::WafBodyInspectionConcurrency,
    Self::CompressionJobs,
    Self::DecompressionJobs,
    Self::RequestBodyBufferedBytes,
    Self::Unavailable,
  ];

  const fn as_str(self) -> &'static str {
    match self {
      Self::Memory => "memory",
      Self::FileDescriptors => "file_descriptors",
      Self::Cpu => "cpu",
      Self::EventLoopLag => "event_loop_lag",
      Self::SharedStateWaiters => "shared_state_waiters",
      Self::DownstreamConnections => "downstream_connections",
      Self::ActiveRequests => "active_requests",
      Self::H2Streams => "h2_streams",
      Self::H3Streams => "h3_streams",
      Self::PendingUpstreamRequests => "pending_upstream_requests",
      Self::RetryConcurrency => "retry_concurrency",
      Self::CacheFillConcurrency => "cache_fill_concurrency",
      Self::WafBodyInspectionConcurrency => "waf_body_inspection_concurrency",
      Self::CompressionJobs => "compression_jobs",
      Self::DecompressionJobs => "decompression_jobs",
      Self::RequestBodyBufferedBytes => "request_body_buffered_bytes",
      Self::Unavailable => "signal_unavailable",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OverloadBoundary {
  Connection,
  Stream,
  Request,
  Priority,
}

impl OverloadBoundary {
  const ALL: [Self; REJECTION_BOUNDARY_COUNT] = [
    Self::Connection,
    Self::Stream,
    Self::Request,
    Self::Priority,
  ];

  const fn as_str(self) -> &'static str {
    match self {
      Self::Connection => "connection",
      Self::Stream => "stream",
      Self::Request => "request",
      Self::Priority => "priority",
    }
  }
}

#[derive(Default)]
struct SamplingState {
  soft_samples: u32,
  recovery_samples: u32,
  probe_failure_since: Option<Instant>,
  cpu: Option<CpuBaseline>,
}

#[derive(Clone, Copy)]
struct CpuBaseline {
  usage_usec: u64,
  at: Instant,
}

#[derive(Default)]
struct LatestSample {
  rss_bytes: u64,
  memory_current_bytes: u64,
  memory_limit_bytes: u64,
  fd_used: u64,
  fd_limit: u64,
  event_loop_lag_ms: u64,
  memory_ratio: f64,
  fd_ratio: f64,
  cpu_ratio: f64,
}

/// Shared manager retained across immutable application snapshots.
pub struct OverloadRuntime {
  config: ArcSwap<OverloadConfig>,
  state: AtomicU8,
  enabled: AtomicBool,
  work: [AtomicU64; WORK_KIND_COUNT],
  transitions: [AtomicU64; STATE_COUNT * STATE_COUNT * SIGNAL_COUNT],
  signal_available: [AtomicBool; SIGNAL_COUNT],
  rejections: [AtomicU64; REJECTION_BOUNDARY_COUNT],
  control_connections: [AtomicU64; CONTROL_PLANE_COUNT],
  control_requests: [AtomicU64; CONTROL_PLANE_COUNT],
  latest: Mutex<LatestSample>,
  sampling: Mutex<SamplingState>,
  runtime_health: Arc<RuntimeHealth>,
}

impl std::fmt::Debug for OverloadRuntime {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("OverloadRuntime")
      .field("state", &self.state_label())
      .field("enabled", &self.enabled.load(Ordering::Relaxed))
      .finish_non_exhaustive()
  }
}

impl OverloadRuntime {
  pub fn new(config: &OverloadConfig) -> Arc<Self> {
    Self::new_with_health(config, Arc::new(RuntimeHealth::default()))
  }

  pub(crate) fn new_with_health(
    config: &OverloadConfig,
    runtime_health: Arc<RuntimeHealth>,
  ) -> Arc<Self> {
    Arc::new(Self {
      config: ArcSwap::from_pointee(config.clone()),
      state: AtomicU8::new(OverloadState::Normal as u8),
      enabled: AtomicBool::new(config.enabled),
      work: std::array::from_fn(|_| AtomicU64::new(0)),
      transitions: std::array::from_fn(|_| AtomicU64::new(0)),
      signal_available: std::array::from_fn(|_| AtomicBool::new(false)),
      rejections: std::array::from_fn(|_| AtomicU64::new(0)),
      control_connections: std::array::from_fn(|_| AtomicU64::new(0)),
      control_requests: std::array::from_fn(|_| AtomicU64::new(0)),
      latest: Mutex::new(LatestSample::default()),
      sampling: Mutex::new(SamplingState::default()),
      runtime_health,
    })
  }

  fn mark_lock_recovery(&self) {
    self
      .runtime_health
      .record_lock_recovery(RuntimeSubsystem::Overload);
    self.runtime_health.set_subsystem_state(
      PROCESS_GENERATION,
      RuntimeSubsystem::Overload,
      RuntimeSubsystemState::Degraded,
      self.enabled.load(Ordering::Acquire),
    );
  }

  fn sampling_guard(&self) -> MutexGuard<'_, SamplingState> {
    match self.sampling.lock() {
      Ok(sampling) => sampling,
      Err(poisoned) => {
        let mut sampling = poisoned.into_inner();
        *sampling = SamplingState::default();
        self.sampling.clear_poison();
        self.mark_lock_recovery();
        sampling
      }
    }
  }

  fn latest_guard(&self) -> MutexGuard<'_, LatestSample> {
    match self.latest.lock() {
      Ok(latest) => latest,
      Err(poisoned) => {
        let mut latest = poisoned.into_inner();
        *latest = LatestSample::default();
        self.latest.clear_poison();
        self.mark_lock_recovery();
        latest
      }
    }
  }

  pub fn configure(&self, config: &OverloadConfig, lifecycle: &LifecycleState) {
    self.config.store(Arc::new(config.clone()));
    self.enabled.store(config.enabled, Ordering::Relaxed);
    if !config.enabled {
      self.transition(OverloadState::Normal, Signal::Unavailable, lifecycle);
      lifecycle.clear_overload_draining();
    } else if self.state() == OverloadState::Hard && config.actions.hard.enter_recoverable_drain {
      lifecycle.set_overload_draining();
    } else {
      lifecycle.clear_overload_draining();
    }
  }

  pub fn bootstrap_validate(&self) -> anyhow::Result<()> {
    let sample = read_process_sample().context("failed to sample overload bootstrap signals")?;
    if sample.rss_bytes == 0 || sample.fd_limit == 0 {
      return Err(anyhow!(
        "overload bootstrap did not provide RSS and file-descriptor limits"
      ));
    }
    Ok(())
  }

  pub fn state(&self) -> OverloadState {
    OverloadState::from_u8(self.state.load(Ordering::Relaxed))
  }

  pub fn state_label(&self) -> &'static str {
    self.state().as_str()
  }

  pub fn response_status(&self) -> StatusCode {
    let code = self.config.load().actions.hard.response_status;
    StatusCode::from_u16(code).unwrap_or(StatusCode::SERVICE_UNAVAILABLE)
  }

  pub fn retry_after_seconds(&self) -> u64 {
    self.config.load().actions.hard.retry_after_seconds
  }

  pub fn reject_large_request_body(&self, content_length: Option<u64>) -> bool {
    let config = self.config.load();
    self.state() == OverloadState::Hard
      && config.actions.hard.stop_large_request_bodies
      && content_length
        .map(|length| length > config.actions.hard.large_request_body_threshold_bytes)
        .unwrap_or(true)
  }

  pub fn reject_priority(&self, priority: PriorityClass) -> bool {
    let config = self.config.load();
    let reject = self.state() != OverloadState::Normal
      && config
        .actions
        .soft
        .reject_priority_classes
        .contains(&priority);
    if reject {
      self.rejections[OverloadBoundary::Priority as usize].fetch_add(1, Ordering::Relaxed);
    }
    reject
  }

  pub fn cache_fill_disabled(&self) -> bool {
    let config = self.config.load();
    match self.state() {
      OverloadState::Normal => false,
      OverloadState::Soft => config.actions.soft.disable_cache_fill,
      OverloadState::Hard => {
        config.actions.soft.disable_cache_fill || config.actions.hard.disable_cache_fill
      }
    }
  }

  pub fn prefer_cached_or_stale(&self) -> bool {
    self.state() != OverloadState::Normal && self.config.load().actions.soft.prefer_cached_or_stale
  }

  pub fn compression_level_cap(&self) -> Option<u8> {
    let config = self.config.load();
    match self.state() {
      OverloadState::Normal => None,
      OverloadState::Soft => config
        .actions
        .soft
        .compression_level_cap
        .filter(|cap| *cap > 0),
      OverloadState::Hard if config.actions.hard.disable_compression => Some(0),
      OverloadState::Hard => config
        .actions
        .soft
        .compression_level_cap
        .filter(|cap| *cap > 0),
    }
  }

  pub fn retries_disabled(&self) -> bool {
    self.state() == OverloadState::Hard && self.config.load().actions.hard.disable_retries
  }

  pub fn request_mirroring_disabled(&self) -> bool {
    self.state() == OverloadState::Hard && self.config.load().actions.hard.disable_request_mirroring
  }

  pub fn retry_budget_multiplier(&self) -> f64 {
    if self.state() == OverloadState::Normal {
      1.0
    } else {
      self.config.load().actions.soft.retry_budget_multiplier
    }
  }

  pub async fn sample(
    &self,
    event_loop_lag: Duration,
    shared_state_waiters: u64,
    lifecycle: &LifecycleState,
  ) {
    if !self.enabled.load(Ordering::Relaxed) {
      lifecycle.clear_overload_draining();
      return;
    }
    match tokio::task::spawn_blocking(read_process_sample).await {
      Ok(Ok(sample)) => {
        self.apply_process_sample(sample, event_loop_lag, shared_state_waiters, lifecycle)
      }
      Ok(Err(_)) | Err(_) => self.record_probe_failure(lifecycle),
    }
  }

  fn apply_process_sample(
    &self,
    sample: ProcessSample,
    event_loop_lag: Duration,
    shared_state_waiters: u64,
    lifecycle: &LifecycleState,
  ) {
    let now = Instant::now();
    self.work[WorkKind::SharedStateWaiters as usize].store(shared_state_waiters, Ordering::Relaxed);
    let cpu_ratio = {
      let mut sampling = self.sampling_guard();
      let ratio = sampling.cpu.and_then(|previous| {
        let elapsed_usec = now.duration_since(previous.at).as_micros() as u64;
        let consumed_usec = sample.cpu_usage_usec.saturating_sub(previous.usage_usec);
        (elapsed_usec > 0 && sample.cpu_usage_usec > 0).then(|| {
          (consumed_usec as f64 / elapsed_usec as f64 / sample.cpu_capacity.max(1.0)).min(1.0)
        })
      });
      sampling.cpu = Some(CpuBaseline {
        usage_usec: sample.cpu_usage_usec,
        at: now,
      });
      sampling.probe_failure_since = None;
      ratio
    };
    let memory_ratio = sample.memory_limit_bytes.and_then(|limit| {
      (limit > 0).then(|| sample.memory_current_bytes.max(sample.rss_bytes) as f64 / limit as f64)
    });
    let reserved_file_descriptors = self.config.load().reserved_capacity.file_descriptors;
    let fd_ratio = (sample.fd_limit > 0).then(|| {
      sample.fd_used.saturating_add(reserved_file_descriptors) as f64 / sample.fd_limit as f64
    });
    {
      let mut latest = self.latest_guard();
      latest.rss_bytes = sample.rss_bytes;
      latest.memory_current_bytes = sample.memory_current_bytes;
      latest.memory_limit_bytes = sample.memory_limit_bytes.unwrap_or(0);
      latest.fd_used = sample.fd_used;
      latest.fd_limit = sample.fd_limit;
      latest.event_loop_lag_ms = event_loop_lag.as_millis().min(u128::from(u64::MAX)) as u64;
      latest.memory_ratio = memory_ratio.unwrap_or(0.0);
      latest.fd_ratio = fd_ratio.unwrap_or(0.0);
      latest.cpu_ratio = cpu_ratio.unwrap_or(0.0);
    }
    for (signal, available) in [
      (Signal::Memory, memory_ratio.is_some()),
      (Signal::FileDescriptors, fd_ratio.is_some()),
      (Signal::Cpu, cpu_ratio.is_some()),
      (Signal::EventLoopLag, true),
      (Signal::SharedStateWaiters, true),
    ] {
      self.signal_available[signal as usize].store(available, Ordering::Relaxed);
    }
    for kind in WorkKind::ALL {
      self.signal_available[signal_for_work(kind) as usize].store(true, Ordering::Relaxed);
    }
    self.apply_pressure_sample(
      PressureSample {
        memory_ratio,
        fd_ratio,
        cpu_ratio,
        event_loop_lag_ms: event_loop_lag.as_millis().min(u128::from(u64::MAX)) as u64,
        work: std::array::from_fn(|index| {
          let active = self.work[index].load(Ordering::Relaxed);
          if index == WorkKind::SharedStateWaiters as usize {
            active.max(shared_state_waiters)
          } else {
            active
          }
        }),
      },
      lifecycle,
    );
    self.runtime_health.set_subsystem_state(
      PROCESS_GENERATION,
      RuntimeSubsystem::Overload,
      RuntimeSubsystemState::Healthy,
      self.enabled.load(Ordering::Acquire),
    );
  }

  fn record_probe_failure(&self, lifecycle: &LifecycleState) {
    for signal in [Signal::Memory, Signal::FileDescriptors, Signal::Cpu] {
      self.signal_available[signal as usize].store(false, Ordering::Relaxed);
    }
    let stale = {
      let mut sampling = self.sampling_guard();
      let timeout = self.config.load().signal_stale_timeout_ms;
      let first_failure = sampling
        .probe_failure_since
        .get_or_insert_with(Instant::now);
      first_failure.elapsed() >= Duration::from_millis(timeout)
    };
    if stale {
      self.transition(OverloadState::Hard, Signal::Unavailable, lifecycle);
    }
  }

  fn apply_pressure_sample(&self, sample: PressureSample, lifecycle: &LifecycleState) {
    let config = self.config.load_full();
    if let Some(signal) = threshold_signal(&sample, &config, true) {
      self.sampling_guard().soft_samples = 0;
      self.transition(OverloadState::Hard, signal, lifecycle);
      return;
    }
    let soft = threshold_signal(&sample, &config, false);
    let mut sampling = self.sampling_guard();
    match (self.state(), soft) {
      (OverloadState::Normal, Some(signal)) => {
        sampling.soft_samples = sampling.soft_samples.saturating_add(1);
        if sampling.soft_samples >= config.soft_enter_samples {
          sampling.soft_samples = 0;
          sampling.recovery_samples = 0;
          drop(sampling);
          self.transition(OverloadState::Soft, signal, lifecycle);
        }
      }
      (OverloadState::Normal, None) => sampling.soft_samples = 0,
      (OverloadState::Soft | OverloadState::Hard, Some(_)) => sampling.recovery_samples = 0,
      (state @ (OverloadState::Soft | OverloadState::Hard), None) => {
        if below_recovery_thresholds(&sample, &config) {
          sampling.recovery_samples = sampling.recovery_samples.saturating_add(1);
          if sampling.recovery_samples >= config.recovery_samples {
            sampling.recovery_samples = 0;
            drop(sampling);
            let next = if state == OverloadState::Hard {
              OverloadState::Soft
            } else {
              OverloadState::Normal
            };
            self.transition(next, Signal::Unavailable, lifecycle);
          }
        } else {
          sampling.recovery_samples = 0;
        }
      }
    }
  }

  fn transition(&self, next: OverloadState, signal: Signal, lifecycle: &LifecycleState) {
    let previous = OverloadState::from_u8(self.state.swap(next as u8, Ordering::Relaxed));
    if previous == next {
      return;
    }
    self.transitions[transition_index(previous, next, signal)].fetch_add(1, Ordering::Relaxed);
    let config = self.config.load();
    if next == OverloadState::Hard && config.actions.hard.enter_recoverable_drain {
      lifecycle.set_overload_draining();
    } else if next != OverloadState::Hard {
      lifecycle.clear_overload_draining();
    }
    info!(
      previous = previous.as_str(),
      next = next.as_str(),
      signal = signal.as_str(),
      "overload manager state transition"
    );
  }
}

#[cfg(test)]
mod tests;

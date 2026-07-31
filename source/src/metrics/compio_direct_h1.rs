//! Fixed-cardinality telemetry for the persistent Compio direct-H1 service.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use super::{Metrics, StripedCounter, StripedGauge};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum CompioDirectH1SubmissionOutcome {
  Immediate,
  Waited,
  Full,
  Unhealthy,
  Draining,
}

impl CompioDirectH1SubmissionOutcome {
  const ALL: [Self; 5] = [
    Self::Immediate,
    Self::Waited,
    Self::Full,
    Self::Unhealthy,
    Self::Draining,
  ];
  const COUNT: usize = Self::ALL.len();

  const fn as_str(self) -> &'static str {
    match self {
      Self::Immediate => "immediate",
      Self::Waited => "waited",
      Self::Full => "full",
      Self::Unhealthy => "unhealthy",
      Self::Draining => "draining",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum CompioDirectH1WorkerState {
  Starting,
  Healthy,
  Unhealthy,
  Draining,
  Stopped,
}

impl CompioDirectH1WorkerState {
  const ALL: [Self; 5] = [
    Self::Starting,
    Self::Healthy,
    Self::Unhealthy,
    Self::Draining,
    Self::Stopped,
  ];
  const COUNT: usize = Self::ALL.len();

  const fn as_str(self) -> &'static str {
    match self {
      Self::Starting => "starting",
      Self::Healthy => "healthy",
      Self::Unhealthy => "unhealthy",
      Self::Draining => "draining",
      Self::Stopped => "stopped",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum CompioDirectH1ConnectionState {
  Active,
  Idle,
}

impl CompioDirectH1ConnectionState {
  const ALL: [Self; 2] = [Self::Active, Self::Idle];
  const COUNT: usize = Self::ALL.len();

  const fn as_str(self) -> &'static str {
    match self {
      Self::Active => "active",
      Self::Idle => "idle",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum CompioDirectH1ConnectionEvent {
  Created,
  Reused,
  RetiredIdleTimeout,
  RetiredAbsoluteLifetime,
  RetiredStaleGeneration,
  RetiredPeerClose,
  RetiredEof,
  RetiredUpgrade,
  RetiredProtocol,
  RetiredTimeout,
  RetiredCancellation,
  RetiredResidualBytes,
  RetiredPoolFull,
  RetiredIoError,
  RetiredWorkerFailure,
  ClosedShutdown,
}

impl CompioDirectH1ConnectionEvent {
  const ALL: [Self; 16] = [
    Self::Created,
    Self::Reused,
    Self::RetiredIdleTimeout,
    Self::RetiredAbsoluteLifetime,
    Self::RetiredStaleGeneration,
    Self::RetiredPeerClose,
    Self::RetiredEof,
    Self::RetiredUpgrade,
    Self::RetiredProtocol,
    Self::RetiredTimeout,
    Self::RetiredCancellation,
    Self::RetiredResidualBytes,
    Self::RetiredPoolFull,
    Self::RetiredIoError,
    Self::RetiredWorkerFailure,
    Self::ClosedShutdown,
  ];
  const COUNT: usize = Self::ALL.len();

  const fn as_str(self) -> &'static str {
    match self {
      Self::Created => "created",
      Self::Reused => "reused",
      Self::RetiredIdleTimeout => "retired_idle_timeout",
      Self::RetiredAbsoluteLifetime => "retired_absolute_lifetime",
      Self::RetiredStaleGeneration => "retired_stale_generation",
      Self::RetiredPeerClose => "retired_peer_close",
      Self::RetiredEof => "retired_eof",
      Self::RetiredUpgrade => "retired_upgrade",
      Self::RetiredProtocol => "retired_protocol",
      Self::RetiredTimeout => "retired_timeout",
      Self::RetiredCancellation => "retired_cancellation",
      Self::RetiredResidualBytes => "retired_residual_bytes",
      Self::RetiredPoolFull => "retired_pool_full",
      Self::RetiredIoError => "retired_io_error",
      Self::RetiredWorkerFailure => "retired_worker_failure",
      Self::ClosedShutdown => "closed_shutdown",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum CompioDirectH1DispatchOutcome {
  PredispatchFallback,
  PostdispatchFailure,
}

impl CompioDirectH1DispatchOutcome {
  const ALL: [Self; 2] = [Self::PredispatchFallback, Self::PostdispatchFailure];
  const COUNT: usize = Self::ALL.len();

  const fn as_str(self) -> &'static str {
    match self {
      Self::PredispatchFallback => "predispatch_fallback",
      Self::PostdispatchFailure => "postdispatch_failure",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum CompioDirectH1BufferEvent {
  Allocate,
  Reuse,
  Discard,
}

impl CompioDirectH1BufferEvent {
  const ALL: [Self; 3] = [Self::Allocate, Self::Reuse, Self::Discard];
  const COUNT: usize = Self::ALL.len();

  const fn as_str(self) -> &'static str {
    match self {
      Self::Allocate => "allocate",
      Self::Reuse => "reuse",
      Self::Discard => "discard",
    }
  }
}

#[derive(Debug, Default)]
pub(super) struct CompioDirectH1Metrics {
  submissions: [StripedCounter; CompioDirectH1SubmissionOutcome::COUNT],
  worker_counts: [AtomicU64; CompioDirectH1WorkerState::COUNT],
  connection_counts: [StripedGauge; CompioDirectH1ConnectionState::COUNT],
  connection_events: [StripedCounter; CompioDirectH1ConnectionEvent::COUNT],
  dispatches: [StripedCounter; CompioDirectH1DispatchOutcome::COUNT],
  buffer_events: [StripedCounter; CompioDirectH1BufferEvent::COUNT],
  queue_occupancy: StripedGauge,
  wait_observations: StripedCounter,
  wait_duration_ns: StripedCounter,
  connect_observations: StripedCounter,
  connect_duration_ns: StripedCounter,
  cancellation_observations: StripedCounter,
  cancellation_duration_ns: StripedCounter,
  copied_bytes: StripedCounter,
}

impl CompioDirectH1Metrics {
  pub(super) fn append_prometheus(&self, output: &mut String) {
    append_counter_family(
      output,
      "oxibelt_http_compio_direct_h1_submissions_total",
      "outcome",
      CompioDirectH1SubmissionOutcome::ALL
        .into_iter()
        .map(|value| (value.as_str(), self.submissions[value as usize].load())),
    );
    append_gauge(
      output,
      "oxibelt_http_compio_direct_h1_queue_occupancy",
      self.queue_occupancy.load(),
    );
    append_gauge_family(
      output,
      "oxibelt_http_compio_direct_h1_workers",
      "state",
      CompioDirectH1WorkerState::ALL.into_iter().map(|state| {
        (
          state.as_str(),
          self.worker_counts[state as usize].load(Ordering::Relaxed),
        )
      }),
    );
    append_gauge_family(
      output,
      "oxibelt_http_compio_direct_h1_connections",
      "state",
      CompioDirectH1ConnectionState::ALL.into_iter().map(|state| {
        (
          state.as_str(),
          self.connection_counts[state as usize].load(),
        )
      }),
    );
    append_counter_family(
      output,
      "oxibelt_http_compio_direct_h1_connection_events_total",
      "event",
      CompioDirectH1ConnectionEvent::ALL.into_iter().map(|event| {
        (
          event.as_str(),
          self.connection_events[event as usize].load(),
        )
      }),
    );
    append_counter_family(
      output,
      "oxibelt_http_compio_direct_h1_dispatch_total",
      "outcome",
      CompioDirectH1DispatchOutcome::ALL
        .into_iter()
        .map(|outcome| (outcome.as_str(), self.dispatches[outcome as usize].load())),
    );
    append_counter_family(
      output,
      "oxibelt_http_compio_direct_h1_buffer_events_total",
      "event",
      CompioDirectH1BufferEvent::ALL
        .into_iter()
        .map(|event| (event.as_str(), self.buffer_events[event as usize].load())),
    );
    append_counter(
      output,
      "oxibelt_http_compio_direct_h1_operation_wait_observations_total",
      self.wait_observations.load(),
    );
    append_counter(
      output,
      "oxibelt_http_compio_direct_h1_operation_wait_duration_ns_total",
      self.wait_duration_ns.load(),
    );
    append_counter(
      output,
      "oxibelt_http_compio_direct_h1_connect_observations_total",
      self.connect_observations.load(),
    );
    append_counter(
      output,
      "oxibelt_http_compio_direct_h1_connect_duration_ns_total",
      self.connect_duration_ns.load(),
    );
    append_counter(
      output,
      "oxibelt_http_compio_direct_h1_cancellation_observations_total",
      self.cancellation_observations.load(),
    );
    append_counter(
      output,
      "oxibelt_http_compio_direct_h1_cancellation_duration_ns_total",
      self.cancellation_duration_ns.load(),
    );
    append_counter(
      output,
      "oxibelt_http_compio_direct_h1_copied_bytes_total",
      self.copied_bytes.load(),
    );
  }
}

impl Metrics {
  pub(crate) fn record_compio_direct_h1_submission(
    &self,
    outcome: CompioDirectH1SubmissionOutcome,
  ) {
    self.compio_direct_h1.submissions[outcome as usize].increment();
  }

  #[cfg(test)]
  pub(crate) fn set_compio_direct_h1_queue_occupancy(&self, value: usize) {
    self.compio_direct_h1.queue_occupancy.set(value);
  }

  pub(crate) fn adjust_compio_direct_h1_queue_occupancy(&self, delta: isize) {
    self.compio_direct_h1.queue_occupancy.adjust(delta);
  }

  #[cfg(test)]
  pub(crate) fn set_compio_direct_h1_worker_count(
    &self,
    state: CompioDirectH1WorkerState,
    value: usize,
  ) {
    self.compio_direct_h1.worker_counts[state as usize].store(value as u64, Ordering::Relaxed);
  }

  #[cfg(test)]
  pub(crate) fn compio_direct_h1_worker_count(&self, state: CompioDirectH1WorkerState) -> u64 {
    self.compio_direct_h1.worker_counts[state as usize].load(Ordering::Relaxed)
  }

  pub(crate) fn adjust_compio_direct_h1_worker_count(
    &self,
    state: CompioDirectH1WorkerState,
    delta: isize,
  ) {
    adjust_gauge(&self.compio_direct_h1.worker_counts[state as usize], delta);
  }

  #[cfg(test)]
  pub(crate) fn set_compio_direct_h1_connection_count(
    &self,
    state: CompioDirectH1ConnectionState,
    value: usize,
  ) {
    self.compio_direct_h1.connection_counts[state as usize].set(value);
  }

  pub(crate) fn adjust_compio_direct_h1_connection_count(
    &self,
    state: CompioDirectH1ConnectionState,
    delta: isize,
  ) {
    self.compio_direct_h1.connection_counts[state as usize].adjust(delta);
  }

  pub(crate) fn record_compio_direct_h1_connection_event(
    &self,
    event: CompioDirectH1ConnectionEvent,
  ) {
    self.compio_direct_h1.connection_events[event as usize].increment();
  }

  pub(crate) fn record_compio_direct_h1_dispatch(&self, outcome: CompioDirectH1DispatchOutcome) {
    self.compio_direct_h1.dispatches[outcome as usize].increment();
  }

  pub(crate) fn record_compio_direct_h1_buffer_event(&self, event: CompioDirectH1BufferEvent) {
    self.compio_direct_h1.buffer_events[event as usize].increment();
  }

  pub(crate) fn observe_compio_direct_h1_wait(&self, duration: Duration) {
    self.compio_direct_h1.wait_observations.increment();
    self
      .compio_direct_h1
      .wait_duration_ns
      .add(duration_ns(duration));
  }

  pub(crate) fn observe_compio_direct_h1_connect(&self, duration: Duration) {
    self.compio_direct_h1.connect_observations.increment();
    self
      .compio_direct_h1
      .connect_duration_ns
      .add(duration_ns(duration));
  }

  pub(crate) fn observe_compio_direct_h1_cancellation(&self, duration: Duration) {
    self.compio_direct_h1.cancellation_observations.increment();
    self
      .compio_direct_h1
      .cancellation_duration_ns
      .add(duration_ns(duration));
  }

  pub(crate) fn record_compio_direct_h1_copied_bytes(&self, value: usize) {
    self.compio_direct_h1.copied_bytes.add(value as u64);
  }
}

fn duration_ns(duration: Duration) -> u64 {
  duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

fn adjust_gauge(gauge: &AtomicU64, delta: isize) {
  let _ = gauge.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
    Some(if delta >= 0 {
      current.saturating_add(delta as u64)
    } else {
      current.saturating_sub(delta.unsigned_abs() as u64)
    })
  });
}

fn append_counter(output: &mut String, name: &str, value: u64) {
  output.push_str("# TYPE ");
  output.push_str(name);
  output.push_str(" counter\n");
  output.push_str(name);
  output.push(' ');
  let _ = writeln!(output, "{value}");
}

fn append_gauge(output: &mut String, name: &str, value: u64) {
  output.push_str("# TYPE ");
  output.push_str(name);
  output.push_str(" gauge\n");
  output.push_str(name);
  output.push(' ');
  let _ = writeln!(output, "{value}");
}

fn append_counter_family<'a>(
  output: &mut String,
  name: &str,
  label: &str,
  values: impl IntoIterator<Item = (&'a str, u64)>,
) {
  append_labeled_family(output, name, "counter", label, values);
}

fn append_gauge_family<'a>(
  output: &mut String,
  name: &str,
  label: &str,
  values: impl IntoIterator<Item = (&'a str, u64)>,
) {
  append_labeled_family(output, name, "gauge", label, values);
}

fn append_labeled_family<'a>(
  output: &mut String,
  name: &str,
  kind: &str,
  label: &str,
  values: impl IntoIterator<Item = (&'a str, u64)>,
) {
  output.push_str("# TYPE ");
  output.push_str(name);
  output.push(' ');
  output.push_str(kind);
  output.push('\n');
  for (value, count) in values {
    output.push_str(name);
    output.push('{');
    output.push_str(label);
    output.push_str("=\"");
    output.push_str(value);
    output.push_str("\"} ");
    let _ = writeln!(output, "{count}");
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn output_uses_only_fixed_service_labels() {
    let metrics = Metrics::default();
    metrics.record_compio_direct_h1_submission(CompioDirectH1SubmissionOutcome::Waited);
    metrics.set_compio_direct_h1_queue_occupancy(3);
    metrics.set_compio_direct_h1_worker_count(CompioDirectH1WorkerState::Healthy, 2);
    metrics.set_compio_direct_h1_connection_count(CompioDirectH1ConnectionState::Idle, 1);
    metrics.record_compio_direct_h1_connection_event(CompioDirectH1ConnectionEvent::Reused);
    metrics.record_compio_direct_h1_dispatch(CompioDirectH1DispatchOutcome::PredispatchFallback);
    metrics.record_compio_direct_h1_buffer_event(CompioDirectH1BufferEvent::Discard);
    metrics.observe_compio_direct_h1_wait(Duration::from_millis(2));
    metrics.observe_compio_direct_h1_connect(Duration::from_millis(3));
    metrics.observe_compio_direct_h1_cancellation(Duration::from_millis(4));
    metrics.record_compio_direct_h1_copied_bytes(7);
    metrics.adjust_compio_direct_h1_queue_occupancy(2);
    metrics.adjust_compio_direct_h1_queue_occupancy(-1);
    metrics.adjust_compio_direct_h1_worker_count(CompioDirectH1WorkerState::Healthy, 1);
    metrics.adjust_compio_direct_h1_connection_count(CompioDirectH1ConnectionState::Idle, -1);

    let mut output = String::new();
    metrics.compio_direct_h1.append_prometheus(&mut output);

    assert!(
      output.contains("oxibelt_http_compio_direct_h1_submissions_total{outcome=\"waited\"} 1")
    );
    assert!(output.contains("oxibelt_http_compio_direct_h1_queue_occupancy 4"));
    assert!(output.contains("oxibelt_http_compio_direct_h1_workers{state=\"healthy\"} 3"));
    assert!(output.contains("oxibelt_http_compio_direct_h1_connections{state=\"idle\"} 0"));
    assert!(
      output.contains("oxibelt_http_compio_direct_h1_connection_events_total{event=\"reused\"} 1")
    );
    assert!(output.contains(
      "oxibelt_http_compio_direct_h1_dispatch_total{outcome=\"predispatch_fallback\"} 1"
    ));
    assert!(
      output.contains("oxibelt_http_compio_direct_h1_buffer_events_total{event=\"discard\"} 1")
    );
    assert!(
      output.contains("oxibelt_http_compio_direct_h1_operation_wait_duration_ns_total 2000000")
    );
    assert!(output.contains("oxibelt_http_compio_direct_h1_connect_duration_ns_total 3000000"));
    assert!(
      output.contains("oxibelt_http_compio_direct_h1_cancellation_duration_ns_total 4000000")
    );
    assert!(output.contains("oxibelt_http_compio_direct_h1_copied_bytes_total 7"));
    assert!(!output.contains("origin="));
    assert!(!output.contains("worker_id="));
  }
}

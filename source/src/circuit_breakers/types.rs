//! Shared admission state types kept separate from the hot runtime methods.

use std::time::{Duration, Instant};

use super::circuit::FailureCircuit;
use super::resources::ResolvedAutoScope;
use crate::config::CircuitBreakerScopeConfig;

pub(super) const RESOURCE_KIND_COUNT: usize = 7;
pub(super) const REJECTION_REASON_COUNT: usize = 5;
pub(super) const CIRCUIT_STATE_COUNT: usize = 3;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub(super) enum ResourceKind {
  Request,
  UpstreamRequest,
  Retry,
  Connection,
  Stream,
  BodyInspection,
  Decompression,
}

impl ResourceKind {
  pub(super) const ALL: [Self; RESOURCE_KIND_COUNT] = [
    Self::Request,
    Self::UpstreamRequest,
    Self::Retry,
    Self::Connection,
    Self::Stream,
    Self::BodyInspection,
    Self::Decompression,
  ];

  pub(super) const fn as_str(self) -> &'static str {
    match self {
      Self::Request => "request",
      Self::UpstreamRequest => "upstream_request",
      Self::Retry => "retry",
      Self::Connection => "connection",
      Self::Stream => "stream",
      Self::BodyInspection => "body_inspection",
      Self::Decompression => "decompression",
    }
  }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) enum ScopeKey {
  Global,
  Route(String),
  Pool(String),
}

impl ScopeKey {
  pub(super) const fn kind(&self) -> &'static str {
    match self {
      Self::Global => "global",
      Self::Route(_) => "route",
      Self::Pool(_) => "pool",
    }
  }

  pub(super) fn label(&self) -> &str {
    match self {
      Self::Global => "global",
      Self::Route(name) | Self::Pool(name) => name,
    }
  }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ResourceLimit {
  pub(super) active: usize,
  pub(super) queue: usize,
  pub(super) timeout: Duration,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ScopeLimits {
  resources: [ResourceLimit; RESOURCE_KIND_COUNT],
}

impl ScopeLimits {
  pub(super) fn for_scope(config: &CircuitBreakerScopeConfig, resolved: ResolvedAutoScope) -> Self {
    let request = ResourceLimit {
      active: resolved.active_requests,
      queue: resolved.pending_requests,
      timeout: Duration::from_millis(config.pending_queue_timeout_ms),
    };
    let connection = ResourceLimit {
      active: resolved.connections,
      ..request
    };
    let stream = ResourceLimit {
      active: resolved.streams,
      ..request
    };
    let inspection = ResourceLimit {
      active: resolved.inspection_jobs,
      ..request
    };
    let decompression = ResourceLimit {
      active: resolved.decompression_jobs,
      ..request
    };
    Self {
      resources: [
        request,
        request,
        request,
        connection,
        stream,
        inspection,
        decompression,
      ],
    }
  }

  pub(super) fn resource(self, kind: ResourceKind) -> ResourceLimit {
    self.resources[kind as usize]
  }
}

#[derive(Debug)]
pub(super) struct ScopeState {
  pub(super) limits: ScopeLimits,
  pub(super) failure_enabled: bool,
  pub(super) active: [usize; RESOURCE_KIND_COUNT],
  pub(super) queued: [usize; RESOURCE_KIND_COUNT],
  pub(super) circuit: FailureCircuit,
}

impl ScopeState {
  pub(super) fn new(limits: ScopeLimits, failure_enabled: bool) -> Self {
    Self {
      limits,
      failure_enabled,
      active: [0; RESOURCE_KIND_COUNT],
      queued: [0; RESOURCE_KIND_COUNT],
      circuit: FailureCircuit::default(),
    }
  }
}

#[derive(Clone, Debug)]
pub(super) struct Allocation {
  pub(super) scope: ScopeKey,
  pub(super) resource: ResourceKind,
  pub(super) limit: Option<ResourceLimit>,
}

impl Allocation {
  pub(super) fn effective_limit(&self, state: &ScopeState) -> ResourceLimit {
    self
      .limit
      .unwrap_or_else(|| state.limits.resource(self.resource))
  }
}

#[derive(Debug)]
pub(super) struct Waiter {
  pub(super) id: u64,
  pub(super) allocations: Vec<Allocation>,
  pub(super) queued_at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AdmissionRejectionReason {
  ActiveLimit,
  QueueFull,
  QueueTimeout,
  CircuitOpen,
  RetryBudget,
}

impl AdmissionRejectionReason {
  pub(super) const ALL: [Self; REJECTION_REASON_COUNT] = [
    Self::ActiveLimit,
    Self::QueueFull,
    Self::QueueTimeout,
    Self::CircuitOpen,
    Self::RetryBudget,
  ];

  pub const fn as_str(self) -> &'static str {
    match self {
      Self::ActiveLimit => "active_limit",
      Self::QueueFull => "queue_full",
      Self::QueueTimeout => "queue_timeout",
      Self::CircuitOpen => "circuit_open",
      Self::RetryBudget => "retry_budget",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionRejection {
  pub reason: AdmissionRejectionReason,
  pub retry_after: Duration,
}

impl std::fmt::Display for AdmissionRejection {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      formatter,
      "circuit-breaker admission rejected: {}",
      self.reason.as_str()
    )
  }
}

impl std::error::Error for AdmissionRejection {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitOutcomeFailure {
  ConnectError,
  FirstByteTimeout,
  ResponseReadTimeout,
  ProtocolError,
  Status(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitOutcome {
  Success,
  Failure(CircuitOutcomeFailure),
  Neutral,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum CircuitState {
  Closed,
  Open,
  HalfOpen,
}

impl CircuitState {
  pub(super) const ALL: [Self; CIRCUIT_STATE_COUNT] = [Self::Closed, Self::Open, Self::HalfOpen];

  pub(super) const fn as_str(self) -> &'static str {
    match self {
      Self::Closed => "closed",
      Self::Open => "open",
      Self::HalfOpen => "half_open",
    }
  }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct RetryBudget {
  pub(super) percent: f64,
  pub(super) min: usize,
  pub(super) max: usize,
  pub(super) queue: usize,
  pub(super) timeout: Duration,
}

//! Panic-safe runtime health, task supervision metadata, and bounded metrics.
//!
//! All labels are fixed enums and all state is atomic so the health path cannot
//! itself be disabled by a poisoned synchronization primitive.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

mod supervisor;

pub(crate) use supervisor::spawn_supervised_task;

pub(crate) const PROCESS_GENERATION: u64 = 0;
const STATE_MASK: u64 = 0b11;
const CRITICAL_MASK: u64 = 0b100;
const POLICY_SHIFT: u32 = 2;
const GENERATION_SHIFT: u32 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum RuntimeSubsystemState {
  Healthy = 0,
  Degraded = 1,
  Failed = 2,
}

impl RuntimeSubsystemState {
  pub(crate) const fn as_str(self) -> &'static str {
    match self {
      Self::Healthy => "healthy",
      Self::Degraded => "degraded",
      Self::Failed => "failed",
    }
  }

  fn from_bits(bits: u64) -> Self {
    match bits & STATE_MASK {
      1 => Self::Degraded,
      2 => Self::Failed,
      _ => Self::Healthy,
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum RuntimeSubsystem {
  AppState,
  TaskRegistry,
  ResponseCache,
  CacheFill,
  StaticObjectCache,
  CircuitBreakers,
  Limits,
  Overload,
  SharedState,
  DynamicPolicy,
  Ipm,
  ClientIdentity,
  AdminAudit,
  AdminMutation,
  Hardening,
  Waf,
  CompioDirectH1,
}

impl RuntimeSubsystem {
  pub(crate) const ALL: [Self; 17] = [
    Self::AppState,
    Self::TaskRegistry,
    Self::ResponseCache,
    Self::CacheFill,
    Self::StaticObjectCache,
    Self::CircuitBreakers,
    Self::Limits,
    Self::Overload,
    Self::SharedState,
    Self::DynamicPolicy,
    Self::Ipm,
    Self::ClientIdentity,
    Self::AdminAudit,
    Self::AdminMutation,
    Self::Hardening,
    Self::Waf,
    Self::CompioDirectH1,
  ];

  const COUNT: usize = Self::ALL.len();

  pub(crate) const fn as_str(self) -> &'static str {
    match self {
      Self::AppState => "app_state",
      Self::TaskRegistry => "task_registry",
      Self::ResponseCache => "response_cache",
      Self::CacheFill => "cache_fill",
      Self::StaticObjectCache => "static_object_cache",
      Self::CircuitBreakers => "circuit_breakers",
      Self::Limits => "limits",
      Self::Overload => "overload",
      Self::SharedState => "shared_state",
      Self::DynamicPolicy => "dynamic_policy",
      Self::Ipm => "ipm",
      Self::ClientIdentity => "client_identity",
      Self::AdminAudit => "admin_audit",
      Self::AdminMutation => "admin_mutation",
      Self::Hardening => "hardening",
      Self::Waf => "waf",
      Self::CompioDirectH1 => "compio_direct_h1",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum RuntimeTaskKind {
  HttpConnection,
  AdminConnection,
  OpsConnection,
  StreamConnection,
  TurnConnection,
  HealthListener,
  MetricsListener,
  PoolHealth,
  OverloadSampler,
  UpstreamDiscovery,
  AdminMutationHeartbeat,
  AdminMutationMember,
  AdminMutationCoordinator,
  AdminAuditAnchor,
  CompioDirectH1Worker,
}

impl RuntimeTaskKind {
  pub(crate) const ALL: [Self; 15] = [
    Self::HttpConnection,
    Self::AdminConnection,
    Self::OpsConnection,
    Self::StreamConnection,
    Self::TurnConnection,
    Self::HealthListener,
    Self::MetricsListener,
    Self::PoolHealth,
    Self::OverloadSampler,
    Self::UpstreamDiscovery,
    Self::AdminMutationHeartbeat,
    Self::AdminMutationMember,
    Self::AdminMutationCoordinator,
    Self::AdminAuditAnchor,
    Self::CompioDirectH1Worker,
  ];

  const COUNT: usize = Self::ALL.len();

  pub(crate) const fn as_str(self) -> &'static str {
    match self {
      Self::HttpConnection => "http_connection",
      Self::AdminConnection => "admin_connection",
      Self::OpsConnection => "ops_connection",
      Self::StreamConnection => "stream_connection",
      Self::TurnConnection => "turn_connection",
      Self::HealthListener => "health_listener",
      Self::MetricsListener => "metrics_listener",
      Self::PoolHealth => "pool_health",
      Self::OverloadSampler => "overload_sampler",
      Self::UpstreamDiscovery => "upstream_discovery",
      Self::AdminMutationHeartbeat => "admin_mutation_heartbeat",
      Self::AdminMutationMember => "admin_mutation_member",
      Self::AdminMutationCoordinator => "admin_mutation_coordinator",
      Self::AdminAuditAnchor => "admin_audit_anchor",
      Self::CompioDirectH1Worker => "compio_direct_h1_worker",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum RuntimeTaskPolicy {
  Contained = 0,
  RestartableOptional = 1,
  RestartableCritical = 2,
  Fatal = 3,
}

impl RuntimeTaskPolicy {
  pub(crate) const fn readiness_critical(self) -> bool {
    matches!(self, Self::RestartableCritical | Self::Fatal)
  }

  pub(crate) const fn restartable(self) -> bool {
    matches!(self, Self::RestartableOptional | Self::RestartableCritical)
  }

  fn from_bits(bits: u64) -> Self {
    match (bits >> POLICY_SHIFT) & 0b11 {
      1 => Self::RestartableOptional,
      2 => Self::RestartableCritical,
      3 => Self::Fatal,
      _ => Self::Contained,
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimePanicScope {
  Connection,
  Background,
}

impl RuntimePanicScope {
  const COUNT: usize = 2;

  const fn index(self) -> usize {
    match self {
      Self::Connection => 0,
      Self::Background => 1,
    }
  }

  const fn as_str(self) -> &'static str {
    match self {
      Self::Connection => "connection",
      Self::Background => "background",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeRestartOutcome {
  Attempt,
  Stable,
}

impl RuntimeRestartOutcome {
  const COUNT: usize = 2;

  const fn index(self) -> usize {
    match self {
      Self::Attempt => 0,
      Self::Stable => 1,
    }
  }

  const fn as_str(self) -> &'static str {
    match self {
      Self::Attempt => "attempt",
      Self::Stable => "stable",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeTaskTermination {
  Error,
  Panic,
  UnexpectedReturn,
}

impl RuntimeTaskTermination {
  pub(crate) const fn as_str(self) -> &'static str {
    match self {
      Self::Error => "error",
      Self::Panic => "panic",
      Self::UnexpectedReturn => "unexpected_return",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeSubsystemError {
  RecoverableStatePoisoned(RuntimeSubsystem),
  CriticalStateUnavailable(RuntimeSubsystem),
  TaskTerminated {
    task: RuntimeTaskKind,
    termination: RuntimeTaskTermination,
  },
}

impl std::fmt::Display for RuntimeSubsystemError {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::RecoverableStatePoisoned(subsystem) => {
        write!(
          formatter,
          "recoverable {} state was poisoned",
          subsystem.as_str()
        )
      }
      Self::CriticalStateUnavailable(subsystem) => {
        write!(
          formatter,
          "critical {} state is unavailable",
          subsystem.as_str()
        )
      }
      Self::TaskTerminated { task, termination } => write!(
        formatter,
        "{} task terminated: {}",
        task.as_str(),
        termination.as_str()
      ),
    }
  }
}

impl std::error::Error for RuntimeSubsystemError {}

#[derive(Debug)]
pub(crate) struct RuntimeHealth {
  next_generation: AtomicU64,
  active_generation: AtomicU64,
  subsystem_states: [AtomicU64; RuntimeSubsystem::COUNT],
  task_states: [AtomicU64; RuntimeTaskKind::COUNT],
  panics: [AtomicU64; RuntimeTaskKind::COUNT * RuntimePanicScope::COUNT],
  restarts: [AtomicU64; RuntimeTaskKind::COUNT * RuntimeRestartOutcome::COUNT],
  lock_recoveries: [AtomicU64; RuntimeSubsystem::COUNT],
}

impl Default for RuntimeHealth {
  fn default() -> Self {
    Self {
      next_generation: AtomicU64::new(1),
      active_generation: AtomicU64::new(PROCESS_GENERATION),
      subsystem_states: std::array::from_fn(|_| AtomicU64::new(0)),
      task_states: std::array::from_fn(|_| AtomicU64::new(0)),
      panics: std::array::from_fn(|_| AtomicU64::new(0)),
      restarts: std::array::from_fn(|_| AtomicU64::new(0)),
      lock_recoveries: std::array::from_fn(|_| AtomicU64::new(0)),
    }
  }
}

impl RuntimeHealth {
  pub(crate) fn allocate_generation(&self) -> u64 {
    self.next_generation.fetch_add(1, Ordering::Relaxed)
  }

  pub(crate) fn activate_generation(&self, generation: u64) {
    self.active_generation.store(generation, Ordering::Release);
  }

  pub(crate) fn active_generation(&self) -> u64 {
    self.active_generation.load(Ordering::Acquire)
  }

  pub(crate) fn set_subsystem_state(
    &self,
    generation: u64,
    subsystem: RuntimeSubsystem,
    state: RuntimeSubsystemState,
    readiness_critical: bool,
  ) {
    let packed = pack_subsystem(generation, state, readiness_critical);
    self.subsystem_states[subsystem as usize].store(packed, Ordering::Release);
  }

  pub(crate) fn set_task_state(
    &self,
    generation: u64,
    task: RuntimeTaskKind,
    policy: RuntimeTaskPolicy,
    state: RuntimeSubsystemState,
  ) {
    let packed = pack_task(generation, state, policy);
    self.task_states[task as usize].store(packed, Ordering::Release);
  }

  pub(crate) fn record_panic(&self, scope: RuntimePanicScope, task: RuntimeTaskKind) {
    let index = task as usize * RuntimePanicScope::COUNT + scope.index();
    self.panics[index].fetch_add(1, Ordering::Relaxed);
  }

  pub(crate) fn record_restart(&self, task: RuntimeTaskKind, outcome: RuntimeRestartOutcome) {
    let index = task as usize * RuntimeRestartOutcome::COUNT + outcome.index();
    self.restarts[index].fetch_add(1, Ordering::Relaxed);
  }

  pub(crate) fn record_lock_recovery(&self, subsystem: RuntimeSubsystem) {
    self.lock_recoveries[subsystem as usize].fetch_add(1, Ordering::Relaxed);
  }

  pub(crate) fn is_ready(&self) -> bool {
    let active = self.active_generation();
    for subsystem in RuntimeSubsystem::ALL {
      let packed = self.subsystem_states[subsystem as usize].load(Ordering::Acquire);
      if record_applies(packed, active)
        && packed & CRITICAL_MASK != 0
        && RuntimeSubsystemState::from_bits(packed) != RuntimeSubsystemState::Healthy
      {
        return false;
      }
    }
    for task in RuntimeTaskKind::ALL {
      let packed = self.task_states[task as usize].load(Ordering::Acquire);
      if record_applies(packed, active)
        && RuntimeTaskPolicy::from_bits(packed).readiness_critical()
        && RuntimeSubsystemState::from_bits(packed) != RuntimeSubsystemState::Healthy
      {
        return false;
      }
    }
    true
  }

  pub(crate) fn subsystem_is_unhealthy(&self, subsystem: RuntimeSubsystem) -> bool {
    let active = self.active_generation();
    let packed = self.subsystem_states[subsystem as usize].load(Ordering::Acquire);
    record_applies(packed, active)
      && RuntimeSubsystemState::from_bits(packed) != RuntimeSubsystemState::Healthy
  }

  #[cfg(feature = "admin-runtime")]
  pub(crate) fn snapshot(&self) -> RuntimeHealthSnapshot {
    let active = self.active_generation();
    let mut degraded_subsystems = Vec::new();
    let mut failed_subsystems = Vec::new();
    let mut degraded_tasks = Vec::new();
    let mut failed_tasks = Vec::new();

    for subsystem in RuntimeSubsystem::ALL {
      let packed = self.subsystem_states[subsystem as usize].load(Ordering::Acquire);
      if !record_applies(packed, active) {
        continue;
      }
      match RuntimeSubsystemState::from_bits(packed) {
        RuntimeSubsystemState::Healthy => {}
        RuntimeSubsystemState::Degraded => degraded_subsystems.push(subsystem.as_str()),
        RuntimeSubsystemState::Failed => failed_subsystems.push(subsystem.as_str()),
      }
    }
    for task in RuntimeTaskKind::ALL {
      let packed = self.task_states[task as usize].load(Ordering::Acquire);
      if !record_applies(packed, active) {
        continue;
      }
      match RuntimeSubsystemState::from_bits(packed) {
        RuntimeSubsystemState::Healthy => {}
        RuntimeSubsystemState::Degraded => degraded_tasks.push(task.as_str()),
        RuntimeSubsystemState::Failed => failed_tasks.push(task.as_str()),
      }
    }

    let status = if failed_subsystems.is_empty() && failed_tasks.is_empty() {
      if degraded_subsystems.is_empty() && degraded_tasks.is_empty() {
        RuntimeSubsystemState::Healthy
      } else {
        RuntimeSubsystemState::Degraded
      }
    } else {
      RuntimeSubsystemState::Failed
    };

    RuntimeHealthSnapshot {
      status,
      degraded_subsystems,
      failed_subsystems,
      degraded_tasks,
      failed_tasks,
    }
  }

  pub(crate) fn append_prometheus(&self, output: &mut String) {
    output.push_str("# TYPE oxibelt_runtime_panics_total counter\n");
    output.push_str("# TYPE oxibelt_runtime_task_restarts_total counter\n");
    output.push_str("# TYPE oxibelt_runtime_task_state gauge\n");
    output.push_str("# TYPE oxibelt_runtime_lock_recoveries_total counter\n");
    output.push_str("# TYPE oxibelt_runtime_subsystem_state gauge\n");
    for task in RuntimeTaskKind::ALL {
      for scope in [RuntimePanicScope::Connection, RuntimePanicScope::Background] {
        let index = task as usize * RuntimePanicScope::COUNT + scope.index();
        let _ = writeln!(
          output,
          "oxibelt_runtime_panics_total{{scope=\"{}\",task=\"{}\"}} {}",
          scope.as_str(),
          task.as_str(),
          self.panics[index].load(Ordering::Relaxed)
        );
      }
      for outcome in [
        RuntimeRestartOutcome::Attempt,
        RuntimeRestartOutcome::Stable,
      ] {
        let index = task as usize * RuntimeRestartOutcome::COUNT + outcome.index();
        let _ = writeln!(
          output,
          "oxibelt_runtime_task_restarts_total{{task=\"{}\",outcome=\"{}\"}} {}",
          task.as_str(),
          outcome.as_str(),
          self.restarts[index].load(Ordering::Relaxed)
        );
      }
      let packed = self.task_states[task as usize].load(Ordering::Acquire);
      let state = if record_applies(packed, self.active_generation()) {
        RuntimeSubsystemState::from_bits(packed)
      } else {
        RuntimeSubsystemState::Healthy
      };
      for candidate in [
        RuntimeSubsystemState::Healthy,
        RuntimeSubsystemState::Degraded,
        RuntimeSubsystemState::Failed,
      ] {
        let _ = writeln!(
          output,
          "oxibelt_runtime_task_state{{task=\"{}\",state=\"{}\"}} {}",
          task.as_str(),
          candidate.as_str(),
          u8::from(candidate == state)
        );
      }
    }
    for subsystem in RuntimeSubsystem::ALL {
      let packed = self.subsystem_states[subsystem as usize].load(Ordering::Acquire);
      let state = if record_applies(packed, self.active_generation()) {
        RuntimeSubsystemState::from_bits(packed)
      } else {
        RuntimeSubsystemState::Healthy
      };
      let _ = writeln!(
        output,
        "oxibelt_runtime_lock_recoveries_total{{subsystem=\"{}\"}} {}",
        subsystem.as_str(),
        self.lock_recoveries[subsystem as usize].load(Ordering::Relaxed)
      );
      for candidate in [
        RuntimeSubsystemState::Healthy,
        RuntimeSubsystemState::Degraded,
        RuntimeSubsystemState::Failed,
      ] {
        let _ = writeln!(
          output,
          "oxibelt_runtime_subsystem_state{{subsystem=\"{}\",state=\"{}\"}} {}",
          subsystem.as_str(),
          candidate.as_str(),
          u8::from(candidate == state)
        );
      }
    }
  }
}

#[cfg(feature = "admin-runtime")]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RuntimeHealthSnapshot {
  pub(crate) status: RuntimeSubsystemState,
  pub(crate) degraded_subsystems: Vec<&'static str>,
  pub(crate) failed_subsystems: Vec<&'static str>,
  pub(crate) degraded_tasks: Vec<&'static str>,
  pub(crate) failed_tasks: Vec<&'static str>,
}

fn pack_subsystem(generation: u64, state: RuntimeSubsystemState, readiness_critical: bool) -> u64 {
  (generation << GENERATION_SHIFT) | (u64::from(readiness_critical) * CRITICAL_MASK) | state as u64
}

fn pack_task(generation: u64, state: RuntimeSubsystemState, policy: RuntimeTaskPolicy) -> u64 {
  (generation << GENERATION_SHIFT) | ((policy as u64) << POLICY_SHIFT) | state as u64
}

fn record_applies(packed: u64, active_generation: u64) -> bool {
  let generation = packed >> GENERATION_SHIFT;
  generation == PROCESS_GENERATION || generation == active_generation
}

#[cfg(test)]
mod tests;

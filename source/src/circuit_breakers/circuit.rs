//! Rolling upstream failure-circuit state machine.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::config::{CircuitBreakerFailureConfig, CircuitFailureCondition};

use super::types::{CircuitOutcome, CircuitOutcomeFailure, CircuitState};

#[derive(Debug)]
pub(super) struct FailureCircuit {
  pub(super) state: CircuitState,
  open_until: Option<Instant>,
  open_timeout: Duration,
  probes: usize,
  successes: usize,
  consecutive_failures: usize,
  samples: VecDeque<(Instant, bool)>,
}

impl Default for FailureCircuit {
  fn default() -> Self {
    Self {
      state: CircuitState::Closed,
      open_until: None,
      open_timeout: Duration::ZERO,
      probes: 0,
      successes: 0,
      consecutive_failures: 0,
      samples: VecDeque::new(),
    }
  }
}

impl FailureCircuit {
  pub(super) fn available(
    &self,
    now: Instant,
    policy: &CircuitBreakerFailureConfig,
  ) -> Result<bool, Duration> {
    match self.state {
      CircuitState::Closed => Ok(false),
      CircuitState::Open => {
        let remaining = self
          .open_until
          .map(|until| until.saturating_duration_since(now))
          .unwrap_or_default();
        if remaining.is_zero() {
          Ok(true)
        } else {
          Err(remaining)
        }
      }
      CircuitState::HalfOpen if self.probes < policy.half_open_max_probes => Ok(true),
      CircuitState::HalfOpen => Err(self.open_timeout),
    }
  }

  pub(super) fn begin_probe(
    &mut self,
    now: Instant,
    policy: &CircuitBreakerFailureConfig,
  ) -> Option<(CircuitState, CircuitState)> {
    match self.state {
      CircuitState::Closed => None,
      CircuitState::Open => {
        if self
          .open_until
          .is_some_and(|until| !until.saturating_duration_since(now).is_zero())
        {
          return None;
        }
        self.state = CircuitState::HalfOpen;
        self.probes = 1;
        self.successes = 0;
        if self.open_timeout.is_zero() {
          self.open_timeout = Duration::from_millis(policy.open_timeout_ms);
        }
        Some((CircuitState::Open, CircuitState::HalfOpen))
      }
      CircuitState::HalfOpen if self.probes < policy.half_open_max_probes => {
        self.probes += 1;
        None
      }
      CircuitState::HalfOpen => None,
    }
  }

  pub(super) fn finish(
    &mut self,
    probe: bool,
    outcome: CircuitOutcome,
    now: Instant,
    policy: &CircuitBreakerFailureConfig,
    sequence: u64,
  ) -> Option<(CircuitState, CircuitState)> {
    if probe && self.state == CircuitState::HalfOpen {
      self.probes = self.probes.saturating_sub(1);
    }
    if outcome == CircuitOutcome::Neutral {
      return None;
    }
    let failed =
      matches!(outcome, CircuitOutcome::Failure(failure) if failure_matches(policy, failure));
    match self.state {
      CircuitState::Closed => {
        self.record_sample(now, failed, policy);
        if failed {
          self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        } else {
          self.consecutive_failures = 0;
        }
        let failures = self.samples.iter().filter(|(_, failed)| *failed).count();
        let requests = self.samples.len();
        let ratio_open = requests >= policy.minimum_requests
          && (failures as f64 / requests as f64) >= policy.failure_ratio;
        if failed && (self.consecutive_failures >= policy.consecutive_failures || ratio_open) {
          self.open(now, policy, sequence);
          Some((CircuitState::Closed, CircuitState::Open))
        } else {
          None
        }
      }
      CircuitState::HalfOpen => {
        if failed {
          self.open_timeout = doubled_capped(self.open_timeout, policy);
          self.open(now, policy, sequence);
          Some((CircuitState::HalfOpen, CircuitState::Open))
        } else {
          self.successes = self.successes.saturating_add(1);
          if self.successes >= policy.half_open_successes {
            self.close();
            Some((CircuitState::HalfOpen, CircuitState::Closed))
          } else {
            None
          }
        }
      }
      CircuitState::Open => None,
    }
  }

  pub(super) fn abandon_probe(&mut self, probe: bool) {
    if probe && self.state == CircuitState::HalfOpen {
      self.probes = self.probes.saturating_sub(1);
    }
  }

  pub(super) fn close(&mut self) {
    self.state = CircuitState::Closed;
    self.open_until = None;
    self.open_timeout = Duration::ZERO;
    self.probes = 0;
    self.successes = 0;
    self.consecutive_failures = 0;
    self.samples.clear();
  }

  fn record_sample(&mut self, now: Instant, failed: bool, policy: &CircuitBreakerFailureConfig) {
    let window = Duration::from_millis(policy.window_ms);
    while self
      .samples
      .front()
      .is_some_and(|(at, _)| now.saturating_duration_since(*at) > window)
    {
      self.samples.pop_front();
    }
    self.samples.push_back((now, failed));
  }

  fn open(&mut self, now: Instant, policy: &CircuitBreakerFailureConfig, sequence: u64) {
    let base = if self.open_timeout.is_zero() {
      Duration::from_millis(policy.open_timeout_ms)
    } else {
      self.open_timeout
    };
    self.open_timeout = jittered(
      base.min(Duration::from_millis(policy.max_open_timeout_ms)),
      sequence,
    );
    self.open_until = now.checked_add(self.open_timeout);
    self.state = CircuitState::Open;
    self.probes = 0;
    self.successes = 0;
  }
}

fn failure_matches(policy: &CircuitBreakerFailureConfig, failure: CircuitOutcomeFailure) -> bool {
  policy.on.iter().any(|condition| {
    matches!(
      (condition, failure),
      (
        CircuitFailureCondition::ConnectError,
        CircuitOutcomeFailure::ConnectError
      ) | (
        CircuitFailureCondition::FirstByteTimeout,
        CircuitOutcomeFailure::FirstByteTimeout
      ) | (
        CircuitFailureCondition::ResponseReadTimeout,
        CircuitOutcomeFailure::ResponseReadTimeout,
      ) | (
        CircuitFailureCondition::ProtocolError,
        CircuitOutcomeFailure::ProtocolError
      ) | (
        CircuitFailureCondition::Status502,
        CircuitOutcomeFailure::Status(502)
      ) | (
        CircuitFailureCondition::Status503,
        CircuitOutcomeFailure::Status(503)
      ) | (
        CircuitFailureCondition::Status504,
        CircuitOutcomeFailure::Status(504)
      )
    )
  })
}

fn doubled_capped(value: Duration, policy: &CircuitBreakerFailureConfig) -> Duration {
  value
    .checked_mul(2)
    .unwrap_or_else(|| Duration::from_millis(policy.max_open_timeout_ms))
    .min(Duration::from_millis(policy.max_open_timeout_ms))
}

fn jittered(value: Duration, sequence: u64) -> Duration {
  let half = value / 2;
  let spread_ms = half.as_millis().min(u128::from(u64::MAX)) as u64;
  half.saturating_add(Duration::from_millis(
    sequence % spread_ms.saturating_add(1),
  ))
}

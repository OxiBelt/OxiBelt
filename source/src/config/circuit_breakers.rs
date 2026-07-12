//! Bounded request, queue, retry, and upstream circuit-breaker configuration.
//!
//! The values in this module deliberately describe *process-local* limits. A
//! Kubernetes replica has an independent admission runtime, so operators must
//! size the limits for one OxiBelt process rather than for a whole Service.

use anyhow::bail;
use serde::{Deserialize, Deserializer};

/// A finite capacity or a process-local value resolved from available resources.
///
/// TOML accepts either a positive integer or the string `"auto"`. Pending
/// queues additionally accept zero, which means reject rather than wait.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum CapacitySetting {
  #[default]
  Auto,
  Fixed(usize),
}

impl<'de> Deserialize<'de> for CapacitySetting {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum RawCapacity {
      Integer(usize),
      Text(String),
    }

    match RawCapacity::deserialize(deserializer)? {
      RawCapacity::Integer(value) => Ok(Self::Fixed(value)),
      RawCapacity::Text(value) if value.trim().eq_ignore_ascii_case("auto") => Ok(Self::Auto),
      RawCapacity::Text(_) => Err(serde::de::Error::custom(
        "capacity must be a non-negative integer or the string \"auto\"",
      )),
    }
  }
}

impl CapacitySetting {
  pub const fn fixed(self) -> Option<usize> {
    match self {
      Self::Auto => None,
      Self::Fixed(value) => Some(value),
    }
  }

  fn validate(self, field: &str, allow_zero: bool) -> anyhow::Result<()> {
    if !allow_zero && self.fixed() == Some(0) {
      bail!("{field} must be greater than 0 or \"auto\"");
    }
    Ok(())
  }
}

/// Limits shared by the global, per-route, and per-upstream-pool scopes.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CircuitBreakerScopeConfig {
  #[serde(default)]
  pub max_active_requests: CapacitySetting,
  #[serde(default)]
  pub max_pending_requests: CapacitySetting,
  #[serde(
    default = "default_pending_queue_timeout_ms",
    alias = "pending_queue_timeout",
    deserialize_with = "deserialize_milliseconds"
  )]
  pub pending_queue_timeout_ms: u64,
  #[serde(default)]
  pub max_connections: CapacitySetting,
  #[serde(default)]
  pub max_streams: CapacitySetting,
  #[serde(default)]
  pub max_body_inspection_jobs: CapacitySetting,
  #[serde(default)]
  pub max_decompression_jobs: CapacitySetting,
}

impl Default for CircuitBreakerScopeConfig {
  fn default() -> Self {
    Self {
      max_active_requests: CapacitySetting::Auto,
      max_pending_requests: CapacitySetting::Auto,
      pending_queue_timeout_ms: default_pending_queue_timeout_ms(),
      max_connections: CapacitySetting::Auto,
      max_streams: CapacitySetting::Auto,
      max_body_inspection_jobs: CapacitySetting::Auto,
      max_decompression_jobs: CapacitySetting::Auto,
    }
  }
}

impl CircuitBreakerScopeConfig {
  fn validate(&self, prefix: &str) -> anyhow::Result<()> {
    self
      .max_active_requests
      .validate(&format!("{prefix}.max_active_requests"), false)?;
    self
      .max_pending_requests
      .validate(&format!("{prefix}.max_pending_requests"), true)?;
    self
      .max_connections
      .validate(&format!("{prefix}.max_connections"), false)?;
    self
      .max_streams
      .validate(&format!("{prefix}.max_streams"), false)?;
    self
      .max_body_inspection_jobs
      .validate(&format!("{prefix}.max_body_inspection_jobs"), false)?;
    self
      .max_decompression_jobs
      .validate(&format!("{prefix}.max_decompression_jobs"), false)?;
    if self.pending_queue_timeout_ms == 0 {
      bail!("{prefix}.pending_queue_timeout_ms must be greater than 0");
    }
    Ok(())
  }
}

/// Sparse route or pool overrides merged with the applicable defaults.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct CircuitBreakerScopeOverride {
  #[serde(default)]
  pub max_active_requests: Option<CapacitySetting>,
  #[serde(default)]
  pub max_pending_requests: Option<CapacitySetting>,
  #[serde(
    default,
    alias = "pending_queue_timeout",
    deserialize_with = "deserialize_optional_milliseconds"
  )]
  pub pending_queue_timeout_ms: Option<u64>,
  #[serde(default)]
  pub max_connections: Option<CapacitySetting>,
  #[serde(default)]
  pub max_streams: Option<CapacitySetting>,
  #[serde(default)]
  pub max_body_inspection_jobs: Option<CapacitySetting>,
  #[serde(default)]
  pub max_decompression_jobs: Option<CapacitySetting>,
}

impl CircuitBreakerScopeOverride {
  pub fn merged_with(&self, defaults: &CircuitBreakerScopeConfig) -> CircuitBreakerScopeConfig {
    CircuitBreakerScopeConfig {
      max_active_requests: self
        .max_active_requests
        .unwrap_or(defaults.max_active_requests),
      max_pending_requests: self
        .max_pending_requests
        .unwrap_or(defaults.max_pending_requests),
      pending_queue_timeout_ms: self
        .pending_queue_timeout_ms
        .unwrap_or(defaults.pending_queue_timeout_ms),
      max_connections: self.max_connections.unwrap_or(defaults.max_connections),
      max_streams: self.max_streams.unwrap_or(defaults.max_streams),
      max_body_inspection_jobs: self
        .max_body_inspection_jobs
        .unwrap_or(defaults.max_body_inspection_jobs),
      max_decompression_jobs: self
        .max_decompression_jobs
        .unwrap_or(defaults.max_decompression_jobs),
    }
  }

  pub(super) fn validate(&self, prefix: &str) -> anyhow::Result<()> {
    for (field, value, allow_zero) in [
      ("max_active_requests", self.max_active_requests, false),
      ("max_pending_requests", self.max_pending_requests, true),
      ("max_connections", self.max_connections, false),
      ("max_streams", self.max_streams, false),
      (
        "max_body_inspection_jobs",
        self.max_body_inspection_jobs,
        false,
      ),
      ("max_decompression_jobs", self.max_decompression_jobs, false),
    ] {
      if let Some(value) = value {
        value.validate(&format!("{prefix}.{field}"), allow_zero)?;
      }
    }
    if self.pending_queue_timeout_ms == Some(0) {
      bail!("{prefix}.pending_queue_timeout_ms must be greater than 0");
    }
    Ok(())
  }
}

/// Shared concurrency budget for non-original upstream attempts.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CircuitBreakerRetryBudgetConfig {
  #[serde(default = "default_retry_budget_percent")]
  pub percent: f64,
  #[serde(default = "default_retry_budget_min_concurrency")]
  pub min_concurrency: usize,
  #[serde(default)]
  pub max_concurrency: CapacitySetting,
  #[serde(default)]
  pub max_queue: CapacitySetting,
  #[serde(
    default = "default_retry_queue_timeout_ms",
    alias = "queue_timeout",
    deserialize_with = "deserialize_milliseconds"
  )]
  pub queue_timeout_ms: u64,
}

impl Default for CircuitBreakerRetryBudgetConfig {
  fn default() -> Self {
    Self {
      percent: default_retry_budget_percent(),
      min_concurrency: default_retry_budget_min_concurrency(),
      max_concurrency: CapacitySetting::Auto,
      max_queue: CapacitySetting::Auto,
      queue_timeout_ms: default_retry_queue_timeout_ms(),
    }
  }
}

impl CircuitBreakerRetryBudgetConfig {
  fn validate(&self) -> anyhow::Result<()> {
    if !self.percent.is_finite() || !(0.0..=1.0).contains(&self.percent) {
      bail!("circuit_breakers.retry_budget.percent must be finite and between 0 and 1");
    }
    if self.min_concurrency == 0 {
      bail!("circuit_breakers.retry_budget.min_concurrency must be greater than 0");
    }
    self
      .max_concurrency
      .validate("circuit_breakers.retry_budget.max_concurrency", false)?;
    self
      .max_queue
      .validate("circuit_breakers.retry_budget.max_queue", true)?;
    if self.queue_timeout_ms == 0 {
      bail!("circuit_breakers.retry_budget.queue_timeout_ms must be greater than 0");
    }
    Ok(())
  }
}

/// Configured upstream outcomes that contribute to a route or pool circuit.
#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CircuitFailureCondition {
  ConnectError,
  FirstByteTimeout,
  ResponseReadTimeout,
  ProtocolError,
  #[serde(rename = "502")]
  Status502,
  #[serde(rename = "503")]
  Status503,
  #[serde(rename = "504")]
  Status504,
}

/// Failure-rate and half-open recovery policy for upstream-backed scopes.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CircuitBreakerFailureConfig {
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default = "default_failure_conditions")]
  pub on: Vec<CircuitFailureCondition>,
  #[serde(default = "default_consecutive_failures")]
  pub consecutive_failures: usize,
  #[serde(default = "default_minimum_requests")]
  pub minimum_requests: usize,
  #[serde(default = "default_failure_ratio")]
  pub failure_ratio: f64,
  #[serde(
    default = "default_failure_window_ms",
    alias = "window",
    deserialize_with = "deserialize_milliseconds"
  )]
  pub window_ms: u64,
  #[serde(
    default = "default_open_timeout_ms",
    alias = "open_timeout",
    deserialize_with = "deserialize_milliseconds"
  )]
  pub open_timeout_ms: u64,
  #[serde(
    default = "default_max_open_timeout_ms",
    alias = "max_open_timeout",
    deserialize_with = "deserialize_milliseconds"
  )]
  pub max_open_timeout_ms: u64,
  #[serde(default = "default_half_open_max_probes")]
  pub half_open_max_probes: usize,
  #[serde(default = "default_half_open_successes")]
  pub half_open_successes: usize,
}

impl Default for CircuitBreakerFailureConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      on: default_failure_conditions(),
      consecutive_failures: default_consecutive_failures(),
      minimum_requests: default_minimum_requests(),
      failure_ratio: default_failure_ratio(),
      window_ms: default_failure_window_ms(),
      open_timeout_ms: default_open_timeout_ms(),
      max_open_timeout_ms: default_max_open_timeout_ms(),
      half_open_max_probes: default_half_open_max_probes(),
      half_open_successes: default_half_open_successes(),
    }
  }
}

impl CircuitBreakerFailureConfig {
  fn validate(&self) -> anyhow::Result<()> {
    if self.on.is_empty() {
      bail!("circuit_breakers.failure.on must not be empty");
    }
    if self.consecutive_failures == 0 || self.minimum_requests == 0 {
      bail!("circuit_breakers.failure thresholds must be greater than 0");
    }
    if !self.failure_ratio.is_finite() || !(0.0..=1.0).contains(&self.failure_ratio) {
      bail!("circuit_breakers.failure.failure_ratio must be finite and between 0 and 1");
    }
    if self.window_ms == 0 || self.open_timeout_ms == 0 || self.max_open_timeout_ms == 0 {
      bail!("circuit_breakers.failure durations must be greater than 0");
    }
    if self.max_open_timeout_ms < self.open_timeout_ms {
      bail!("circuit_breakers.failure.max_open_timeout_ms must be at least open_timeout_ms");
    }
    if self.half_open_max_probes == 0 || self.half_open_successes == 0 {
      bail!("circuit_breakers.failure half-open limits must be greater than 0");
    }
    Ok(())
  }
}

/// Process-local admission and upstream failure-circuit policy.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CircuitBreakersConfig {
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default = "default_circuit_response_status")]
  pub response_status: u16,
  #[serde(
    default = "default_capacity_retry_after_ms",
    alias = "capacity_retry_after",
    deserialize_with = "deserialize_milliseconds"
  )]
  pub capacity_retry_after_ms: u64,
  #[serde(default)]
  pub global: CircuitBreakerScopeConfig,
  #[serde(default)]
  pub route_defaults: CircuitBreakerScopeConfig,
  #[serde(default)]
  pub pool_defaults: CircuitBreakerScopeConfig,
  #[serde(default)]
  pub retry_budget: CircuitBreakerRetryBudgetConfig,
  #[serde(default)]
  pub failure: CircuitBreakerFailureConfig,
}

impl Default for CircuitBreakersConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      response_status: default_circuit_response_status(),
      capacity_retry_after_ms: default_capacity_retry_after_ms(),
      global: CircuitBreakerScopeConfig::default(),
      route_defaults: CircuitBreakerScopeConfig::default(),
      pool_defaults: CircuitBreakerScopeConfig::default(),
      retry_budget: CircuitBreakerRetryBudgetConfig::default(),
      failure: CircuitBreakerFailureConfig::default(),
    }
  }
}

impl CircuitBreakersConfig {
  pub(super) fn validate(&self) -> anyhow::Result<()> {
    if !(500..=599).contains(&self.response_status) {
      bail!("circuit_breakers.response_status must be a 5xx status");
    }
    if self.capacity_retry_after_ms == 0 {
      bail!("circuit_breakers.capacity_retry_after_ms must be greater than 0");
    }
    self.global.validate("circuit_breakers.global")?;
    self
      .route_defaults
      .validate("circuit_breakers.route_defaults")?;
    self
      .pool_defaults
      .validate("circuit_breakers.pool_defaults")?;
    self.retry_budget.validate()?;
    self.failure.validate()
  }
}

const fn default_true() -> bool {
  true
}

const fn default_pending_queue_timeout_ms() -> u64 {
  50
}

const fn default_retry_budget_percent() -> f64 {
  0.10
}

const fn default_retry_budget_min_concurrency() -> usize {
  1
}

const fn default_retry_queue_timeout_ms() -> u64 {
  25
}

fn default_failure_conditions() -> Vec<CircuitFailureCondition> {
  vec![
    CircuitFailureCondition::ConnectError,
    CircuitFailureCondition::FirstByteTimeout,
    CircuitFailureCondition::ResponseReadTimeout,
    CircuitFailureCondition::ProtocolError,
    CircuitFailureCondition::Status502,
    CircuitFailureCondition::Status503,
    CircuitFailureCondition::Status504,
  ]
}

const fn default_consecutive_failures() -> usize {
  5
}

const fn default_minimum_requests() -> usize {
  20
}

const fn default_failure_ratio() -> f64 {
  0.50
}

const fn default_failure_window_ms() -> u64 {
  10_000
}

const fn default_open_timeout_ms() -> u64 {
  1_000
}

const fn default_max_open_timeout_ms() -> u64 {
  30_000
}

const fn default_half_open_max_probes() -> usize {
  1
}

const fn default_half_open_successes() -> usize {
  2
}

const fn default_circuit_response_status() -> u16 {
  503
}

const fn default_capacity_retry_after_ms() -> u64 {
  1_000
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DurationLiteral {
  Milliseconds(u64),
  Text(String),
}

fn deserialize_milliseconds<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
  D: Deserializer<'de>,
{
  match DurationLiteral::deserialize(deserializer)? {
    DurationLiteral::Milliseconds(value) => Ok(value),
    DurationLiteral::Text(value) => parse_milliseconds(&value).map_err(serde::de::Error::custom),
  }
}

fn deserialize_optional_milliseconds<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
  D: Deserializer<'de>,
{
  Option::<DurationLiteral>::deserialize(deserializer)?.map_or(Ok(None), |value| match value {
    DurationLiteral::Milliseconds(value) => Ok(Some(value)),
    DurationLiteral::Text(value) => parse_milliseconds(&value)
      .map(Some)
      .map_err(serde::de::Error::custom),
  })
}

fn parse_milliseconds(value: &str) -> Result<u64, &'static str> {
  let value = value.trim();
  if let Some(milliseconds) = value.strip_suffix("ms") {
    return milliseconds
      .parse()
      .map_err(|_| "duration must be an unsigned integer followed by ms or s");
  }
  if let Some(seconds) = value.strip_suffix('s') {
    return seconds
      .parse::<u64>()
      .map_err(|_| "duration must be an unsigned integer followed by ms or s")?
      .checked_mul(1_000)
      .ok_or("duration is too large");
  }
  Err("duration must be an unsigned integer followed by ms or s")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn defaults_are_enabled_and_validate() {
    let config = CircuitBreakersConfig::default();
    assert!(config.enabled);
    config.validate().expect("safe defaults should validate");
  }

  #[test]
  fn capacity_accepts_auto_or_integer_only() {
    let auto: CircuitBreakerScopeConfig =
      toml::from_str("max_active_requests = \"auto\"").expect("auto should parse");
    assert_eq!(auto.max_active_requests, CapacitySetting::Auto);
    let fixed: CircuitBreakerScopeConfig =
      toml::from_str("max_active_requests = 12").expect("integer should parse");
    assert_eq!(fixed.max_active_requests, CapacitySetting::Fixed(12));
    assert!(
      toml::from_str::<CircuitBreakerScopeConfig>("max_active_requests = \"unlimited\"").is_err()
    );
  }

  #[test]
  fn route_override_merges_without_erasing_defaults() {
    let defaults = CircuitBreakerScopeConfig {
      max_active_requests: CapacitySetting::Fixed(8),
      ..Default::default()
    };
    let override_config = CircuitBreakerScopeOverride {
      max_pending_requests: Some(CapacitySetting::Fixed(0)),
      ..Default::default()
    };
    let merged = override_config.merged_with(&defaults);
    assert_eq!(merged.max_active_requests, CapacitySetting::Fixed(8));
    assert_eq!(merged.max_pending_requests, CapacitySetting::Fixed(0));
  }

  #[test]
  fn parses_documented_duration_aliases() {
    let config: CircuitBreakersConfig = toml::from_str(
      r#"
capacity_retry_after = "1s"

[global]
pending_queue_timeout = "50ms"

[retry_budget]
queue_timeout = "25ms"

[failure]
window = "10s"
open_timeout = "1s"
max_open_timeout = "30s"
"#,
    )
    .expect("documented duration aliases should parse");
    assert_eq!(config.capacity_retry_after_ms, 1_000);
    assert_eq!(config.global.pending_queue_timeout_ms, 50);
    assert_eq!(config.retry_budget.queue_timeout_ms, 25);
    assert_eq!(config.failure.window_ms, 10_000);
  }
}

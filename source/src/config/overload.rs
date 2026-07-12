//! Global overload-management configuration.
//! All defaults preserve the historical no-shedding behavior until operators opt in.

use anyhow::bail;
use serde::{Deserialize, Deserializer};

/// Trusted, configuration-assigned route priority.
///
/// This is deliberately distinct from client request priority metadata. The public listener
/// never grants reserved capacity from a request header or route name.
#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PriorityClass {
  Admin,
  Health,
  SecurityCallback,
  Interactive,
  #[default]
  Default,
  Background,
  Crawler,
}

impl PriorityClass {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Admin => "admin",
      Self::Health => "health",
      Self::SecurityCallback => "security_callback",
      Self::Interactive => "interactive",
      Self::Default => "default",
      Self::Background => "background",
      Self::Crawler => "crawler",
    }
  }

  pub const fn is_soft_sheddable(self) -> bool {
    matches!(self, Self::Background | Self::Crawler)
  }
}

/// Process-wide admission and shedding policy.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct OverloadConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(
    default = "default_sample_interval_ms",
    alias = "sample_interval",
    deserialize_with = "deserialize_milliseconds"
  )]
  pub sample_interval_ms: u64,
  #[serde(default = "default_soft_enter_samples")]
  pub soft_enter_samples: u32,
  #[serde(default = "default_recovery_samples")]
  pub recovery_samples: u32,
  #[serde(default = "default_recovery_ratio")]
  pub recovery_ratio: f64,
  #[serde(default = "default_signal_stale_timeout_ms")]
  pub signal_stale_timeout_ms: u64,
  #[serde(default)]
  pub thresholds: OverloadThresholds,
  #[serde(default)]
  pub actions: OverloadActions,
  #[serde(default)]
  pub reserved_capacity: OverloadReservedCapacity,
}

impl Default for OverloadConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      sample_interval_ms: default_sample_interval_ms(),
      soft_enter_samples: default_soft_enter_samples(),
      recovery_samples: default_recovery_samples(),
      recovery_ratio: default_recovery_ratio(),
      signal_stale_timeout_ms: default_signal_stale_timeout_ms(),
      thresholds: OverloadThresholds::default(),
      actions: OverloadActions::default(),
      reserved_capacity: OverloadReservedCapacity::default(),
    }
  }
}

/// Actions to apply at each overload state.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct OverloadActions {
  #[serde(default)]
  pub soft: OverloadSoftActions,
  #[serde(default)]
  pub hard: OverloadHardActions,
}

/// Soft and hard trigger values. Optional count pairs disable only that individual signal.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct OverloadThresholds {
  #[serde(default = "default_memory_soft_ratio")]
  pub memory_soft_ratio: f64,
  #[serde(default = "default_memory_hard_ratio")]
  pub memory_hard_ratio: f64,
  #[serde(default = "default_fd_soft_ratio")]
  pub fd_soft_ratio: f64,
  #[serde(default = "default_fd_hard_ratio")]
  pub fd_hard_ratio: f64,
  #[serde(default = "default_cpu_soft_ratio")]
  pub cpu_soft_ratio: f64,
  #[serde(default = "default_cpu_hard_ratio")]
  pub cpu_hard_ratio: f64,
  #[serde(
    default = "default_event_loop_lag_soft_ms",
    alias = "event_loop_lag_soft",
    deserialize_with = "deserialize_milliseconds"
  )]
  pub event_loop_lag_soft_ms: u64,
  #[serde(
    default = "default_event_loop_lag_hard_ms",
    alias = "event_loop_lag_hard",
    deserialize_with = "deserialize_milliseconds"
  )]
  pub event_loop_lag_hard_ms: u64,
  #[serde(default = "default_shared_state_waiters_soft")]
  pub shared_state_waiters_soft: u64,
  #[serde(default = "default_shared_state_waiters_hard")]
  pub shared_state_waiters_hard: u64,
  #[serde(default)]
  pub downstream_connections_soft: Option<u64>,
  #[serde(default)]
  pub downstream_connections_hard: Option<u64>,
  #[serde(default)]
  pub active_requests_soft: Option<u64>,
  #[serde(default)]
  pub active_requests_hard: Option<u64>,
  #[serde(default)]
  pub h2_streams_soft: Option<u64>,
  #[serde(default)]
  pub h2_streams_hard: Option<u64>,
  #[serde(default)]
  pub h3_streams_soft: Option<u64>,
  #[serde(default)]
  pub h3_streams_hard: Option<u64>,
  #[serde(default)]
  pub pending_upstream_requests_soft: Option<u64>,
  #[serde(default)]
  pub pending_upstream_requests_hard: Option<u64>,
  #[serde(default)]
  pub retry_concurrency_soft: Option<u64>,
  #[serde(default)]
  pub retry_concurrency_hard: Option<u64>,
  #[serde(default)]
  pub cache_fill_concurrency_soft: Option<u64>,
  #[serde(default)]
  pub cache_fill_concurrency_hard: Option<u64>,
  #[serde(default)]
  pub waf_body_inspection_concurrency_soft: Option<u64>,
  #[serde(default)]
  pub waf_body_inspection_concurrency_hard: Option<u64>,
  #[serde(default)]
  pub compression_jobs_soft: Option<u64>,
  #[serde(default)]
  pub compression_jobs_hard: Option<u64>,
  #[serde(default)]
  pub decompression_jobs_soft: Option<u64>,
  #[serde(default)]
  pub decompression_jobs_hard: Option<u64>,
  #[serde(default)]
  pub request_body_buffered_bytes_soft: Option<u64>,
  #[serde(default)]
  pub request_body_buffered_bytes_hard: Option<u64>,
}

impl Default for OverloadThresholds {
  fn default() -> Self {
    Self {
      memory_soft_ratio: default_memory_soft_ratio(),
      memory_hard_ratio: default_memory_hard_ratio(),
      fd_soft_ratio: default_fd_soft_ratio(),
      fd_hard_ratio: default_fd_hard_ratio(),
      cpu_soft_ratio: default_cpu_soft_ratio(),
      cpu_hard_ratio: default_cpu_hard_ratio(),
      event_loop_lag_soft_ms: default_event_loop_lag_soft_ms(),
      event_loop_lag_hard_ms: default_event_loop_lag_hard_ms(),
      shared_state_waiters_soft: default_shared_state_waiters_soft(),
      shared_state_waiters_hard: default_shared_state_waiters_hard(),
      downstream_connections_soft: None,
      downstream_connections_hard: None,
      active_requests_soft: None,
      active_requests_hard: None,
      h2_streams_soft: None,
      h2_streams_hard: None,
      h3_streams_soft: None,
      h3_streams_hard: None,
      pending_upstream_requests_soft: None,
      pending_upstream_requests_hard: None,
      retry_concurrency_soft: None,
      retry_concurrency_hard: None,
      cache_fill_concurrency_soft: None,
      cache_fill_concurrency_hard: None,
      waf_body_inspection_concurrency_soft: None,
      waf_body_inspection_concurrency_hard: None,
      compression_jobs_soft: None,
      compression_jobs_hard: None,
      decompression_jobs_soft: None,
      decompression_jobs_hard: None,
      request_body_buffered_bytes_soft: None,
      request_body_buffered_bytes_hard: None,
    }
  }
}

/// Actions enabled while pressure is soft. `0` concurrency caps mean automatic caps.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct OverloadSoftActions {
  #[serde(default = "default_true")]
  pub disable_cache_fill: bool,
  #[serde(default = "default_compression_level_cap")]
  pub compression_level_cap: Option<u8>,
  #[serde(default = "default_reject_priority_classes")]
  pub reject_priority_classes: Vec<PriorityClass>,
  #[serde(default = "default_retry_budget_multiplier")]
  pub retry_budget_multiplier: f64,
  #[serde(default)]
  pub waf_body_inspection_concurrency_cap: usize,
  #[serde(default)]
  pub decompression_concurrency_cap: usize,
  #[serde(default = "default_true")]
  pub prefer_cached_or_stale: bool,
}

impl Default for OverloadSoftActions {
  fn default() -> Self {
    Self {
      disable_cache_fill: true,
      compression_level_cap: default_compression_level_cap(),
      reject_priority_classes: default_reject_priority_classes(),
      retry_budget_multiplier: default_retry_budget_multiplier(),
      waf_body_inspection_concurrency_cap: 0,
      decompression_concurrency_cap: 0,
      prefer_cached_or_stale: true,
    }
  }
}

/// Actions enabled while pressure is hard. Soft actions continue to apply.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct OverloadHardActions {
  #[serde(default = "default_true")]
  pub reject_new_connections: bool,
  #[serde(default = "default_true")]
  pub reject_new_streams: bool,
  #[serde(default = "default_true")]
  pub reject_new_requests: bool,
  #[serde(default = "default_true")]
  pub stop_large_request_bodies: bool,
  #[serde(default = "default_large_request_body_threshold_bytes")]
  pub large_request_body_threshold_bytes: u64,
  #[serde(default = "default_true")]
  pub disable_cache_fill: bool,
  #[serde(default = "default_true")]
  pub disable_compression: bool,
  #[serde(default = "default_true")]
  pub disable_retries: bool,
  #[serde(default = "default_true")]
  pub disable_request_mirroring: bool,
  #[serde(default = "default_true")]
  pub reject_expensive_waf_bodies: bool,
  #[serde(default = "default_true")]
  pub enter_recoverable_drain: bool,
  #[serde(default = "default_true")]
  pub fail_readiness: bool,
  #[serde(default = "default_overload_response_status")]
  pub response_status: u16,
  #[serde(
    default = "default_retry_after_seconds",
    alias = "retry_after",
    deserialize_with = "deserialize_seconds"
  )]
  pub retry_after_seconds: u64,
}

impl Default for OverloadHardActions {
  fn default() -> Self {
    Self {
      reject_new_connections: true,
      reject_new_streams: true,
      reject_new_requests: true,
      stop_large_request_bodies: true,
      large_request_body_threshold_bytes: default_large_request_body_threshold_bytes(),
      disable_cache_fill: true,
      disable_compression: true,
      disable_retries: true,
      disable_request_mirroring: true,
      reject_expensive_waf_bodies: true,
      enter_recoverable_drain: true,
      fail_readiness: true,
      response_status: default_overload_response_status(),
      retry_after_seconds: default_retry_after_seconds(),
    }
  }
}

/// Capacity excluded from data-plane admission and kept for dedicated control listeners.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct OverloadReservedCapacity {
  #[serde(default = "default_reserved_file_descriptors")]
  pub file_descriptors: u64,
  #[serde(default = "default_admin_connections")]
  pub admin_connections: usize,
  #[serde(default = "default_admin_requests")]
  pub admin_requests: usize,
  #[serde(default = "default_health_connections")]
  pub health_connections: usize,
  #[serde(default = "default_health_requests")]
  pub health_requests: usize,
  #[serde(default = "default_metrics_connections")]
  pub metrics_connections: usize,
  #[serde(default = "default_metrics_requests")]
  pub metrics_requests: usize,
}

impl Default for OverloadReservedCapacity {
  fn default() -> Self {
    Self {
      file_descriptors: default_reserved_file_descriptors(),
      admin_connections: default_admin_connections(),
      admin_requests: default_admin_requests(),
      health_connections: default_health_connections(),
      health_requests: default_health_requests(),
      metrics_connections: default_metrics_connections(),
      metrics_requests: default_metrics_requests(),
    }
  }
}

impl OverloadConfig {
  pub(super) fn validate(&self) -> anyhow::Result<()> {
    if self.sample_interval_ms == 0 {
      bail!("overload.sample_interval_ms must be greater than 0");
    }
    if self.soft_enter_samples == 0 || self.recovery_samples == 0 {
      bail!("overload soft_enter_samples and recovery_samples must be greater than 0");
    }
    if !(0.0 < self.recovery_ratio && self.recovery_ratio < 1.0) {
      bail!("overload.recovery_ratio must be greater than 0 and less than 1");
    }
    if self.signal_stale_timeout_ms < self.sample_interval_ms {
      bail!("overload.signal_stale_timeout_ms must be at least overload.sample_interval_ms");
    }
    self.thresholds.validate()?;
    if !self.actions.soft.retry_budget_multiplier.is_finite()
      || !(0.0..=1.0).contains(&self.actions.soft.retry_budget_multiplier)
    {
      bail!("overload.actions.soft.retry_budget_multiplier must be finite and between 0 and 1");
    }
    if self
      .actions
      .soft
      .compression_level_cap
      .is_some_and(|value| value > 9)
    {
      bail!("overload.actions.soft.compression_level_cap must be between 0 and 9");
    }
    if self
      .actions
      .soft
      .reject_priority_classes
      .iter()
      .any(|class| !class.is_soft_sheddable())
    {
      bail!("overload.actions.soft.reject_priority_classes may contain only background or crawler");
    }
    let hard = &self.actions.hard;
    if hard.stop_large_request_bodies && hard.large_request_body_threshold_bytes == 0 {
      bail!("overload.actions.hard.large_request_body_threshold_bytes must be greater than 0");
    }
    if !(500..=599).contains(&hard.response_status) {
      bail!("overload.actions.hard.response_status must be a 5xx status");
    }
    if hard.retry_after_seconds == 0 {
      bail!("overload.actions.hard.retry_after_seconds must be greater than 0");
    }
    self.reserved_capacity.validate()
  }
}

impl OverloadThresholds {
  fn validate(&self) -> anyhow::Result<()> {
    validate_ratio_pair("memory", self.memory_soft_ratio, self.memory_hard_ratio)?;
    validate_ratio_pair("fd", self.fd_soft_ratio, self.fd_hard_ratio)?;
    validate_ratio_pair("cpu", self.cpu_soft_ratio, self.cpu_hard_ratio)?;
    validate_count_pair(
      "event_loop_lag_ms",
      Some(self.event_loop_lag_soft_ms),
      Some(self.event_loop_lag_hard_ms),
    )?;
    validate_count_pair(
      "shared_state_waiters",
      Some(self.shared_state_waiters_soft),
      Some(self.shared_state_waiters_hard),
    )?;
    for (name, soft, hard) in [
      (
        "downstream_connections",
        self.downstream_connections_soft,
        self.downstream_connections_hard,
      ),
      (
        "active_requests",
        self.active_requests_soft,
        self.active_requests_hard,
      ),
      ("h2_streams", self.h2_streams_soft, self.h2_streams_hard),
      ("h3_streams", self.h3_streams_soft, self.h3_streams_hard),
      (
        "pending_upstream_requests",
        self.pending_upstream_requests_soft,
        self.pending_upstream_requests_hard,
      ),
      (
        "retry_concurrency",
        self.retry_concurrency_soft,
        self.retry_concurrency_hard,
      ),
      (
        "cache_fill_concurrency",
        self.cache_fill_concurrency_soft,
        self.cache_fill_concurrency_hard,
      ),
      (
        "waf_body_inspection_concurrency",
        self.waf_body_inspection_concurrency_soft,
        self.waf_body_inspection_concurrency_hard,
      ),
      (
        "compression_jobs",
        self.compression_jobs_soft,
        self.compression_jobs_hard,
      ),
      (
        "decompression_jobs",
        self.decompression_jobs_soft,
        self.decompression_jobs_hard,
      ),
      (
        "request_body_buffered_bytes",
        self.request_body_buffered_bytes_soft,
        self.request_body_buffered_bytes_hard,
      ),
    ] {
      validate_count_pair(name, soft, hard)?;
    }
    Ok(())
  }
}

impl OverloadReservedCapacity {
  fn validate(&self) -> anyhow::Result<()> {
    if self.file_descriptors == 0 {
      bail!("overload.reserved_capacity.file_descriptors must be greater than 0");
    }
    for (name, value) in [
      ("admin_connections", self.admin_connections),
      ("admin_requests", self.admin_requests),
      ("health_connections", self.health_connections),
      ("health_requests", self.health_requests),
      ("metrics_connections", self.metrics_connections),
      ("metrics_requests", self.metrics_requests),
    ] {
      if value == 0 {
        bail!("overload.reserved_capacity.{name} must be greater than 0");
      }
    }
    Ok(())
  }
}

fn validate_ratio_pair(name: &str, soft: f64, hard: f64) -> anyhow::Result<()> {
  if !(soft.is_finite() && hard.is_finite() && 0.0 < soft && soft < hard && hard <= 1.0) {
    bail!(
      "overload.thresholds.{name}_soft_ratio and {name}_hard_ratio must satisfy 0 < soft < hard <= 1"
    );
  }
  Ok(())
}

fn validate_count_pair(name: &str, soft: Option<u64>, hard: Option<u64>) -> anyhow::Result<()> {
  match (soft, hard) {
    (None, None) => Ok(()),
    (Some(soft), Some(hard)) if soft > 0 && soft < hard => Ok(()),
    _ => bail!(
      "overload.thresholds.{name}_soft and {name}_hard must both be set and satisfy 0 < soft < hard"
    ),
  }
}

const fn default_sample_interval_ms() -> u64 {
  250
}
const fn default_soft_enter_samples() -> u32 {
  2
}
const fn default_recovery_samples() -> u32 {
  8
}
const fn default_recovery_ratio() -> f64 {
  0.90
}
const fn default_signal_stale_timeout_ms() -> u64 {
  2_000
}
const fn default_memory_soft_ratio() -> f64 {
  0.75
}
const fn default_memory_hard_ratio() -> f64 {
  0.90
}
const fn default_fd_soft_ratio() -> f64 {
  0.75
}
const fn default_fd_hard_ratio() -> f64 {
  0.90
}
const fn default_cpu_soft_ratio() -> f64 {
  0.85
}
const fn default_cpu_hard_ratio() -> f64 {
  0.95
}
const fn default_event_loop_lag_soft_ms() -> u64 {
  25
}
const fn default_event_loop_lag_hard_ms() -> u64 {
  100
}
const fn default_shared_state_waiters_soft() -> u64 {
  100
}
const fn default_shared_state_waiters_hard() -> u64 {
  500
}
const fn default_compression_level_cap() -> Option<u8> {
  Some(2)
}
fn default_reject_priority_classes() -> Vec<PriorityClass> {
  vec![PriorityClass::Background, PriorityClass::Crawler]
}
const fn default_retry_budget_multiplier() -> f64 {
  0.5
}
const fn default_large_request_body_threshold_bytes() -> u64 {
  1_048_576
}
const fn default_overload_response_status() -> u16 {
  503
}
const fn default_retry_after_seconds() -> u64 {
  3
}
const fn default_reserved_file_descriptors() -> u64 {
  64
}
const fn default_admin_connections() -> usize {
  32
}
const fn default_admin_requests() -> usize {
  32
}
const fn default_health_connections() -> usize {
  8
}
const fn default_health_requests() -> usize {
  8
}
const fn default_metrics_connections() -> usize {
  4
}
const fn default_metrics_requests() -> usize {
  4
}
const fn default_true() -> bool {
  true
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

fn deserialize_seconds<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
  D: Deserializer<'de>,
{
  match DurationLiteral::deserialize(deserializer)? {
    DurationLiteral::Milliseconds(value) => Ok(value),
    DurationLiteral::Text(value) => {
      let milliseconds = parse_milliseconds(&value).map_err(serde::de::Error::custom)?;
      if milliseconds % 1_000 != 0 {
        return Err(serde::de::Error::custom(
          "duration must be expressed as a whole number of seconds",
        ));
      }
      Ok(milliseconds / 1_000)
    }
  }
}

fn parse_milliseconds(value: &str) -> Result<u64, &'static str> {
  let value = value.trim();
  if let Some(milliseconds) = value.strip_suffix("ms") {
    return milliseconds
      .parse()
      .map_err(|_| "duration must be an unsigned integer followed by ms or s");
  }
  if let Some(seconds) = value.strip_suffix('s') {
    let seconds = seconds
      .parse::<u64>()
      .map_err(|_| "duration must be an unsigned integer followed by ms or s")?;
    return seconds.checked_mul(1_000).ok_or("duration is too large");
  }
  Err("duration must be an unsigned integer followed by ms or s")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn defaults_are_compatible_and_validate() {
    let config = OverloadConfig::default();
    assert!(!config.enabled);
    config.validate().expect("defaults should validate");
  }

  #[test]
  fn rejects_public_priority_as_soft_shedding_class() {
    let mut config = OverloadConfig::default();
    config.actions.soft.reject_priority_classes = vec![PriorityClass::Interactive];
    assert!(config.validate().is_err());
  }

  #[test]
  fn validates_optional_threshold_pairs() {
    let mut config = OverloadConfig::default();
    config.thresholds.active_requests_soft = Some(4);
    assert!(config.validate().is_err());
    config.thresholds.active_requests_hard = Some(8);
    config
      .validate()
      .expect("complete threshold pair should validate");
  }

  #[test]
  fn zero_soft_compression_cap_disables_that_soft_action() {
    let mut config = OverloadConfig::default();
    config.actions.soft.compression_level_cap = Some(0);
    config
      .validate()
      .expect("zero should disable only the soft compression cap");
  }

  #[test]
  fn parses_plan_duration_literals_without_overflow() {
    let config: OverloadConfig = toml::from_str(
      r#"
sample_interval = "250ms"

[thresholds]
event_loop_lag_soft = "25ms"
event_loop_lag_hard = "100ms"

[actions.hard]
retry_after = "3s"
"#,
    )
    .expect("plan duration literals should parse");
    assert_eq!(config.sample_interval_ms, 250);
    assert_eq!(config.thresholds.event_loop_lag_soft_ms, 25);
    assert_eq!(config.actions.hard.retry_after_seconds, 3);
    assert!(
      toml::from_str::<OverloadConfig>("sample_interval = \"18446744073709551616s\"").is_err()
    );
  }
}

//! Upstream retry configuration validation.
//! Retry conditions are normalized before request dispatch can use them.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ProxyRetryConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_retry_tries")]
  pub tries: usize,
  #[serde(default = "default_retry_timeout_ms")]
  pub timeout_ms: u64,
  #[serde(default)]
  pub total_budget_ms: Option<u64>,
  #[serde(default)]
  pub per_attempt_timeout_ms: Option<u64>,
  #[serde(default = "default_retry_on")]
  pub on: Vec<RetryCondition>,
  #[serde(default)]
  pub retry_non_idempotent: bool,
  #[serde(default)]
  pub backoff_base_ms: u64,
  #[serde(default)]
  pub backoff_max_ms: u64,
  #[serde(default)]
  pub jitter: bool,
  #[serde(default = "default_retry_pool_reselect")]
  pub reselect_pool_on_retry: bool,
  #[serde(default = "default_retry_pool_reselect")]
  pub exclude_failed_pool_upstreams: bool,
  #[serde(default = "default_retry_pool_reselect")]
  pub report_passive_health: bool,
}

impl Default for ProxyRetryConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      tries: default_retry_tries(),
      timeout_ms: default_retry_timeout_ms(),
      total_budget_ms: None,
      per_attempt_timeout_ms: None,
      on: default_retry_on(),
      retry_non_idempotent: false,
      backoff_base_ms: 0,
      backoff_max_ms: 0,
      jitter: false,
      reselect_pool_on_retry: true,
      exclude_failed_pool_upstreams: true,
      report_passive_health: true,
    }
  }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RetryCondition {
  ConnectError,
  ReadTimeout,
  #[serde(rename = "502")]
  Status502,
  #[serde(rename = "503")]
  Status503,
  #[serde(rename = "504")]
  Status504,
}

fn default_retry_tries() -> usize {
  2
}

fn default_retry_timeout_ms() -> u64 {
  5_000
}

fn default_retry_pool_reselect() -> bool {
  true
}

fn default_retry_on() -> Vec<RetryCondition> {
  vec![
    RetryCondition::ConnectError,
    RetryCondition::ReadTimeout,
    RetryCondition::Status502,
    RetryCondition::Status503,
    RetryCondition::Status504,
  ]
}

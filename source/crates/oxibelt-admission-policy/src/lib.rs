//! Process-local overload and circuit-breaker configuration and validation.

mod circuit_breakers;
mod overload;

pub use circuit_breakers::{
  CapacitySetting, CircuitBreakerFailureConfig, CircuitBreakerPriorityClassConfig,
  CircuitBreakerPriorityConfig, CircuitBreakerRetryBudgetConfig, CircuitBreakerScopeConfig,
  CircuitBreakerScopeOverride, CircuitBreakersConfig, CircuitFailureCondition,
  PriorityRejectionPolicy,
};
#[doc(hidden)]
pub use circuit_breakers::{PriorityClassPolicy, max_class_requests};
pub use overload::{
  OverloadActions, OverloadConfig, OverloadHardActions, OverloadReservedCapacity,
  OverloadSoftActions, OverloadThresholds, PriorityClass,
};

// The integration crate calls these without widening methods on its public
// configuration types. This crate is an unpublished workspace implementation.
#[doc(hidden)]
pub fn validate_overload_config(config: &OverloadConfig) -> anyhow::Result<()> {
  config.validate()
}

#[doc(hidden)]
pub fn validate_circuit_breakers_config(config: &CircuitBreakersConfig) -> anyhow::Result<()> {
  config.validate()
}

#[doc(hidden)]
pub fn validate_circuit_breaker_scope_override(
  config: &CircuitBreakerScopeOverride,
  prefix: &str,
) -> anyhow::Result<()> {
  config.validate(prefix)
}

#[doc(hidden)]
pub fn resolved_priority_policy(
  config: &CircuitBreakerPriorityConfig,
  class: PriorityClass,
) -> PriorityClassPolicy {
  config.resolved_for_validation(class)
}

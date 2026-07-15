//! Generation-aware health and admission services shared across snapshot reloads.

use std::sync::Arc;

use crate::circuit_breakers::CircuitBreakerRuntime;
use crate::config::Config;
use crate::overload::OverloadRuntime;
use crate::runtime_health::RuntimeHealth;

use super::AppSnapshot;

#[allow(
  clippy::type_complexity,
  reason = "keeps snapshot construction below the module-size gate"
)]
pub(super) fn build(
  config: &Config,
  previous: Option<&AppSnapshot>,
) -> anyhow::Result<(
  Arc<RuntimeHealth>,
  u64,
  Arc<OverloadRuntime>,
  Arc<CircuitBreakerRuntime>,
)> {
  let runtime_health = previous
    .map(|snapshot| snapshot.runtime_health.clone())
    .unwrap_or_default();
  let runtime_generation = runtime_health.allocate_generation();
  let overload = previous
    .map(|snapshot| snapshot.overload.clone())
    .unwrap_or_else(|| OverloadRuntime::new_with_health(&config.overload, runtime_health.clone()));
  if config.overload.enabled {
    overload.bootstrap_validate()?;
  }
  let circuit_breakers = previous
    .map(|snapshot| snapshot.circuit_breakers.clone())
    .unwrap_or_else(|| CircuitBreakerRuntime::new_with_health(config, runtime_health.clone()));
  circuit_breakers.configure(config);
  Ok((
    runtime_health,
    runtime_generation,
    overload,
    circuit_breakers,
  ))
}

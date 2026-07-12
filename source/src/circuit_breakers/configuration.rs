//! Snapshot-to-runtime scope resolution and small admission helpers.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::{CircuitBreakerRetryBudgetConfig, Config};

use super::resources::{
  AutoScope, RuntimeResources, configured_capacity, configured_queue_capacity, scope_defaults,
};
use super::runtime::RuntimeState;
use super::types::{Allocation, ResourceKind, RetryBudget, ScopeKey, ScopeLimits, ScopeState};

pub(super) fn resolve_scopes(config: &Config) -> (HashMap<ScopeKey, ScopeState>, RetryBudget) {
  let breaker = &config.circuit_breakers;
  let resources = RuntimeResources::discover(config);
  let global_auto = scope_defaults(resources, AutoScope::Global, &breaker.global, None);
  let global_limits = ScopeLimits::for_scope(&breaker.global, global_auto);
  let mut scopes = HashMap::new();
  scopes.insert(ScopeKey::Global, ScopeState::new(global_limits, false));
  for route in &config.routes {
    let effective = route
      .circuit_breaker
      .as_ref()
      .map(|override_config| override_config.merged_with(&breaker.route_defaults))
      .unwrap_or_else(|| breaker.route_defaults.clone());
    let automatic = scope_defaults(resources, AutoScope::Route, &effective, Some(&global_auto));
    scopes.insert(
      ScopeKey::Route(route.name.clone()),
      ScopeState::new(
        ScopeLimits::for_scope(&effective, automatic),
        breaker.failure.enabled,
      ),
    );
  }
  for pool in &config.upstream_pools {
    let effective = pool
      .circuit_breaker
      .as_ref()
      .map(|override_config| override_config.merged_with(&breaker.pool_defaults))
      .unwrap_or_else(|| breaker.pool_defaults.clone());
    let automatic = scope_defaults(resources, AutoScope::Pool, &effective, Some(&global_auto));
    scopes.insert(
      ScopeKey::Pool(pool.name.clone()),
      ScopeState::new(
        ScopeLimits::for_scope(&effective, automatic),
        breaker.failure.enabled,
      ),
    );
  }
  let retry = resolve_retry_budget(resources, &breaker.retry_budget);
  (scopes, retry)
}

fn resolve_retry_budget(
  resources: RuntimeResources,
  config: &CircuitBreakerRetryBudgetConfig,
) -> RetryBudget {
  let automatic = resources.retry_concurrency();
  let max = configured_capacity(config.max_concurrency, automatic);
  RetryBudget {
    percent: config.percent,
    min: config.min_concurrency,
    max: max.max(config.min_concurrency),
    queue: configured_queue_capacity(config.max_queue, resources.retry_queue(max)),
    timeout: Duration::from_millis(config.queue_timeout_ms),
  }
}

pub(super) fn scoped_allocations(
  route: Option<&str>,
  pool: Option<&str>,
  resource: ResourceKind,
) -> Vec<Allocation> {
  let mut allocations = vec![Allocation {
    scope: ScopeKey::Global,
    resource,
    limit: None,
  }];
  if let Some(route) = route {
    allocations.push(Allocation {
      scope: ScopeKey::Route(route.to_string()),
      resource,
      limit: None,
    });
  }
  if let Some(pool) = pool {
    allocations.push(Allocation {
      scope: ScopeKey::Pool(pool.to_string()),
      resource,
      limit: None,
    });
  }
  allocations
}

pub(super) fn deduplicate_allocations(allocations: Vec<Allocation>) -> Vec<Allocation> {
  let mut unique = Vec::with_capacity(allocations.len());
  for allocation in allocations {
    if let Some(existing) = unique.iter_mut().find(|existing: &&mut Allocation| {
      existing.scope == allocation.scope && existing.resource == allocation.resource
    }) {
      if allocation.limit.is_some() {
        existing.limit = allocation.limit;
      }
    } else {
      unique.push(allocation);
    }
  }
  unique
}

pub(super) fn queue_timeout(
  state: &Mutex<RuntimeState>,
  allocations: &[Allocation],
  deadline: Option<Instant>,
) -> Duration {
  let state = state.lock().expect("circuit-breaker state lock poisoned");
  let configured = allocations
    .iter()
    .filter_map(|allocation| {
      state
        .scopes
        .get(&allocation.scope)
        .map(|scope| allocation.effective_limit(scope).timeout)
    })
    .min()
    .unwrap_or(Duration::ZERO);
  deadline
    .map(|deadline| configured.min(deadline.saturating_duration_since(Instant::now())))
    .unwrap_or(configured)
}

pub(super) fn elapsed_ms(started: Instant) -> u64 {
  started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

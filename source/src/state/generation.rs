//! Runtime generation counters for independently replaceable pool state.

use super::AppSnapshot;
use crate::circuit_breakers::CompioDirectH1Budget;
use crate::config::{Config, RuntimeDirectH1IoMode};

pub(super) fn next_upstream_pool_generation(
  config: &Config,
  previous: Option<&AppSnapshot>,
) -> u64 {
  let Some(previous) = previous else {
    return 0;
  };
  if config.upstream_pools == previous.config.upstream_pools {
    previous.upstream_pool_generation
  } else {
    previous.upstream_pool_generation.saturating_add(1)
  }
}

pub(super) fn next_direct_h1_plan_generation(
  config: &Config,
  effective_io: RuntimeDirectH1IoMode,
  budget: Option<CompioDirectH1Budget>,
  previous: Option<&AppSnapshot>,
) -> u64 {
  let Some(previous) = previous else {
    return 0;
  };
  if direct_h1_plan_equivalent(config, effective_io, budget, previous) {
    previous.direct_h1_plan_generation
  } else {
    previous.direct_h1_plan_generation.saturating_add(1)
  }
}

fn direct_h1_plan_equivalent(
  config: &Config,
  effective_io: RuntimeDirectH1IoMode,
  budget: Option<CompioDirectH1Budget>,
  previous: &AppSnapshot,
) -> bool {
  effective_io == previous.effective_direct_h1_io
    && budget == previous.compio_direct_h1_budget
    && config.upstreams == previous.config.upstreams
    && config.upstream_pools == previous.config.upstream_pools
}

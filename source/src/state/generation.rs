//! Runtime generation counters for independently replaceable pool state.

use super::AppSnapshot;
use crate::config::Config;

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

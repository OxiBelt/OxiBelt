//! Active-generation runtime topology derivation.

use anyhow::Context;

use crate::config::Config;
use crate::runtime::topology::{
  RuntimeResolvedPreset, RuntimeTopologySnapshot, resolve_runtime_topology,
};
use crate::runtime::topology_config::{
  capabilities_for_active, external_topology, request_from_config,
};

use super::AppSnapshot;

pub(super) fn for_snapshot_build(
  config: &Config,
  supplied: Option<RuntimeTopologySnapshot>,
  previous: Option<&AppSnapshot>,
) -> anyhow::Result<RuntimeTopologySnapshot> {
  if let Some(topology) = supplied {
    return Ok(topology);
  }
  let Some(previous) = previous else {
    return Ok(external_topology(config));
  };
  if previous.runtime_topology.resolved_preset == RuntimeResolvedPreset::External {
    return Ok(external_topology(config));
  }
  resolve_runtime_topology(
    request_from_config(config),
    capabilities_for_active(&previous.runtime_topology),
  )
  .context("replacement runtime topology is incompatible with the active process")
}

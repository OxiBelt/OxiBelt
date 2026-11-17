//! Owned Tokio runtime activation.
use crate::config::Config;
use crate::runtime::main_runtime::MainRuntime;
use crate::runtime::topology::{
  RuntimeTopologyCapabilities, RuntimeTopologySnapshot, resolve_runtime_topology,
};
use crate::runtime::topology_config::request_from_config;
use anyhow::Context;

pub(crate) struct ActivatedOwnedRuntime {
  pub(crate) runtime: MainRuntime,
  pub(crate) topology: RuntimeTopologySnapshot,
}
pub(crate) fn activate_owned_runtime(
  config: &Config,
  capabilities: RuntimeTopologyCapabilities,
) -> anyhow::Result<ActivatedOwnedRuntime> {
  let topology = resolve_runtime_topology(request_from_config(config), capabilities)
    .context("requested Tokio topology cannot be activated")?;
  let runtime = MainRuntime::build_tokio(config.runtime.workers.tokio)
    .context("Tokio runtime failed to build")?;
  Ok(ActivatedOwnedRuntime { runtime, topology })
}

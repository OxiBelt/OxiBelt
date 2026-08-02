//! Owned-runtime topology resolution and one-shot activation fallback.

use anyhow::Context;

use crate::config::Config;
use crate::runtime::main_runtime::{ActiveMainRuntime, MainRuntime};
use crate::runtime::topology::{
  RuntimeCapability, RuntimeRequestedPreset, RuntimeResolvedPreset, RuntimeTopologyCapabilities,
  RuntimeTopologyPolicy, RuntimeTopologyReason, RuntimeTopologySnapshot, resolve_runtime_topology,
};
use crate::runtime::topology_config::request_from_config;

pub(crate) struct ActivatedOwnedRuntime {
  pub(crate) runtime: MainRuntime,
  pub(crate) topology: RuntimeTopologySnapshot,
}

pub(crate) fn activate_owned_runtime(
  config: &Config,
  mut capabilities: RuntimeTopologyCapabilities,
) -> anyhow::Result<ActivatedOwnedRuntime> {
  let request = request_from_config(config);
  let worker_threads = config.runtime.workers.tokio;
  let mut topology = resolve_runtime_topology(request, capabilities)
    .context("requested runtime topology cannot be activated")?;
  let mut active = active_runtime_for_topology(&topology);
  let runtime = match build_main_runtime(active, worker_threads) {
    Ok(runtime) => runtime,
    Err(_error)
      if request.requested_preset == RuntimeRequestedPreset::Auto
        && request.policy == RuntimeTopologyPolicy::AllowFallback
        && active == ActiveMainRuntime::Compio =>
    {
      tracing::warn!(
        reason = RuntimeTopologyReason::CompioRuntimeBuildFailed.as_str(),
        worker_threads,
        "runtime topology capability changed during activation; resolving once more"
      );
      capabilities.compio_main =
        RuntimeCapability::Unavailable(RuntimeTopologyReason::CompioRuntimeBuildFailed);
      topology = resolve_runtime_topology(request, capabilities)
        .context("fallback runtime topology cannot be activated")?;
      active = active_runtime_for_topology(&topology);
      build_main_runtime(active, worker_threads).with_context(|| {
        format!(
          "fallback runtime build failed after {}",
          RuntimeTopologyReason::CompioRuntimeBuildFailed.as_str()
        )
      })?
    }
    Err(error) => return Err(error.context("resolved main runtime failed to build")),
  };
  Ok(ActivatedOwnedRuntime { runtime, topology })
}

fn active_runtime_for_topology(topology: &RuntimeTopologySnapshot) -> ActiveMainRuntime {
  match topology.resolved_preset {
    RuntimeResolvedPreset::HybridCompio => ActiveMainRuntime::Compio,
    RuntimeResolvedPreset::TokioHyper | RuntimeResolvedPreset::External => {
      ActiveMainRuntime::TokioHyper
    }
  }
}

fn build_main_runtime(
  active_runtime: ActiveMainRuntime,
  worker_threads: usize,
) -> anyhow::Result<MainRuntime> {
  match active_runtime {
    ActiveMainRuntime::Compio => MainRuntime::build_compio(worker_threads),
    ActiveMainRuntime::TokioHyper => MainRuntime::build_tokio(worker_threads),
  }
}

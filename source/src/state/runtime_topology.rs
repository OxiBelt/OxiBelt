//! Active-generation runtime topology derivation.

use anyhow::Context;

use crate::config::{Config, RuntimeDirectH1IoMode};
use crate::runtime::topology::{
  RuntimeDirectH1Backend, RuntimeResolvedPreset, RuntimeTopologySnapshot, resolve_runtime_topology,
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

pub(super) fn effective_direct_h1_io(
  config: &Config,
  topology: &RuntimeTopologySnapshot,
) -> RuntimeDirectH1IoMode {
  match topology.direct_h1.resolved {
    RuntimeDirectH1Backend::Compio => RuntimeDirectH1IoMode::Compio,
    RuntimeDirectH1Backend::TokioHyper => {
      if config.runtime.direct_h1_io == RuntimeDirectH1IoMode::Auto {
        RuntimeDirectH1IoMode::Auto
      } else {
        RuntimeDirectH1IoMode::TokioHyper
      }
    }
    RuntimeDirectH1Backend::Disabled | RuntimeDirectH1Backend::External => {
      RuntimeDirectH1IoMode::TokioHyper
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::topology::RuntimeTopologyOutcome;

  #[test]
  fn embedded_snapshot_does_not_claim_compio_direct_h1() {
    let mut config: Config = toml::from_str(
      r#"
[listeners]
https_bind = "127.0.0.1:8443"

[tls]
cert_chain = "fullchain.pem"
private_key = "privkey.pem"
"#,
    )
    .expect("minimal TOML should resolve configuration defaults");
    config.runtime.direct_h1_io = RuntimeDirectH1IoMode::Compio;
    let topology = external_topology(&config);

    assert_eq!(
      effective_direct_h1_io(&config, &topology),
      RuntimeDirectH1IoMode::TokioHyper
    );
    assert_eq!(topology.outcome, RuntimeTopologyOutcome::External);
  }
}

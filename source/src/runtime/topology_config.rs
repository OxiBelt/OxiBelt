//! Configuration adapters for the typed runtime-topology resolver.

use crate::config::{
  Config, RuntimeDirectH1IoMode, RuntimeMainRuntimeMode,
  RuntimeTopologyPolicy as ConfigRuntimeTopologyPolicy,
};

use super::topology::{
  RuntimeCapability, RuntimeDirectH1Requested, RuntimeRequestedPreset, RuntimeResolvedPreset,
  RuntimeTargetArch, RuntimeTargetOs, RuntimeTopologyCapabilities, RuntimeTopologyPolicy,
  RuntimeTopologyReason, RuntimeTopologyRequest, RuntimeTopologySnapshot, RuntimeWorkerAllocations,
};

pub fn request_from_config(config: &Config) -> RuntimeTopologyRequest {
  RuntimeTopologyRequest {
    requested_preset: match config.runtime.main_runtime {
      RuntimeMainRuntimeMode::Auto => RuntimeRequestedPreset::Auto,
      RuntimeMainRuntimeMode::HybridCompio => RuntimeRequestedPreset::HybridCompio,
      RuntimeMainRuntimeMode::Compio => RuntimeRequestedPreset::Compio,
      RuntimeMainRuntimeMode::TokioHyper => RuntimeRequestedPreset::TokioHyper,
    },
    policy: match config.runtime.topology_policy {
      ConfigRuntimeTopologyPolicy::AllowFallback => RuntimeTopologyPolicy::AllowFallback,
      ConfigRuntimeTopologyPolicy::RequireExact => RuntimeTopologyPolicy::RequireExact,
    },
    direct_h1: match config.runtime.direct_h1_io {
      RuntimeDirectH1IoMode::Auto => RuntimeDirectH1Requested::Auto,
      RuntimeDirectH1IoMode::TokioHyper => RuntimeDirectH1Requested::TokioHyper,
      RuntimeDirectH1IoMode::Compio => RuntimeDirectH1Requested::Compio,
    },
    http3_enabled: config.listeners.http3,
    workers: RuntimeWorkerAllocations {
      tokio_executor_workers: config.runtime.workers.tokio,
      tcp_accept_workers: config.runtime.accept.workers,
      quic_socket_workers: config.quic.socket.workers,
      compio_direct_h1_workers: config.runtime.workers.compio_direct_h1,
      tokio_blocking_worker_limit: None,
    },
  }
}

pub fn available_capabilities(
  driver: Option<super::backend::CompioDriverSelection>,
) -> RuntimeTopologyCapabilities {
  let target_os = target_os();
  let target_arch = target_arch();
  let mut capabilities = RuntimeTopologyCapabilities::available(target_os, target_arch, driver);
  if target_os == RuntimeTargetOs::Other {
    capabilities.platform =
      RuntimeCapability::Unavailable(RuntimeTopologyReason::UnsupportedOperatingSystem);
  } else if target_arch == RuntimeTargetArch::Other {
    capabilities.platform =
      RuntimeCapability::Unavailable(RuntimeTopologyReason::UnsupportedArchitecture);
  }
  if target_os != RuntimeTargetOs::Linux {
    capabilities.compio_direct_h1 =
      RuntimeCapability::Unavailable(RuntimeTopologyReason::UnsupportedOperatingSystem);
  }
  capabilities
}

pub fn capabilities_for_active(topology: &RuntimeTopologySnapshot) -> RuntimeTopologyCapabilities {
  let compio_main = if topology.resolved_preset == RuntimeResolvedPreset::HybridCompio {
    RuntimeCapability::Available
  } else {
    RuntimeCapability::Unavailable(if topology.reason == RuntimeTopologyReason::None {
      RuntimeTopologyReason::MainTopologyIncompatible
    } else {
      topology.reason
    })
  };
  RuntimeTopologyCapabilities {
    target_os: topology.target_os,
    target_arch: topology.target_arch,
    compio_driver: topology.compio_driver,
    platform: RuntimeCapability::Available,
    compio_main,
    compio_direct_h1: RuntimeCapability::Available,
    required_socket_features: RuntimeCapability::Available,
    selected_protocol_features: RuntimeCapability::Available,
    hardening: RuntimeCapability::Available,
  }
}

pub fn external_topology(config: &Config) -> RuntimeTopologySnapshot {
  let mut workers = request_from_config(config).workers;
  workers.tokio_executor_workers = 0;
  workers.compio_direct_h1_workers = 0;
  workers.tokio_blocking_worker_limit = None;
  if !config.listeners.http3 {
    workers.quic_socket_workers = 0;
  }
  RuntimeTopologySnapshot::external_with_workers(workers)
}

fn target_os() -> RuntimeTargetOs {
  match std::env::consts::OS {
    "linux" => RuntimeTargetOs::Linux,
    "windows" => RuntimeTargetOs::Windows,
    "macos" => RuntimeTargetOs::Macos,
    _ => RuntimeTargetOs::Other,
  }
}

fn target_arch() -> RuntimeTargetArch {
  match std::env::consts::ARCH {
    "x86_64" => RuntimeTargetArch::X86_64,
    "aarch64" => RuntimeTargetArch::Aarch64,
    "riscv64" => RuntimeTargetArch::Riscv64,
    _ => RuntimeTargetArch::Other,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn default_config() -> Config {
    toml::from_str(
      r#"
[listeners]
https_bind = "127.0.0.1:8443"

[tls]
cert_chain = "fullchain.pem"
private_key = "privkey.pem"
"#,
    )
    .expect("minimal TOML should resolve configuration defaults")
  }

  #[test]
  fn explicit_legacy_compio_request_keeps_alias_provenance() {
    let mut config = default_config();
    config.runtime.main_runtime = RuntimeMainRuntimeMode::Compio;

    assert_eq!(
      request_from_config(&config).requested_preset,
      RuntimeRequestedPreset::Compio
    );
  }

  #[test]
  fn external_topology_does_not_claim_an_owned_executor() {
    let topology = external_topology(&default_config());

    assert_eq!(topology.resolved_preset, RuntimeResolvedPreset::External);
    assert_eq!(topology.workers.tokio_executor_workers, 0);
    assert_eq!(
      topology.workers.tcp_accept_workers,
      default_config().runtime.accept.workers
    );
    assert_eq!(topology.workers.quic_socket_workers, 0);
    assert_eq!(topology.workers.compio_direct_h1_workers, 0);
    assert_eq!(
      topology.worker_applicability.tokio_executor_workers,
      super::super::topology::RuntimeWorkerApplicability::Inapplicable
    );
    assert_eq!(
      topology.worker_applicability.tcp_accept_workers,
      super::super::topology::RuntimeWorkerApplicability::Applied
    );
  }

  #[test]
  fn external_topology_retains_oxibelt_accept_and_quic_fan_out() {
    let mut config = default_config();
    config.listeners.http3 = true;
    config.runtime.accept.workers = 3;
    config.quic.socket.workers = 2;

    let topology = external_topology(&config);

    assert_eq!(topology.workers.tcp_accept_workers, 3);
    assert_eq!(topology.workers.quic_socket_workers, 2);
    assert_eq!(
      topology.worker_applicability.quic_socket_workers,
      super::super::topology::RuntimeWorkerApplicability::Applied
    );
    assert_eq!(
      topology.worker_applicability.compio_direct_h1_workers,
      super::super::topology::RuntimeWorkerApplicability::Inapplicable
    );
  }
}

//! Configuration adapters for the sole supported Tokio/Hyper topology.
use super::topology::{
  RuntimeDirectH1Requested, RuntimeRequestedPreset, RuntimeTargetArch, RuntimeTargetOs,
  RuntimeTopologyCapabilities, RuntimeTopologyPolicy, RuntimeTopologyRequest,
  RuntimeTopologySnapshot, RuntimeWorkerAllocations,
};
use crate::config::Config;
pub fn request_from_config(config: &Config) -> RuntimeTopologyRequest {
  RuntimeTopologyRequest {
    requested_preset: RuntimeRequestedPreset::TokioHyper,
    policy: RuntimeTopologyPolicy::RequireExact,
    direct_h1: RuntimeDirectH1Requested::TokioHyper,
    http3_enabled: config.listeners.http3,
    workers: RuntimeWorkerAllocations {
      tokio_executor_workers: config.runtime.workers.tokio,
      tcp_accept_workers: config.runtime.accept.workers,
      quic_socket_workers: config.quic.socket.workers,
      tokio_blocking_worker_limit: None,
    },
  }
}
pub fn available_capabilities() -> RuntimeTopologyCapabilities {
  RuntimeTopologyCapabilities::available(target_os(), target_arch())
}
pub fn capabilities_for_active(topology: &RuntimeTopologySnapshot) -> RuntimeTopologyCapabilities {
  RuntimeTopologyCapabilities::available(topology.target_os, topology.target_arch)
}
pub fn external_topology(config: &Config) -> RuntimeTopologySnapshot {
  let mut workers = request_from_config(config).workers;
  workers.tokio_executor_workers = 0;
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

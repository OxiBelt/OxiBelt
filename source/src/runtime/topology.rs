//! Typed runtime-topology resolution and fixed observability vocabulary.

use std::fmt;
use std::fmt::Write as _;

use serde::Serialize;

use super::backend::RuntimeBackendSnapshot;

mod worker_applicability;
pub use worker_applicability::{RuntimeWorkerApplicabilities, RuntimeWorkerApplicability};

pub const RUNTIME_TOPOLOGY_SCHEMA_VERSION: u32 = 3;

macro_rules! fixed_enum {
  ($name:ident { $($variant:ident => $label:literal),+ $(,)? }) => {
    #[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
    #[serde(rename_all = "snake_case")]
    pub enum $name { $($variant),+ }

    impl $name {
      pub const fn as_str(self) -> &'static str {
        match self { $(Self::$variant => $label),+ }
      }
    }
  };
}

fixed_enum!(RuntimeRequestedPreset {
  TokioHyper => "tokio_hyper", External => "external"
});
fixed_enum!(RuntimeResolvedPreset {
  TokioHyper => "tokio_hyper", External => "external"
});
fixed_enum!(RuntimeTopologyPolicy {
  RequireExact => "require_exact",
  ExternallyManaged => "externally_managed"
});
fixed_enum!(RuntimeTopologyOutcome {
  Exact => "exact", FeatureDisabled => "feature_disabled",
  Rejected => "rejected", External => "external"
});
fixed_enum!(RuntimeTopologyReason {
  None => "none", ExplicitlyDisabled => "explicitly_disabled",
  UnsupportedOperatingSystem => "unsupported_operating_system",
  UnsupportedArchitecture => "unsupported_architecture",
  RequiredSocketFeatureUnavailable => "required_socket_feature_unavailable",
  SelectedProtocolFeatureUnavailable => "selected_protocol_feature_unavailable",
  HardeningIncompatible => "hardening_incompatible",
  WorkerAllocationInvalid => "worker_allocation_invalid", ExternallyManaged => "externally_managed"
});
fixed_enum!(RuntimeTargetOs {
  Linux => "linux", Windows => "windows", Macos => "macos", Other => "other",
  External => "external"
});
fixed_enum!(RuntimeTargetArch {
  X86_64 => "x86_64", Aarch64 => "aarch64", Riscv64 => "riscv64", Other => "other",
  External => "external"
});

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeCapability {
  Available,
  Unavailable(RuntimeTopologyReason),
  Disabled(RuntimeTopologyReason),
}

impl RuntimeCapability {
  pub const fn blocking_reason(self) -> Option<RuntimeTopologyReason> {
    match self {
      Self::Available => None,
      Self::Unavailable(reason) | Self::Disabled(reason) => Some(reason),
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
pub struct RuntimeTopologyCapabilities {
  pub target_os: RuntimeTargetOs,
  pub target_arch: RuntimeTargetArch,
  pub platform: RuntimeCapability,
  pub required_socket_features: RuntimeCapability,
  pub selected_protocol_features: RuntimeCapability,
  pub hardening: RuntimeCapability,
}

impl RuntimeTopologyCapabilities {
  pub const fn available(target_os: RuntimeTargetOs, target_arch: RuntimeTargetArch) -> Self {
    Self {
      target_os,
      target_arch,
      platform: RuntimeCapability::Available,
      required_socket_features: RuntimeCapability::Available,
      selected_protocol_features: RuntimeCapability::Available,
      hardening: RuntimeCapability::Available,
    }
  }

  fn required_failure(self) -> Option<RuntimeTopologyReason> {
    [
      self.platform,
      self.required_socket_features,
      self.selected_protocol_features,
      self.hardening,
    ]
    .into_iter()
    .find_map(RuntimeCapability::blocking_reason)
  }
}

fixed_enum!(RuntimeDirectH1Requested {
  TokioHyper => "tokio_hyper", Disabled => "disabled",
  External => "external"
});
fixed_enum!(RuntimeDirectH1Backend {
  TokioHyper => "tokio_hyper", Disabled => "disabled",
  External => "external"
});
fixed_enum!(RuntimeDirectH1Status {
  Active => "active", Disabled => "disabled", External => "external"
});

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
pub struct RuntimeDirectH1Topology {
  pub requested: RuntimeDirectH1Requested,
  pub resolved: RuntimeDirectH1Backend,
  pub status: RuntimeDirectH1Status,
  pub active: bool,
  pub reason: RuntimeTopologyReason,
}

fixed_enum!(RuntimeSubsystemOwner {
  Tokio => "tokio",
  Disabled => "disabled", External => "external"
});
fixed_enum!(RuntimeSubsystem {
  StartupOrchestration => "startup_orchestration", TcpAccept => "tcp_accept",
  GeneralHttp => "general_http", DirectH1Transport => "direct_h1_transport",
  Http3Quic => "http3_quic", DnsDiscovery => "dns_discovery",
  BackgroundControl => "background_control"
});

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
pub struct RuntimeSubsystemOwners {
  pub startup_orchestration: RuntimeSubsystemOwner,
  pub tcp_accept: RuntimeSubsystemOwner,
  pub general_http: RuntimeSubsystemOwner,
  pub direct_h1_transport: RuntimeSubsystemOwner,
  pub http3_quic: RuntimeSubsystemOwner,
  pub dns_discovery: RuntimeSubsystemOwner,
  pub background_control: RuntimeSubsystemOwner,
}

impl RuntimeSubsystemOwners {
  fn assignments(self) -> [(RuntimeSubsystem, RuntimeSubsystemOwner); 7] {
    [
      (
        RuntimeSubsystem::StartupOrchestration,
        self.startup_orchestration,
      ),
      (RuntimeSubsystem::TcpAccept, self.tcp_accept),
      (RuntimeSubsystem::GeneralHttp, self.general_http),
      (
        RuntimeSubsystem::DirectH1Transport,
        self.direct_h1_transport,
      ),
      (RuntimeSubsystem::Http3Quic, self.http3_quic),
      (RuntimeSubsystem::DnsDiscovery, self.dns_discovery),
      (RuntimeSubsystem::BackgroundControl, self.background_control),
    ]
  }
}

fixed_enum!(RuntimeWorkerPool {
  TokioExecutor => "tokio_executor", TcpAccept => "tcp_accept", QuicSocket => "quic_socket"
});

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize)]
pub struct RuntimeWorkerAllocations {
  pub tokio_executor_workers: usize,
  pub tcp_accept_workers: usize,
  pub quic_socket_workers: usize,
  pub tokio_blocking_worker_limit: Option<usize>,
}

impl RuntimeWorkerAllocations {
  fn metric_allocations(self) -> [(RuntimeWorkerPool, RuntimeSubsystemOwner, usize); 3] {
    [
      (
        RuntimeWorkerPool::TokioExecutor,
        RuntimeSubsystemOwner::Tokio,
        self.tokio_executor_workers,
      ),
      (
        RuntimeWorkerPool::TcpAccept,
        RuntimeSubsystemOwner::Tokio,
        self.tcp_accept_workers,
      ),
      (
        RuntimeWorkerPool::QuicSocket,
        RuntimeSubsystemOwner::Tokio,
        self.quic_socket_workers,
      ),
    ]
  }
}

fixed_enum!(RuntimeBlockingStrategy {
  TokioManagedPool => "tokio_managed_pool",
  Disabled => "disabled", External => "external"
});

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
pub struct RuntimeBlockingWorkerStrategy {
  pub strategy: RuntimeBlockingStrategy,
  pub tokio_worker_limit: Option<usize>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
pub struct RuntimeTopologyRequest {
  pub requested_preset: RuntimeRequestedPreset,
  pub policy: RuntimeTopologyPolicy,
  pub direct_h1: RuntimeDirectH1Requested,
  pub http3_enabled: bool,
  pub workers: RuntimeWorkerAllocations,
}

impl RuntimeTopologyRequest {
  pub const fn external(workers: RuntimeWorkerAllocations) -> Self {
    Self {
      requested_preset: RuntimeRequestedPreset::External,
      policy: RuntimeTopologyPolicy::ExternallyManaged,
      direct_h1: RuntimeDirectH1Requested::External,
      http3_enabled: false,
      workers,
    }
  }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct RuntimeTopologySnapshot {
  pub schema_version: u32,
  pub requested_preset: RuntimeRequestedPreset,
  pub resolved_preset: RuntimeResolvedPreset,
  pub policy: RuntimeTopologyPolicy,
  pub outcome: RuntimeTopologyOutcome,
  pub reason: RuntimeTopologyReason,
  pub target_os: RuntimeTargetOs,
  pub target_arch: RuntimeTargetArch,
  pub subsystems: RuntimeSubsystemOwners,
  pub workers: RuntimeWorkerAllocations,
  pub worker_applicability: RuntimeWorkerApplicabilities,
  pub blocking: RuntimeBlockingWorkerStrategy,
  pub direct_h1: RuntimeDirectH1Topology,
}

impl RuntimeTopologySnapshot {
  pub fn external() -> Self {
    Self::external_with_workers(RuntimeWorkerAllocations::default())
  }

  pub fn external_with_workers(workers: RuntimeWorkerAllocations) -> Self {
    Self {
      schema_version: RUNTIME_TOPOLOGY_SCHEMA_VERSION,
      requested_preset: RuntimeRequestedPreset::External,
      resolved_preset: RuntimeResolvedPreset::External,
      policy: RuntimeTopologyPolicy::ExternallyManaged,
      outcome: RuntimeTopologyOutcome::External,
      reason: RuntimeTopologyReason::ExternallyManaged,
      target_os: RuntimeTargetOs::External,
      target_arch: RuntimeTargetArch::External,
      subsystems: RuntimeSubsystemOwners {
        startup_orchestration: RuntimeSubsystemOwner::External,
        tcp_accept: RuntimeSubsystemOwner::External,
        general_http: RuntimeSubsystemOwner::External,
        direct_h1_transport: RuntimeSubsystemOwner::External,
        http3_quic: RuntimeSubsystemOwner::External,
        dns_discovery: RuntimeSubsystemOwner::External,
        background_control: RuntimeSubsystemOwner::External,
      },
      workers,
      worker_applicability: RuntimeWorkerApplicabilities::embedded(),
      blocking: RuntimeBlockingWorkerStrategy {
        strategy: RuntimeBlockingStrategy::External,
        tokio_worker_limit: workers.tokio_blocking_worker_limit,
      },
      direct_h1: RuntimeDirectH1Topology {
        requested: RuntimeDirectH1Requested::External,
        resolved: RuntimeDirectH1Backend::External,
        status: RuntimeDirectH1Status::External,
        active: false,
        reason: RuntimeTopologyReason::ExternallyManaged,
      },
    }
  }

  pub const fn legacy_backend_snapshot(&self) -> RuntimeBackendSnapshot {
    RuntimeBackendSnapshot {
      target_runtime: self.requested_preset.as_str(),
      active_runtime: self.resolved_preset.as_str(),
    }
  }

  pub fn append_prometheus(&self, output: &mut String) {
    output.push_str(
      "# HELP oxibelt_runtime_topology_info Resolved OxiBelt runtime topology.\n\
       # TYPE oxibelt_runtime_topology_info gauge\n",
    );
    let _ = writeln!(
      output,
      "oxibelt_runtime_topology_info{{requested_preset=\"{}\",resolved_preset=\"{}\",outcome=\"{}\",reason=\"{}\"}} 1",
      self.requested_preset.as_str(),
      self.resolved_preset.as_str(),
      self.outcome.as_str(),
      self.reason.as_str(),
    );

    output.push_str(
      "# HELP oxibelt_runtime_subsystem_owner Active executor owner for each runtime subsystem.\n\
       # TYPE oxibelt_runtime_subsystem_owner gauge\n",
    );
    for (subsystem, owner) in self.subsystems.assignments() {
      let _ = writeln!(
        output,
        "oxibelt_runtime_subsystem_owner{{subsystem=\"{}\",owner=\"{}\"}} 1",
        subsystem.as_str(),
        owner.as_str(),
      );
    }

    output.push_str(
      "# HELP oxibelt_runtime_worker_allocation Resolved worker allocation by fixed pool and executor.\n\
       # TYPE oxibelt_runtime_worker_allocation gauge\n",
    );
    for (pool, default_executor, workers) in self.workers.metric_allocations() {
      let applicability = self.worker_applicability.for_pool(pool);
      let executor = if self.resolved_preset == RuntimeResolvedPreset::External {
        RuntimeSubsystemOwner::External
      } else {
        default_executor
      };
      let _ = writeln!(
        output,
        "oxibelt_runtime_worker_allocation{{pool=\"{}\",owner=\"{}\",applicability=\"{}\"}} {workers}",
        pool.as_str(),
        executor.as_str(),
        applicability.as_str(),
      );
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
pub struct RuntimeTopologyRejection {
  pub outcome: RuntimeTopologyOutcome,
  pub requested_preset: RuntimeRequestedPreset,
  pub requested_direct_h1: RuntimeDirectH1Requested,
  pub policy: RuntimeTopologyPolicy,
  pub reason: RuntimeTopologyReason,
}

impl fmt::Display for RuntimeTopologyRejection {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      formatter,
      "runtime topology request {} rejected: {}",
      self.requested_preset.as_str(),
      self.reason.as_str(),
    )
  }
}

impl std::error::Error for RuntimeTopologyRejection {}

pub fn resolve_runtime_topology(
  request: RuntimeTopologyRequest,
  capabilities: RuntimeTopologyCapabilities,
) -> Result<RuntimeTopologySnapshot, RuntimeTopologyRejection> {
  if request.requested_preset == RuntimeRequestedPreset::External {
    return Ok(RuntimeTopologySnapshot::external_with_workers(
      request.workers,
    ));
  }
  if let Some(reason) = capabilities.required_failure() {
    return Err(rejection(request, reason));
  }
  if request.workers.tokio_executor_workers == 0
    || request.workers.tcp_accept_workers == 0
    || (request.http3_enabled && request.workers.quic_socket_workers == 0)
  {
    return Err(rejection(
      request,
      RuntimeTopologyReason::WorkerAllocationInvalid,
    ));
  }
  let mut workers = request.workers;
  if !request.http3_enabled {
    workers.quic_socket_workers = 0;
  }
  let enabled = request.direct_h1 == RuntimeDirectH1Requested::TokioHyper;
  Ok(RuntimeTopologySnapshot {
    schema_version: RUNTIME_TOPOLOGY_SCHEMA_VERSION,
    requested_preset: RuntimeRequestedPreset::TokioHyper,
    resolved_preset: RuntimeResolvedPreset::TokioHyper,
    policy: request.policy,
    outcome: if enabled {
      RuntimeTopologyOutcome::Exact
    } else {
      RuntimeTopologyOutcome::FeatureDisabled
    },
    reason: if enabled {
      RuntimeTopologyReason::None
    } else {
      RuntimeTopologyReason::ExplicitlyDisabled
    },
    target_os: capabilities.target_os,
    target_arch: capabilities.target_arch,
    subsystems: RuntimeSubsystemOwners {
      startup_orchestration: RuntimeSubsystemOwner::Tokio,
      tcp_accept: RuntimeSubsystemOwner::Tokio,
      general_http: RuntimeSubsystemOwner::Tokio,
      direct_h1_transport: if enabled {
        RuntimeSubsystemOwner::Tokio
      } else {
        RuntimeSubsystemOwner::Disabled
      },
      http3_quic: if request.http3_enabled {
        RuntimeSubsystemOwner::Tokio
      } else {
        RuntimeSubsystemOwner::Disabled
      },
      dns_discovery: RuntimeSubsystemOwner::Tokio,
      background_control: RuntimeSubsystemOwner::Tokio,
    },
    workers,
    worker_applicability: RuntimeWorkerApplicabilities::applied(),
    blocking: RuntimeBlockingWorkerStrategy {
      strategy: RuntimeBlockingStrategy::TokioManagedPool,
      tokio_worker_limit: workers.tokio_blocking_worker_limit,
    },
    direct_h1: RuntimeDirectH1Topology {
      requested: request.direct_h1,
      resolved: if enabled {
        RuntimeDirectH1Backend::TokioHyper
      } else {
        RuntimeDirectH1Backend::Disabled
      },
      status: if enabled {
        RuntimeDirectH1Status::Active
      } else {
        RuntimeDirectH1Status::Disabled
      },
      active: enabled,
      reason: if enabled {
        RuntimeTopologyReason::None
      } else {
        RuntimeTopologyReason::ExplicitlyDisabled
      },
    },
  })
}

fn rejection(
  request: RuntimeTopologyRequest,
  reason: RuntimeTopologyReason,
) -> RuntimeTopologyRejection {
  RuntimeTopologyRejection {
    outcome: RuntimeTopologyOutcome::Rejected,
    requested_preset: request.requested_preset,
    requested_direct_h1: request.direct_h1,
    policy: request.policy,
    reason,
  }
}

#[cfg(test)]
mod tests;

use super::*;

#[test]
fn legacy_compio_resolves_to_observable_hybrid_topology() {
  let request = RuntimeTopologyRequest {
    requested_preset: RuntimeRequestedPreset::Compio,
    policy: RuntimeTopologyPolicy::AllowFallback,
    direct_h1: RuntimeDirectH1Requested::Compio,
    http3_enabled: true,
    workers: RuntimeWorkerAllocations {
      tokio_executor_workers: 4,
      tcp_accept_workers: 2,
      quic_socket_workers: 2,
      compio_direct_h1_workers: 3,
      tokio_blocking_worker_limit: None,
    },
  };
  let capabilities = RuntimeTopologyCapabilities::available(
    RuntimeTargetOs::Linux,
    RuntimeTargetArch::X86_64,
    Some(CompioDriverSelection::IoUring),
  );
  let topology = resolve_runtime_topology(request, capabilities)
    .expect("supported Compio topology should resolve");

  assert_eq!(
    topology.resolved_preset,
    RuntimeResolvedPreset::HybridCompio
  );
  assert_eq!(topology.reason, RuntimeTopologyReason::LegacyAlias);
  assert_eq!(
    topology.subsystems.general_http,
    RuntimeSubsystemOwner::Tokio
  );
  assert_eq!(
    topology.subsystems.startup_orchestration,
    RuntimeSubsystemOwner::Compio
  );
  assert_eq!(
    topology.subsystems.direct_h1_transport,
    RuntimeSubsystemOwner::Compio
  );
  assert_eq!(
    topology.compatibility_boundaries.compatibility_island_count,
    1
  );
  assert_eq!(
    topology.legacy_backend_snapshot().active_runtime,
    "hybrid_compio"
  );
  let mut metrics = String::new();
  topology.append_prometheus(&mut metrics);
  assert!(metrics.contains(
    "requested_preset=\"compio\",resolved_preset=\"hybrid_compio\",outcome=\"exact\",reason=\"legacy_alias\""
  ));
}

fn auto_request(policy: RuntimeTopologyPolicy) -> RuntimeTopologyRequest {
  RuntimeTopologyRequest {
    requested_preset: RuntimeRequestedPreset::Auto,
    policy,
    direct_h1: RuntimeDirectH1Requested::Auto,
    http3_enabled: false,
    workers: RuntimeWorkerAllocations {
      tokio_executor_workers: 4,
      tcp_accept_workers: 2,
      quic_socket_workers: 2,
      compio_direct_h1_workers: 3,
      tokio_blocking_worker_limit: None,
    },
  }
}

#[test]
fn auto_allow_fallback_records_compio_capability_failure() {
  let mut capabilities =
    RuntimeTopologyCapabilities::available(RuntimeTargetOs::Linux, RuntimeTargetArch::X86_64, None);
  capabilities.compio_main =
    RuntimeCapability::Unavailable(RuntimeTopologyReason::CompioProbeFailed);

  let topology = resolve_runtime_topology(
    auto_request(RuntimeTopologyPolicy::AllowFallback),
    capabilities,
  )
  .expect("allow_fallback should retain a safe Tokio topology");

  assert_eq!(topology.resolved_preset, RuntimeResolvedPreset::TokioHyper);
  assert_eq!(topology.outcome, RuntimeTopologyOutcome::Fallback);
  assert_eq!(topology.reason, RuntimeTopologyReason::CompioProbeFailed);
  assert_eq!(topology.workers.compio_direct_h1_workers, 0);
}

#[test]
fn auto_require_exact_rejects_compio_capability_failure() {
  let mut capabilities =
    RuntimeTopologyCapabilities::available(RuntimeTargetOs::Linux, RuntimeTargetArch::X86_64, None);
  capabilities.compio_main =
    RuntimeCapability::Unavailable(RuntimeTopologyReason::CompioProbeFailed);

  let rejection = resolve_runtime_topology(
    auto_request(RuntimeTopologyPolicy::RequireExact),
    capabilities,
  )
  .expect_err("require_exact must reject the fallback");

  assert_eq!(rejection.outcome, RuntimeTopologyOutcome::Rejected);
  assert_eq!(rejection.reason, RuntimeTopologyReason::CompioProbeFailed);
}

#[test]
fn invalid_owned_worker_allocation_is_rejected_before_activation() {
  let mut request = auto_request(RuntimeTopologyPolicy::AllowFallback);
  request.direct_h1 = RuntimeDirectH1Requested::Compio;
  request.workers.compio_direct_h1_workers = 0;
  let capabilities = RuntimeTopologyCapabilities::available(
    RuntimeTargetOs::Linux,
    RuntimeTargetArch::X86_64,
    Some(CompioDriverSelection::IoUring),
  );

  let rejection = resolve_runtime_topology(request, capabilities)
    .expect_err("an active Compio direct-H1 fleet requires an owned worker");

  assert_eq!(
    rejection.reason,
    RuntimeTopologyReason::WorkerAllocationInvalid
  );
}

#[test]
fn unsupported_platform_rejection_uses_fixed_capability_reason() {
  let mut capabilities =
    RuntimeTopologyCapabilities::available(RuntimeTargetOs::Other, RuntimeTargetArch::X86_64, None);
  capabilities.platform =
    RuntimeCapability::Unavailable(RuntimeTopologyReason::UnsupportedOperatingSystem);

  let rejection = resolve_runtime_topology(
    auto_request(RuntimeTopologyPolicy::RequireExact),
    capabilities,
  )
  .expect_err("an unsupported platform cannot satisfy exact topology");

  assert_eq!(
    rejection.reason,
    RuntimeTopologyReason::UnsupportedOperatingSystem
  );
}

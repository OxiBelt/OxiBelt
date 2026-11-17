use super::*;

fn request() -> RuntimeTopologyRequest {
  RuntimeTopologyRequest {
    requested_preset: RuntimeRequestedPreset::TokioHyper,
    policy: RuntimeTopologyPolicy::RequireExact,
    direct_h1: RuntimeDirectH1Requested::TokioHyper,
    http3_enabled: true,
    workers: RuntimeWorkerAllocations {
      tokio_executor_workers: 4,
      tcp_accept_workers: 2,
      quic_socket_workers: 2,
      tokio_blocking_worker_limit: None,
    },
  }
}
fn capabilities() -> RuntimeTopologyCapabilities {
  RuntimeTopologyCapabilities::available(RuntimeTargetOs::Linux, RuntimeTargetArch::X86_64)
}

#[test]
fn owned_topology_reports_tokio_ownership_without_compatibility_boundaries() {
  let topology = resolve_runtime_topology(request(), capabilities()).expect("Tokio topology");
  assert_eq!(topology.schema_version, 3);
  assert_eq!(topology.outcome, RuntimeTopologyOutcome::Exact);
  for (_, owner) in topology.subsystems.assignments() {
    assert_eq!(owner, RuntimeSubsystemOwner::Tokio);
  }
  assert_eq!(
    topology.blocking.strategy,
    RuntimeBlockingStrategy::TokioManagedPool
  );
  assert_eq!(
    topology.legacy_backend_snapshot().active_runtime,
    "tokio_hyper"
  );
  let value = serde_json::to_string(&topology).expect("serializable topology");
  assert!(!value.contains("compio"));
  assert!(!value.contains("compatibility"));
  let mut metrics = String::new();
  topology.append_prometheus(&mut metrics);
  assert!(metrics.contains("pool=\"tokio_executor\",owner=\"tokio\",applicability=\"applied\"} 4"));
  assert!(!metrics.contains("compio"));
  assert!(!metrics.contains("compatibility_boundary"));
}

#[test]
fn external_topology_marks_only_caller_owned_executor_settings_inapplicable() {
  let topology = RuntimeTopologySnapshot::external_with_workers(request().workers);
  assert_eq!(
    topology.worker_applicability.tokio_executor_workers,
    RuntimeWorkerApplicability::Inapplicable
  );
  assert_eq!(
    topology.worker_applicability.tcp_accept_workers,
    RuntimeWorkerApplicability::Applied
  );
  assert_eq!(
    topology.subsystems.general_http,
    RuntimeSubsystemOwner::External
  );
  assert_eq!(
    topology.blocking.strategy,
    RuntimeBlockingStrategy::External
  );
}

#[test]
fn invalid_worker_allocations_are_rejected_before_activation() {
  for pool in 0..3 {
    let mut request = request();
    match pool {
      0 => request.workers.tokio_executor_workers = 0,
      1 => request.workers.tcp_accept_workers = 0,
      _ => request.workers.quic_socket_workers = 0,
    }
    assert_eq!(
      resolve_runtime_topology(request, capabilities())
        .unwrap_err()
        .reason,
      RuntimeTopologyReason::WorkerAllocationInvalid
    );
  }
}

#[test]
fn required_capability_failures_are_never_downgraded_to_fallback() {
  for index in 0..4 {
    let mut capabilities = capabilities();
    let reason = match index {
      0 => {
        capabilities.platform =
          RuntimeCapability::Unavailable(RuntimeTopologyReason::UnsupportedOperatingSystem);
        RuntimeTopologyReason::UnsupportedOperatingSystem
      }
      1 => {
        capabilities.required_socket_features =
          RuntimeCapability::Unavailable(RuntimeTopologyReason::RequiredSocketFeatureUnavailable);
        RuntimeTopologyReason::RequiredSocketFeatureUnavailable
      }
      2 => {
        capabilities.selected_protocol_features =
          RuntimeCapability::Unavailable(RuntimeTopologyReason::SelectedProtocolFeatureUnavailable);
        RuntimeTopologyReason::SelectedProtocolFeatureUnavailable
      }
      _ => {
        capabilities.hardening =
          RuntimeCapability::Unavailable(RuntimeTopologyReason::HardeningIncompatible);
        RuntimeTopologyReason::HardeningIncompatible
      }
    };
    assert_eq!(
      resolve_runtime_topology(request(), capabilities)
        .unwrap_err()
        .reason,
      reason
    );
  }
}

#[test]
fn disabled_http3_owns_no_quic_workers() {
  let mut request = request();
  request.http3_enabled = false;
  request.workers.quic_socket_workers = 0;
  let topology = resolve_runtime_topology(request, capabilities()).expect("disabled HTTP/3");
  assert_eq!(
    topology.subsystems.http3_quic,
    RuntimeSubsystemOwner::Disabled
  );
  assert_eq!(topology.workers.quic_socket_workers, 0);
}

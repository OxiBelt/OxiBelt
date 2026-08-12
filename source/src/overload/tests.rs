use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use http::Version;

use super::*;

fn sample(memory_ratio: Option<f64>) -> PressureSample {
  PressureSample {
    memory_ratio,
    fd_ratio: Some(0.1),
    cpu_ratio: Some(0.1),
    event_loop_lag_ms: 0,
    work: [0; WORK_KIND_COUNT],
  }
}

#[test]
fn soft_requires_two_samples_and_hard_is_immediate() {
  let config = OverloadConfig {
    enabled: true,
    ..Default::default()
  };
  let runtime = OverloadRuntime::new(&config);
  let lifecycle = LifecycleState::default();
  runtime.apply_pressure_sample(sample(Some(0.8)), &lifecycle);
  assert_eq!(runtime.state(), OverloadState::Normal);
  runtime.apply_pressure_sample(sample(Some(0.8)), &lifecycle);
  assert_eq!(runtime.state(), OverloadState::Soft);
  runtime.apply_pressure_sample(sample(Some(0.95)), &lifecycle);
  assert_eq!(runtime.state(), OverloadState::Hard);
  assert!(lifecycle.is_draining());
}

#[test]
fn cgroup_usage_above_the_hard_ratio_enters_hard_overload_when_rss_is_low() {
  let runtime = OverloadRuntime::new(&OverloadConfig {
    enabled: true,
    ..Default::default()
  });
  let lifecycle = LifecycleState::default();

  runtime.apply_process_sample(
    ProcessSample {
      rss_bytes: 100,
      memory_current_bytes: 950,
      memory_limit_bytes: Some(1_000),
      fd_used: 1,
      fd_limit: 1_000,
      cpu_usage_usec: 0,
      cpu_capacity: 1.0,
    },
    Duration::ZERO,
    0,
    &lifecycle,
  );

  assert_eq!(runtime.state(), OverloadState::Hard);
  assert!(lifecycle.is_draining());
}

#[test]
fn leases_release_when_dropped() {
  let runtime = OverloadRuntime::new(&OverloadConfig {
    enabled: true,
    ..Default::default()
  });
  let lease = runtime.lease(WorkKind::CacheFillConcurrency, 2);
  assert_eq!(
    runtime.work[WorkKind::CacheFillConcurrency as usize].load(Ordering::Relaxed),
    2
  );
  drop(lease);
  assert_eq!(
    runtime.work[WorkKind::CacheFillConcurrency as usize].load(Ordering::Relaxed),
    0
  );
}

#[test]
fn hard_request_admission_is_rejected() {
  let runtime = OverloadRuntime::new(&OverloadConfig {
    enabled: true,
    ..Default::default()
  });
  let lifecycle = LifecycleState::default();
  runtime.transition(OverloadState::Hard, Signal::Memory, &lifecycle);
  assert_eq!(
    runtime
      .try_admit_request(Version::HTTP_11)
      .unwrap_err()
      .boundary,
    OverloadBoundary::Request
  );
  assert_eq!(
    runtime
      .try_admit_request(Version::HTTP_2)
      .unwrap_err()
      .boundary,
    OverloadBoundary::Stream
  );
}

#[test]
fn soft_expensive_work_cap_bounds_inspection_concurrency() {
  let mut config = OverloadConfig {
    enabled: true,
    ..Default::default()
  };
  config.actions.soft.waf_body_inspection_concurrency_cap = 1;
  let runtime = OverloadRuntime::new(&config);
  runtime.transition(
    OverloadState::Soft,
    Signal::Memory,
    &LifecycleState::default(),
  );
  let first = runtime
    .try_admit_expensive(WorkKind::WafBodyInspectionConcurrency)
    .expect("first inspection should fit within the configured cap");
  assert!(
    runtime
      .try_admit_expensive(WorkKind::WafBodyInspectionConcurrency)
      .is_none(),
    "second inspection should be rejected instead of queued"
  );
  drop(first);
  assert!(
    runtime
      .try_admit_expensive(WorkKind::WafBodyInspectionConcurrency)
      .is_some(),
    "dropping the lease must make capacity available again"
  );
}

#[test]
fn recovery_requires_the_configured_hysteresis_window() {
  let runtime = OverloadRuntime::new(&OverloadConfig {
    enabled: true,
    recovery_samples: 2,
    ..Default::default()
  });
  let lifecycle = LifecycleState::default();
  runtime.apply_pressure_sample(sample(Some(0.95)), &lifecycle);
  assert_eq!(runtime.state(), OverloadState::Hard);
  runtime.apply_pressure_sample(sample(Some(0.1)), &lifecycle);
  assert_eq!(runtime.state(), OverloadState::Hard);
  runtime.apply_pressure_sample(sample(Some(0.1)), &lifecycle);
  assert_eq!(runtime.state(), OverloadState::Soft);
  runtime.apply_pressure_sample(sample(Some(0.1)), &lifecycle);
  assert_eq!(runtime.state(), OverloadState::Soft);
  runtime.apply_pressure_sample(sample(Some(0.1)), &lifecycle);
  assert_eq!(runtime.state(), OverloadState::Normal);
  assert!(!lifecycle.is_draining());
}

#[test]
fn control_plane_capacity_is_independent_of_public_admission() {
  let runtime = OverloadRuntime::new(&OverloadConfig {
    enabled: true,
    ..Default::default()
  });
  runtime.transition(
    OverloadState::Hard,
    Signal::Memory,
    &LifecycleState::default(),
  );
  let first = runtime
    .try_admit_control_connection(ControlPlane::Metrics)
    .expect("first metrics slot should be available");
  let second = runtime
    .try_admit_control_connection(ControlPlane::Metrics)
    .expect("second metrics slot should be available");
  let third = runtime
    .try_admit_control_connection(ControlPlane::Metrics)
    .expect("third metrics slot should be available");
  let fourth = runtime
    .try_admit_control_connection(ControlPlane::Metrics)
    .expect("fourth metrics slot should be available");
  assert!(
    runtime
      .try_admit_control_connection(ControlPlane::Metrics)
      .is_none(),
    "metrics reserve must be bounded"
  );
  drop(first);
  assert!(
    runtime
      .try_admit_control_connection(ControlPlane::Metrics)
      .is_some()
  );
  drop(second);
  drop(third);
  drop(fourth);
}

#[test]
fn control_plane_capacity_remains_bounded_when_pressure_sampling_is_disabled() {
  let config = OverloadConfig {
    enabled: false,
    reserved_capacity: crate::config::OverloadReservedCapacity {
      metrics_connections: 1,
      metrics_requests: 1,
      ..Default::default()
    },
    ..Default::default()
  };
  let runtime = OverloadRuntime::new(&config);

  let connection = runtime
    .try_admit_control_connection(ControlPlane::Metrics)
    .expect("the configured metrics connection slot should be available");
  assert!(
    runtime
      .try_admit_control_connection(ControlPlane::Metrics)
      .is_none(),
    "control-plane connections must remain bounded when overload sampling is off"
  );
  let request = runtime
    .try_admit_control_request(ControlPlane::Metrics)
    .expect("the configured metrics request slot should be available");
  assert!(
    runtime
      .try_admit_control_request(ControlPlane::Metrics)
      .is_none(),
    "control-plane requests must remain bounded when overload sampling is off"
  );

  drop(connection);
  drop(request);
  assert!(
    runtime
      .try_admit_control_connection(ControlPlane::Metrics)
      .is_some(),
    "dropping a control connection lease must restore its slot"
  );
}

#[test]
fn probe_failure_uses_a_stale_grace_window_before_hard_overload() {
  let runtime = OverloadRuntime::new(&OverloadConfig {
    enabled: true,
    signal_stale_timeout_ms: 10,
    ..Default::default()
  });
  let lifecycle = LifecycleState::default();
  runtime.record_probe_failure(&lifecycle);
  assert_eq!(runtime.state(), OverloadState::Normal);
  runtime
    .sampling
    .lock()
    .expect("sampling lock")
    .probe_failure_since = Some(Instant::now() - Duration::from_millis(11));
  runtime.record_probe_failure(&lifecycle);
  assert_eq!(runtime.state(), OverloadState::Hard);
}

#[test]
fn prometheus_output_uses_only_fixed_overload_labels() {
  let runtime = OverloadRuntime::new(&OverloadConfig {
    enabled: true,
    ..Default::default()
  });
  let mut output = String::new();
  runtime.append_prometheus(&mut output);
  assert!(output.contains("oxibelt_overload_state{state=\"normal\"} 1"));
  assert!(output.contains("# TYPE oxibelt_overload_active_work gauge\n"));
  assert!(output.contains("oxibelt_overload_active_work{kind=\"active_http_requests\"} 0"));
  let request = runtime
    .try_admit_request(Version::HTTP_11)
    .expect("enabled overload runtime should admit an ordinary request");
  output.clear();
  runtime.append_prometheus(&mut output);
  assert!(output.contains("oxibelt_overload_active_work{kind=\"active_http_requests\"} 1"));
  drop(request);
  assert!(
    output.contains("oxibelt_overload_control_plane_capacity{plane=\"admin\",kind=\"connection\"}")
  );
}

#[test]
fn finite_cgroup_limit_requires_same_hierarchy_usage() {
  let observation = crate::platform_resources::CgroupMemoryObservation {
    current_bytes: None,
    limit_bytes: 1_000,
  };

  let error = super::process::select_memory_values(100, Some(observation), Some(10_000))
    .expect_err("RSS must not be paired with a finite cgroup limit");

  assert!(error.to_string().contains("same-hierarchy usage"));
}

#[test]
fn host_limit_is_paired_with_process_rss_without_a_cgroup_limit() {
  assert_eq!(
    super::process::select_memory_values(100, None, Some(10_000))
      .expect("host fallback should remain valid"),
    (100, Some(10_000))
  );
}

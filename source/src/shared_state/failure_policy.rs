//! Fixed-cardinality post-activation failure policy tracking.
//!
//! Backend construction remains intentionally strict. This registry begins
//! only after a shared-state snapshot is active, then records the bounded
//! feature-level status needed by the request path, health endpoint, support
//! bundle, and Prometheus output.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::config::{BackendFailureMode, SharedStateFailurePolicies};
use crate::metrics::Metrics;

use super::{Backend, now_unix_ms};

const FEATURE_COUNT: usize = 7;

/// The fixed shared-state feature set governed by `[shared_state.failure_policies]`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum SharedStateFeature {
  RateLimits,
  ConnectionLimits,
  PersonProof,
  UpstreamHealth,
  StickySessions,
  Cache,
  Reload,
}

impl SharedStateFeature {
  const ALL: [Self; FEATURE_COUNT] = [
    Self::RateLimits,
    Self::ConnectionLimits,
    Self::PersonProof,
    Self::UpstreamHealth,
    Self::StickySessions,
    Self::Cache,
    Self::Reload,
  ];

  pub(crate) const fn as_str(self) -> &'static str {
    match self {
      Self::RateLimits => "rate_limits",
      Self::ConnectionLimits => "connection_limits",
      Self::PersonProof => "person_proof",
      Self::UpstreamHealth => "upstream_health",
      Self::StickySessions => "sticky_sessions",
      Self::Cache => "cache",
      Self::Reload => "reload",
    }
  }

  const fn index(self) -> usize {
    self as usize
  }
}

/// Sanitized runtime state suitable for bounded diagnostics and support data.
#[derive(Debug, Clone)]
pub(crate) struct BackendFeatureFailureStatus {
  pub(crate) feature: &'static str,
  pub(crate) mode: BackendFailureMode,
  pub(crate) backend: Option<String>,
  pub(crate) kind: Option<&'static str>,
  pub(crate) degraded: bool,
  pub(crate) stale_snapshot_age_seconds: Option<u64>,
}

#[derive(Debug)]
pub(super) struct BackendFailureRegistry {
  entries: [BackendFeatureRuntime; FEATURE_COUNT],
}

#[derive(Debug)]
struct BackendFeatureRuntime {
  feature: SharedStateFeature,
  mode: BackendFailureMode,
  backend: Option<Arc<str>>,
  kind: Option<&'static str>,
  degraded: AtomicBool,
  degraded_since_ms: AtomicU64,
  metrics: Arc<Metrics>,
}

#[derive(Debug, Clone)]
pub(super) struct BackendFailureBinding {
  backend: Option<Arc<str>>,
  kind: Option<&'static str>,
}

impl BackendFailureBinding {
  pub(super) fn from_backend(backend: Option<&Backend>) -> Self {
    let Some(backend) = backend else {
      return Self {
        backend: None,
        kind: None,
      };
    };
    let (backend, kind) = backend.failure_identity();
    Self {
      backend: Some(backend),
      kind: Some(kind),
    }
  }

  #[cfg(test)]
  fn test(backend: &str, kind: &'static str) -> Self {
    Self {
      backend: Some(Arc::from(backend)),
      kind: Some(kind),
    }
  }
}

impl BackendFailureRegistry {
  pub(super) fn new(
    policies: &SharedStateFailurePolicies,
    bindings: [BackendFailureBinding; FEATURE_COUNT],
    metrics: Arc<Metrics>,
  ) -> Self {
    let entries = std::array::from_fn(|index| {
      let feature = SharedStateFeature::ALL[index];
      let mode = mode_for(policies, feature);
      let binding = &bindings[index];
      if let (Some(backend), Some(kind)) = (&binding.backend, binding.kind) {
        metrics.register_backend_failure_feature(
          backend.as_ref(),
          kind,
          feature.as_str(),
          mode.as_str(),
        );
      }
      BackendFeatureRuntime {
        feature,
        mode,
        backend: binding.backend.clone(),
        kind: binding.kind,
        degraded: AtomicBool::new(false),
        degraded_since_ms: AtomicU64::new(0),
        metrics: metrics.clone(),
      }
    });
    Self { entries }
  }

  pub(super) fn mode(&self, feature: SharedStateFeature) -> BackendFailureMode {
    self.entry(feature).mode
  }

  /// Records an operation failure and returns the configured, feature-local
  /// post-activation mode. Callers make their behavior decision after this
  /// point; the registry never retries mutations that may already have
  /// committed remotely.
  pub(super) fn record_failure(&self, feature: SharedStateFeature) -> BackendFailureMode {
    let entry = self.entry(feature);
    let Some((backend, kind)) = entry.identity() else {
      return entry.mode;
    };
    entry.metrics.record_backend_failure_policy(
      backend,
      kind,
      entry.feature.as_str(),
      entry.mode.as_str(),
      "operation_error",
    );
    if !entry.degraded.swap(true, Ordering::AcqRel) {
      entry
        .degraded_since_ms
        .store(now_unix_ms().max(0) as u64, Ordering::Release);
    }
    entry.mode
  }

  pub(super) fn record_success(&self, feature: SharedStateFeature) {
    let entry = self.entry(feature);
    let Some((backend, kind)) = entry.identity() else {
      return;
    };
    if entry.degraded.swap(false, Ordering::AcqRel) {
      entry.degraded_since_ms.store(0, Ordering::Release);
      entry.metrics.record_backend_feature_recovery(
        backend,
        kind,
        entry.feature.as_str(),
        entry.mode.as_str(),
      );
    }
  }

  pub(super) fn record_local_fallback(&self, feature: SharedStateFeature) {
    let entry = self.entry(feature);
    let Some((backend, kind)) = entry.identity() else {
      return;
    };
    entry.metrics.record_backend_local_fallback(
      backend,
      kind,
      entry.feature.as_str(),
      entry.mode.as_str(),
    );
  }

  pub(super) fn record_stale_snapshot(&self, feature: SharedStateFeature) {
    let entry = self.entry(feature);
    let Some((backend, kind)) = entry.identity() else {
      return;
    };
    let age_seconds = entry.stale_snapshot_age_seconds();
    entry.metrics.record_backend_stale_snapshot_age(
      backend,
      kind,
      entry.feature.as_str(),
      entry.mode.as_str(),
      age_seconds,
    );
  }

  pub(super) fn is_degraded(&self) -> bool {
    self
      .entries
      .iter()
      .any(|entry| entry.backend.is_some() && entry.degraded.load(Ordering::Acquire))
  }

  pub(super) fn statuses(&self) -> Vec<BackendFeatureFailureStatus> {
    self
      .entries
      .iter()
      .map(|entry| {
        let degraded = entry.degraded.load(Ordering::Acquire);
        BackendFeatureFailureStatus {
          feature: entry.feature.as_str(),
          mode: entry.mode,
          backend: entry.backend.as_deref().map(str::to_string),
          kind: entry.kind,
          degraded,
          stale_snapshot_age_seconds: (degraded && entry.mode == BackendFailureMode::StaleSnapshot)
            .then(|| entry.stale_snapshot_age_seconds()),
        }
      })
      .collect()
  }

  fn entry(&self, feature: SharedStateFeature) -> &BackendFeatureRuntime {
    &self.entries[feature.index()]
  }
}

impl BackendFeatureRuntime {
  fn identity(&self) -> Option<(&str, &'static str)> {
    self.backend.as_deref().zip(self.kind)
  }

  fn stale_snapshot_age_seconds(&self) -> u64 {
    let since_ms = self.degraded_since_ms.load(Ordering::Acquire);
    if since_ms == 0 {
      return 0;
    }
    let now_ms = now_unix_ms().max(0) as u64;
    now_ms.saturating_sub(since_ms) / 1_000
  }
}

const fn mode_for(
  policies: &SharedStateFailurePolicies,
  feature: SharedStateFeature,
) -> BackendFailureMode {
  match feature {
    SharedStateFeature::RateLimits => policies.rate_limits,
    SharedStateFeature::ConnectionLimits => policies.connection_limits,
    SharedStateFeature::PersonProof => policies.person_proof,
    SharedStateFeature::UpstreamHealth => policies.upstream_health,
    SharedStateFeature::StickySessions => policies.sticky_sessions,
    SharedStateFeature::Cache => policies.cache,
    SharedStateFeature::Reload => policies.reload,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::cache::CacheStats;
  use crate::config::MetricsConfig;
  use crate::tls::TlsServerSessionStorageStats;

  #[test]
  fn failures_and_recovery_export_only_fixed_labels() {
    let metrics = Metrics::new();
    let policies = SharedStateFailurePolicies::default();
    let bindings = std::array::from_fn(|_| BackendFailureBinding::test("redis-main", "redis"));
    let registry = BackendFailureRegistry::new(&policies, bindings, metrics.clone());

    assert_eq!(
      registry.record_failure(SharedStateFeature::RateLimits),
      BackendFailureMode::FailClosed
    );
    registry.record_local_fallback(SharedStateFeature::RateLimits);
    registry.record_success(SharedStateFeature::RateLimits);

    let body = metrics.prometheus(
      &MetricsConfig::default(),
      CacheStats::default(),
      TlsServerSessionStorageStats::default(),
    );
    assert!(body.contains(
      "oxibelt_backend_failure_policy_applied_total{feature=\"rate_limits\",backend=\"redis-main\",kind=\"redis\",mode=\"fail_closed\",failure_kind=\"operation_error\"} 1"
    ));
    assert!(body.contains(
      "oxibelt_backend_feature_recoveries_total{feature=\"rate_limits\",backend=\"redis-main\",kind=\"redis\",mode=\"fail_closed\"} 1"
    ));
  }
}

//! Redacted shared-state policy details for support bundles.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::config::{SharedStateBackendKind, SharedStateConfig};
use crate::state::AppSnapshot;

/// Bounded shared-backend health and policy state. This intentionally omits
/// endpoint URLs and raw backend error strings from the support bundle.
#[derive(Debug, Serialize)]
pub struct BackendFailurePolicySnapshot {
  pub mode: String,
  pub backend: Option<String>,
  pub kind: Option<String>,
  pub degraded: bool,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub stale_snapshot_age_seconds: Option<u64>,
}

pub(super) fn feature_backends(snapshot: &AppSnapshot) -> BTreeMap<String, Option<String>> {
  let shared = &snapshot.config.shared_state;
  let default_backend = default_backend(shared);
  BTreeMap::from([
    (
      "rate_limits".to_string(),
      shared
        .rate_limits_backend
        .clone()
        .or_else(|| default_backend.clone()),
    ),
    (
      "connection_limits".to_string(),
      shared
        .connection_limits_backend
        .clone()
        .or_else(|| default_backend.clone()),
    ),
    (
      "person_proof".to_string(),
      shared
        .person_proof_backend
        .clone()
        .or_else(|| default_backend.clone()),
    ),
    (
      "upstream_health".to_string(),
      shared
        .upstream_health_backend
        .clone()
        .or_else(|| default_backend.clone()),
    ),
    (
      "sticky_sessions".to_string(),
      shared
        .sticky_sessions_backend
        .clone()
        .or_else(|| default_backend.clone()),
    ),
    (
      "cache".to_string(),
      shared
        .cache_backend
        .clone()
        .or_else(|| default_backend.clone()),
    ),
    (
      "reload".to_string(),
      shared
        .reload_backend
        .clone()
        .or_else(|| default_backend.clone()),
    ),
    (
      "dynamic_policy".to_string(),
      shared
        .dynamic_policy_backend
        .clone()
        .or_else(|| default_backend.clone()),
    ),
  ])
}

pub(super) fn failure_policies(
  snapshot: &AppSnapshot,
) -> BTreeMap<String, BackendFailurePolicySnapshot> {
  let shared = &snapshot.config.shared_state;
  let feature_backends = feature_backends(snapshot);
  let runtime_statuses = snapshot
    .shared_state
    .as_deref()
    .map(|state| state.backend_failure_statuses())
    .unwrap_or_default();
  let mut policies = BTreeMap::new();
  for (feature, mode) in [
    ("rate_limits", shared.failure_policies.rate_limits),
    (
      "connection_limits",
      shared.failure_policies.connection_limits,
    ),
    ("person_proof", shared.failure_policies.person_proof),
    ("upstream_health", shared.failure_policies.upstream_health),
    ("sticky_sessions", shared.failure_policies.sticky_sessions),
    ("cache", shared.failure_policies.cache),
    ("reload", shared.failure_policies.reload),
  ] {
    let runtime = runtime_statuses
      .iter()
      .find(|status| status.feature == feature);
    let backend = runtime
      .and_then(|status| status.backend.clone())
      .or_else(|| feature_backends.get(feature).cloned().flatten());
    let kind = runtime
      .and_then(|status| status.kind.map(str::to_string))
      .or_else(|| backend_kind(shared, backend.as_deref()));
    policies.insert(
      feature.to_string(),
      BackendFailurePolicySnapshot {
        mode: runtime
          .map(|status| status.mode.as_str())
          .unwrap_or_else(|| mode.as_str())
          .to_string(),
        backend,
        kind,
        degraded: runtime.is_some_and(|status| status.degraded),
        stale_snapshot_age_seconds: runtime.and_then(|status| status.stale_snapshot_age_seconds),
      },
    );
  }
  policies
}

fn default_backend(shared: &SharedStateConfig) -> Option<String> {
  shared
    .default_backend
    .clone()
    .or_else(|| shared.backends.first().map(|backend| backend.name.clone()))
}

fn backend_kind(shared: &SharedStateConfig, backend_name: Option<&str>) -> Option<String> {
  let backend_name = backend_name?;
  shared
    .backends
    .iter()
    .find(|backend| backend.name == backend_name)
    .map(|backend| match backend.kind {
      SharedStateBackendKind::Redis => "redis".to_string(),
      SharedStateBackendKind::Postgres => "postgres".to_string(),
    })
}

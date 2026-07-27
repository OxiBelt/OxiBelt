//! Async shared-backend decisions for distributed connection and rate limits.

use std::sync::Arc;

use http::StatusCode;

use crate::config::{BackendFailureMode, LimitMode};
use crate::shared_state::{
  ConnectionScope, SharedConnectionAcquire, SharedRateLimitOutcome, SharedStateFeature,
  UdpFlowConnectionMarker,
};

use super::{
  ConnectionAcquireSpec, ConnectionPermit, LimitState, LocalConnectionRelease, RateLimitBucketSpec,
};

impl LimitState {
  pub(super) async fn acquire_scopes_async(
    self: &Arc<Self>,
    specs: Vec<ConnectionAcquireSpec>,
  ) -> Result<ConnectionPermit, StatusCode> {
    self.acquire_scopes_async_with_marker(specs, None).await
  }

  pub(super) async fn acquire_scopes_async_with_marker(
    self: &Arc<Self>,
    specs: Vec<ConnectionAcquireSpec>,
    udp_marker: Option<&UdpFlowConnectionMarker>,
  ) -> Result<ConnectionPermit, StatusCode> {
    if let Some(shared) = &self.shared_state
      && shared.has_connection_limits()
    {
      let scopes = specs
        .iter()
        .map(|spec| ConnectionScope {
          key: spec.key.as_str(),
          limit: spec.limit,
          status: spec.status,
        })
        .collect::<Vec<_>>();
      let acquired = match udp_marker {
        Some(marker) => {
          shared
            .acquire_connections_with_udp_marker(&scopes, marker)
            .await
        }
        None => shared.acquire_connections(&scopes).await,
      };
      drop(scopes);
      return match acquired {
        Ok(SharedConnectionAcquire::Acquired(lease)) => Ok(ConnectionPermit {
          state: self.clone(),
          local_release: LocalConnectionRelease::default(),
          shared_lease: Some(lease),
        }),
        Ok(SharedConnectionAcquire::Denied(status)) => Err(status),
        Err(error) => {
          let mode = shared.backend_failure_mode(SharedStateFeature::ConnectionLimits);
          tracing::warn!(
            error = %error,
            mode = mode.as_str(),
            "shared connection limit backend failed"
          );
          match mode {
            BackendFailureMode::LocalFallback => {
              shared.record_backend_local_fallback(SharedStateFeature::ConnectionLimits);
              self.acquire_scopes_local(specs)
            }
            BackendFailureMode::FailOpen => Ok(ConnectionPermit {
              state: self.clone(),
              local_release: LocalConnectionRelease::default(),
              shared_lease: None,
            }),
            BackendFailureMode::StaleSnapshot => {
              // A stale connection count cannot safely admit a new lease. Existing
              // lease holders are unaffected; new work remains rejected.
              shared.record_backend_stale_snapshot(SharedStateFeature::ConnectionLimits);
              Err(StatusCode::SERVICE_UNAVAILABLE)
            }
            BackendFailureMode::FailClosed | BackendFailureMode::RejectNewOnly => {
              Err(StatusCode::SERVICE_UNAVAILABLE)
            }
          }
        }
      };
    }
    self.acquire_scopes_local(specs)
  }

  pub(super) async fn check_rate_limit_bucket(
    &self,
    spec: RateLimitBucketSpec<'_>,
  ) -> Option<StatusCode> {
    if let Some(shared) = &self.shared_state
      && shared.has_rate_limits()
    {
      let result = if spec.key.is_empty() {
        shared
          .take_rate_token_bucket(spec.name, spec.rate, spec.burst)
          .await
      } else {
        shared
          .take_rate_token(spec.name, spec.key, spec.rate, spec.burst, spec.max_buckets)
          .await
      };
      match result {
        Ok(SharedRateLimitOutcome::Allowed) => {}
        Ok(SharedRateLimitOutcome::RateLimited | SharedRateLimitOutcome::BucketCapExceeded) => {
          if spec.mode == LimitMode::Enforcing {
            return Some(
              StatusCode::from_u16(spec.status).unwrap_or(StatusCode::TOO_MANY_REQUESTS),
            );
          }
        }
        Err(error) => {
          let mode = shared.backend_failure_mode(SharedStateFeature::RateLimits);
          tracing::warn!(
            error = %error,
            mode = mode.as_str(),
            "shared rate limit backend failed"
          );
          return match mode {
            BackendFailureMode::FailOpen => None,
            BackendFailureMode::LocalFallback => {
              shared.record_backend_local_fallback(SharedStateFeature::RateLimits);
              self.check_rate_limit_bucket_local(spec)
            }
            BackendFailureMode::StaleSnapshot => {
              // Rate decisions are consumptive. Reusing a prior result could
              // double-spend a token, so this mode remains conservative here.
              shared.record_backend_stale_snapshot(SharedStateFeature::RateLimits);
              Some(StatusCode::SERVICE_UNAVAILABLE)
            }
            BackendFailureMode::FailClosed | BackendFailureMode::RejectNewOnly => {
              Some(StatusCode::SERVICE_UNAVAILABLE)
            }
          };
        }
      }
      return None;
    }
    self.check_rate_limit_bucket_local(spec)
  }
}

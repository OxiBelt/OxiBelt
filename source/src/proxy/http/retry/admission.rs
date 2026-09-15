//! Shared upstream-attempt admission used by ordinary and pool retries.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use http::{Request, Response};
use hyper::body::Incoming;

use crate::circuit_breakers::{AdmissionLease, CircuitOutcome, CircuitOutcomeFailure};
use crate::config::UpstreamConfig;
use crate::overload::WorkKind;
use crate::state::{AppSnapshot, UpstreamClientRef};

use super::super::body::ProxyBody;
use super::{EffectiveTimeouts, RetryAdmissionContext, UpstreamFirstByteTimeout};

/// Carries an upstream stream permit from response headers to body completion.
///
/// HTTP response extensions require `Clone`; clones share one take-once lease
/// so an extension copy cannot duplicate an admission slot.
#[derive(Clone)]
pub(crate) struct UpstreamStreamLease(Arc<Mutex<Option<AdmissionLease>>>);

impl UpstreamStreamLease {
  fn new(lease: AdmissionLease) -> Self {
    Self(Arc::new(Mutex::new(Some(lease))))
  }

  fn take(self) -> Option<AdmissionLease> {
    self
      .0
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .take()
  }
}

pub(crate) fn take_stream_lease<B>(response: &mut Response<B>) -> Option<AdmissionLease> {
  response
    .extensions_mut()
    .remove::<UpstreamStreamLease>()
    .and_then(UpstreamStreamLease::take)
}

/// Per-attempt transport data for an HTTP/3 request. Grouping the attempt
/// inputs keeps the common adapter's policy boundary explicit and prevents
/// H3 call sites from growing a separate retry interface.
pub(super) struct H3AttemptContext<'a, 'admission> {
  pub(super) upstream: &'a UpstreamConfig,
  pub(super) timeouts: EffectiveTimeouts,
  pub(super) timeout: Duration,
  pub(super) deadline: Option<Instant>,
  pub(super) state: &'a AppSnapshot,
  pub(super) admission: Option<RetryAdmissionContext<'admission>>,
  pub(super) retry: bool,
}

pub(super) async fn send_attempt(
  client: UpstreamClientRef<'_>,
  request: Request<ProxyBody>,
  timeout: Duration,
  deadline: Option<Instant>,
  state: &AppSnapshot,
  admission: Option<RetryAdmissionContext<'_>>,
  retry: bool,
) -> anyhow::Result<Response<Incoming>> {
  let mut circuit_lease = match admission {
    Some(context) if retry => Some(
      state
        .circuit_breakers
        .admit_retry_attempt(
          context.route_name,
          context.pool_name,
          deadline,
          state.overload.retry_budget_multiplier(),
        )
        .await
        .map_err(anyhow::Error::new)?,
    ),
    Some(context) => Some(
      state
        .circuit_breakers
        .admit_upstream_attempt(context.route_name, context.pool_name, deadline)
        .await
        .map_err(anyhow::Error::new)?,
    ),
    None => None,
  };
  let stream_lease = match admission {
    Some(context) => Some(
      state
        .circuit_breakers
        .admit_upstream_stream(context.route_name, context.pool_name, deadline)
        .await
        .map_err(anyhow::Error::new)?,
    ),
    None => None,
  };
  let request_deadline = deadline
    .unwrap_or_else(|| {
      Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now)
    })
    .min(
      Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now),
    );
  if Instant::now() >= request_deadline {
    if let Some(lease) = circuit_lease.as_mut() {
      lease.record_outcome(CircuitOutcome::Failure(
        CircuitOutcomeFailure::FirstByteTimeout,
      ));
    }
    return Err(UpstreamFirstByteTimeout::new(timeout).into());
  }
  let _retry = retry.then(|| state.overload.lease(WorkKind::RetryConcurrency, 1));
  let _pending = state.overload.lease(WorkKind::PendingUpstreamRequests, 1);
  let result = tokio::select! {
    biased;
    () = tokio::time::sleep_until(request_deadline.into()) => None,
    response = client.request(request) => Some(response),
  };
  let result = match result {
    Some(Ok(mut response)) => {
      if let Some(lease) = circuit_lease.as_mut() {
        lease.record_outcome(CircuitOutcome::Failure(CircuitOutcomeFailure::Status(
          response.status().as_u16(),
        )));
      }
      if let Some(lease) = stream_lease {
        response
          .extensions_mut()
          .insert(UpstreamStreamLease::new(lease));
      }
      Ok(response)
    }
    Some(Err(error)) => {
      if let Some(lease) = circuit_lease.as_mut() {
        lease.record_outcome(CircuitOutcome::Failure(CircuitOutcomeFailure::ConnectError));
      }
      Err(error.into())
    }
    None => {
      if let Some(lease) = circuit_lease.as_mut() {
        lease.record_outcome(CircuitOutcome::Failure(
          CircuitOutcomeFailure::FirstByteTimeout,
        ));
      }
      Err(UpstreamFirstByteTimeout::new(timeout).into())
    }
  };
  // The attempt lease ends at response headers. Logical request and selected
  // server leases independently cover response-body and tunnel lifetimes.
  drop(circuit_lease);
  result
}

/// Protocol-aware H3 attempt with the same circuit and overload accounting as
/// Hyper attempts. H3 owns connection/pending-request accounting internally;
/// this layer owns route admission and the retry-concurrency lease.
pub(super) async fn send_h3_attempt(
  request: Request<ProxyBody>,
  H3AttemptContext {
    upstream,
    timeouts,
    timeout,
    deadline,
    state,
    admission,
    retry,
  }: H3AttemptContext<'_, '_>,
) -> anyhow::Result<Response<ProxyBody>> {
  let mut circuit_lease = match admission {
    Some(context) if retry => Some(
      state
        .circuit_breakers
        .admit_retry_attempt(
          context.route_name,
          context.pool_name,
          deadline,
          state.overload.retry_budget_multiplier(),
        )
        .await
        .map_err(anyhow::Error::new)?,
    ),
    Some(context) => Some(
      state
        .circuit_breakers
        .admit_upstream_attempt(context.route_name, context.pool_name, deadline)
        .await
        .map_err(anyhow::Error::new)?,
    ),
    None => None,
  };
  let stream_lease = match admission {
    Some(context) => Some(
      state
        .circuit_breakers
        .admit_upstream_stream(context.route_name, context.pool_name, deadline)
        .await
        .map_err(anyhow::Error::new)?,
    ),
    None => None,
  };
  let request_deadline = deadline
    .unwrap_or_else(|| {
      Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now)
    })
    .min(
      Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now),
    );
  if Instant::now() >= request_deadline {
    if let Some(lease) = circuit_lease.as_mut() {
      lease.record_outcome(CircuitOutcome::Failure(
        CircuitOutcomeFailure::FirstByteTimeout,
      ));
    }
    return Err(UpstreamFirstByteTimeout::new(timeout).into());
  }
  let _retry = retry.then(|| state.overload.lease(WorkKind::RetryConcurrency, 1));
  let capped_timeouts = timeouts.cap_upstream_to_deadline(request_deadline);
  let result = tokio::select! {
    biased;
    () = tokio::time::sleep_until(request_deadline.into()) => None,
    response = crate::proxy::http3::forward_request(request, upstream, state, capped_timeouts) => Some(response),
  };
  let result = match result {
    Some(Ok(mut response)) => {
      if let Some(lease) = circuit_lease.as_mut() {
        lease.record_outcome(CircuitOutcome::Failure(CircuitOutcomeFailure::Status(
          response.status().as_u16(),
        )));
      }
      if let Some(lease) = stream_lease {
        response
          .extensions_mut()
          .insert(UpstreamStreamLease::new(lease));
      }
      Ok(response)
    }
    Some(Err(error)) => {
      if let Some(lease) = circuit_lease.as_mut() {
        lease.record_outcome(CircuitOutcome::Failure(CircuitOutcomeFailure::ConnectError));
      }
      Err(error)
    }
    None => {
      if let Some(lease) = circuit_lease.as_mut() {
        lease.record_outcome(CircuitOutcome::Failure(
          CircuitOutcomeFailure::FirstByteTimeout,
        ));
      }
      Err(UpstreamFirstByteTimeout::new(timeout).into())
    }
  };
  drop(circuit_lease);
  result
}

#[cfg(test)]
mod tests {
  use super::*;

  use crate::circuit_breakers::{AdmissionRejectionReason, CircuitBreakerRuntime};
  use crate::config::{CapacitySetting, Config};

  fn config() -> Config {
    toml::from_str(include_str!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/config/oxibelt.toml"
    )))
    .expect("example configuration parses")
  }

  #[tokio::test]
  async fn discarded_retry_response_releases_its_stream_admission() {
    let mut config = config();
    config.circuit_breakers.global.max_streams = CapacitySetting::Fixed(2);
    config.circuit_breakers.route_defaults.max_streams = CapacitySetting::Fixed(1);
    config.circuit_breakers.route_defaults.max_pending_requests = CapacitySetting::Fixed(0);
    let route = config.routes[0].name.clone();
    let runtime = CircuitBreakerRuntime::new(&config);
    let lease = runtime
      .admit_upstream_stream(&route, None, None)
      .await
      .expect("first stream is admitted");
    let mut discarded_response = Response::new(());
    discarded_response
      .extensions_mut()
      .insert(UpstreamStreamLease::new(lease));

    assert_eq!(
      runtime
        .admit_upstream_stream(&route, None, None)
        .await
        .expect_err("discarded response must retain stream capacity until dropped")
        .reason,
      AdmissionRejectionReason::ActiveLimit
    );
    drop(discarded_response);
    runtime
      .admit_upstream_stream(&route, None, None)
      .await
      .expect("dropping a discarded retry response releases stream capacity");
  }
}

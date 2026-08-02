//! Shared upstream-attempt admission used by ordinary and pool retries.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use http::{Request, Response};
use hyper::body::Incoming;

use crate::circuit_breakers::{AdmissionLease, CircuitOutcome, CircuitOutcomeFailure};
use crate::overload::WorkKind;
use crate::state::{AppSnapshot, UpstreamClientRef};

use super::super::body::ProxyBody;
use super::{RetryAdmissionContext, UpstreamFirstByteTimeout};

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

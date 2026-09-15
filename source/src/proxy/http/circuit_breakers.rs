//! HTTP response adaptation for bounded circuit-breaker admission.

use std::time::Duration;

use http::{Response, StatusCode};

use crate::circuit_breakers::{AdmissionLease, AdmissionRejection};
use crate::state::AppSnapshot;

use super::body::{self, ProxyBody};
use super::response::text_response;

pub(crate) fn rejection_response(
  snapshot: &AppSnapshot,
  rejection: AdmissionRejection,
) -> Response<ProxyBody> {
  let status = StatusCode::from_u16(snapshot.circuit_breakers.response_status())
    .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
  let mut response = text_response(status, "request admission unavailable");
  response.extensions_mut().insert(rejection);
  let retry_after = retry_after_seconds(rejection.retry_after);
  if let Ok(value) = http::HeaderValue::from_str(&retry_after.to_string()) {
    response
      .headers_mut()
      .insert(http::header::RETRY_AFTER, value);
  }
  response
}

/// Finds an admission error after transport layers have wrapped it.
pub(crate) fn admission_rejection(error: &anyhow::Error) -> Option<AdmissionRejection> {
  error
    .chain()
    .find_map(|source| source.downcast_ref::<AdmissionRejection>().copied())
}

pub(crate) fn with_request_lease(
  response: Response<ProxyBody>,
  lease: AdmissionLease,
) -> Response<ProxyBody> {
  if let Some(exchange) = response
    .extensions()
    .get::<super::incremental_exchange::IncrementalExchange>()
  {
    exchange.retain(lease);
    return response;
  }
  let (parts, body) = response.into_parts();
  Response::from_parts(parts, body::with_drop_guard(body, lease))
}

fn retry_after_seconds(duration: Duration) -> u64 {
  duration
    .as_secs()
    .saturating_add(u64::from(duration.subsec_nanos() != 0))
    .max(1)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::circuit_breakers::AdmissionRejectionReason;

  #[test]
  fn admission_rejection_survives_transport_error_context() {
    let rejection = AdmissionRejection {
      reason: AdmissionRejectionReason::ActiveLimit,
      retry_after: Duration::from_secs(1),
    };
    let error = anyhow::Error::new(rejection).context("upstream connector failed");
    assert_eq!(admission_rejection(&error), Some(rejection));
  }

  #[test]
  fn retry_after_rounds_up_with_a_one_second_minimum() {
    for (duration, expected) in [
      (Duration::ZERO, 1),
      (Duration::from_millis(1), 1),
      (Duration::from_secs(1), 1),
      (Duration::from_millis(1001), 2),
      (Duration::MAX, u64::MAX),
    ] {
      assert_eq!(retry_after_seconds(duration), expected);
    }
  }
}

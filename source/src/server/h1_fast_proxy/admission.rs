//! Circuit-breaker admission for the guarded pre-Hyper HTTP/1 path.

use crate::circuit_breakers::AdmissionLease;
use crate::config::PriorityClass;
use crate::state::AppSnapshot;

/// Acquire the same downstream leases as the ordinary HTTP entrypoint.
///
/// The pre-Hyper path owns the complete response body until it writes it to the socket. It has
/// no IPM evaluation, and routes with client-certificate matchers fall back during preflight, so
/// this path deliberately cannot claim an authenticated public reservation.
pub(super) async fn admit(
  snapshot: &AppSnapshot,
  priority: PriorityClass,
  route: &str,
) -> Option<(AdmissionLease, AdmissionLease)> {
  let global = snapshot
    .circuit_breakers
    .admit_priority_global_request(priority, false, None)
    .await
    .ok()?;
  let route = snapshot
    .circuit_breakers
    .admit_route_scope_request(route, None)
    .await
    .ok()?;
  Some((global, route))
}

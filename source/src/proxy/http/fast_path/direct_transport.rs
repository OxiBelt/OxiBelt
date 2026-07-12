use http::{Request, Response};
use http_body_util::BodyExt;

use crate::config::{HttpVersion, UpstreamConfig};
use crate::overload::WorkKind;
use crate::proxy::http::EffectiveTimeouts;
use crate::proxy::http::body::{self, ProxyBody};
use crate::state::AppSnapshot;

use super::direct_h1::{DirectH1Lease, DirectH1SendResult, try_send_direct_h1};
use super::direct_h2::{DirectH2Lease, DirectH2SendResult, try_send_direct_h2};
use super::request_body::FastPathRequestBodyMode;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectFastPathTransport {
  H1,
  H2,
}

pub(super) fn direct_fast_path_transport(
  upstream_version: HttpVersion,
  direct_candidate: bool,
) -> Option<DirectFastPathTransport> {
  if !direct_candidate {
    return None;
  }
  match upstream_version {
    HttpVersion::H1 => Some(DirectFastPathTransport::H1),
    HttpVersion::H2 => Some(DirectFastPathTransport::H2),
    HttpVersion::H3 => None,
  }
}

pub(super) enum DirectTransportAttempt {
  Sent(anyhow::Result<Response<ProxyBody>>),
  Fallback(Request<ProxyBody>),
}

pub(super) struct DirectTransportOutcome {
  pub(super) attempt: DirectTransportAttempt,
  pub(super) h1_lease: Option<DirectH1Lease>,
  pub(super) h2_lease: Option<DirectH2Lease>,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn attempt_direct_transport(
  transport: Option<DirectFastPathTransport>,
  state: &AppSnapshot,
  upstream_index: usize,
  upstream: &UpstreamConfig,
  upstream_version: HttpVersion,
  request_version: http::Version,
  request_body_mode: FastPathRequestBodyMode,
  retry_policy_enabled: bool,
  outbound: Request<ProxyBody>,
  timeouts: EffectiveTimeouts,
  timing_enabled: bool,
) -> DirectTransportOutcome {
  let _pending = transport
    .is_some()
    .then(|| state.overload.lease(WorkKind::PendingUpstreamRequests, 1));
  let mut h1_lease = None;
  let mut h2_lease = None;
  let attempt = match transport {
    Some(DirectFastPathTransport::H1) => match try_send_direct_h1(
      &state.direct_h1_pools,
      &state.metrics,
      upstream_index,
      upstream,
      upstream_version,
      request_version,
      true,
      request_body_mode,
      retry_policy_enabled,
      !state.overload.retries_disabled() && state.overload.retry_budget_multiplier() >= 1.0,
      Some(state.overload.clone()),
      state.effective_direct_h1_io,
      outbound,
      timeouts,
      state.request_path_features.hot_path_metrics,
      state.request_path_features.hot_path_diagnostic_metrics,
      timing_enabled,
    )
    .await
    {
      DirectH1SendResult::Sent(result) => DirectTransportAttempt::Sent(result.map(|mut direct| {
        h1_lease = direct.take_lease();
        direct.response
      })),
      DirectH1SendResult::Fallback(outbound) => DirectTransportAttempt::Fallback(outbound),
    },
    Some(DirectFastPathTransport::H2) => match try_send_direct_h2(
      &state.direct_h2_pools,
      &state.metrics,
      upstream_index,
      upstream,
      upstream_version,
      request_version,
      true,
      request_body_mode,
      outbound,
      timeouts,
      state.request_path_features.hot_path_metrics,
      timing_enabled,
    )
    .await
    {
      DirectH2SendResult::Sent(result) => DirectTransportAttempt::Sent(result.map(|mut direct| {
        h2_lease = direct.take_lease();
        direct
          .response
          .map(|body| body.map_err(body::boxed_error).boxed())
      })),
      DirectH2SendResult::Fallback(outbound) => DirectTransportAttempt::Fallback(outbound),
    },
    None => DirectTransportAttempt::Fallback(outbound),
  };
  DirectTransportOutcome {
    attempt,
    h1_lease,
    h2_lease,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn dispatches_by_upstream_version() {
    assert_eq!(
      direct_fast_path_transport(HttpVersion::H1, true),
      Some(DirectFastPathTransport::H1)
    );
    assert_eq!(
      direct_fast_path_transport(HttpVersion::H2, true),
      Some(DirectFastPathTransport::H2)
    );
    assert_eq!(direct_fast_path_transport(HttpVersion::H3, true), None);
    assert_eq!(direct_fast_path_transport(HttpVersion::H1, false), None);
    assert_eq!(direct_fast_path_transport(HttpVersion::H2, false), None);
  }
}

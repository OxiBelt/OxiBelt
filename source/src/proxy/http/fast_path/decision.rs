//! Plain proxy fast-path eligibility decisions and low-cardinality telemetry.

use http::{Method, Request};
use hyper::body::Body;

use crate::proxy::http::headers::is_upgrade_request;
use crate::proxy::http::semantics;
use crate::routes::ResolvedRoute;
use crate::state::AppSnapshot;

use super::helpers::plain_proxy_fast_path_supported_route;

pub(super) use crate::metrics::fast_path::labels::FastPathPlainProxyMissReason as PlainProxyFastPathMissReason;

pub(super) fn plain_proxy_fast_path_decision<B>(
  request: &Request<B>,
  state: &AppSnapshot,
  resolved: &ResolvedRoute<'_>,
) -> Result<(), PlainProxyFastPathMissReason>
where
  B: Body,
{
  let plan_enabled = match request.version() {
    http::Version::HTTP_10 | http::Version::HTTP_11 => {
      resolved.execution_plan.fast_path.plain_proxy_h1
    }
    http::Version::HTTP_2 => resolved.execution_plan.fast_path.plain_proxy_h2,
    http::Version::HTTP_3 => resolved.execution_plan.fast_path.plain_proxy_h3,
    _ => return Err(PlainProxyFastPathMissReason::UnsupportedVersion),
  };
  if !plan_enabled {
    return Err(PlainProxyFastPathMissReason::PlanDisabled);
  }
  if !plain_proxy_fast_path_supported_route(state, resolved) {
    return Err(PlainProxyFastPathMissReason::UnsupportedRoute);
  }
  if state.request_path_features.person_proof_api
    && state.waf.has_person_proof_api_path(request.uri().path())
  {
    return Err(PlainProxyFastPathMissReason::PersonProofApi);
  }
  if resolved.execution_plan.features.cache
    && state
      .cache
      .policy_enabled(resolved.route.cache.as_deref(), request.method())
  {
    return Err(PlainProxyFastPathMissReason::CachePolicy);
  }
  if semantics::is_native_grpc_request(request.headers(), &state.config) {
    return Err(PlainProxyFastPathMissReason::NativeGrpc);
  }
  if is_upgrade_request(request) {
    return Err(PlainProxyFastPathMissReason::Upgrade);
  }
  if request.method() == Method::CONNECT {
    return Err(PlainProxyFastPathMissReason::Connect);
  }
  Ok(())
}

pub(super) fn record_plain_proxy_fast_path_decision(
  state: &AppSnapshot,
  version: http::Version,
  miss_reason: Option<PlainProxyFastPathMissReason>,
) {
  if !state.request_path_features.hot_path_metrics {
    return;
  }
  let protocol = plain_proxy_fast_path_protocol(version);
  match miss_reason {
    Some(reason) => {
      state
        .metrics
        .record_plain_proxy_fast_path_decision_miss_id(protocol, reason);
    }
    None => {
      state
        .metrics
        .record_plain_proxy_fast_path_decision_hit_id(protocol);
    }
  }
}

fn plain_proxy_fast_path_protocol(
  version: http::Version,
) -> crate::metrics::fast_path::labels::FastPathMetricProtocol {
  use crate::metrics::fast_path::labels::FastPathMetricProtocol;

  match version {
    http::Version::HTTP_10 | http::Version::HTTP_11 => FastPathMetricProtocol::H1,
    http::Version::HTTP_2 => FastPathMetricProtocol::H2,
    http::Version::HTTP_3 => FastPathMetricProtocol::H3,
    _ => FastPathMetricProtocol::Other,
  }
}

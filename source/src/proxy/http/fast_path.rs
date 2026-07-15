//! Optimized HTTP forwarding paths that are only used when policy permits bypassing slower work.
//! Each shortcut keeps WAF, body, cache, and protocol preconditions explicit.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use http::header::COOKIE;
use http::{HeaderMap, Request, Response, StatusCode};
use hyper::body::Body;
use tracing::warn;

use crate::config::{HttpVersion, ProxyProtocolEgressMode};
use crate::proxy::http::body::{self, BodyTimeoutKind, ProxyBody, error_indicates_body_timeout};
use crate::proxy::http::headers::{ForwardedHeaderCache, ForwardedRequestHeaderValues};
use crate::proxy::http::request::{RebuildRequestOptions, rebuild_request_parts};
use crate::proxy::http::response::{text_response, with_route_security_headers};
use crate::proxy::http::semantics::{self, configured_error_response};
use crate::proxy::http::upstream::select_request_upstream;
use crate::proxy::http::version::select_upstream_http_version;
use crate::proxy::http::{DownstreamListenerBind, SystemAccessLogContext};
use crate::routes::ResolvedRoute;
use crate::state::AppSnapshot;
use crate::telemetry::TraceContext;
use crate::waf::{
  RequestWafDecision, WafProtocol, WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork,
};

use super::flow_helpers::elapsed_ms;
use super::{
  EffectiveRetryPolicy, EffectiveTimeouts, send_one_shot_with_state, send_pool_with_retry,
  send_with_retry,
};

mod compiled;
mod decision;
mod direct;
pub(crate) mod direct_h1;
pub(crate) mod direct_h2;
mod direct_transport;
mod downstream_direct_h1;
mod entry;
mod finalize;
mod handler;
mod helpers;
mod request_body;
mod response_body;
mod response_send_timing;
mod response_waf;
mod small_response;
pub(crate) mod stage_timing;
mod waf;
use self::compiled::select_compiled_proxy_action;
pub(crate) use self::compiled::{CompiledRouteFastPathActions, build_compiled_fast_path_actions};
#[cfg(test)]
use self::decision::PlainProxyFastPathMissReason;
pub(crate) use self::decision::plain_proxy_fast_path_decision;
use self::direct::{direct_http_retry_enabled, select_direct_fast_path_upstream};
pub(crate) use self::direct_h1::DirectH1Pools;
pub(crate) use self::direct_h2::DirectH2Pools;
use self::direct_transport::{
  DirectTransportAttempt, attempt_direct_transport, direct_fast_path_transport,
};
use self::downstream_direct_h1::{
  DownstreamDirectH1Preparation, DownstreamDirectH1RequestBuild, DownstreamDirectH1RequestOptions,
  prepare_downstream_direct_h1_or_generic, try_build_downstream_direct_h1_request,
};
pub(crate) use self::entry::try_handle_plain_proxy;
use self::finalize::{compiled_known_small_noop_static_candidate, finalize_response};
#[cfg(test)]
use self::helpers::fast_path_downstream_response_timeout;
use self::helpers::{
  apply_fast_path_priority_policy, fast_path_metric_protocol, fast_path_outbound_request_body,
  fast_path_request_state_unavailable, fast_path_target_uri, fast_path_unavailable_response,
  fast_path_upstream_timing_required, record_empty_request_body, request_body_definitely_empty,
};
#[cfg(test)]
use self::request_body::fast_path_empty_request_body;
#[cfg(test)]
use self::request_body::fast_path_request_body;
#[cfg(test)]
use self::request_body::fast_path_request_body_is_definitely_empty;
#[cfg(test)]
use self::request_body::fast_path_small_exact_request_body;
use self::request_body::{
  FastPathRequestBody, FastPathRequestBodyMode, fast_path_prepare_nonempty_request_body,
  fast_path_request_body_error_status,
};
#[cfg(test)]
use self::request_body::{
  fast_path_request_body_empty_probe_allowed, fast_path_request_body_with_metrics,
  fast_path_small_request_body_candidate, fast_path_small_request_body_options,
};
use self::response_body::{
  FastPathResponseBody, FastPathResponseBodyOptions, FastPathResponseSemantics,
  fast_path_response_body,
};
use self::stage_timing as timing;

use self::handler::PlainProxyFastPath;

#[cfg(test)]
mod tests;

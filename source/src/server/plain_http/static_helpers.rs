use ::http::HeaderMap;
use ::http::header::CONTENT_LENGTH;
use std::time::Duration;

use super::parse::ParsedPlainRequest;
use crate::config::{ConnectionLimitIdentityMode, HttpListenerMode, StaticFilesSendfileMode};
use crate::proxy::http::static_files::{self, StaticBodyPlan, StaticResponsePlan};
use crate::routes::ResolvedRoute;
use crate::state::AppSnapshot;

pub(super) fn static_fast_path_request_has_body(headers: &HeaderMap) -> bool {
  let mut content_lengths = headers.get_all(CONTENT_LENGTH).iter();
  let Some(value) = content_lengths.next() else {
    return false;
  };
  if content_lengths.next().is_some() {
    return true;
  }
  value
    .to_str()
    .map(|value| value.trim() != "0")
    .unwrap_or(true)
}

pub(super) fn static_body_source_label(body: &StaticBodyPlan) -> &'static str {
  match body {
    StaticBodyPlan::Empty => "empty",
    StaticBodyPlan::Text(_) => "text",
    StaticBodyPlan::Bytes { source, .. } => source.metric_label(),
    StaticBodyPlan::File(_) => "sendfile",
  }
}

pub(super) fn sendfile_disabled_reason(
  snapshot: &AppSnapshot,
  kernel_sendfile_available: bool,
) -> Option<&'static str> {
  let config = &snapshot.config;
  if config.listeners.http_mode != HttpListenerMode::Proxy {
    return Some("plain listener is not proxy mode");
  }
  if config.proxy.static_files.sendfile != StaticFilesSendfileMode::Auto {
    return Some("proxy.static_files.sendfile is not auto");
  }
  if !snapshot.route_table.has_static_sendfile_candidates() {
    return Some("no static sendfile routes are configured");
  }
  if !kernel_sendfile_available {
    return Some("Linux kernel sendfile is not available");
  }
  if snapshot.request_path_features.rate_limits {
    return Some("rate limits are configured");
  }
  if snapshot.request_path_features.dynamic_policy {
    return Some("dynamic policy is enabled");
  }
  if snapshot.request_path_features.compression {
    return Some("compression is enabled");
  }
  if config.limits.connection_limit_identity != ConnectionLimitIdentityMode::ProxyProtocol {
    return Some("Real-IP connection limit identity requires general path");
  }
  None
}

pub(super) fn compiled_static_hot_object_response(
  request: &ParsedPlainRequest,
  request_path: &str,
  snapshot: &AppSnapshot,
  resolved: &ResolvedRoute<'_>,
) -> Option<(StaticResponsePlan, Duration)> {
  let action = snapshot
    .compiled_fast_path_actions(resolved.route_index)
    .and_then(|actions| actions.static_hot_bytes())?;
  debug_assert_eq!(action.route_name(), resolved.route.name.as_str());
  let plan = static_files::cached_hot_object_plan(
    &request.method,
    &request.headers,
    request_path,
    action.path_prefix(),
    action.static_root(),
    action.static_options(),
    &snapshot.static_files,
  )
  .into_hit()?;
  Some((plan, action.response_send_timeout()))
}

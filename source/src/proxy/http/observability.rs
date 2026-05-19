use std::sync::Arc;

use http::Response;

use super::access_log::SystemAccessLogContext;
use super::body::ProxyBody;
use crate::state::AppSnapshot;
use crate::telemetry::{SpanKind, TelemetryStart, TraceAttribute, TraceContext};

pub(super) fn record_request_observability(
  state: &Arc<AppSnapshot>,
  access_log: &SystemAccessLogContext<'_>,
  response: &Response<ProxyBody>,
  trace_context: Option<TraceContext>,
  telemetry_start: TelemetryStart,
) {
  let duration_ms = telemetry_start.elapsed_ms();
  state.metrics.record_http_detail(
    &state.config.metrics,
    access_log.route_name_for_metrics(),
    access_log.upstream_name_for_metrics(),
    access_log.method().as_str(),
    access_log.protocol_label(),
    response.status(),
    duration_ms,
  );
  if let Some(upstream_duration_ms) = access_log.upstream_duration_ms_for_metrics() {
    state.metrics.record_upstream_detail(
      &state.config.metrics,
      access_log.route_name_for_metrics(),
      access_log.upstream_name_for_metrics(),
      access_log.upstream_protocol_for_metrics(),
      access_log.upstream_outcome_for_metrics(),
      upstream_duration_ms,
    );
    state.telemetry.record_child_span(
      trace_context,
      "http.client",
      SpanKind::Client,
      TelemetryStart::elapsed_ago(upstream_duration_ms),
      vec![
        TraceAttribute::string("http.route", access_log.route_name_for_metrics()),
        TraceAttribute::string("upstream.name", access_log.upstream_name_for_metrics()),
        TraceAttribute::string(
          "upstream.protocol",
          access_log.upstream_protocol_for_metrics(),
        ),
        TraceAttribute::string("outcome", access_log.upstream_outcome_for_metrics()),
      ],
    );
  }
  state.telemetry.record_span(
    trace_context,
    "http.server",
    SpanKind::Server,
    telemetry_start,
    vec![
      TraceAttribute::string("http.request.method", access_log.method().as_str()),
      TraceAttribute::string("http.route", access_log.route_name_for_metrics()),
      TraceAttribute::string("network.protocol.name", access_log.protocol_label()),
      TraceAttribute::string(
        "http.response.status_code",
        response.status().as_u16().to_string(),
      ),
      TraceAttribute::string("upstream.name", access_log.upstream_name_for_metrics()),
    ],
  );
}

pub(super) fn record_websocket_session_end(
  state: &Arc<AppSnapshot>,
  route_name: &str,
  upstream_name: &str,
  trace_context: Option<TraceContext>,
  started_at: TelemetryStart,
  outcome: &str,
) {
  state.metrics.record_websocket_session_end(
    &state.config.metrics,
    route_name,
    upstream_name,
    outcome,
    started_at.elapsed_ms(),
  );
  state.telemetry.record_span(
    trace_context,
    "websocket.session",
    SpanKind::Server,
    started_at,
    vec![
      TraceAttribute::string("http.route", route_name),
      TraceAttribute::string("upstream.name", upstream_name),
      TraceAttribute::string("outcome", outcome),
    ],
  );
}

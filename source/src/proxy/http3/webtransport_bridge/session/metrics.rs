//! Metric projection for active WebTransport sessions.

use super::ActiveWebTransportSession;
use crate::telemetry::{SpanKind, TraceAttribute};
use crate::waf::WafStreamClose;

pub(super) fn record_session_end_metrics(
  session: &ActiveWebTransportSession,
  close: Option<&WafStreamClose>,
) {
  let outcome = if close.is_some() { "blocked" } else { "closed" };
  session
    .metrics_state
    .metrics
    .record_webtransport_session_end(
      &session.metrics_state.config.metrics,
      &session.route_name,
      &session.upstream_name,
      outcome,
      session.started_at.elapsed_ms(),
    );
  session.metrics_state.telemetry.record_span(
    session.trace_context,
    "webtransport.session",
    SpanKind::Server,
    session.started_at,
    vec![
      TraceAttribute::string("http.route", &session.route_name),
      TraceAttribute::string("upstream.name", &session.upstream_name),
      TraceAttribute::string("outcome", outcome),
    ],
  );
}

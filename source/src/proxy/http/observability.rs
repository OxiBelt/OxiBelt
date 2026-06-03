use std::sync::Arc;

use http::Response;

use super::access_log::SystemAccessLogContext;
use super::body::ProxyBody;
use crate::state::AppSnapshot;
use crate::telemetry::{SpanKind, TelemetryRuntime, TelemetryStart, TraceAttribute, TraceContext};

pub(super) fn request_observability_start(
  state: &Arc<AppSnapshot>,
  trace_context: Option<TraceContext>,
) -> Option<TelemetryStart> {
  (detailed_metrics_enabled(state) || telemetry_span_enabled(state, trace_context))
    .then(TelemetryRuntime::start)
}

pub(super) fn record_request_observability(
  state: &Arc<AppSnapshot>,
  access_log: &SystemAccessLogContext<'_>,
  response: &Response<ProxyBody>,
  trace_context: Option<TraceContext>,
  telemetry_start: Option<TelemetryStart>,
) {
  if detailed_metrics_enabled(state)
    && let Some(telemetry_start) = telemetry_start
  {
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
    }
  }
  if telemetry_span_enabled(state, trace_context)
    && let Some(telemetry_start) = telemetry_start
  {
    if let Some(upstream_duration_ms) = access_log.upstream_duration_ms_for_metrics() {
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
  if telemetry_span_enabled(state, trace_context) {
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
}

fn telemetry_span_enabled(state: &Arc<AppSnapshot>, trace_context: Option<TraceContext>) -> bool {
  trace_context.is_some() && state.request_path_features.telemetry
}

fn detailed_metrics_enabled(state: &Arc<AppSnapshot>) -> bool {
  state.request_path_features.detailed_metrics
}

#[cfg(test)]
mod tests {
  use http::{Request, StatusCode};

  use super::*;
  use crate::cache::CacheStats;
  use crate::config::{Config, MetricsConfig, MetricsDetail};
  use crate::proxy::http::response::text_response;
  use crate::tls::TlsServerSessionStorageStats;
  use crate::waf::{WafProtocol, WafTransportMetadataInput, WafTransportNetwork};

  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  fn parse_config(raw: &str) -> Config {
    let config: Config = toml::from_str(raw).expect("config should parse");
    config.validate().expect("config should validate");
    config
  }

  async fn state_with_metrics(extra: &str, test_name: &str) -> Arc<AppSnapshot> {
    let temp_dir = common::TempDir::new(test_name);
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), test_name);
    let raw = format!(
      "{}{}",
      common::minimal_config_toml(&cert_path, &key_path),
      extra
    );
    Arc::new(
      AppSnapshot::new(parse_config(&raw))
        .await
        .expect("snapshot should initialize"),
    )
  }

  fn record_observability_once(state: &Arc<AppSnapshot>) {
    let request = Request::builder()
      .method("GET")
      .version(http::Version::HTTP_2)
      .uri("https://example.com/")
      .body(())
      .expect("request should build");
    let mut access_log = SystemAccessLogContext::new(
      &request,
      "127.0.0.1:12345".parse().unwrap(),
      None,
      None,
      WafProtocol::Http,
      WafTransportNetwork::Tcp,
      WafTransportMetadataInput::default(),
      "https",
      true,
      false,
    );
    access_log.set_route_name("app-root");
    access_log.set_upstream("app", "https");
    let response = text_response(StatusCode::OK, "ok");
    record_request_observability(
      state,
      &access_log,
      &response,
      None,
      request_observability_start(state, None),
    );
  }

  fn detailed_scrape(state: &AppSnapshot, mut config: MetricsConfig) -> String {
    config.enabled = true;
    config.detail = MetricsDetail::Detailed;
    state.metrics.prometheus(
      &config,
      CacheStats::default(),
      TlsServerSessionStorageStats::default(),
    )
  }

  #[tokio::test]
  async fn observability_skips_hidden_detailed_metrics_when_metrics_are_disabled() {
    let state = state_with_metrics("", "observability-metrics-disabled").await;

    record_observability_once(&state);
    let body = detailed_scrape(&state, state.config.metrics.clone());

    assert!(!body.contains("oxibelt_http_requests_total"));
  }

  #[tokio::test]
  async fn observability_skips_hidden_detailed_metrics_in_basic_mode() {
    let state = state_with_metrics(
      r#"

[metrics]
enabled = true
detail = "basic"
"#,
      "observability-metrics-basic",
    )
    .await;

    record_observability_once(&state);
    let body = detailed_scrape(&state, state.config.metrics.clone());

    assert!(!body.contains("oxibelt_http_requests_total"));
  }

  #[tokio::test]
  async fn observability_records_detailed_metrics_when_enabled() {
    let state = state_with_metrics(
      r#"

[metrics]
enabled = true
detail = "detailed"
"#,
      "observability-metrics-detailed",
    )
    .await;

    record_observability_once(&state);
    let body = detailed_scrape(&state, state.config.metrics.clone());

    assert!(body.contains("oxibelt_http_requests_total"));
    assert!(body.contains("protocol=\"h2\""));
  }
}

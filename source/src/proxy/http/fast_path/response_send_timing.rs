//! Downstream response-send stage timing wrappers.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Instant;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};

use crate::metrics::Metrics;
use crate::metrics::fast_path::labels::FastPathMetricProtocol;
use crate::proxy::http::body::{self, ProxyBody};
use crate::state::AppSnapshot;

use super::stage_timing as timing;

pub(super) fn maybe_wrap_h2_response_send_timing(
  state: &AppSnapshot,
  request_version: http::Version,
  metric_protocol: FastPathMetricProtocol,
  body: ProxyBody,
) -> ProxyBody {
  if request_version != http::Version::HTTP_2 || !state.request_path_features.stage_timing_metrics {
    return body;
  }
  H2ResponseSendTimingBody::new(body, state.metrics.clone(), metric_protocol).boxed()
}

struct H2ResponseSendTimingBody {
  body: ProxyBody,
  metrics: Arc<Metrics>,
  protocol: FastPathMetricProtocol,
  started_at: Option<Instant>,
  recorded: bool,
}

impl H2ResponseSendTimingBody {
  fn new(body: ProxyBody, metrics: Arc<Metrics>, protocol: FastPathMetricProtocol) -> Self {
    let mut timing = Self {
      body,
      metrics,
      protocol,
      started_at: Some(Instant::now()),
      recorded: false,
    };
    if timing.body.is_end_stream() {
      timing.record(true);
    }
    timing
  }

  fn record(&mut self, success: bool) {
    if self.recorded {
      return;
    }
    self.recorded = true;
    timing::record_metrics_plain_result(
      self.metrics.as_ref(),
      self.protocol,
      timing::STAGE_H2_RESPONSE_SEND,
      success,
      self.started_at.take(),
    );
  }
}

impl Body for H2ResponseSendTimingBody {
  type Data = Bytes;
  type Error = body::BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut TaskContext<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    let poll = Pin::new(&mut self.body).poll_frame(cx);
    let success = match &poll {
      Poll::Ready(Some(Ok(_))) | Poll::Ready(None) => Some(true),
      Poll::Ready(Some(Err(_))) => Some(false),
      Poll::Pending => None,
    };
    if let Some(success) = success {
      self.record(success);
    }
    poll
  }

  fn is_end_stream(&self) -> bool {
    self.body.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    self.body.size_hint()
  }
}

#[cfg(test)]
mod tests {
  use bytes::Bytes;
  use http_body_util::{BodyExt, Full};

  use crate::config::Config;
  use crate::metrics::fast_path::labels::FastPathMetricProtocol;
  use crate::proxy::http::body;
  use crate::state::AppSnapshot;

  use super::*;

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

  async fn h2_direct_h1_state(extra: &str) -> AppSnapshot {
    let temp_dir = common::TempDir::new("h2-response-send-timing");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "h2-response-send-timing");
    let mut raw = common::minimal_config_toml(&cert_path, &key_path)
      .replace(
        "[compression]\nenabled = true",
        "[compression]\nenabled = false",
      )
      .replace(
        "origin = \"https://app.internal.example\"\nmax_http_version = \"h2\"",
        "origin = \"http://app.internal.example\"\nmax_http_version = \"h1\"",
      );
    raw.push_str(extra);
    AppSnapshot::new(parse_config(&raw))
      .await
      .expect("snapshot should initialize")
  }

  #[tokio::test]
  async fn h2_response_send_timing_records_first_body_poll() {
    let state = h2_direct_h1_state(
      r#"

[metrics]
enabled = true
detail = "detailed"
"#,
    )
    .await;
    let body = Full::new(Bytes::from_static(b"ok"))
      .map_err(|never| -> body::BoxError { match never {} })
      .boxed();
    let body = maybe_wrap_h2_response_send_timing(
      &state,
      http::Version::HTTP_2,
      FastPathMetricProtocol::H2,
      body,
    );

    let _ = body.collect().await.expect("body should collect");
    let metrics = state.metrics.prometheus(
      &state.config.metrics,
      crate::cache::CacheStats::default(),
      crate::tls::TlsServerSessionStorageStats::default(),
    );

    assert!(metrics.contains(
      "oxibelt_http_fast_path_stage_observations_total{path=\"plain_proxy\",protocol=\"h2\",stage=\"h2_response_send\",outcome=\"ok\"} 1"
    ));
  }
}

use std::time::Duration;

use bytes::Bytes;
use http::HeaderMap;
use http::header::CONTENT_LENGTH;
use http::{Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};

use super::super::{body, fast_path_downstream_response_timeout, fast_path_response_body};
use crate::config::TrailerMode;
use crate::metrics::Metrics;
use crate::metrics::fast_path::labels::FastPathMetricProtocol;
use crate::proxy::http::DownstreamResponseSendTimeout;
use crate::waf::WafTransportNetwork;

fn response_headers_with_content_length(length: &str) -> HeaderMap {
  let mut headers = HeaderMap::new();
  headers.insert(
    CONTENT_LENGTH,
    http::HeaderValue::from_str(length).expect("content length should be valid"),
  );
  headers
}

fn proxy_body(bytes: &'static [u8]) -> body::ProxyBody {
  Full::new(Bytes::from_static(bytes))
    .map_err(|never| -> body::BoxError { match never {} })
    .boxed()
}

#[tokio::test]
async fn non_h3_fast_path_response_body_inlines_small_known_body_with_materialized_body() {
  for version in [http::Version::HTTP_11, http::Version::HTTP_2] {
    let body =
      Full::new(Bytes::from_static(b"ok")).map_err(|never| -> body::BoxError { match never {} });

    let prepared = match fast_path_response_body(
      &response_headers_with_content_length("2"),
      body,
      Duration::from_secs(1),
      TrailerMode::Drop,
      version,
      None,
    )
    .await
    {
      Ok(prepared) => prepared,
      Err(error) => panic!("unexpected response status {}", error.response.status()),
    };

    assert!(prepared.inlined_known_small_body.is_none());
    assert!(prepared.known_small_response_body);
    assert!(prepared.known_no_trailers);
    assert!(prepared.trailers_handled);
    assert_eq!(prepared.disposition, "inlined");
    assert_eq!(prepared.reason, "known_small");
    let bytes = prepared
      .body
      .collect()
      .await
      .expect("materialized body should collect")
      .to_bytes();
    assert_eq!(bytes, Bytes::from_static(b"ok"));
  }
}

#[tokio::test]
async fn h3_fast_path_response_body_inlines_small_known_body_without_materialized_body() {
  let body =
    Full::new(Bytes::from_static(b"ok")).map_err(|never| -> body::BoxError { match never {} });

  let prepared = match fast_path_response_body(
    &response_headers_with_content_length("2"),
    body,
    Duration::from_secs(1),
    TrailerMode::Drop,
    http::Version::HTTP_3,
    None,
  )
  .await
  {
    Ok(prepared) => prepared,
    Err(error) => panic!("unexpected response status {}", error.response.status()),
  };

  let inlined = prepared
    .inlined_known_small_body
    .expect("H3 response should keep inlined small body metadata");
  assert!(prepared.known_small_response_body);
  assert!(prepared.known_no_trailers);
  assert_eq!(prepared.disposition, "inlined");
  assert_eq!(prepared.reason, "known_small");
  assert_eq!(inlined.data.as_ref(), b"ok");
  assert!(prepared.trailers_handled);
  let bytes = prepared
    .body
    .collect()
    .await
    .expect("placeholder body should collect")
    .to_bytes();
  assert!(bytes.is_empty());
}

#[tokio::test]
async fn end_stream_fast_path_response_body_skips_timeout_wrapping() {
  let body = Empty::<Bytes>::new().map_err(|never| -> body::BoxError { match never {} });

  let prepared = match fast_path_response_body(
    &HeaderMap::new(),
    body,
    Duration::from_secs(1),
    TrailerMode::Drop,
    http::Version::HTTP_11,
    None,
  )
  .await
  {
    Ok(prepared) => prepared,
    Err(error) => panic!("unexpected response status {}", error.response.status()),
  };

  assert!(prepared.known_small_response_body);
  assert!(prepared.known_no_trailers);
  assert!(prepared.trailers_handled);
  assert!(prepared.inlined_known_small_body.is_none());
  assert_eq!(prepared.disposition, "inlined");
  assert_eq!(prepared.reason, "empty");
  let bytes = prepared
    .body
    .collect()
    .await
    .expect("empty body should collect")
    .to_bytes();
  assert!(bytes.is_empty());
}

#[tokio::test]
async fn unknown_length_fast_path_response_body_keeps_streaming_metadata() {
  let body = Full::new(Bytes::from_static(b"streaming"))
    .map_err(|never| -> body::BoxError { match never {} });

  let prepared = match fast_path_response_body(
    &HeaderMap::new(),
    body,
    Duration::from_secs(1),
    TrailerMode::Drop,
    http::Version::HTTP_11,
    None,
  )
  .await
  {
    Ok(prepared) => prepared,
    Err(error) => panic!("unexpected response status {}", error.response.status()),
  };

  assert!(!prepared.known_small_response_body);
  assert!(!prepared.known_no_trailers);
  assert!(!prepared.trailers_handled);
  assert!(prepared.inlined_known_small_body.is_none());
  assert_eq!(prepared.disposition, "streamed");
  assert_eq!(prepared.reason, "unknown_length");
}

#[tokio::test]
async fn direct_h1_first_frame_timing_records_when_body_is_polled() {
  let body =
    Full::new(Bytes::from_static(b"ok")).map_err(|never| -> body::BoxError { match never {} });
  let metrics = Metrics::new();

  let prepared = match fast_path_response_body(
    &response_headers_with_content_length("2"),
    body,
    Duration::from_secs(1),
    TrailerMode::Drop,
    http::Version::HTTP_11,
    Some((metrics.clone(), FastPathMetricProtocol::H2)),
  )
  .await
  {
    Ok(prepared) => prepared,
    Err(error) => panic!("unexpected response status {}", error.response.status()),
  };

  let bytes = prepared
    .body
    .collect()
    .await
    .expect("materialized body should collect")
    .to_bytes();
  assert_eq!(bytes, Bytes::from_static(b"ok"));
  let body = metrics_prometheus(&metrics);
  assert!(body.contains("stage=\"direct_h1_response_body_first_frame\",outcome=\"ok\"} 1"));
}

#[test]
fn known_small_tcp_fast_path_response_skips_downstream_timeout_metadata() {
  let response = Response::builder()
    .status(StatusCode::OK)
    .body(proxy_body(b"ok"))
    .expect("response should build");

  let response = fast_path_downstream_response_timeout(
    response,
    true,
    Duration::from_millis(1),
    WafTransportNetwork::Tcp,
  );

  assert!(
    response
      .extensions()
      .get::<DownstreamResponseSendTimeout>()
      .is_none()
  );
}

#[tokio::test]
async fn known_small_response_body_reports_trailer_presence() {
  let mut trailers = HeaderMap::new();
  trailers.insert("x-trailer", "kept".parse().unwrap());
  let body = Full::new(Bytes::from_static(b"ok"))
    .with_trailers(std::future::ready(Some(Ok::<_, std::convert::Infallible>(
      trailers,
    ))))
    .map_err(|never| -> body::BoxError { match never {} });

  let prepared = match fast_path_response_body(
    &response_headers_with_content_length("2"),
    body,
    Duration::from_secs(1),
    TrailerMode::Pass,
    http::Version::HTTP_2,
    None,
  )
  .await
  {
    Ok(prepared) => prepared,
    Err(error) => panic!("unexpected response status {}", error.response.status()),
  };

  assert!(prepared.known_small_response_body);
  assert!(!prepared.known_no_trailers);
  assert!(prepared.trailers_handled);
  let collected = prepared
    .body
    .collect()
    .await
    .expect("known-small body with trailers should collect");
  assert_eq!(
    collected
      .trailers()
      .expect("trailers should remain available")["x-trailer"],
    "kept"
  );
  assert_eq!(collected.to_bytes().as_ref(), b"ok");
}

fn metrics_prometheus(metrics: &Metrics) -> String {
  metrics.prometheus(
    &crate::config::MetricsConfig::default(),
    crate::cache::CacheStats::default(),
    crate::tls::TlsServerSessionStorageStats::default(),
  )
}

#[tokio::test]
async fn streaming_tcp_fast_path_response_keeps_downstream_timeout_metadata() {
  let response = Response::builder()
    .status(StatusCode::OK)
    .body(proxy_body(b"streaming"))
    .expect("response should build");

  let response = fast_path_downstream_response_timeout(
    response,
    false,
    Duration::from_millis(1),
    WafTransportNetwork::Tcp,
  );

  assert!(
    response
      .extensions()
      .get::<DownstreamResponseSendTimeout>()
      .is_some()
  );
}

#[test]
fn udp_fast_path_response_keeps_downstream_timeout_metadata() {
  let response = Response::builder()
    .status(StatusCode::OK)
    .body(proxy_body(b"ok"))
    .expect("response should build");

  let response = fast_path_downstream_response_timeout(
    response,
    true,
    Duration::from_millis(1),
    WafTransportNetwork::Udp,
  );

  assert!(
    response
      .extensions()
      .get::<DownstreamResponseSendTimeout>()
      .is_some()
  );
}

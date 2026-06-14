use std::time::Duration;

use bytes::Bytes;
use http::HeaderMap;
use http::header::CONTENT_LENGTH;
use http::{Response, StatusCode};
use http_body_util::{BodyExt, Full};

use super::super::{body, fast_path_downstream_response_timeout, fast_path_response_body};
use crate::config::TrailerMode;
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
    )
    .await
    {
      Ok(prepared) => prepared,
      Err(response) => panic!("unexpected response status {}", response.status()),
    };

    assert!(prepared.inlined_known_small_body.is_none());
    assert!(prepared.known_small_response_body);
    assert!(prepared.trailers_handled);
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
  )
  .await
  {
    Ok(prepared) => prepared,
    Err(response) => panic!("unexpected response status {}", response.status()),
  };

  let inlined = prepared
    .inlined_known_small_body
    .expect("H3 response should keep inlined small body metadata");
  assert!(prepared.known_small_response_body);
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

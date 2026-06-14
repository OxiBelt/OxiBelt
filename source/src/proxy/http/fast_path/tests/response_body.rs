use std::time::Duration;

use bytes::Bytes;
use http::header::CONTENT_LENGTH;
use http::{HeaderMap, Response};
use http_body_util::{BodyExt, Full};

use super::super::{body, fast_path_response_body};
use crate::config::TrailerMode;
use crate::proxy::http::{downstream_response_send_timeout, with_downstream_response_timeout};
use crate::waf::WafTransportNetwork;

fn response_headers_with_content_length(length: &str) -> HeaderMap {
  let mut headers = HeaderMap::new();
  headers.insert(
    CONTENT_LENGTH,
    http::HeaderValue::from_str(length).expect("content length should be valid"),
  );
  headers
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
    assert!(prepared.known_small_body);
    assert!(prepared.trailers_handled);

    let mut response = Response::new(prepared.body);
    if prepared.known_small_body && version != http::Version::HTTP_3 {
      response
        .extensions_mut()
        .insert(body::KnownSmallResponseBody);
    }
    let response =
      with_downstream_response_timeout(response, Duration::from_secs(1), WafTransportNetwork::Tcp);

    assert!(downstream_response_send_timeout(&response).is_none());
    assert!(
      response
        .extensions()
        .get::<body::KnownSmallResponseBody>()
        .is_some()
    );
    let bytes = response
      .into_body()
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
    .clone()
    .expect("H3 response should keep inlined small body metadata");
  assert_eq!(inlined.data.as_ref(), b"ok");
  assert!(prepared.known_small_body);
  assert!(prepared.trailers_handled);

  let mut response = Response::new(prepared.body);
  response.extensions_mut().insert(inlined);
  let response =
    with_downstream_response_timeout(response, Duration::from_secs(1), WafTransportNetwork::Udp);

  assert_eq!(
    downstream_response_send_timeout(&response),
    Some(Duration::from_secs(1))
  );
  assert!(
    response
      .extensions()
      .get::<body::KnownSmallResponseBody>()
      .is_none()
  );
  assert!(
    response
      .extensions()
      .get::<body::InlinedKnownSmallResponseBody>()
      .is_some()
  );
  let bytes = response
    .into_body()
    .collect()
    .await
    .expect("placeholder body should collect")
    .to_bytes();
  assert!(bytes.is_empty());
}

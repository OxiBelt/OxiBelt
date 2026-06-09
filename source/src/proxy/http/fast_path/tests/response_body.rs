use std::time::Duration;

use bytes::Bytes;
use http::HeaderMap;
use http::header::CONTENT_LENGTH;
use http_body_util::{BodyExt, Full};
use hyper::body::Body;

use super::super::{body, fast_path_response_body};
use super::PanicBody;
use crate::config::TrailerMode;

fn response_headers_with_content_length(length: &str) -> HeaderMap {
  let mut headers = HeaderMap::new();
  headers.insert(
    CONTENT_LENGTH,
    http::HeaderValue::from_str(length).expect("content length should be valid"),
  );
  headers
}

#[tokio::test]
async fn non_h3_fast_path_response_body_streams_small_known_body_without_polling() {
  for version in [http::Version::HTTP_11, http::Version::HTTP_2] {
    let prepared = match fast_path_response_body(
      &response_headers_with_content_length("2"),
      PanicBody,
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
    assert!(!prepared.trailers_handled);
    assert_eq!(prepared.body.size_hint().upper(), None);
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

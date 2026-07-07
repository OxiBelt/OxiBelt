use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Full};
use url::Url;

use crate::proxy::http::body::{BoxError, ProxyBody};

use super::*;

#[test]
fn guard_accepts_streaming_post_when_retry_replay_is_disabled() {
  let upstream = upstream("http://backend.internal:18080");
  let request = Request::builder()
    .method(Method::POST)
    .uri("http://backend.internal/perf/post")
    .body(non_empty_body(b"{\"ok\":true}"))
    .unwrap();

  assert_eq!(
    direct_h1_guard_miss(
      &upstream,
      HttpVersion::H1,
      http::Version::HTTP_2,
      true,
      FastPathRequestBodyMode::Streaming,
      false,
      &request,
    ),
    None
  );
}

#[test]
fn guard_rejects_streaming_post_when_retry_replay_is_enabled() {
  let upstream = upstream("http://backend.internal:18080");
  let request = Request::builder()
    .method(Method::POST)
    .uri("http://backend.internal/perf/post")
    .body(non_empty_body(b"{\"ok\":true}"))
    .unwrap();

  assert_eq!(
    direct_h1_guard_miss(
      &upstream,
      HttpVersion::H1,
      http::Version::HTTP_2,
      true,
      FastPathRequestBodyMode::Streaming,
      true,
      &request,
    ),
    Some(FastPathTransportMissReason::RequestBody)
  );
}

#[test]
fn guard_accepts_small_exact_post_when_retry_replay_is_disabled() {
  let upstream = upstream("http://backend.internal:18080");
  let request = Request::builder()
    .method(Method::POST)
    .uri("http://backend.internal/perf/post")
    .body(non_empty_body(b"{\"ok\":true}"))
    .unwrap();

  assert_eq!(
    direct_h1_guard_miss(
      &upstream,
      HttpVersion::H1,
      http::Version::HTTP_2,
      true,
      FastPathRequestBodyMode::SmallExact,
      false,
      &request,
    ),
    None
  );
}

#[test]
fn prepared_request_only_replays_empty_bodies() {
  let origin = DirectH1Origin::from_url(&Url::parse("http://backend.internal:18080").unwrap())
    .expect("origin should be direct-H1 eligible");
  let empty = Request::builder()
    .method(Method::GET)
    .uri("http://backend.internal:18080/perf/h1?body=ok")
    .body(empty_body())
    .unwrap();
  let bodyful = Request::builder()
    .method(Method::POST)
    .uri("http://backend.internal:18080/perf/post")
    .body(non_empty_body(b"{\"ok\":true}"))
    .unwrap();

  assert!(
    PreparedDirectH1Request::from_request(empty, &origin)
      .unwrap()
      .retry_request()
      .is_some()
  );
  assert!(
    PreparedDirectH1Request::from_request(bodyful, &origin)
      .unwrap()
      .retry_request()
      .is_none()
  );
}

fn non_empty_body(bytes: &'static [u8]) -> ProxyBody {
  Full::new(Bytes::from_static(bytes))
    .map_err(|never| -> BoxError { match never {} })
    .boxed()
}

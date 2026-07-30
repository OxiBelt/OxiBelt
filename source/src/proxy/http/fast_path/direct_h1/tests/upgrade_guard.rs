use super::*;

#[test]
fn guard_rejects_upgrade_before_direct_h1_dispatch() {
  let upstream = upstream("http://backend.internal:18080");
  let request = Request::builder()
    .method(Method::GET)
    .uri("http://backend.internal/upgrade")
    .header(CONNECTION, "upgrade")
    .header("upgrade", "websocket")
    .body(empty_body())
    .unwrap();

  assert_eq!(
    direct_h1_guard_miss(
      &upstream,
      HttpVersion::H1,
      http::Version::HTTP_11,
      true,
      FastPathRequestBodyMode::Empty,
      false,
      &request,
    ),
    Some(FastPathTransportMissReason::UnsupportedRequest)
  );
}

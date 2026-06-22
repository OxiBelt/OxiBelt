use super::*;
use http_body_util::{BodyExt, Full};

fn full_test_body(bytes: Bytes) -> ProxyBody {
  Full::new(bytes)
    .map_err(|never| -> crate::proxy::http::body::BoxError { match never {} })
    .boxed()
}

#[test]
fn detects_webtransport_extended_connect() {
  let mut request = Request::builder()
    .method(Method::CONNECT)
    .uri("https://example.com/session")
    .body(())
    .unwrap();
  request.extensions_mut().insert(Protocol::WEB_TRANSPORT);

  assert!(is_webtransport_request(&request));
}

#[test]
fn plain_connect_is_not_webtransport() {
  let request = Request::builder()
    .method(Method::CONNECT)
    .uri("https://example.com/session")
    .body(())
    .unwrap();

  assert!(!is_webtransport_request(&request));
}

#[test]
fn zero_rtt_policy_rejects_non_safe_early_data_methods() {
  let request = Request::builder()
    .method(Method::POST)
    .uri("https://example.com/upload")
    .body(())
    .unwrap();

  assert!(rejects_unsafe_early_data(
    &request,
    crate::config::QuicZeroRttMode::SafeMethods,
    true
  ));
}

#[test]
fn zero_rtt_policy_allows_safe_early_data_methods() {
  for method in [Method::GET, Method::HEAD] {
    let request = Request::builder()
      .method(method)
      .uri("https://example.com/read")
      .body(())
      .unwrap();

    assert!(!rejects_unsafe_early_data(
      &request,
      crate::config::QuicZeroRttMode::SafeMethods,
      true
    ));
  }
}

#[test]
fn zero_rtt_policy_ignores_spoofed_early_data_header_after_handshake() {
  let request = Request::builder()
    .method(Method::POST)
    .uri("https://example.com/upload")
    .header("early-data", "1")
    .body(())
    .unwrap();

  assert!(!rejects_unsafe_early_data(
    &request,
    crate::config::QuicZeroRttMode::SafeMethods,
    false
  ));
}

#[test]
fn zero_rtt_policy_is_disabled_when_zero_rtt_is_off() {
  let request = Request::builder()
    .method(Method::POST)
    .uri("https://example.com/upload")
    .body(())
    .unwrap();

  assert!(!rejects_unsafe_early_data(
    &request,
    crate::config::QuicZeroRttMode::Off,
    true
  ));
}

#[test]
fn h3_accept_normal_close_messages_are_not_warnable() {
  for message in [
    "Remote error: ApplicationClose: H3_NO_ERROR",
    "connection closed before request headers completed",
    "connection closed",
    "graceful shutdown",
  ] {
    assert!(downstream_h3_accept_message_is_normal_close(message));
  }
}

#[test]
fn h3_accept_protocol_errors_remain_warnable() {
  for message in [
    "Local error: Application { code: H3_MESSAGE_ERROR, reason: \"bad frame\" }",
    "Remote error: ApplicationClose: H3_FRAME_UNEXPECTED",
    "Timeout",
  ] {
    assert!(!downstream_h3_accept_message_is_normal_close(message));
  }
}

#[test]
fn h3_known_small_path_requires_marker_and_small_upper_bound() {
  let small = full_test_body(Bytes::from_static(b"ok"));
  assert!(use_h3_known_small_body_path(true, &small));
  assert!(!use_h3_known_small_body_path(false, &small));

  let (_sender, unknown_upper) = crate::proxy::http::body::channel_body(1);
  assert!(!use_h3_known_small_body_path(true, &unknown_upper));

  let large = full_test_body(Bytes::from(vec![0; KNOWN_SMALL_BODY_MAX_BYTES + 1]));
  assert!(!use_h3_known_small_body_path(true, &large));
}

#[test]
fn h3_known_small_plan_selects_compiled_noop_no_trailer_branch() {
  let mut extensions = http::Extensions::new();
  extensions.insert(crate::proxy::http::body::CompiledKnownSmallNoopResponse);
  extensions.insert(InlinedKnownSmallResponseBody::new(
    Bytes::from_static(b"ok"),
    None,
  ));

  match take_h3_known_small_body_plan(&mut extensions) {
    H3KnownSmallBodyPlan::CompiledNoopNoTrailers(data) => {
      assert_eq!(data, Bytes::from_static(b"ok"));
    }
    plan => panic!("expected compiled no-trailer branch, got {plan:?}"),
  }
}

#[test]
fn h3_known_small_plan_keeps_unmarked_inlined_body_on_fallback_branch() {
  let mut extensions = http::Extensions::new();
  extensions.insert(InlinedKnownSmallResponseBody::new(
    Bytes::from_static(b"ok"),
    None,
  ));

  match take_h3_known_small_body_plan(&mut extensions) {
    H3KnownSmallBodyPlan::Inlined(inlined) => {
      let (data, trailers) = inlined.into_parts();
      assert_eq!(data, Bytes::from_static(b"ok"));
      assert!(trailers.is_none());
    }
    plan => panic!("expected generic inlined branch, got {plan:?}"),
  }
}

#[test]
fn h3_known_small_plan_keeps_trailer_body_on_fallback_branch() {
  let mut trailers = http::HeaderMap::new();
  trailers.insert("x-trailer", "kept".parse().unwrap());
  let mut extensions = http::Extensions::new();
  extensions.insert(crate::proxy::http::body::CompiledKnownSmallNoopResponse);
  extensions.insert(InlinedKnownSmallResponseBody::new(
    Bytes::from_static(b"ok"),
    Some(trailers),
  ));

  match take_h3_known_small_body_plan(&mut extensions) {
    H3KnownSmallBodyPlan::Inlined(inlined) => {
      let (data, trailers) = inlined.into_parts();
      assert_eq!(data, Bytes::from_static(b"ok"));
      assert_eq!(
        trailers.expect("trailers should remain available")["x-trailer"],
        "kept"
      );
    }
    plan => panic!("expected generic inlined branch, got {plan:?}"),
  }
}

#[test]
fn h3_known_small_plan_ignores_marker_without_inlined_body() {
  let mut extensions = http::Extensions::new();
  extensions.insert(crate::proxy::http::body::CompiledKnownSmallNoopResponse);

  match take_h3_known_small_body_plan(&mut extensions) {
    H3KnownSmallBodyPlan::None => {}
    plan => panic!("expected no known-small body plan, got {plan:?}"),
  }
}

#[tokio::test]
async fn h3_known_small_collect_rejects_body_over_limit() {
  let body = full_test_body(Bytes::from(vec![0; KNOWN_SMALL_BODY_MAX_BYTES + 1]));
  let error = collect_h3_known_small_body(body)
    .await
    .expect_err("known-small body over the limit should fail closed");

  assert!(
    error
      .to_string()
      .contains("known-small response body exceeded")
  );
}

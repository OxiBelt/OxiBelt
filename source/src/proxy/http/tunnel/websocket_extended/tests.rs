use super::*;

#[test]
fn extended_handshake_has_no_h1_key_or_upgrade_fields() {
  let request = Request::builder()
    .method(Method::CONNECT)
    .version(http::Version::HTTP_2)
    .uri("https://example.test/chat")
    .header("sec-websocket-version", "13")
    .body(())
    .unwrap();
  assert_eq!(validate_downstream(&request, true), Ok(None));
  let mut invalid = request;
  invalid
    .headers_mut()
    .insert("sec-websocket-key", HeaderValue::from_static("abc"));
  assert!(validate_downstream(&invalid, true).is_err());
  invalid.headers_mut().remove("sec-websocket-key");
  invalid
    .headers_mut()
    .append("sec-websocket-version", HeaderValue::from_static("13"));
  assert!(validate_downstream(&invalid, true).is_err());
}

#[test]
fn h1_handshake_accept_matches_rfc_6455_sample() {
  let request = Request::builder()
    .method(Method::GET)
    .version(http::Version::HTTP_11)
    .uri("/chat")
    .header("connection", "Upgrade")
    .header("upgrade", "websocket")
    .header("sec-websocket-version", "13")
    .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
    .body(())
    .unwrap();
  assert_eq!(
    validate_downstream(&request, false),
    Ok(Some("dGhlIHNhbXBsZSBub25jZQ==".to_owned()))
  );
  assert_eq!(
    accept_key("dGhlIHNhbXBsZSBub25jZQ==").unwrap(),
    HeaderValue::from_static("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
  );
}

#[test]
fn invalid_h1_key_header_does_not_modify_outbound_headers() {
  let mut headers = HeaderMap::new();
  headers.insert("x-stays", HeaderValue::from_static("original"));
  let original = headers.clone();
  assert!(matches!(
    prepare_h1_headers(&mut headers, None, "invalid\nkey"),
    Err(H1HeaderError::Key)
  ));
  assert_eq!(headers, original);
}

#[test]
fn upstream_cannot_select_unoffered_websocket_negotiation() {
  let mut selected = HeaderMap::new();
  selected.insert("sec-websocket-protocol", HeaderValue::from_static("other"));
  assert!(!valid_upstream_negotiation(
    &selected,
    Some(&HeaderValue::from_static("chat")),
    None,
    HttpVersion::H2,
    false
  ));
  selected.remove("sec-websocket-protocol");
  selected.insert(
    "sec-websocket-extensions",
    HeaderValue::from_static("permessage-deflate"),
  );
  assert!(!valid_upstream_negotiation(
    &selected,
    None,
    Some(&HeaderValue::from_static("x-webkit-deflate-frame")),
    HttpVersion::H3,
    false
  ));
  selected.remove("sec-websocket-extensions");
  selected.append("sec-websocket-protocol", HeaderValue::from_static("chat"));
  selected.append("sec-websocket-protocol", HeaderValue::from_static("chat"));
  assert!(!valid_upstream_negotiation(
    &selected,
    Some(&HeaderValue::from_static("chat")),
    None,
    HttpVersion::H2,
    false
  ));
}

#[test]
fn translated_handshake_keeps_end_to_end_headers() {
  let mut headers = HeaderMap::new();
  headers.insert(
    http::header::CONNECTION,
    HeaderValue::from_static("Upgrade, x-local"),
  );
  headers.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
  headers.insert("x-local", HeaderValue::from_static("drop"));
  headers.insert("sec-websocket-accept", HeaderValue::from_static("old"));
  headers.append(http::header::SET_COOKIE, HeaderValue::from_static("a=1"));
  headers.append(http::header::SET_COOKIE, HeaderValue::from_static("b=2"));
  headers.insert("x-session", HeaderValue::from_static("keep"));
  let headers = translated_response_headers(headers);
  assert!(!headers.contains_key(http::header::CONNECTION));
  assert!(!headers.contains_key(http::header::UPGRADE));
  assert!(!headers.contains_key("x-local"));
  assert!(!headers.contains_key("sec-websocket-accept"));
  assert_eq!(headers.get_all(http::header::SET_COOKIE).iter().count(), 2);
  assert_eq!(headers["x-session"], "keep");
}

#[test]
fn permessage_deflate_can_negotiate_offered_parameters() {
  assert!(extension_matches_offer(
    "permessage-deflate",
    "permessage-deflate; client_max_window_bits"
  ));
  assert!(extension_matches_offer(
    "permessage-deflate; client_max_window_bits=12; server_no_context_takeover",
    "permessage-deflate; client_max_window_bits"
  ));
  assert!(!extension_matches_offer(
    "permessage-deflate; client_max_window_bits=12",
    "permessage-deflate"
  ));
  assert!(!extension_matches_offer(
    "permessage-deflate; server_max_window_bits=15",
    "permessage-deflate; server_max_window_bits=12"
  ));
  assert!(!extension_matches_offer(
    "permessage-deflate; server_max_window_bits=7",
    "permessage-deflate"
  ));
  assert!(!extension_matches_offer(
    "permessage-deflate",
    "permessage-deflate; server_max_window_bits"
  ));
  assert!(!extension_matches_offer(
    "permessage-deflate; server_no_context_takeover; server_no_context_takeover",
    "permessage-deflate"
  ));
}

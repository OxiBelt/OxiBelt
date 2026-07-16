use super::*;

#[test]
fn response_body_mode_rejects_chunked_with_content_length() {
  let headers = vec![
    (TRANSFER_ENCODING, HeaderValue::from_static("chunked")),
    (CONTENT_LENGTH, HeaderValue::from_static("999")),
  ];

  let error = match response_body_mode(&Method::GET, StatusCode::OK, &headers) {
    Ok(_) => panic!("ambiguous response framing should fail closed"),
    Err(error) => error,
  };

  assert!(
    error
      .to_string()
      .contains("ambiguous upstream response framing"),
    "unexpected error: {error}"
  );
}

#[test]
fn response_body_mode_keeps_pure_chunked_response() -> anyhow::Result<()> {
  let headers = vec![(TRANSFER_ENCODING, HeaderValue::from_static("chunked"))];

  assert!(matches!(
    response_body_mode(&Method::GET, StatusCode::OK, &headers)?,
    ResponseBodyMode::Chunked
  ));
  Ok(())
}

#[test]
fn response_body_mode_keeps_pure_content_length_response() -> anyhow::Result<()> {
  let headers = vec![(CONTENT_LENGTH, HeaderValue::from_static("5"))];

  assert!(matches!(
    response_body_mode(&Method::GET, StatusCode::OK, &headers)?,
    ResponseBodyMode::ContentLength(5)
  ));
  Ok(())
}

#[test]
fn trailer_parser_preserves_http_ows_and_first_colon_semantics() -> anyhow::Result<()> {
  let trailers = parse_trailers(b"X-Trace:\t value:with:colons \t\r\n\r\n")?;

  assert_eq!(
    trailers.get("x-trace"),
    Some(&HeaderValue::from_static("value:with:colons"))
  );
  Ok(())
}

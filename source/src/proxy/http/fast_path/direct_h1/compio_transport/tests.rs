use super::*;
use crate::metrics::Metrics;
use crate::proxy::http::fast_path::direct_h1::response_protocol::ResponseProtocolLimits;
use crate::proxy::http::fast_path::direct_h1::{
  DirectH1UpstreamErrorKind, direct_h1_upstream_error_kind,
};

#[test]
fn serializer_preserves_request_target_and_headers() -> anyhow::Result<()> {
  let request = Request::builder()
    .method(http::Method::HEAD)
    .uri("/ready?probe=1")
    .header(http::header::HOST, "origin.example.test")
    .header("x-test", "yes")
    .body(body::known_small_no_trailers_body(Bytes::new()))?;

  let serialized = serialize_empty_h1_request(&request)?;

  assert_eq!(
    serialized,
    b"HEAD /ready?probe=1 HTTP/1.1\r\nhost: origin.example.test\r\nx-test: yes\r\n\r\n"
  );
  Ok(())
}

#[test]
fn metadata_reads_are_capped_by_active_state() -> anyhow::Result<()> {
  let mut engine =
    ResponseProtocolEngine::new(http::Method::GET, ResponseProtocolLimits::default())?;

  assert_eq!(
    next_read_capacity(&engine, engine.limits().max_response_head_bytes - 1),
    1
  );

  let mut input = BytesMut::from(&b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"[..]);
  assert!(matches!(
    engine.decode(&mut input, false)?,
    ResponseStep::Event(ResponseEvent::FinalHead { .. })
  ));
  assert_eq!(
    next_read_capacity(&engine, engine.limits().max_chunk_size_line_bytes),
    2
  );
  Ok(())
}

#[test]
fn every_protocol_reason_has_a_stable_metric_reason() {
  for reason in [
    ResponseProtocolFailureReason::HeadTooLarge,
    ResponseProtocolFailureReason::TooManyHeaders,
    ResponseProtocolFailureReason::HeaderFieldTooLarge,
    ResponseProtocolFailureReason::TooManyInterimResponses,
    ResponseProtocolFailureReason::InvalidStatusLine,
    ResponseProtocolFailureReason::InvalidHeaderSyntax,
    ResponseProtocolFailureReason::InvalidTransferCodingSequence,
    ResponseProtocolFailureReason::ChunkLineTooLarge,
    ResponseProtocolFailureReason::InvalidChunkSize,
    ResponseProtocolFailureReason::InvalidChunkExtension,
    ResponseProtocolFailureReason::InvalidChunkTerminator,
    ResponseProtocolFailureReason::ChunkExtensionTooLarge,
    ResponseProtocolFailureReason::TrailerBlockTooLarge,
    ResponseProtocolFailureReason::TooManyTrailers,
    ResponseProtocolFailureReason::InvalidTrailerField,
    ResponseProtocolFailureReason::TrailerFieldTooLarge,
    ResponseProtocolFailureReason::UnexpectedEof,
    ResponseProtocolFailureReason::IdleTimeout,
    ResponseProtocolFailureReason::DownstreamCancellation,
    ResponseProtocolFailureReason::UnsupportedUpgrade,
  ] {
    assert!(!metric_reason(reason).as_str().is_empty());
  }
}

#[test]
fn downstream_cancellation_is_classified_in_every_reachable_parser_state() -> anyhow::Result<()> {
  fn engine() -> anyhow::Result<ResponseProtocolEngine> {
    Ok(ResponseProtocolEngine::new(
      http::Method::GET,
      ResponseProtocolLimits::default(),
    )?)
  }

  fn decode_interim(engine: &mut ResponseProtocolEngine) -> anyhow::Result<()> {
    let mut input = BytesMut::from(&b"HTTP/1.1 100 Continue\r\n\r\n"[..]);
    assert!(matches!(
      engine.decode(&mut input, false)?,
      ResponseStep::Event(ResponseEvent::InterimHead { .. })
    ));
    Ok(())
  }

  fn decode_final(
    engine: &mut ResponseProtocolEngine,
    response: &'static [u8],
  ) -> anyhow::Result<BytesMut> {
    let mut input = BytesMut::from(response);
    assert!(matches!(
      engine.decode(&mut input, false)?,
      ResponseStep::Event(ResponseEvent::FinalHead { .. })
    ));
    Ok(input)
  }

  let reading_head = engine()?;

  let mut processing_interim = engine()?;
  decode_interim(&mut processing_interim)?;

  let mut waiting_for_final_head = engine()?;
  decode_interim(&mut waiting_for_final_head)?;
  let mut empty = BytesMut::new();
  assert!(matches!(
    waiting_for_final_head.decode(&mut empty, false)?,
    ResponseStep::NeedInput
  ));

  let mut fixed_length = engine()?;
  let _ = decode_final(
    &mut fixed_length,
    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
  )?;

  let mut chunk_size_line = engine()?;
  let _ = decode_final(
    &mut chunk_size_line,
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
  )?;

  let mut chunk_data = engine()?;
  let mut chunk_data_input = decode_final(
    &mut chunk_data,
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n",
  )?;
  assert!(matches!(
    chunk_data.decode(&mut chunk_data_input, false)?,
    ResponseStep::NeedInput
  ));

  let mut chunk_terminator = engine()?;
  let mut chunk_terminator_input = decode_final(
    &mut chunk_terminator,
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na",
  )?;
  assert!(matches!(
    chunk_terminator.decode(&mut chunk_terminator_input, false)?,
    ResponseStep::Event(ResponseEvent::Body(_))
  ));

  let mut trailers = engine()?;
  let mut trailer_input = decode_final(
    &mut trailers,
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n",
  )?;
  assert!(matches!(
    trailers.decode(&mut trailer_input, false)?,
    ResponseStep::NeedInput
  ));

  let mut close_delimited = engine()?;
  let _ = decode_final(&mut close_delimited, b"HTTP/1.1 200 OK\r\n\r\n")?;

  let metrics = Metrics::new();
  for (expected_state, engine) in [
    ("reading_head", reading_head),
    ("processing_interim", processing_interim),
    ("waiting_for_final_head", waiting_for_final_head),
    ("fixed_length", fixed_length),
    ("chunk_size_line", chunk_size_line),
    ("chunk_data", chunk_data),
    ("chunk_terminator", chunk_terminator),
    ("trailers", trailers),
    ("close_delimited", close_delimited),
  ] {
    assert_eq!(engine.state_label().as_str(), expected_state);
    let error = cancellation_failure(&metrics, FastPathMetricProtocol::H1, &engine);
    assert_eq!(
      direct_h1_upstream_error_kind(&error),
      Some(DirectH1UpstreamErrorKind::DownstreamCancellation),
      "{expected_state}"
    );
    let diagnostic = error.to_string();
    assert!(
      diagnostic.contains("downstream cancellation"),
      "{expected_state}: {diagnostic}"
    );
    assert!(
      diagnostic.contains(expected_state),
      "{expected_state}: {diagnostic}"
    );
  }
  Ok(())
}

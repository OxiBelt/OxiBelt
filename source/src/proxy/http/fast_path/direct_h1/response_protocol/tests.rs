use bytes::BytesMut;
use http::{HeaderValue, Method, StatusCode};

use super::*;

fn decode_all(
  method: Method,
  response: &[u8],
  fragment: usize,
) -> Result<Vec<ResponseEvent>, ResponseProtocolError> {
  decode_all_with_limits(
    method,
    response,
    fragment,
    ResponseProtocolLimits::default(),
  )
}

fn decode_all_with_limits(
  method: Method,
  response: &[u8],
  fragment: usize,
  limits: ResponseProtocolLimits,
) -> Result<Vec<ResponseEvent>, ResponseProtocolError> {
  let mut engine = ResponseProtocolEngine::new(method, limits).unwrap();
  let mut pending = BytesMut::new();
  let mut events = Vec::new();
  for chunk in response.chunks(fragment.max(1)) {
    pending.extend_from_slice(chunk);
    loop {
      match engine.decode(&mut pending, false)? {
        ResponseStep::Event(event) => {
          let complete = matches!(&event, ResponseEvent::Complete);
          events.push(event);
          if complete {
            return Ok(events);
          }
        }
        ResponseStep::NeedInput => break,
      }
    }
  }
  loop {
    match engine.decode(&mut pending, true)? {
      ResponseStep::Event(event) => {
        let complete = matches!(&event, ResponseEvent::Complete);
        events.push(event);
        if complete {
          return Ok(events);
        }
      }
      ResponseStep::NeedInput => panic!("EOF must not need more input before completion"),
    }
  }
}

fn body_bytes(events: &[ResponseEvent]) -> Vec<u8> {
  events
    .iter()
    .filter_map(|event| match event {
      ResponseEvent::Body(bytes) => Some(bytes.as_ref()),
      _ => None,
    })
    .flatten()
    .copied()
    .collect()
}

fn assert_failure(
  response: &[u8],
  limits: ResponseProtocolLimits,
  reason: ResponseProtocolFailureReason,
) {
  let error = decode_all_with_limits(Method::GET, response, 1, limits).unwrap_err();
  assert_eq!(error.reason(), reason);
  let mut engine = ResponseProtocolEngine::new(Method::GET, limits).unwrap();
  let mut input = BytesMut::from(response);
  let first = loop {
    match engine.decode(&mut input, true) {
      Ok(ResponseStep::Event(_)) => continue,
      Ok(ResponseStep::NeedInput) => panic!("EOF failure unexpectedly requested input"),
      Err(error) => break error,
    }
  };
  assert_eq!(first.reason(), reason);
  assert_eq!(engine.decode(&mut input, false).unwrap_err(), first);
  assert_eq!(engine.state(), ResponseState::FailedNonReusable);
}

#[test]
fn defaults_and_all_nine_limits_validate_independently() {
  let defaults = ResponseProtocolLimits::default();
  assert_eq!(defaults.max_response_head_bytes, 65_536);
  assert_eq!(defaults.max_response_header_fields, 128);
  assert_eq!(defaults.max_response_header_field_bytes, 8_192);
  assert_eq!(defaults.max_interim_responses, 8);
  assert_eq!(defaults.max_chunk_size_line_bytes, 8_192);
  assert_eq!(defaults.max_chunk_extension_bytes, 8_192);
  assert_eq!(defaults.max_trailer_block_bytes, 65_536);
  assert_eq!(defaults.max_trailer_fields, 128);
  assert_eq!(defaults.max_trailer_field_bytes, 8_192);

  for limits in [
    ResponseProtocolLimits {
      max_response_head_bytes: 1,
      ..defaults
    },
    ResponseProtocolLimits {
      max_response_header_fields: 1,
      ..defaults
    },
    ResponseProtocolLimits {
      max_response_header_field_bytes: 1,
      ..defaults
    },
    ResponseProtocolLimits {
      max_interim_responses: 1,
      ..defaults
    },
    ResponseProtocolLimits {
      max_chunk_size_line_bytes: 1,
      ..defaults
    },
    ResponseProtocolLimits {
      max_chunk_extension_bytes: 1,
      ..defaults
    },
    ResponseProtocolLimits {
      max_trailer_block_bytes: 1,
      ..defaults
    },
    ResponseProtocolLimits {
      max_trailer_fields: 1,
      ..defaults
    },
    ResponseProtocolLimits {
      max_trailer_field_bytes: 1,
      ..defaults
    },
  ] {
    limits.validate().unwrap();
  }
}

#[test]
fn zero_limits_are_rejected() {
  let defaults = ResponseProtocolLimits::default();
  for limits in [
    ResponseProtocolLimits {
      max_response_head_bytes: 0,
      ..defaults
    },
    ResponseProtocolLimits {
      max_response_header_fields: 0,
      ..defaults
    },
    ResponseProtocolLimits {
      max_response_header_field_bytes: 0,
      ..defaults
    },
    ResponseProtocolLimits {
      max_interim_responses: 0,
      ..defaults
    },
    ResponseProtocolLimits {
      max_chunk_size_line_bytes: 0,
      ..defaults
    },
    ResponseProtocolLimits {
      max_chunk_extension_bytes: 0,
      ..defaults
    },
    ResponseProtocolLimits {
      max_trailer_block_bytes: 0,
      ..defaults
    },
    ResponseProtocolLimits {
      max_trailer_fields: 0,
      ..defaults
    },
    ResponseProtocolLimits {
      max_trailer_field_bytes: 0,
      ..defaults
    },
  ] {
    assert!(limits.validate().is_err());
  }
}

#[test]
fn fixed_length_is_fragmentation_invariant() {
  let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Test: yes\r\n\r\nhello";
  for fragment in 1..=response.len() {
    let events = decode_all(Method::GET, response, fragment).unwrap();
    assert!(matches!(
      events.first(),
      Some(ResponseEvent::FinalHead {
        status: StatusCode::OK,
        body_mode: ResponseBodyMode::ContentLength(5),
        ..
      })
    ));
    assert_eq!(body_bytes(&events), b"hello");
    assert!(matches!(events.last(), Some(ResponseEvent::Complete)));
  }
}

#[test]
fn chunked_response_is_fragmentation_invariant() {
  let response = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;foo=\"bar\"\r\nhello\r\n0\r\nX-Trace: done\r\n\r\n";
  for fragment in 1..=response.len() {
    let events = decode_all(Method::GET, response, fragment).unwrap();
    assert_eq!(body_bytes(&events), b"hello");
    assert!(matches!(
      events.first(),
      Some(ResponseEvent::InterimHead {
        status: StatusCode::CONTINUE,
        ..
      })
    ));
    assert!(events.iter().any(|event| matches!(
      event,
      ResponseEvent::Trailers(headers)
        if headers.get("x-trace") == Some(&HeaderValue::from_static("done"))
    )));
  }
}

#[test]
fn randomized_fragment_schedules_preserve_chunked_result() {
  let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n4;v=x\r\ndefg\r\n0\r\nDigest: ok\r\n\r\n";
  for seed in 1..=32u32 {
    let mut engine =
      ResponseProtocolEngine::new(Method::GET, ResponseProtocolLimits::default()).unwrap();
    let mut input = BytesMut::new();
    let mut body = Vec::new();
    let mut offset = 0;
    let mut random = seed;
    let mut complete = false;
    while offset < response.len() {
      random = random.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
      let take = (1 + (random as usize % 11)).min(response.len() - offset);
      input.extend_from_slice(&response[offset..offset + take]);
      offset += take;
      loop {
        match engine.decode(&mut input, false).unwrap() {
          ResponseStep::Event(ResponseEvent::Body(bytes)) => body.extend_from_slice(&bytes),
          ResponseStep::Event(ResponseEvent::Complete) => {
            complete = true;
            break;
          }
          ResponseStep::Event(_) => {}
          ResponseStep::NeedInput => break,
        }
      }
    }
    if !complete {
      loop {
        match engine.decode(&mut input, true).unwrap() {
          ResponseStep::Event(ResponseEvent::Body(bytes)) => body.extend_from_slice(&bytes),
          ResponseStep::Event(ResponseEvent::Complete) => break,
          ResponseStep::Event(_) => {}
          ResponseStep::NeedInput => panic!("complete input requested another fragment"),
        }
      }
    }
    assert_eq!(body, b"abcdefg", "seed {seed}");
  }
}

#[test]
fn interim_limit_accepts_exact_and_rejects_one_over() {
  for (limit, expected) in [
    (
      1,
      Err(ResponseProtocolFailureReason::TooManyInterimResponses),
    ),
    (2, Ok(())),
    (3, Ok(())),
  ] {
    let limits = ResponseProtocolLimits {
      max_interim_responses: limit,
      ..ResponseProtocolLimits::default()
    };
    let response =
      b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n";
    let actual = decode_all_with_limits(Method::GET, response, 1, limits)
      .map(|_| ())
      .map_err(|error| error.reason());
    assert_eq!(actual, expected);
  }
}

#[test]
fn head_header_and_field_boundaries_are_exact() {
  let response = b"HTTP/1.1 204 No Content\r\nX: one\r\nY: two\r\n\r\n";
  let head_bytes = response.len();
  assert_failure(
    response,
    ResponseProtocolLimits {
      max_response_head_bytes: head_bytes - 1,
      ..ResponseProtocolLimits::default()
    },
    ResponseProtocolFailureReason::HeadTooLarge,
  );
  for limit in [head_bytes, head_bytes + 1] {
    decode_all_with_limits(
      Method::GET,
      response,
      1,
      ResponseProtocolLimits {
        max_response_head_bytes: limit,
        ..ResponseProtocolLimits::default()
      },
    )
    .unwrap();
  }

  assert_failure(
    response,
    ResponseProtocolLimits {
      max_response_header_fields: 1,
      ..ResponseProtocolLimits::default()
    },
    ResponseProtocolFailureReason::TooManyHeaders,
  );
  for limit in [2, 3] {
    decode_all_with_limits(
      Method::GET,
      response,
      1,
      ResponseProtocolLimits {
        max_response_header_fields: limit,
        ..ResponseProtocolLimits::default()
      },
    )
    .unwrap();
  }

  let field_bytes = b"X: one".len();
  assert_failure(
    response,
    ResponseProtocolLimits {
      max_response_header_field_bytes: field_bytes - 1,
      ..ResponseProtocolLimits::default()
    },
    ResponseProtocolFailureReason::HeaderFieldTooLarge,
  );
  for limit in [field_bytes, field_bytes + 1] {
    decode_all_with_limits(
      Method::GET,
      response,
      1,
      ResponseProtocolLimits {
        max_response_header_field_bytes: limit,
        ..ResponseProtocolLimits::default()
      },
    )
    .unwrap();
  }
}

#[test]
fn chunk_line_and_extension_boundaries_are_exact() {
  let line = b"1;foo=bar";
  let extension_bytes = b"foo=bar".len();
  let response =
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;foo=bar\r\nx\r\n0\r\n\r\n";
  assert_failure(
    response,
    ResponseProtocolLimits {
      max_chunk_size_line_bytes: line.len() - 1,
      ..ResponseProtocolLimits::default()
    },
    ResponseProtocolFailureReason::ChunkLineTooLarge,
  );
  for limit in [line.len(), line.len() + 1] {
    decode_all_with_limits(
      Method::GET,
      response,
      1,
      ResponseProtocolLimits {
        max_chunk_size_line_bytes: limit,
        ..ResponseProtocolLimits::default()
      },
    )
    .unwrap();
  }

  assert_failure(
    response,
    ResponseProtocolLimits {
      max_chunk_extension_bytes: extension_bytes - 1,
      ..ResponseProtocolLimits::default()
    },
    ResponseProtocolFailureReason::ChunkExtensionTooLarge,
  );
  for limit in [extension_bytes, extension_bytes + 1] {
    decode_all_with_limits(
      Method::GET,
      response,
      1,
      ResponseProtocolLimits {
        max_chunk_extension_bytes: limit,
        ..ResponseProtocolLimits::default()
      },
    )
    .unwrap();
  }
}

#[test]
fn trailer_block_count_and_field_boundaries_are_exact() {
  let block = b"X: one\r\nY: two\r\n\r\n";
  let response =
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: one\r\nY: two\r\n\r\n";
  assert_failure(
    response,
    ResponseProtocolLimits {
      max_trailer_block_bytes: block.len() - 1,
      ..ResponseProtocolLimits::default()
    },
    ResponseProtocolFailureReason::TrailerBlockTooLarge,
  );
  for limit in [block.len(), block.len() + 1] {
    decode_all_with_limits(
      Method::GET,
      response,
      1,
      ResponseProtocolLimits {
        max_trailer_block_bytes: limit,
        ..ResponseProtocolLimits::default()
      },
    )
    .unwrap();
  }

  assert_failure(
    response,
    ResponseProtocolLimits {
      max_trailer_fields: 1,
      ..ResponseProtocolLimits::default()
    },
    ResponseProtocolFailureReason::TooManyTrailers,
  );
  for limit in [2, 3] {
    decode_all_with_limits(
      Method::GET,
      response,
      1,
      ResponseProtocolLimits {
        max_trailer_fields: limit,
        ..ResponseProtocolLimits::default()
      },
    )
    .unwrap();
  }

  let field_bytes = b"X: one".len();
  assert_failure(
    response,
    ResponseProtocolLimits {
      max_trailer_field_bytes: field_bytes - 1,
      ..ResponseProtocolLimits::default()
    },
    ResponseProtocolFailureReason::TrailerFieldTooLarge,
  );
  for limit in [field_bytes, field_bytes + 1] {
    decode_all_with_limits(
      Method::GET,
      response,
      1,
      ResponseProtocolLimits {
        max_trailer_field_bytes: limit,
        ..ResponseProtocolLimits::default()
      },
    )
    .unwrap();
  }
}

#[test]
fn strict_transfer_encoding_and_content_length_matrix() {
  for invalid in [
    "gzip",
    "gzip, chunked",
    "chunked, gzip",
    "chunked, chunked",
    ",chunked",
    "chunked,",
    "chunked; q=1",
    "chunked; q=\"unterminated",
  ] {
    let response = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: {invalid}\r\n\r\n0\r\n\r\n");
    assert_failure(
      response.as_bytes(),
      ResponseProtocolLimits::default(),
      ResponseProtocolFailureReason::InvalidTransferCodingSequence,
    );
  }

  for response in [
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\n"
      .as_slice(),
    b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".as_slice(),
  ] {
    assert_failure(
      response,
      ResponseProtocolLimits::default(),
      ResponseProtocolFailureReason::InvalidTransferCodingSequence,
    );
  }

  let accepted = b"HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\nContent-Length: 5\r\n\r\nhello";
  decode_all(Method::GET, accepted, 1).unwrap();
  assert_failure(
    b"HTTP/1.1 200 OK\r\nContent-Length: 5, 6\r\n\r\nhello",
    ResponseProtocolLimits::default(),
    ResponseProtocolFailureReason::InvalidHeaderSyntax,
  );
}

#[test]
fn invalid_chunk_and_trailer_reasons_are_typed() {
  for (response, reason) in [
    (
      b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n".as_slice(),
      ResponseProtocolFailureReason::InvalidChunkSize,
    ),
    (
      b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;=x\r\n".as_slice(),
      ResponseProtocolFailureReason::InvalidChunkExtension,
    ),
    (
      b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nxX".as_slice(),
      ResponseProtocolFailureReason::InvalidChunkTerminator,
    ),
    (
      b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nBad Trailer\r\n\r\n".as_slice(),
      ResponseProtocolFailureReason::InvalidTrailerField,
    ),
  ] {
    assert_failure(response, ResponseProtocolLimits::default(), reason);
  }
}

#[test]
fn framing_and_routing_trailers_fail_closed() {
  for name in [
    "Content-Length",
    "Transfer-Encoding",
    "Host",
    "Connection",
    "TE",
    "Trailer",
    "Upgrade",
    "Keep-Alive",
    "Proxy-Connection",
  ] {
    let response =
      format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n{name}: value\r\n\r\n");
    assert_failure(
      response.as_bytes(),
      ResponseProtocolLimits::default(),
      ResponseProtocolFailureReason::InvalidTrailerField,
    );
  }
}

#[test]
fn status_header_upgrade_and_eof_reasons_are_sticky() {
  for (response, reason) in [
    (
      b"HTTP/1.1 XYZ Invalid\r\n\r\n".as_slice(),
      ResponseProtocolFailureReason::InvalidStatusLine,
    ),
    (
      b"HTTP/1.1 200 OK\r\nBad Header: value\r\n\r\n".as_slice(),
      ResponseProtocolFailureReason::InvalidHeaderSyntax,
    ),
    (
      b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n".as_slice(),
      ResponseProtocolFailureReason::UnsupportedUpgrade,
    ),
    (
      b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\na".as_slice(),
      ResponseProtocolFailureReason::UnexpectedEof,
    ),
  ] {
    assert_failure(response, ResponseProtocolLimits::default(), reason);
  }
}

#[test]
fn eof_latches_across_body_events_and_complete_is_emitted_once() {
  let mut engine =
    ResponseProtocolEngine::new(Method::GET, ResponseProtocolLimits::default()).unwrap();
  let mut input = BytesMut::from(&b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\na"[..]);
  assert!(matches!(
    engine.decode(&mut input, true).unwrap(),
    ResponseStep::Event(ResponseEvent::FinalHead { .. })
  ));
  assert!(matches!(
    engine.decode(&mut input, false).unwrap(),
    ResponseStep::Event(ResponseEvent::Body(_))
  ));
  assert_eq!(
    engine.decode(&mut input, false).unwrap_err().reason(),
    ResponseProtocolFailureReason::UnexpectedEof
  );

  let mut engine =
    ResponseProtocolEngine::new(Method::GET, ResponseProtocolLimits::default()).unwrap();
  let mut input = BytesMut::from(&b"HTTP/1.1 204 No Content\r\n\r\n"[..]);
  assert!(matches!(
    engine.decode(&mut input, false).unwrap(),
    ResponseStep::Event(ResponseEvent::FinalHead { .. })
  ));
  assert!(matches!(
    engine.decode(&mut input, false).unwrap(),
    ResponseStep::Event(ResponseEvent::Complete)
  ));
  assert!(matches!(
    engine.decode(&mut input, false).unwrap(),
    ResponseStep::NeedInput
  ));
}

#[test]
fn head_and_not_modified_responses_never_enter_body_state() {
  for (method, response) in [
    (
      Method::HEAD,
      b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n".as_slice(),
    ),
    (
      Method::GET,
      b"HTTP/1.1 304 Not Modified\r\nContent-Length: 99\r\n\r\n".as_slice(),
    ),
  ] {
    let events = decode_all(method, response, 1).unwrap();
    assert!(matches!(
      events.first(),
      Some(ResponseEvent::FinalHead {
        body_mode: ResponseBodyMode::None,
        ..
      })
    ));
    assert!(body_bytes(&events).is_empty());
  }
}

#[test]
fn close_delimited_body_completes_only_on_eof() {
  let response = b"HTTP/1.0 200 OK\r\n\r\nstream";
  let events = decode_all(Method::GET, response, 1).unwrap();
  assert!(matches!(
    events[0],
    ResponseEvent::FinalHead {
      body_mode: ResponseBodyMode::CloseDelimited,
      ..
    }
  ));
  assert_eq!(body_bytes(&events), b"stream");
  assert!(matches!(events.last(), Some(ResponseEvent::Complete)));
}

#[test]
fn transport_failure_vocabulary_is_fixed_and_typed() {
  for reason in [
    ResponseProtocolFailureReason::IdleTimeout,
    ResponseProtocolFailureReason::DownstreamCancellation,
  ] {
    let error = ResponseProtocolError::new(reason, ResponseStateLabel::ChunkData);
    assert_eq!(error.reason(), reason);
    assert_eq!(error.state(), ResponseStateLabel::ChunkData);
    assert!(!error.to_string().is_empty());
  }
}

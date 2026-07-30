use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::{HeaderMap, Method, Request, StatusCode, Version};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::config::EarlyHintsMode;
use crate::proxy::http::semantics::{
  InterimResponses, attach_early_hints_capture, sanitize_interim_response,
};

#[derive(Debug, Eq, PartialEq)]
struct NormalizedInterim {
  status: StatusCode,
  headers: Vec<(String, Vec<u8>)>,
}

#[derive(Debug, Eq, PartialEq)]
struct NormalizedResponse {
  version: Version,
  status: StatusCode,
  headers: Vec<(String, Vec<u8>)>,
  interim: Vec<NormalizedInterim>,
  body: Vec<u8>,
  trailers: Vec<(String, Vec<u8>)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DifferentialFailureClass {
  Protocol,
}

fn normalize_headers(headers: &HeaderMap) -> Vec<(String, Vec<u8>)> {
  let mut normalized = headers
    .iter()
    .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
    .collect::<Vec<_>>();
  normalized.sort();
  normalized
}

fn normalize_interim(interim: InterimResponses) -> Vec<NormalizedInterim> {
  interim
    .responses
    .into_iter()
    .map(|response| NormalizedInterim {
      status: response.status,
      headers: normalize_headers(&response.headers),
    })
    .collect()
}

fn parse_with_compio_engine(
  method: Method,
  wire: &[u8],
) -> Result<NormalizedResponse, DifferentialFailureClass> {
  let mut engine = ResponseProtocolEngine::new(method, ResponseProtocolLimits::default())
    .expect("default protocol limits should validate");
  let mut input = BytesMut::from(wire);
  let mut final_head = None;
  let mut interim = InterimResponses::default();
  let mut body = Vec::new();
  let mut trailers = HeaderMap::new();

  loop {
    let step = engine
      .decode(&mut input, true)
      .map_err(|_| DifferentialFailureClass::Protocol)?;
    match step {
      ResponseStep::Event(ResponseEvent::InterimHead { status, headers }) => {
        if let Some(response) = sanitize_interim_response(status, &headers) {
          interim.responses.push(response);
        }
      }
      ResponseStep::Event(ResponseEvent::FinalHead {
        version,
        status,
        headers,
        ..
      }) => {
        final_head = Some((version, status, headers));
      }
      ResponseStep::Event(ResponseEvent::Body(bytes)) => body.extend_from_slice(&bytes),
      ResponseStep::Event(ResponseEvent::Trailers(parsed)) => trailers = parsed,
      ResponseStep::Event(ResponseEvent::Complete) => break,
      ResponseStep::NeedInput => panic!("complete in-memory input must not need another read"),
    }
  }

  assert_eq!(engine.state(), ResponseState::Completed);
  assert!(
    input.is_empty(),
    "supported corpus must consume the response"
  );
  let (version, status, headers) =
    final_head.expect("completed response should contain one final head");
  Ok(NormalizedResponse {
    version,
    status,
    headers: normalize_headers(&headers),
    interim: normalize_interim(interim),
    body,
    trailers: normalize_headers(&trailers),
  })
}

async fn parse_with_hyper(
  method: Method,
  wire: &[u8],
) -> Result<NormalizedResponse, DifferentialFailureClass> {
  let capacity = wire.len().saturating_add(4096);
  let (client_io, mut origin_io) = tokio::io::duplex(capacity);
  let wire = wire.to_vec();
  let origin_task = tokio::spawn(async move {
    let mut request = Vec::with_capacity(512);
    loop {
      let mut buffer = [0u8; 256];
      let count = origin_io
        .read(&mut buffer)
        .await
        .expect("in-memory origin should read the request");
      assert!(count > 0, "client closed before sending a request head");
      request.extend_from_slice(&buffer[..count]);
      if request.windows(4).any(|window| window == b"\r\n\r\n") {
        break;
      }
      assert!(
        request.len() <= 4096,
        "differential request is unexpectedly large"
      );
    }
    origin_io
      .write_all(&wire)
      .await
      .expect("in-memory origin response should fit the bounded duplex");
    origin_io
      .shutdown()
      .await
      .expect("in-memory origin write side should close");
  });

  let (mut sender, connection) =
    hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(TokioIo::new(client_io))
      .await
      .expect("in-memory Hyper handshake should initialize");
  let mut connection_task = tokio::spawn(connection);
  let mut request = Request::builder()
    .method(method)
    .uri("/")
    .header(http::header::HOST, "differential.example.test")
    .body(Empty::<Bytes>::new())
    .expect("differential request should be valid");
  let capture = attach_early_hints_capture(&mut request, EarlyHintsMode::Pass)
    .expect("pass mode should install informational capture");

  let normalized = match sender.send_request(request).await {
    Ok(response) => {
      let (parts, response_body) = response.into_parts();
      match response_body.collect().await {
        Ok(collected) => {
          let trailers = collected
            .trailers()
            .map(normalize_headers)
            .unwrap_or_default();
          Ok(NormalizedResponse {
            version: parts.version,
            status: parts.status,
            headers: normalize_headers(&parts.headers),
            interim: normalize_interim(capture.take()),
            body: collected.to_bytes().to_vec(),
            trailers,
          })
        }
        Err(_) => Err(DifferentialFailureClass::Protocol),
      }
    }
    Err(_) => Err(DifferentialFailureClass::Protocol),
  };

  drop(sender);
  origin_task
    .await
    .expect("in-memory origin task should complete");
  if tokio::time::timeout(Duration::from_secs(1), &mut connection_task)
    .await
    .is_err()
  {
    connection_task.abort();
    let _ = connection_task.await;
    panic!("in-memory Hyper connection did not terminate");
  }
  normalized
}

#[tokio::test]
async fn supported_response_corpus_matches_hyper() {
  let corpus = [
    (
      "fixed length and duplicate headers",
      Method::GET,
      b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Test: one\r\nX-Test: two\r\n\r\nhello"
        .as_slice(),
    ),
    (
      "chunked body and trailers",
      Method::GET,
      b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trace\r\n\r\n5;name=\"value\"\r\nhello\r\n0\r\nX-Trace: done\r\n\r\n"
        .as_slice(),
    ),
    (
      "close delimited body",
      Method::GET,
      b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nuntil-close".as_slice(),
    ),
    (
      "head response",
      Method::HEAD,
      b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n".as_slice(),
    ),
    (
      "no-content response",
      Method::GET,
      b"HTTP/1.1 204 No Content\r\nX-Test: yes\r\n\r\n".as_slice(),
    ),
    (
      "not-modified response",
      Method::GET,
      b"HTTP/1.1 304 Not Modified\r\nETag: \"shared\"\r\n\r\n".as_slice(),
    ),
    (
      "continue and sanitized early hints before final",
      Method::GET,
      b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\nX-Ignored: no\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        .as_slice(),
    ),
  ];

  for (name, method, wire) in corpus {
    let compio = parse_with_compio_engine(method.clone(), wire)
      .unwrap_or_else(|class| panic!("{name}: Compio rejected supported input as {class:?}"));
    let hyper = parse_with_hyper(method, wire)
      .await
      .unwrap_or_else(|class| panic!("{name}: Hyper rejected supported input as {class:?}"));
    assert_eq!(compio, hyper, "{name}");
  }
}

#[tokio::test]
async fn shared_invalid_corpus_matches_hyper_failure_class() {
  let corpus = [
    (
      "conflicting content lengths",
      b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx".as_slice(),
    ),
    (
      "invalid header name",
      b"HTTP/1.1 200 OK\r\nBad Header: value\r\n\r\n".as_slice(),
    ),
    (
      "invalid status",
      b"HTTP/1.1 XYZ Invalid\r\nContent-Length: 0\r\n\r\n".as_slice(),
    ),
  ];

  for (name, wire) in corpus {
    assert_eq!(
      parse_with_compio_engine(Method::GET, wire),
      Err(DifferentialFailureClass::Protocol),
      "{name}: Compio failure class"
    );
    assert_eq!(
      parse_with_hyper(Method::GET, wire).await,
      Err(DifferentialFailureClass::Protocol),
      "{name}: Hyper failure class"
    );
  }
}

// Unsupported or malformed transfer-coding chains and 101 upgrades are
// intentionally absent: OB-P0-01 makes Compio stricter than the established
// Hyper path for those inputs, so equality would weaken the fail-closed policy.

//! Negotiation shared by Admin operation event transports.

use ::http::header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, VARY};
use ::http::{HeaderMap, HeaderValue, Response};
use sfv::visitor::{ItemVisitor, ParameterVisitor};
use sfv::{BareItemFromInput, KeyRef, Parser};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::OwnedSemaphorePermit;

use crate::config::AdminEventCompressionConfig;
use crate::proxy::http::body::ProxyBody;

use super::admin_operations::AdminOperationRuntime;

pub(super) const WEBTRANSPORT_EVENT_STREAM_HEADER: &str = "oxibelt-event-stream";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EventCoding {
  Br,
  Zstd,
  Gzip,
  Deflate,
  Identity,
}

pub(super) struct EventStreamCompression {
  pub(super) coding: EventCoding,
  pub(super) permit: Option<OwnedSemaphorePermit>,
}

enum EventStreamWriterInner<W> {
  Identity(W),
  Compressed(Box<crate::proxy::http::sse_compression::SseCompressionEncoder<W>>),
}

pub(super) struct EventStreamWriter<W> {
  inner: EventStreamWriterInner<W>,
  _permit: Option<OwnedSemaphorePermit>,
}

impl<W: AsyncWrite + Unpin> EventStreamWriter<W> {
  pub(super) fn new(writer: W, compression: Option<EventStreamCompression>, level: u8) -> Self {
    let (inner, permit) = match compression {
      Some(compression) => match compression.coding.compression_coding() {
        Some(coding) => (
          EventStreamWriterInner::Compressed(Box::new(
            crate::proxy::http::sse_compression::SseCompressionEncoder::new(writer, coding, level),
          )),
          compression.permit,
        ),
        None => (EventStreamWriterInner::Identity(writer), compression.permit),
      },
      None => (EventStreamWriterInner::Identity(writer), None),
    };
    Self {
      inner,
      _permit: permit,
    }
  }

  pub(super) async fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
    match &mut self.inner {
      EventStreamWriterInner::Identity(writer) => writer.write_all(bytes).await,
      EventStreamWriterInner::Compressed(writer) => writer.write_all(bytes).await,
    }
  }

  pub(super) async fn flush_record(&mut self) -> std::io::Result<()> {
    match &mut self.inner {
      EventStreamWriterInner::Identity(writer) => writer.flush().await,
      EventStreamWriterInner::Compressed(writer) => writer.flush_record().await,
    }
  }

  pub(super) async fn shutdown(&mut self) -> std::io::Result<()> {
    match &mut self.inner {
      EventStreamWriterInner::Identity(writer) => writer.shutdown().await,
      EventStreamWriterInner::Compressed(writer) => writer.shutdown().await,
    }
  }
}

impl EventCoding {
  pub(super) const fn as_str(self) -> &'static str {
    match self {
      Self::Br => "br",
      Self::Zstd => "zstd",
      Self::Gzip => "gzip",
      Self::Deflate => "deflate",
      Self::Identity => "identity",
    }
  }

  pub(super) const fn enabled(self, config: &AdminEventCompressionConfig) -> bool {
    match self {
      Self::Br => config.br,
      Self::Zstd => config.zstd,
      Self::Gzip => config.gzip,
      Self::Deflate => config.deflate,
      Self::Identity => true,
    }
  }

  pub(super) const fn compression_coding(
    self,
  ) -> Option<crate::proxy::http::sse_compression::SseCompressionCoding> {
    use crate::proxy::http::sse_compression::SseCompressionCoding;
    match self {
      Self::Br => Some(SseCompressionCoding::Br),
      Self::Zstd => Some(SseCompressionCoding::Zstd),
      Self::Gzip => Some(SseCompressionCoding::Gzip),
      Self::Deflate => Some(SseCompressionCoding::Deflate),
      Self::Identity => None,
    }
  }
}

pub(super) fn negotiate_http_coding(
  headers: &HeaderMap,
  config: &AdminEventCompressionConfig,
) -> Option<EventCoding> {
  if !config.enabled || !headers.contains_key(ACCEPT_ENCODING) {
    return None;
  }
  let mut best = None;
  let mut best_quality = 0.0f32;
  for coding in [
    EventCoding::Br,
    EventCoding::Zstd,
    EventCoding::Gzip,
    EventCoding::Deflate,
  ] {
    if !coding.enabled(config) {
      continue;
    }
    let quality =
      crate::proxy::http::compression::accepted_encoding_quality(headers, coding.as_str());
    if quality > best_quality {
      best = Some(coding);
      best_quality = quality;
    }
  }
  best
}

pub(super) fn compress_http_event_response(
  response: Response<ProxyBody>,
  request_headers: &HeaderMap,
  operations: &AdminOperationRuntime,
) -> Response<ProxyBody> {
  let config = &operations.config().event_compression;
  if !config.enabled {
    return response;
  }
  let (mut parts, body) = response.into_parts();
  append_vary_accept_encoding(&mut parts.headers);
  let Some(coding) = negotiate_http_coding(request_headers, config) else {
    return Response::from_parts(parts, body);
  };
  let Ok(permit) = operations.try_acquire_event_compression() else {
    return Response::from_parts(parts, body);
  };
  let Some(compression_coding) = coding.compression_coding() else {
    return Response::from_parts(parts, body);
  };
  parts
    .headers
    .insert(CONTENT_ENCODING, HeaderValue::from_static(coding.as_str()));
  parts.headers.remove(CONTENT_LENGTH);
  let body = crate::proxy::http::sse_compression::compress_body(
    body,
    compression_coding,
    config.level,
    crate::proxy::http::sse_compression::SseFlushBoundary::EveryFrame,
    permit,
  );
  Response::from_parts(parts, body)
}

fn append_vary_accept_encoding(headers: &mut HeaderMap) {
  let already_varies = headers
    .get_all(VARY)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(','))
    .map(str::trim)
    .any(|item| item == "*" || item.eq_ignore_ascii_case("accept-encoding"));
  if !already_varies {
    headers.append(VARY, HeaderValue::from_static("Accept-Encoding"));
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WebTransportEventStreamError {
  Invalid,
  Unavailable,
}

pub(super) fn webtransport_event_coding(
  headers: &HeaderMap,
  config: &AdminEventCompressionConfig,
) -> Result<Option<EventCoding>, WebTransportEventStreamError> {
  let mut values = headers.get_all(WEBTRANSPORT_EVENT_STREAM_HEADER).iter();
  let Some(value) = values.next() else {
    return Ok(None);
  };
  if values.next().is_some() || value.len() > 256 {
    return Err(WebTransportEventStreamError::Invalid);
  }
  let coding = Parser::new(value.as_bytes())
    .with_version(sfv::Version::Rfc8941)
    .parse_item_with_visitor(EventStreamItem)
    .map_err(|_| WebTransportEventStreamError::Invalid)?;
  if coding != EventCoding::Identity && (!config.enabled || !coding.enabled(config)) {
    return Err(WebTransportEventStreamError::Unavailable);
  }
  Ok(Some(coding))
}

struct EventStreamItem;

#[derive(Debug)]
struct InvalidEventStreamField;

impl std::fmt::Display for InvalidEventStreamField {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str("invalid OxiBelt event stream field")
  }
}

impl std::error::Error for InvalidEventStreamField {}

impl<'de> ItemVisitor<'de> for EventStreamItem {
  type Out = EventCoding;
  type Error = InvalidEventStreamField;

  fn bare_item(
    self,
    item: BareItemFromInput<'de>,
  ) -> Result<impl ParameterVisitor<'de, Out = EventCoding>, Self::Error> {
    match item {
      BareItemFromInput::Token(value) if value.as_str() == "ndjson-v1" => {
        Ok(EventStreamParameters { coding: None })
      }
      _ => Err(InvalidEventStreamField),
    }
  }
}

struct EventStreamParameters {
  coding: Option<EventCoding>,
}

impl<'de> ParameterVisitor<'de> for EventStreamParameters {
  type Out = EventCoding;
  type Error = InvalidEventStreamField;

  fn parameter(
    &mut self,
    key: &'de KeyRef,
    value: BareItemFromInput<'de>,
  ) -> Result<(), Self::Error> {
    if key.as_str() != "coding" || self.coding.is_some() {
      return Err(InvalidEventStreamField);
    }
    let BareItemFromInput::Token(value) = value else {
      return Err(InvalidEventStreamField);
    };
    self.coding = Some(match value.as_str() {
      "br" => EventCoding::Br,
      "zstd" => EventCoding::Zstd,
      "gzip" => EventCoding::Gzip,
      "deflate" => EventCoding::Deflate,
      "identity" => EventCoding::Identity,
      _ => return Err(InvalidEventStreamField),
    });
    Ok(())
  }

  fn finish(self) -> Result<Self::Out, Self::Error> {
    self.coding.ok_or(InvalidEventStreamField)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use ::http::HeaderValue;
  use async_compression::tokio::bufread::GzipDecoder;
  use bytes::Bytes;
  use http_body_util::{BodyExt, Full};
  use tokio::io::{AsyncReadExt, BufReader};

  fn event_body(bytes: &'static [u8]) -> ProxyBody {
    Full::new(Bytes::from_static(bytes))
      .map_err(|never| -> crate::proxy::http::body::BoxError { match never {} })
      .boxed()
  }

  fn operations(max_concurrent_streams: usize) -> AdminOperationRuntime {
    let mut config = crate::config::AdminOperationsConfig::default();
    config.event_compression.enabled = true;
    config.event_compression.max_concurrent_streams = max_concurrent_streams;
    AdminOperationRuntime::new(config)
  }

  #[test]
  fn webtransport_contract_is_explicit_and_strict() {
    let mut config = AdminEventCompressionConfig {
      enabled: true,
      ..AdminEventCompressionConfig::default()
    };
    let mut headers = HeaderMap::new();
    assert_eq!(webtransport_event_coding(&headers, &config), Ok(None));

    headers.insert(
      WEBTRANSPORT_EVENT_STREAM_HEADER,
      HeaderValue::from_static("ndjson-v1; coding=identity"),
    );
    config.enabled = false;
    assert_eq!(
      webtransport_event_coding(&headers, &config),
      Ok(Some(EventCoding::Identity))
    );
    headers.insert(
      WEBTRANSPORT_EVENT_STREAM_HEADER,
      HeaderValue::from_static("ndjson-v1; coding=gzip"),
    );
    assert_eq!(
      webtransport_event_coding(&headers, &config),
      Err(WebTransportEventStreamError::Unavailable)
    );
    config.enabled = true;

    headers.insert(
      WEBTRANSPORT_EVENT_STREAM_HEADER,
      HeaderValue::from_static("ndjson-v1; coding=gzip"),
    );
    assert_eq!(
      webtransport_event_coding(&headers, &config),
      Ok(Some(EventCoding::Gzip))
    );

    for invalid in [
      "ndjson-v2; coding=gzip",
      "ndjson-v1",
      "ndjson-v1; coding=gzip; coding=br",
      "ndjson-v1; coding=unknown",
      "ndjson-v1; extra=?1; coding=gzip",
    ] {
      headers.insert(
        WEBTRANSPORT_EVENT_STREAM_HEADER,
        HeaderValue::from_str(invalid).unwrap(),
      );
      assert_eq!(
        webtransport_event_coding(&headers, &config),
        Err(WebTransportEventStreamError::Invalid),
        "{invalid}"
      );
    }

    headers.insert(
      WEBTRANSPORT_EVENT_STREAM_HEADER,
      HeaderValue::from_static("ndjson-v1; coding=br"),
    );
    config.br = false;
    assert_eq!(
      webtransport_event_coding(&headers, &config),
      Err(WebTransportEventStreamError::Unavailable)
    );
  }

  #[test]
  fn http_negotiation_uses_quality_then_server_preference() {
    let config = AdminEventCompressionConfig {
      enabled: true,
      ..AdminEventCompressionConfig::default()
    };
    let mut headers = HeaderMap::new();
    assert_eq!(negotiate_http_coding(&headers, &config), None);
    headers.insert(
      ACCEPT_ENCODING,
      HeaderValue::from_static("gzip;q=1, br;q=0.5"),
    );
    assert_eq!(
      negotiate_http_coding(&headers, &config),
      Some(EventCoding::Gzip)
    );
    headers.insert(
      ACCEPT_ENCODING,
      HeaderValue::from_static("gzip;q=1, br;q=1"),
    );
    assert_eq!(
      negotiate_http_coding(&headers, &config),
      Some(EventCoding::Br)
    );
  }

  #[tokio::test]
  async fn http_streams_compress_and_fall_back_to_identity_at_capacity() {
    let operations = operations(1);
    let mut request_headers = HeaderMap::new();
    request_headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
    let response = Response::builder()
      .header(::http::header::CONTENT_TYPE, "text/event-stream")
      .body(event_body(b"data: ready\n\n"))
      .unwrap();
    let response = compress_http_event_response(response, &request_headers, &operations);
    assert_eq!(response.headers()[CONTENT_ENCODING], "gzip");
    assert_eq!(response.headers()[VARY], "Accept-Encoding");
    let compressed = response.into_body().collect().await.unwrap().to_bytes();
    let mut decoder = GzipDecoder::new(BufReader::new(compressed.as_ref()));
    let mut decoded = Vec::new();
    decoder.read_to_end(&mut decoded).await.unwrap();
    assert_eq!(decoded, b"data: ready\n\n");

    let permit = operations.try_acquire_event_compression().unwrap();
    let response = Response::builder()
      .header(::http::header::CONTENT_TYPE, "application/x-ndjson")
      .body(event_body(b"{\"event\":\"ready\"}\n"))
      .unwrap();
    let response = compress_http_event_response(response, &request_headers, &operations);
    assert!(!response.headers().contains_key(CONTENT_ENCODING));
    assert_eq!(response.headers()[VARY], "Accept-Encoding");
    drop(permit);
  }
}

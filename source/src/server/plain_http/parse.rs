//! Minimal HTTP/1 request parser for the plain listener path.
//! Parsed targets and headers remain untrusted until later validation stages accept them.

use std::time::Duration;

use ::http::{HeaderMap, HeaderName, HeaderValue, Method};
use anyhow::{Context as AnyhowContext, bail};
use httparse::Status;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::watch;

const READ_CHUNK_BYTES: usize = 4096;
const STACK_HEADER_CAPACITY: usize = 128;

pub(super) enum ReadRequestOutcome {
  Closed,
  Fallback {
    prefix: Vec<u8>,
    reason: &'static str,
  },
  Request(ParsedPlainRequest),
}

pub(super) struct ParsedPlainRequest {
  pub(super) method: Method,
  pub(super) target: String,
  pub(super) version: u8,
  pub(super) headers: HeaderMap,
  pub(super) raw: Vec<u8>,
  pub(super) remaining: Vec<u8>,
}

impl ParsedPlainRequest {
  pub(super) fn header_count(&self, name: HeaderName) -> usize {
    self.headers.get_all(name).iter().count()
  }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn read_request(
  stream: &mut TcpStream,
  mut buffer: Vec<u8>,
  max_header_bytes: usize,
  max_headers: usize,
  header_timeout: Duration,
  target_can_match_static: &(dyn Fn(&str) -> bool + Sync),
  shutdown: &mut watch::Receiver<bool>,
  data_plane_drain: &mut watch::Receiver<bool>,
) -> anyhow::Result<ReadRequestOutcome> {
  let started = tokio::time::Instant::now();
  let mut chunk = [0_u8; READ_CHUNK_BYTES];
  loop {
    match parse_buffered_request_with_static_target_filter(
      &buffer,
      max_headers,
      target_can_match_static,
    ) {
      ParseResult::Complete {
        header_len,
        request,
      } => {
        let remaining = buffer.split_off(header_len);
        let raw = buffer;
        return Ok(ReadRequestOutcome::Request(ParsedPlainRequest {
          method: request.method,
          target: request.target,
          version: request.version,
          headers: request.headers,
          raw,
          remaining,
        }));
      }
      ParseResult::Partial => {}
      ParseResult::Fallback(reason) => {
        return Ok(ReadRequestOutcome::Fallback {
          prefix: buffer,
          reason,
        });
      }
    }
    if buffer.len() >= max_header_bytes {
      return Ok(ReadRequestOutcome::Fallback {
        prefix: buffer,
        reason: "header block exceeded configured limit",
      });
    }
    let remaining_timeout = match header_timeout.checked_sub(started.elapsed()) {
      Some(value) if !value.is_zero() => value,
      _ => bail!("plain HTTP static sendfile header read timed out"),
    };
    let read_limit = READ_CHUNK_BYTES.min(max_header_bytes - buffer.len());
    let read = tokio::select! {
      biased;
      changed = shutdown.changed() => {
        if changed.is_ok() && *shutdown.borrow() {
          return Ok(ReadRequestOutcome::Closed);
        }
        continue;
      }
      changed = data_plane_drain.changed() => {
        if changed.is_ok() && *data_plane_drain.borrow() {
          return Ok(ReadRequestOutcome::Closed);
        }
        continue;
      }
      result = tokio::time::timeout(remaining_timeout, stream.read(&mut chunk[..read_limit])) => {
        result.context("plain HTTP static sendfile header read timed out")??
      }
    };
    if read == 0 {
      if buffer.is_empty() {
        return Ok(ReadRequestOutcome::Closed);
      }
      return Ok(ReadRequestOutcome::Fallback {
        prefix: buffer,
        reason: "connection closed during header parse",
      });
    }
    buffer.extend_from_slice(&chunk[..read]);
  }
}

pub(super) enum ParseResult {
  Complete {
    header_len: usize,
    request: ParsedPlainRequestSeed,
  },
  Partial,
  Fallback(&'static str),
}

pub(super) struct ParsedPlainRequestSeed {
  pub(super) method: Method,
  pub(super) target: String,
  pub(super) version: u8,
  pub(super) headers: HeaderMap,
}

#[cfg(test)]
pub(super) fn parse_buffered_request(buffer: &[u8], max_headers: usize) -> ParseResult {
  parse_buffered_request_with_static_target_filter(buffer, max_headers, &|_| true)
}

pub(super) fn parse_buffered_request_with_static_target_filter(
  buffer: &[u8],
  max_headers: usize,
  target_can_match_static: &(dyn Fn(&str) -> bool + Sync),
) -> ParseResult {
  if max_headers <= STACK_HEADER_CAPACITY {
    let mut parsed_headers = [httparse::EMPTY_HEADER; STACK_HEADER_CAPACITY];
    return parse_buffered_request_with_headers(
      buffer,
      &mut parsed_headers[..max_headers],
      target_can_match_static,
    );
  }
  let mut parsed_headers = vec![httparse::EMPTY_HEADER; max_headers];
  parse_buffered_request_with_headers(buffer, &mut parsed_headers, target_can_match_static)
}

fn parse_buffered_request_with_headers<'a>(
  buffer: &'a [u8],
  parsed_headers: &mut [httparse::Header<'a>],
  target_can_match_static: &(dyn Fn(&str) -> bool + Sync),
) -> ParseResult {
  let mut request = httparse::Request::new(parsed_headers);
  let header_len = match request.parse(buffer) {
    Ok(Status::Complete(len)) => len,
    Ok(Status::Partial) => return ParseResult::Partial,
    Err(_) => return ParseResult::Fallback("HTTP/1.1 parser rejected request"),
  };
  let Some(method) = request.method else {
    return ParseResult::Fallback("HTTP/1.1 request is missing method");
  };
  let method = match Method::from_bytes(method.as_bytes()) {
    Ok(method) => method,
    Err(_) => return ParseResult::Fallback("HTTP/1.1 request method is invalid"),
  };
  let Some(target) = request.path else {
    return ParseResult::Fallback("HTTP/1.1 request is missing target");
  };
  let Some(version) = request.version else {
    return ParseResult::Fallback("HTTP/1.1 request is missing version");
  };
  if origin_form_target_path(target).is_some() && !target_can_match_static(target) {
    return ParseResult::Fallback("request target cannot match static sendfile route");
  }
  let mut headers = HeaderMap::new();
  for header in request.headers {
    let name = match HeaderName::from_bytes(header.name.as_bytes()) {
      Ok(name) => name,
      Err(_) => return ParseResult::Fallback("HTTP/1.1 header name is invalid"),
    };
    let value = match HeaderValue::from_bytes(header.value) {
      Ok(value) => value,
      Err(_) => return ParseResult::Fallback("HTTP/1.1 header value is invalid"),
    };
    headers.append(name, value);
  }
  ParseResult::Complete {
    header_len,
    request: ParsedPlainRequestSeed {
      method,
      target: target.to_string(),
      version,
      headers,
    },
  }
}

fn origin_form_target_path(target: &str) -> Option<&str> {
  if !target.starts_with('/') || target.starts_with("//") || target.contains("://") {
    return None;
  }
  Some(target.split_once('?').map_or(target, |(path, _)| path))
}

pub(super) fn header_has_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
  headers.get_all(name).iter().any(|value| {
    value.to_str().ok().is_some_and(|value| {
      value
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate.eq_ignore_ascii_case(token))
    })
  })
}

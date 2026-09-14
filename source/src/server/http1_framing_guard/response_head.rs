use super::{ChunkDecoder, is_header_name_byte, trim_ascii_whitespace};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TunnelKind {
  Connect,
  Upgrade,
}

pub(super) enum ResponseHeadOutcome {
  Pending,
  ConnectRejectionPending,
  Accepted,
  Rejected,
  Invalid,
}

pub(super) struct ResponseHeadParser {
  kind: TunnelKind,
  max_bytes: usize,
  observed_bytes: usize,
  buffered: Vec<u8>,
  connect_rejection_body: Option<ResponseBodyTracker>,
}

impl ResponseHeadParser {
  pub(super) fn new(kind: TunnelKind, max_bytes: usize) -> Self {
    Self {
      kind,
      max_bytes: max_bytes.max(1),
      observed_bytes: 0,
      buffered: Vec::with_capacity(256.min(max_bytes)),
      connect_rejection_body: None,
    }
  }

  pub(super) fn consume(&mut self, input: &[u8]) -> ResponseHeadOutcome {
    if self.connect_rejection_body.is_some() {
      return self.consume_connect_rejection_body(input);
    }
    for (offset, byte) in input.iter().enumerate() {
      if self.observed_bytes >= self.max_bytes {
        return ResponseHeadOutcome::Invalid;
      }
      self.observed_bytes += 1;
      self.buffered.push(*byte);
      if !self.buffered.ends_with(b"\r\n\r\n") {
        continue;
      }
      let Some(head) = response_head(&self.buffered) else {
        return ResponseHeadOutcome::Invalid;
      };
      if head.status == 101 {
        return if self.kind == TunnelKind::Upgrade {
          ResponseHeadOutcome::Accepted
        } else if head.body.is_no_body() {
          ResponseHeadOutcome::Rejected
        } else {
          ResponseHeadOutcome::Invalid
        };
      }
      if (100..200).contains(&head.status) {
        if !head.body.is_no_body() {
          return ResponseHeadOutcome::Invalid;
        }
        self.buffered.clear();
        continue;
      }
      if self.kind == TunnelKind::Connect && (200..300).contains(&head.status) {
        return if head.tunnel_success_framing_valid {
          ResponseHeadOutcome::Accepted
        } else {
          ResponseHeadOutcome::Invalid
        };
      }
      if self.kind == TunnelKind::Upgrade {
        return ResponseHeadOutcome::Rejected;
      }
      if head.body.is_no_body() {
        return ResponseHeadOutcome::Rejected;
      }
      let Some(body) = ResponseBodyTracker::new(head.body, self.max_bytes) else {
        return ResponseHeadOutcome::Invalid;
      };
      self.connect_rejection_body = Some(body);
      return self.consume_connect_rejection_body(&input[offset + 1..]);
    }
    ResponseHeadOutcome::Pending
  }

  fn consume_connect_rejection_body(&mut self, input: &[u8]) -> ResponseHeadOutcome {
    let Some(body) = self.connect_rejection_body.as_mut() else {
      return ResponseHeadOutcome::Invalid;
    };
    match body.consume(input) {
      BodyProgress::Pending => ResponseHeadOutcome::ConnectRejectionPending,
      BodyProgress::Complete => ResponseHeadOutcome::Rejected,
      BodyProgress::Invalid => ResponseHeadOutcome::Invalid,
    }
  }

  pub(super) const fn kind(&self) -> TunnelKind {
    self.kind
  }
}

struct ResponseHead {
  status: u16,
  body: ResponseBody,
  tunnel_success_framing_valid: bool,
}
enum ResponseBody {
  NoBody,
  Fixed(u64),
  Chunked,
  CloseDelimited,
}
impl ResponseBody {
  fn is_no_body(&self) -> bool {
    matches!(self, Self::NoBody | Self::Fixed(0))
  }
}

fn response_head(head: &[u8]) -> Option<ResponseHead> {
  let lines = head.strip_suffix(b"\r\n\r\n")?;
  let status_line_end = memchr::memmem::find(lines, b"\r\n").unwrap_or(lines.len());
  let status_line = &lines[..status_line_end];
  let headers = if status_line_end == lines.len() {
    &[][..]
  } else {
    &lines[status_line_end + 2..]
  };
  let status = validate_status_line(status_line)?;
  let (transfer_encoding, content_length) = response_framing_headers(headers)?;
  let tunnel_success_framing_valid = !transfer_encoding && content_length.is_none();
  let body = if (100..200).contains(&status) || matches!(status, 204 | 304) {
    ResponseBody::NoBody
  } else if transfer_encoding {
    ResponseBody::Chunked
  } else if let Some(length) = content_length {
    ResponseBody::Fixed(length)
  } else {
    ResponseBody::CloseDelimited
  };
  Some(ResponseHead {
    status,
    body,
    tunnel_success_framing_valid,
  })
}

fn validate_status_line(line: &[u8]) -> Option<u16> {
  let version_end = memchr::memchr(b' ', line)?;
  if !matches!(&line[..version_end], b"HTTP/1.0" | b"HTTP/1.1") {
    return None;
  }
  let status_and_reason = &line[version_end + 1..];
  if status_and_reason.len() < 3
    || !status_and_reason[..3].iter().all(u8::is_ascii_digit)
    || status_and_reason
      .get(3)
      .is_some_and(|separator| *separator != b' ')
    || status_and_reason[3..]
      .iter()
      .any(|byte| byte.is_ascii_control() && *byte != b'\t')
  {
    return None;
  }
  std::str::from_utf8(&status_and_reason[..3])
    .ok()?
    .parse::<u16>()
    .ok()
    .filter(|status| (100..600).contains(status))
}

fn response_framing_headers(headers: &[u8]) -> Option<(bool, Option<u64>)> {
  let mut headers = headers;
  let mut has_transfer_encoding = false;
  let mut final_transfer_coding: Option<&[u8]> = None;
  let mut content_length = None;
  while !headers.is_empty() {
    let line_end = memchr::memmem::find(headers, b"\r\n").unwrap_or(headers.len());
    let line = &headers[..line_end];
    let colon = memchr::memchr(b':', line)?;
    let name = &line[..colon];
    let value = trim_ascii_whitespace(&line[colon + 1..]);
    if name.is_empty()
      || !name.iter().all(|byte| is_header_name_byte(*byte))
      || value
        .iter()
        .any(|byte| byte.is_ascii_control() && *byte != b'\t')
    {
      return None;
    }
    if name.eq_ignore_ascii_case(b"transfer-encoding") {
      has_transfer_encoding = true;
      for coding in value.split(|byte| *byte == b',') {
        let coding = trim_ascii_whitespace(
          coding
            .split(|byte| *byte == b';')
            .next()
            .unwrap_or_default(),
        );
        if coding.is_empty() || !coding.iter().all(|byte| is_header_name_byte(*byte)) {
          return None;
        }
        if final_transfer_coding.is_some_and(|previous| previous.eq_ignore_ascii_case(b"chunked")) {
          return None;
        }
        final_transfer_coding = Some(coding);
      }
    } else if name.eq_ignore_ascii_case(b"content-length") {
      for item in value.split(|byte| *byte == b',') {
        let item = trim_ascii_whitespace(item);
        if item.is_empty() || !item.iter().all(u8::is_ascii_digit) {
          return None;
        }
        let length = std::str::from_utf8(item).ok()?.parse::<u64>().ok()?;
        if content_length.is_some_and(|existing| existing != length) {
          return None;
        }
        content_length = Some(length);
      }
    }
    if line_end == headers.len() {
      break;
    }
    headers = &headers[line_end + 2..];
  }
  if has_transfer_encoding && content_length.is_some() {
    return None;
  }
  if has_transfer_encoding
    && !final_transfer_coding.is_some_and(|coding| coding.eq_ignore_ascii_case(b"chunked"))
  {
    return None;
  }
  Some((has_transfer_encoding, content_length))
}

enum ResponseBodyTracker {
  Fixed(u64),
  Chunked(ChunkDecoder),
  CloseDelimited,
}
impl ResponseBodyTracker {
  fn new(body: ResponseBody, max_bytes: usize) -> Option<Self> {
    match body {
      ResponseBody::Fixed(0) => None,
      ResponseBody::Fixed(length) => Some(Self::Fixed(length)),
      ResponseBody::Chunked => Some(Self::Chunked(ChunkDecoder::new(max_bytes))),
      ResponseBody::CloseDelimited => Some(Self::CloseDelimited),
      ResponseBody::NoBody => None,
    }
  }
  fn consume(&mut self, input: &[u8]) -> BodyProgress {
    match self {
      Self::Fixed(remaining) => {
        let consumed = input
          .len()
          .min(usize::try_from(*remaining).unwrap_or(usize::MAX));
        *remaining -= consumed as u64;
        if *remaining == 0 {
          BodyProgress::Complete
        } else {
          BodyProgress::Pending
        }
      }
      Self::Chunked(decoder) => {
        let progress = decoder.consume(input);
        if progress.invalid {
          BodyProgress::Invalid
        } else if progress.complete {
          BodyProgress::Complete
        } else {
          BodyProgress::Pending
        }
      }
      // A close-delimited response completes only when AsyncWrite::poll_shutdown
      // is called. Until then, forward every body write while keeping request
      // reads blocked so optimistic tunnel bytes cannot become a new request.
      Self::CloseDelimited => BodyProgress::Pending,
    }
  }
}
enum BodyProgress {
  Pending,
  Complete,
  Invalid,
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn waits_through_bounded_informational_responses() {
    let mut parser = ResponseHeadParser::new(TunnelKind::Upgrade, 256);
    assert!(matches!(
      parser.consume(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 10"),
      ResponseHeadOutcome::Pending
    ));
    assert!(matches!(
      parser.consume(b"3 Early Hints\r\nLink: </style.css>\r\n\r\nHTTP/1.1 404 Not Found\r\n\r\n"),
      ResponseHeadOutcome::Rejected
    ));
  }
  #[test]
  fn accepts_only_the_response_for_the_pending_tunnel_kind() {
    let mut upgrade = ResponseHeadParser::new(TunnelKind::Upgrade, 128);
    assert!(matches!(
      upgrade.consume(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"),
      ResponseHeadOutcome::Accepted
    ));
    let mut connect = ResponseHeadParser::new(TunnelKind::Connect, 128);
    assert!(matches!(
      connect.consume(b"HTTP/1.1 200 OK\r\n\r\n"),
      ResponseHeadOutcome::Accepted
    ));
  }
  #[test]
  fn connect_rejection_waits_for_the_framed_body_in_the_same_write() {
    let mut parser = ResponseHeadParser::new(TunnelKind::Connect, 128);
    assert!(matches!(
      parser.consume(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\r\nden"),
      ResponseHeadOutcome::ConnectRejectionPending
    ));
    assert!(matches!(
      parser.consume(b"ied"),
      ResponseHeadOutcome::Rejected
    ));
  }

  #[test]
  fn connect_rejection_tracks_chunked_body_and_trailers() {
    let mut parser = ResponseHeadParser::new(TunnelKind::Connect, 256);
    assert!(matches!(
      parser.consume(b"HTTP/1.1 502 Bad Gateway\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nde"),
      ResponseHeadOutcome::ConnectRejectionPending
    ));
    assert!(matches!(
      parser.consume(b"n\r\n0\r\nX-Test: complete\r\n\r\n"),
      ResponseHeadOutcome::Rejected
    ));
  }

  #[test]
  fn connect_rejection_with_zero_length_body_is_immediately_terminal() {
    let mut parser = ResponseHeadParser::new(TunnelKind::Connect, 128);
    assert!(matches!(
      parser.consume(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"),
      ResponseHeadOutcome::Rejected
    ));
  }

  #[test]
  fn successful_connect_rejects_http_message_body_framing() {
    for response in [
      b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".as_slice(),
      b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
    ] {
      let mut parser = ResponseHeadParser::new(TunnelKind::Connect, 128);
      assert!(matches!(
        parser.consume(response),
        ResponseHeadOutcome::Invalid
      ));
    }
  }

  #[test]
  fn close_delimited_connect_rejection_waits_for_shutdown() {
    let mut parser = ResponseHeadParser::new(TunnelKind::Connect, 128);
    assert!(matches!(
      parser.consume(b"HTTP/1.0 403 Forbidden\r\n\r\ndenied"),
      ResponseHeadOutcome::ConnectRejectionPending
    ));
    assert!(matches!(
      parser.consume(b"-continued"),
      ResponseHeadOutcome::ConnectRejectionPending
    ));
  }
  #[test]
  fn malformed_or_oversized_heads_fail_closed() {
    let mut malformed = ResponseHeadParser::new(TunnelKind::Upgrade, 128);
    assert!(matches!(
      malformed.consume(b"HTTP/1.1 101 Switching Protocols\r\nBroken\r\n\r\n"),
      ResponseHeadOutcome::Invalid
    ));
    let mut oversized = ResponseHeadParser::new(TunnelKind::Upgrade, 16);
    assert!(matches!(
      oversized.consume(b"HTTP/1.1 101 Switching Protocols\r\n\r\n"),
      ResponseHeadOutcome::Invalid
    ));
  }
}

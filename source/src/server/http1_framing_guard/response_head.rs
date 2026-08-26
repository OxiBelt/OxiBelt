use super::is_header_name_byte;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TunnelKind {
  Connect,
  Upgrade,
}

pub(super) enum ResponseHeadOutcome {
  Pending,
  Accepted,
  Rejected,
  Invalid,
}

pub(super) struct ResponseHeadParser {
  kind: TunnelKind,
  max_bytes: usize,
  observed_bytes: usize,
  buffered: Vec<u8>,
}

impl ResponseHeadParser {
  pub(super) fn new(kind: TunnelKind, max_bytes: usize) -> Self {
    Self {
      kind,
      max_bytes: max_bytes.max(1),
      observed_bytes: 0,
      buffered: Vec::with_capacity(256.min(max_bytes)),
    }
  }

  pub(super) fn consume(&mut self, input: &[u8]) -> ResponseHeadOutcome {
    for byte in input {
      if self.observed_bytes >= self.max_bytes {
        return ResponseHeadOutcome::Invalid;
      }
      self.observed_bytes += 1;
      self.buffered.push(*byte);
      if !self.buffered.ends_with(b"\r\n\r\n") {
        continue;
      }

      let Some(status) = response_status(&self.buffered) else {
        return ResponseHeadOutcome::Invalid;
      };
      if status == 101 {
        return if self.kind == TunnelKind::Upgrade {
          ResponseHeadOutcome::Accepted
        } else {
          ResponseHeadOutcome::Rejected
        };
      }
      if (100..200).contains(&status) {
        self.buffered.clear();
        continue;
      }
      if self.kind == TunnelKind::Connect && (200..300).contains(&status) {
        return ResponseHeadOutcome::Accepted;
      }
      return ResponseHeadOutcome::Rejected;
    }
    ResponseHeadOutcome::Pending
  }
}

fn response_status(head: &[u8]) -> Option<u16> {
  let lines = head.strip_suffix(b"\r\n\r\n")?;
  let status_line_end = memchr::memmem::find(lines, b"\r\n").unwrap_or(lines.len());
  let status_line = &lines[..status_line_end];
  let remaining = if status_line_end == lines.len() {
    &[][..]
  } else {
    &lines[status_line_end + 2..]
  };
  validate_status_line(status_line).and_then(|status| validate_headers(remaining).then_some(status))
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

fn validate_headers(mut headers: &[u8]) -> bool {
  while !headers.is_empty() {
    let line_end = memchr::memmem::find(headers, b"\r\n").unwrap_or(headers.len());
    let line = &headers[..line_end];
    let Some(colon) = memchr::memchr(b':', line) else {
      return false;
    };
    if colon == 0
      || !line[..colon].iter().all(|byte| is_header_name_byte(*byte))
      || line[colon + 1..]
        .iter()
        .any(|byte| byte.is_ascii_control() && *byte != b'\t')
    {
      return false;
    }
    if line_end == headers.len() {
      return true;
    }
    headers = &headers[line_end + 2..];
  }
  true
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

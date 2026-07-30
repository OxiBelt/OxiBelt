use http::header::{CONNECTION, CONTENT_LENGTH, HOST, TE, TRAILER, TRANSFER_ENCODING, UPGRADE};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Version};

use super::types::{ResponseBodyMode, ResponseProtocolFailureReason, ResponseProtocolLimits};

const MAX_HEADER_NAME_BYTES: usize = 128;

pub(super) fn parse_head(
  bytes: &[u8],
  limits: ResponseProtocolLimits,
) -> Result<(Version, StatusCode, HeaderMap), ResponseProtocolFailureReason> {
  let status_line_end =
    find_bytes(bytes, b"\r\n").ok_or(ResponseProtocolFailureReason::InvalidStatusLine)?;
  validate_status_line(&bytes[..status_line_end])?;
  validate_raw_fields(
    &bytes[status_line_end + 2..bytes.len() - 2],
    limits.max_response_header_fields,
    limits.max_response_header_field_bytes,
    ResponseProtocolFailureReason::TooManyHeaders,
    ResponseProtocolFailureReason::HeaderFieldTooLarge,
    ResponseProtocolFailureReason::InvalidHeaderSyntax,
  )?;

  let mut parsed_headers = vec![httparse::EMPTY_HEADER; limits.max_response_header_fields];
  let mut response = httparse::Response::new(&mut parsed_headers);
  let status = response.parse(bytes).map_err(|error| match error {
    httparse::Error::TooManyHeaders => ResponseProtocolFailureReason::TooManyHeaders,
    httparse::Error::Status | httparse::Error::Version => {
      ResponseProtocolFailureReason::InvalidStatusLine
    }
    _ => ResponseProtocolFailureReason::InvalidHeaderSyntax,
  })?;
  if !status.is_complete() {
    return Err(ResponseProtocolFailureReason::InvalidHeaderSyntax);
  }
  let version = match response.version {
    Some(0) => Version::HTTP_10,
    Some(1) => Version::HTTP_11,
    _ => return Err(ResponseProtocolFailureReason::InvalidStatusLine),
  };
  let status = StatusCode::from_u16(
    response
      .code
      .ok_or(ResponseProtocolFailureReason::InvalidStatusLine)?,
  )
  .map_err(|_| ResponseProtocolFailureReason::InvalidStatusLine)?;
  let mut headers = HeaderMap::with_capacity(response.headers.len());
  for header in response.headers {
    let name = HeaderName::from_bytes(header.name.as_bytes())
      .map_err(|_| ResponseProtocolFailureReason::InvalidHeaderSyntax)?;
    let value = HeaderValue::from_bytes(header.value)
      .map_err(|_| ResponseProtocolFailureReason::InvalidHeaderSyntax)?;
    headers.append(name, value);
  }
  Ok((version, status, headers))
}

pub(super) fn response_body_mode(
  request_method: &Method,
  version: Version,
  status: StatusCode,
  headers: &HeaderMap,
) -> Result<ResponseBodyMode, ResponseProtocolFailureReason> {
  let transfer_encoding = parse_transfer_encoding(headers)?;
  let content_length = parse_content_length(headers)?;
  if transfer_encoding && version != Version::HTTP_11 {
    return Err(ResponseProtocolFailureReason::InvalidTransferCodingSequence);
  }
  if transfer_encoding && content_length.is_some() {
    return Err(ResponseProtocolFailureReason::InvalidTransferCodingSequence);
  }
  if request_method == Method::HEAD
    || status == StatusCode::NO_CONTENT
    || status == StatusCode::NOT_MODIFIED
  {
    return Ok(ResponseBodyMode::None);
  }
  if transfer_encoding {
    return Ok(ResponseBodyMode::Chunked);
  }
  if let Some(length) = content_length {
    return Ok(ResponseBodyMode::ContentLength(length));
  }
  Ok(ResponseBodyMode::CloseDelimited)
}

pub(super) fn parse_trailers(
  bytes: &[u8],
  limits: ResponseProtocolLimits,
) -> Result<HeaderMap, ResponseProtocolFailureReason> {
  if bytes == b"\r\n" {
    return Ok(HeaderMap::new());
  }
  let fields = bytes
    .strip_suffix(b"\r\n\r\n")
    .ok_or(ResponseProtocolFailureReason::InvalidTrailerField)?;
  validate_raw_fields(
    fields,
    limits.max_trailer_fields,
    limits.max_trailer_field_bytes,
    ResponseProtocolFailureReason::TooManyTrailers,
    ResponseProtocolFailureReason::TrailerFieldTooLarge,
    ResponseProtocolFailureReason::InvalidTrailerField,
  )?;
  let mut trailers = HeaderMap::with_capacity(limits.max_trailer_fields.min(16));
  for line in split_crlf(fields) {
    let colon = line
      .iter()
      .position(|byte| *byte == b':')
      .ok_or(ResponseProtocolFailureReason::InvalidTrailerField)?;
    let name = HeaderName::from_bytes(&line[..colon])
      .map_err(|_| ResponseProtocolFailureReason::InvalidTrailerField)?;
    if is_forbidden_trailer_name(&name) {
      return Err(ResponseProtocolFailureReason::InvalidTrailerField);
    }
    let value = HeaderValue::from_bytes(trim_ows(&line[colon + 1..]))
      .map_err(|_| ResponseProtocolFailureReason::InvalidTrailerField)?;
    trailers.append(name, value);
  }
  Ok(trailers)
}

fn validate_status_line(line: &[u8]) -> Result<(), ResponseProtocolFailureReason> {
  let valid_version = line.starts_with(b"HTTP/1.0 ") || line.starts_with(b"HTTP/1.1 ");
  if !valid_version || line.len() < 12 {
    return Err(ResponseProtocolFailureReason::InvalidStatusLine);
  }
  let status = &line[9..12];
  if !status.iter().all(u8::is_ascii_digit)
    || (line.len() > 12 && line[12] != b' ')
    || line[12..]
      .iter()
      .any(|byte| (*byte < b' ' && *byte != b'\t') || *byte == 0x7f)
  {
    return Err(ResponseProtocolFailureReason::InvalidStatusLine);
  }
  Ok(())
}

fn validate_raw_fields(
  bytes: &[u8],
  max_fields: usize,
  max_field_bytes: usize,
  count_reason: ResponseProtocolFailureReason,
  size_reason: ResponseProtocolFailureReason,
  syntax_reason: ResponseProtocolFailureReason,
) -> Result<(), ResponseProtocolFailureReason> {
  if bytes.is_empty() {
    return Ok(());
  }
  let mut fields = 0usize;
  for line in split_crlf(bytes) {
    if line.is_empty() {
      return Err(syntax_reason);
    }
    fields = fields.saturating_add(1);
    if fields > max_fields {
      return Err(count_reason);
    }
    if line.len() > max_field_bytes {
      return Err(size_reason);
    }
    let colon = line
      .iter()
      .position(|byte| *byte == b':')
      .ok_or(syntax_reason)?;
    if colon == 0
      || colon > MAX_HEADER_NAME_BYTES
      || !line[..colon].iter().copied().all(is_token_byte)
    {
      return Err(syntax_reason);
    }
  }
  Ok(())
}

fn parse_transfer_encoding(headers: &HeaderMap) -> Result<bool, ResponseProtocolFailureReason> {
  let values = headers.get_all(TRANSFER_ENCODING);
  let mut combined = Vec::new();
  for value in values.iter() {
    if !combined.is_empty() {
      combined.push(b',');
    }
    combined.extend_from_slice(value.as_bytes());
  }
  if combined.is_empty() {
    return Ok(false);
  }
  let codings = split_quoted_commas(&combined)
    .ok_or(ResponseProtocolFailureReason::InvalidTransferCodingSequence)?;
  if codings.len() != 1 {
    return Err(ResponseProtocolFailureReason::InvalidTransferCodingSequence);
  }
  let coding = trim_ows(codings[0]);
  let (name, parameter_count) = split_coding_parameters(coding)
    .ok_or(ResponseProtocolFailureReason::InvalidTransferCodingSequence)?;
  if !name.eq_ignore_ascii_case(b"chunked") || parameter_count != 0 {
    return Err(ResponseProtocolFailureReason::InvalidTransferCodingSequence);
  }
  Ok(true)
}

fn parse_content_length(headers: &HeaderMap) -> Result<Option<u64>, ResponseProtocolFailureReason> {
  let mut observed = None;
  for value in headers.get_all(CONTENT_LENGTH).iter() {
    for member in value.as_bytes().split(|byte| *byte == b',') {
      let member = trim_ows(member);
      if member.is_empty() || !member.iter().all(u8::is_ascii_digit) {
        return Err(ResponseProtocolFailureReason::InvalidHeaderSyntax);
      }
      let mut parsed = 0u64;
      for digit in member {
        parsed = parsed
          .checked_mul(10)
          .and_then(|value| value.checked_add(u64::from(*digit - b'0')))
          .ok_or(ResponseProtocolFailureReason::InvalidHeaderSyntax)?;
      }
      if observed.is_some_and(|existing| existing != parsed) {
        return Err(ResponseProtocolFailureReason::InvalidHeaderSyntax);
      }
      observed = Some(parsed);
    }
  }
  Ok(observed)
}

fn is_forbidden_trailer_name(name: &HeaderName) -> bool {
  name == CONTENT_LENGTH
    || name == TRANSFER_ENCODING
    || name == HOST
    || name == CONNECTION
    || name == TE
    || name == TRAILER
    || name == UPGRADE
    || matches!(name.as_str(), "keep-alive" | "proxy-connection")
}

fn split_coding_parameters(bytes: &[u8]) -> Option<(&[u8], usize)> {
  let semicolon = bytes.iter().position(|byte| *byte == b';');
  let name = trim_ows(&bytes[..semicolon.unwrap_or(bytes.len())]);
  if name.is_empty() || !name.iter().copied().all(is_token_byte) {
    return None;
  }
  let mut parameter_count = 0usize;
  let mut rest = semicolon.map(|index| &bytes[index..]).unwrap_or_default();
  while !rest.is_empty() {
    if rest.first() != Some(&b';') {
      return None;
    }
    rest = trim_ows(&rest[1..]);
    let name_len = rest
      .iter()
      .copied()
      .take_while(|byte| is_token_byte(*byte))
      .count();
    if name_len == 0 {
      return None;
    }
    rest = trim_ows(&rest[name_len..]);
    if rest.first() != Some(&b'=') {
      return None;
    }
    rest = trim_ows(&rest[1..]);
    let value_len = parse_token_or_quoted(rest)?;
    parameter_count = parameter_count.saturating_add(1);
    rest = trim_ows(&rest[value_len..]);
  }
  Some((name, parameter_count))
}

fn split_quoted_commas(bytes: &[u8]) -> Option<Vec<&[u8]>> {
  let mut parts = Vec::new();
  let mut start = 0usize;
  let mut quoted = false;
  let mut escaped = false;
  for (index, byte) in bytes.iter().enumerate() {
    if escaped {
      escaped = false;
      continue;
    }
    match *byte {
      b'\\' if quoted => escaped = true,
      b'"' => quoted = !quoted,
      b',' if !quoted => {
        let part = trim_ows(&bytes[start..index]);
        if part.is_empty() {
          return None;
        }
        parts.push(part);
        start = index + 1;
      }
      _ => {}
    }
  }
  if quoted || escaped {
    return None;
  }
  let part = trim_ows(&bytes[start..]);
  if part.is_empty() {
    return None;
  }
  parts.push(part);
  Some(parts)
}

fn parse_token_or_quoted(bytes: &[u8]) -> Option<usize> {
  if bytes.first() == Some(&b'"') {
    let mut escaped = false;
    for (index, byte) in bytes.iter().enumerate().skip(1) {
      if escaped {
        if (*byte < b' ' && *byte != b'\t') || *byte == 0x7f {
          return None;
        }
        escaped = false;
      } else if *byte == b'\\' {
        escaped = true;
      } else if *byte == b'"' {
        return Some(index + 1);
      } else if (*byte < b' ' && *byte != b'\t') || *byte == 0x7f {
        return None;
      }
    }
    return None;
  }
  let len = bytes
    .iter()
    .copied()
    .take_while(|byte| is_token_byte(*byte))
    .count();
  (len > 0).then_some(len)
}

fn split_crlf(mut bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
  std::iter::from_fn(move || {
    if bytes.is_empty() {
      return None;
    }
    let (line, rest) = match find_bytes(bytes, b"\r\n") {
      Some(index) => (&bytes[..index], &bytes[index + 2..]),
      None => (bytes, &[][..]),
    };
    bytes = rest;
    Some(line)
  })
}

fn trim_ows(bytes: &[u8]) -> &[u8] {
  let start = bytes
    .iter()
    .position(|byte| *byte != b' ' && *byte != b'\t')
    .unwrap_or(bytes.len());
  let end = bytes
    .iter()
    .rposition(|byte| *byte != b' ' && *byte != b'\t')
    .map(|index| index + 1)
    .unwrap_or(start);
  &bytes[start..end]
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
  memchr::memmem::find(haystack, needle)
}

fn is_token_byte(byte: u8) -> bool {
  matches!(
    byte,
    b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'0'..=b'9' | b'A'..=b'Z'
      | b'^' | b'_' | b'`' | b'a'..=b'z' | b'|' | b'~'
  )
}

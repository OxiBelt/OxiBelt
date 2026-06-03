//! Cached byte-range response construction.

use std::io::{Read, Seek, SeekFrom};

use bytes::{Bytes, BytesMut};
use http::header::{
  ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, LAST_MODIFIED, RANGE,
};
use http::{HeaderMap, HeaderValue, Method, StatusCode};

use super::CacheEntry;

const MULTIPART_BOUNDARY: &str = "oxibelt-cache-boundary";
const MAX_MULTIPART_RANGES: usize = 16;
const MAX_MULTIPART_BODY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
struct ByteRange {
  start: usize,
  end: usize,
}

impl ByteRange {
  fn len(self) -> usize {
    self.end - self.start + 1
  }
}

pub(crate) fn range_entry(
  entry: CacheEntry,
  method: &Method,
  request_headers: &HeaderMap,
) -> CacheEntry {
  if method == Method::HEAD {
    return entry.with_body(Bytes::new());
  }
  let Some(range) = request_headers
    .get(RANGE)
    .and_then(|value| value.to_str().ok())
  else {
    return entry;
  };
  if !if_range_allows_range(&entry, request_headers) {
    return entry;
  }
  let full_len = entry.body_len;
  let Some(ranges) = parse_byte_ranges(range, full_len) else {
    return unsatisfiable_entry(entry, full_len);
  };
  if ranges.len() == 1 {
    return single_range_entry(entry, ranges[0], full_len);
  }
  multipart_range_entry(entry, &ranges, full_len)
}

fn single_range_entry(entry: CacheEntry, range: ByteRange, full_len: usize) -> CacheEntry {
  let mut headers = entry.headers.clone();
  headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
  if let Ok(value) =
    HeaderValue::from_str(&format!("bytes {}-{}/{}", range.start, range.end, full_len))
  {
    headers.insert(CONTENT_RANGE, value);
  }
  if let Ok(value) = HeaderValue::from_str(&range.len().to_string()) {
    headers.insert(CONTENT_LENGTH, value);
  }
  if entry.body_file.is_some() {
    return CacheEntry {
      status: StatusCode::PARTIAL_CONTENT,
      headers,
      ..entry.with_file_range(range.start as u64, range.len())
    };
  }
  let body = entry.body.slice(range.start..range.end + 1);
  CacheEntry {
    status: StatusCode::PARTIAL_CONTENT,
    headers,
    ..entry.with_body(body)
  }
}

fn multipart_range_entry(entry: CacheEntry, ranges: &[ByteRange], full_len: usize) -> CacheEntry {
  if ranges.len() > MAX_MULTIPART_RANGES {
    return entry;
  }
  let content_type = entry
    .headers
    .get(CONTENT_TYPE)
    .and_then(|value| value.to_str().ok())
    .unwrap_or("application/octet-stream")
    .to_string();
  let Some(body_len) = multipart_body_len(&content_type, ranges, full_len)
    .filter(|body_len| *body_len <= MAX_MULTIPART_BODY_BYTES)
  else {
    return entry;
  };
  let mut body = BytesMut::with_capacity(body_len);
  for range in ranges {
    body.extend_from_slice(format!("\r\n--{MULTIPART_BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
    body.extend_from_slice(
      format!(
        "Content-Range: bytes {}-{}/{}\r\n\r\n",
        range.start, range.end, full_len
      )
      .as_bytes(),
    );
    let Some(bytes) = entry_range_bytes(&entry, *range) else {
      return entry;
    };
    body.extend_from_slice(&bytes);
  }
  body.extend_from_slice(format!("\r\n--{MULTIPART_BOUNDARY}--\r\n").as_bytes());
  let body = body.freeze();
  let mut headers = entry.headers.clone();
  headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
  headers.remove(CONTENT_RANGE);
  headers.insert(
    CONTENT_TYPE,
    HeaderValue::from_str(&format!(
      "multipart/byteranges; boundary={MULTIPART_BOUNDARY}"
    ))
    .unwrap_or_else(|_| HeaderValue::from_static("multipart/byteranges")),
  );
  if let Ok(value) = HeaderValue::from_str(&body.len().to_string()) {
    headers.insert(CONTENT_LENGTH, value);
  }
  CacheEntry {
    status: StatusCode::PARTIAL_CONTENT,
    headers,
    ..entry.with_body(body)
  }
}

fn multipart_body_len(content_type: &str, ranges: &[ByteRange], full_len: usize) -> Option<usize> {
  let mut len = 0usize;
  for range in ranges {
    len = len.checked_add(format!("\r\n--{MULTIPART_BOUNDARY}\r\n").len())?;
    len = len.checked_add(format!("Content-Type: {content_type}\r\n").len())?;
    len = len.checked_add(
      format!(
        "Content-Range: bytes {}-{}/{}\r\n\r\n",
        range.start, range.end, full_len
      )
      .len(),
    )?;
    len = len.checked_add(range.len())?;
  }
  len.checked_add(format!("\r\n--{MULTIPART_BOUNDARY}--\r\n").len())
}

fn unsatisfiable_entry(entry: CacheEntry, full_len: usize) -> CacheEntry {
  let mut headers = entry.headers.clone();
  headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
  headers.insert(
    CONTENT_RANGE,
    HeaderValue::from_str(&format!("bytes */{full_len}"))
      .unwrap_or_else(|_| HeaderValue::from_static("bytes */0")),
  );
  headers.remove(CONTENT_LENGTH);
  CacheEntry {
    status: StatusCode::RANGE_NOT_SATISFIABLE,
    headers,
    ..entry.with_body(Bytes::new())
  }
}

fn entry_range_bytes(entry: &CacheEntry, range: ByteRange) -> Option<Bytes> {
  if let Some(file) = &entry.body_file {
    let mut reader = std::fs::File::open(&file.path).ok()?;
    reader
      .seek(SeekFrom::Start(file.offset + range.start as u64))
      .ok()?;
    let mut bytes = vec![0_u8; range.len()];
    reader.read_exact(&mut bytes).ok()?;
    return Some(Bytes::from(bytes));
  }
  Some(entry.body.slice(range.start..range.end + 1))
}

fn parse_byte_ranges(range: &str, len: usize) -> Option<Vec<ByteRange>> {
  let range = range.strip_prefix("bytes=")?;
  if len == 0 {
    return None;
  }
  let mut ranges = Vec::new();
  for item in range.split(',') {
    let item = item.trim();
    if item.is_empty() {
      return None;
    }
    let (start, end) = item.split_once('-')?;
    let parsed = if start.is_empty() {
      let suffix = end.parse::<usize>().ok()?;
      if suffix == 0 {
        return None;
      }
      let start = len.saturating_sub(suffix);
      ByteRange {
        start,
        end: len - 1,
      }
    } else {
      let start = start.parse::<usize>().ok()?;
      let end = if end.is_empty() {
        len - 1
      } else {
        end.parse::<usize>().ok()?
      };
      if start > end || start >= len {
        return None;
      }
      ByteRange {
        start,
        end: end.min(len - 1),
      }
    };
    ranges.push(parsed);
  }
  (!ranges.is_empty()).then_some(ranges)
}

fn if_range_allows_range(entry: &CacheEntry, request_headers: &HeaderMap) -> bool {
  let Some(value) = request_headers
    .get("if-range")
    .and_then(|value| value.to_str().ok())
    .map(str::trim)
  else {
    return true;
  };
  if value.starts_with("W/") {
    return false;
  }
  if let Some(etag) = entry
    .headers
    .get(ETAG)
    .and_then(|value| value.to_str().ok())
    && value == etag
  {
    return true;
  }
  let Some(last_modified) = entry
    .headers
    .get(LAST_MODIFIED)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| httpdate::parse_http_date(value).ok())
  else {
    return false;
  };
  let Some(if_range_date) = httpdate::parse_http_date(value).ok() else {
    return false;
  };
  if_range_date >= last_modified
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_multiple_byte_ranges() {
    let ranges = parse_byte_ranges("bytes=0-1, 8-", 10).unwrap();
    assert_eq!(ranges[0].start, 0);
    assert_eq!(ranges[0].end, 1);
    assert_eq!(ranges[1].start, 8);
    assert_eq!(ranges[1].end, 9);
  }
}

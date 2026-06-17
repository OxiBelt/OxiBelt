//! Static-file response planning.
//! Range and conditional-request decisions are computed before streaming file contents.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use bytes::Bytes;
use futures_util::StreamExt;
use http::header::{
  ACCEPT_RANGES, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE,
  ETAG, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, RANGE, VARY,
};
use http::{HeaderMap, Method, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::body::{Body, Frame, SizeHint};
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;
use tracing::warn;

use super::{CachedStaticObject, StaticBodyPlan, StaticFileBodyPlan, StaticResponsePlan};
use crate::proxy::http::body::{
  BoxError, InlinedKnownSmallResponseBody, KnownSmallResponseBody, ProxyBody, boxed_error,
  is_known_small_response_body_len,
};
use crate::proxy::http::response::text_response;

const STATIC_BODY_CHANNEL_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy)]
pub(crate) enum StaticBodySource {
  HotObject,
}

impl StaticBodySource {
  pub(crate) fn metric_label(self) -> &'static str {
    match self {
      Self::HotObject => "hot_object",
    }
  }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct StaticResponseMetadata {
  pub(crate) content_type: String,
  pub(crate) content_encoding: Option<&'static str>,
  pub(crate) cache_control: Option<String>,
  pub(crate) vary_accept_encoding: bool,
}

impl StaticResponseMetadata {
  #[cfg(test)]
  pub(crate) fn for_path(path: &Path) -> Self {
    Self {
      content_type: content_type_for_path(path).to_string(),
      content_encoding: None,
      cache_control: None,
      vary_accept_encoding: false,
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum RangeSelection {
  Full,
  Partial { start: u64, end: u64 },
  NotSatisfiable,
}

pub(crate) async fn response_from_plan(
  plan: StaticResponsePlan,
  inline_max_bytes: usize,
) -> Response<ProxyBody> {
  let StaticResponsePlan {
    status,
    headers,
    body,
  } = plan;
  let mut response = match body {
    StaticBodyPlan::Empty => Response::new(empty_body()),
    StaticBodyPlan::Text(message) => text_response(status, &message),
    StaticBodyPlan::Bytes { bytes, .. } => {
      let mut response = Response::new(full_body(bytes.clone()));
      if bytes.len() <= inline_max_bytes {
        response.extensions_mut().insert(KnownSmallResponseBody);
        if is_known_small_response_body_len(bytes.len()) {
          response
            .extensions_mut()
            .insert(InlinedKnownSmallResponseBody::new(bytes, None));
        }
      }
      response
    }
    StaticBodyPlan::File(file) => {
      let path = file.path.clone();
      match file_body(
        file.file,
        path.clone(),
        file.offset,
        file.len,
        inline_max_bytes,
      )
      .await
      {
        Ok((body, known_small)) => {
          let mut response = Response::new(body);
          if known_small {
            response.extensions_mut().insert(KnownSmallResponseBody);
          }
          response
        }
        Err(error) => {
          warn!(error = %error, path = %path.display(), "failed to read static file");
          return text_response(StatusCode::NOT_FOUND, "not found");
        }
      }
    }
  };
  *response.status_mut() = status;
  for (name, value) in headers {
    if let Some(name) = name {
      response.headers_mut().insert(name, value);
    }
  }
  response
}

pub(super) fn cached_object_plan(
  method: &Method,
  headers: &HeaderMap,
  cached: Arc<CachedStaticObject>,
) -> StaticResponsePlan {
  let len = cached.body.len() as u64;
  if conditional_not_modified(headers, &cached.etag, cached.modified) {
    return not_modified_plan(&cached.etag, cached.modified, &cached.response_metadata);
  }

  let range = match headers.get(RANGE) {
    Some(value) => parse_range(value, len),
    None => RangeSelection::Full,
  };
  match range {
    RangeSelection::NotSatisfiable => range_not_satisfiable_plan(len),
    RangeSelection::Full => cached_full_bytes_plan(method, cached),
    RangeSelection::Partial { start, end } => {
      let etag = cached.etag.clone();
      let response_metadata = cached.response_metadata.clone();
      bytes_plan(
        method,
        StatusCode::PARTIAL_CONTENT,
        cached.path.clone(),
        cached.body.clone(),
        FileContentPlan {
          offset: start,
          body_len: end - start + 1,
          content_range: Some((start, end, len)),
        },
        &etag,
        cached.modified,
        &response_metadata,
      )
    }
  }
}

fn cached_full_bytes_plan(method: &Method, cached: Arc<CachedStaticObject>) -> StaticResponsePlan {
  let headers = cached.full_headers.clone();
  let body = if method == Method::HEAD || cached.body.is_empty() {
    StaticBodyPlan::Empty
  } else {
    StaticBodyPlan::Bytes {
      bytes: cached.body.clone(),
      source: StaticBodySource::HotObject,
    }
  };
  StaticResponsePlan {
    status: StatusCode::OK,
    headers,
    body,
  }
}

pub(super) struct FileContentPlan {
  pub(super) offset: u64,
  pub(super) body_len: u64,
  pub(super) content_range: Option<(u64, u64, u64)>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn file_plan(
  method: &Method,
  status: StatusCode,
  path: PathBuf,
  file: File,
  content: FileContentPlan,
  etag: &str,
  modified: Option<SystemTime>,
  response_metadata: &StaticResponseMetadata,
) -> StaticResponsePlan {
  let mut headers = HeaderMap::new();
  set_common_headers(
    &mut headers,
    content.body_len,
    etag,
    modified,
    response_metadata,
  );
  if let Some((start, end, full_len)) = content.content_range
    && let Ok(value) = HeaderValue::from_str(&format!("bytes {start}-{end}/{full_len}"))
  {
    headers.insert(CONTENT_RANGE, value);
  }
  let body = if method == Method::HEAD || content.body_len == 0 {
    StaticBodyPlan::Empty
  } else {
    StaticBodyPlan::File(StaticFileBodyPlan {
      file,
      path,
      offset: content.offset,
      len: content.body_len,
    })
  };
  StaticResponsePlan {
    status,
    headers,
    body,
  }
}

#[allow(clippy::too_many_arguments)]
fn bytes_plan(
  method: &Method,
  status: StatusCode,
  _path: PathBuf,
  bytes: Bytes,
  content: FileContentPlan,
  etag: &str,
  modified: Option<SystemTime>,
  response_metadata: &StaticResponseMetadata,
) -> StaticResponsePlan {
  let mut headers = HeaderMap::new();
  set_common_headers(
    &mut headers,
    content.body_len,
    etag,
    modified,
    response_metadata,
  );
  if let Some((start, end, full_len)) = content.content_range
    && let Ok(value) = HeaderValue::from_str(&format!("bytes {start}-{end}/{full_len}"))
  {
    headers.insert(CONTENT_RANGE, value);
  }
  let body = if method == Method::HEAD || content.body_len == 0 {
    StaticBodyPlan::Empty
  } else if content.offset == 0 && content.body_len == bytes.len() as u64 {
    StaticBodyPlan::Bytes {
      bytes,
      source: StaticBodySource::HotObject,
    }
  } else {
    let start = content.offset as usize;
    let end = start + content.body_len as usize;
    StaticBodyPlan::Bytes {
      bytes: bytes.slice(start..end),
      source: StaticBodySource::HotObject,
    }
  };
  StaticResponsePlan {
    status,
    headers,
    body,
  }
}

pub(super) async fn read_file_bytes_for_cache(
  file: &mut File,
  path: &Path,
  len: u64,
) -> anyhow::Result<Vec<u8>> {
  file
    .seek(std::io::SeekFrom::Start(0))
    .await
    .with_context(|| format!("failed to seek static file {}", path.display()))?;
  let mut bytes = Vec::with_capacity(len as usize);
  file
    .take(len)
    .read_to_end(&mut bytes)
    .await
    .with_context(|| format!("failed to read static file {}", path.display()))?;
  if bytes.len() as u64 != len {
    bail!(
      "static file {} changed while reading for cache",
      path.display()
    );
  }
  Ok(bytes)
}

async fn file_body(
  mut file: File,
  path: PathBuf,
  offset: u64,
  len: u64,
  inline_max_bytes: usize,
) -> anyhow::Result<(ProxyBody, bool)> {
  file
    .seek(std::io::SeekFrom::Start(offset))
    .await
    .with_context(|| format!("failed to seek static file {}", path.display()))?;
  if inline_max_bytes > 0 && len <= inline_max_bytes as u64 {
    let mut bytes = Vec::with_capacity(len as usize);
    file
      .take(len)
      .read_to_end(&mut bytes)
      .await
      .with_context(|| format!("failed to read static file {}", path.display()))?;
    return Ok((full_body(Bytes::from(bytes)), true));
  }
  Ok((reader_body(file.take(len), len), false))
}

fn reader_body<R>(reader: R, len: u64) -> ProxyBody
where
  R: AsyncRead + Unpin + Send + Sync + 'static,
{
  let stream = ReaderStream::with_capacity(reader, STATIC_BODY_CHANNEL_CHUNK_BYTES)
    .map(|result| result.map(Frame::data).map_err(boxed_error));
  BodyExt::boxed(ExactSizeBody {
    inner: StreamBody::new(stream),
    len,
  })
}

fn full_body(bytes: Bytes) -> ProxyBody {
  Full::new(bytes)
    .map_err(|never| -> BoxError { match never {} })
    .boxed()
}

fn empty_body() -> ProxyBody {
  Empty::<Bytes>::new()
    .map_err(|never| -> BoxError { match never {} })
    .boxed()
}

struct ExactSizeBody<B> {
  inner: B,
  len: u64,
}

impl<B> Body for ExactSizeBody<B>
where
  B: Body<Data = Bytes> + Unpin,
{
  type Data = Bytes;
  type Error = B::Error;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut TaskContext<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    Pin::new(&mut self.inner).poll_frame(cx)
  }

  fn size_hint(&self) -> SizeHint {
    SizeHint::with_exact(self.len)
  }
}

fn set_common_headers(
  headers: &mut http::HeaderMap,
  body_len: u64,
  etag: &str,
  modified: Option<SystemTime>,
  response_metadata: &StaticResponseMetadata,
) {
  headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
  if let Ok(value) = HeaderValue::from_str(&body_len.to_string()) {
    headers.insert(CONTENT_LENGTH, value);
  }
  if let Ok(value) = HeaderValue::from_str(etag) {
    headers.insert(ETAG, value);
  }
  if let Some(modified) = modified
    && let Ok(value) = HeaderValue::from_str(&httpdate::fmt_http_date(modified))
  {
    headers.insert(LAST_MODIFIED, value);
  }
  apply_response_metadata(headers, response_metadata);
}

pub(super) fn not_modified_plan(
  etag: &str,
  modified: Option<SystemTime>,
  response_metadata: &StaticResponseMetadata,
) -> StaticResponsePlan {
  let mut headers = HeaderMap::new();
  headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
  if let Ok(value) = HeaderValue::from_str(etag) {
    headers.insert(ETAG, value);
  }
  if let Some(modified) = modified
    && let Ok(value) = HeaderValue::from_str(&httpdate::fmt_http_date(modified))
  {
    headers.insert(LAST_MODIFIED, value);
  }
  apply_response_metadata(&mut headers, response_metadata);
  StaticResponsePlan {
    status: StatusCode::NOT_MODIFIED,
    headers,
    body: StaticBodyPlan::Empty,
  }
}

fn apply_response_metadata(headers: &mut HeaderMap, response_metadata: &StaticResponseMetadata) {
  if let Ok(value) = HeaderValue::from_str(&response_metadata.content_type) {
    headers.insert(CONTENT_TYPE, value);
  }
  if let Some(encoding) = response_metadata.content_encoding {
    headers.insert(CONTENT_ENCODING, HeaderValue::from_static(encoding));
  }
  if let Some(cache_control) = &response_metadata.cache_control
    && let Ok(value) = HeaderValue::from_str(cache_control)
  {
    headers.insert(CACHE_CONTROL, value);
  }
  if response_metadata.vary_accept_encoding {
    headers.insert(VARY, HeaderValue::from_static("Accept-Encoding"));
  }
}

pub(super) fn range_not_satisfiable_plan(len: u64) -> StaticResponsePlan {
  let mut headers = HeaderMap::new();
  headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
  if let Ok(value) = HeaderValue::from_str(&format!("bytes */{len}")) {
    headers.insert(CONTENT_RANGE, value);
  }
  headers.insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
  StaticResponsePlan {
    status: StatusCode::RANGE_NOT_SATISFIABLE,
    headers,
    body: StaticBodyPlan::Empty,
  }
}

pub(crate) fn text_plan(status: StatusCode, message: impl Into<String>) -> StaticResponsePlan {
  let message = message.into();
  let mut headers = HeaderMap::new();
  if let Ok(value) = HeaderValue::from_str(&message.len().to_string()) {
    headers.insert(CONTENT_LENGTH, value);
  }
  headers.insert(
    CONTENT_TYPE,
    HeaderValue::from_static("text/plain; charset=utf-8"),
  );
  StaticResponsePlan {
    status,
    headers,
    body: StaticBodyPlan::Text(message),
  }
}

pub(super) fn conditional_not_modified(
  headers: &HeaderMap,
  etag: &str,
  modified: Option<SystemTime>,
) -> bool {
  if let Some(value) = headers.get(IF_NONE_MATCH)
    && let Ok(value) = value.to_str()
  {
    return value
      .split(',')
      .map(str::trim)
      .any(|candidate| candidate == "*" || candidate == etag);
  }
  let Some(modified) = modified.map(truncate_to_http_date_precision) else {
    return false;
  };
  headers
    .get(IF_MODIFIED_SINCE)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| httpdate::parse_http_date(value).ok())
    .is_some_and(|since| modified <= since)
}

fn truncate_to_http_date_precision(time: SystemTime) -> SystemTime {
  let since_epoch = time
    .duration_since(UNIX_EPOCH)
    .unwrap_or_else(|_| Duration::from_secs(0));
  UNIX_EPOCH + Duration::from_secs(since_epoch.as_secs())
}

pub(super) fn parse_range(value: &HeaderValue, len: u64) -> RangeSelection {
  if len == 0 {
    return RangeSelection::NotSatisfiable;
  }
  let Ok(value) = value.to_str() else {
    return RangeSelection::NotSatisfiable;
  };
  let Some(range) = value.trim().strip_prefix("bytes=") else {
    return RangeSelection::NotSatisfiable;
  };
  if range.contains(',') {
    return RangeSelection::NotSatisfiable;
  }
  let Some((start, end)) = range.split_once('-') else {
    return RangeSelection::NotSatisfiable;
  };
  let start = start.trim();
  let end = end.trim();
  if start.is_empty() {
    let Ok(suffix_len) = end.parse::<u64>() else {
      return RangeSelection::NotSatisfiable;
    };
    if suffix_len == 0 {
      return RangeSelection::NotSatisfiable;
    }
    let start = len.saturating_sub(suffix_len);
    return RangeSelection::Partial {
      start,
      end: len - 1,
    };
  }
  let Ok(start) = start.parse::<u64>() else {
    return RangeSelection::NotSatisfiable;
  };
  if start >= len {
    return RangeSelection::NotSatisfiable;
  }
  let end = if end.is_empty() {
    len - 1
  } else {
    let Ok(end) = end.parse::<u64>() else {
      return RangeSelection::NotSatisfiable;
    };
    end.min(len - 1)
  };
  if end < start {
    return RangeSelection::NotSatisfiable;
  }
  RangeSelection::Partial { start, end }
}

#[cfg(unix)]
pub(super) fn etag_for_metadata(metadata: &std::fs::Metadata) -> String {
  use std::os::unix::fs::MetadataExt;

  format!(
    "W/\"{:x}-{:x}-{:x}-{:x}\"",
    metadata.dev(),
    metadata.ino(),
    metadata.size(),
    metadata.mtime_nsec()
  )
}

#[cfg(not(unix))]
pub(super) fn etag_for_metadata(metadata: &std::fs::Metadata) -> String {
  let modified = metadata
    .modified()
    .ok()
    .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
    .map(|duration| duration.as_nanos())
    .unwrap_or_default();
  format!("W/\"{:x}-{modified:x}\"", metadata.len())
}

pub(crate) fn content_type_for_path(path: &Path) -> &'static str {
  match path.extension().and_then(OsStr::to_str).unwrap_or_default() {
    "avif" => "image/avif",
    "br" => "application/octet-stream",
    "css" => "text/css; charset=utf-8",
    "gif" => "image/gif",
    "gz" => "application/gzip",
    "htm" | "html" => "text/html; charset=utf-8",
    "ico" => "image/x-icon",
    "jpeg" | "jpg" => "image/jpeg",
    "js" | "mjs" => "application/javascript; charset=utf-8",
    "json" => "application/json",
    "pdf" => "application/pdf",
    "png" => "image/png",
    "svg" => "image/svg+xml",
    "txt" => "text/plain; charset=utf-8",
    "wasm" => "application/wasm",
    "webp" => "image/webp",
    "xml" => "application/xml",
    "zst" => "application/zstd",
    _ => "application/octet-stream",
  }
}

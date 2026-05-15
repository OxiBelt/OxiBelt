use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use bytes::Bytes;
use futures_util::StreamExt;
use http::header::{
  ACCEPT_RANGES, ALLOW, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, HeaderValue,
  IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, RANGE,
};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, StreamBody};
use hyper::body::{Body, Frame};
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;
use tracing::warn;

use super::body::{BoxError, ProxyBody, boxed_error};
use super::response::{apply_security_headers, text_response, waf_terminal_response};
use super::{
  SystemAccessLogContext, WafBodyCaptureDecision, apply_alt_svc_header, capture_body_prefix,
  compression, empty_captured_body, positive_content_length, response_body_capture_decision,
  waf_body_input, with_downstream_response_timeout,
};
use crate::config::RouteConfig;
use crate::state::AppSnapshot;
use crate::waf::{
  BodyNeed, RequestWafDecision, WafBodyInput, WafProtocol, WafRequestInput, WafResponseInput,
  WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork, apply_header_mutations,
};

const STATIC_BODY_CHANNEL_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RangeSelection {
  Full,
  Partial { start: u64, end: u64 },
  NotSatisfiable,
}

pub(crate) fn validate_static_root(path: &Path) -> anyhow::Result<PathBuf> {
  let canonical = path
    .canonicalize()
    .with_context(|| format!("failed to resolve static_root {}", path.display()))?;
  let metadata = canonical
    .metadata()
    .with_context(|| format!("failed to inspect static_root {}", canonical.display()))?;
  if !metadata.is_dir() {
    bail!("static_root must point to an existing directory");
  }
  Ok(canonical)
}

pub(crate) async fn serve<B>(
  request: &Request<B>,
  route_name: &str,
  route_prefix: &str,
  static_root: &Path,
) -> Response<ProxyBody>
where
  B: Body<Data = Bytes> + Send + Sync + 'static,
{
  if request.method() != Method::GET && request.method() != Method::HEAD {
    let mut response = text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    response
      .headers_mut()
      .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
    return response;
  }

  let root = match validate_static_root(static_root) {
    Ok(root) => root,
    Err(error) => {
      warn!(error = %error, route = %route_name, "static_root is not usable");
      return text_response(StatusCode::INTERNAL_SERVER_ERROR, "static root unavailable");
    }
  };
  let path = match resolve_request_path(&root, route_prefix, request.uri().path()) {
    Ok(path) => path,
    Err(StaticPathError::NotFound) => return text_response(StatusCode::NOT_FOUND, "not found"),
    Err(StaticPathError::Forbidden) => return text_response(StatusCode::FORBIDDEN, "forbidden"),
    Err(StaticPathError::Invalid) => {
      return text_response(StatusCode::BAD_REQUEST, "invalid static file path");
    }
  };

  let metadata = match tokio::fs::metadata(&path).await {
    Ok(metadata) => metadata,
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      return text_response(StatusCode::NOT_FOUND, "not found");
    }
    Err(error) => {
      warn!(error = %error, route = %route_name, path = %path.display(), "failed to inspect static file");
      return text_response(StatusCode::FORBIDDEN, "forbidden");
    }
  };
  if !metadata.is_file() {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }

  let len = metadata.len();
  let modified = metadata.modified().ok();
  let etag = etag_for_metadata(&metadata);
  if conditional_not_modified(request, &etag, modified) {
    return not_modified_response(&etag, modified);
  }

  let range = match request.headers().get(RANGE) {
    Some(value) => parse_range(value, len),
    None => RangeSelection::Full,
  };
  match range {
    RangeSelection::NotSatisfiable => range_not_satisfiable_response(len),
    RangeSelection::Full => {
      file_response(
        request.method(),
        StatusCode::OK,
        path,
        len,
        None,
        &etag,
        modified,
      )
      .await
    }
    RangeSelection::Partial { start, end } => {
      let body_len = end - start + 1;
      file_response(
        request.method(),
        StatusCode::PARTIAL_CONTENT,
        path,
        body_len,
        Some((start, end, len)),
        &etag,
        modified,
      )
      .await
    }
  }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn finalize_response(
  response: Response<ProxyBody>,
  state: &AppSnapshot,
  route: &RouteConfig,
  request_waf: &RequestWafDecision,
  response_waf_enabled: bool,
  response_body_need: BodyNeed,
  request_method: &Method,
  request_uri: &http::Uri,
  request_version: http::Version,
  request_headers: &HeaderMap,
  peer_addr: std::net::SocketAddr,
  downstream_host: &str,
  tcp_max_hop: Option<u8>,
  tls: &WafTlsMetadata,
  protocol: WafProtocol,
  transport_network: WafTransportNetwork,
  transport_metadata: WafTransportMetadataInput<'_>,
  downstream_scheme: &'static str,
  request_body: Option<WafBodyInput<'_>>,
  tags: &HashMap<String, String>,
  access_log: &mut SystemAccessLogContext<'_>,
) -> Response<ProxyBody> {
  let (mut parts, body) = response.into_parts();
  apply_security_headers(&mut parts.headers, &state.config.security.headers);
  apply_header_mutations(&mut parts.headers, &request_waf.response_header_mutations);

  let (body, captured_response_body) = match response_body_capture_decision(
    parts.version,
    &parts.headers,
    response_body_need,
  ) {
    WafBodyCaptureDecision::Skip => (body, None),
    WafBodyCaptureDecision::Empty => (body, Some(empty_captured_body())),
    WafBodyCaptureDecision::Prefix => {
      match capture_body_prefix(
        body,
        state.config.waf.limits.max_body_inspection_bytes,
        positive_content_length(&parts.headers),
      )
      .await
      {
        Ok((body, captured)) => (body, Some(captured)),
        Err(error) => {
          warn!(error = %error, route = %route.name, "failed to read static response body for WAF inspection");
          return text_response(StatusCode::NOT_FOUND, "not found");
        }
      }
    }
  };
  let response_body = captured_response_body.as_ref().map(waf_body_input);

  if response_waf_enabled {
    access_log.ensure_response_ids();
    access_log.response_received_at_unix_ms = crate::waf::current_unix_ms();
    let request_input = WafRequestInput {
      request_id: access_log.request_id(),
      transaction_id: access_log.transaction_id(),
      received_at_unix_ms: access_log.request_received_at_unix_ms,
      method: request_method,
      uri: request_uri,
      version: request_version,
      headers: request_headers,
      body: request_body,
      peer_addr,
      downstream_host,
      downstream_scheme,
      route_name: &route.name,
      tcp_max_hop,
      tls,
      protocol,
      transport_network,
      transport_metadata,
      tags,
      dynamic_policy: &access_log.dynamic_policy,
    };
    let response_waf = state.waf.evaluate_response(WafResponseInput {
      request: request_input,
      response_id: access_log.response_id(),
      received_at_unix_ms: access_log.response_received_at_unix_ms,
      version: parts.version,
      status: parts.status,
      headers: &parts.headers,
      body: response_body,
      upstream_name: "static",
      upstream_pool: None,
      upstream_scheme: "file",
      upstream_connect_time_ms: None,
      upstream_first_byte_time_ms: None,
      upstream_error: None,
    });
    for access_log in &response_waf.access_logs {
      state.access_logs.emit(access_log);
    }
    if let Some(terminal) = response_waf.terminal {
      let mut mutations = request_waf.response_header_mutations.clone();
      mutations.extend(response_waf.response_header_mutations);
      return waf_terminal_response(terminal, &mutations);
    }
    apply_header_mutations(&mut parts.headers, &response_waf.response_header_mutations);
  }

  apply_alt_svc_header(
    &mut parts.headers,
    parts.status,
    state,
    downstream_scheme,
    request_version,
  );
  let response = Response::from_parts(parts, body);
  let response = compression::maybe_compress_response(
    response,
    request_method,
    request_headers,
    route.compression.as_deref(),
    &state.config.compression,
    &state.compression,
  );
  let response = with_downstream_response_timeout(
    response,
    static_response_send_timeout(state, route),
    transport_network,
  );
  state.metrics.record_response(response.status());
  response
}

fn static_response_send_timeout(state: &AppSnapshot, route: &RouteConfig) -> Duration {
  Duration::from_millis(
    route
      .timeouts
      .response_send_timeout_ms
      .unwrap_or(state.config.limits.response_send_timeout_ms),
  )
}

fn resolve_request_path(
  root: &Path,
  route_prefix: &str,
  request_path: &str,
) -> Result<PathBuf, StaticPathError> {
  let relative = if route_prefix == "/" {
    request_path.trim_start_matches('/')
  } else if request_path == route_prefix {
    ""
  } else {
    request_path
      .strip_prefix(route_prefix)
      .ok_or(StaticPathError::NotFound)?
      .trim_start_matches('/')
  };

  let mut candidate = root.to_path_buf();
  for raw_segment in relative.split('/') {
    if raw_segment.is_empty() {
      continue;
    }
    let segment = percent_decode_segment(raw_segment)?;
    if segment == "." || segment == ".." {
      return Err(StaticPathError::Forbidden);
    }
    if segment
      .bytes()
      .any(|byte| byte.is_ascii_control() || matches!(byte, b'/' | b'\\'))
    {
      return Err(StaticPathError::Invalid);
    }
    candidate.push(segment);
  }

  let canonical = match candidate.canonicalize() {
    Ok(path) => path,
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      return Err(StaticPathError::NotFound);
    }
    Err(_) => return Err(StaticPathError::Forbidden),
  };
  if !canonical.starts_with(root) {
    return Err(StaticPathError::Forbidden);
  }
  Ok(canonical)
}

fn percent_decode_segment(segment: &str) -> Result<String, StaticPathError> {
  let bytes = segment.as_bytes();
  let mut decoded = Vec::with_capacity(bytes.len());
  let mut index = 0;
  while index < bytes.len() {
    if bytes[index] != b'%' {
      decoded.push(bytes[index]);
      index += 1;
      continue;
    }
    if index + 2 >= bytes.len() {
      return Err(StaticPathError::Invalid);
    }
    let high = hex_value(bytes[index + 1]).ok_or(StaticPathError::Invalid)?;
    let low = hex_value(bytes[index + 2]).ok_or(StaticPathError::Invalid)?;
    decoded.push((high << 4) | low);
    index += 3;
  }
  String::from_utf8(decoded).map_err(|_| StaticPathError::Invalid)
}

fn hex_value(byte: u8) -> Option<u8> {
  match byte {
    b'0'..=b'9' => Some(byte - b'0'),
    b'a'..=b'f' => Some(byte - b'a' + 10),
    b'A'..=b'F' => Some(byte - b'A' + 10),
    _ => None,
  }
}

async fn file_response(
  method: &Method,
  status: StatusCode,
  path: PathBuf,
  body_len: u64,
  content_range: Option<(u64, u64, u64)>,
  etag: &str,
  modified: Option<SystemTime>,
) -> Response<ProxyBody> {
  let mut response = if method == Method::HEAD || body_len == 0 {
    Response::new(empty_body())
  } else {
    match file_body(
      path.clone(),
      content_range.map(|(start, _, _)| start),
      body_len,
    )
    .await
    {
      Ok(body) => Response::new(body),
      Err(error) => {
        warn!(error = %error, path = %path.display(), "failed to open static file");
        return text_response(StatusCode::NOT_FOUND, "not found");
      }
    }
  };
  *response.status_mut() = status;
  set_common_headers(response.headers_mut(), &path, body_len, etag, modified);
  if let Some((start, end, full_len)) = content_range
    && let Ok(value) = HeaderValue::from_str(&format!("bytes {start}-{end}/{full_len}"))
  {
    response.headers_mut().insert(CONTENT_RANGE, value);
  }
  response
}

async fn file_body(path: PathBuf, start: Option<u64>, len: u64) -> anyhow::Result<ProxyBody> {
  let mut file = File::open(&path)
    .await
    .with_context(|| format!("failed to open static file {}", path.display()))?;
  if let Some(start) = start {
    file
      .seek(std::io::SeekFrom::Start(start))
      .await
      .with_context(|| format!("failed to seek static file {}", path.display()))?;
  }
  Ok(reader_body(file.take(len)))
}

fn reader_body<R>(reader: R) -> ProxyBody
where
  R: AsyncRead + Unpin + Send + Sync + 'static,
{
  let stream = ReaderStream::with_capacity(reader, STATIC_BODY_CHANNEL_CHUNK_BYTES)
    .map(|result| result.map(Frame::data).map_err(boxed_error));
  BodyExt::boxed(StreamBody::new(stream))
}

fn empty_body() -> ProxyBody {
  Empty::<Bytes>::new()
    .map_err(|never| -> BoxError { match never {} })
    .boxed()
}

fn set_common_headers(
  headers: &mut http::HeaderMap,
  path: &Path,
  body_len: u64,
  etag: &str,
  modified: Option<SystemTime>,
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
  headers.insert(
    CONTENT_TYPE,
    HeaderValue::from_static(content_type_for_path(path)),
  );
}

fn not_modified_response(etag: &str, modified: Option<SystemTime>) -> Response<ProxyBody> {
  let mut response = Response::new(empty_body());
  *response.status_mut() = StatusCode::NOT_MODIFIED;
  response
    .headers_mut()
    .insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
  if let Ok(value) = HeaderValue::from_str(etag) {
    response.headers_mut().insert(ETAG, value);
  }
  if let Some(modified) = modified
    && let Ok(value) = HeaderValue::from_str(&httpdate::fmt_http_date(modified))
  {
    response.headers_mut().insert(LAST_MODIFIED, value);
  }
  response
}

fn range_not_satisfiable_response(len: u64) -> Response<ProxyBody> {
  let mut response = Response::new(empty_body());
  *response.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
  response
    .headers_mut()
    .insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
  if let Ok(value) = HeaderValue::from_str(&format!("bytes */{len}")) {
    response.headers_mut().insert(CONTENT_RANGE, value);
  }
  response
    .headers_mut()
    .insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
  response
}

fn conditional_not_modified<B>(
  request: &Request<B>,
  etag: &str,
  modified: Option<SystemTime>,
) -> bool {
  if let Some(value) = request.headers().get(IF_NONE_MATCH)
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
  request
    .headers()
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

fn parse_range(value: &HeaderValue, len: u64) -> RangeSelection {
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
fn etag_for_metadata(metadata: &std::fs::Metadata) -> String {
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
fn etag_for_metadata(metadata: &std::fs::Metadata) -> String {
  let modified = metadata
    .modified()
    .ok()
    .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
    .map(|duration| duration.as_nanos())
    .unwrap_or_default();
  format!("W/\"{:x}-{modified:x}\"", metadata.len())
}

fn content_type_for_path(path: &Path) -> &'static str {
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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum StaticPathError {
  NotFound,
  Forbidden,
  Invalid,
}

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use bytes::Bytes;
use futures_util::StreamExt;
use http::header::{
  ACCEPT_RANGES, ALLOW, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, HeaderValue,
  IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, RANGE,
};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::body::{Body, Frame, SizeHint};
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;
use tracing::warn;

use super::body::{BoxError, KnownSmallResponseBody, ProxyBody, boxed_error};
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

mod open;
mod path;
#[cfg(all(test, target_os = "linux"))]
use self::open::open_verified_file_with_openat2_for_tests;
#[cfg(test)]
use self::open::verify_opened_file;
use self::open::{OpenedStaticFile, StaticOpenError, open_verified_file};
pub(crate) use self::path::{StaticPathError, resolve_request_path};

const STATIC_BODY_CHANNEL_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub(crate) struct StaticResponsePlan {
  pub(crate) status: StatusCode,
  pub(crate) headers: HeaderMap,
  pub(crate) body: StaticBodyPlan,
}

#[derive(Debug)]
pub(crate) enum StaticBodyPlan {
  Empty,
  Text(&'static str),
  File(StaticFileBodyPlan),
}

#[derive(Debug)]
pub(crate) struct StaticFileBodyPlan {
  pub(crate) file: File,
  pub(crate) path: PathBuf,
  pub(crate) offset: u64,
  pub(crate) len: u64,
}

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
  inline_max_bytes: usize,
) -> Response<ProxyBody>
where
  B: Body<Data = Bytes> + Send + Sync + 'static,
{
  let plan = plan_response(
    request.method(),
    request.headers(),
    request.uri().path(),
    route_name,
    route_prefix,
    static_root,
  )
  .await;
  response_from_plan(plan, inline_max_bytes).await
}

pub(crate) async fn plan_response(
  method: &Method,
  headers: &HeaderMap,
  request_path: &str,
  route_name: &str,
  route_prefix: &str,
  static_root: &Path,
) -> StaticResponsePlan {
  if method != Method::GET && method != Method::HEAD {
    let mut plan = text_plan(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    plan
      .headers
      .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
    return plan;
  }

  let root = static_root;
  let path = match resolve_request_path(root, route_prefix, request_path) {
    Ok(path) => path,
    Err(StaticPathError::NotFound) => return text_plan(StatusCode::NOT_FOUND, "not found"),
    Err(StaticPathError::Forbidden) => return text_plan(StatusCode::FORBIDDEN, "forbidden"),
    Err(StaticPathError::Invalid) => {
      return text_plan(StatusCode::BAD_REQUEST, "invalid static file path");
    }
  };

  let opened = match open_verified_file(root, &path).await {
    Ok(opened) => opened,
    Err(StaticOpenError::NotFound) => {
      if !root.is_dir() {
        warn!(route = %route_name, root = %root.display(), "static_root is not usable");
        return text_plan(StatusCode::INTERNAL_SERVER_ERROR, "static root unavailable");
      }
      return text_plan(StatusCode::NOT_FOUND, "not found");
    }
    Err(StaticOpenError::Forbidden(error)) => {
      warn!(error = %error, route = %route_name, path = %path.display(), "failed to open static file");
      return text_plan(StatusCode::FORBIDDEN, "forbidden");
    }
  };
  let OpenedStaticFile {
    file,
    path,
    metadata,
  } = opened;

  let len = metadata.len();
  let modified = metadata.modified().ok();
  let etag = etag_for_metadata(&metadata);
  if conditional_not_modified(headers, &etag, modified) {
    return not_modified_plan(&etag, modified);
  }

  let range = match headers.get(RANGE) {
    Some(value) => parse_range(value, len),
    None => RangeSelection::Full,
  };
  match range {
    RangeSelection::NotSatisfiable => range_not_satisfiable_plan(len),
    RangeSelection::Full => file_plan(
      method,
      StatusCode::OK,
      path,
      file,
      FileContentPlan {
        offset: 0,
        body_len: len,
        content_range: None,
      },
      &etag,
      modified,
    ),
    RangeSelection::Partial { start, end } => {
      let body_len = end - start + 1;
      file_plan(
        method,
        StatusCode::PARTIAL_CONTENT,
        path,
        file,
        FileContentPlan {
          offset: start,
          body_len,
          content_range: Some((start, end, len)),
        },
        &etag,
        modified,
      )
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

pub(crate) fn static_response_send_timeout(state: &AppSnapshot, route: &RouteConfig) -> Duration {
  Duration::from_millis(
    route
      .timeouts
      .response_send_timeout_ms
      .unwrap_or(state.config.limits.response_send_timeout_ms),
  )
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
    StaticBodyPlan::Text(message) => text_response(status, message),
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

struct FileContentPlan {
  offset: u64,
  body_len: u64,
  content_range: Option<(u64, u64, u64)>,
}

fn file_plan(
  method: &Method,
  status: StatusCode,
  path: PathBuf,
  file: File,
  content: FileContentPlan,
  etag: &str,
  modified: Option<SystemTime>,
) -> StaticResponsePlan {
  let mut headers = HeaderMap::new();
  set_common_headers(&mut headers, &path, content.body_len, etag, modified);
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

fn not_modified_plan(etag: &str, modified: Option<SystemTime>) -> StaticResponsePlan {
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
  StaticResponsePlan {
    status: StatusCode::NOT_MODIFIED,
    headers,
    body: StaticBodyPlan::Empty,
  }
}

fn range_not_satisfiable_plan(len: u64) -> StaticResponsePlan {
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

fn text_plan(status: StatusCode, message: &'static str) -> StaticResponsePlan {
  StaticResponsePlan {
    status,
    headers: HeaderMap::new(),
    body: StaticBodyPlan::Text(message),
  }
}

fn conditional_not_modified(headers: &HeaderMap, etag: &str, modified: Option<SystemTime>) -> bool {
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

#[cfg(test)]
mod tests;

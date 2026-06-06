//! Static-file route handling for local content.
//! Path resolution, range handling, WAF, and cache decisions stay explicit before file reads.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use bytes::Bytes;
use http::header::{ALLOW, HeaderValue, RANGE};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use hyper::body::Body;
use tokio::fs::File;
use tracing::warn;

#[cfg(test)]
use super::body::KnownSmallResponseBody;
use super::body::ProxyBody;
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
mod response_plan;
mod runtime;
#[cfg(all(test, target_os = "linux"))]
use self::open::open_verified_file_with_openat2_for_tests;
#[cfg(test)]
use self::open::verify_opened_file;
use self::open::{OpenedStaticFile, StaticOpenError, open_verified_file};
pub(crate) use self::path::{StaticPathError, resolve_request_path};
use self::response_plan::{
  FileContentPlan, RangeSelection, cached_object_plan, conditional_not_modified, etag_for_metadata,
  file_plan, not_modified_plan, parse_range, range_not_satisfiable_plan, read_file_bytes_for_cache,
};
pub(crate) use self::response_plan::{response_from_plan, text_plan};
pub(crate) use self::runtime::{CachedStaticObject, StaticFilesRuntime, StaticRootPathStatus};

#[derive(Debug)]
pub(crate) struct StaticResponsePlan {
  pub(crate) status: StatusCode,
  pub(crate) headers: HeaderMap,
  pub(crate) body: StaticBodyPlan,
}

#[derive(Debug)]
pub(crate) enum StaticBodyPlan {
  Empty,
  Text(String),
  Bytes(Bytes),
  File(StaticFileBodyPlan),
}

#[derive(Debug)]
pub(crate) struct StaticFileBodyPlan {
  pub(crate) file: File,
  pub(crate) path: PathBuf,
  pub(crate) offset: u64,
  pub(crate) len: u64,
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
  runtime: &StaticFilesRuntime,
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
    runtime,
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
  runtime: &StaticFilesRuntime,
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

  if let Some(cached) = runtime.cached_object(root, &path) {
    match runtime.root_handle(root).path_status() {
      StaticRootPathStatus::Replaced => {
        warn!(route = %route_name, root = %root.display(), "static_root was replaced after validation");
        return text_plan(StatusCode::FORBIDDEN, "forbidden");
      }
      StaticRootPathStatus::Unavailable => {
        warn!(route = %route_name, root = %root.display(), "static_root is not usable");
        return text_plan(StatusCode::INTERNAL_SERVER_ERROR, "static root unavailable");
      }
      StaticRootPathStatus::Matches | StaticRootPathStatus::Uncached => {}
    }
    return cached_object_plan(method, headers, cached);
  }

  let root_handle = runtime.root_handle(root);
  let opened = match open_verified_file(&root_handle, &path).await {
    Ok(opened) => opened,
    Err(StaticOpenError::NotFound) => {
      match root_handle.path_status() {
        StaticRootPathStatus::Replaced => {
          warn!(route = %route_name, root = %root.display(), "static_root was replaced after validation");
          return text_plan(StatusCode::FORBIDDEN, "forbidden");
        }
        StaticRootPathStatus::Unavailable => {
          warn!(route = %route_name, root = %root.display(), "static_root is not usable");
          return text_plan(StatusCode::INTERNAL_SERVER_ERROR, "static root unavailable");
        }
        StaticRootPathStatus::Matches | StaticRootPathStatus::Uncached => {}
      }
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
    mut file,
    path,
    metadata,
  } = opened;

  let len = metadata.len();
  let modified = metadata.modified().ok();
  let etag = etag_for_metadata(&metadata);
  if conditional_not_modified(headers, &etag, modified) {
    return not_modified_plan(&etag, modified);
  }

  if method == Method::GET
    && runtime.object_cache_accepts(len)
    && let Ok(bytes) = read_file_bytes_for_cache(&mut file, &path, len).await
  {
    let bytes = Bytes::from(bytes);
    runtime.store_object(root, path.clone(), etag.clone(), modified, bytes.clone());
    return cached_object_plan(
      method,
      headers,
      CachedStaticObject::new(path, etag, modified, bytes),
    );
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
      client_asn: state.client_identity.asn.lookup(peer_addr.ip()),
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

#[cfg(test)]
mod tests;

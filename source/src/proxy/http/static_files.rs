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
use crate::config::{RouteConfig, RouteStaticFilesConfig};
use crate::state::AppSnapshot;
use crate::waf::{
  BodyNeed, RequestWafDecision, WafBodyInput, WafProtocol, WafRequestInput, WafResponseInput,
  WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork, apply_header_mutations,
};

mod open;
mod path;
mod response_plan;
mod route_options;
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
pub(crate) use self::response_plan::{StaticResponseMetadata, response_from_plan, text_plan};
use self::route_options::relative_slash_path;
use self::route_options::{
  render_try_file_path, response_metadata_for_path, root_relative_config_path,
  select_precompressed_file, should_use_spa_fallback,
};
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
  static_options: &RouteStaticFilesConfig,
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
    static_options,
    runtime,
  )
  .await;
  response_from_plan(plan, inline_max_bytes).await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn plan_response(
  method: &Method,
  headers: &HeaderMap,
  request_path: &str,
  route_name: &str,
  route_prefix: &str,
  static_root: &Path,
  static_options: &RouteStaticFilesConfig,
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
  let root_handle = runtime.root_handle(root);
  let requested_path = match resolve_request_path(root, route_prefix, request_path) {
    Ok(path) => path,
    Err(StaticPathError::NotFound) => {
      match root_handle.path_status() {
        StaticRootPathStatus::Replaced => {
          warn!(route = %route_name, root = %root.display(), "static_root was replaced after validation");
          return text_plan(StatusCode::FORBIDDEN, "forbidden");
        }
        StaticRootPathStatus::Unavailable => {
          warn!(route = %route_name, root = %root.display(), "static_root is not usable");
          return plan_custom_error_page(
            method,
            StatusCode::INTERNAL_SERVER_ERROR,
            "static root unavailable",
            static_options.error_pages.server_error.as_deref(),
            root,
            runtime,
            static_options,
          )
          .await;
        }
        StaticRootPathStatus::Matches | StaticRootPathStatus::Uncached => {}
      }
      return plan_custom_error_page(
        method,
        StatusCode::NOT_FOUND,
        "not found",
        static_options.error_pages.not_found.as_deref(),
        root,
        runtime,
        static_options,
      )
      .await;
    }
    Err(StaticPathError::Forbidden) => return text_plan(StatusCode::FORBIDDEN, "forbidden"),
    Err(StaticPathError::Invalid) => {
      return text_plan(StatusCode::BAD_REQUEST, "invalid static file path");
    }
  };

  match root_handle.path_status() {
    StaticRootPathStatus::Replaced => {
      warn!(route = %route_name, root = %root.display(), "static_root was replaced after validation");
      return text_plan(StatusCode::FORBIDDEN, "forbidden");
    }
    StaticRootPathStatus::Unavailable => {
      warn!(route = %route_name, root = %root.display(), "static_root is not usable");
      return plan_custom_error_page(
        method,
        StatusCode::INTERNAL_SERVER_ERROR,
        "static root unavailable",
        static_options.error_pages.server_error.as_deref(),
        root,
        runtime,
        static_options,
      )
      .await;
    }
    StaticRootPathStatus::Matches | StaticRootPathStatus::Uncached => {}
  }

  match open_verified_file(&root_handle, &requested_path).await {
    Ok(opened) => {
      return plan_opened_file(
        method,
        headers,
        root,
        runtime,
        static_options,
        opened,
        requested_path,
        StatusCode::OK,
        true,
        true,
      )
      .await;
    }
    Err(StaticOpenError::IsDirectory) => {
      match plan_directory_index(
        method,
        headers,
        root,
        &requested_path,
        runtime,
        static_options,
      )
      .await
      {
        CandidatePlan::Found(plan) => return *plan,
        CandidatePlan::Forbidden => return text_plan(StatusCode::FORBIDDEN, "forbidden"),
        CandidatePlan::NotFound => return text_plan(StatusCode::FORBIDDEN, "forbidden"),
      }
    }
    Err(StaticOpenError::NotFound) => {}
    Err(StaticOpenError::Forbidden(error)) => {
      warn!(error = %error, route = %route_name, path = %requested_path.display(), "failed to open static file");
      return text_plan(StatusCode::FORBIDDEN, "forbidden");
    }
  }

  match plan_try_files(
    method,
    headers,
    root,
    &requested_path,
    runtime,
    static_options,
  )
  .await
  {
    CandidatePlan::Found(plan) => return *plan,
    CandidatePlan::Forbidden => return text_plan(StatusCode::FORBIDDEN, "forbidden"),
    CandidatePlan::NotFound => {}
  }

  if should_use_spa_fallback(headers, root, &requested_path, request_path)
    && let Some(fallback) = static_options.spa_fallback.as_deref()
  {
    let fallback_path = root_relative_config_path(root, fallback);
    match plan_candidate_path(
      method,
      headers,
      root,
      fallback_path,
      runtime,
      static_options,
      StatusCode::OK,
      true,
      true,
    )
    .await
    {
      CandidatePlan::Found(plan) => return *plan,
      CandidatePlan::Forbidden => return text_plan(StatusCode::FORBIDDEN, "forbidden"),
      CandidatePlan::NotFound => {}
    }
  }

  match root_handle.path_status() {
    StaticRootPathStatus::Replaced => {
      warn!(route = %route_name, root = %root.display(), "static_root was replaced after validation");
      return text_plan(StatusCode::FORBIDDEN, "forbidden");
    }
    StaticRootPathStatus::Unavailable => {
      warn!(route = %route_name, root = %root.display(), "static_root is not usable");
      return plan_custom_error_page(
        method,
        StatusCode::INTERNAL_SERVER_ERROR,
        "static root unavailable",
        static_options.error_pages.server_error.as_deref(),
        root,
        runtime,
        static_options,
      )
      .await;
    }
    StaticRootPathStatus::Matches | StaticRootPathStatus::Uncached => {}
  }
  if !root.is_dir() {
    warn!(route = %route_name, root = %root.display(), "static_root is not usable");
    return plan_custom_error_page(
      method,
      StatusCode::INTERNAL_SERVER_ERROR,
      "static root unavailable",
      static_options.error_pages.server_error.as_deref(),
      root,
      runtime,
      static_options,
    )
    .await;
  }

  plan_custom_error_page(
    method,
    StatusCode::NOT_FOUND,
    "not found",
    static_options.error_pages.not_found.as_deref(),
    root,
    runtime,
    static_options,
  )
  .await
}

#[allow(clippy::too_many_arguments)]
async fn plan_opened_file(
  method: &Method,
  headers: &HeaderMap,
  root: &Path,
  runtime: &StaticFilesRuntime,
  static_options: &RouteStaticFilesConfig,
  opened: OpenedStaticFile,
  logical_path: PathBuf,
  status: StatusCode,
  allow_cache_control: bool,
  allow_precompressed: bool,
) -> StaticResponsePlan {
  let selected = select_precompressed_file(
    method,
    headers,
    runtime,
    root,
    opened,
    &logical_path,
    static_options,
    allow_precompressed,
  )
  .await;
  let (opened, content_encoding) = match selected {
    Ok(selected) => selected,
    Err(error) => return error,
  };

  let OpenedStaticFile {
    mut file,
    path,
    metadata,
  } = opened;
  let response_metadata = response_metadata_for_path(
    method,
    headers,
    &logical_path,
    static_options,
    content_encoding,
    allow_cache_control,
    allow_precompressed,
  );

  let len = metadata.len();
  let modified = metadata.modified().ok();
  let etag = etag_for_metadata(&metadata);
  if status.is_success()
    && let Some(cached) = runtime.cached_object(root, &path, &response_metadata)
    && cached.etag == etag
    && cached.modified == modified
  {
    return cached_object_plan(method, headers, cached);
  }

  if conditional_not_modified(headers, &etag, modified) {
    return not_modified_plan(&etag, modified, &response_metadata);
  }

  if method == Method::GET
    && status.is_success()
    && runtime.object_cache_accepts(len)
    && let Ok(bytes) = read_file_bytes_for_cache(&mut file, &path, len).await
  {
    let bytes = Bytes::from(bytes);
    runtime.store_object(
      root,
      path.clone(),
      etag.clone(),
      modified,
      response_metadata.clone(),
      bytes.clone(),
    );
    return cached_object_plan(
      method,
      headers,
      CachedStaticObject::new(path, etag, modified, response_metadata, bytes),
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
      status,
      path,
      file,
      FileContentPlan {
        offset: 0,
        body_len: len,
        content_range: None,
      },
      &etag,
      modified,
      &response_metadata,
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
        &response_metadata,
      )
    }
  }
}

enum CandidatePlan {
  Found(Box<StaticResponsePlan>),
  NotFound,
  Forbidden,
}

#[allow(clippy::too_many_arguments)]
async fn plan_candidate_path(
  method: &Method,
  headers: &HeaderMap,
  root: &Path,
  path: PathBuf,
  runtime: &StaticFilesRuntime,
  static_options: &RouteStaticFilesConfig,
  status: StatusCode,
  allow_cache_control: bool,
  allow_precompressed: bool,
) -> CandidatePlan {
  let root_handle = runtime.root_handle(root);
  match open_verified_file(&root_handle, &path).await {
    Ok(opened) => CandidatePlan::Found(Box::new(
      plan_opened_file(
        method,
        headers,
        root,
        runtime,
        static_options,
        opened,
        path,
        status,
        allow_cache_control,
        allow_precompressed,
      )
      .await,
    )),
    Err(StaticOpenError::NotFound | StaticOpenError::IsDirectory) => CandidatePlan::NotFound,
    Err(StaticOpenError::Forbidden(error)) => {
      warn!(error = %error, path = %path.display(), "failed to open static file candidate");
      CandidatePlan::Forbidden
    }
  }
}

async fn plan_directory_index(
  method: &Method,
  headers: &HeaderMap,
  root: &Path,
  requested_path: &Path,
  runtime: &StaticFilesRuntime,
  static_options: &RouteStaticFilesConfig,
) -> CandidatePlan {
  for index in &static_options.directory_index {
    match plan_candidate_path(
      method,
      headers,
      root,
      requested_path.join(index),
      runtime,
      static_options,
      StatusCode::OK,
      true,
      true,
    )
    .await
    {
      CandidatePlan::NotFound => {}
      other => return other,
    }
  }
  CandidatePlan::NotFound
}

async fn plan_try_files(
  method: &Method,
  headers: &HeaderMap,
  root: &Path,
  requested_path: &Path,
  runtime: &StaticFilesRuntime,
  static_options: &RouteStaticFilesConfig,
) -> CandidatePlan {
  let relative = relative_slash_path(root, requested_path);
  for candidate in &static_options.try_files {
    let path = render_try_file_path(root, &relative, candidate);
    match plan_candidate_path(
      method,
      headers,
      root,
      path,
      runtime,
      static_options,
      StatusCode::OK,
      true,
      true,
    )
    .await
    {
      CandidatePlan::NotFound => {}
      other => return other,
    }
  }
  CandidatePlan::NotFound
}

async fn plan_custom_error_page(
  method: &Method,
  status: StatusCode,
  fallback_message: &str,
  page: Option<&str>,
  root: &Path,
  runtime: &StaticFilesRuntime,
  static_options: &RouteStaticFilesConfig,
) -> StaticResponsePlan {
  let Some(page) = page else {
    return text_plan(status, fallback_message);
  };
  let empty_headers = HeaderMap::new();
  match plan_candidate_path(
    method,
    &empty_headers,
    root,
    root_relative_config_path(root, page),
    runtime,
    static_options,
    status,
    false,
    false,
  )
  .await
  {
    CandidatePlan::Found(plan) => *plan,
    CandidatePlan::NotFound | CandidatePlan::Forbidden => text_plan(status, fallback_message),
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

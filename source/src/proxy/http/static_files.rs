//! Static-file route handling for local content.
//! Path resolution, range handling, WAF, and cache decisions stay explicit before file reads.

use std::path::{Path, PathBuf};

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
use crate::config::RouteStaticFilesConfig;

mod finalize;
mod head_bytes;
mod open;
mod path;
mod response_plan;
mod route_options;
mod runtime;
pub(in crate::proxy::http) use self::finalize::finalize_response;
pub(crate) use self::finalize::static_response_send_timeout;
pub(crate) use self::head_bytes::StaticResponseHeadBytes;
#[cfg(all(test, target_os = "linux"))]
use self::open::open_verified_file_with_openat2_for_tests;
#[cfg(test)]
use self::open::verify_opened_file;
use self::open::{
  OpenedStaticFile, StaticOpenError, open_verified_file, verify_cached_file_metadata,
};
pub(crate) use self::path::{StaticPathError, resolve_request_path};
pub(crate) use self::response_plan::StaticBodySource;
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
  Bytes {
    bytes: Bytes,
    source: StaticBodySource,
    response_heads: Option<StaticResponseHeadBytes>,
  },
  File(StaticFileBodyPlan),
}

#[derive(Debug)]
pub(crate) struct StaticFileBodyPlan {
  pub(crate) file: File,
  pub(crate) path: PathBuf,
  pub(crate) offset: u64,
  pub(crate) len: u64,
}

struct StaticErrorPage<'a> {
  status: StatusCode,
  fallback_message: &'a str,
  page: Option<&'a str>,
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
  plan_response_inner(
    method,
    headers,
    request_path,
    route_name,
    route_prefix,
    static_root,
    static_options,
    runtime,
    true,
  )
  .await
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) async fn plan_response_without_hot_object_cache(
  method: &Method,
  headers: &HeaderMap,
  request_path: &str,
  route_name: &str,
  route_prefix: &str,
  static_root: &Path,
  static_options: &RouteStaticFilesConfig,
  runtime: &StaticFilesRuntime,
) -> StaticResponsePlan {
  plan_response_inner(
    method,
    headers,
    request_path,
    route_name,
    route_prefix,
    static_root,
    static_options,
    runtime,
    false,
  )
  .await
}

#[allow(clippy::too_many_arguments)]
async fn plan_response_inner(
  method: &Method,
  headers: &HeaderMap,
  request_path: &str,
  route_name: &str,
  route_prefix: &str,
  static_root: &Path,
  static_options: &RouteStaticFilesConfig,
  runtime: &StaticFilesRuntime,
  allow_hot_object_cache: bool,
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
            StaticErrorPage {
              status: StatusCode::INTERNAL_SERVER_ERROR,
              fallback_message: "static root unavailable",
              page: static_options.error_pages.server_error.as_deref(),
            },
            root,
            runtime,
            static_options,
            allow_hot_object_cache,
          )
          .await;
        }
        StaticRootPathStatus::Matches | StaticRootPathStatus::Uncached => {}
      }
      return plan_custom_error_page(
        method,
        StaticErrorPage {
          status: StatusCode::NOT_FOUND,
          fallback_message: "not found",
          page: static_options.error_pages.not_found.as_deref(),
        },
        root,
        runtime,
        static_options,
        allow_hot_object_cache,
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
        StaticErrorPage {
          status: StatusCode::INTERNAL_SERVER_ERROR,
          fallback_message: "static root unavailable",
          page: static_options.error_pages.server_error.as_deref(),
        },
        root,
        runtime,
        static_options,
        allow_hot_object_cache,
      )
      .await;
    }
    StaticRootPathStatus::Matches | StaticRootPathStatus::Uncached => {}
  }

  if let Some(plan) = cached_full_object_plan(
    method,
    headers,
    root,
    &root_handle,
    &requested_path,
    static_options,
    runtime,
    true,
    true,
    allow_hot_object_cache,
  ) {
    return plan;
  }

  match open_verified_file_for_mode(&root_handle, &requested_path).await {
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
        allow_hot_object_cache,
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
        allow_hot_object_cache,
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
    allow_hot_object_cache,
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
      allow_hot_object_cache,
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
        StaticErrorPage {
          status: StatusCode::INTERNAL_SERVER_ERROR,
          fallback_message: "static root unavailable",
          page: static_options.error_pages.server_error.as_deref(),
        },
        root,
        runtime,
        static_options,
        allow_hot_object_cache,
      )
      .await;
    }
    StaticRootPathStatus::Matches | StaticRootPathStatus::Uncached => {}
  }
  if !root.is_dir() {
    warn!(route = %route_name, root = %root.display(), "static_root is not usable");
    return plan_custom_error_page(
      method,
      StaticErrorPage {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        fallback_message: "static root unavailable",
        page: static_options.error_pages.server_error.as_deref(),
      },
      root,
      runtime,
      static_options,
      allow_hot_object_cache,
    )
    .await;
  }

  plan_custom_error_page(
    method,
    StaticErrorPage {
      status: StatusCode::NOT_FOUND,
      fallback_message: "not found",
      page: static_options.error_pages.not_found.as_deref(),
    },
    root,
    runtime,
    static_options,
    allow_hot_object_cache,
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
  allow_hot_object_cache: bool,
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
    && allow_hot_object_cache
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
    && allow_hot_object_cache
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
      std::sync::Arc::new(CachedStaticObject::new(
        path,
        etag,
        modified,
        response_metadata,
        bytes,
      )),
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

#[allow(clippy::too_many_arguments)]
fn cached_full_object_plan(
  method: &Method,
  headers: &HeaderMap,
  root: &Path,
  root_handle: &runtime::StaticRootHandle,
  path: &Path,
  static_options: &RouteStaticFilesConfig,
  runtime: &StaticFilesRuntime,
  allow_cache_control: bool,
  allow_precompressed: bool,
  allow_hot_object_cache: bool,
) -> Option<StaticResponsePlan> {
  if !allow_hot_object_cache
    || (method != Method::GET && method != Method::HEAD)
    || headers.contains_key(RANGE)
    || !static_options.precompressed.is_empty()
  {
    return None;
  }
  let response_metadata = response_metadata_for_path(
    method,
    headers,
    path,
    static_options,
    None,
    allow_cache_control,
    allow_precompressed,
  );
  let cached = runtime.cached_object(root, path, &response_metadata)?;
  let metadata = match verify_cached_file_metadata(root_handle, path) {
    Ok(Some(verified)) => verified.metadata,
    Ok(None) => return None,
    Err(StaticOpenError::Forbidden(error)) => {
      warn!(error = %error, path = %path.display(), "cached static file revalidation failed");
      return Some(text_plan(StatusCode::FORBIDDEN, "forbidden"));
    }
    Err(StaticOpenError::IsDirectory | StaticOpenError::NotFound) => return None,
  };
  let etag = etag_for_metadata(&metadata);
  let modified = metadata.modified().ok();
  (cached.etag == etag && cached.modified == modified)
    .then(|| cached_object_plan(method, headers, cached))
}

enum CandidatePlan {
  Found(Box<StaticResponsePlan>),
  NotFound,
  Forbidden,
}

async fn open_verified_file_for_mode(
  root: &runtime::StaticRootHandle,
  path: &Path,
) -> Result<OpenedStaticFile, StaticOpenError> {
  open_verified_file(root, path).await
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
  allow_hot_object_cache: bool,
) -> CandidatePlan {
  let root_handle = runtime.root_handle(root);
  match open_verified_file_for_mode(&root_handle, &path).await {
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
        allow_hot_object_cache,
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

#[allow(clippy::too_many_arguments)]
async fn plan_directory_index(
  method: &Method,
  headers: &HeaderMap,
  root: &Path,
  requested_path: &Path,
  runtime: &StaticFilesRuntime,
  static_options: &RouteStaticFilesConfig,
  allow_hot_object_cache: bool,
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
      allow_hot_object_cache,
    )
    .await
    {
      CandidatePlan::NotFound => {}
      other => return other,
    }
  }
  CandidatePlan::NotFound
}

#[allow(clippy::too_many_arguments)]
async fn plan_try_files(
  method: &Method,
  headers: &HeaderMap,
  root: &Path,
  requested_path: &Path,
  runtime: &StaticFilesRuntime,
  static_options: &RouteStaticFilesConfig,
  allow_hot_object_cache: bool,
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
      allow_hot_object_cache,
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
  error_page: StaticErrorPage<'_>,
  root: &Path,
  runtime: &StaticFilesRuntime,
  static_options: &RouteStaticFilesConfig,
  allow_hot_object_cache: bool,
) -> StaticResponsePlan {
  let Some(page) = error_page.page else {
    return text_plan(error_page.status, error_page.fallback_message);
  };
  let empty_headers = HeaderMap::new();
  match plan_candidate_path(
    method,
    &empty_headers,
    root,
    root_relative_config_path(root, page),
    runtime,
    static_options,
    error_page.status,
    false,
    false,
    allow_hot_object_cache,
  )
  .await
  {
    CandidatePlan::Found(plan) => *plan,
    CandidatePlan::NotFound | CandidatePlan::Forbidden => {
      text_plan(error_page.status, error_page.fallback_message)
    }
  }
}

#[cfg(test)]
mod tests;

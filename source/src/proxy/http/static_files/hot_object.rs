//! Hot-object cache planning for static files.
//! Fresh cached bytes avoid per-request file opens while expired entries revalidate before refresh.

use std::path::Path;
use std::sync::Arc;

use http::header::RANGE;
use http::{HeaderMap, Method, StatusCode};
use tracing::warn;

use super::open::{StaticOpenError, verify_cached_file_metadata};
use super::path::resolve_request_path;
use super::response_plan::{cached_object_plan, etag_for_metadata};
use super::route_options::response_metadata_for_path;
use super::runtime::{
  CachedStaticObject, CachedStaticObjectLookup, StaticFilesRuntime, StaticRootHandle,
  StaticRootPathStatus,
};
use super::{StaticResponsePlan, text_plan};
use crate::config::RouteStaticFilesConfig;

pub(crate) enum CachedHotObjectPlan {
  Hit(Box<StaticResponsePlan>),
  Miss,
}

impl CachedHotObjectPlan {
  pub(crate) fn into_hit(self) -> Option<StaticResponsePlan> {
    match self {
      Self::Hit(plan) => Some(*plan),
      Self::Miss => None,
    }
  }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cached_hot_object_plan(
  method: &Method,
  headers: &HeaderMap,
  request_path: &str,
  route_prefix: &str,
  root: &Path,
  static_options: &RouteStaticFilesConfig,
  runtime: &StaticFilesRuntime,
) -> CachedHotObjectPlan {
  if !cached_hot_object_request_supported(method, headers, static_options) {
    return CachedHotObjectPlan::Miss;
  }
  let root_handle = runtime.root_handle(root);
  match root_handle.path_status() {
    StaticRootPathStatus::Matches | StaticRootPathStatus::Uncached => {}
    StaticRootPathStatus::Replaced | StaticRootPathStatus::Unavailable => {
      return CachedHotObjectPlan::Miss;
    }
  }
  let Ok(path) = resolve_request_path(root, route_prefix, request_path) else {
    return CachedHotObjectPlan::Miss;
  };
  cached_hot_object_plan_for_path(
    method,
    headers,
    root,
    &root_handle,
    &path,
    static_options,
    runtime,
    true,
    true,
    true,
  )
}

#[allow(clippy::too_many_arguments)]
pub(in crate::proxy::http::static_files) fn cached_hot_object_plan_for_path(
  method: &Method,
  headers: &HeaderMap,
  root: &Path,
  root_handle: &StaticRootHandle,
  path: &Path,
  static_options: &RouteStaticFilesConfig,
  runtime: &StaticFilesRuntime,
  allow_cache_control: bool,
  allow_precompressed: bool,
  allow_hot_object_cache: bool,
) -> CachedHotObjectPlan {
  if !allow_hot_object_cache
    || !cached_hot_object_request_supported(method, headers, static_options)
  {
    return CachedHotObjectPlan::Miss;
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
  let Some(lookup) = runtime.cached_object_lookup(root, path, &response_metadata) else {
    return CachedHotObjectPlan::Miss;
  };
  match lookup {
    CachedStaticObjectLookup::Fresh(cached) => {
      CachedHotObjectPlan::Hit(Box::new(cached_object_plan(method, headers, cached)))
    }
    CachedStaticObjectLookup::Expired(cached) => revalidate_expired_cached_object(
      method,
      headers,
      root,
      root_handle,
      path,
      runtime,
      &response_metadata,
      cached,
    ),
  }
}

fn cached_hot_object_request_supported(
  method: &Method,
  headers: &HeaderMap,
  static_options: &RouteStaticFilesConfig,
) -> bool {
  (method == Method::GET || method == Method::HEAD)
    && !headers.contains_key(RANGE)
    && static_options.precompressed.is_empty()
}

#[allow(clippy::too_many_arguments)]
fn revalidate_expired_cached_object(
  method: &Method,
  headers: &HeaderMap,
  root: &Path,
  root_handle: &StaticRootHandle,
  path: &Path,
  runtime: &StaticFilesRuntime,
  response_metadata: &super::StaticResponseMetadata,
  cached: Arc<CachedStaticObject>,
) -> CachedHotObjectPlan {
  let metadata = match verify_cached_file_metadata(root_handle, path) {
    Ok(Some(verified)) => verified.metadata,
    Ok(None) => return CachedHotObjectPlan::Miss,
    Err(StaticOpenError::Forbidden(error)) => {
      warn!(error = %error, path = %path.display(), "cached static file revalidation failed");
      return CachedHotObjectPlan::Hit(Box::new(text_plan(StatusCode::FORBIDDEN, "forbidden")));
    }
    Err(StaticOpenError::IsDirectory | StaticOpenError::NotFound) => {
      return CachedHotObjectPlan::Miss;
    }
  };
  let etag = etag_for_metadata(&metadata);
  let modified = metadata.modified().ok();
  if cached.etag == etag && cached.modified == modified {
    let cached = runtime
      .refresh_cached_object(root, path, response_metadata, &etag, modified)
      .unwrap_or(cached);
    return CachedHotObjectPlan::Hit(Box::new(cached_object_plan(method, headers, cached)));
  }
  CachedHotObjectPlan::Miss
}

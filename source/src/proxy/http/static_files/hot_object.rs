//! Hot-object cache shortcuts for direct static-file hits.

use std::path::Path;

use http::header::RANGE;
use http::{HeaderMap, Method};

use crate::config::RouteStaticFilesConfig;

use super::StaticResponsePlan;
use super::response_plan::cached_object_plan;
use super::route_options::response_metadata_for_path;
use super::runtime::StaticFilesRuntime;

pub(super) fn plan_cached_direct_file(
  method: &Method,
  headers: &HeaderMap,
  root: &Path,
  path: &Path,
  runtime: &StaticFilesRuntime,
  static_options: &RouteStaticFilesConfig,
) -> Option<StaticResponsePlan> {
  if !direct_cache_metadata_is_deterministic(headers, static_options) {
    return None;
  }
  let response_metadata =
    response_metadata_for_path(method, headers, path, static_options, None, true, true);
  runtime
    .cached_object(root, path, &response_metadata)
    .map(|cached| cached_object_plan(method, headers, cached))
}

fn direct_cache_metadata_is_deterministic(
  headers: &HeaderMap,
  static_options: &RouteStaticFilesConfig,
) -> bool {
  static_options.precompressed.is_empty() || headers.contains_key(RANGE)
}

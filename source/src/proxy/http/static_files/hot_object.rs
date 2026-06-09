//! Hot-object cache shortcuts for direct static-file hits.

use std::path::Path;

use http::{HeaderMap, Method};

use crate::config::RouteStaticFilesConfig;

use super::StaticResponsePlan;
use super::response_plan::cached_object_plan;
use super::runtime::StaticFilesRuntime;

pub(super) fn plan_cached_direct_file(
  method: &Method,
  headers: &HeaderMap,
  root: &Path,
  path: &Path,
  runtime: &StaticFilesRuntime,
  static_options: &RouteStaticFilesConfig,
) -> Option<StaticResponsePlan> {
  if !direct_cache_metadata_is_default(static_options) {
    return None;
  }
  runtime
    .cached_direct_object(root, path)
    .map(|cached| cached_object_plan(method, headers, cached))
}

fn direct_cache_metadata_is_default(static_options: &RouteStaticFilesConfig) -> bool {
  static_options.precompressed.is_empty()
    && static_options.cache_control.is_none()
    && static_options.cache_control_by_extension.is_empty()
    && static_options.mime_overrides.is_empty()
}

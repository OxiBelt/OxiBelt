//! Per-route static-file option helpers.

use std::path::{Path, PathBuf};

use http::header::{ACCEPT, RANGE};
use http::{HeaderMap, Method, StatusCode};
use tracing::warn;

use super::super::compression;
use super::open::{OpenedStaticFile, StaticOpenError, open_verified_file};
use super::response_plan;
use super::runtime::StaticFilesRuntime;
use super::{StaticResponseMetadata, StaticResponsePlan, text_plan};
use crate::config::{RouteStaticFilesConfig, StaticPrecompressedEncoding};

#[allow(clippy::too_many_arguments)]
pub(super) async fn select_precompressed_file(
  method: &Method,
  headers: &HeaderMap,
  runtime: &StaticFilesRuntime,
  root: &Path,
  opened: OpenedStaticFile,
  logical_path: &Path,
  static_options: &RouteStaticFilesConfig,
  allow_precompressed: bool,
) -> Result<(OpenedStaticFile, Option<&'static str>), StaticResponsePlan> {
  if !allow_precompressed
    || (method != Method::GET && method != Method::HEAD)
    || headers.contains_key(RANGE)
    || static_options.precompressed.is_empty()
  {
    return Ok((opened, None));
  }

  let mut candidates = static_options
    .precompressed
    .iter()
    .enumerate()
    .filter_map(|(index, encoding)| {
      let q = compression::accepted_encoding_quality(headers, encoding.content_encoding());
      (q > 0.0).then_some((index, *encoding, q))
    })
    .collect::<Vec<_>>();
  candidates.sort_by(|left, right| {
    right
      .2
      .partial_cmp(&left.2)
      .unwrap_or(std::cmp::Ordering::Equal)
      .then_with(|| left.0.cmp(&right.0))
  });

  let root_handle = runtime.root_handle(root);
  for (_, encoding, _) in candidates {
    let compressed_path = precompressed_path(&opened.path, encoding);
    match open_verified_file(&root_handle, &compressed_path).await {
      Ok(compressed) => return Ok((compressed, Some(encoding.content_encoding()))),
      Err(StaticOpenError::NotFound) => {}
      Err(StaticOpenError::IsDirectory) => {
        return Err(text_plan(StatusCode::FORBIDDEN, "forbidden"));
      }
      Err(StaticOpenError::Forbidden(error)) => {
        warn!(
          error = %error,
          path = %compressed_path.display(),
          logical_path = %logical_path.display(),
          "failed to open precompressed static file"
        );
        return Err(text_plan(StatusCode::FORBIDDEN, "forbidden"));
      }
    }
  }
  Ok((opened, None))
}

pub(in crate::proxy::http::static_files) fn response_metadata_for_path(
  method: &Method,
  headers: &HeaderMap,
  logical_path: &Path,
  static_options: &RouteStaticFilesConfig,
  content_encoding: Option<&'static str>,
  allow_cache_control: bool,
  allow_precompressed: bool,
) -> StaticResponseMetadata {
  let extension = extension_key(logical_path);
  let content_type = extension
    .as_ref()
    .and_then(|extension| static_options.mime_overrides.get(extension))
    .cloned()
    .unwrap_or_else(|| response_plan::content_type_for_path(logical_path).to_string());
  let cache_control = if allow_cache_control {
    extension
      .as_ref()
      .and_then(|extension| static_options.cache_control_by_extension.get(extension))
      .cloned()
      .or_else(|| static_options.cache_control.clone())
  } else {
    None
  };
  StaticResponseMetadata {
    content_type,
    content_encoding,
    cache_control,
    vary_accept_encoding: should_vary_accept_encoding(
      method,
      headers,
      static_options,
      content_encoding,
      allow_precompressed,
    ),
  }
}

pub(super) fn root_relative_config_path(root: &Path, value: &str) -> PathBuf {
  let mut path = root.to_path_buf();
  for segment in value.trim_start_matches('/').split('/') {
    if !segment.is_empty() {
      path.push(segment);
    }
  }
  path
}

pub(super) fn render_try_file_path(root: &Path, relative: &str, candidate: &str) -> PathBuf {
  if candidate.contains("{path}") {
    let rendered = candidate.replace("{path}", relative);
    let rendered = if rendered.starts_with('/') {
      rendered
    } else {
      format!("/{rendered}")
    };
    return root_relative_config_path(root, &rendered);
  }
  root_relative_config_path(root, candidate)
}

pub(super) fn relative_slash_path(root: &Path, path: &Path) -> String {
  path
    .strip_prefix(root)
    .ok()
    .map(|relative| {
      relative
        .components()
        .filter_map(|component| match component {
          std::path::Component::Normal(value) => value.to_str(),
          _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
    })
    .unwrap_or_default()
}

pub(super) fn should_use_spa_fallback(
  headers: &HeaderMap,
  root: &Path,
  requested_path: &Path,
  request_path: &str,
) -> bool {
  !request_path.ends_with('/')
    && requested_path
      .strip_prefix(root)
      .ok()
      .and_then(|relative| relative.extension())
      .is_none()
    && accepts_html(headers)
}

fn precompressed_path(path: &Path, encoding: StaticPrecompressedEncoding) -> PathBuf {
  let mut value = path.as_os_str().to_os_string();
  value.push(".");
  value.push(encoding.extension());
  PathBuf::from(value)
}

fn extension_key(path: &Path) -> Option<String> {
  path
    .extension()
    .and_then(|extension| extension.to_str())
    .map(str::to_ascii_lowercase)
}

fn should_vary_accept_encoding(
  method: &Method,
  headers: &HeaderMap,
  static_options: &RouteStaticFilesConfig,
  content_encoding: Option<&'static str>,
  allow_precompressed: bool,
) -> bool {
  content_encoding.is_some()
    || (allow_precompressed
      && !static_options.precompressed.is_empty()
      && (method == Method::GET || method == Method::HEAD)
      && !headers.contains_key(RANGE))
}

fn accepts_html(headers: &HeaderMap) -> bool {
  headers.get_all(ACCEPT).iter().any(|value| {
    value.to_str().ok().is_some_and(|value| {
      value.split(',').any(|item| {
        let mut parts = item.split(';').map(str::trim);
        let media_type = parts.next().unwrap_or_default().to_ascii_lowercase();
        if media_type != "text/html" && media_type != "application/xhtml+xml" {
          return false;
        }
        let mut q = 1.0f32;
        for parameter in parts {
          let Some((name, value)) = parameter.split_once('=') else {
            continue;
          };
          if name.trim().eq_ignore_ascii_case("q") {
            q = value.trim().parse::<f32>().unwrap_or(0.0).clamp(0.0, 1.0);
          }
        }
        q > 0.0
      })
    })
  })
}

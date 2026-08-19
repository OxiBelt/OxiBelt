//! HTTP version selection helpers.
//! Downstream and upstream protocol choices stay independent unless configuration binds them.

use http::Version;

use crate::config::{HttpVersion, RouteConfig, UpstreamHttpVersionMode};

pub(super) fn upstream_request_version(version: HttpVersion) -> Version {
  match version {
    HttpVersion::H1 => Version::HTTP_11,
    HttpVersion::H2 => Version::HTTP_2,
    HttpVersion::H3 => Version::HTTP_3,
  }
}

pub(crate) fn select_upstream_http_version(
  auto_upgrade_enabled: bool,
  configured_max: HttpVersion,
  upstream_max: HttpVersion,
) -> HttpVersion {
  if !auto_upgrade_enabled {
    return upstream_max;
  }
  std::cmp::min(configured_max, upstream_max)
}

pub(crate) fn select_route_upstream_http_version(
  route: &RouteConfig,
  auto_upgrade_enabled: bool,
  configured_max: HttpVersion,
  upstream_max: HttpVersion,
) -> HttpVersion {
  select_route_version(
    route.upstream_http_version,
    route.upstream_http_version_mode,
    auto_upgrade_enabled,
    configured_max,
    upstream_max,
  )
}

fn select_route_version(
  route_version: Option<HttpVersion>,
  mode: UpstreamHttpVersionMode,
  auto_upgrade_enabled: bool,
  configured_max: HttpVersion,
  upstream_max: HttpVersion,
) -> HttpVersion {
  let automatic = select_upstream_http_version(auto_upgrade_enabled, configured_max, upstream_max);
  match (route_version, mode) {
    (Some(version), UpstreamHttpVersionMode::Exact) => version,
    (Some(ceiling), UpstreamHttpVersionMode::Ceiling) => automatic.min(ceiling),
    (None, _) => automatic,
  }
}

#[cfg(test)]
mod tests {
  use pretty_assertions::assert_eq;

  use super::*;

  #[test]
  fn upstream_request_version_matches_selected_upstream_version() {
    assert_eq!(upstream_request_version(HttpVersion::H1), Version::HTTP_11);
    assert_eq!(upstream_request_version(HttpVersion::H2), Version::HTTP_2);
    assert_eq!(upstream_request_version(HttpVersion::H3), Version::HTTP_3);
  }

  #[test]
  fn explicit_route_versions_are_exact_by_default_or_bound_a_ceiling() {
    assert_eq!(
      select_route_version(
        Some(HttpVersion::H1),
        UpstreamHttpVersionMode::Exact,
        true,
        HttpVersion::H3,
        HttpVersion::H3,
      ),
      HttpVersion::H1
    );

    assert_eq!(
      select_route_version(
        Some(HttpVersion::H2),
        UpstreamHttpVersionMode::Ceiling,
        true,
        HttpVersion::H3,
        HttpVersion::H3,
      ),
      HttpVersion::H2
    );
    assert_eq!(
      select_route_version(
        Some(HttpVersion::H2),
        UpstreamHttpVersionMode::Ceiling,
        true,
        HttpVersion::H1,
        HttpVersion::H3,
      ),
      HttpVersion::H1
    );
  }
}

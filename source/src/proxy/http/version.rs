use http::Version;

use crate::config::HttpVersion;

pub(super) fn upstream_request_version(version: HttpVersion) -> Version {
  match version {
    HttpVersion::H1 => Version::HTTP_11,
    HttpVersion::H2 => Version::HTTP_2,
    HttpVersion::H3 => Version::HTTP_3,
  }
}

pub(super) fn select_upstream_http_version(
  auto_upgrade_enabled: bool,
  configured_max: HttpVersion,
  upstream_max: HttpVersion,
) -> HttpVersion {
  if !auto_upgrade_enabled {
    return upstream_max;
  }
  std::cmp::min(configured_max, upstream_max)
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
}

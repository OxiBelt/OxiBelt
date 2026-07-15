use std::borrow::Cow;
use std::ops::Range;

use http::Request;
use http::header::{HOST, HeaderValue};
use http::uri::Authority;

use crate::routes::normalize_host_cow;

pub(crate) struct HostSnapshot {
  source: HostSnapshotSource,
  normalized: HostSnapshotNormalized,
  explicit_port: Option<u16>,
}

enum HostSnapshotSource {
  Authority(Authority),
  Header(HeaderValue),
  Empty,
}

enum HostSnapshotNormalized {
  Slice(Range<usize>),
  Owned(String),
  Empty,
}

impl HostSnapshot {
  pub(crate) fn as_str(&self) -> &str {
    match &self.normalized {
      HostSnapshotNormalized::Slice(range) => &self.raw_host()[range.clone()],
      HostSnapshotNormalized::Owned(host) => host,
      HostSnapshotNormalized::Empty => "",
    }
  }

  pub(crate) fn downstream_port(&self, scheme: &str) -> u16 {
    self
      .explicit_port
      .unwrap_or_else(|| super::default_port_for_scheme(scheme))
  }

  fn from_authority(authority: Authority) -> Self {
    let explicit_port = authority.port_u16();
    let normalized = normalize_host_snapshot(authority.host());
    Self {
      source: HostSnapshotSource::Authority(authority),
      normalized,
      explicit_port,
    }
  }

  fn from_header(value: HeaderValue) -> Self {
    let explicit_port = value.to_str().ok().and_then(super::explicit_authority_port);
    let normalized = value
      .to_str()
      .map(normalize_host_snapshot)
      .unwrap_or(HostSnapshotNormalized::Empty);
    Self {
      source: HostSnapshotSource::Header(value),
      normalized,
      explicit_port,
    }
  }

  fn empty() -> Self {
    Self {
      source: HostSnapshotSource::Empty,
      normalized: HostSnapshotNormalized::Empty,
      explicit_port: None,
    }
  }

  fn raw_host(&self) -> &str {
    match &self.source {
      HostSnapshotSource::Authority(authority) => authority.host(),
      HostSnapshotSource::Header(value) => value.to_str().unwrap_or(""),
      HostSnapshotSource::Empty => "",
    }
  }

  #[cfg(test)]
  fn uses_borrowed_slice(&self) -> bool {
    matches!(self.normalized, HostSnapshotNormalized::Slice(_))
  }
}

pub(crate) fn extract_host<B>(request: &Request<B>) -> Option<Cow<'_, str>> {
  if let Some(authority) = request.uri().authority() {
    return Some(normalize_host_cow(authority.host()));
  }

  request
    .headers()
    .get(HOST)
    .and_then(|value| value.to_str().ok())
    .map(normalize_host_cow)
}

pub(crate) fn extract_host_snapshot<B>(request: &Request<B>) -> HostSnapshot {
  if let Some(authority) = request.uri().authority() {
    return HostSnapshot::from_authority(authority.clone());
  }

  request
    .headers()
    .get(HOST)
    .cloned()
    .map(HostSnapshot::from_header)
    .unwrap_or_else(HostSnapshot::empty)
}

pub(crate) fn extract_downstream_port<B>(request: &Request<B>, scheme: &str) -> u16 {
  request
    .uri()
    .authority()
    .and_then(|authority| authority.port_u16())
    .or_else(|| {
      request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(super::explicit_authority_port)
    })
    .unwrap_or_else(|| super::default_port_for_scheme(scheme))
}

fn normalize_host_snapshot(raw: &str) -> HostSnapshotNormalized {
  let trimmed = raw.trim().trim_end_matches('.');
  let host = if trimmed.starts_with('[')
    && let Some(end) = trimmed.find(']')
  {
    &trimmed[1..end]
  } else if let Some((host, port)) = trimmed.rsplit_once(':')
    && !host.contains(':')
    && !port.is_empty()
    && port.chars().all(|ch| ch.is_ascii_digit())
  {
    host
  } else {
    trimmed
  };

  if host.is_empty() {
    return HostSnapshotNormalized::Empty;
  }

  if host.bytes().any(|byte| byte.is_ascii_uppercase()) {
    return HostSnapshotNormalized::Owned(host.to_ascii_lowercase());
  }

  HostSnapshotNormalized::Slice(host_range(raw, host))
}

fn host_range(raw: &str, host: &str) -> Range<usize> {
  let start = host.as_ptr() as usize - raw.as_ptr() as usize;
  start..start + host.len()
}

#[cfg(test)]
mod tests {
  use http::Request;
  use http::header::HOST;

  use super::*;

  #[test]
  fn extract_host_prefers_absolute_form_authority_over_host_header() {
    let request = Request::builder()
      .uri("http://absolute.example:8080/path?query=1")
      .header(HOST, "header.example")
      .body(())
      .expect("request should build");

    assert_eq!(extract_host(&request).as_deref(), Some("absolute.example"));
  }

  #[test]
  fn downstream_port_prefers_authority_then_host_then_scheme_default() {
    let authority = Request::builder()
      .uri("http://absolute.example:8080/path")
      .header(HOST, "header.example:9443")
      .body(())
      .expect("request should build");
    let host = Request::builder()
      .uri("/path")
      .header(HOST, "header.example:9443")
      .body(())
      .expect("request should build");
    let default = Request::builder()
      .uri("/path")
      .header(HOST, "header.example")
      .body(())
      .expect("request should build");

    assert_eq!(extract_downstream_port(&authority, "http"), 8080);
    assert_eq!(extract_downstream_port(&host, "https"), 9443);
    assert_eq!(extract_downstream_port(&default, "https"), 443);
  }

  #[test]
  fn host_extraction_borrows_common_normalized_host() {
    let request = Request::builder()
      .uri("/path")
      .header(HOST, "example.test")
      .body(())
      .expect("request should build");
    assert!(matches!(
      extract_host(&request),
      Some(std::borrow::Cow::Borrowed("example.test"))
    ));

    let upper = Request::builder()
      .uri("/path")
      .header(HOST, "Example.Test:8443")
      .body(())
      .expect("request should build");
    assert!(matches!(
      extract_host(&upper),
      Some(std::borrow::Cow::Owned(value)) if value == "example.test"
    ));
  }

  #[test]
  fn host_snapshot_keeps_common_host_without_string_allocation() {
    let request = Request::builder()
      .uri("/path")
      .header(HOST, "example.test")
      .body(())
      .expect("request should build");
    let host = extract_host_snapshot(&request);

    assert_eq!(host.as_str(), "example.test");
    assert!(host.uses_borrowed_slice());

    let (_parts, _body) = request.into_parts();
    assert_eq!(host.as_str(), "example.test");
  }

  #[test]
  fn host_snapshot_matches_host_normalization_rules() {
    let authority = Request::builder()
      .uri("http://absolute.example:8080/path?query=1")
      .header(HOST, "header.example")
      .body(())
      .expect("request should build");
    let upper = Request::builder()
      .uri("/path")
      .header(HOST, "Example.Test:8443")
      .body(())
      .expect("request should build");

    assert_eq!(
      extract_host_snapshot(&authority).as_str(),
      "absolute.example"
    );
    assert_eq!(extract_host_snapshot(&upper).as_str(), "example.test");
    assert_eq!(extract_host_snapshot(&upper).downstream_port("https"), 8443);
    assert!(!extract_host_snapshot(&upper).uses_borrowed_slice());
  }

  #[test]
  fn downstream_port_handles_ipv6_and_non_port_hosts() {
    let bracketed = Request::builder()
      .uri("/path")
      .header(HOST, "[2001:db8::1]:9443")
      .body(())
      .expect("request should build");
    let bare_ipv6 = Request::builder()
      .uri("/path")
      .header(HOST, "2001:db8::1")
      .body(())
      .expect("request should build");

    assert_eq!(extract_downstream_port(&bracketed, "https"), 9443);
    assert_eq!(extract_downstream_port(&bare_ipv6, "https"), 443);
  }
}

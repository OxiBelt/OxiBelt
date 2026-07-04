use http::{Request, Response};

use crate::config::HttpVersion;
use crate::proxy::http::body::ProxyBody;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectFastPathTransport {
  H1,
  H2,
}

pub(super) fn direct_fast_path_transport(
  upstream_version: HttpVersion,
  direct_candidate: bool,
) -> Option<DirectFastPathTransport> {
  if !direct_candidate {
    return None;
  }
  match upstream_version {
    HttpVersion::H1 => Some(DirectFastPathTransport::H1),
    HttpVersion::H2 => Some(DirectFastPathTransport::H2),
    HttpVersion::H3 => None,
  }
}

pub(super) enum DirectTransportAttempt {
  Sent(anyhow::Result<Response<ProxyBody>>),
  Fallback(Request<ProxyBody>),
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn dispatches_by_upstream_version() {
    assert_eq!(
      direct_fast_path_transport(HttpVersion::H1, true),
      Some(DirectFastPathTransport::H1)
    );
    assert_eq!(
      direct_fast_path_transport(HttpVersion::H2, true),
      Some(DirectFastPathTransport::H2)
    );
    assert_eq!(direct_fast_path_transport(HttpVersion::H3, true), None);
    assert_eq!(direct_fast_path_transport(HttpVersion::H1, false), None);
    assert_eq!(direct_fast_path_transport(HttpVersion::H2, false), None);
  }
}

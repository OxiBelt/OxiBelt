//! Route-surface admission for Certificate Transparency endpoints.

use http::Method;

use crate::config::CertificateTransparencyRouteSurface;

pub(super) fn surface_allows(
  surface: CertificateTransparencyRouteSurface,
  method: &Method,
  path: &str,
) -> bool {
  match surface {
    CertificateTransparencyRouteSurface::Submission => is_submission_endpoint(method, path),
    CertificateTransparencyRouteSurface::Monitoring => is_monitoring_endpoint(method, path),
  }
}

fn is_submission_endpoint(method: &Method, path: &str) -> bool {
  method == Method::POST
    && [
      "/ct/v1/add-chain",
      "/ct/v1/add-pre-chain",
      "/ct/v2/submit-entry",
    ]
    .iter()
    .any(|suffix| path.ends_with(suffix))
}

fn is_monitoring_endpoint(method: &Method, path: &str) -> bool {
  method == Method::GET
    && ([
      "/ct/v1/get-sth",
      "/ct/v1/get-entries",
      "/ct/v1/get-proof-by-hash",
      "/ct/v1/get-sth-consistency",
      "/ct/v1/get-roots",
      "/ct/v2/get-sth",
      "/ct/v2/get-final-sth",
      "/ct/v2/get-entries",
      "/ct/v2/get-inclusion-proof",
      "/ct/v2/get-consistency-proof",
      "/checkpoint",
    ]
    .iter()
    .any(|suffix| path.ends_with(suffix))
      || path.contains("/tile/")
      || path.contains("/issuer/"))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn submission_surface_admits_only_submission_endpoints() {
    for path in [
      "/ct/v1/add-chain",
      "/prefix/ct/v1/add-pre-chain",
      "/ct/v2/submit-entry",
    ] {
      assert!(surface_allows(
        CertificateTransparencyRouteSurface::Submission,
        &Method::POST,
        path,
      ));
      assert!(!surface_allows(
        CertificateTransparencyRouteSurface::Monitoring,
        &Method::POST,
        path,
      ));
    }

    for path in [
      "/ct/v1/get-sth",
      "/ct/v2/get-inclusion-proof",
      "/checkpoint",
      "/tile/0/000",
      "/issuer/0000000000000000000000000000000000000000000000000000000000000000",
    ] {
      assert!(!surface_allows(
        CertificateTransparencyRouteSurface::Submission,
        &Method::GET,
        path,
      ));
    }
  }

  #[test]
  fn monitoring_surface_admits_only_read_endpoints() {
    for path in [
      "/ct/v1/get-sth",
      "/ct/v1/get-entries",
      "/ct/v1/get-proof-by-hash",
      "/ct/v1/get-sth-consistency",
      "/ct/v1/get-roots",
      "/ct/v2/get-sth",
      "/ct/v2/get-final-sth",
      "/ct/v2/get-entries",
      "/ct/v2/get-inclusion-proof",
      "/ct/v2/get-consistency-proof",
      "/prefix/checkpoint",
      "/prefix/tile/data/000",
      "/prefix/issuer/0000000000000000000000000000000000000000000000000000000000000000",
    ] {
      assert!(surface_allows(
        CertificateTransparencyRouteSurface::Monitoring,
        &Method::GET,
        path,
      ));
      assert!(!surface_allows(
        CertificateTransparencyRouteSurface::Submission,
        &Method::GET,
        path,
      ));
    }

    assert!(!surface_allows(
      CertificateTransparencyRouteSurface::Monitoring,
      &Method::POST,
      "/ct/v1/get-sth",
    ));
    assert!(!surface_allows(
      CertificateTransparencyRouteSurface::Monitoring,
      &Method::GET,
      "/ct/v1/add-chain",
    ));
    assert!(!surface_allows(
      CertificateTransparencyRouteSurface::Monitoring,
      &Method::GET,
      "/unrelated",
    ));
  }
}

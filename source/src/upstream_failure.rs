//! Typed, public-safe classifications for failures while obtaining an upstream response.
//!
//! The classifier deliberately relies on typed sources and explicit markers.  It never
//! interprets an error's display text or an HTTP response status.

use std::error::Error;
use std::fmt;

/// RFC 9209 proxy error types that OxiBelt can establish from typed transport state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamFailure {
  DnsTimeout,
  DnsError,
  ConnectionRefused,
  ConnectionTerminated,
  ConnectionTimeout,
  ConnectionReadTimeout,
  ConnectionWriteTimeout,
  TlsProtocolError,
  TlsCertificateError,
  TlsAlertReceived,
  HttpResponseTimeout,
  HttpProtocolError,
}

impl UpstreamFailure {
  /// The registered RFC 9209 error token.
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::DnsTimeout => "dns_timeout",
      Self::DnsError => "dns_error",
      Self::ConnectionRefused => "connection_refused",
      Self::ConnectionTerminated => "connection_terminated",
      Self::ConnectionTimeout => "connection_timeout",
      Self::ConnectionReadTimeout => "connection_read_timeout",
      Self::ConnectionWriteTimeout => "connection_write_timeout",
      Self::TlsProtocolError => "tls_protocol_error",
      Self::TlsCertificateError => "tls_certificate_error",
      Self::TlsAlertReceived => "tls_alert_received",
      Self::HttpResponseTimeout => "http_response_timeout",
      Self::HttpProtocolError => "http_protocol_error",
    }
  }
}

/// Adds a typed upstream-failure marker without changing the error's display text or source chain.
#[derive(Debug)]
struct UpstreamFailureError {
  failure: UpstreamFailure,
  source: Box<dyn Error + Send + Sync>,
}

impl UpstreamFailureError {
  fn new(failure: UpstreamFailure, source: Box<dyn Error + Send + Sync>) -> Self {
    Self { failure, source }
  }

  fn failure(&self) -> UpstreamFailure {
    self.failure
  }
}

impl fmt::Display for UpstreamFailureError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.source.fmt(formatter)
  }
}

impl Error for UpstreamFailureError {
  fn source(&self) -> Option<&(dyn Error + 'static)> {
    Some(self.source.as_ref())
  }
}

/// Returns `error` with a marker that [`classify`] can recover through context layers.
pub(crate) fn annotate(error: anyhow::Error, failure: UpstreamFailure) -> anyhow::Error {
  anyhow::Error::new(UpstreamFailureError::new(
    failure,
    error.into_boxed_dyn_error(),
  ))
}

/// Marks a Happy Eyeballs terminal error as ambiguous when several endpoint failures occurred.
///
/// The original error remains the displayed/source error, but a classifier must not select the
/// last attempt as representative of the whole race.
#[derive(Debug)]
struct AmbiguousCandidateFailure {
  source: Box<dyn Error + Send + Sync>,
}

impl fmt::Display for AmbiguousCandidateFailure {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.source.fmt(formatter)
  }
}

impl Error for AmbiguousCandidateFailure {
  fn source(&self) -> Option<&(dyn Error + 'static)> {
    Some(self.source.as_ref())
  }
}

/// Preserves `error` while preventing a last-candidate classification from escaping a mixed race.
pub(crate) fn ambiguous_candidate_failure(error: anyhow::Error) -> anyhow::Error {
  anyhow::Error::new(AmbiguousCandidateFailure {
    source: error.into_boxed_dyn_error(),
  })
}

/// Classifies a typed upstream failure, if its cause is established by the source chain.
pub fn classify(error: &(dyn Error + 'static)) -> Option<UpstreamFailure> {
  let mut current = Some(error);
  while let Some(source) = current {
    if source.downcast_ref::<AmbiguousCandidateFailure>().is_some() {
      return None;
    }
    if let Some(marker) = source.downcast_ref::<UpstreamFailureError>() {
      return Some(marker.failure());
    }
    if let Some(resolution) = source.downcast_ref::<crate::upstream_resolution::ResolutionError>() {
      return match resolution.class() {
        crate::upstream_resolution::ResolutionErrorClass::Deadline => {
          Some(UpstreamFailure::DnsTimeout)
        }
        crate::upstream_resolution::ResolutionErrorClass::NxDomain
        | crate::upstream_resolution::ResolutionErrorClass::NoData
        | crate::upstream_resolution::ResolutionErrorClass::ServerFailure
        | crate::upstream_resolution::ResolutionErrorClass::Refused
        | crate::upstream_resolution::ResolutionErrorClass::Truncated
        | crate::upstream_resolution::ResolutionErrorClass::Malformed
        | crate::upstream_resolution::ResolutionErrorClass::Io
        | crate::upstream_resolution::ResolutionErrorClass::NoNameservers => {
          Some(UpstreamFailure::DnsError)
        }
        crate::upstream_resolution::ResolutionErrorClass::Cancelled
        | crate::upstream_resolution::ResolutionErrorClass::InvalidInput
        | crate::upstream_resolution::ResolutionErrorClass::Internal => None,
      };
    }
    if let Some(tls) = source.downcast_ref::<rustls::Error>() {
      return Some(match tls {
        rustls::Error::InvalidCertificate(_) => UpstreamFailure::TlsCertificateError,
        rustls::Error::AlertReceived(_) => UpstreamFailure::TlsAlertReceived,
        _ => UpstreamFailure::TlsProtocolError,
      });
    }
    if let Some(io) = source.downcast_ref::<std::io::Error>() {
      let failure = match io.kind() {
        std::io::ErrorKind::ConnectionRefused => UpstreamFailure::ConnectionRefused,
        std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::BrokenPipe
        | std::io::ErrorKind::UnexpectedEof => UpstreamFailure::ConnectionTerminated,
        _ => {
          current = source.source();
          continue;
        }
      };
      return Some(failure);
    }
    current = source.source();
  }
  None
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::upstream_resolution::{ResolutionError, ResolutionErrorClass};

  #[test]
  fn classifies_typed_dns_and_io_failures_without_display_parsing() {
    let timeout = ResolutionError::new(ResolutionErrorClass::Deadline, "any text");
    assert_eq!(classify(&timeout), Some(UpstreamFailure::DnsTimeout));
    let nxdomain = ResolutionError::new(ResolutionErrorClass::NxDomain, "any text");
    assert_eq!(classify(&nxdomain), Some(UpstreamFailure::DnsError));
    let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
    assert_eq!(classify(&refused), Some(UpstreamFailure::ConnectionRefused));
    let timed_out = std::io::Error::from(std::io::ErrorKind::TimedOut);
    assert_eq!(classify(&timed_out), None);
  }

  #[test]
  fn marker_is_transparent_and_wins_over_generic_sources() {
    let error = anyhow::anyhow!("existing diagnostic");
    let annotated = annotate(error, UpstreamFailure::HttpProtocolError);
    assert_eq!(annotated.to_string(), "existing diagnostic");
    assert_eq!(
      classify(annotated.as_ref()),
      Some(UpstreamFailure::HttpProtocolError)
    );
  }

  #[test]
  fn ambiguous_candidate_marker_suppresses_a_last_attempt_classification() {
    let error = annotate(
      anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
      UpstreamFailure::ConnectionRefused,
    );
    let ambiguous = ambiguous_candidate_failure(error);
    assert_eq!(classify(ambiguous.as_ref()), None);
  }
}

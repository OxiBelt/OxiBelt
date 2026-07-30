use std::fmt;

use http::StatusCode;

use crate::metrics::fast_path::labels::FastPathTransportMissReason;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectH1TransportFailureKind {
  Connect,
  Send,
  ResponseProtocol,
  ReadTimeout,
  DownstreamCancellation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::proxy::http::fast_path) enum DirectH1UpstreamErrorKind {
  Protocol,
  ReadTimeout,
  DownstreamCancellation,
}

#[derive(Debug)]
pub(super) struct DirectH1TransportError {
  kind: DirectH1TransportFailureKind,
  source: anyhow::Error,
}

impl DirectH1TransportError {
  pub(super) fn connect(source: anyhow::Error) -> anyhow::Error {
    Self {
      kind: DirectH1TransportFailureKind::Connect,
      source,
    }
    .into()
  }

  pub(super) fn send(source: anyhow::Error) -> anyhow::Error {
    Self {
      kind: DirectH1TransportFailureKind::Send,
      source,
    }
    .into()
  }

  pub(super) fn response_protocol(source: anyhow::Error) -> anyhow::Error {
    Self {
      kind: DirectH1TransportFailureKind::ResponseProtocol,
      source,
    }
    .into()
  }

  pub(super) fn read_timeout(source: anyhow::Error) -> anyhow::Error {
    Self {
      kind: DirectH1TransportFailureKind::ReadTimeout,
      source,
    }
    .into()
  }

  pub(super) fn downstream_cancellation(source: anyhow::Error) -> anyhow::Error {
    Self {
      kind: DirectH1TransportFailureKind::DownstreamCancellation,
      source,
    }
    .into()
  }

  fn reason(&self) -> FastPathTransportMissReason {
    match self.kind {
      DirectH1TransportFailureKind::Connect => FastPathTransportMissReason::ConnectError,
      DirectH1TransportFailureKind::Send => FastPathTransportMissReason::SendError,
      DirectH1TransportFailureKind::ResponseProtocol
      | DirectH1TransportFailureKind::ReadTimeout
      | DirectH1TransportFailureKind::DownstreamCancellation => {
        FastPathTransportMissReason::ResponseError
      }
    }
  }

  fn upstream_error_kind(&self) -> Option<DirectH1UpstreamErrorKind> {
    match self.kind {
      DirectH1TransportFailureKind::Connect | DirectH1TransportFailureKind::Send => None,
      DirectH1TransportFailureKind::ResponseProtocol => Some(DirectH1UpstreamErrorKind::Protocol),
      DirectH1TransportFailureKind::ReadTimeout => Some(DirectH1UpstreamErrorKind::ReadTimeout),
      DirectH1TransportFailureKind::DownstreamCancellation => {
        Some(DirectH1UpstreamErrorKind::DownstreamCancellation)
      }
    }
  }
}

impl fmt::Display for DirectH1TransportError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.source)
  }
}

impl std::error::Error for DirectH1TransportError {}

pub(super) fn direct_h1_transport_miss_reason(
  error: &anyhow::Error,
) -> FastPathTransportMissReason {
  if let Some(error) = error.downcast_ref::<DirectH1TransportError>() {
    return error.reason();
  }
  if error.to_string().contains("timed out") {
    FastPathTransportMissReason::ConnectError
  } else {
    FastPathTransportMissReason::SendError
  }
}

pub(in crate::proxy::http::fast_path) fn direct_h1_upstream_error_kind(
  error: &anyhow::Error,
) -> Option<DirectH1UpstreamErrorKind> {
  error
    .downcast_ref::<DirectH1TransportError>()
    .and_then(DirectH1TransportError::upstream_error_kind)
}

pub(in crate::proxy::http::fast_path) fn direct_h1_upstream_error_response(
  error: &anyhow::Error,
) -> Option<(&'static str, StatusCode)> {
  match direct_h1_upstream_error_kind(error)? {
    DirectH1UpstreamErrorKind::Protocol => Some(("protocol_error", StatusCode::BAD_GATEWAY)),
    DirectH1UpstreamErrorKind::ReadTimeout => Some(("read_timeout", StatusCode::GATEWAY_TIMEOUT)),
    DirectH1UpstreamErrorKind::DownstreamCancellation => {
      Some(("downstream_cancellation", StatusCode::BAD_GATEWAY))
    }
  }
}

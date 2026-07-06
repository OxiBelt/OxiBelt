use std::fmt;

use crate::metrics::fast_path::labels::FastPathTransportMissReason;

#[derive(Debug)]
pub(super) struct DirectH1TransportError {
  reason: FastPathTransportMissReason,
  source: anyhow::Error,
}

impl DirectH1TransportError {
  pub(super) fn connect(source: anyhow::Error) -> anyhow::Error {
    Self {
      reason: FastPathTransportMissReason::ConnectError,
      source,
    }
    .into()
  }

  pub(super) fn send(source: anyhow::Error) -> anyhow::Error {
    Self {
      reason: FastPathTransportMissReason::SendError,
      source,
    }
    .into()
  }

  fn reason(&self) -> FastPathTransportMissReason {
    self.reason
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

use std::sync::Arc;

use crate::circuit_breakers::AdmissionRejection;

#[derive(Debug)]
pub(in super::super) struct SharedConnectFailure {
  message: Arc<str>,
  admission: Option<AdmissionRejection>,
  failure: Option<crate::upstream_failure::UpstreamFailure>,
  retry_at: tokio::time::Instant,
}

impl SharedConnectFailure {
  pub(in super::super) fn from_error(error: anyhow::Error, retry_at: tokio::time::Instant) -> Self {
    let admission = admission_rejection(&error);
    Self {
      message: Arc::from(error.to_string()),
      admission,
      failure: crate::upstream_failure::classify(error.as_ref()),
      retry_at,
    }
  }

  pub(in super::super) fn from_ambiguous_error(
    error: anyhow::Error,
    retry_at: tokio::time::Instant,
  ) -> Self {
    let admission = admission_rejection(&error);
    Self {
      message: Arc::from(error.to_string()),
      admission,
      failure: None,
      retry_at,
    }
  }

  pub(in super::super) fn message(
    message: impl Into<Arc<str>>,
    retry_at: tokio::time::Instant,
  ) -> Self {
    Self {
      message: message.into(),
      admission: None,
      failure: None,
      retry_at,
    }
  }

  pub(in super::super) fn typed_message(
    message: impl Into<Arc<str>>,
    failure: crate::upstream_failure::UpstreamFailure,
    retry_at: tokio::time::Instant,
  ) -> Self {
    Self {
      message: message.into(),
      admission: None,
      failure: Some(failure),
      retry_at,
    }
  }

  pub(in super::super) fn retry_at(&self) -> tokio::time::Instant {
    self.retry_at
  }

  pub(in super::super) fn into_error(self) -> anyhow::Error {
    let error = self
      .admission
      .map(anyhow::Error::new)
      .unwrap_or_else(|| anyhow::anyhow!(self.message.to_string()));
    if let Some(failure) = self.failure {
      crate::upstream_failure::annotate(error, failure)
    } else {
      error
    }
  }

  pub(in super::super) fn to_error(&self) -> anyhow::Error {
    let error = self
      .admission
      .map(anyhow::Error::new)
      .unwrap_or_else(|| anyhow::anyhow!(self.message.to_string()));
    if let Some(failure) = self.failure {
      crate::upstream_failure::annotate(error, failure)
    } else {
      error
    }
  }
}

pub(super) fn admission_rejection(error: &anyhow::Error) -> Option<AdmissionRejection> {
  error
    .chain()
    .find_map(|source| source.downcast_ref::<AdmissionRejection>().copied())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn reconstituted_failure_keeps_its_typed_sidecar_and_display() {
    let failure = SharedConnectFailure::from_error(
      crate::upstream_failure::annotate(
        anyhow::anyhow!("QUIC connect failed"),
        crate::upstream_failure::UpstreamFailure::ConnectionTimeout,
      ),
      tokio::time::Instant::now(),
    );
    let error = failure.into_error();
    assert_eq!(error.to_string(), "QUIC connect failed");
    assert_eq!(
      crate::upstream_failure::classify(error.as_ref()),
      Some(crate::upstream_failure::UpstreamFailure::ConnectionTimeout)
    );
  }
}

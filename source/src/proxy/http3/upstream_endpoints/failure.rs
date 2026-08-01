use std::sync::Arc;

use crate::circuit_breakers::AdmissionRejection;

#[derive(Debug)]
pub(in super::super) struct SharedConnectFailure {
  message: Arc<str>,
  admission: Option<AdmissionRejection>,
  retry_at: tokio::time::Instant,
}

impl SharedConnectFailure {
  pub(in super::super) fn from_error(error: anyhow::Error, retry_at: tokio::time::Instant) -> Self {
    let admission = admission_rejection(&error);
    Self {
      message: Arc::from(error.to_string()),
      admission,
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
      retry_at,
    }
  }

  pub(in super::super) fn retry_at(&self) -> tokio::time::Instant {
    self.retry_at
  }

  pub(in super::super) fn into_error(self) -> anyhow::Error {
    self
      .admission
      .map(anyhow::Error::new)
      .unwrap_or_else(|| anyhow::anyhow!(self.message.to_string()))
  }

  pub(in super::super) fn to_error(&self) -> anyhow::Error {
    self
      .admission
      .map(anyhow::Error::new)
      .unwrap_or_else(|| anyhow::anyhow!(self.message.to_string()))
  }
}

pub(super) fn admission_rejection(error: &anyhow::Error) -> Option<AdmissionRejection> {
  error
    .chain()
    .find_map(|source| source.downcast_ref::<AdmissionRejection>().copied())
}

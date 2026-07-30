//! Typed, low-cardinality response failure mapping for the Compio worker.

use std::io;

use crate::metrics::Metrics;
use crate::metrics::fast_path::labels::{DirectH1ResponseProtocolFailure, FastPathMetricProtocol};

use super::super::DirectH1TransportError;
use super::super::response_protocol::{
  ResponseProtocolEngine, ResponseProtocolError, ResponseProtocolFailureReason,
};

pub(super) fn protocol_failure(
  metrics: &Metrics,
  protocol: FastPathMetricProtocol,
  error: ResponseProtocolError,
) -> anyhow::Error {
  record_protocol_failure(metrics, protocol, error.reason());
  DirectH1TransportError::response_protocol(error.into())
}

pub(super) fn protocol_failure_with_source(
  metrics: &Metrics,
  protocol: FastPathMetricProtocol,
  error: ResponseProtocolError,
  source: io::Error,
) -> anyhow::Error {
  record_protocol_failure(metrics, protocol, error.reason());
  DirectH1TransportError::response_protocol(anyhow::anyhow!("{error}: {source}"))
}

pub(super) fn timeout_failure(
  metrics: &Metrics,
  protocol: FastPathMetricProtocol,
  engine: &ResponseProtocolEngine,
  source: io::Error,
) -> anyhow::Error {
  record_protocol_failure(
    metrics,
    protocol,
    ResponseProtocolFailureReason::IdleTimeout,
  );
  let error = ResponseProtocolError::new(
    ResponseProtocolFailureReason::IdleTimeout,
    engine.state_label(),
  );
  DirectH1TransportError::read_timeout(anyhow::anyhow!("{error}: {source}"))
}

pub(super) fn cancellation_failure(
  metrics: &Metrics,
  protocol: FastPathMetricProtocol,
  engine: &ResponseProtocolEngine,
) -> anyhow::Error {
  cancellation_failure_with_source(
    metrics,
    protocol,
    engine,
    anyhow::anyhow!("downstream response receiver dropped"),
  )
}

pub(super) fn cancellation_failure_with_source(
  metrics: &Metrics,
  protocol: FastPathMetricProtocol,
  engine: &ResponseProtocolEngine,
  source: impl Into<anyhow::Error>,
) -> anyhow::Error {
  record_protocol_failure(
    metrics,
    protocol,
    ResponseProtocolFailureReason::DownstreamCancellation,
  );
  let error = ResponseProtocolError::new(
    ResponseProtocolFailureReason::DownstreamCancellation,
    engine.state_label(),
  );
  let source = source.into();
  DirectH1TransportError::downstream_cancellation(anyhow::anyhow!("{error}: {source}"))
}

fn record_protocol_failure(
  metrics: &Metrics,
  protocol: FastPathMetricProtocol,
  reason: ResponseProtocolFailureReason,
) {
  metrics.record_direct_h1_response_protocol_failure_id(protocol, metric_reason(reason));
}

pub(super) fn metric_reason(
  reason: ResponseProtocolFailureReason,
) -> DirectH1ResponseProtocolFailure {
  match reason {
    ResponseProtocolFailureReason::HeadTooLarge => DirectH1ResponseProtocolFailure::HeadTooLarge,
    ResponseProtocolFailureReason::TooManyHeaders => {
      DirectH1ResponseProtocolFailure::TooManyHeaders
    }
    ResponseProtocolFailureReason::HeaderFieldTooLarge => {
      DirectH1ResponseProtocolFailure::HeaderFieldTooLarge
    }
    ResponseProtocolFailureReason::TooManyInterimResponses => {
      DirectH1ResponseProtocolFailure::TooManyInterimResponses
    }
    ResponseProtocolFailureReason::InvalidStatusLine => {
      DirectH1ResponseProtocolFailure::InvalidStatusLine
    }
    ResponseProtocolFailureReason::InvalidHeaderSyntax => {
      DirectH1ResponseProtocolFailure::InvalidHeaderSyntax
    }
    ResponseProtocolFailureReason::InvalidTransferCodingSequence => {
      DirectH1ResponseProtocolFailure::InvalidTransferCodingSequence
    }
    ResponseProtocolFailureReason::ChunkLineTooLarge => {
      DirectH1ResponseProtocolFailure::ChunkLineTooLarge
    }
    ResponseProtocolFailureReason::InvalidChunkSize => {
      DirectH1ResponseProtocolFailure::InvalidChunkSize
    }
    ResponseProtocolFailureReason::InvalidChunkExtension => {
      DirectH1ResponseProtocolFailure::InvalidChunkExtension
    }
    ResponseProtocolFailureReason::InvalidChunkTerminator => {
      DirectH1ResponseProtocolFailure::InvalidChunkTerminator
    }
    ResponseProtocolFailureReason::ChunkExtensionTooLarge => {
      DirectH1ResponseProtocolFailure::ChunkExtensionTooLarge
    }
    ResponseProtocolFailureReason::TrailerBlockTooLarge => {
      DirectH1ResponseProtocolFailure::TrailerBlockTooLarge
    }
    ResponseProtocolFailureReason::TooManyTrailers => {
      DirectH1ResponseProtocolFailure::TooManyTrailers
    }
    ResponseProtocolFailureReason::InvalidTrailerField => {
      DirectH1ResponseProtocolFailure::InvalidTrailerField
    }
    ResponseProtocolFailureReason::TrailerFieldTooLarge => {
      DirectH1ResponseProtocolFailure::TrailerFieldTooLarge
    }
    ResponseProtocolFailureReason::UnexpectedEof => DirectH1ResponseProtocolFailure::UnexpectedEof,
    ResponseProtocolFailureReason::IdleTimeout => DirectH1ResponseProtocolFailure::IdleTimeout,
    ResponseProtocolFailureReason::DownstreamCancellation => {
      DirectH1ResponseProtocolFailure::DownstreamCancellation
    }
    ResponseProtocolFailureReason::UnsupportedUpgrade => {
      DirectH1ResponseProtocolFailure::UnsupportedUpgrade
    }
  }
}

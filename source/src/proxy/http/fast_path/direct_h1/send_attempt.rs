use std::fmt;
use std::time::Duration;

use http::{Request, Response};
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use tokio::time::{Instant as TokioInstant, timeout_at};

use crate::metrics::Metrics;
use crate::metrics::fast_path::labels::FastPathMetricProtocol;
use crate::proxy::http::body::ProxyBody;

use super::timing;

#[derive(Debug)]
pub(super) enum DirectH1SendAttemptError {
  Timeout,
  Hyper(hyper::Error),
}

impl fmt::Display for DirectH1SendAttemptError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Timeout => formatter.write_str("direct H1 upstream first-byte timed out"),
      Self::Hyper(error) => write!(formatter, "{error}"),
    }
  }
}

impl std::error::Error for DirectH1SendAttemptError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::Timeout => None,
      Self::Hyper(error) => Some(error),
    }
  }
}

pub(super) async fn send_request_with_timing(
  sender: &mut SendRequest<ProxyBody>,
  request: Request<ProxyBody>,
  metrics: &Metrics,
  protocol: FastPathMetricProtocol,
  timeout: Duration,
  timing_enabled: bool,
) -> Result<Response<Incoming>, DirectH1SendAttemptError> {
  let deadline = TokioInstant::now() + timeout;
  let attempt_started = timing::start(timing_enabled);

  let ready_started = timing::start(timing_enabled);
  match timeout_at(deadline, sender.ready()).await {
    Ok(Ok(())) => record_stage(
      metrics,
      protocol,
      timing::STAGE_DIRECT_H1_SENDER_READY,
      true,
      ready_started,
    ),
    Ok(Err(error)) => {
      record_stage(
        metrics,
        protocol,
        timing::STAGE_DIRECT_H1_SENDER_READY,
        false,
        ready_started,
      );
      record_stage(
        metrics,
        protocol,
        timing::STAGE_DIRECT_H1_SEND_REQUEST,
        false,
        attempt_started,
      );
      return Err(DirectH1SendAttemptError::Hyper(error));
    }
    Err(_) => {
      record_stage(
        metrics,
        protocol,
        timing::STAGE_DIRECT_H1_SENDER_READY,
        false,
        ready_started,
      );
      record_stage(
        metrics,
        protocol,
        timing::STAGE_DIRECT_H1_SEND_REQUEST,
        false,
        attempt_started,
      );
      return Err(DirectH1SendAttemptError::Timeout);
    }
  }

  let submit_started = timing::start(timing_enabled);
  let response = sender.send_request(request);
  record_stage(
    metrics,
    protocol,
    timing::STAGE_DIRECT_H1_REQUEST_SUBMIT,
    true,
    submit_started,
  );

  let response_head_started = timing::start(timing_enabled);
  let response = timeout_at(deadline, response).await;
  let success = matches!(&response, Ok(Ok(_)));
  record_stage(
    metrics,
    protocol,
    timing::STAGE_DIRECT_H1_RESPONSE_HEAD,
    success,
    response_head_started,
  );
  record_stage(
    metrics,
    protocol,
    timing::STAGE_DIRECT_H1_SEND_REQUEST,
    success,
    attempt_started,
  );

  match response {
    Ok(Ok(response)) => Ok(response),
    Ok(Err(error)) => Err(DirectH1SendAttemptError::Hyper(error)),
    Err(_) => Err(DirectH1SendAttemptError::Timeout),
  }
}

fn record_stage(
  metrics: &Metrics,
  protocol: FastPathMetricProtocol,
  stage: crate::metrics::fast_path::labels::FastPathMetricStage,
  success: bool,
  started_at: Option<std::time::Instant>,
) {
  timing::record_metrics_plain_result(metrics, protocol, stage, success, started_at);
}

//! Ownership-bearing request operation passed to a persistent Compio worker.

use std::cell::RefCell;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use bytes::Bytes;
use http::{HeaderMap, Response, Version};
use hyper::body::Frame;
use tokio::runtime::Handle;
use tokio::sync::{OwnedSemaphorePermit, mpsc, oneshot};

use crate::circuit_breakers::AdmissionLease;
use crate::config::EarlyHintsMode;
use crate::metrics::Metrics;
use crate::metrics::compio_direct_h1::{CompioDirectH1BufferEvent, CompioDirectH1ConnectionEvent};
use crate::metrics::fast_path::labels::FastPathMetricProtocol;
use crate::proxy::http::EffectiveTimeouts;
use crate::proxy::http::body::{self, BoxError, ProxyBody, ProxyBodyFrame};
use crate::proxy::http::semantics::{
  InterimResponses, attach_interim_responses, capture_early_hint,
};

use super::super::compio_transport::cancellation::CancellationToken;
use super::super::compio_transport::failure::{
  cancellation_failure, cancellation_failure_with_source, protocol_failure,
  protocol_failure_with_source, timeout_failure,
};
use super::super::response_protocol::{
  ResponseBodyMode, ResponseEvent, ResponseProtocolEngine, ResponseProtocolError,
  ResponseProtocolFailureReason, ResponseProtocolLimits, ResponseState, ResponseStep,
};
use super::super::{
  DirectH1Pool, DirectH1SendMetricOptions, DirectH1TransportError, PreparedDirectH1Request,
  connection_header_contains, timing,
};
use super::connection_pool::{Checkout, WorkerConnection, WorkerConnectionPool};
use super::io as compio_io;

const RESPONSE_IO_BUFFER_BYTES: usize = 16 * 1024;
const BODY_CHANNEL_CAPACITY: usize = 16;

pub(in crate::proxy::http::fast_path::direct_h1) struct CompioDirectH1Operation {
  pub(super) pool: Arc<DirectH1Pool>,
  pub(super) metrics: Arc<Metrics>,
  pub(super) protocol: FastPathMetricProtocol,
  pub(super) prepared: Option<PreparedDirectH1Request>,
  pub(super) resolved: Arc<[SocketAddr]>,
  pub(super) timeouts: EffectiveTimeouts,
  pub(super) early_hints_mode: EarlyHintsMode,
  pub(super) metric_options: DirectH1SendMetricOptions,
  pub(super) cancellation: CancellationToken,
  pub(super) body_sender: Option<mpsc::Sender<ProxyBodyFrame>>,
  _operation_admission: Option<OwnedSemaphorePermit>,
  completion: Option<oneshot::Sender<CompioDirectH1OperationResult>>,
}

impl CompioDirectH1Operation {
  #[allow(clippy::too_many_arguments)]
  pub(in crate::proxy::http::fast_path::direct_h1) fn new(
    pool: Arc<DirectH1Pool>,
    metrics: Arc<Metrics>,
    protocol: FastPathMetricProtocol,
    prepared: PreparedDirectH1Request,
    resolved: Arc<[SocketAddr]>,
    timeouts: EffectiveTimeouts,
    early_hints_mode: EarlyHintsMode,
    metric_options: DirectH1SendMetricOptions,
    cancellation: CancellationToken,
  ) -> Self {
    Self {
      pool,
      metrics,
      protocol,
      prepared: Some(prepared),
      resolved,
      timeouts,
      early_hints_mode,
      metric_options,
      cancellation,
      body_sender: None,
      _operation_admission: None,
      completion: None,
    }
  }

  pub(super) fn origin(&self) -> &super::super::DirectH1Origin {
    &self.pool.origin
  }

  pub(super) fn with_completion(
    mut self,
  ) -> (Self, oneshot::Receiver<CompioDirectH1OperationResult>) {
    let (sender, receiver) = oneshot::channel();
    self.completion = Some(sender);
    (self, receiver)
  }

  pub(super) fn set_admission_permit(&mut self, permit: OwnedSemaphorePermit) {
    self._operation_admission = Some(permit);
  }

  pub(super) fn predispatch(
    &mut self,
    reason: CompioDirectH1PredispatchReason,
  ) -> CompioDirectH1OperationResult {
    self.predispatch_with_source(reason, None)
  }

  pub(super) fn predispatch_with_source(
    &mut self,
    reason: CompioDirectH1PredispatchReason,
    source: Option<anyhow::Error>,
  ) -> CompioDirectH1OperationResult {
    let Some(prepared) = self.prepared.take() else {
      return CompioDirectH1OperationResult::Failed {
        visibility: CompioDirectH1Visibility::WriteSubmitted,
        bytes_written: 0,
        source: anyhow::anyhow!(
          "Compio direct-H1 operation lost request ownership before dispatch"
        ),
      };
    };
    CompioDirectH1OperationResult::NotSubmitted {
      prepared: Box::new(prepared),
      reason,
      source,
      visibility: CompioDirectH1Visibility::NotSubmitted,
      bytes_written: 0,
    }
  }

  pub(super) fn complete(&mut self, result: CompioDirectH1OperationResult) -> bool {
    self
      .completion
      .take()
      .is_some_and(|sender| sender.send(result).is_ok())
  }

  pub(super) fn take_prepared(&mut self) -> Option<PreparedDirectH1Request> {
    self.prepared.take()
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::proxy::http::fast_path::direct_h1) enum CompioDirectH1PredispatchReason {
  QueueFull,
  Unhealthy,
  Draining,
  ConnectionLimit,
  Resolve,
  Connect,
  Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::proxy::http::fast_path::direct_h1) enum CompioDirectH1Visibility {
  NotSubmitted,
  WriteSubmitted,
  ResponseObserved,
}

pub(in crate::proxy::http::fast_path::direct_h1) enum CompioDirectH1OperationResult {
  NotSubmitted {
    prepared: Box<PreparedDirectH1Request>,
    reason: CompioDirectH1PredispatchReason,
    source: Option<anyhow::Error>,
    visibility: CompioDirectH1Visibility,
    bytes_written: usize,
  },
  ResponseHead {
    head: ResponseHead,
    body: ProxyBody,
    downstream_cancellation_required: bool,
    visibility: CompioDirectH1Visibility,
    bytes_written: usize,
  },
  Failed {
    visibility: CompioDirectH1Visibility,
    bytes_written: usize,
    source: anyhow::Error,
  },
}

pub(in crate::proxy::http::fast_path::direct_h1) struct ResponseHead {
  version: Version,
  status: http::StatusCode,
  headers: HeaderMap,
  interim: InterimResponses,
}

impl ResponseHead {
  pub(super) fn new(
    version: Version,
    status: http::StatusCode,
    headers: HeaderMap,
    interim: InterimResponses,
  ) -> Self {
    Self {
      version,
      status,
      headers,
      interim,
    }
  }

  pub(in crate::proxy::http::fast_path::direct_h1) fn into_response(
    self,
    body: ProxyBody,
  ) -> anyhow::Result<Response<ProxyBody>> {
    let mut response = Response::builder()
      .version(self.version)
      .status(self.status)
      .body(body)
      .context("failed to build Compio direct-H1 response")?;
    *response.headers_mut() = self.headers;
    attach_interim_responses(&mut response, self.interim);
    Ok(response)
  }
}

/// Execute one ownership-bearing transaction on the worker's persistent
/// Compio runtime. The response parser is the sole authority that may return a
/// connection to the idle pool: only an emitted `Complete` event with no
/// residual input and reusable HTTP/1.1 framing reaches `put_idle`.
pub(super) async fn run_operation(
  operation: &mut CompioDirectH1Operation,
  pool: &Rc<RefCell<WorkerConnectionPool>>,
  tokio_handle: &Handle,
) {
  let origin = operation.origin().identity();
  if operation.cancellation.is_cancelled() {
    let result = operation.predispatch(CompioDirectH1PredispatchReason::Cancelled);
    operation.complete(result);
    return;
  }

  let checkout = pool.borrow_mut().checkout(
    &origin,
    operation.pool.idle_timeout,
    operation.pool.max_lifetime,
  );
  let connection = match checkout {
    Checkout::Reused(connection) => connection,
    Checkout::Limited => {
      let result = operation.predispatch(CompioDirectH1PredispatchReason::ConnectionLimit);
      operation.complete(result);
      return;
    }
    Checkout::Reserved(permit) => {
      let connect_deadline = deadline(operation.timeouts.upstream_connect);
      let shared_admission = match acquire_shared_connection_admission(
        operation,
        tokio_handle,
        connect_deadline,
      )
      .await
      {
        Ok(admission) => admission,
        Err(source) => {
          pool.borrow_mut().connect_failed(&origin, permit);
          let reason = if operation.cancellation.is_cancelled() {
            CompioDirectH1PredispatchReason::Cancelled
          } else {
            CompioDirectH1PredispatchReason::ConnectionLimit
          };
          let result = operation.predispatch_with_source(reason, Some(source));
          operation.complete(result);
          return;
        }
      };
      let connect_timeout = match remaining_timeout(connect_deadline) {
        Ok(timeout) => timeout,
        Err(source) => {
          pool.borrow_mut().connect_failed(&origin, permit);
          let source = DirectH1TransportError::connect(source.into());
          let result = operation
            .predispatch_with_source(CompioDirectH1PredispatchReason::Connect, Some(source));
          operation.complete(result);
          return;
        }
      };
      let connect_started = Instant::now();
      let connect_timing = timing::start(operation.metric_options.timing_enabled);
      let connected = compio_io::connect(
        &operation.resolved,
        connect_timeout,
        &operation.cancellation,
      )
      .await;
      operation
        .metrics
        .observe_compio_direct_h1_connect(connect_started.elapsed());
      timing::record_metrics_plain_result(
        &operation.metrics,
        operation.protocol,
        timing::STAGE_DIRECT_H1_CONNECT,
        connected.is_ok(),
        connect_timing,
      );
      let (fd, endpoint) = match connected {
        Ok(connected) => connected,
        Err(source) => {
          pool.borrow_mut().connect_failed(&origin, permit);
          let reason = if operation.cancellation.is_cancelled()
            || source.kind() == io::ErrorKind::Interrupted
          {
            CompioDirectH1PredispatchReason::Cancelled
          } else {
            CompioDirectH1PredispatchReason::Connect
          };
          let source = DirectH1TransportError::connect(source.into());
          let result = operation.predispatch_with_source(reason, Some(source));
          operation.complete(result);
          return;
        }
      };
      operation
        .metrics
        .record_compio_direct_h1_connection_event(CompioDirectH1ConnectionEvent::Created);
      if operation.metric_options.hot_path_metrics {
        operation
          .metrics
          .record_http_upstream_h1_http_primary_connection_created();
      }
      let generation = pool.borrow().generation();
      WorkerConnection::new(fd, endpoint, generation, permit, shared_admission)
    }
  };
  run_on_connection(operation, pool, &origin, connection).await;
}

async fn acquire_shared_connection_admission(
  operation: &CompioDirectH1Operation,
  tokio_handle: &Handle,
  deadline: Instant,
) -> anyhow::Result<Option<AdmissionLease>> {
  let Some(circuit_breakers) = operation.pool.circuit_breakers.clone() else {
    return Ok(None);
  };
  let mut admission = tokio_handle.spawn(async move {
    circuit_breakers
      .admit_upstream_connection(None, Some(deadline))
      .await
  });
  tokio::select! {
    biased;
    _ = operation.cancellation.cancelled() => {
      admission.abort();
      let _ = admission.await;
      anyhow::bail!("Compio direct-H1 connection admission cancelled");
    }
    result = &mut admission => {
      Ok(Some(
        result
          .context("Compio direct-H1 connection admission task failed")?
          .context("Compio direct-H1 shared connection capacity rejected the connection")?
      ))
    }
  }
}

async fn run_on_connection(
  operation: &mut CompioDirectH1Operation,
  pool: &Rc<RefCell<WorkerConnectionPool>>,
  origin: &super::super::origin::DirectH1OriginIdentity,
  mut connection: WorkerConnection,
) {
  let limits = ResponseProtocolLimits::default();
  let request = match operation.prepared.as_ref() {
    Some(prepared) => prepared.request(),
    None => {
      pool.borrow_mut().retire_active(
        origin,
        connection,
        CompioDirectH1ConnectionEvent::RetiredWorkerFailure,
      );
      operation.complete(CompioDirectH1OperationResult::Failed {
        visibility: CompioDirectH1Visibility::WriteSubmitted,
        bytes_written: 0,
        source: anyhow::anyhow!(
          "Compio direct-H1 operation request ownership was already consumed"
        ),
      });
      return;
    }
  };
  let mut engine = match ResponseProtocolEngine::new(request.method().clone(), limits) {
    Ok(engine) => engine,
    Err(error) => {
      pool
        .borrow_mut()
        .put_idle(origin, connection, operation.pool.max_idle);
      let result = operation.predispatch_with_source(
        CompioDirectH1PredispatchReason::Unhealthy,
        Some(error.into()),
      );
      operation.complete(result);
      return;
    }
  };
  let request_allows_reuse = !connection_header_contains(request.headers(), "close");
  let mut write_buffer = pool.borrow_mut().take_buffer(512);
  if let Err(error) = operation
    .prepared
    .as_ref()
    .map(|prepared| prepared.serialize_compio_wire(&mut write_buffer))
    .unwrap_or_else(|| Err(anyhow::anyhow!("Compio request ownership is unavailable")))
  {
    pool.borrow_mut().put_buffer(write_buffer);
    pool
      .borrow_mut()
      .put_idle(origin, connection, operation.pool.max_idle);
    let result =
      operation.predispatch_with_source(CompioDirectH1PredispatchReason::Unhealthy, Some(error));
    operation.complete(result);
    return;
  }
  operation
    .metrics
    .record_compio_direct_h1_copied_bytes(write_buffer.len());
  if operation.cancellation.is_cancelled() {
    pool.borrow_mut().put_buffer(write_buffer);
    pool
      .borrow_mut()
      .put_idle(origin, connection, operation.pool.max_idle);
    let result = operation.predispatch(CompioDirectH1PredispatchReason::Cancelled);
    operation.complete(result);
    return;
  }

  // Consuming the request immediately before entering `send_all` is the
  // conservative externally-observable boundary. Any later ambiguity is
  // reported as `WriteSubmitted`, even when confirmed bytes_written is zero.
  let Some(_dispatched_request) = operation.take_prepared() else {
    pool.borrow_mut().put_buffer(write_buffer);
    pool.borrow_mut().retire_active(
      origin,
      connection,
      CompioDirectH1ConnectionEvent::RetiredWorkerFailure,
    );
    operation.complete(CompioDirectH1OperationResult::Failed {
      visibility: CompioDirectH1Visibility::WriteSubmitted,
      bytes_written: 0,
      source: anyhow::anyhow!("Compio request ownership vanished before write submission"),
    });
    return;
  };
  let request_started = timing::start(operation.metric_options.timing_enabled);
  let submit_started = timing::start(operation.metric_options.timing_enabled);
  let send_result = compio_io::send_all(
    &connection.fd,
    write_buffer,
    operation.timeouts.upstream_send,
    &operation.cancellation,
  )
  .await;
  timing::record_metrics_plain_result(
    &operation.metrics,
    operation.protocol,
    timing::STAGE_DIRECT_H1_REQUEST_SUBMIT,
    send_result.is_ok(),
    submit_started,
  );
  let (write_buffer, bytes_written) = match send_result {
    Ok(result) => result,
    Err(error) => {
      operation
        .metrics
        .record_compio_direct_h1_buffer_event(CompioDirectH1BufferEvent::Discard);
      let event = retirement_for_io(&error.source, &operation.cancellation);
      pool.borrow_mut().retire_active(origin, connection, event);
      let source = if operation.cancellation.is_cancelled() {
        cancellation_failure(&operation.metrics, operation.protocol, &engine)
      } else {
        DirectH1TransportError::send(error.source.into())
      };
      operation.complete(CompioDirectH1OperationResult::Failed {
        visibility: CompioDirectH1Visibility::WriteSubmitted,
        bytes_written: error.bytes_written,
        source,
      });
      return;
    }
  };
  pool.borrow_mut().put_buffer(write_buffer);
  connection.request_count = connection.request_count.saturating_add(1);

  let response_head_started = timing::start(operation.metric_options.timing_enabled);
  let first_head_deadline = deadline(operation.timeouts.upstream_first_byte);
  let mut pending = pool
    .borrow_mut()
    .take_response_buffer(RESPONSE_IO_BUFFER_BYTES);
  let mut response_buffer_owned = true;
  let mut interim = InterimResponses::default();
  let mut head_delivered = false;
  let mut response_observed = false;
  let mut eof = false;
  let mut response_version = None;
  let mut response_body_mode = None;
  let mut response_allows_reuse = false;
  let mut inline_head = None;
  let mut inline_body = None;
  let mut inline_body_length = None;

  let completion = loop {
    let step = match engine.decode(&mut pending, eof) {
      Ok(step) => step,
      Err(error) => {
        let event = retirement_for_protocol_failure(error.reason());
        break Err((
          event,
          protocol_failure(&operation.metrics, operation.protocol, error),
        ));
      }
    };
    match step {
      ResponseStep::Event(ResponseEvent::InterimHead { status, headers }) => {
        response_observed = true;
        let _ = capture_early_hint(
          &mut interim,
          operation.early_hints_mode,
          status,
          &headers,
          limits.max_interim_responses,
        );
      }
      ResponseStep::Event(ResponseEvent::FinalHead {
        version,
        status,
        headers,
        body_mode,
      }) => {
        response_observed = true;
        response_version = Some(version);
        response_body_mode = Some(body_mode);
        response_allows_reuse = !connection_header_contains(&headers, "close");
        let head = ResponseHead::new(version, status, headers, std::mem::take(&mut interim));
        if let Some(length) = inline_response_length(body_mode, pending.len()) {
          inline_head = Some(head);
          inline_body_length = Some(length);
        } else {
          let (body_sender, body) = body::channel_body(BODY_CHANNEL_CAPACITY);
          operation.body_sender = Some(body_sender);
          if !operation.complete(CompioDirectH1OperationResult::ResponseHead {
            head,
            body,
            downstream_cancellation_required: true,
            visibility: CompioDirectH1Visibility::ResponseObserved,
            bytes_written,
          }) {
            break Err((
              CompioDirectH1ConnectionEvent::RetiredCancellation,
              cancellation_failure(&operation.metrics, operation.protocol, &engine),
            ));
          }
          head_delivered = true;
          timing::record_metrics_plain_result(
            &operation.metrics,
            operation.protocol,
            timing::STAGE_DIRECT_H1_RESPONSE_HEAD,
            true,
            response_head_started,
          );
          timing::record_metrics_plain_result(
            &operation.metrics,
            operation.protocol,
            timing::STAGE_DIRECT_H1_SEND_REQUEST,
            true,
            request_started,
          );
        }
      }
      ResponseStep::Event(ResponseEvent::Body(bytes)) => {
        if inline_head.is_some() {
          if inline_body.replace(bytes).is_some() {
            break Err((
              CompioDirectH1ConnectionEvent::RetiredWorkerFailure,
              DirectH1TransportError::response_protocol(anyhow::anyhow!(
                "Compio direct-H1 inline response emitted multiple body frames"
              )),
            ));
          }
        } else if let Err(error) = send_body_frame(operation, Ok(Frame::data(bytes))).await {
          break Err((
            CompioDirectH1ConnectionEvent::RetiredCancellation,
            cancellation_failure_with_source(
              &operation.metrics,
              operation.protocol,
              &engine,
              error,
            ),
          ));
        }
      }
      ResponseStep::Event(ResponseEvent::Trailers(trailers)) => {
        if inline_head.is_some() {
          break Err((
            CompioDirectH1ConnectionEvent::RetiredWorkerFailure,
            DirectH1TransportError::response_protocol(anyhow::anyhow!(
              "Compio direct-H1 inline response unexpectedly emitted trailers"
            )),
          ));
        } else if !trailers.is_empty()
          && let Err(error) = send_body_frame(operation, Ok(Frame::trailers(trailers))).await
        {
          break Err((
            CompioDirectH1ConnectionEvent::RetiredCancellation,
            cancellation_failure_with_source(
              &operation.metrics,
              operation.protocol,
              &engine,
              error,
            ),
          ));
        }
      }
      ResponseStep::Event(ResponseEvent::Complete) => {
        let observed_inline_length = inline_body.as_ref().map_or(0, Bytes::len);
        if inline_body_length.is_some_and(|expected| expected != observed_inline_length) {
          break Err((
            CompioDirectH1ConnectionEvent::RetiredWorkerFailure,
            DirectH1TransportError::response_protocol(anyhow::anyhow!(
              "Compio direct-H1 inline response length invariant failed"
            )),
          ));
        }
        break Ok(());
      }
      ResponseStep::NeedInput => {
        if eof {
          let error = ResponseProtocolError::new(
            ResponseProtocolFailureReason::UnexpectedEof,
            engine.state_label(),
          );
          break Err((
            CompioDirectH1ConnectionEvent::RetiredEof,
            protocol_failure(&operation.metrics, operation.protocol, error),
          ));
        }
        if operation.cancellation.is_cancelled() {
          break Err((
            CompioDirectH1ConnectionEvent::RetiredCancellation,
            cancellation_failure(&operation.metrics, operation.protocol, &engine),
          ));
        }
        let read_timeout = match response_read_timeout(
          head_delivered,
          first_head_deadline,
          operation.timeouts.upstream_read,
        ) {
          Ok(timeout) => timeout,
          Err(error) => {
            break Err((
              CompioDirectH1ConnectionEvent::RetiredTimeout,
              timeout_failure(&operation.metrics, operation.protocol, &engine, error),
            ));
          }
        };
        let read_capacity = next_read_capacity(&engine, pending.len());
        let receive_buffer = std::mem::take(&mut pending);
        response_buffer_owned = false;
        match compio_io::recv_once(
          &connection.fd,
          receive_buffer,
          read_capacity,
          connection.recv_socket_nonempty,
          read_timeout,
          &operation.cancellation,
        )
        .await
        {
          Ok((received, bytes_read, socket_nonempty)) => {
            pending = received;
            response_buffer_owned = true;
            connection.recv_socket_nonempty = socket_nonempty;
            if bytes_read == 0 {
              eof = true;
            } else {
              response_observed = true;
            }
          }
          Err(error)
            if operation.cancellation.is_cancelled()
              || error.kind() == io::ErrorKind::Interrupted =>
          {
            operation
              .metrics
              .record_compio_direct_h1_buffer_event(CompioDirectH1BufferEvent::Discard);
            break Err((
              CompioDirectH1ConnectionEvent::RetiredCancellation,
              cancellation_failure_with_source(
                &operation.metrics,
                operation.protocol,
                &engine,
                error,
              ),
            ));
          }
          Err(error) if error.kind() == io::ErrorKind::TimedOut => {
            operation
              .metrics
              .record_compio_direct_h1_buffer_event(CompioDirectH1BufferEvent::Discard);
            break Err((
              CompioDirectH1ConnectionEvent::RetiredTimeout,
              timeout_failure(&operation.metrics, operation.protocol, &engine, error),
            ));
          }
          Err(error) => {
            operation
              .metrics
              .record_compio_direct_h1_buffer_event(CompioDirectH1BufferEvent::Discard);
            let retirement = retirement_for_response_read_error(&error);
            let protocol_error = ResponseProtocolError::new(
              ResponseProtocolFailureReason::UnexpectedEof,
              engine.state_label(),
            );
            break Err((
              retirement,
              protocol_failure_with_source(
                &operation.metrics,
                operation.protocol,
                protocol_error,
                error,
              ),
            ));
          }
        }
      }
    }
  };

  match completion {
    Ok(()) => {
      let retirement = if !pending.is_empty() {
        Some(CompioDirectH1ConnectionEvent::RetiredResidualBytes)
      } else if eof || response_body_mode == Some(ResponseBodyMode::CloseDelimited) {
        Some(CompioDirectH1ConnectionEvent::RetiredEof)
      } else if response_version != Some(Version::HTTP_11)
        || !request_allows_reuse
        || !response_allows_reuse
      {
        Some(CompioDirectH1ConnectionEvent::RetiredPeerClose)
      } else if operation.cancellation.is_cancelled() {
        Some(CompioDirectH1ConnectionEvent::RetiredCancellation)
      } else {
        match compio_io::reuse_readiness(&connection.fd, connection.recv_socket_nonempty) {
          Ok(compio_io::ReuseReadiness::Clean) => None,
          Ok(compio_io::ReuseReadiness::Residual) => {
            Some(CompioDirectH1ConnectionEvent::RetiredResidualBytes)
          }
          Ok(compio_io::ReuseReadiness::Eof) => Some(CompioDirectH1ConnectionEvent::RetiredEof),
          Err(_) => Some(CompioDirectH1ConnectionEvent::RetiredIoError),
        }
      };
      if let Some(event) = retirement {
        pool.borrow_mut().retire_active(origin, connection, event);
      } else {
        pool
          .borrow_mut()
          .put_idle(origin, connection, operation.pool.max_idle);
      }
      if let Some(head) = inline_head.take() {
        // The complete framing and connection-retirement decision are already
        // terminal. Disarm before waking Tokio so dropping the materialized
        // body cannot race a finished worker operation.
        operation.cancellation.disarm();
        let body = body::known_small_no_trailers_body(inline_body.take().unwrap_or_default());
        if operation.complete(CompioDirectH1OperationResult::ResponseHead {
          head,
          body,
          downstream_cancellation_required: false,
          visibility: CompioDirectH1Visibility::ResponseObserved,
          bytes_written,
        }) {
          timing::record_metrics_plain_result(
            &operation.metrics,
            operation.protocol,
            timing::STAGE_DIRECT_H1_RESPONSE_HEAD,
            true,
            response_head_started,
          );
          timing::record_metrics_plain_result(
            &operation.metrics,
            operation.protocol,
            timing::STAGE_DIRECT_H1_SEND_REQUEST,
            true,
            request_started,
          );
        }
      }
    }
    Err((event, error)) => {
      pool.borrow_mut().retire_active(origin, connection, event);
      if !head_delivered {
        timing::record_metrics_plain_result(
          &operation.metrics,
          operation.protocol,
          timing::STAGE_DIRECT_H1_RESPONSE_HEAD,
          false,
          response_head_started,
        );
        timing::record_metrics_plain_result(
          &operation.metrics,
          operation.protocol,
          timing::STAGE_DIRECT_H1_SEND_REQUEST,
          false,
          request_started,
        );
        operation.complete(CompioDirectH1OperationResult::Failed {
          visibility: if response_observed {
            CompioDirectH1Visibility::ResponseObserved
          } else {
            CompioDirectH1Visibility::WriteSubmitted
          },
          bytes_written,
          source: error,
        });
      } else if !operation.cancellation.is_cancelled() {
        let body_error: BoxError = Box::new(io::Error::other(error.to_string()));
        let _ = send_body_frame(operation, Err(body_error)).await;
      }
    }
  }
  if response_buffer_owned {
    pool.borrow_mut().put_response_buffer(pending);
  }
}

fn retirement_for_protocol_failure(
  reason: ResponseProtocolFailureReason,
) -> CompioDirectH1ConnectionEvent {
  match reason {
    ResponseProtocolFailureReason::UnexpectedEof => CompioDirectH1ConnectionEvent::RetiredEof,
    ResponseProtocolFailureReason::UnsupportedUpgrade => {
      CompioDirectH1ConnectionEvent::RetiredUpgrade
    }
    _ => CompioDirectH1ConnectionEvent::RetiredProtocol,
  }
}

fn retirement_for_response_read_error(error: &io::Error) -> CompioDirectH1ConnectionEvent {
  if matches!(
    error.kind(),
    io::ErrorKind::UnexpectedEof
      | io::ErrorKind::ConnectionReset
      | io::ErrorKind::ConnectionAborted
      | io::ErrorKind::BrokenPipe
      | io::ErrorKind::NotConnected
  ) {
    CompioDirectH1ConnectionEvent::RetiredEof
  } else {
    CompioDirectH1ConnectionEvent::RetiredIoError
  }
}

fn retirement_for_io(
  error: &io::Error,
  cancellation: &CancellationToken,
) -> CompioDirectH1ConnectionEvent {
  if cancellation.is_cancelled() || error.kind() == io::ErrorKind::Interrupted {
    CompioDirectH1ConnectionEvent::RetiredCancellation
  } else if error.kind() == io::ErrorKind::TimedOut {
    CompioDirectH1ConnectionEvent::RetiredTimeout
  } else {
    CompioDirectH1ConnectionEvent::RetiredIoError
  }
}

async fn send_body_frame(
  operation: &CompioDirectH1Operation,
  frame: ProxyBodyFrame,
) -> anyhow::Result<()> {
  let Some(body_sender) = operation.body_sender.as_ref() else {
    return Err(anyhow::anyhow!(
      "Compio direct-H1 streaming response body sender is unavailable"
    ));
  };
  if operation.cancellation.is_cancelled() {
    return Err(anyhow::anyhow!("downstream response body receiver dropped"));
  }
  let frame = match body_sender.try_send(frame) {
    Ok(()) => return Ok(()),
    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
      return Err(anyhow::anyhow!("downstream response body receiver dropped"));
    }
    Err(tokio::sync::mpsc::error::TrySendError::Full(frame)) => frame,
  };
  let sleep = compio::time::sleep(operation.timeouts.response_send);
  tokio::pin!(sleep);
  tokio::select! {
    biased;
    _ = operation.cancellation.cancelled() => {
      Err(anyhow::anyhow!("downstream response body receiver dropped"))
    }
    _ = &mut sleep => {
      Err(anyhow::anyhow!("downstream response body send timed out"))
    }
    result = body_sender.send(frame) => {
      result.map_err(|_| anyhow::anyhow!("downstream response body receiver dropped"))
    }
  }
}

fn inline_response_length(body_mode: ResponseBodyMode, pending_len: usize) -> Option<usize> {
  match body_mode {
    ResponseBodyMode::None => Some(0),
    ResponseBodyMode::ContentLength(length) => usize::try_from(length)
      .ok()
      .filter(|length| *length <= body::KNOWN_SMALL_BODY_MAX_BYTES && *length <= pending_len),
    ResponseBodyMode::Chunked | ResponseBodyMode::CloseDelimited => None,
  }
}

fn next_read_capacity(engine: &ResponseProtocolEngine, pending_len: usize) -> usize {
  let limits = engine.limits();
  match engine.state() {
    ResponseState::ReadingHead
    | ResponseState::ProcessingInterim
    | ResponseState::WaitingForFinalHead => limits
      .max_response_head_bytes
      .saturating_sub(pending_len)
      .clamp(1, RESPONSE_IO_BUFFER_BYTES),
    ResponseState::ChunkSizeLine => limits
      .max_chunk_size_line_bytes
      .saturating_add(2)
      .saturating_sub(pending_len)
      .max(1),
    ResponseState::ChunkTerminator => 2usize.saturating_sub(pending_len).max(1),
    ResponseState::Trailers => limits
      .max_trailer_block_bytes
      .saturating_sub(pending_len)
      .clamp(1, RESPONSE_IO_BUFFER_BYTES),
    ResponseState::FixedLength { remaining } | ResponseState::ChunkData { remaining } => {
      usize::try_from(remaining)
        .unwrap_or(usize::MAX)
        .clamp(1, RESPONSE_IO_BUFFER_BYTES)
    }
    ResponseState::CloseDelimited => RESPONSE_IO_BUFFER_BYTES,
    ResponseState::Completed | ResponseState::FailedNonReusable => 1,
  }
}

fn response_read_timeout(
  head_delivered: bool,
  first_head_deadline: Instant,
  idle_timeout: Duration,
) -> io::Result<Duration> {
  if head_delivered {
    return Ok(idle_timeout);
  }
  Ok(idle_timeout.min(remaining_timeout(first_head_deadline)?))
}

fn deadline(timeout: Duration) -> Instant {
  Instant::now()
    .checked_add(timeout)
    .unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400 * 365))
}

fn remaining_timeout(deadline: Instant) -> io::Result<Duration> {
  let now = Instant::now();
  if now >= deadline {
    return Err(io::Error::new(
      io::ErrorKind::TimedOut,
      "Compio direct-H1 operation timed out",
    ));
  }
  Ok(deadline.duration_since(now))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn metadata_reads_are_chunked_without_weakening_total_limits() -> anyhow::Result<()> {
    let engine = ResponseProtocolEngine::new(http::Method::GET, ResponseProtocolLimits::default())?;
    assert_eq!(next_read_capacity(&engine, 0), RESPONSE_IO_BUFFER_BYTES);
    assert_eq!(
      next_read_capacity(&engine, engine.limits().max_response_head_bytes - 1),
      1
    );
    Ok(())
  }

  #[test]
  fn inline_response_requires_a_complete_already_buffered_small_body() {
    let maximum = body::KNOWN_SMALL_BODY_MAX_BYTES;
    assert_eq!(inline_response_length(ResponseBodyMode::None, 0), Some(0));
    assert_eq!(
      inline_response_length(ResponseBodyMode::ContentLength(maximum as u64), maximum),
      Some(maximum)
    );
    assert_eq!(
      inline_response_length(ResponseBodyMode::ContentLength(maximum as u64), maximum - 1),
      None
    );
    assert_eq!(
      inline_response_length(
        ResponseBodyMode::ContentLength((maximum + 1) as u64),
        maximum + 1
      ),
      None
    );
    assert_eq!(
      inline_response_length(ResponseBodyMode::Chunked, maximum),
      None
    );
    assert_eq!(
      inline_response_length(ResponseBodyMode::CloseDelimited, maximum),
      None
    );
  }

  #[test]
  fn protocol_failure_retirement_preserves_terminal_transport_identity() {
    assert_eq!(
      retirement_for_protocol_failure(ResponseProtocolFailureReason::UnexpectedEof),
      CompioDirectH1ConnectionEvent::RetiredEof
    );
    assert_eq!(
      retirement_for_protocol_failure(ResponseProtocolFailureReason::UnsupportedUpgrade),
      CompioDirectH1ConnectionEvent::RetiredUpgrade
    );
    assert_eq!(
      retirement_for_protocol_failure(ResponseProtocolFailureReason::InvalidStatusLine),
      CompioDirectH1ConnectionEvent::RetiredProtocol
    );
  }

  #[test]
  fn response_read_connection_termination_is_classified_as_eof_retirement() {
    for kind in [
      io::ErrorKind::UnexpectedEof,
      io::ErrorKind::ConnectionReset,
      io::ErrorKind::ConnectionAborted,
      io::ErrorKind::BrokenPipe,
      io::ErrorKind::NotConnected,
    ] {
      let error = io::Error::new(kind, "test connection termination");
      assert_eq!(
        retirement_for_response_read_error(&error),
        CompioDirectH1ConnectionEvent::RetiredEof
      );
    }
    let other = io::Error::other("test non-termination I/O error");
    assert_eq!(
      retirement_for_response_read_error(&other),
      CompioDirectH1ConnectionEvent::RetiredIoError
    );
  }
}

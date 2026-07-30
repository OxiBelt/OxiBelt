//! Linux-only Compio driver transport for guarded direct-H1 requests.

use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use bytes::{Bytes, BytesMut};
use compio::buf::IntoInner;
use compio::{BufResult, driver::OpCode};
use compio_driver::op::{Recv, RecvFlags, Send, SendFlags};
use compio_driver::{Proactor, PushEntry, SharedFd};
use http::header::TRANSFER_ENCODING;
use http::{HeaderMap, Request, Response, Version};
use hyper::body::{Body, Frame};
use tokio::sync::{mpsc, oneshot};

use crate::config::EarlyHintsMode;
use crate::metrics::Metrics;
use crate::metrics::fast_path::labels::FastPathMetricProtocol;
use crate::proxy::http::EffectiveTimeouts;
use crate::proxy::http::body::{self, BoxError, ProxyBody, ProxyBodyFrame};
use crate::proxy::http::semantics::{
  InterimResponses, attach_interim_responses, capture_early_hint,
};

use super::request::PreparedDirectH1Request;
use super::response_protocol::{
  ResponseBodyMode, ResponseEvent, ResponseProtocolEngine, ResponseProtocolError,
  ResponseProtocolFailureReason, ResponseProtocolLimits, ResponseState, ResponseStep,
};
use super::{
  DirectH1Pool, DirectH1Response, DirectH1SendMetricOptions, DirectH1TransportError, timing,
};

mod cancellation;
mod failure;
#[cfg(test)]
mod tests;

use self::cancellation::CancellationToken;
#[cfg(test)]
use self::failure::metric_reason;
use self::failure::{
  cancellation_failure, cancellation_failure_with_source, protocol_failure,
  protocol_failure_with_source, timeout_failure,
};

const RESPONSE_IO_BUFFER_BYTES: usize = 16 * 1024;
const BODY_CHANNEL_CAPACITY: usize = 16;

struct ResponseHead {
  version: Version,
  status: http::StatusCode,
  headers: HeaderMap,
  interim: InterimResponses,
}

pub(super) async fn send_prepared_request(
  pool: Arc<DirectH1Pool>,
  metrics: Arc<Metrics>,
  protocol: FastPathMetricProtocol,
  prepared: PreparedDirectH1Request,
  timeouts: EffectiveTimeouts,
  early_hints_mode: EarlyHintsMode,
  metric_options: DirectH1SendMetricOptions,
) -> anyhow::Result<DirectH1Response> {
  let request = prepared.into_request();
  let (body_sender, body) = body::channel_body(BODY_CHANNEL_CAPACITY);
  let (cancellation, cancellation_guard) = CancellationToken::pair();
  let body = body::with_drop_guard(body, cancellation_guard);
  let (head_sender, head_receiver) = oneshot::channel();
  tokio::task::spawn_blocking(move || {
    run_compio_transaction(
      pool,
      metrics,
      protocol,
      request,
      timeouts,
      early_hints_mode,
      metric_options,
      cancellation,
      head_sender,
      body_sender,
    );
  });

  let head = head_receiver
    .await
    .context("compio direct H1 transport ended before response head")??;
  let response = head.into_response(body)?;
  Ok(DirectH1Response {
    response,
    lease: None,
  })
}

#[allow(clippy::too_many_arguments)]
fn run_compio_transaction(
  pool: Arc<DirectH1Pool>,
  metrics: Arc<Metrics>,
  protocol: FastPathMetricProtocol,
  request: Request<ProxyBody>,
  timeouts: EffectiveTimeouts,
  early_hints_mode: EarlyHintsMode,
  metric_options: DirectH1SendMetricOptions,
  cancellation: CancellationToken,
  head_sender: oneshot::Sender<anyhow::Result<ResponseHead>>,
  body_sender: mpsc::Sender<ProxyBodyFrame>,
) {
  let mut head_sender = Some(head_sender);
  let result = run_compio_transaction_inner(
    &pool,
    &metrics,
    protocol,
    request,
    timeouts,
    early_hints_mode,
    metric_options,
    &cancellation,
    &mut head_sender,
    &body_sender,
  );
  if let Err(error) = result {
    if let Some(head_sender) = head_sender {
      let _ = head_sender.send(Err(error));
    } else if !cancellation.is_cancelled() {
      send_body_error(&body_sender, error);
    }
  }
}

#[allow(clippy::too_many_arguments)]
fn run_compio_transaction_inner(
  pool: &DirectH1Pool,
  metrics: &Metrics,
  protocol: FastPathMetricProtocol,
  request: Request<ProxyBody>,
  timeouts: EffectiveTimeouts,
  early_hints_mode: EarlyHintsMode,
  metric_options: DirectH1SendMetricOptions,
  cancellation: &CancellationToken,
  head_sender: &mut Option<oneshot::Sender<anyhow::Result<ResponseHead>>>,
  body_sender: &mpsc::Sender<ProxyBodyFrame>,
) -> anyhow::Result<()> {
  let mut driver = Proactor::new()
    .context("failed to build Compio direct H1 proactor")
    .map_err(DirectH1TransportError::connect)?;
  cancellation.install_driver_waker(driver.waker());
  let limits = ResponseProtocolLimits::default();
  let mut engine = ResponseProtocolEngine::new(request.method().clone(), limits)
    .context("default direct H1 response limits are invalid")?;
  if cancellation.is_cancelled() {
    return Err(cancellation_failure(metrics, protocol, &engine));
  }

  let connect_started = timing::start(metric_options.timing_enabled);
  let fd = connect_upstream(&mut driver, pool, timeouts.upstream_connect, cancellation);
  timing::record_metrics_plain_result(
    metrics,
    protocol,
    timing::STAGE_DIRECT_H1_CONNECT,
    fd.is_ok(),
    connect_started,
  );
  let fd = match fd {
    Ok(fd) => fd,
    Err(error)
      if error
        .downcast_ref::<io::Error>()
        .is_some_and(|error| error.kind() == io::ErrorKind::Interrupted) =>
    {
      return Err(cancellation_failure_with_source(
        metrics, protocol, &engine, error,
      ));
    }
    Err(error) => return Err(DirectH1TransportError::connect(error)),
  };
  if metric_options.hot_path_metrics {
    metrics.record_http_upstream_h1_http_primary_connection_created();
  }
  if cancellation.is_cancelled() {
    return Err(cancellation_failure(metrics, protocol, &engine));
  }

  let serialized = serialize_empty_h1_request(&request).map_err(DirectH1TransportError::send)?;
  let request_started = timing::start(metric_options.timing_enabled);
  let submit_started = timing::start(metric_options.timing_enabled);
  let write_result = send_all(
    &mut driver,
    &fd,
    &serialized,
    timeouts.upstream_send,
    cancellation,
  );
  timing::record_metrics_plain_result(
    metrics,
    protocol,
    timing::STAGE_DIRECT_H1_REQUEST_SUBMIT,
    write_result.is_ok(),
    submit_started,
  );
  if let Err(error) = write_result {
    if error.kind() == io::ErrorKind::Interrupted {
      return Err(cancellation_failure(metrics, protocol, &engine));
    }
    return Err(DirectH1TransportError::send(error.into()));
  }

  let response_head_started = timing::start(metric_options.timing_enabled);
  let first_head_deadline = deadline(timeouts.upstream_first_byte);
  let mut pending = BytesMut::with_capacity(RESPONSE_IO_BUFFER_BYTES);
  let mut interim = InterimResponses::default();
  let mut eof = false;
  let mut head_delivered = false;

  let result = loop {
    let step = match engine.decode(&mut pending, eof) {
      Ok(step) => step,
      Err(error) => break Err(protocol_failure(metrics, protocol, error)),
    };
    match step {
      ResponseStep::Event(ResponseEvent::InterimHead { status, headers }) => {
        let _ = capture_early_hint(
          &mut interim,
          early_hints_mode,
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
        debug_assert!(response_body_mode_matches_state(body_mode, &engine.state()));
        let response_head = ResponseHead {
          version,
          status,
          headers,
          interim: std::mem::take(&mut interim),
        };
        let Some(sender) = head_sender.take() else {
          break Err(cancellation_failure(metrics, protocol, &engine));
        };
        if sender.send(Ok(response_head)).is_err() {
          break Err(cancellation_failure(metrics, protocol, &engine));
        }
        head_delivered = true;
        timing::record_metrics_plain_result(
          metrics,
          protocol,
          timing::STAGE_DIRECT_H1_RESPONSE_HEAD,
          true,
          response_head_started,
        );
        timing::record_metrics_plain_result(
          metrics,
          protocol,
          timing::STAGE_DIRECT_H1_SEND_REQUEST,
          true,
          request_started,
        );
      }
      ResponseStep::Event(ResponseEvent::Body(bytes)) => {
        if let Err(error) = send_body_data(body_sender, bytes) {
          break Err(cancellation_failure_with_source(
            metrics, protocol, &engine, error,
          ));
        }
      }
      ResponseStep::Event(ResponseEvent::Trailers(trailers)) => {
        if let Err(error) = send_body_trailers(body_sender, trailers) {
          break Err(cancellation_failure_with_source(
            metrics, protocol, &engine, error,
          ));
        }
      }
      ResponseStep::Event(ResponseEvent::Complete) => break Ok(()),
      ResponseStep::NeedInput => {
        if eof {
          break Err(protocol_failure(
            metrics,
            protocol,
            ResponseProtocolError::new(
              ResponseProtocolFailureReason::UnexpectedEof,
              engine.state_label(),
            ),
          ));
        }
        if cancellation.is_cancelled() {
          break Err(cancellation_failure(metrics, protocol, &engine));
        }
        let read_timeout = match response_read_timeout(
          head_delivered,
          first_head_deadline,
          timeouts.upstream_read,
        ) {
          Ok(timeout) => timeout,
          Err(error) => break Err(timeout_failure(metrics, protocol, &engine, error)),
        };
        let read_capacity = next_read_capacity(&engine, pending.len());
        let bytes = match recv_once(&mut driver, &fd, read_capacity, read_timeout, cancellation) {
          Ok(bytes) => bytes,
          Err(error) if error.kind() == io::ErrorKind::Interrupted => {
            break Err(cancellation_failure_with_source(
              metrics, protocol, &engine, error,
            ));
          }
          Err(error) if error.kind() == io::ErrorKind::TimedOut => {
            break Err(timeout_failure(metrics, protocol, &engine, error));
          }
          Err(error) => {
            let protocol_error = ResponseProtocolError::new(
              ResponseProtocolFailureReason::UnexpectedEof,
              engine.state_label(),
            );
            break Err(protocol_failure_with_source(
              metrics,
              protocol,
              protocol_error,
              error,
            ));
          }
        };
        if bytes.is_empty() {
          eof = true;
        } else {
          pending.extend_from_slice(&bytes);
        }
      }
    }
  };

  if result.is_err() && !head_delivered {
    timing::record_metrics_plain_result(
      metrics,
      protocol,
      timing::STAGE_DIRECT_H1_RESPONSE_HEAD,
      false,
      response_head_started,
    );
    timing::record_metrics_plain_result(
      metrics,
      protocol,
      timing::STAGE_DIRECT_H1_SEND_REQUEST,
      false,
      request_started,
    );
  }
  result
}

fn response_body_mode_matches_state(mode: ResponseBodyMode, state: &ResponseState) -> bool {
  matches!(
    (mode, state),
    (ResponseBodyMode::None, ResponseState::Completed)
      | (
        ResponseBodyMode::ContentLength(_),
        ResponseState::FixedLength { .. }
      )
      | (ResponseBodyMode::Chunked, ResponseState::ChunkSizeLine)
      | (
        ResponseBodyMode::CloseDelimited,
        ResponseState::CloseDelimited
      )
  )
}

fn connect_upstream(
  driver: &mut Proactor,
  pool: &DirectH1Pool,
  timeout: Duration,
  cancellation: &CancellationToken,
) -> anyhow::Result<SharedFd<TcpStream>> {
  let mut last_error = None;
  let addrs = (pool.origin.host.as_str(), pool.origin.port)
    .to_socket_addrs()
    .with_context(|| {
      format!(
        "failed to resolve direct H1 upstream {}:{}",
        pool.origin.host, pool.origin.port
      )
    })?;
  for addr in addrs {
    if cancellation.is_cancelled() {
      return Err(cancelled_io_error().into());
    }
    match TcpStream::connect_timeout(&addr, timeout) {
      Ok(stream) => {
        if cancellation.is_cancelled() {
          return Err(cancelled_io_error().into());
        }
        stream
          .set_nodelay(true)
          .context("failed to enable TCP_NODELAY for compio direct H1 upstream")?;
        stream
          .set_nonblocking(true)
          .context("failed to set compio direct H1 upstream nonblocking")?;
        let fd = SharedFd::new(stream);
        driver
          .attach(fd.as_raw_fd())
          .context("failed to attach compio direct H1 upstream socket")?;
        return Ok(fd);
      }
      Err(error) => last_error = Some(error),
    }
  }
  Err(
    last_error
      .map(anyhow::Error::from)
      .unwrap_or_else(|| anyhow::anyhow!("direct H1 upstream resolved no socket addresses")),
  )
}

fn serialize_empty_h1_request(request: &Request<ProxyBody>) -> anyhow::Result<Vec<u8>> {
  if !request.body().is_end_stream() {
    bail!("compio direct H1 only supports prevalidated empty request bodies");
  }
  if request.headers().contains_key(TRANSFER_ENCODING) {
    bail!("compio direct H1 does not serialize transfer-encoded request bodies");
  }
  let mut bytes = Vec::with_capacity(512 + request.headers().len() * 48);
  bytes.extend_from_slice(request.method().as_str().as_bytes());
  bytes.push(b' ');
  let target = request
    .uri()
    .path_and_query()
    .map(|target| target.as_str())
    .unwrap_or("/");
  bytes.extend_from_slice(target.as_bytes());
  bytes.extend_from_slice(b" HTTP/1.1\r\n");
  for (name, value) in request.headers() {
    bytes.extend_from_slice(name.as_str().as_bytes());
    bytes.extend_from_slice(b": ");
    bytes.extend_from_slice(value.as_bytes());
    bytes.extend_from_slice(b"\r\n");
  }
  bytes.extend_from_slice(b"\r\n");
  Ok(bytes)
}

fn send_all(
  driver: &mut Proactor,
  fd: &SharedFd<TcpStream>,
  bytes: &[u8],
  timeout: Duration,
  cancellation: &CancellationToken,
) -> io::Result<()> {
  let deadline = deadline(timeout);
  let mut written = 0;
  while written < bytes.len() {
    let buffer = bytes[written..].to_vec();
    let remaining = remaining_timeout(deadline)?;
    let (count, _) = push_and_wait(
      driver,
      Send::new(fd.clone(), buffer, SendFlags::empty()),
      remaining,
      cancellation,
    )?;
    if count == 0 {
      return Err(io::Error::new(
        io::ErrorKind::WriteZero,
        "compio direct H1 upstream send wrote zero bytes",
      ));
    }
    written += count;
  }
  Ok(())
}

fn recv_once(
  driver: &mut Proactor,
  fd: &SharedFd<TcpStream>,
  capacity: usize,
  timeout: Duration,
  cancellation: &CancellationToken,
) -> io::Result<Vec<u8>> {
  let buffer = vec![0; capacity.max(1)];
  let (count, op) = push_and_wait(
    driver,
    Recv::new(fd.clone(), buffer, RecvFlags::empty()),
    timeout,
    cancellation,
  )?;
  let mut buffer = op.into_inner();
  buffer.truncate(count);
  Ok(buffer)
}

fn next_read_capacity(engine: &ResponseProtocolEngine, pending_len: usize) -> usize {
  let limits = engine.limits();
  match engine.state() {
    ResponseState::ReadingHead
    | ResponseState::ProcessingInterim
    | ResponseState::WaitingForFinalHead => limits
      .max_response_head_bytes
      .saturating_sub(pending_len)
      .max(1),
    ResponseState::ChunkSizeLine => limits
      .max_chunk_size_line_bytes
      .saturating_add(2)
      .saturating_sub(pending_len)
      .max(1),
    ResponseState::ChunkTerminator => 2usize.saturating_sub(pending_len).max(1),
    ResponseState::Trailers => limits
      .max_trailer_block_bytes
      .saturating_sub(pending_len)
      .max(1),
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

fn send_body_data(sender: &mpsc::Sender<ProxyBodyFrame>, bytes: Bytes) -> anyhow::Result<()> {
  if bytes.is_empty() {
    return Ok(());
  }
  sender
    .blocking_send(Ok(Frame::data(bytes)))
    .map_err(|_| anyhow::anyhow!("downstream response body receiver dropped"))
}

fn send_body_trailers(
  sender: &mpsc::Sender<ProxyBodyFrame>,
  trailers: HeaderMap,
) -> anyhow::Result<()> {
  if trailers.is_empty() {
    return Ok(());
  }
  sender
    .blocking_send(Ok(Frame::trailers(trailers)))
    .map_err(|_| anyhow::anyhow!("downstream response body receiver dropped"))
}

fn send_body_error(sender: &mpsc::Sender<ProxyBodyFrame>, error: anyhow::Error) {
  let error: BoxError = Box::new(io::Error::other(error.to_string()));
  let _ = sender.blocking_send(Err(error));
}

fn push_and_wait<O>(
  driver: &mut Proactor,
  op: O,
  timeout: Duration,
  cancellation: &CancellationToken,
) -> io::Result<(usize, O)>
where
  O: OpCode + 'static,
{
  if cancellation.is_cancelled() {
    return Err(cancelled_io_error());
  }
  let end = deadline(timeout);
  match driver.push(op) {
    PushEntry::Ready(result) => result_parts(result),
    PushEntry::Pending(mut key) => loop {
      if cancellation.is_cancelled() {
        let _ = driver.cancel(key);
        return Err(cancelled_io_error());
      }
      let remaining = match remaining_timeout(end) {
        Ok(remaining) => remaining,
        Err(error) => {
          let _ = driver.cancel(key);
          return Err(error);
        }
      };
      if let Err(error) = driver.poll(Some(remaining)) {
        let _ = driver.cancel(key);
        return Err(error);
      }
      if cancellation.is_cancelled() {
        let _ = driver.cancel(key);
        return Err(cancelled_io_error());
      }
      match driver.pop(key) {
        PushEntry::Ready(result) => return result_parts(result),
        PushEntry::Pending(pending) => key = pending,
      }
    },
  }
}

fn cancelled_io_error() -> io::Error {
  io::Error::new(
    io::ErrorKind::Interrupted,
    "compio direct H1 operation cancelled by downstream",
  )
}

fn result_parts<O>(result: BufResult<usize, O>) -> io::Result<(usize, O)> {
  let (result, op) = result.into_parts();
  result.map(|count| (count, op))
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
      "compio direct H1 operation timed out",
    ));
  }
  Ok(deadline.duration_since(now))
}

impl ResponseHead {
  fn into_response(self, body: ProxyBody) -> anyhow::Result<Response<ProxyBody>> {
    let mut response = Response::builder()
      .version(self.version)
      .status(self.status)
      .body(body)
      .context("failed to build compio direct H1 response")?;
    *response.headers_mut() = self.headers;
    attach_interim_responses(&mut response, self.interim);
    Ok(response)
  }
}

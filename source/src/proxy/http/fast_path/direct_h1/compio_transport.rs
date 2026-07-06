//! Linux-only Compio driver transport for guarded direct-H1 requests.

use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use bytes::Bytes;
use compio::buf::IntoInner;
use compio::{BufResult, driver::OpCode};
use compio_driver::op::{Recv, RecvFlags, Send, SendFlags};
use compio_driver::{Proactor, PushEntry, SharedFd};
use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version};
use hyper::body::{Body, Frame};
use tokio::sync::{mpsc, oneshot};

use crate::metrics::Metrics;
use crate::metrics::fast_path::labels::FastPathMetricProtocol;
use crate::proxy::http::EffectiveTimeouts;
use crate::proxy::http::body::{self, BoxError, ProxyBody, ProxyBodyFrame};

use super::request::PreparedDirectH1Request;
use super::{
  DirectH1Pool, DirectH1Response, DirectH1SendMetricOptions, DirectH1TransportError, timing,
};

#[cfg(test)]
mod tests;

const RESPONSE_HEAD_BUFFER_LIMIT: usize = 64 * 1024;
const RESPONSE_IO_BUFFER_BYTES: usize = 16 * 1024;
const BODY_CHANNEL_CAPACITY: usize = 16;
const MAX_RESPONSE_HEADERS: usize = 128;

struct ResponseHead {
  version: Version,
  status: StatusCode,
  headers: Vec<(HeaderName, HeaderValue)>,
}

enum ResponseBodyMode {
  None,
  ContentLength(u64),
  Chunked,
  UntilClose,
}

struct ParsedResponse {
  head: ResponseHead,
  body_mode: ResponseBodyMode,
  initial_body: Vec<u8>,
}

pub(super) async fn send_prepared_request(
  pool: Arc<DirectH1Pool>,
  metrics: Arc<Metrics>,
  protocol: FastPathMetricProtocol,
  prepared: PreparedDirectH1Request,
  timeouts: EffectiveTimeouts,
  metric_options: DirectH1SendMetricOptions,
) -> anyhow::Result<DirectH1Response> {
  let request = prepared.into_request();
  let (body_sender, body) = body::channel_body(BODY_CHANNEL_CAPACITY);
  let (head_sender, head_receiver) = oneshot::channel();
  tokio::task::spawn_blocking(move || {
    run_compio_transaction(
      pool,
      metrics,
      protocol,
      request,
      timeouts,
      metric_options,
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
  metric_options: DirectH1SendMetricOptions,
  head_sender: oneshot::Sender<anyhow::Result<ResponseHead>>,
  body_sender: mpsc::Sender<ProxyBodyFrame>,
) {
  let result = run_compio_until_head(&pool, &metrics, protocol, request, timeouts, metric_options);
  let (mut driver, fd, parsed) = match result {
    Ok(parsed) => parsed,
    Err(error) => {
      let _ = head_sender.send(Err(error));
      return;
    }
  };

  if head_sender.send(Ok(parsed.head)).is_err() {
    return;
  }

  let body_result = stream_response_body(
    &mut driver,
    &fd,
    parsed.initial_body,
    parsed.body_mode,
    timeouts.upstream_read,
    &body_sender,
  );
  if let Err(error) = body_result {
    send_body_error(&body_sender, error);
  }
}

fn run_compio_until_head(
  pool: &DirectH1Pool,
  metrics: &Metrics,
  protocol: FastPathMetricProtocol,
  request: Request<ProxyBody>,
  timeouts: EffectiveTimeouts,
  metric_options: DirectH1SendMetricOptions,
) -> anyhow::Result<(Proactor, SharedFd<TcpStream>, ParsedResponse)> {
  let mut driver = Proactor::new()
    .context("failed to build Compio direct H1 proactor")
    .map_err(DirectH1TransportError::connect)?;
  let connect_started = timing::start(metric_options.timing_enabled);
  let fd = connect_upstream(&mut driver, pool, timeouts.upstream_connect)
    .map_err(DirectH1TransportError::connect);
  timing::record_metrics_plain_result(
    metrics,
    protocol,
    timing::STAGE_DIRECT_H1_CONNECT,
    fd.is_ok(),
    connect_started,
  );
  let fd = fd?;
  if metric_options.hot_path_metrics {
    metrics.record_http_upstream_h1_http_primary_connection_created();
  }

  let serialized = serialize_empty_h1_request(&request).map_err(DirectH1TransportError::send)?;
  let request_started = timing::start(metric_options.timing_enabled);
  let submit_started = timing::start(metric_options.timing_enabled);
  let write_result = send_all(&mut driver, &fd, &serialized, timeouts.upstream_send);
  timing::record_metrics_plain_result(
    metrics,
    protocol,
    timing::STAGE_DIRECT_H1_REQUEST_SUBMIT,
    write_result.is_ok(),
    submit_started,
  );
  write_result
    .map_err(anyhow::Error::new)
    .map_err(DirectH1TransportError::send)?;

  let response_head_started = timing::start(metric_options.timing_enabled);
  let parsed = read_response_head(
    &mut driver,
    &fd,
    request.method(),
    timeouts.upstream_first_byte,
  );
  let success = parsed.is_ok();
  timing::record_metrics_plain_result(
    metrics,
    protocol,
    timing::STAGE_DIRECT_H1_RESPONSE_HEAD,
    success,
    response_head_started,
  );
  timing::record_metrics_plain_result(
    metrics,
    protocol,
    timing::STAGE_DIRECT_H1_SEND_REQUEST,
    success,
    request_started,
  );
  let parsed = parsed.map_err(DirectH1TransportError::send)?;
  Ok((driver, fd, parsed))
}

fn connect_upstream(
  driver: &mut Proactor,
  pool: &DirectH1Pool,
  timeout: Duration,
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
    match TcpStream::connect_timeout(&addr, timeout) {
      Ok(stream) => {
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
  timeout: Duration,
) -> io::Result<Vec<u8>> {
  let buffer = vec![0; RESPONSE_IO_BUFFER_BYTES];
  let (count, op) = push_and_wait(
    driver,
    Recv::new(fd.clone(), buffer, RecvFlags::empty()),
    timeout,
  )?;
  let mut buffer = op.into_inner();
  buffer.truncate(count);
  Ok(buffer)
}

fn read_response_head(
  driver: &mut Proactor,
  fd: &SharedFd<TcpStream>,
  request_method: &Method,
  timeout: Duration,
) -> anyhow::Result<ParsedResponse> {
  let end = deadline(timeout);
  let mut buffer = Vec::with_capacity(RESPONSE_IO_BUFFER_BYTES);
  loop {
    if let Some(head_end) = header_end(&buffer) {
      return parse_response(buffer, head_end, request_method);
    }
    if buffer.len() >= RESPONSE_HEAD_BUFFER_LIMIT {
      bail!("compio direct H1 response head exceeded {RESPONSE_HEAD_BUFFER_LIMIT} bytes");
    }
    let chunk = recv_once(driver, fd, remaining_timeout(end)?)
      .context("failed to read compio direct H1 response head")?;
    if chunk.is_empty() {
      bail!("compio direct H1 upstream closed before response head");
    }
    buffer.extend_from_slice(&chunk);
  }
}

fn parse_response(
  buffer: Vec<u8>,
  head_end: usize,
  request_method: &Method,
) -> anyhow::Result<ParsedResponse> {
  let mut parsed_headers = [httparse::EMPTY_HEADER; MAX_RESPONSE_HEADERS];
  let mut response = httparse::Response::new(&mut parsed_headers);
  let status = match response.parse(&buffer[..head_end])? {
    httparse::Status::Complete(_) => response.code.context("upstream response omitted status")?,
    httparse::Status::Partial => bail!("partial response head after delimiter"),
  };
  let version = match response.version {
    Some(0) => Version::HTTP_10,
    Some(1) => Version::HTTP_11,
    _ => bail!("unsupported upstream HTTP response version"),
  };
  let headers = response
    .headers
    .iter()
    .map(|header| {
      let name = HeaderName::from_bytes(header.name.as_bytes())
        .context("upstream response header name is invalid")?;
      let value = HeaderValue::from_bytes(header.value)
        .context("upstream response header value is invalid")?;
      Ok((name, value))
    })
    .collect::<anyhow::Result<Vec<_>>>()?;
  let status = StatusCode::from_u16(status).context("upstream response status is invalid")?;
  let body_mode = response_body_mode(request_method, status, &headers)?;
  Ok(ParsedResponse {
    head: ResponseHead {
      version,
      status,
      headers,
    },
    body_mode,
    initial_body: buffer[head_end..].to_vec(),
  })
}

fn response_body_mode(
  request_method: &Method,
  status: StatusCode,
  headers: &[(HeaderName, HeaderValue)],
) -> anyhow::Result<ResponseBodyMode> {
  if request_method == Method::HEAD
    || status.is_informational()
    || status == StatusCode::NO_CONTENT
    || status == StatusCode::NOT_MODIFIED
  {
    return Ok(ResponseBodyMode::None);
  }
  let chunked = transfer_encoding_is_chunked(headers);
  let length = content_length(headers)?;
  if chunked {
    if length.is_some() {
      bail!("ambiguous upstream response framing: transfer-encoding chunked with content-length");
    }
    return Ok(ResponseBodyMode::Chunked);
  }
  if let Some(length) = length {
    return Ok(ResponseBodyMode::ContentLength(length));
  }
  Ok(ResponseBodyMode::UntilClose)
}

fn transfer_encoding_is_chunked(headers: &[(HeaderName, HeaderValue)]) -> bool {
  headers
    .iter()
    .filter(|(name, _)| name == TRANSFER_ENCODING)
    .any(|(_, value)| {
      value
        .as_bytes()
        .split(|byte| *byte == b',')
        .filter_map(|part| std::str::from_utf8(part).ok())
        .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
    })
}

fn content_length(headers: &[(HeaderName, HeaderValue)]) -> anyhow::Result<Option<u64>> {
  let mut observed = None;
  for (_, value) in headers.iter().filter(|(name, _)| name == CONTENT_LENGTH) {
    let parsed = std::str::from_utf8(value.as_bytes())
      .context("content-length is not utf-8")?
      .trim()
      .parse::<u64>()
      .context("content-length is not an integer")?;
    if observed.is_some_and(|existing| existing != parsed) {
      bail!("conflicting content-length headers");
    }
    observed = Some(parsed);
  }
  Ok(observed)
}

fn stream_response_body(
  driver: &mut Proactor,
  fd: &SharedFd<TcpStream>,
  initial_body: Vec<u8>,
  mode: ResponseBodyMode,
  timeout: Duration,
  sender: &mpsc::Sender<ProxyBodyFrame>,
) -> anyhow::Result<()> {
  match mode {
    ResponseBodyMode::None => Ok(()),
    ResponseBodyMode::ContentLength(length) => {
      stream_content_length(driver, fd, initial_body, length, timeout, sender)
    }
    ResponseBodyMode::Chunked => stream_chunked(driver, fd, initial_body, timeout, sender),
    ResponseBodyMode::UntilClose => stream_until_close(driver, fd, initial_body, timeout, sender),
  }
}

fn stream_content_length(
  driver: &mut Proactor,
  fd: &SharedFd<TcpStream>,
  mut pending: Vec<u8>,
  length: u64,
  timeout: Duration,
  sender: &mpsc::Sender<ProxyBodyFrame>,
) -> anyhow::Result<()> {
  let mut remaining = usize::try_from(length).context("content-length does not fit usize")?;
  while remaining > 0 {
    if pending.is_empty() {
      pending = recv_once(driver, fd, timeout).context("failed to read response body")?;
      if pending.is_empty() {
        bail!("upstream closed before content-length response body completed");
      }
    }
    let take = remaining.min(pending.len());
    send_body_data(sender, pending[..take].to_vec())?;
    pending.drain(..take);
    remaining -= take;
  }
  Ok(())
}

fn stream_until_close(
  driver: &mut Proactor,
  fd: &SharedFd<TcpStream>,
  pending: Vec<u8>,
  timeout: Duration,
  sender: &mpsc::Sender<ProxyBodyFrame>,
) -> anyhow::Result<()> {
  send_body_data(sender, pending)?;
  loop {
    let chunk = recv_once(driver, fd, timeout).context("failed to read response body")?;
    if chunk.is_empty() {
      return Ok(());
    }
    send_body_data(sender, chunk)?;
  }
}

fn stream_chunked(
  driver: &mut Proactor,
  fd: &SharedFd<TcpStream>,
  mut pending: Vec<u8>,
  timeout: Duration,
  sender: &mpsc::Sender<ProxyBodyFrame>,
) -> anyhow::Result<()> {
  loop {
    let line = read_chunk_line(driver, fd, &mut pending, timeout)?;
    let size = parse_chunk_size(&line)?;
    if size == 0 {
      read_chunk_trailers(driver, fd, &mut pending, timeout, sender)?;
      return Ok(());
    }
    let mut remaining = size;
    while remaining > 0 {
      if pending.is_empty() {
        pending = recv_once(driver, fd, timeout).context("failed to read chunk body")?;
        if pending.is_empty() {
          bail!("upstream closed before chunk completed");
        }
      }
      let take = remaining.min(pending.len());
      send_body_data(sender, pending[..take].to_vec())?;
      pending.drain(..take);
      remaining -= take;
    }
    read_exact_discard(driver, fd, &mut pending, 2, timeout)?;
  }
}

fn read_chunk_trailers(
  driver: &mut Proactor,
  fd: &SharedFd<TcpStream>,
  pending: &mut Vec<u8>,
  timeout: Duration,
  sender: &mpsc::Sender<ProxyBodyFrame>,
) -> anyhow::Result<()> {
  loop {
    if let Some(end) = trailer_end(pending) {
      let trailers = parse_trailers(&pending[..end])?;
      pending.drain(..end);
      send_body_trailers(sender, trailers)?;
      return Ok(());
    }
    let chunk = recv_once(driver, fd, timeout).context("failed to read chunk trailers")?;
    if chunk.is_empty() {
      bail!("upstream closed before chunk trailers completed");
    }
    pending.extend_from_slice(&chunk);
  }
}

fn read_chunk_line(
  driver: &mut Proactor,
  fd: &SharedFd<TcpStream>,
  pending: &mut Vec<u8>,
  timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
  loop {
    if let Some(line_end) = find_crlf(pending) {
      let line = pending[..line_end].to_vec();
      pending.drain(..line_end + 2);
      return Ok(line);
    }
    let chunk = recv_once(driver, fd, timeout).context("failed to read chunk line")?;
    if chunk.is_empty() {
      bail!("upstream closed before chunk line completed");
    }
    pending.extend_from_slice(&chunk);
  }
}

fn read_exact_discard(
  driver: &mut Proactor,
  fd: &SharedFd<TcpStream>,
  pending: &mut Vec<u8>,
  len: usize,
  timeout: Duration,
) -> anyhow::Result<()> {
  while pending.len() < len {
    let chunk = recv_once(driver, fd, timeout).context("failed to read chunk delimiter")?;
    if chunk.is_empty() {
      bail!("upstream closed before chunk delimiter completed");
    }
    pending.extend_from_slice(&chunk);
  }
  if &pending[..len] != b"\r\n" {
    bail!("invalid chunk delimiter");
  }
  pending.drain(..len);
  Ok(())
}

fn parse_chunk_size(line: &[u8]) -> anyhow::Result<usize> {
  let size = line
    .split(|byte| *byte == b';')
    .next()
    .unwrap_or(line)
    .trim_ascii();
  let size = std::str::from_utf8(size).context("chunk size is not utf-8")?;
  usize::from_str_radix(size, 16).context("chunk size is invalid")
}

fn send_body_data(sender: &mpsc::Sender<ProxyBodyFrame>, bytes: Vec<u8>) -> anyhow::Result<()> {
  if bytes.is_empty() {
    return Ok(());
  }
  sender
    .blocking_send(Ok(Frame::data(Bytes::from(bytes))))
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

fn header_end(buffer: &[u8]) -> Option<usize> {
  buffer
    .windows(4)
    .position(|window| window == b"\r\n\r\n")
    .map(|index| index + 4)
}

fn find_crlf(buffer: &[u8]) -> Option<usize> {
  buffer.windows(2).position(|window| window == b"\r\n")
}

fn trailer_end(buffer: &[u8]) -> Option<usize> {
  if buffer.starts_with(b"\r\n") {
    Some(2)
  } else {
    header_end(buffer)
  }
}

fn parse_trailers(bytes: &[u8]) -> anyhow::Result<HeaderMap> {
  if bytes == b"\r\n" {
    return Ok(HeaderMap::new());
  }
  let mut trailers = HeaderMap::new();
  let header_bytes = bytes
    .strip_suffix(b"\r\n")
    .context("chunk trailers missing final CRLF")?;
  for line in header_bytes.split(|byte| *byte == b'\n') {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.is_empty() {
      continue;
    }
    let Some(colon) = line.iter().position(|byte| *byte == b':') else {
      bail!("chunk trailer omitted ':' separator");
    };
    let name = HeaderName::from_bytes(&line[..colon]).context("chunk trailer name is invalid")?;
    let value = trim_header_value(&line[colon + 1..]);
    let value = HeaderValue::from_bytes(value).context("chunk trailer value is invalid")?;
    trailers.append(name, value);
  }
  Ok(trailers)
}

fn trim_header_value(bytes: &[u8]) -> &[u8] {
  let start = bytes
    .iter()
    .position(|byte| *byte != b' ' && *byte != b'\t')
    .unwrap_or(bytes.len());
  let end = bytes
    .iter()
    .rposition(|byte| *byte != b' ' && *byte != b'\t')
    .map(|index| index + 1)
    .unwrap_or(start);
  &bytes[start..end]
}

fn push_and_wait<O>(driver: &mut Proactor, op: O, timeout: Duration) -> io::Result<(usize, O)>
where
  O: OpCode + 'static,
{
  let end = deadline(timeout);
  match driver.push(op) {
    PushEntry::Ready(result) => result_parts(result),
    PushEntry::Pending(mut key) => loop {
      driver.poll(Some(remaining_timeout(end)?))?;
      match driver.pop(key) {
        PushEntry::Ready(result) => return result_parts(result),
        PushEntry::Pending(pending) => key = pending,
      }
    },
  }
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
    for (name, value) in self.headers {
      response.headers_mut().append(name, value);
    }
    Ok(response)
  }
}

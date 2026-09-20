//! Live, record-boundary SSE compression probe.
//!
//! The upstream deliberately sends the first event in several transfer chunks,
//! then waits before it sends the second event and clean EOF.  Each downstream
//! client therefore proves that the proxy exposes a complete decoded event
//! before upstream completion rather than merely that a completed response can
//! be decoded.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use bytes::{Buf, Bytes};
use h3_quinn::quinn::crypto::rustls::QuicClientConfig;
use h3_quinn::quinn::{ClientConfig as QuinnClientConfig, Endpoint};
use http::{Request, StatusCode, Version};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::event_stream::{EventStreamCoding, EventStreamDecoder};
use crate::{client_bind_addr, downstream_client_config, resolve_remote_addr, DownstreamProtocol};

const FIRST_EVENT: &[u8] = b"data: first\r\n\r\n";
const EXPECTED_EVENTS: &[u8] = b"data: first\r\n\r\ndata: second\r\n\r\n";
const MAX_ENCODED_BYTES: usize = 64 * 1024;
const MAX_DECODED_BYTES: usize = 4 * 1024;
const FIRST_EVENT_DEADLINE: Duration = Duration::from_secs(1);
const STREAM_DEADLINE: Duration = Duration::from_secs(5);

struct ClientArgs {
  protocol: DownstreamProtocol,
  host: String,
  port: u16,
  server_name: String,
  authority: String,
  path: String,
  ca_cert: String,
  coding: EventStreamCoding,
}

pub(crate) async fn client(mut values: impl Iterator<Item = String>) -> anyhow::Result<()> {
  let mut protocol = None;
  let mut host = None;
  let mut port = None;
  let mut server_name = None;
  let mut authority = None;
  let mut path = None;
  let mut ca_cert = None;
  let mut coding = None;
  while let Some(flag) = values.next() {
    let value = values
      .next()
      .ok_or_else(|| anyhow!("missing value for {flag}"))?;
    match flag.as_str() {
      "--protocol" => protocol = Some(DownstreamProtocol::parse(&value)?),
      "--host" => host = Some(value),
      "--port" => port = Some(value.parse().context("invalid --port")?),
      "--server-name" => server_name = Some(value),
      "--authority" => authority = Some(value),
      "--path" => path = Some(value),
      "--ca-cert" => ca_cert = Some(value),
      "--coding" => {
        coding = Some(match value.as_str() {
          "br" => EventStreamCoding::Br,
          "zstd" => EventStreamCoding::Zstd,
          "gzip" => EventStreamCoding::Gzip,
          "deflate" => EventStreamCoding::Deflate,
          _ => bail!("--coding must be br, zstd, gzip, or deflate"),
        });
      }
      _ => bail!("unknown SSE client option: {flag}"),
    }
  }
  let args = ClientArgs {
    protocol: protocol.ok_or_else(|| anyhow!("--protocol is required"))?,
    host: host.ok_or_else(|| anyhow!("--host is required"))?,
    port: port.ok_or_else(|| anyhow!("--port is required"))?,
    server_name: server_name.ok_or_else(|| anyhow!("--server-name is required"))?,
    authority: authority.ok_or_else(|| anyhow!("--authority is required"))?,
    path: path.ok_or_else(|| anyhow!("--path is required"))?,
    ca_cert: ca_cert.ok_or_else(|| anyhow!("--ca-cert is required"))?,
    coding: coding.ok_or_else(|| anyhow!("--coding is required"))?,
  };
  match args.protocol {
    DownstreamProtocol::H1 => client_h1(&args).await,
    DownstreamProtocol::H2 => client_h2(&args).await,
    DownstreamProtocol::H3 => client_h3(&args).await,
  }?;
  println!("sse-stream-ok");
  Ok(())
}

struct Observer {
  decoder: EventStreamDecoder,
  decoded: Vec<u8>,
  encoded_bytes: usize,
  first_seen: bool,
  first_deadline: tokio::time::Instant,
  stream_deadline: tokio::time::Instant,
}

impl Observer {
  fn new(coding: EventStreamCoding) -> Self {
    Self {
      decoder: EventStreamDecoder::new(coding),
      decoded: Vec::new(),
      encoded_bytes: 0,
      first_seen: false,
      first_deadline: tokio::time::Instant::now() + FIRST_EVENT_DEADLINE,
      stream_deadline: tokio::time::Instant::now() + STREAM_DEADLINE,
    }
  }

  fn observe(&mut self, encoded: &[u8]) -> anyhow::Result<()> {
    self.encoded_bytes = self
      .encoded_bytes
      .checked_add(encoded.len())
      .ok_or_else(|| anyhow!("SSE encoded byte count overflow"))?;
    if self.encoded_bytes > MAX_ENCODED_BYTES {
      bail!("SSE response exceeded {MAX_ENCODED_BYTES} encoded bytes");
    }
    self.decoded.extend(self.decoder.push(encoded)?);
    if self.decoded.len() > MAX_DECODED_BYTES {
      bail!("SSE response exceeded {MAX_DECODED_BYTES} decoded bytes");
    }
    if !EXPECTED_EVENTS.starts_with(&self.decoded) {
      bail!("SSE decoded bytes did not preserve upstream event order");
    }
    if self.decoded.len() >= FIRST_EVENT.len() && !self.first_seen {
      if tokio::time::Instant::now() > self.first_deadline {
        bail!("SSE first complete event was not observable before upstream EOF delay");
      }
      self.first_seen = true;
    }
    Ok(())
  }

  fn finish(mut self) -> anyhow::Result<()> {
    self.decoded.extend(self.decoder.finish()?);
    if self.decoded.as_slice() != EXPECTED_EVENTS {
      bail!("SSE decoded bytes did not exactly match both upstream events");
    }
    if !self.first_seen {
      bail!("SSE first complete event was never observable");
    }
    Ok(())
  }

  fn next_timeout(&self) -> Duration {
    let deadline = if self.first_seen {
      self.stream_deadline
    } else {
      self.first_deadline
    };
    deadline.saturating_duration_since(tokio::time::Instant::now())
  }
}

fn coding_label(coding: EventStreamCoding) -> &'static str {
  match coding {
    EventStreamCoding::Identity => "identity",
    EventStreamCoding::Br => "br",
    EventStreamCoding::Zstd => "zstd",
    EventStreamCoding::Gzip => "gzip",
    EventStreamCoding::Deflate => "deflate",
  }
}

fn assert_headers(headers: &http::HeaderMap, coding: EventStreamCoding) -> anyhow::Result<()> {
  if headers
    .get("content-encoding")
    .and_then(|value| value.to_str().ok())
    != Some(coding_label(coding))
  {
    bail!("SSE response Content-Encoding did not match requested coding");
  }
  if !headers
    .get("content-type")
    .and_then(|value| value.to_str().ok())
    .is_some_and(|value| value.eq_ignore_ascii_case("text/event-stream"))
  {
    bail!("SSE response Content-Type was not text/event-stream");
  }
  Ok(())
}

async fn client_h1(args: &ClientArgs) -> anyhow::Result<()> {
  let config = downstream_client_config(Path::new(&args.ca_cert), b"http/1.1", None)?;
  let server_name =
    ServerName::try_from(args.server_name.clone()).map_err(|_| anyhow!("invalid --server-name"))?;
  let tcp = within(TcpStream::connect((args.host.as_str(), args.port)))
    .await
    .context("connect SSE H1 downstream")?;
  let mut stream = within(TlsConnector::from(Arc::new(config)).connect(server_name, tcp))
    .await
    .context("TLS SSE H1 downstream")?;
  let request = format!(
    "GET {} HTTP/1.1\r\nHost: {}\r\nAccept-Encoding: {}\r\nConnection: close\r\n\r\n",
    args.path,
    args.authority,
    coding_label(args.coding)
  );
  within(stream.write_all(request.as_bytes()))
    .await
    .context("write SSE H1 request")?;
  within(stream.flush())
    .await
    .context("flush SSE H1 request")?;
  let head = within(read_until(&mut stream, b"\r\n\r\n"))
    .await
    .context("read SSE H1 response headers")?;
  let head_text = std::str::from_utf8(&head).context("SSE H1 response headers were not UTF-8")?;
  if !head_text.starts_with("HTTP/1.1 200 ") {
    bail!("SSE H1 response was not 200");
  }
  let headers = parse_headers(head_text)?;
  assert_headers(&headers, args.coding)?;
  if !headers
    .get("transfer-encoding")
    .and_then(|value| value.to_str().ok())
    .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
  {
    bail!("SSE H1 response did not use chunked framing");
  }
  let mut observer = Observer::new(args.coding);
  loop {
    let line = timed_read_until(&mut stream, b"\r\n", observer.next_timeout()).await?;
    let size_text = std::str::from_utf8(&line[..line.len() - 2])
      .context("invalid SSE H1 chunk size")?
      .split(';')
      .next()
      .unwrap_or_default()
      .trim();
    let size = usize::from_str_radix(size_text, 16).context("invalid SSE H1 chunk size")?;
    if size == 0 {
      let tail = timed_read_until(&mut stream, b"\r\n", STREAM_DEADLINE).await?;
      if tail != b"\r\n" {
        bail!("SSE H1 terminal chunk had unexpected trailers");
      }
      break;
    }
    if size > MAX_ENCODED_BYTES {
      bail!("SSE H1 chunk exceeded encoded-byte bound");
    }
    let mut chunk = vec![0; size + 2];
    timed_read_exact(&mut stream, &mut chunk, observer.next_timeout()).await?;
    if &chunk[size..] != b"\r\n" {
      bail!("SSE H1 chunk was missing its terminator");
    }
    observer.observe(&chunk[..size])?;
  }
  observer.finish()
}

async fn client_h2(args: &ClientArgs) -> anyhow::Result<()> {
  let config = downstream_client_config(Path::new(&args.ca_cert), b"h2", None)?;
  let server_name =
    ServerName::try_from(args.server_name.clone()).map_err(|_| anyhow!("invalid --server-name"))?;
  let tcp = within(TcpStream::connect((args.host.as_str(), args.port)))
    .await
    .context("connect SSE H2 downstream")?;
  let tls = within(TlsConnector::from(Arc::new(config)).connect(server_name, tcp))
    .await
    .context("TLS SSE H2 downstream")?;
  let (mut sender, connection) = within(h2::client::handshake(tls))
    .await
    .context("establish SSE H2 downstream")?;
  tokio::spawn(async move {
    let _ = connection.await;
  });
  let request = request(args, Version::HTTP_2)?;
  let (response, _request_stream) = sender
    .send_request(request, true)
    .context("send SSE H2 request")?;
  let response = within(response).await.context("receive SSE H2 response")?;
  if response.status() != StatusCode::OK {
    bail!("SSE H2 response was not 200");
  }
  assert_headers(response.headers(), args.coding)?;
  let mut body = response.into_body();
  let mut observer = Observer::new(args.coding);
  while let Some(chunk) = tokio::time::timeout(observer.next_timeout(), body.data())
    .await
    .context("SSE first H2 event was not observable before upstream EOF delay")?
  {
    let chunk = chunk.context("read SSE H2 response body")?;
    let len = chunk.len();
    observer.observe(&chunk)?;
    body
      .flow_control()
      .release_capacity(len)
      .context("release SSE H2 response capacity")?;
  }
  if within(body.trailers())
    .await
    .context("read SSE H2 response trailers")?
    .is_some()
  {
    bail!("SSE H2 response unexpectedly included trailers");
  }
  observer.finish()
}

async fn client_h3(args: &ClientArgs) -> anyhow::Result<()> {
  let config = downstream_client_config(Path::new(&args.ca_cert), b"h3", None)?;
  let quic_config = QuinnClientConfig::new(Arc::new(
    QuicClientConfig::try_from(config).context("build SSE H3 TLS client")?,
  ));
  let remote = resolve_remote_addr(&args.host, args.port).await?;
  let endpoint = Endpoint::client(client_bind_addr(remote)).context("create SSE H3 endpoint")?;
  let connection = within(async {
    endpoint
      .connect_with(quic_config, remote, &args.server_name)
      .context("start SSE H3 connection")?
      .await
      .context("connect SSE H3 downstream")
  })
  .await?;
  let close = connection.clone();
  let h3_connection = h3_quinn::Connection::new(connection);
  let (mut driver, mut sender) = within(h3::client::builder().build::<_, _, Bytes>(h3_connection))
    .await
    .context("establish SSE H3 downstream")?;
  let driver_task = tokio::spawn(async move {
    let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
  });
  let mut stream = within(sender.send_request(request(args, Version::HTTP_3)?))
    .await
    .context("send SSE H3 request")?;
  within(stream.finish())
    .await
    .context("finish SSE H3 request")?;
  let response = within(stream.recv_response())
    .await
    .context("receive SSE H3 response")?;
  if response.status() != StatusCode::OK {
    bail!("SSE H3 response was not 200");
  }
  assert_headers(response.headers(), args.coding)?;
  let mut observer = Observer::new(args.coding);
  while let Some(mut chunk) = tokio::time::timeout(observer.next_timeout(), stream.recv_data())
    .await
    .context("SSE first H3 event was not observable before upstream EOF delay")?
    .context("read SSE H3 response body")?
  {
    let len = chunk.remaining();
    observer.observe(&chunk.copy_to_bytes(len))?;
  }
  if within(futures_util::future::poll_fn(|cx| {
    stream.poll_recv_trailers(cx)
  }))
  .await
  .context("read SSE H3 response trailers")?
  .is_some()
  {
    bail!("SSE H3 response unexpectedly included trailers");
  }
  close.close(0u32.into(), b"SSE probe complete");
  let _ = tokio::time::timeout(STREAM_DEADLINE, driver_task).await;
  observer.finish()
}

fn request(args: &ClientArgs, version: Version) -> anyhow::Result<Request<()>> {
  Request::builder()
    .method("GET")
    .version(version)
    .uri(
      http::Uri::builder()
        .scheme("https")
        .authority(args.authority.as_str())
        .path_and_query(args.path.as_str())
        .build()
        .context("build SSE request URI")?,
    )
    .header("host", &args.authority)
    .header("accept-encoding", coding_label(args.coding))
    .body(())
    .context("build SSE request")
}

fn parse_headers(head: &str) -> anyhow::Result<http::HeaderMap> {
  let mut headers = http::HeaderMap::new();
  for line in head.lines().skip(1).filter(|line| !line.is_empty()) {
    let (name, value) = line
      .split_once(':')
      .ok_or_else(|| anyhow!("malformed SSE H1 response header"))?;
    headers.append(
      http::HeaderName::from_bytes(name.trim().as_bytes()).context("invalid SSE header name")?,
      http::HeaderValue::from_str(value.trim()).context("invalid SSE header value")?,
    );
  }
  Ok(headers)
}

async fn within<T, E>(future: impl Future<Output = Result<T, E>>) -> anyhow::Result<T>
where
  E: Into<anyhow::Error>,
{
  tokio::time::timeout(STREAM_DEADLINE, future)
    .await
    .context("SSE network phase exceeded stream deadline")?
    .map_err(Into::into)
}

async fn read_until<S: AsyncRead + Unpin>(
  stream: &mut S,
  delimiter: &[u8],
) -> anyhow::Result<Vec<u8>> {
  let mut bytes = Vec::new();
  while !bytes.ends_with(delimiter) {
    if bytes.len() >= 64 * 1024 {
      bail!("SSE HTTP/1 framing exceeded bound");
    }
    let mut byte = [0_u8; 1];
    stream.read_exact(&mut byte).await?;
    bytes.push(byte[0]);
  }
  Ok(bytes)
}

async fn timed_read_until<S: AsyncRead + Unpin>(
  stream: &mut S,
  delimiter: &[u8],
  timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
  tokio::time::timeout(
    timeout.max(Duration::from_millis(1)),
    read_until(stream, delimiter),
  )
  .await
  .context("SSE stream did not expose its first event before upstream EOF delay")?
}

async fn timed_read_exact<S: AsyncRead + Unpin>(
  stream: &mut S,
  bytes: &mut [u8],
  timeout: Duration,
) -> anyhow::Result<()> {
  tokio::time::timeout(
    timeout.max(Duration::from_millis(1)),
    stream.read_exact(bytes),
  )
  .await
  .context("SSE stream did not expose its first event before upstream EOF delay")?
  .map(|_| ())
  .context("read SSE HTTP/1 chunk")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn observer_accepts_the_second_event_after_the_first_record() {
    let mut observer = Observer::new(EventStreamCoding::Identity);
    observer.observe(FIRST_EVENT).unwrap();
    observer.observe(b"data: second\r\n\r\n").unwrap();
    observer.finish().unwrap();
  }

  #[test]
  fn h1_header_parser_ignores_the_terminal_empty_line() {
    let headers = parse_headers(
      "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Encoding: gzip\r\n\r\n",
    )
    .unwrap();
    assert_eq!(headers["content-type"], "text/event-stream");
    assert_eq!(headers["content-encoding"], "gzip");
  }
}

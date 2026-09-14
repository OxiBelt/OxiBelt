//! RFC 10036 Incremental request/response qualification probe.
//!
//! Each response marker is both a proof of the preceding upload and the
//! permission to send the next one.  This makes the test a causal duplex
//! exchange rather than a timing-sensitive upload/download race.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use bytes::{Buf, Bytes};
use h3_quinn::quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use h3_quinn::quinn::{
  ClientConfig as QuinnClientConfig, Endpoint, ServerConfig as QuinnServerConfig,
};
use http::{Request, Response, StatusCode, Version};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const DEADLINE: Duration = Duration::from_secs(10);
const FIRST: &[u8] = b"one";
const SECOND: &[u8] = b"two";
const LAST: &[u8] = b"fin";
const COMPLETION_CHANNEL_CAPACITY: usize = 16;

#[derive(Clone, Copy)]
enum Protocol {
  H1,
  H2,
  H3,
}

impl Protocol {
  fn parse(value: &str) -> anyhow::Result<Self> {
    match value {
      "h1" => Ok(Self::H1),
      "h2" => Ok(Self::H2),
      "h3" => Ok(Self::H3),
      _ => bail!("unsupported Incremental protocol: {value}"),
    }
  }
}

struct UpstreamArgs {
  protocol: Protocol,
  listen: SocketAddr,
  cert: Option<String>,
  key: Option<String>,
  completion_listen: SocketAddr,
}
struct ClientArgs {
  protocol: Protocol,
  host: String,
  port: u16,
  server_name: String,
  authority: String,
  path: String,
  ca_cert: String,
  completion_host: String,
  completion_port: u16,
  expected_status: StatusCode,
  response_mode: ResponseMode,
  expected_proxy_status: Option<String>,
  expected_cache_status: Option<String>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ResponseMode {
  Duplex,
  FixedLength200,
}

impl ResponseMode {
  fn parse(value: &str) -> anyhow::Result<Self> {
    match value {
      "duplex" => Ok(Self::Duplex),
      "fixed-length-200" => Ok(Self::FixedLength200),
      _ => bail!("unsupported Incremental response mode: {value}"),
    }
  }

  fn header_value(self, status: StatusCode) -> Option<&'static str> {
    if status == StatusCode::NO_CONTENT {
      Some("early-204")
    } else if self == Self::FixedLength200 {
      Some("fixed-length-200")
    } else {
      None
    }
  }
}

pub(crate) async fn serve(mut values: impl Iterator<Item = String>) -> anyhow::Result<()> {
  let mut protocol = None;
  let mut listen = None;
  let mut cert = None;
  let mut key = None;
  let mut completion_listen = None;
  while let Some(flag) = values.next() {
    let value = values
      .next()
      .ok_or_else(|| anyhow!("missing value for {flag}"))?;
    match flag.as_str() {
      "--protocol" => protocol = Some(Protocol::parse(&value)?),
      "--listen" => listen = Some(value.parse().context("invalid --listen")?),
      "--cert" => cert = Some(value),
      "--key" => key = Some(value),
      "--completion-listen" => {
        completion_listen = Some(value.parse().context("invalid --completion-listen")?)
      }
      _ => bail!("unknown Incremental upstream option: {flag}"),
    }
  }
  let args = UpstreamArgs {
    protocol: protocol.ok_or_else(|| anyhow!("--protocol is required"))?,
    listen: listen.ok_or_else(|| anyhow!("--listen is required"))?,
    cert,
    key,
    completion_listen: completion_listen
      .ok_or_else(|| anyhow!("--completion-listen is required"))?,
  };
  let completion_listener = TcpListener::bind(args.completion_listen)
    .await
    .context("bind Incremental completion listener")?;
  let (completion_tx, completion_rx) = mpsc::channel(COMPLETION_CHANNEL_CAPACITY);
  tokio::spawn(async move {
    if let Err(error) = serve_completion_listener(completion_listener, completion_rx).await {
      eprintln!("Incremental completion listener failed: {error:#}");
    }
  });
  match args.protocol {
    Protocol::H1 => serve_h1(args.listen, completion_tx).await,
    Protocol::H2 => serve_h2(args, completion_tx).await,
    Protocol::H3 => serve_h3(args, completion_tx).await,
  }
}

pub(crate) async fn client(mut values: impl Iterator<Item = String>) -> anyhow::Result<()> {
  let mut protocol = None;
  let mut host = None;
  let mut port = None;
  let mut server_name = None;
  let mut authority = None;
  let mut path = None;
  let mut ca_cert = None;
  let mut completion_host = None;
  let mut completion_port = None;
  let mut expected_status = StatusCode::OK;
  let mut response_mode = ResponseMode::Duplex;
  let mut expected_proxy_status = None;
  let mut expected_cache_status = None;
  while let Some(flag) = values.next() {
    let value = values
      .next()
      .ok_or_else(|| anyhow!("missing value for {flag}"))?;
    match flag.as_str() {
      "--protocol" => protocol = Some(Protocol::parse(&value)?),
      "--host" => host = Some(value),
      "--port" => port = Some(value.parse().context("invalid --port")?),
      "--server-name" => server_name = Some(value),
      "--authority" => authority = Some(value),
      "--path" => path = Some(value),
      "--ca-cert" => ca_cert = Some(value),
      "--completion-host" => completion_host = Some(value),
      "--completion-port" => {
        completion_port = Some(value.parse().context("invalid --completion-port")?)
      }
      "--expect-status" => {
        expected_status = StatusCode::from_u16(value.parse().context("invalid --expect-status")?)
          .context("unsupported --expect-status")?
      }
      "--response-mode" => response_mode = ResponseMode::parse(&value)?,
      "--expect-proxy-status" => expected_proxy_status = Some(value),
      "--expect-cache-status" => expected_cache_status = Some(value),
      _ => bail!("unknown Incremental client option: {flag}"),
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
    completion_host: completion_host.ok_or_else(|| anyhow!("--completion-host is required"))?,
    completion_port: completion_port.ok_or_else(|| anyhow!("--completion-port is required"))?,
    expected_status,
    response_mode,
    expected_proxy_status,
    expected_cache_status,
  };
  match args.protocol {
    Protocol::H1 => client_h1(&args).await,
    Protocol::H2 => client_h2(&args).await,
    Protocol::H3 => client_h3(&args).await,
  }?;
  println!("incremental-duplex-ok");
  Ok(())
}

fn response() -> anyhow::Result<Response<()>> {
  Response::builder()
    .status(StatusCode::OK)
    .header("incremental", "?1")
    .header("cache-status", "incremental; hit")
    .header("content-type", "text/plain")
    .body(())
    .context("build Incremental response")
}
fn request(args: &ClientArgs, version: Version) -> anyhow::Result<Request<()>> {
  let uri = http::Uri::builder()
    .scheme("https")
    .authority(args.authority.as_str())
    .path_and_query(args.path.as_str())
    .build()
    .context("build Incremental request URI")?;
  let mut builder = Request::builder()
    .method("POST")
    .version(version)
    .uri(uri)
    .header("host", &args.authority)
    .header("incremental", "?1");
  if let Some(mode) = args.response_mode.header_value(args.expected_status) {
    builder = builder.header("x-incremental-probe-mode", mode);
  }
  builder.body(()).context("build Incremental request")
}
fn assert_incremental(headers: &http::HeaderMap) -> anyhow::Result<()> {
  if headers.get("incremental").and_then(|v| v.to_str().ok()) != Some("?1") {
    bail!("response did not preserve Incremental: ?1")
  }
  Ok(())
}
fn assert_expected_header<'a>(
  name: &str,
  expected: Option<&str>,
  values: impl Iterator<Item = anyhow::Result<&'a str>>,
) -> anyhow::Result<()> {
  let Some(expected) = expected else {
    return Ok(());
  };
  let values = values.collect::<anyhow::Result<Vec<_>>>()?;
  if values != [expected] {
    bail!(
      "response {name} was {:?}, expected exactly {expected:?}",
      values
    )
  }
  Ok(())
}
fn assert_expected_status_headers(
  headers: &http::HeaderMap,
  args: &ClientArgs,
) -> anyhow::Result<()> {
  assert_expected_header(
    "Proxy-Status",
    args.expected_proxy_status.as_deref(),
    headers
      .get_all("proxy-status")
      .iter()
      .map(|value| value.to_str().context("Proxy-Status was not UTF-8")),
  )?;
  assert_expected_header(
    "Cache-Status",
    args.expected_cache_status.as_deref(),
    headers
      .get_all("cache-status")
      .iter()
      .map(|value| value.to_str().context("Cache-Status was not UTF-8")),
  )
}
fn h1_header_values<'a>(response: &'a str, name: &str) -> Vec<&'a str> {
  response
    .lines()
    .skip(1)
    .filter_map(|line| {
      let (field, value) = line.split_once(':')?;
      field.eq_ignore_ascii_case(name).then_some(value.trim())
    })
    .collect()
}
fn assert_expected_h1_status_headers(response: &str, args: &ClientArgs) -> anyhow::Result<()> {
  assert_expected_header(
    "Proxy-Status",
    args.expected_proxy_status.as_deref(),
    h1_header_values(response, "proxy-status")
      .into_iter()
      .map(Ok),
  )?;
  assert_expected_header(
    "Cache-Status",
    args.expected_cache_status.as_deref(),
    h1_header_values(response, "cache-status")
      .into_iter()
      .map(Ok),
  )
}
#[track_caller]
fn within<T>(
  action: impl std::future::Future<Output = anyhow::Result<T>>,
) -> impl std::future::Future<Output = anyhow::Result<T>> {
  let caller = std::panic::Location::caller();
  async move {
    tokio::time::timeout(DEADLINE, action)
      .await
      .with_context(|| {
        format!(
          "Incremental duplex barrier timed out at {}:{}",
          caller.file(),
          caller.line()
        )
      })?
  }
}

async fn serve_completion_listener(
  listener: TcpListener,
  mut completions: mpsc::Receiver<()>,
) -> anyhow::Result<()> {
  loop {
    let (mut stream, _) = listener
      .accept()
      .await
      .context("accept Incremental completion client")?;
    let mut request = [0; 4];
    within(async {
      stream
        .read_exact(&mut request)
        .await
        .context("read Incremental completion request")
    })
    .await?;
    if request != *b"wait" {
      bail!("invalid Incremental completion request")
    }
    within(async {
      completions
        .recv()
        .await
        .ok_or_else(|| anyhow!("Incremental completion channel closed"))
    })
    .await?;
    within(async {
      stream
        .write_all(b"ok")
        .await
        .context("write Incremental completion acknowledgment")?;
      stream
        .flush()
        .await
        .context("flush Incremental completion acknowledgment")
    })
    .await?;
  }
}

async fn wait_for_completion(args: &ClientArgs) -> anyhow::Result<()> {
  let mut stream = within(async {
    TcpStream::connect((args.completion_host.as_str(), args.completion_port))
      .await
      .context("connect Incremental completion listener")
  })
  .await?;
  within(async {
    stream
      .write_all(b"wait")
      .await
      .context("write Incremental completion request")?;
    stream
      .flush()
      .await
      .context("flush Incremental completion request")?;
    let mut acknowledgment = [0; 2];
    stream
      .read_exact(&mut acknowledgment)
      .await
      .context("read Incremental completion acknowledgment")?;
    if acknowledgment != *b"ok" {
      bail!("invalid Incremental completion acknowledgment")
    }
    Ok(())
  })
  .await
}

async fn notify_completion(completions: &mpsc::Sender<()>) -> anyhow::Result<()> {
  within(async {
    completions
      .send(())
      .await
      .map_err(|_| anyhow!("Incremental completion listener stopped"))
  })
  .await
}

async fn serve_h1(listen: SocketAddr, completions: mpsc::Sender<()>) -> anyhow::Result<()> {
  let listener = TcpListener::bind(listen)
    .await
    .context("bind Incremental H1 upstream")?;
  loop {
    let (stream, _) = listener
      .accept()
      .await
      .context("accept Incremental H1 upstream")?;
    let completions = completions.clone();
    tokio::spawn(async move {
      if let Err(error) = h1_server_exchange(stream, &completions).await {
        eprintln!("Incremental H1 upstream failed: {error:#}");
      }
    });
  }
}
async fn h1_server_exchange<S: AsyncRead + AsyncWrite + Unpin>(
  mut stream: S,
  completions: &mpsc::Sender<()>,
) -> anyhow::Result<()> {
  let head = read_until(&mut stream, b"\r\n\r\n").await?;
  let head_text = std::str::from_utf8(&head).context("Incremental H1 head was not UTF-8")?;
  if !head_text
    .lines()
    .any(|line| line.eq_ignore_ascii_case("incremental: ?1"))
  {
    bail!("Incremental H1 request header missing")
  }
  let early_no_content = head_text
    .lines()
    .any(|line| line.eq_ignore_ascii_case("x-incremental-probe-mode: early-204"));
  expect_h1_marker(&mut stream, FIRST).await?;
  if early_no_content {
    stream
      .write_all(b"HTTP/1.1 204 No Content\r\nIncremental: ?1\r\nConnection: keep-alive\r\n\r\n")
      .await
      .context("send early Incremental H1 204 response")?;
    stream
      .flush()
      .await
      .context("flush early Incremental H1 204 response")?;
    expect_h1_marker(&mut stream, SECOND).await?;
    expect_h1_marker(&mut stream, LAST).await?;
    expect_h1_end(&mut stream).await?;
    return notify_completion(completions).await;
  }
  stream.write_all(b"HTTP/1.1 200 OK\r\nIncremental: ?1\r\nCache-Status: incremental; hit\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n3\r\none\r\n").await.context("send first Incremental H1 response")?;
  stream
    .flush()
    .await
    .context("flush first Incremental H1 response")?;
  expect_h1_marker(&mut stream, SECOND).await?;
  stream
    .write_all(b"3\r\ntwo\r\n0\r\n\r\n")
    .await
    .context("send final Incremental H1 response")?;
  stream
    .flush()
    .await
    .context("flush final Incremental H1 response")?;
  expect_h1_marker(&mut stream, LAST).await?;
  expect_h1_end(&mut stream).await?;
  notify_completion(completions).await
}
async fn client_h1(args: &ClientArgs) -> anyhow::Result<()> {
  let config = crate::downstream_client_config(Path::new(&args.ca_cert), b"http/1.1", None)?;
  let server_name =
    ServerName::try_from(args.server_name.clone()).map_err(|_| anyhow!("invalid --server-name"))?;
  let tcp = within(async {
    TcpStream::connect((args.host.as_str(), args.port))
      .await
      .context("connect Incremental H1 downstream")
  })
  .await?;
  let mut stream = within(async {
    TlsConnector::from(Arc::new(config))
      .connect(server_name, tcp)
      .await
      .context("TLS Incremental H1 downstream")
  })
  .await?;
  let probe_mode = args
    .response_mode
    .header_value(args.expected_status)
    .map(|mode| format!("X-Incremental-Probe-Mode: {mode}\r\n"))
    .unwrap_or_default();
  let head = format!(
    "POST {} HTTP/1.1\r\nHost: {}\r\nIncremental: ?1\r\n{}Transfer-Encoding: chunked\r\n\r\n",
    args.path, args.authority, probe_mode
  );
  stream.write_all(head.as_bytes()).await?;
  write_h1_chunk(&mut stream, FIRST).await?;
  let response_head = read_until(&mut stream, b"\r\n\r\n").await?;
  let response_text =
    std::str::from_utf8(&response_head).context("Incremental H1 response head was not UTF-8")?;
  if !response_text.contains(&format!(" {} ", args.expected_status.as_u16()))
    || !response_text
      .lines()
      .any(|line| line.eq_ignore_ascii_case("incremental: ?1"))
  {
    bail!("Incremental H1 response headers invalid")
  }
  assert_expected_h1_status_headers(response_text, args)?;
  if args.expected_status == StatusCode::NO_CONTENT {
    write_h1_chunk(&mut stream, SECOND).await?;
    write_h1_chunk(&mut stream, LAST).await?;
    finish_h1_upload(&mut stream).await?;
    wait_for_completion(args).await?;
    return Ok(());
  }
  if args.response_mode == ResponseMode::FixedLength200 {
    let mut first = [0; 3];
    within(async {
      stream
        .read_exact(&mut first)
        .await
        .context("read first fixed-length Incremental H1 response fragment")
    })
    .await?;
    if first != *FIRST {
      bail!("unexpected first fixed-length Incremental H1 response fragment")
    }
    write_h1_chunk(&mut stream, SECOND).await?;
    let mut second = [0; 3];
    within(async {
      stream
        .read_exact(&mut second)
        .await
        .context("read second fixed-length Incremental H1 response fragment")
    })
    .await?;
    if second != *SECOND {
      bail!("unexpected second fixed-length Incremental H1 response fragment")
    }
    write_h1_chunk(&mut stream, LAST).await?;
    finish_h1_upload(&mut stream).await?;
    wait_for_completion(args).await?;
    return Ok(());
  }
  expect_h1_marker(&mut stream, FIRST).await?;
  write_h1_chunk(&mut stream, SECOND).await?;
  expect_h1_marker(&mut stream, SECOND).await?;
  expect_h1_end(&mut stream).await?;
  write_h1_chunk(&mut stream, LAST).await?;
  finish_h1_upload(&mut stream).await?;
  wait_for_completion(args).await?;
  Ok(())
}
async fn finish_h1_upload<S: AsyncWrite + Unpin>(stream: &mut S) -> anyhow::Result<()> {
  stream
    .write_all(b"0\r\n\r\n")
    .await
    .context("finish Incremental H1 upload")?;
  stream.flush().await.context("flush Incremental H1 upload")
}
async fn write_h1_chunk<S: AsyncWrite + Unpin>(stream: &mut S, data: &[u8]) -> anyhow::Result<()> {
  stream
    .write_all(format!("{:x}\r\n", data.len()).as_bytes())
    .await?;
  stream.write_all(data).await?;
  stream.write_all(b"\r\n").await?;
  stream
    .flush()
    .await
    .context("flush Incremental H1 request chunk")
}
async fn expect_h1_marker<S: AsyncRead + Unpin>(
  stream: &mut S,
  wanted: &[u8],
) -> anyhow::Result<()> {
  let mut marker = Vec::new();
  while marker.len() < wanted.len() {
    let line = read_until(stream, b"\r\n").await?;
    let size = usize::from_str_radix(
      std::str::from_utf8(&line[..line.len() - 2]).context("invalid chunk size")?,
      16,
    )
    .context("invalid chunk size")?;
    if size == 0 {
      bail!("Incremental H1 stream ended before its marker")
    }
    let mut data = vec![0; size + 2];
    within(async {
      stream
        .read_exact(&mut data)
        .await
        .context("read Incremental H1 chunk")
    })
    .await?;
    if &data[size..] != b"\r\n" {
      bail!("malformed Incremental H1 chunk")
    }
    marker.extend_from_slice(&data[..size]);
    if !wanted.starts_with(&marker) {
      bail!("unexpected Incremental H1 marker")
    }
  }
  Ok(())
}
async fn expect_h1_end<S: AsyncRead + Unpin>(stream: &mut S) -> anyhow::Result<()> {
  let line = read_until(stream, b"\r\n").await?;
  if line != b"0\r\n" {
    bail!("Incremental H1 stream did not end cleanly")
  }
  let tail = read_until(stream, b"\r\n").await?;
  if tail != b"\r\n" {
    bail!("Incremental H1 trailers were malformed")
  }
  Ok(())
}
async fn read_until<S: AsyncRead + Unpin>(
  stream: &mut S,
  needle: &[u8],
) -> anyhow::Result<Vec<u8>> {
  let mut out = Vec::new();
  loop {
    let mut byte = [0];
    within(async {
      stream
        .read_exact(&mut byte)
        .await
        .context("read Incremental H1 bytes")
    })
    .await?;
    out.push(byte[0]);
    if out.ends_with(needle) {
      return Ok(out);
    }
    if out.len() > 64 * 1024 {
      bail!("Incremental H1 frame exceeded limit")
    }
  }
}

async fn serve_h2(args: UpstreamArgs, completions: mpsc::Sender<()>) -> anyhow::Result<()> {
  let (cert, key) = args
    .cert
    .zip(args.key)
    .ok_or_else(|| anyhow!("H2 Incremental upstream requires --cert and --key"))?;
  let mut tls = crate::upstream_tls_server_config(&cert, &key, None, false)?;
  tls.alpn_protocols = vec![b"h2".to_vec()];
  let acceptor = TlsAcceptor::from(Arc::new(tls));
  let listener = TcpListener::bind(args.listen).await?;
  loop {
    let (tcp, _) = listener.accept().await?;
    let acceptor = acceptor.clone();
    let completions = completions.clone();
    tokio::spawn(async move {
      let result: anyhow::Result<()> = async {
        let tls = acceptor
          .accept(tcp)
          .await
          .context("accept Incremental H2 TLS")?;
        let mut connection = h2::server::handshake(tls)
          .await
          .context("handshake Incremental H2")?;
        while let Some(request) = connection.accept().await {
          let request = request.context("accept Incremental H2 request")?;
          let completions = completions.clone();
          // Keep polling the H2 connection while this stream waits for the
          // next causal upload fragment; RecvStream alone does not drive IO.
          tokio::spawn(async move {
            if let Err(error) = h2_server_exchange(request, &completions).await {
              eprintln!("Incremental H2 exchange failed: {error:#}");
            }
          });
        }
        Ok(())
      }
      .await;
      if let Err(error) = result {
        eprintln!("Incremental H2 upstream failed: {error:#}");
      }
    });
  }
}
async fn h2_server_exchange(
  (request, mut respond): (Request<h2::RecvStream>, h2::server::SendResponse<Bytes>),
  completions: &mpsc::Sender<()>,
) -> anyhow::Result<()> {
  if request
    .headers()
    .get("incremental")
    .and_then(|v| v.to_str().ok())
    != Some("?1")
  {
    bail!("Incremental H2 request header missing")
  }
  let (_, mut body) = request.into_parts();
  expect_h2_data(&mut body, FIRST).await?;
  let mut response = respond
    .send_response(response()?, false)
    .context("send Incremental H2 response")?;
  response
    .send_data(Bytes::from_static(FIRST), false)
    .context("send first Incremental H2 data")?;
  expect_h2_data(&mut body, SECOND).await?;
  response
    .send_data(Bytes::from_static(SECOND), true)
    .context("finish Incremental H2 response")?;
  expect_h2_data(&mut body, LAST).await?;
  expect_h2_end(&mut body, "server request").await?;
  notify_completion(completions).await
}
async fn expect_h2_data(body: &mut h2::RecvStream, wanted: &[u8]) -> anyhow::Result<()> {
  let mut marker = Vec::new();
  while marker.len() < wanted.len() {
    let data = within(async {
      body
        .data()
        .await
        .ok_or_else(|| anyhow!("unexpected Incremental H2 EOF"))?
        .context("read Incremental H2 data")
    })
    .await?;
    let length = data.len();
    marker.extend_from_slice(&data);
    body
      .flow_control()
      .release_capacity(length)
      .context("release Incremental H2 capacity")?;
    if !wanted.starts_with(&marker) {
      bail!("unexpected Incremental H2 marker")
    }
  }
  Ok(())
}
async fn expect_h2_end(body: &mut h2::RecvStream, direction: &str) -> anyhow::Result<()> {
  loop {
    let data = within(async {
      body
        .data()
        .await
        .transpose()
        .context("read Incremental H2 EOF frame")
    })
    .await?;
    let Some(data) = data else {
      return Ok(());
    };
    let length = data.len();
    body
      .flow_control()
      .release_capacity(length)
      .context("release Incremental H2 EOF frame capacity")?;
    if length != 0 {
      bail!("Incremental H2 {direction} carried data after its final marker")
    }
  }
}
async fn client_h2(args: &ClientArgs) -> anyhow::Result<()> {
  let config = crate::downstream_client_config(Path::new(&args.ca_cert), b"h2", None)?;
  let server_name =
    ServerName::try_from(args.server_name.clone()).map_err(|_| anyhow!("invalid --server-name"))?;
  let tcp = within(async {
    TcpStream::connect((args.host.as_str(), args.port))
      .await
      .context("connect Incremental H2 downstream")
  })
  .await?;
  let tls = within(async {
    TlsConnector::from(Arc::new(config))
      .connect(server_name, tcp)
      .await
      .context("TLS Incremental H2 downstream")
  })
  .await?;
  let (mut sender, connection) = h2::client::handshake(tls)
    .await
    .context("handshake Incremental H2 client")?;
  tokio::spawn(async move {
    let _ = connection.await;
  });
  let (response_future, mut upload) = sender
    .send_request(request(args, Version::HTTP_2)?, false)
    .context("send Incremental H2 headers")?;
  upload
    .send_data(Bytes::from_static(FIRST), false)
    .context("send first Incremental H2 marker")?;
  let response = within(async {
    response_future
      .await
      .context("receive Incremental H2 response")
  })
  .await?;
  assert_incremental(response.headers())?;
  assert_expected_status_headers(response.headers(), args)?;
  let (_, mut download) = response.into_parts();
  expect_h2_data(&mut download, FIRST).await?;
  upload
    .send_data(Bytes::from_static(SECOND), false)
    .context("send second Incremental H2 marker")?;
  expect_h2_data(&mut download, SECOND).await?;
  expect_h2_end(&mut download, "client response").await?;
  upload
    .send_data(Bytes::from_static(LAST), true)
    .context("finish Incremental H2 upload")?;
  wait_for_completion(args).await?;
  Ok(())
}

async fn serve_h3(args: UpstreamArgs, completions: mpsc::Sender<()>) -> anyhow::Result<()> {
  let (cert, key) = args
    .cert
    .zip(args.key)
    .ok_or_else(|| anyhow!("H3 Incremental upstream requires --cert and --key"))?;
  let mut tls = crate::upstream_tls_server_config(&cert, &key, None, true)?;
  tls.alpn_protocols = vec![b"h3".to_vec()];
  let crypto = QuicServerConfig::try_from(tls).context("build Incremental H3 TLS")?;
  let endpoint = Endpoint::server(
    QuinnServerConfig::with_crypto(Arc::new(crypto)),
    args.listen,
  )
  .context("bind Incremental H3")?;
  while let Some(connecting) = endpoint.accept().await {
    let completions = completions.clone();
    tokio::spawn(async move {
      let result: anyhow::Result<()> = async {
        let connection = connecting
          .await
          .context("accept Incremental H3 connection")?;
        let mut connection = h3::server::builder()
          .build(h3_quinn::Connection::new(connection))
          .await
          .context("build Incremental H3")?;
        while let Some(resolver) = connection
          .accept()
          .await
          .context("accept Incremental H3 request")?
        {
          let (request, stream) = resolver
            .resolve_request()
            .await
            .context("resolve Incremental H3 request")?;
          h3_server_exchange(request, stream, &completions).await?;
        }
        Ok(())
      }
      .await;
      if let Err(error) = result {
        eprintln!("Incremental H3 upstream failed: {error:#}");
      }
    });
  }
  Ok(())
}
async fn h3_server_exchange(
  request: Request<()>,
  mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
  completions: &mpsc::Sender<()>,
) -> anyhow::Result<()> {
  if request
    .headers()
    .get("incremental")
    .and_then(|v| v.to_str().ok())
    != Some("?1")
  {
    bail!("Incremental H3 request header missing")
  }
  let response_mode = request
    .headers()
    .get("x-incremental-probe-mode")
    .and_then(|value| value.to_str().ok());
  expect_h3_data(&mut stream, FIRST).await?;
  if response_mode == Some("early-204") {
    let response = Response::builder()
      .status(StatusCode::NO_CONTENT)
      .header("incremental", "?1")
      .body(())
      .context("build early Incremental H3 204 response")?;
    stream
      .send_response(response)
      .await
      .context("send early Incremental H3 204 response")?;
    stream
      .finish()
      .await
      .context("finish early Incremental H3 204 response")?;
    expect_h3_data(&mut stream, SECOND).await?;
    expect_h3_data(&mut stream, LAST).await?;
    expect_h3_server_end(&mut stream, "early request").await?;
    return notify_completion(completions).await;
  }
  if response_mode == Some("fixed-length-200") {
    let response = Response::builder()
      .status(StatusCode::OK)
      .header("incremental", "?1")
      .header("content-length", "6")
      .body(())
      .context("build fixed-length Incremental H3 response")?;
    stream
      .send_response(response)
      .await
      .context("send fixed-length Incremental H3 response")?;
    stream
      .send_data(Bytes::from_static(FIRST))
      .await
      .context("send first fixed-length Incremental H3 response fragment")?;
    expect_h3_data(&mut stream, SECOND).await?;
    stream
      .send_data(Bytes::from_static(SECOND))
      .await
      .context("send second fixed-length Incremental H3 response fragment")?;
    stream
      .finish()
      .await
      .context("finish fixed-length Incremental H3 response")?;
    expect_h3_data(&mut stream, LAST).await?;
    expect_h3_server_end(&mut stream, "fixed-length request").await?;
    return notify_completion(completions).await;
  }
  stream
    .send_response(response()?)
    .await
    .context("send Incremental H3 response")?;
  stream
    .send_data(Bytes::from_static(FIRST))
    .await
    .context("send first Incremental H3 data")?;
  expect_h3_data(&mut stream, SECOND).await?;
  stream
    .send_data(Bytes::from_static(SECOND))
    .await
    .context("send second Incremental H3 data")?;
  stream
    .finish()
    .await
    .context("finish Incremental H3 response")?;
  expect_h3_data(&mut stream, LAST).await?;
  expect_h3_server_end(&mut stream, "request").await?;
  notify_completion(completions).await
}
async fn expect_h3_data(
  stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
  wanted: &[u8],
) -> anyhow::Result<()> {
  let mut marker = Vec::new();
  while marker.len() < wanted.len() {
    let mut data = within(async {
      stream
        .recv_data()
        .await
        .context("read Incremental H3 data")?
        .ok_or_else(|| anyhow!("unexpected Incremental H3 EOF"))
    })
    .await?;
    let length = data.remaining();
    marker.extend_from_slice(&data.copy_to_bytes(length));
    if !wanted.starts_with(&marker) {
      bail!("unexpected Incremental H3 marker")
    }
  }
  Ok(())
}
async fn expect_h3_server_end(
  stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
  direction: &str,
) -> anyhow::Result<()> {
  loop {
    let data = within(async {
      stream
        .recv_data()
        .await
        .context("read Incremental H3 EOF frame")
    })
    .await?;
    let Some(data) = data else {
      return Ok(());
    };
    if data.remaining() != 0 {
      bail!("Incremental H3 {direction} carried data after its final marker")
    }
  }
}
async fn client_h3(args: &ClientArgs) -> anyhow::Result<()> {
  let tls = crate::downstream_client_config(Path::new(&args.ca_cert), b"h3", None)?;
  let crypto = QuicClientConfig::try_from(tls).context("build Incremental H3 TLS")?;
  let remote = lookup_host((args.host.as_str(), args.port))
    .await?
    .next()
    .ok_or_else(|| anyhow!("no Incremental H3 address"))?;
  let endpoint = Endpoint::client(
    if remote.is_ipv4() {
      "0.0.0.0:0"
    } else {
      "[::]:0"
    }
    .parse::<SocketAddr>()?,
  )
  .context("create Incremental H3 endpoint")?;
  let connection = within(async {
    endpoint
      .connect_with(
        QuinnClientConfig::new(Arc::new(crypto)),
        remote,
        &args.server_name,
      )
      .context("connect Incremental H3")?
      .await
      .context("complete Incremental H3 connection")
  })
  .await?;
  let close = connection.clone();
  let (mut driver, mut sender) = h3::client::builder()
    .build(h3_quinn::Connection::new(connection))
    .await
    .context("build Incremental H3 client")?;
  let driver_task = tokio::spawn(async move {
    let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
  });
  let mut stream = sender
    .send_request(request(args, Version::HTTP_3)?)
    .await
    .context("send Incremental H3 headers")?;
  stream
    .send_data(Bytes::from_static(FIRST))
    .await
    .context("send first Incremental H3 marker")?;
  let response = within(async {
    stream
      .recv_response()
      .await
      .context("receive Incremental H3 response")
  })
  .await?;
  assert_incremental(response.headers())?;
  assert_expected_status_headers(response.headers(), args)?;
  if response.status() != args.expected_status {
    bail!(
      "Incremental H3 response status was {}, expected {}",
      response.status(),
      args.expected_status
    )
  }
  if args.expected_status == StatusCode::NO_CONTENT {
    expect_h3_client_end(&mut stream, "early response").await?;
    stream
      .send_data(Bytes::from_static(SECOND))
      .await
      .context("send second Incremental H3 marker after 204 headers")?;
    stream
      .send_data(Bytes::from_static(LAST))
      .await
      .context("send final Incremental H3 marker after 204 headers")?;
    stream
      .finish()
      .await
      .context("finish Incremental H3 upload after 204 headers")?;
    wait_for_completion(args).await?;
    close.close(0u32.into(), b"incremental complete");
    let _ = tokio::time::timeout(Duration::from_secs(1), driver_task).await;
    return Ok(());
  }
  expect_h3_client_data(&mut stream, FIRST).await?;
  stream
    .send_data(Bytes::from_static(SECOND))
    .await
    .context("send second Incremental H3 marker")?;
  expect_h3_client_data(&mut stream, SECOND).await?;
  expect_h3_client_end(&mut stream, "response").await?;
  stream
    .send_data(Bytes::from_static(LAST))
    .await
    .context("send final Incremental H3 marker")?;
  stream
    .finish()
    .await
    .context("finish Incremental H3 upload")?;
  wait_for_completion(args).await?;
  close.close(0u32.into(), b"incremental complete");
  let _ = tokio::time::timeout(Duration::from_secs(1), driver_task).await;
  Ok(())
}
async fn expect_h3_client_data(
  stream: &mut h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
  wanted: &[u8],
) -> anyhow::Result<()> {
  let mut data = within(async {
    stream
      .recv_data()
      .await
      .context("read Incremental H3 data")?
      .ok_or_else(|| anyhow!("unexpected Incremental H3 EOF"))
  })
  .await?;
  let len = data.remaining();
  let data = data.copy_to_bytes(len);
  if data.as_ref() != wanted {
    bail!("unexpected Incremental H3 marker")
  }
  Ok(())
}
async fn expect_h3_client_end(
  stream: &mut h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
  direction: &str,
) -> anyhow::Result<()> {
  loop {
    let data = within(async {
      stream
        .recv_data()
        .await
        .context("read Incremental H3 EOF frame")
    })
    .await?;
    let Some(data) = data else {
      return Ok(());
    };
    if data.remaining() != 0 {
      bail!("Incremental H3 {direction} carried data after its final marker")
    }
  }
}

//! Real-wire managed resumable-upload lifecycle probe.
//!
//! Creation deliberately withholds its entire body until the downstream sends
//! `104 Upload Resumption Supported`.  The remaining operations prove that the
//! acknowledged offset and published object survive independent connections.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use bytes::{Buf, Bytes, BytesMut};
use h3_quinn::quinn::{ClientConfig as QuinnClientConfig, Endpoint};
use http::{HeaderMap, Method, Request, StatusCode, Version};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream};
use tokio_rustls::TlsConnector;

use crate::ClientIdentity;

const TIMEOUT: Duration = Duration::from_secs(10);
const FIRST_PART: &[u8] = b"hello";
const SECOND_PART: &[u8] = b" world";
const COMPLETE_BODY: &[u8] = b"hello world";

#[derive(Clone, Copy)]
enum Protocol {
  H1,
  H2,
  H3,
}

impl Protocol {
  fn parse(raw: &str) -> anyhow::Result<Self> {
    match raw {
      "h1" => Ok(Self::H1),
      "h2" => Ok(Self::H2),
      "h3" => Ok(Self::H3),
      _ => bail!("unsupported managed-upload protocol: {raw}"),
    }
  }

  fn label(self) -> &'static str {
    match self {
      Self::H1 => "h1",
      Self::H2 => "h2",
      Self::H3 => "h3",
    }
  }
}

struct Args {
  protocol: Protocol,
  host: String,
  port: u16,
  server_name: String,
  authority: String,
  creation_path: String,
  ca_cert: String,
  owner: ClientIdentity,
  wrong_owner: ClientIdentity,
}

struct WireResponse {
  status: StatusCode,
  headers: BTreeMap<String, String>,
  body: Bytes,
}

impl WireResponse {
  fn header(&self, name: &str) -> anyhow::Result<&str> {
    self
      .headers
      .get(name)
      .map(String::as_str)
      .ok_or_else(|| anyhow!("response omitted {name}"))
  }

  fn expect_status(&self, expected: StatusCode, operation: &str) -> anyhow::Result<()> {
    if self.status != expected {
      bail!(
        "managed-upload {operation} returned {}, expected {expected}",
        self.status
      );
    }
    Ok(())
  }
}

pub(crate) async fn client(args: impl Iterator<Item = String>) -> anyhow::Result<()> {
  let args = parse(args)?;
  let created = create_after_live_104(&args).await?;
  created.expect_status(StatusCode::CREATED, "create")?;
  expect_header(&created, "upload-offset", "5")?;
  expect_header(&created, "upload-complete", "?0")?;
  let control_path = location_path(created.header("location")?)?;

  let wrong_head = request(
    &args,
    &args.wrong_owner,
    Method::HEAD,
    &control_path,
    &[],
    &[],
  )
  .await?;
  wrong_head.expect_status(StatusCode::NOT_FOUND, "wrong-owner HEAD")?;

  let head = request(&args, &args.owner, Method::HEAD, &control_path, &[], &[]).await?;
  head.expect_status(StatusCode::NO_CONTENT, "HEAD")?;
  expect_header(&head, "upload-offset", "5")?;
  expect_header(&head, "upload-complete", "?0")?;

  let completed = request(
    &args,
    &args.owner,
    Method::PATCH,
    &control_path,
    &[
      ("upload-draft-interop-version", "9"),
      ("upload-complete", "?1"),
      ("upload-offset", "5"),
      ("content-type", "application/partial-upload"),
    ],
    SECOND_PART,
  )
  .await?;
  completed.expect_status(StatusCode::CREATED, "completion")?;
  expect_header(&completed, "upload-offset", "11")?;
  expect_header(&completed, "upload-complete", "?1")?;
  let object_path = location_path(completed.header("location")?)?;

  let wrong_get = request(
    &args,
    &args.wrong_owner,
    Method::GET,
    &object_path,
    &[],
    &[],
  )
  .await?;
  wrong_get.expect_status(StatusCode::NOT_FOUND, "wrong-owner object GET")?;

  let object = request(&args, &args.owner, Method::GET, &object_path, &[], &[]).await?;
  object.expect_status(StatusCode::OK, "object GET")?;
  expect_header(&object, "content-length", "11")?;
  expect_header(&object, "content-disposition", "attachment")?;
  expect_header(&object, "x-content-type-options", "nosniff")?;
  expect_header(&object, "cache-control", "private, no-store")?;
  if object.body.as_ref() != COMPLETE_BODY {
    bail!("managed-upload object bytes differed from the two durable parts");
  }

  let deleted = request(&args, &args.owner, Method::DELETE, &object_path, &[], &[]).await?;
  deleted.expect_status(StatusCode::NO_CONTENT, "DELETE")?;
  let missing = request(&args, &args.owner, Method::GET, &object_path, &[], &[]).await?;
  missing.expect_status(StatusCode::NOT_FOUND, "post-delete GET")?;

  println!("managed-upload-wire-ok protocol={}", args.protocol.label());
  Ok(())
}

fn parse(mut values: impl Iterator<Item = String>) -> anyhow::Result<Args> {
  let mut protocol = None;
  let mut host = None;
  let mut port = None;
  let mut server_name = None;
  let mut authority = None;
  let mut creation_path = None;
  let mut ca_cert = None;
  let mut client_cert = None;
  let mut client_key = None;
  let mut wrong_client_cert = None;
  let mut wrong_client_key = None;
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
      "--creation-path" => creation_path = Some(value),
      "--ca-cert" => ca_cert = Some(value),
      "--client-cert" => client_cert = Some(value),
      "--client-key" => client_key = Some(value),
      "--wrong-client-cert" => wrong_client_cert = Some(value),
      "--wrong-client-key" => wrong_client_key = Some(value),
      _ => bail!("unknown managed-upload-client argument: {flag}"),
    }
  }
  let creation_path = creation_path.ok_or_else(|| anyhow!("missing --creation-path"))?;
  if !creation_path.starts_with('/') {
    bail!("--creation-path must be origin-relative");
  }
  Ok(Args {
    protocol: protocol.ok_or_else(|| anyhow!("missing --protocol"))?,
    host: host.ok_or_else(|| anyhow!("missing --host"))?,
    port: port.ok_or_else(|| anyhow!("missing --port"))?,
    server_name: server_name.ok_or_else(|| anyhow!("missing --server-name"))?,
    authority: authority.ok_or_else(|| anyhow!("missing --authority"))?,
    creation_path,
    ca_cert: ca_cert.ok_or_else(|| anyhow!("missing --ca-cert"))?,
    owner: ClientIdentity {
      cert: client_cert.ok_or_else(|| anyhow!("missing --client-cert"))?,
      key: client_key.ok_or_else(|| anyhow!("missing --client-key"))?,
    },
    wrong_owner: ClientIdentity {
      cert: wrong_client_cert.ok_or_else(|| anyhow!("missing --wrong-client-cert"))?,
      key: wrong_client_key.ok_or_else(|| anyhow!("missing --wrong-client-key"))?,
    },
  })
}

fn expect_header(response: &WireResponse, name: &str, expected: &str) -> anyhow::Result<()> {
  let actual = response.header(name)?;
  if actual != expected {
    bail!("managed-upload response {name} was {actual:?}, expected {expected:?}");
  }
  Ok(())
}

fn location_path(location: &str) -> anyhow::Result<String> {
  let url = url::Url::parse(location).context("managed-upload Location was not absolute")?;
  if url.scheme() != "https" || url.query().is_some() || url.fragment().is_some() {
    bail!("managed-upload Location was not a plain HTTPS resource URL");
  }
  Ok(url.path().to_owned())
}

async fn create_after_live_104(args: &Args) -> anyhow::Result<WireResponse> {
  let headers = [
    ("upload-draft-interop-version", "9"),
    ("upload-complete", "?0"),
    ("upload-length", "11"),
    ("content-type", "text/plain"),
  ];
  match args.protocol {
    Protocol::H1 => h1_create(args, &headers).await,
    Protocol::H2 => h2_create(args, &headers).await,
    Protocol::H3 => h3_create(args, &headers).await,
  }
}

async fn request(
  args: &Args,
  identity: &ClientIdentity,
  method: Method,
  path: &str,
  headers: &[(&str, &str)],
  body: &[u8],
) -> anyhow::Result<WireResponse> {
  match args.protocol {
    Protocol::H1 => h1_request(args, identity, method, path, headers, body).await,
    Protocol::H2 => h2_request(args, identity, method, path, headers, body).await,
    Protocol::H3 => h3_request(args, identity, method, path, headers, body).await,
  }
}

fn request_head(
  args: &Args,
  method: Method,
  path: &str,
  version: Version,
  headers: &[(&str, &str)],
  body_len: usize,
) -> anyhow::Result<Request<()>> {
  let uri = http::Uri::builder()
    .scheme("https")
    .authority(args.authority.as_str())
    .path_and_query(path)
    .build()
    .context("build managed-upload request URI")?;
  let mut builder = Request::builder()
    .method(method)
    .version(version)
    .uri(uri)
    .header("host", &args.authority)
    .header("content-length", body_len);
  for (name, value) in headers {
    builder = builder.header(*name, *value);
  }
  builder.body(()).context("build managed-upload request")
}

fn client_config(
  args: &Args,
  alpn: &[u8],
  identity: &ClientIdentity,
) -> anyhow::Result<rustls::ClientConfig> {
  super::downstream_client_config_with_client_identity(
    Path::new(&args.ca_cert),
    alpn,
    None,
    Some(identity),
  )
}

async fn tls_stream(
  args: &Args,
  alpn: &[u8],
  identity: &ClientIdentity,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
  let config = client_config(args, alpn, identity)?;
  let tcp = within(TcpStream::connect((args.host.as_str(), args.port)))
    .await?
    .context("connect managed-upload downstream")?;
  let server_name =
    ServerName::try_from(args.server_name.clone()).map_err(|_| anyhow!("invalid --server-name"))?;
  within(TlsConnector::from(Arc::new(config)).connect(server_name, tcp))
    .await?
    .context("establish managed-upload downstream TLS")
}

async fn h1_create(args: &Args, headers: &[(&str, &str)]) -> anyhow::Result<WireResponse> {
  let mut stream = tls_stream(args, b"http/1.1", &args.owner).await?;
  let head = h1_head(
    args,
    &Method::POST,
    &args.creation_path,
    headers,
    FIRST_PART.len(),
  );
  within(stream.write_all(head.as_bytes())).await??;
  within(stream.flush()).await??;
  let interim = read_h1_head(&mut stream).await?;
  if interim.status.as_u16() != 104 {
    bail!(
      "managed-upload H1 first response was {}, expected live 104",
      interim.status
    );
  }
  expect_header(&interim, "upload-offset", "0")?;
  within(stream.write_all(FIRST_PART)).await??;
  within(stream.flush()).await??;
  read_h1_response(&mut stream, false).await
}

async fn h1_request(
  args: &Args,
  identity: &ClientIdentity,
  method: Method,
  path: &str,
  headers: &[(&str, &str)],
  body: &[u8],
) -> anyhow::Result<WireResponse> {
  let mut stream = tls_stream(args, b"http/1.1", identity).await?;
  let head = h1_head(args, &method, path, headers, body.len());
  within(stream.write_all(head.as_bytes())).await??;
  if !body.is_empty() {
    within(stream.write_all(body)).await??;
  }
  within(stream.flush()).await??;
  read_h1_response(&mut stream, method == Method::HEAD).await
}

fn h1_head(
  args: &Args,
  method: &Method,
  path: &str,
  headers: &[(&str, &str)],
  body_len: usize,
) -> String {
  let mut head = format!(
    "{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Length: {body_len}\r\nConnection: close\r\n",
    args.authority
  );
  for (name, value) in headers {
    head.push_str(name);
    head.push_str(": ");
    head.push_str(value);
    head.push_str("\r\n");
  }
  head.push_str("\r\n");
  head
}

async fn read_h1_head<S: AsyncRead + Unpin>(stream: &mut S) -> anyhow::Result<WireResponse> {
  let raw = read_until(stream, b"\r\n\r\n", 64 * 1024).await?;
  let text = std::str::from_utf8(&raw).context("managed-upload H1 head was not UTF-8")?;
  let mut lines = text.trim_end_matches("\r\n\r\n").split("\r\n");
  let status = lines
    .next()
    .and_then(|line| line.split_ascii_whitespace().nth(1))
    .ok_or_else(|| anyhow!("managed-upload H1 response omitted status"))?
    .parse::<u16>()
    .context("managed-upload H1 status was invalid")?;
  let mut headers = BTreeMap::new();
  for line in lines {
    let (name, value) = line
      .split_once(':')
      .ok_or_else(|| anyhow!("managed-upload H1 response header was malformed"))?;
    headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
  }
  Ok(WireResponse {
    status: StatusCode::from_u16(status)?,
    headers,
    body: Bytes::new(),
  })
}

async fn read_h1_response<S: AsyncRead + Unpin>(
  stream: &mut S,
  head_request: bool,
) -> anyhow::Result<WireResponse> {
  let mut response = read_h1_head(stream).await?;
  let length = response
    .headers
    .get("content-length")
    .map(|value| value.parse::<usize>().context("invalid H1 content-length"))
    .transpose()?
    .unwrap_or(0);
  if !head_request && length != 0 {
    if length > 1024 * 1024 {
      bail!("managed-upload H1 response exceeded probe bound");
    }
    let mut body = vec![0; length];
    within(stream.read_exact(&mut body)).await??;
    response.body = body.into();
  }
  Ok(response)
}

async fn h2_create(args: &Args, headers: &[(&str, &str)]) -> anyhow::Result<WireResponse> {
  let tls = tls_stream(args, b"h2", &args.owner).await?;
  let (mut sender, connection) = within(h2::client::handshake(tls))
    .await?
    .context("handshake managed-upload H2")?;
  let connection_task = tokio::spawn(async move { connection.await });
  let request = request_head(
    args,
    Method::POST,
    &args.creation_path,
    Version::HTTP_2,
    headers,
    FIRST_PART.len(),
  )?;
  let (mut response, mut upload) = sender
    .send_request(request, false)
    .context("send managed-upload H2 create headers")?;
  let interim = within(futures_util::future::poll_fn(|cx| {
    response.poll_informational(cx)
  }))
  .await?
  .ok_or_else(|| anyhow!("managed-upload H2 completed before live 104"))??;
  if interim.status().as_u16() != 104 {
    bail!(
      "managed-upload H2 first response was {}, expected live 104",
      interim.status()
    );
  }
  if interim
    .headers()
    .get("upload-offset")
    .and_then(|v| v.to_str().ok())
    != Some("0")
  {
    bail!("managed-upload H2 live 104 omitted offset zero");
  }
  upload
    .send_data(Bytes::from_static(FIRST_PART), true)
    .context("send managed-upload H2 create body after 104")?;
  let final_response = within(response)
    .await?
    .context("receive managed-upload H2 create")?;
  let result = collect_h2(final_response).await;
  drop(sender);
  let _ = within(connection_task).await;
  result
}

async fn h2_request(
  args: &Args,
  identity: &ClientIdentity,
  method: Method,
  path: &str,
  headers: &[(&str, &str)],
  body: &[u8],
) -> anyhow::Result<WireResponse> {
  let tls = tls_stream(args, b"h2", identity).await?;
  let (mut sender, connection) = within(h2::client::handshake(tls))
    .await?
    .context("handshake managed-upload H2")?;
  let connection_task = tokio::spawn(async move { connection.await });
  let request = request_head(args, method, path, Version::HTTP_2, headers, body.len())?;
  let (response, mut upload) = sender
    .send_request(request, body.is_empty())
    .context("send managed-upload H2 request")?;
  if !body.is_empty() {
    upload
      .send_data(Bytes::copy_from_slice(body), true)
      .context("send managed-upload H2 body")?;
  }
  let response = within(response)
    .await?
    .context("receive managed-upload H2 response")?;
  let result = collect_h2(response).await;
  drop(sender);
  let _ = within(connection_task).await;
  result
}

async fn collect_h2(response: http::Response<h2::RecvStream>) -> anyhow::Result<WireResponse> {
  let (parts, mut body) = response.into_parts();
  let mut bytes = BytesMut::new();
  while let Some(chunk) = within(body.data()).await? {
    let chunk = chunk.context("read managed-upload H2 response body")?;
    if bytes.len().saturating_add(chunk.len()) > 1024 * 1024 {
      bail!("managed-upload H2 response exceeded probe bound");
    }
    body.flow_control().release_capacity(chunk.len())?;
    bytes.extend_from_slice(&chunk);
  }
  Ok(WireResponse {
    status: parts.status,
    headers: header_map(&parts.headers),
    body: bytes.freeze(),
  })
}

async fn h3_create(args: &Args, headers: &[(&str, &str)]) -> anyhow::Result<WireResponse> {
  let (endpoint, close, driver_task, mut sender) = h3_connection(args, &args.owner).await?;
  let request = request_head(
    args,
    Method::POST,
    &args.creation_path,
    Version::HTTP_3,
    headers,
    FIRST_PART.len(),
  )?;
  let mut stream = sender
    .send_request(request)
    .await
    .context("send managed-upload H3 create headers")?;
  let interim = within(stream.recv_response())
    .await?
    .context("receive managed-upload H3 live 104")?;
  if interim.status().as_u16() != 104 {
    bail!(
      "managed-upload H3 first response was {}, expected live 104",
      interim.status()
    );
  }
  if interim
    .headers()
    .get("upload-offset")
    .and_then(|v| v.to_str().ok())
    != Some("0")
  {
    bail!("managed-upload H3 live 104 omitted offset zero");
  }
  stream
    .send_data(Bytes::from_static(FIRST_PART))
    .await
    .context("send managed-upload H3 create body after 104")?;
  stream
    .finish()
    .await
    .context("finish managed-upload H3 create body")?;
  let result = collect_h3(&mut stream).await;
  finish_h3(endpoint, close, driver_task).await;
  result
}

async fn h3_request(
  args: &Args,
  identity: &ClientIdentity,
  method: Method,
  path: &str,
  headers: &[(&str, &str)],
  body: &[u8],
) -> anyhow::Result<WireResponse> {
  let (endpoint, close, driver_task, mut sender) = h3_connection(args, identity).await?;
  let request = request_head(args, method, path, Version::HTTP_3, headers, body.len())?;
  let mut stream = sender
    .send_request(request)
    .await
    .context("send managed-upload H3 request")?;
  if !body.is_empty() {
    stream
      .send_data(Bytes::copy_from_slice(body))
      .await
      .context("send managed-upload H3 body")?;
  }
  stream
    .finish()
    .await
    .context("finish managed-upload H3 request")?;
  let result = collect_h3(&mut stream).await;
  finish_h3(endpoint, close, driver_task).await;
  result
}

type H3Stream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

async fn collect_h3(stream: &mut H3Stream) -> anyhow::Result<WireResponse> {
  let response = within(stream.recv_response())
    .await?
    .context("receive managed-upload H3 response")?;
  let mut bytes = BytesMut::new();
  while let Some(mut chunk) = within(stream.recv_data())
    .await?
    .context("read managed-upload H3 response body")?
  {
    if bytes.len().saturating_add(chunk.remaining()) > 1024 * 1024 {
      bail!("managed-upload H3 response exceeded probe bound");
    }
    let len = chunk.remaining();
    bytes.extend_from_slice(&chunk.copy_to_bytes(len));
  }
  Ok(WireResponse {
    status: response.status(),
    headers: header_map(response.headers()),
    body: bytes.freeze(),
  })
}

async fn h3_connection(
  args: &Args,
  identity: &ClientIdentity,
) -> anyhow::Result<(
  Endpoint,
  h3_quinn::quinn::Connection,
  tokio::task::JoinHandle<()>,
  h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
)> {
  let crypto = h3_quinn::quinn::crypto::rustls::QuicClientConfig::try_from(client_config(
    args, b"h3", identity,
  )?)
  .context("build managed-upload H3 TLS")?;
  let remote = lookup_host((args.host.as_str(), args.port))
    .await?
    .next()
    .ok_or_else(|| anyhow!("managed-upload H3 host resolved without an address"))?;
  let endpoint =
    Endpoint::client(client_bind(remote)).context("create managed-upload H3 endpoint")?;
  let connection = within(
    endpoint
      .connect_with(
        QuinnClientConfig::new(Arc::new(crypto)),
        remote,
        &args.server_name,
      )
      .context("start managed-upload H3 connection")?,
  )
  .await?
  .context("complete managed-upload H3 connection")?;
  let close = connection.clone();
  let (mut driver, sender) = h3::client::builder()
    .build(h3_quinn::Connection::new(connection))
    .await
    .context("build managed-upload H3 client")?;
  let driver_task = tokio::spawn(async move {
    let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
  });
  Ok((endpoint, close, driver_task, sender))
}

async fn finish_h3(
  endpoint: Endpoint,
  close: h3_quinn::quinn::Connection,
  driver_task: tokio::task::JoinHandle<()>,
) {
  close.close(0u32.into(), b"managed-upload probe complete");
  endpoint.wait_idle().await;
  let _ = within(driver_task).await;
}

fn client_bind(remote: SocketAddr) -> SocketAddr {
  if remote.is_ipv4() {
    "0.0.0.0:0".parse().expect("valid IPv4 wildcard")
  } else {
    "[::]:0".parse().expect("valid IPv6 wildcard")
  }
}

fn header_map(headers: &HeaderMap) -> BTreeMap<String, String> {
  headers
    .iter()
    .filter_map(|(name, value)| {
      value
        .to_str()
        .ok()
        .map(|value| (name.as_str().to_ascii_lowercase(), value.to_owned()))
    })
    .collect()
}

async fn read_until<S: AsyncRead + Unpin>(
  stream: &mut S,
  needle: &[u8],
  maximum: usize,
) -> anyhow::Result<Vec<u8>> {
  let mut bytes = Vec::new();
  loop {
    if bytes.ends_with(needle) {
      return Ok(bytes);
    }
    if bytes.len() >= maximum {
      bail!("managed-upload H1 response head exceeded probe bound");
    }
    let mut byte = [0u8; 1];
    within(stream.read_exact(&mut byte))
      .await?
      .context("read managed-upload H1 response")?;
    bytes.push(byte[0]);
  }
}

async fn within<F: Future>(future: F) -> anyhow::Result<F::Output> {
  tokio::time::timeout(TIMEOUT, future)
    .await
    .context("managed-upload wire operation timed out")
}

use std::future::Future;

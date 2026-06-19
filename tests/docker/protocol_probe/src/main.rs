use std::collections::BTreeMap;
use std::convert::Infallible;
use std::env;
use std::fs;
use std::future::Future;
use std::io::{self, Read as StdRead, Write as StdWrite};
use std::net::{SocketAddr, TcpStream as StdTcpStream};
use std::ops::Range;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context};
use base64::Engine;
use bytes::{Buf, Bytes, BytesMut};
use h3_quinn::quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use h3_quinn::quinn::{
  ClientConfig as QuinnClientConfig, Endpoint, ServerConfig as QuinnServerConfig,
};
use http::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_LENGTH, CONTENT_TYPE};
use http::{Method, Request, Response, StatusCode, Uri, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming, SizeHint};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use md5::{Digest, Md5};
use ring::hmac;
use rustls::client::Resumption;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, HandshakeKind, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[derive(Clone, Copy)]
enum DownstreamProtocol {
  H2,
  H3,
}

impl DownstreamProtocol {
  fn parse(raw: &str) -> anyhow::Result<Self> {
    match raw {
      "h2" => Ok(Self::H2),
      "h3" => Ok(Self::H3),
      _ => bail!("unsupported downstream protocol: {raw}"),
    }
  }

  fn label(self) -> &'static str {
    match self {
      Self::H2 => "h2",
      Self::H3 => "h3",
    }
  }
}

struct H2UpstreamArgs {
  listen: SocketAddr,
  cert: String,
  key: String,
  name: String,
}

struct H2cUpstreamArgs {
  listen: SocketAddr,
  name: String,
}

struct H1StallUpstreamArgs {
  listen: SocketAddr,
  name: String,
  read_delay_ms: u64,
}

struct H3UpstreamArgs {
  listen: SocketAddr,
  cert: String,
  key: String,
  name: String,
}

struct WebTransportUpstreamArgs {
  listen: SocketAddr,
  cert: String,
  key: String,
  name: String,
}

struct DownstreamArgs {
  protocol: DownstreamProtocol,
  host: String,
  port: u16,
  server_name: String,
  authority: String,
  path: String,
  method: Method,
  body: String,
  body_bytes: Option<usize>,
  body_chunk_size: usize,
  zero_length_body_end_delay_ms: Option<u64>,
  omit_content_length: bool,
  headers: HeaderMap,
  ca_cert: String,
  expect_status: Option<u16>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DpiTlsProfile {
  ByedpiSplitSni,
  ByedpiTlsrecSni,
  GoodbyeDpiNativeFrag,
  GoodbyeDpiFragBySni,
  DpibreakSegment01,
  DpibreakSegment05,
}

impl DpiTlsProfile {
  fn parse(raw: &str) -> anyhow::Result<Self> {
    match raw {
      "byedpi-split-sni" => Ok(Self::ByedpiSplitSni),
      "byedpi-tlsrec-sni" => Ok(Self::ByedpiTlsrecSni),
      "goodbyedpi-native-frag" => Ok(Self::GoodbyeDpiNativeFrag),
      "goodbyedpi-frag-by-sni" => Ok(Self::GoodbyeDpiFragBySni),
      "dpibreak-segment-0-1" => Ok(Self::DpibreakSegment01),
      "dpibreak-segment-0-5" => Ok(Self::DpibreakSegment05),
      _ => bail!("unsupported DPI TLS profile: {raw}"),
    }
  }

  fn label(self) -> &'static str {
    match self {
      Self::ByedpiSplitSni => "byedpi-split-sni",
      Self::ByedpiTlsrecSni => "byedpi-tlsrec-sni",
      Self::GoodbyeDpiNativeFrag => "goodbyedpi-native-frag",
      Self::GoodbyeDpiFragBySni => "goodbyedpi-frag-by-sni",
      Self::DpibreakSegment01 => "dpibreak-segment-0-1",
      Self::DpibreakSegment05 => "dpibreak-segment-0-5",
    }
  }
}

struct DpiTlsArgs {
  profile: DpiTlsProfile,
  host: String,
  port: u16,
  server_name: String,
  authority: String,
  path: String,
  ca_cert: String,
  expect_status: Option<u16>,
}

struct ClientHelloView {
  record: Range<usize>,
  payload: Range<usize>,
  sni_name: Range<usize>,
}

struct DpiTlsWritePlan {
  chunks: Vec<Vec<u8>>,
  tcp_chunk_count: usize,
  tls_record_count: usize,
  sni_offset: usize,
}

struct TlsResumptionLoadArgs {
  host: String,
  port: u16,
  server_name: String,
  authority: String,
  path: String,
  ca_cert: String,
  connections: usize,
  expect_resumed_min: usize,
}

struct WebTransportMultiplexArgs {
  host: String,
  port: u16,
  server_name: String,
  authority: String,
  path: String,
  headers: HeaderMap,
  ca_cert: String,
  sessions: usize,
  expect_statuses: Vec<u16>,
}

struct WebTransportReloadGatedArgs {
  host: String,
  port: u16,
  server_name: String,
  authority: String,
  path: String,
  http_path: String,
  headers: HeaderMap,
  ca_cert: String,
  first_ready_path: String,
  resume_path: String,
  expect_initial_status: u16,
  expect_drained_status: u16,
}

struct AdminOperationWtEventsArgs {
  host: String,
  port: u16,
  path: String,
  headers: HeaderMap,
  ca_cert: String,
  expect_events: Vec<String>,
  expect_terminal_state: Option<String>,
  timeout_ms: u64,
}

struct WebSocketEchoArgs {
  listen: SocketAddr,
}

struct WebSocketClientArgs {
  host: String,
  port: u16,
  server_name: String,
  authority: String,
  path: String,
  ca_cert: String,
  payload: Vec<u8>,
  expect_status: u16,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TurnTransport {
  Udp,
  Tcp,
  Tls,
}

impl TurnTransport {
  fn parse(raw: &str) -> anyhow::Result<Self> {
    match raw {
      "udp" => Ok(Self::Udp),
      "tcp" => Ok(Self::Tcp),
      "tls" => Ok(Self::Tls),
      _ => bail!("unsupported TURN transport: {raw}"),
    }
  }

  fn label(self) -> &'static str {
    match self {
      Self::Udp => "udp",
      Self::Tcp => "tcp",
      Self::Tls => "tls",
    }
  }
}

struct TurnUpstreamArgs {
  transport: TurnTransport,
  listen: SocketAddr,
  cert: Option<String>,
  key: Option<String>,
}

#[derive(Clone, Copy)]
enum TurnClientAuth {
  Valid,
  Invalid,
  Missing,
}

impl TurnClientAuth {
  fn parse(raw: &str) -> anyhow::Result<Self> {
    match raw {
      "valid" => Ok(Self::Valid),
      "invalid" => Ok(Self::Invalid),
      "missing" => Ok(Self::Missing),
      _ => bail!("unsupported TURN auth mode: {raw}"),
    }
  }
}

#[derive(Clone, Copy)]
enum TurnClientExpect {
  Echo,
  NoResponse,
}

impl TurnClientExpect {
  fn parse(raw: &str) -> anyhow::Result<Self> {
    match raw {
      "echo" => Ok(Self::Echo),
      "no-response" => Ok(Self::NoResponse),
      _ => bail!("unsupported TURN expectation: {raw}"),
    }
  }
}

struct TurnClientArgs {
  transport: TurnTransport,
  host: String,
  port: u16,
  server_name: String,
  ca_cert: Option<String>,
  username: String,
  realm: String,
  password: String,
  auth: TurnClientAuth,
  expect: TurnClientExpect,
}

impl DownstreamArgs {
  fn body_len(&self) -> usize {
    if self.zero_length_body_end_delay_ms.is_some() {
      return 0;
    }
    self.body_bytes.unwrap_or(self.body.len())
  }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let mut args = env::args().skip(1);
  let Some(command) = args.next() else {
    usage();
    bail!("missing command");
  };

  match command.as_str() {
    "h2-upstream" => serve_h2_upstream(parse_h2_upstream_args(args)?).await,
    "h2c-upstream" => serve_h2c_upstream(parse_h2c_upstream_args(args)?).await,
    "h1-stall-upstream" => serve_h1_stall_upstream(parse_h1_stall_upstream_args(args)?).await,
    "h3-upstream" => serve_h3_upstream(parse_h3_upstream_args(args)?).await,
    "webtransport-upstream" => {
      serve_webtransport_upstream(parse_webtransport_upstream_args(args)?).await
    }
    "websocket-echo-upstream" => {
      serve_websocket_echo_upstream(parse_websocket_echo_args(args)?).await
    }
    "websocket-client" => run_websocket_client(parse_websocket_client_args(args)?).await,
    "turn-upstream" => serve_turn_upstream(parse_turn_upstream_args(args)?).await,
    "turn-client" => run_turn_client(parse_turn_client_args(args)?).await,
    "downstream" => run_downstream_client(parse_downstream_args(args)?).await,
    "dpi-tls-client" => run_dpi_tls_client(parse_dpi_tls_args(args)?).await,
    "tls-resumption-load" => run_tls_resumption_load(parse_tls_resumption_load_args(args)?).await,
    "webtransport-multiplex" => {
      run_webtransport_multiplex_client(parse_webtransport_multiplex_args(args)?).await
    }
    "webtransport-reload-gated" => {
      run_webtransport_reload_gated_client(parse_webtransport_reload_gated_args(args)?).await
    }
    "admin-operation-wt-events" => {
      run_admin_operation_wt_events_client(parse_admin_operation_wt_events_args(args)?).await
    }
    _ => {
      usage();
      bail!("unknown command: {command}");
    }
  }
}

fn usage() {
  eprintln!(
        "usage:\n  protocol-probe h2-upstream --listen <addr:port> --cert <pem> --key <pem> --name <name>\n  protocol-probe h2c-upstream --listen <addr:port> --name <name>\n  protocol-probe h1-stall-upstream --listen <addr:port> --name <name> --read-delay-ms <ms>\n  protocol-probe h3-upstream --listen <addr:port> --cert <pem> --key <pem> --name <name>\n  protocol-probe webtransport-upstream --listen <addr:port> --cert <pem> --key <pem> --name <name>\n  protocol-probe websocket-echo-upstream --listen <addr:port>\n  protocol-probe websocket-client --host <host> --port <port> --server-name <sni> --authority <authority> --path <path> --ca-cert <pem> --payload <text> --expect-status <status>\n  protocol-probe turn-upstream --transport <udp|tcp|tls> --listen <addr:port> [--cert <pem> --key <pem>]\n  protocol-probe turn-client --transport <udp|tcp|tls> --host <host> --port <port> --server-name <sni> --username <name> --realm <realm> --password <password> --auth <valid|invalid|missing> --expect <echo|no-response> [--ca-cert <pem>]\n  protocol-probe downstream --protocol <h2|h3> --host <host> --port <port> --server-name <sni> --authority <authority> --path <path> --ca-cert <pem> [--body <text>|--body-bytes <n>] [--body-chunk-size <n>] [--zero-length-body-end-delay-ms <ms>] [--omit-content-length] [--header <name:value>] [--expect-status <status>]\n  protocol-probe dpi-tls-client --profile <name> --host <host> --port <port> --server-name <sni> --authority <authority> --path <path> --ca-cert <pem> [--expect-status <status>]\n  protocol-probe tls-resumption-load --host <host> --port <port> --server-name <sni> --authority <authority> --path <path> --ca-cert <pem> --connections <n> --expect-resumed-min <n>\n  protocol-probe webtransport-multiplex --host <host> --port <port> --server-name <sni> --authority <authority> --path <path> --ca-cert <pem> --sessions <n> --expect-statuses <csv> [--header <name:value>]\n  protocol-probe webtransport-reload-gated --host <host> --port <port> --server-name <sni> --authority <authority> --path <path> --http-path <path> --ca-cert <pem> --first-ready-path <path> --resume-path <path> --expect-initial-status <status> --expect-drained-status <status> [--header <name:value>]\n  protocol-probe admin-operation-wt-events --host <host> --port <port> --path <path> --ca-cert <pem> [--header <name:value>] [--expect-event <name>] [--expect-terminal-state <state>] [--timeout-ms <ms>]"
  );
}

fn parse_h2_upstream_args(
  mut args: impl Iterator<Item = String>,
) -> anyhow::Result<H2UpstreamArgs> {
  let mut listen = None;
  let mut cert = None;
  let mut key = None;
  let mut name = None;

  while let Some(flag) = args.next() {
    let value = args
      .next()
      .ok_or_else(|| anyhow!("missing value for {flag}"))?;
    match flag.as_str() {
      "--listen" => listen = Some(value.parse().context("invalid --listen value")?),
      "--cert" => cert = Some(value),
      "--key" => key = Some(value),
      "--name" => name = Some(value),
      _ => bail!("unknown h2-upstream flag: {flag}"),
    }
  }

  Ok(H2UpstreamArgs {
    listen: listen.ok_or_else(|| anyhow!("--listen is required"))?,
    cert: cert.ok_or_else(|| anyhow!("--cert is required"))?,
    key: key.ok_or_else(|| anyhow!("--key is required"))?,
    name: name.ok_or_else(|| anyhow!("--name is required"))?,
  })
}

fn parse_h2c_upstream_args(
  mut args: impl Iterator<Item = String>,
) -> anyhow::Result<H2cUpstreamArgs> {
  let mut listen = None;
  let mut name = None;

  while let Some(flag) = args.next() {
    let value = args
      .next()
      .ok_or_else(|| anyhow!("missing value for {flag}"))?;
    match flag.as_str() {
      "--listen" => listen = Some(value.parse().context("invalid --listen value")?),
      "--name" => name = Some(value),
      _ => bail!("unknown h2c-upstream flag: {flag}"),
    }
  }

  Ok(H2cUpstreamArgs {
    listen: listen.ok_or_else(|| anyhow!("--listen is required"))?,
    name: name.ok_or_else(|| anyhow!("--name is required"))?,
  })
}

fn parse_h1_stall_upstream_args(
  mut args: impl Iterator<Item = String>,
) -> anyhow::Result<H1StallUpstreamArgs> {
  let mut listen = None;
  let mut name = None;
  let mut read_delay_ms = None;

  while let Some(flag) = args.next() {
    let value = args
      .next()
      .ok_or_else(|| anyhow!("missing value for {flag}"))?;
    match flag.as_str() {
      "--listen" => listen = Some(value.parse().context("invalid --listen value")?),
      "--name" => name = Some(value),
      "--read-delay-ms" => {
        read_delay_ms = Some(value.parse().context("invalid --read-delay-ms value")?);
      }
      _ => bail!("unknown h1-stall-upstream flag: {flag}"),
    }
  }

  Ok(H1StallUpstreamArgs {
    listen: listen.ok_or_else(|| anyhow!("--listen is required"))?,
    name: name.ok_or_else(|| anyhow!("--name is required"))?,
    read_delay_ms: read_delay_ms.ok_or_else(|| anyhow!("--read-delay-ms is required"))?,
  })
}

fn parse_h3_upstream_args(args: impl Iterator<Item = String>) -> anyhow::Result<H3UpstreamArgs> {
  let parsed = parse_h2_upstream_args(args)?;
  Ok(H3UpstreamArgs {
    listen: parsed.listen,
    cert: parsed.cert,
    key: parsed.key,
    name: parsed.name,
  })
}

fn parse_webtransport_upstream_args(
  args: impl Iterator<Item = String>,
) -> anyhow::Result<WebTransportUpstreamArgs> {
  let parsed = parse_h2_upstream_args(args)?;
  Ok(WebTransportUpstreamArgs {
    listen: parsed.listen,
    cert: parsed.cert,
    key: parsed.key,
    name: parsed.name,
  })
}

fn parse_websocket_echo_args(
  mut args: impl Iterator<Item = String>,
) -> anyhow::Result<WebSocketEchoArgs> {
  let mut listen = None;
  while let Some(flag) = args.next() {
    let value = args
      .next()
      .ok_or_else(|| anyhow!("missing value for {flag}"))?;
    match flag.as_str() {
      "--listen" => listen = Some(value.parse().context("invalid --listen value")?),
      _ => bail!("unknown websocket-echo-upstream flag: {flag}"),
    }
  }
  Ok(WebSocketEchoArgs {
    listen: listen.ok_or_else(|| anyhow!("--listen is required"))?,
  })
}

fn parse_websocket_client_args(
  mut args: impl Iterator<Item = String>,
) -> anyhow::Result<WebSocketClientArgs> {
  let mut host = None;
  let mut port = None;
  let mut server_name = None;
  let mut authority = None;
  let mut path = None;
  let mut ca_cert = None;
  let mut payload = None;
  let mut expect_status = None;

  while let Some(flag) = args.next() {
    let value = args
      .next()
      .ok_or_else(|| anyhow!("missing value for {flag}"))?;
    match flag.as_str() {
      "--host" => host = Some(value),
      "--port" => port = Some(value.parse().context("invalid --port value")?),
      "--server-name" => server_name = Some(value),
      "--authority" => authority = Some(value),
      "--path" => path = Some(validate_origin_form_path(&value)?),
      "--ca-cert" => ca_cert = Some(value),
      "--payload" => payload = Some(value.into_bytes()),
      "--expect-status" => {
        expect_status = Some(value.parse().context("invalid --expect-status value")?);
      }
      _ => bail!("unknown websocket-client flag: {flag}"),
    }
  }

  let server_name = server_name.ok_or_else(|| anyhow!("--server-name is required"))?;
  Ok(WebSocketClientArgs {
    host: host.ok_or_else(|| anyhow!("--host is required"))?,
    port: port.ok_or_else(|| anyhow!("--port is required"))?,
    authority: authority.unwrap_or_else(|| server_name.clone()),
    server_name,
    path: path.ok_or_else(|| anyhow!("--path is required"))?,
    ca_cert: ca_cert.ok_or_else(|| anyhow!("--ca-cert is required"))?,
    payload: payload.ok_or_else(|| anyhow!("--payload is required"))?,
    expect_status: expect_status.ok_or_else(|| anyhow!("--expect-status is required"))?,
  })
}

fn parse_turn_upstream_args(
  mut args: impl Iterator<Item = String>,
) -> anyhow::Result<TurnUpstreamArgs> {
  let mut transport = None;
  let mut listen = None;
  let mut cert = None;
  let mut key = None;

  while let Some(flag) = args.next() {
    let value = args
      .next()
      .ok_or_else(|| anyhow!("missing value for {flag}"))?;
    match flag.as_str() {
      "--transport" => transport = Some(TurnTransport::parse(&value)?),
      "--listen" => listen = Some(value.parse().context("invalid --listen value")?),
      "--cert" => cert = Some(value),
      "--key" => key = Some(value),
      _ => bail!("unknown turn-upstream flag: {flag}"),
    }
  }

  let transport = transport.ok_or_else(|| anyhow!("--transport is required"))?;
  if transport == TurnTransport::Tls && (cert.is_none() || key.is_none()) {
    bail!("TURN TLS upstream requires --cert and --key");
  }
  Ok(TurnUpstreamArgs {
    transport,
    listen: listen.ok_or_else(|| anyhow!("--listen is required"))?,
    cert,
    key,
  })
}

fn parse_turn_client_args(
  mut args: impl Iterator<Item = String>,
) -> anyhow::Result<TurnClientArgs> {
  let mut transport = None;
  let mut host = None;
  let mut port = None;
  let mut server_name = None;
  let mut ca_cert = None;
  let mut username = None;
  let mut realm = None;
  let mut password = None;
  let mut auth = None;
  let mut expect = None;

  while let Some(flag) = args.next() {
    let value = args
      .next()
      .ok_or_else(|| anyhow!("missing value for {flag}"))?;
    match flag.as_str() {
      "--transport" => transport = Some(TurnTransport::parse(&value)?),
      "--host" => host = Some(value),
      "--port" => port = Some(value.parse().context("invalid --port value")?),
      "--server-name" => server_name = Some(value),
      "--ca-cert" => ca_cert = Some(value),
      "--username" => username = Some(value),
      "--realm" => realm = Some(value),
      "--password" => password = Some(value),
      "--auth" => auth = Some(TurnClientAuth::parse(&value)?),
      "--expect" => expect = Some(TurnClientExpect::parse(&value)?),
      _ => bail!("unknown turn-client flag: {flag}"),
    }
  }

  let transport = transport.ok_or_else(|| anyhow!("--transport is required"))?;
  if transport == TurnTransport::Tls && ca_cert.is_none() {
    bail!("TURN TLS client requires --ca-cert");
  }
  Ok(TurnClientArgs {
    transport,
    host: host.ok_or_else(|| anyhow!("--host is required"))?,
    port: port.ok_or_else(|| anyhow!("--port is required"))?,
    server_name: server_name.unwrap_or_else(|| "proxy".to_string()),
    ca_cert,
    username: username.ok_or_else(|| anyhow!("--username is required"))?,
    realm: realm.ok_or_else(|| anyhow!("--realm is required"))?,
    password: password.ok_or_else(|| anyhow!("--password is required"))?,
    auth: auth.ok_or_else(|| anyhow!("--auth is required"))?,
    expect: expect.ok_or_else(|| anyhow!("--expect is required"))?,
  })
}

fn parse_webtransport_multiplex_args(
  mut args: impl Iterator<Item = String>,
) -> anyhow::Result<WebTransportMultiplexArgs> {
  let mut host = None;
  let mut port = None;
  let mut server_name = None;
  let mut authority = None;
  let mut path = None;
  let mut headers = HeaderMap::new();
  let mut ca_cert = None;
  let mut sessions = None;
  let mut expect_statuses = None;

  while let Some(flag) = args.next() {
    let value = args
      .next()
      .ok_or_else(|| anyhow!("missing value for {flag}"))?;
    match flag.as_str() {
      "--host" => host = Some(value),
      "--port" => port = Some(value.parse().context("invalid --port value")?),
      "--server-name" => server_name = Some(value),
      "--authority" => authority = Some(value),
      "--path" => path = Some(validate_origin_form_path(&value)?),
      "--header" => insert_header(&mut headers, &value)?,
      "--ca-cert" => ca_cert = Some(value),
      "--sessions" => {
        let parsed = value.parse().context("invalid --sessions value")?;
        if parsed == 0 {
          bail!("--sessions must be greater than zero");
        }
        sessions = Some(parsed);
      }
      "--expect-statuses" => {
        let parsed = value
          .split(',')
          .map(|item| item.parse().context("invalid --expect-statuses value"))
          .collect::<anyhow::Result<Vec<u16>>>()?;
        expect_statuses = Some(parsed);
      }
      _ => bail!("unknown webtransport-multiplex flag: {flag}"),
    }
  }

  let sessions = sessions.ok_or_else(|| anyhow!("--sessions is required"))?;
  let expect_statuses = expect_statuses.ok_or_else(|| anyhow!("--expect-statuses is required"))?;
  if expect_statuses.len() != sessions {
    bail!("--expect-statuses count must match --sessions");
  }
  let server_name = server_name.ok_or_else(|| anyhow!("--server-name is required"))?;
  Ok(WebTransportMultiplexArgs {
    host: host.ok_or_else(|| anyhow!("--host is required"))?,
    port: port.ok_or_else(|| anyhow!("--port is required"))?,
    authority: authority.unwrap_or_else(|| server_name.clone()),
    server_name,
    path: path.ok_or_else(|| anyhow!("--path is required"))?,
    headers,
    ca_cert: ca_cert.ok_or_else(|| anyhow!("--ca-cert is required"))?,
    sessions,
    expect_statuses,
  })
}

fn parse_webtransport_reload_gated_args(
  mut args: impl Iterator<Item = String>,
) -> anyhow::Result<WebTransportReloadGatedArgs> {
  let mut host = None;
  let mut port = None;
  let mut server_name = None;
  let mut authority = None;
  let mut path = None;
  let mut http_path = None;
  let mut headers = HeaderMap::new();
  let mut ca_cert = None;
  let mut first_ready_path = None;
  let mut resume_path = None;
  let mut expect_initial_status = None;
  let mut expect_drained_status = None;

  while let Some(flag) = args.next() {
    let value = args
      .next()
      .ok_or_else(|| anyhow!("missing value for {flag}"))?;
    match flag.as_str() {
      "--host" => host = Some(value),
      "--port" => port = Some(value.parse().context("invalid --port value")?),
      "--server-name" => server_name = Some(value),
      "--authority" => authority = Some(value),
      "--path" => path = Some(validate_origin_form_path(&value)?),
      "--http-path" => http_path = Some(validate_origin_form_path(&value)?),
      "--header" => insert_header(&mut headers, &value)?,
      "--ca-cert" => ca_cert = Some(value),
      "--first-ready-path" => first_ready_path = Some(value),
      "--resume-path" => resume_path = Some(value),
      "--expect-initial-status" => {
        expect_initial_status = Some(
          value
            .parse()
            .context("invalid --expect-initial-status value")?,
        );
      }
      "--expect-drained-status" => {
        expect_drained_status = Some(
          value
            .parse()
            .context("invalid --expect-drained-status value")?,
        );
      }
      _ => bail!("unknown webtransport-reload-gated flag: {flag}"),
    }
  }

  let server_name = server_name.ok_or_else(|| anyhow!("--server-name is required"))?;
  Ok(WebTransportReloadGatedArgs {
    host: host.ok_or_else(|| anyhow!("--host is required"))?,
    port: port.ok_or_else(|| anyhow!("--port is required"))?,
    authority: authority.unwrap_or_else(|| server_name.clone()),
    server_name,
    path: path.ok_or_else(|| anyhow!("--path is required"))?,
    http_path: http_path.ok_or_else(|| anyhow!("--http-path is required"))?,
    headers,
    ca_cert: ca_cert.ok_or_else(|| anyhow!("--ca-cert is required"))?,
    first_ready_path: first_ready_path.ok_or_else(|| anyhow!("--first-ready-path is required"))?,
    resume_path: resume_path.ok_or_else(|| anyhow!("--resume-path is required"))?,
    expect_initial_status: expect_initial_status
      .ok_or_else(|| anyhow!("--expect-initial-status is required"))?,
    expect_drained_status: expect_drained_status
      .ok_or_else(|| anyhow!("--expect-drained-status is required"))?,
  })
}

fn parse_admin_operation_wt_events_args(
  mut args: impl Iterator<Item = String>,
) -> anyhow::Result<AdminOperationWtEventsArgs> {
  let mut host = None;
  let mut port = None;
  let mut path = None;
  let mut headers = HeaderMap::new();
  let mut ca_cert = None;
  let mut expect_events = Vec::new();
  let mut expect_terminal_state = None;
  let mut timeout_ms = 10_000;

  while let Some(flag) = args.next() {
    let value = args
      .next()
      .ok_or_else(|| anyhow!("missing value for {flag}"))?;
    match flag.as_str() {
      "--host" => host = Some(value),
      "--port" => port = Some(value.parse().context("invalid --port value")?),
      "--path" => path = Some(validate_origin_form_path(&value)?),
      "--header" => insert_header(&mut headers, &value)?,
      "--ca-cert" => ca_cert = Some(value),
      "--expect-event" => expect_events.push(value),
      "--expect-terminal-state" => expect_terminal_state = Some(value),
      "--timeout-ms" => {
        timeout_ms = value.parse().context("invalid --timeout-ms value")?;
        if timeout_ms == 0 {
          bail!("--timeout-ms must be greater than zero");
        }
      }
      _ => bail!("unknown admin-operation-wt-events flag: {flag}"),
    }
  }

  Ok(AdminOperationWtEventsArgs {
    host: host.ok_or_else(|| anyhow!("--host is required"))?,
    port: port.ok_or_else(|| anyhow!("--port is required"))?,
    path: path.ok_or_else(|| anyhow!("--path is required"))?,
    headers,
    ca_cert: ca_cert.ok_or_else(|| anyhow!("--ca-cert is required"))?,
    expect_events,
    expect_terminal_state,
    timeout_ms,
  })
}

fn parse_downstream_args(mut args: impl Iterator<Item = String>) -> anyhow::Result<DownstreamArgs> {
  let mut protocol = None;
  let mut host = None;
  let mut port = None;
  let mut server_name = None;
  let mut authority = None;
  let mut path = None;
  let mut method = Method::GET;
  let mut body = String::new();
  let mut body_bytes = None;
  let mut body_chunk_size = 16 * 1024;
  let mut zero_length_body_end_delay_ms = None;
  let mut omit_content_length = false;
  let mut headers = HeaderMap::new();
  let mut ca_cert = None;
  let mut expect_status = None;

  while let Some(flag) = args.next() {
    if flag.as_str() == "--omit-content-length" {
      omit_content_length = true;
      continue;
    }
    let value = args
      .next()
      .ok_or_else(|| anyhow!("missing value for {flag}"))?;
    match flag.as_str() {
      "--protocol" => protocol = Some(DownstreamProtocol::parse(&value)?),
      "--host" => host = Some(value),
      "--port" => port = Some(value.parse().context("invalid --port value")?),
      "--server-name" => server_name = Some(value),
      "--authority" => authority = Some(value),
      "--path" => path = Some(validate_origin_form_path(&value)?),
      "--method" => method = value.parse().context("invalid --method value")?,
      "--body" => body = value,
      "--body-bytes" => {
        let bytes = value.parse().context("invalid --body-bytes value")?;
        body_bytes = Some(bytes);
      }
      "--body-chunk-size" => {
        body_chunk_size = value.parse().context("invalid --body-chunk-size value")?;
        if body_chunk_size == 0 {
          bail!("--body-chunk-size must be greater than zero");
        }
      }
      "--zero-length-body-end-delay-ms" => {
        zero_length_body_end_delay_ms = Some(
          value
            .parse()
            .context("invalid --zero-length-body-end-delay-ms value")?,
        );
      }
      "--header" => insert_header(&mut headers, &value)?,
      "--ca-cert" => ca_cert = Some(value),
      "--expect-status" => {
        expect_status = Some(value.parse().context("invalid --expect-status value")?);
      }
      _ => bail!("unknown downstream flag: {flag}"),
    }
  }

  let server_name = server_name.ok_or_else(|| anyhow!("--server-name is required"))?;
  let protocol = protocol.ok_or_else(|| anyhow!("--protocol is required"))?;
  if zero_length_body_end_delay_ms.is_some() {
    if !matches!(protocol, DownstreamProtocol::H2) {
      bail!("--zero-length-body-end-delay-ms is only supported for HTTP/2");
    }
    if body_bytes.is_some() || !body.is_empty() {
      bail!("--zero-length-body-end-delay-ms cannot be combined with request body data");
    }
  }
  Ok(DownstreamArgs {
    protocol,
    host: host.ok_or_else(|| anyhow!("--host is required"))?,
    port: port.ok_or_else(|| anyhow!("--port is required"))?,
    authority: authority.unwrap_or_else(|| server_name.clone()),
    server_name,
    path: path.ok_or_else(|| anyhow!("--path is required"))?,
    method,
    body,
    body_bytes,
    body_chunk_size,
    zero_length_body_end_delay_ms,
    omit_content_length,
    headers,
    ca_cert: ca_cert.ok_or_else(|| anyhow!("--ca-cert is required"))?,
    expect_status,
  })
}

fn parse_dpi_tls_args(mut args: impl Iterator<Item = String>) -> anyhow::Result<DpiTlsArgs> {
  let mut profile = None;
  let mut host = None;
  let mut port = None;
  let mut server_name = None;
  let mut authority = None;
  let mut path = None;
  let mut ca_cert = None;
  let mut expect_status = None;

  while let Some(flag) = args.next() {
    let value = args
      .next()
      .ok_or_else(|| anyhow!("missing value for {flag}"))?;
    match flag.as_str() {
      "--profile" => profile = Some(DpiTlsProfile::parse(&value)?),
      "--host" => host = Some(value),
      "--port" => port = Some(value.parse().context("invalid --port value")?),
      "--server-name" => server_name = Some(value),
      "--authority" => authority = Some(value),
      "--path" => path = Some(validate_origin_form_path(&value)?),
      "--ca-cert" => ca_cert = Some(value),
      "--expect-status" => {
        expect_status = Some(value.parse().context("invalid --expect-status value")?);
      }
      _ => bail!("unknown dpi-tls-client flag: {flag}"),
    }
  }

  let server_name = server_name.ok_or_else(|| anyhow!("--server-name is required"))?;
  Ok(DpiTlsArgs {
    profile: profile.ok_or_else(|| anyhow!("--profile is required"))?,
    host: host.ok_or_else(|| anyhow!("--host is required"))?,
    port: port.ok_or_else(|| anyhow!("--port is required"))?,
    authority: authority.unwrap_or_else(|| server_name.clone()),
    server_name,
    path: path.ok_or_else(|| anyhow!("--path is required"))?,
    ca_cert: ca_cert.ok_or_else(|| anyhow!("--ca-cert is required"))?,
    expect_status,
  })
}

fn parse_tls_resumption_load_args(
  mut args: impl Iterator<Item = String>,
) -> anyhow::Result<TlsResumptionLoadArgs> {
  let mut host = None;
  let mut port = None;
  let mut server_name = None;
  let mut authority = None;
  let mut path = None;
  let mut ca_cert = None;
  let mut connections = None;
  let mut expect_resumed_min = None;

  while let Some(flag) = args.next() {
    let value = args
      .next()
      .ok_or_else(|| anyhow!("missing value for {flag}"))?;
    match flag.as_str() {
      "--host" => host = Some(value),
      "--port" => port = Some(value.parse().context("invalid --port value")?),
      "--server-name" => server_name = Some(value),
      "--authority" => authority = Some(value),
      "--path" => path = Some(validate_origin_form_path(&value)?),
      "--ca-cert" => ca_cert = Some(value),
      "--connections" => {
        let parsed = value.parse().context("invalid --connections value")?;
        if parsed == 0 {
          bail!("--connections must be greater than zero");
        }
        connections = Some(parsed);
      }
      "--expect-resumed-min" => {
        expect_resumed_min = Some(
          value
            .parse()
            .context("invalid --expect-resumed-min value")?,
        );
      }
      _ => bail!("unknown tls-resumption-load flag: {flag}"),
    }
  }

  let server_name = server_name.ok_or_else(|| anyhow!("--server-name is required"))?;
  Ok(TlsResumptionLoadArgs {
    host: host.ok_or_else(|| anyhow!("--host is required"))?,
    port: port.ok_or_else(|| anyhow!("--port is required"))?,
    authority: authority.unwrap_or_else(|| server_name.clone()),
    server_name,
    path: path.ok_or_else(|| anyhow!("--path is required"))?,
    ca_cert: ca_cert.ok_or_else(|| anyhow!("--ca-cert is required"))?,
    connections: connections.ok_or_else(|| anyhow!("--connections is required"))?,
    expect_resumed_min: expect_resumed_min
      .ok_or_else(|| anyhow!("--expect-resumed-min is required"))?,
  })
}

fn insert_header(headers: &mut HeaderMap, raw: &str) -> anyhow::Result<()> {
  let (name, value) = raw
    .split_once(':')
    .ok_or_else(|| anyhow!("invalid --header value; expected name:value"))?;
  headers.insert(
    HeaderName::try_from(name.trim()).context("invalid --header name")?,
    HeaderValue::from_str(value.trim()).context("invalid --header value")?,
  );
  Ok(())
}

fn validate_origin_form_path(raw_path: &str) -> anyhow::Result<String> {
  if !raw_path.starts_with('/') {
    bail!("request path must start with '/'");
  }
  if raw_path.chars().any(|ch| matches!(ch, '\r' | '\n' | '\0')) {
    bail!("request path must not contain control characters");
  }
  Ok(raw_path.to_string())
}

async fn serve_h2_upstream(args: H2UpstreamArgs) -> anyhow::Result<()> {
  let mut server_config =
    ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
      .with_safe_default_protocol_versions()
      .context("failed to configure upstream TLS versions")?
      .with_no_client_auth()
      .with_single_cert(
        load_certs(Path::new(&args.cert))?,
        load_private_key(Path::new(&args.key))?,
      )
      .context("failed to configure upstream TLS certificate")?;
  server_config.alpn_protocols = vec![b"h2".to_vec()];

  let listener = TcpListener::bind(args.listen)
    .await
    .with_context(|| format!("failed to bind h2 upstream to {}", args.listen))?;
  let acceptor = TlsAcceptor::from(Arc::new(server_config));
  let upstream_name = Arc::<str>::from(args.name);
  let scheme = Arc::<str>::from("https");

  loop {
    let (stream, peer_addr) = listener.accept().await.context("failed to accept TCP")?;
    let acceptor = acceptor.clone();
    let upstream_name = upstream_name.clone();
    let scheme = scheme.clone();
    tokio::spawn(async move {
      if let Err(error) =
        handle_h2_upstream_connection(stream, acceptor, upstream_name, scheme).await
      {
        eprintln!("h2 upstream connection from {peer_addr} failed: {error:#}");
      }
    });
  }
}

async fn handle_h2_upstream_connection(
  stream: TcpStream,
  acceptor: TlsAcceptor,
  upstream_name: Arc<str>,
  scheme: Arc<str>,
) -> anyhow::Result<()> {
  let tls_stream = acceptor
    .accept(stream)
    .await
    .context("failed to accept upstream TLS")?;
  let negotiated = tls_stream
    .get_ref()
    .1
    .alpn_protocol()
    .map(|protocol| protocol.to_vec())
    .unwrap_or_default();
  if negotiated != b"h2" {
    bail!(
      "expected upstream ALPN h2, got {}",
      String::from_utf8_lossy(&negotiated)
    );
  }

  let service = service_fn(move |request| {
    let upstream_name = upstream_name.clone();
    let scheme = scheme.clone();
    async move { Ok::<_, Infallible>(echo_upstream_request(request, upstream_name, scheme).await) }
  });

  hyper::server::conn::http2::Builder::new(TokioExecutor::new())
    .serve_connection(TokioIo::new(tls_stream), service)
    .await
    .context("failed to serve upstream HTTP/2 connection")?;
  Ok(())
}

async fn serve_h2c_upstream(args: H2cUpstreamArgs) -> anyhow::Result<()> {
  let listener = TcpListener::bind(args.listen)
    .await
    .with_context(|| format!("failed to bind h2c upstream to {}", args.listen))?;
  let upstream_name = Arc::<str>::from(args.name);
  let scheme = Arc::<str>::from("http");

  loop {
    let (stream, peer_addr) = listener.accept().await.context("failed to accept TCP")?;
    let upstream_name = upstream_name.clone();
    let scheme = scheme.clone();
    tokio::spawn(async move {
      if let Err(error) = handle_h2c_upstream_connection(stream, upstream_name, scheme).await {
        eprintln!("h2c upstream connection from {peer_addr} failed: {error:#}");
      }
    });
  }
}

async fn handle_h2c_upstream_connection(
  stream: TcpStream,
  upstream_name: Arc<str>,
  scheme: Arc<str>,
) -> anyhow::Result<()> {
  let service = service_fn(move |request| {
    let upstream_name = upstream_name.clone();
    let scheme = scheme.clone();
    async move { Ok::<_, Infallible>(echo_upstream_request(request, upstream_name, scheme).await) }
  });

  hyper::server::conn::http2::Builder::new(TokioExecutor::new())
    .serve_connection(TokioIo::new(stream), service)
    .await
    .context("failed to serve upstream cleartext HTTP/2 connection")?;
  Ok(())
}

async fn serve_h1_stall_upstream(args: H1StallUpstreamArgs) -> anyhow::Result<()> {
  let listener = TcpListener::bind(args.listen)
    .await
    .with_context(|| format!("failed to bind h1 stall upstream to {}", args.listen))?;
  let upstream_name = Arc::<str>::from(args.name);
  let read_delay = Duration::from_millis(args.read_delay_ms);

  loop {
    let (stream, peer_addr) = listener.accept().await.context("failed to accept TCP")?;
    let upstream_name = upstream_name.clone();
    tokio::spawn(async move {
      if let Err(error) =
        handle_h1_stall_upstream_connection(stream, upstream_name, read_delay).await
      {
        eprintln!("h1 stall upstream connection from {peer_addr} failed: {error:#}");
      }
    });
  }
}

async fn handle_h1_stall_upstream_connection(
  mut stream: TcpStream,
  upstream_name: Arc<str>,
  read_delay: Duration,
) -> anyhow::Result<()> {
  let request_head = read_http1_request_head(&mut stream).await?;
  tokio::time::sleep(read_delay).await;

  let (body_bytes, clean_chunk_end) = read_chunked_body_observation(&mut stream).await?;
  let status = if clean_chunk_end {
    StatusCode::OK
  } else {
    StatusCode::BAD_REQUEST
  };
  let payload = serde_json::json!({
    "upstream": upstream_name.as_ref(),
    "request_head": request_head,
    "body_bytes": body_bytes,
    "clean_chunk_end": clean_chunk_end,
  });
  write_http1_json_response(
    &mut stream,
    status,
    payload.to_string(),
    Some(upstream_name.as_ref()),
  )
  .await
}

async fn read_http1_request_head(stream: &mut TcpStream) -> anyhow::Result<String> {
  read_http1_head_from_io(stream).await
}

async fn read_http1_head_from_io<S>(stream: &mut S) -> anyhow::Result<String>
where
  S: tokio::io::AsyncRead + Unpin,
{
  let mut head = Vec::new();
  let mut byte = [0u8; 1];
  while head.len() < 64 * 1024 {
    let read = stream
      .read(&mut byte)
      .await
      .context("failed to read request head")?;
    if read == 0 {
      bail!("connection closed before HTTP/1 request head completed");
    }
    head.push(byte[0]);
    if head.ends_with(b"\r\n\r\n") {
      return Ok(String::from_utf8_lossy(&head).into_owned());
    }
  }
  bail!("HTTP/1 request head exceeded 64KiB")
}

fn parse_http1_headers(head: &str) -> BTreeMap<String, String> {
  head
    .lines()
    .skip(1)
    .filter_map(|line| {
      let (name, value) = line.split_once(':')?;
      Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
    })
    .collect()
}

fn parse_http_status(head: &str) -> anyhow::Result<u16> {
  let status = head
    .lines()
    .next()
    .and_then(|line| line.split_whitespace().nth(1))
    .ok_or_else(|| anyhow!("HTTP response is missing status line"))?;
  status.parse().context("invalid HTTP response status")
}

fn websocket_accept_key(key: &str) -> String {
  let mut context = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
  context.update(key.as_bytes());
  context.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
  base64::engine::general_purpose::STANDARD.encode(context.finish().as_ref())
}

struct WebSocketFrame {
  opcode: u8,
  payload: Vec<u8>,
}

async fn read_websocket_frame<S>(stream: &mut S) -> anyhow::Result<Option<WebSocketFrame>>
where
  S: tokio::io::AsyncRead + Unpin,
{
  let mut header = [0u8; 2];
  if stream.read_exact(&mut header).await.is_err() {
    return Ok(None);
  }
  let opcode = header[0] & 0x0f;
  let masked = header[1] & 0x80 != 0;
  let mut len = u64::from(header[1] & 0x7f);
  if len == 126 {
    let mut extended = [0u8; 2];
    stream
      .read_exact(&mut extended)
      .await
      .context("failed to read WebSocket 16-bit length")?;
    len = u64::from(u16::from_be_bytes(extended));
  } else if len == 127 {
    let mut extended = [0u8; 8];
    stream
      .read_exact(&mut extended)
      .await
      .context("failed to read WebSocket 64-bit length")?;
    len = u64::from_be_bytes(extended);
  }
  if len > 1024 * 1024 {
    bail!("WebSocket frame too large for probe: {len}");
  }
  let mut mask = [0u8; 4];
  if masked {
    stream
      .read_exact(&mut mask)
      .await
      .context("failed to read WebSocket mask")?;
  }
  let mut payload = vec![0u8; len as usize];
  stream
    .read_exact(&mut payload)
    .await
    .context("failed to read WebSocket payload")?;
  if masked {
    for (index, byte) in payload.iter_mut().enumerate() {
      *byte ^= mask[index % mask.len()];
    }
  }
  Ok(Some(WebSocketFrame { opcode, payload }))
}

async fn write_websocket_frame<S>(
  stream: &mut S,
  opcode: u8,
  payload: &[u8],
  masked: bool,
) -> anyhow::Result<()>
where
  S: tokio::io::AsyncWrite + Unpin,
{
  let mut frame = Vec::with_capacity(payload.len() + 16);
  frame.push(0x80 | (opcode & 0x0f));
  let mask_bit = if masked { 0x80 } else { 0 };
  if payload.len() < 126 {
    frame.push(mask_bit | payload.len() as u8);
  } else if payload.len() <= u16::MAX as usize {
    frame.push(mask_bit | 126);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
  } else {
    frame.push(mask_bit | 127);
    frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
  }
  if masked {
    let mask = [0x10, 0x20, 0x30, 0x40];
    frame.extend_from_slice(&mask);
    frame.extend(
      payload
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ mask[index % mask.len()]),
    );
  } else {
    frame.extend_from_slice(payload);
  }
  stream
    .write_all(&frame)
    .await
    .context("failed to write WebSocket frame")
}

async fn read_chunked_body_observation(stream: &mut TcpStream) -> anyhow::Result<(usize, bool)> {
  let started = tokio::time::Instant::now();
  let mut body_bytes = 0usize;
  let mut tail = Vec::new();

  loop {
    if started.elapsed() > Duration::from_secs(10) {
      return Ok((body_bytes, false));
    }

    let mut chunk = [0u8; 8192];
    let read = match tokio::time::timeout(Duration::from_millis(250), stream.read(&mut chunk)).await
    {
      Ok(Ok(read)) => read,
      Ok(Err(error)) => return Err(error).context("failed to read request body"),
      Err(_) => continue,
    };
    if read == 0 {
      return Ok((body_bytes, false));
    }

    body_bytes += read;
    tail.extend_from_slice(&chunk[..read]);
    if tail.len() > 64 {
      tail.drain(..tail.len() - 64);
    }
    if tail
      .windows(b"\r\n0\r\n\r\n".len())
      .any(|window| window == b"\r\n0\r\n\r\n")
      || tail
        .windows(b"0\r\n\r\n".len())
        .any(|window| window == b"0\r\n\r\n")
    {
      return Ok((body_bytes, true));
    }
  }
}

async fn write_http1_json_response(
  stream: &mut TcpStream,
  status: StatusCode,
  body: String,
  upstream_marker: Option<&str>,
) -> anyhow::Result<()> {
  let reason = status.canonical_reason().unwrap_or("Unknown");
  let marker = upstream_marker
    .map(|value| format!("x-upstream-marker: {value}\r\n"))
    .unwrap_or_default();
  let response = format!(
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{}connection: close\r\n\r\n{}",
        status.as_u16(),
        reason,
        body.len(),
        marker,
        body,
    );
  stream
    .write_all(response.as_bytes())
    .await
    .context("failed to write HTTP/1 response")
}

async fn serve_h3_upstream(args: H3UpstreamArgs) -> anyhow::Result<()> {
  let mut server_config =
    ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
      .with_protocol_versions(&[&rustls::version::TLS13])
      .context("failed to configure upstream QUIC TLS versions")?
      .with_no_client_auth()
      .with_single_cert(
        load_certs(Path::new(&args.cert))?,
        load_private_key(Path::new(&args.key))?,
      )
      .context("failed to configure upstream QUIC certificate")?;
  server_config.alpn_protocols = vec![b"h3".to_vec()];
  let quic_crypto =
    QuicServerConfig::try_from(server_config).context("failed to build QUIC server config")?;
  let mut quic_server_config = QuinnServerConfig::with_crypto(Arc::new(quic_crypto));
  let mut transport = h3_quinn::quinn::TransportConfig::default();
  transport.datagram_receive_buffer_size(Some(1024 * 1024));
  transport.datagram_send_buffer_size(1024 * 1024);
  quic_server_config.transport_config(Arc::new(transport));
  let endpoint = Endpoint::server(quic_server_config, args.listen)
    .with_context(|| format!("failed to bind h3 upstream to {}", args.listen))?;
  let upstream_name = Arc::<str>::from(args.name);
  let scheme = Arc::<str>::from("https");
  let instance_id = Arc::<str>::from(
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .context("system clock is before Unix epoch")?
      .as_nanos()
      .to_string(),
  );
  let next_connection_id = Arc::new(AtomicU64::new(1));

  loop {
    let Some(incoming) = endpoint.accept().await else {
      return Ok(());
    };
    let upstream_name = upstream_name.clone();
    let scheme = scheme.clone();
    let instance_id = instance_id.clone();
    let next_connection_id = next_connection_id.clone();
    tokio::spawn(async move {
      match incoming.await {
        Ok(connection) => {
          let connection_id = next_connection_id.fetch_add(1, Ordering::Relaxed);
          if let Err(error) = handle_h3_upstream_connection(
            connection,
            upstream_name,
            scheme,
            instance_id,
            connection_id,
          )
          .await
          {
            eprintln!("h3 upstream connection {connection_id} failed: {error:#}");
          }
        }
        Err(error) => eprintln!("h3 upstream accept failed: {error:#}"),
      }
    });
  }
}

async fn serve_webtransport_upstream(args: WebTransportUpstreamArgs) -> anyhow::Result<()> {
  let mut server = web_transport_quinn::ServerBuilder::new()
    .with_addr(args.listen)
    .with_certificate(
      load_certs(Path::new(&args.cert))?,
      load_private_key(Path::new(&args.key))?,
    )
    .context("failed to build WebTransport upstream server")?;
  let upstream_name = Arc::<str>::from(args.name);

  while let Some(request) = server.accept().await {
    let upstream_name = upstream_name.clone();
    tokio::spawn(async move {
      if let Err(error) = handle_webtransport_upstream_request(request, upstream_name).await {
        eprintln!("WebTransport upstream session failed: {error:#}");
      }
    });
  }

  Ok(())
}

async fn handle_webtransport_upstream_request(
  request: web_transport_quinn::Request,
  upstream_name: Arc<str>,
) -> anyhow::Result<()> {
  let session = request
    .ok()
    .await
    .with_context(|| format!("failed to accept {upstream_name} WebTransport session"))?;
  loop {
    tokio::select! {
        result = session.accept_bi() => {
            let (mut send, mut recv) = result.context("failed to accept WebTransport bidi stream")?;
            let bytes = recv.read_to_end(64 * 1024).await.context("failed to read WebTransport bidi stream")?;
            send.write_all(&bytes).await.context("failed to echo WebTransport bidi stream")?;
            send.finish().context("failed to finish WebTransport bidi stream")?;
        }
        result = session.read_datagram() => {
            let bytes = result.context("failed to read WebTransport datagram")?;
            session.send_datagram(bytes).context("failed to echo WebTransport datagram")?;
        }
        _ = session.closed() => {
            return Ok(());
        }
    }
  }
}

async fn serve_websocket_echo_upstream(args: WebSocketEchoArgs) -> anyhow::Result<()> {
  let listener = TcpListener::bind(args.listen)
    .await
    .with_context(|| format!("failed to bind WebSocket echo upstream to {}", args.listen))?;
  loop {
    let (stream, peer_addr) = listener.accept().await.context("failed to accept TCP")?;
    tokio::spawn(async move {
      if let Err(error) = handle_websocket_echo_connection(stream).await {
        eprintln!("WebSocket echo connection from {peer_addr} failed: {error:#}");
      }
    });
  }
}

async fn handle_websocket_echo_connection(mut stream: TcpStream) -> anyhow::Result<()> {
  let head = read_http1_request_head(&mut stream).await?;
  let headers = parse_http1_headers(&head);
  let key = headers
    .get("sec-websocket-key")
    .ok_or_else(|| anyhow!("WebSocket request missing Sec-WebSocket-Key"))?;
  let accept = websocket_accept_key(key);
  let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nconnection: Upgrade\r\nupgrade: websocket\r\nsec-websocket-accept: {accept}\r\n\r\n"
    );
  stream
    .write_all(response.as_bytes())
    .await
    .context("failed to write WebSocket handshake response")?;

  while let Some(frame) = read_websocket_frame(&mut stream).await? {
    if frame.opcode == 0x8 {
      write_websocket_frame(&mut stream, 0x8, &frame.payload, false).await?;
      return Ok(());
    }
    write_websocket_frame(&mut stream, frame.opcode, &frame.payload, false).await?;
  }
  Ok(())
}

async fn run_websocket_client(args: WebSocketClientArgs) -> anyhow::Result<()> {
  let mut client_config = downstream_client_config(Path::new(&args.ca_cert), b"http/1.1")?;
  client_config.enable_sni = true;
  let connector = TlsConnector::from(Arc::new(client_config));
  let stream = TcpStream::connect((args.host.as_str(), args.port))
    .await
    .with_context(|| format!("failed to connect to {}:{}", args.host, args.port))?;
  let server_name = ServerName::try_from(args.server_name.clone())
    .map_err(|_| anyhow!("invalid server name: {}", args.server_name))?;
  let mut stream = connector
    .connect(server_name, stream)
    .await
    .context("failed to establish WebSocket downstream TLS")?;
  let key = base64::engine::general_purpose::STANDARD.encode(b"oxibelt-probe-key");
  let request = format!(
        "GET {} HTTP/1.1\r\nhost: {}\r\nconnection: Upgrade\r\nupgrade: websocket\r\nsec-websocket-key: {}\r\nsec-websocket-version: 13\r\n\r\n",
        args.path, args.authority, key
    );
  stream
    .write_all(request.as_bytes())
    .await
    .context("failed to write WebSocket handshake request")?;
  let response_head = read_http1_head_from_io(&mut stream)
    .await
    .context("failed to read WebSocket handshake response")?;
  let status = parse_http_status(&response_head)?;
  if status != args.expect_status {
    bail!(
      "expected WebSocket status {}, got {} with response {response_head:?}",
      args.expect_status,
      status
    );
  }
  if status != 101 {
    println!(
      "{}",
      serde_json::to_string(&serde_json::json!({
        "status": status,
        "upgraded": false,
      }))?
    );
    return Ok(());
  }

  write_websocket_frame(&mut stream, 0x2, &args.payload, true)
    .await
    .context("failed to write WebSocket payload")?;
  let echoed = read_websocket_frame(&mut stream)
    .await?
    .ok_or_else(|| anyhow!("WebSocket closed before echo frame"))?;
  if echoed.opcode != 0x2 || echoed.payload != args.payload {
    bail!("unexpected WebSocket echo frame");
  }
  write_websocket_frame(&mut stream, 0x8, &[], true)
    .await
    .context("failed to write WebSocket close")?;
  let _ = read_websocket_frame(&mut stream).await?;
  println!(
    "{}",
    serde_json::to_string(&serde_json::json!({
      "status": status,
      "upgraded": true,
      "echoed_bytes": args.payload.len(),
    }))?
  );
  Ok(())
}

async fn serve_turn_upstream(args: TurnUpstreamArgs) -> anyhow::Result<()> {
  match args.transport {
    TurnTransport::Udp => serve_turn_udp_upstream(args.listen).await,
    TurnTransport::Tcp => serve_turn_tcp_upstream(args.listen).await,
    TurnTransport::Tls => {
      let cert = args.cert.ok_or_else(|| anyhow!("--cert is required"))?;
      let key = args.key.ok_or_else(|| anyhow!("--key is required"))?;
      serve_turn_tls_upstream(args.listen, cert, key).await
    }
  }
}

async fn serve_turn_udp_upstream(listen: SocketAddr) -> anyhow::Result<()> {
  let socket = tokio::net::UdpSocket::bind(listen)
    .await
    .with_context(|| format!("failed to bind TURN UDP upstream to {listen}"))?;
  let mut buffer = vec![0u8; 65_536];
  loop {
    let (len, peer) = socket
      .recv_from(&mut buffer)
      .await
      .context("failed to receive TURN UDP datagram")?;
    socket
      .send_to(&buffer[..len], peer)
      .await
      .context("failed to echo TURN UDP datagram")?;
  }
}

async fn serve_turn_tcp_upstream(listen: SocketAddr) -> anyhow::Result<()> {
  let listener = TcpListener::bind(listen)
    .await
    .with_context(|| format!("failed to bind TURN TCP upstream to {listen}"))?;
  loop {
    let (stream, peer_addr) = listener.accept().await.context("failed to accept TCP")?;
    tokio::spawn(async move {
      if let Err(error) = handle_turn_stream_echo(stream).await {
        eprintln!("TURN TCP upstream connection from {peer_addr} failed: {error:#}");
      }
    });
  }
}

async fn serve_turn_tls_upstream(
  listen: SocketAddr,
  cert: String,
  key: String,
) -> anyhow::Result<()> {
  let server_config =
    ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
      .with_safe_default_protocol_versions()
      .context("failed to configure TURN TLS upstream versions")?
      .with_no_client_auth()
      .with_single_cert(
        load_certs(Path::new(&cert))?,
        load_private_key(Path::new(&key))?,
      )
      .context("failed to configure TURN TLS upstream certificate")?;
  let acceptor = TlsAcceptor::from(Arc::new(server_config));
  let listener = TcpListener::bind(listen)
    .await
    .with_context(|| format!("failed to bind TURN TLS upstream to {listen}"))?;
  loop {
    let (stream, peer_addr) = listener.accept().await.context("failed to accept TCP")?;
    let acceptor = acceptor.clone();
    tokio::spawn(async move {
      let result = async {
        let stream = acceptor
          .accept(stream)
          .await
          .context("failed to accept TURN TLS upstream connection")?;
        handle_turn_stream_echo(stream).await
      }
      .await;
      if let Err(error) = result {
        eprintln!("TURN TLS upstream connection from {peer_addr} failed: {error:#}");
      }
    });
  }
}

async fn handle_turn_stream_echo<S>(mut stream: S) -> anyhow::Result<()>
where
  S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
  loop {
    let frame = match read_turn_frame(&mut stream).await {
      Ok(frame) => frame,
      Err(_) => return Ok(()),
    };
    stream
      .write_all(&frame)
      .await
      .context("failed to echo TURN stream frame")?;
    stream
      .flush()
      .await
      .context("failed to flush TURN stream")?;
  }
}

async fn run_turn_client(args: TurnClientArgs) -> anyhow::Result<()> {
  let request = turn_request(&args);
  let response = match args.transport {
    TurnTransport::Udp => turn_udp_round_trip(&args, &request).await?,
    TurnTransport::Tcp => turn_tcp_round_trip(&args, &request).await?,
    TurnTransport::Tls => turn_tls_round_trip(&args, &request).await?,
  };
  match args.expect {
    TurnClientExpect::Echo => {
      let response = response.ok_or_else(|| anyhow!("expected TURN echo response"))?;
      if response != request {
        bail!(
          "TURN {} response did not echo request",
          args.transport.label()
        );
      }
    }
    TurnClientExpect::NoResponse => {
      if response.is_some() {
        bail!(
          "TURN {} unexpectedly returned a response",
          args.transport.label()
        );
      }
    }
  }
  println!(
    "{}",
    serde_json::to_string(&serde_json::json!({
      "transport": args.transport.label(),
      "expect": match args.expect {
        TurnClientExpect::Echo => "echo",
        TurnClientExpect::NoResponse => "no-response",
      },
    }))?
  );
  Ok(())
}

async fn handle_h3_upstream_connection(
  connection: h3_quinn::quinn::Connection,
  upstream_name: Arc<str>,
  scheme: Arc<str>,
  instance_id: Arc<str>,
  connection_id: u64,
) -> anyhow::Result<()> {
  let quic_connection = h3_quinn::Connection::new(connection);
  let mut h3_connection = h3::server::builder()
    .build(quic_connection)
    .await
    .context("failed to establish upstream HTTP/3 connection")?;

  loop {
    let Some(resolver) = h3_connection
      .accept()
      .await
      .context("failed to accept upstream HTTP/3 request")?
    else {
      return Ok(());
    };
    let (request, mut stream) = resolver
      .resolve_request()
      .await
      .context("failed to resolve upstream HTTP/3 request")?;
    let response = echo_h3_upstream_request(
      request,
      &mut stream,
      upstream_name.clone(),
      scheme.clone(),
      instance_id.clone(),
      connection_id,
    )
    .await;
    let (parts, body) = response.into_parts();
    let body = body
      .collect()
      .await
      .expect("Full body is infallible")
      .to_bytes();
    stream
      .send_response(Response::from_parts(parts, ()))
      .await
      .context("failed to send upstream HTTP/3 response headers")?;
    if !body.is_empty() {
      stream
        .send_data(body)
        .await
        .context("failed to send upstream HTTP/3 response body")?;
    }
    stream
      .finish()
      .await
      .context("failed to finish upstream HTTP/3 response")?;
  }
}

async fn echo_h3_upstream_request(
  request: Request<()>,
  stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
  upstream_name: Arc<str>,
  scheme: Arc<str>,
  instance_id: Arc<str>,
  connection_id: u64,
) -> Response<Full<Bytes>> {
  let (parts, _) = request.into_parts();
  let status = status_from_path(parts.uri.path()).unwrap_or(StatusCode::OK);
  let mut body_bytes = BytesMut::new();
  loop {
    match stream.recv_data().await {
      Ok(Some(mut chunk)) => {
        let len = chunk.remaining();
        body_bytes.extend_from_slice(&chunk.copy_to_bytes(len));
      }
      Ok(None) => break,
      Err(error) => {
        return text_response(
          StatusCode::BAD_REQUEST,
          &format!("failed to read upstream HTTP/3 request body: {error}"),
        );
      }
    }
  }
  let body_text = String::from_utf8_lossy(&body_bytes);
  let path = parts
    .uri
    .path_and_query()
    .map(|value| value.as_str())
    .unwrap_or("/");
  let payload = serde_json::json!({
    "upstream": upstream_name.as_ref(),
    "scheme": scheme.as_ref(),
    "method": parts.method.as_str(),
    "path": path,
    "request_version": version_label(Version::HTTP_3),
    "headers": header_json(&parts.headers),
    "body": body_text,
    "instance_id": instance_id.as_ref(),
    "connection_id": connection_id,
  });
  json_response(status, payload.to_string(), Some(upstream_name.as_ref()))
}

async fn echo_upstream_request(
  request: Request<Incoming>,
  upstream_name: Arc<str>,
  scheme: Arc<str>,
) -> Response<Full<Bytes>> {
  let (parts, body) = request.into_parts();
  if parts.uri.path() == "/grpc.health.v1.Health/Check" {
    return grpc_health_response();
  }
  let status = status_from_path(parts.uri.path()).unwrap_or(StatusCode::OK);
  if let Some(delay_ms) = query_u64(&parts.uri, "request_body_delay_ms") {
    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
  }
  let body_bytes = match body.collect().await {
    Ok(collected) => collected.to_bytes(),
    Err(error) => {
      return text_response(
        StatusCode::BAD_REQUEST,
        &format!("failed to read upstream request body: {error}"),
      );
    }
  };
  let body_text = String::from_utf8_lossy(&body_bytes);
  let path = parts
    .uri
    .path_and_query()
    .map(|value| value.as_str())
    .unwrap_or("/");
  let payload = serde_json::json!({
    "upstream": upstream_name.as_ref(),
    "scheme": scheme.as_ref(),
    "method": parts.method.as_str(),
    "path": path,
    "request_version": version_label(parts.version),
    "headers": header_json(&parts.headers),
    "body": body_text,
  });
  json_response(status, payload.to_string(), Some(upstream_name.as_ref()))
}

fn query_u64(uri: &Uri, key: &str) -> Option<u64> {
  uri.query()?.split('&').find_map(|part| {
    let (name, value) = part.split_once('=').unwrap_or((part, ""));
    if name == key {
      value.parse().ok()
    } else {
      None
    }
  })
}

fn grpc_health_response() -> Response<Full<Bytes>> {
  let mut response = Response::new(Full::new(Bytes::from_static(&[0, 0, 0, 0, 2, 0x08, 1])));
  *response.status_mut() = StatusCode::OK;
  response
    .headers_mut()
    .insert(CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
  response.headers_mut().insert(
    HeaderName::from_static("grpc-status"),
    HeaderValue::from_static("0"),
  );
  response
}

fn status_from_path(path: &str) -> Option<StatusCode> {
  let raw_status = path.strip_prefix("/status/")?.split('/').next()?;
  raw_status.parse::<u16>().ok().and_then(|status| {
    StatusCode::from_u16(status)
      .ok()
      .filter(|status| status.as_u16() >= 100)
  })
}

async fn run_downstream_client(args: DownstreamArgs) -> anyhow::Result<()> {
  let output = match args.protocol {
    DownstreamProtocol::H2 => h2_downstream_request(&args).await?,
    DownstreamProtocol::H3 => h3_downstream_request(&args).await?,
  };

  if let Some(expected) = args.expect_status {
    let status = output["status"]
      .as_u64()
      .ok_or_else(|| anyhow!("probe output did not contain numeric status"))?;
    if status != u64::from(expected) {
      eprintln!("{}", serde_json::to_string(&output)?);
      bail!("expected downstream status {expected}, got {status}");
    }
  }

  println!("{}", serde_json::to_string(&output)?);
  Ok(())
}

async fn run_dpi_tls_client(args: DpiTlsArgs) -> anyhow::Result<()> {
  let expected = args.expect_status;
  let output = tokio::task::spawn_blocking(move || dpi_tls_http1_request(args))
    .await
    .context("DPI TLS probe task failed")??;

  if let Some(expected) = expected {
    let status = output["status"]
      .as_u64()
      .ok_or_else(|| anyhow!("probe output did not contain numeric status"))?;
    if status != u64::from(expected) {
      eprintln!("{}", serde_json::to_string(&output)?);
      bail!("expected DPI TLS probe status {expected}, got {status}");
    }
  }

  println!("{}", serde_json::to_string(&output)?);
  Ok(())
}

fn dpi_tls_http1_request(args: DpiTlsArgs) -> anyhow::Result<serde_json::Value> {
  let config = downstream_client_config(Path::new(&args.ca_cert), b"http/1.1")?;
  let server_name = ServerName::try_from(args.server_name.clone())
    .map_err(|_| anyhow!("invalid server name: {}", args.server_name))?;
  let mut conn = ClientConnection::new(Arc::new(config), server_name)
    .context("failed to initialize rustls client connection")?;
  let mut client_hello = Vec::new();
  while conn.wants_write() {
    let written = conn
      .write_tls(&mut client_hello)
      .context("failed to collect ClientHello bytes")?;
    if written == 0 {
      break;
    }
  }
  if client_hello.is_empty() {
    bail!("rustls did not produce an initial ClientHello");
  }

  let plan = dpi_tls_write_plan(args.profile, &client_hello)?;
  let mut stream = StdTcpStream::connect((args.host.as_str(), args.port))
    .with_context(|| format!("failed to connect to {}:{}", args.host, args.port))?;
  stream
    .set_read_timeout(Some(Duration::from_secs(10)))
    .context("failed to set DPI TLS probe read timeout")?;
  stream
    .set_write_timeout(Some(Duration::from_secs(10)))
    .context("failed to set DPI TLS probe write timeout")?;

  for (index, chunk) in plan.chunks.iter().enumerate() {
    stream
      .write_all(chunk)
      .context("failed to write fragmented ClientHello chunk")?;
    stream
      .flush()
      .context("failed to flush fragmented ClientHello chunk")?;
    if index + 1 < plan.chunks.len() {
      std::thread::sleep(Duration::from_millis(25));
    }
  }

  complete_rustls_handshake(&mut conn, &mut stream)?;
  let request = format!(
    "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
    args.path, args.authority
  );
  conn
    .writer()
    .write_all(request.as_bytes())
    .context("failed to write DPI TLS HTTP request")?;
  flush_rustls(&mut conn, &mut stream)?;

  let (status, headers, body) = read_http1_response_from_rustls(&mut conn, &mut stream)?;
  Ok(serde_json::json!({
      "negotiated_protocol": "http/1.1",
      "profile": args.profile.label(),
      "status": status,
      "headers": headers,
      "body": String::from_utf8_lossy(&body),
      "client_hello_bytes": client_hello.len(),
      "tcp_chunks": plan.tcp_chunk_count,
      "tls_records": plan.tls_record_count,
      "sni_offset": plan.sni_offset,
  }))
}

fn flush_rustls(conn: &mut ClientConnection, stream: &mut StdTcpStream) -> anyhow::Result<()> {
  while conn.wants_write() {
    let written = conn
      .write_tls(stream)
      .context("failed to write pending TLS bytes")?;
    if written == 0 {
      break;
    }
  }
  stream.flush().context("failed to flush TLS stream")?;
  Ok(())
}

fn complete_rustls_handshake(
  conn: &mut ClientConnection,
  stream: &mut StdTcpStream,
) -> anyhow::Result<()> {
  while conn.is_handshaking() {
    flush_rustls(conn, stream)?;
    let read = conn
      .read_tls(stream)
      .context("failed to read TLS handshake bytes")?;
    if read == 0 {
      bail!("peer closed before TLS handshake completed");
    }
    conn
      .process_new_packets()
      .context("failed to process TLS handshake bytes")?;
  }
  flush_rustls(conn, stream)?;
  Ok(())
}

fn read_http1_response_from_rustls(
  conn: &mut ClientConnection,
  stream: &mut StdTcpStream,
) -> anyhow::Result<(u16, BTreeMap<String, String>, Vec<u8>)> {
  let mut response = Vec::new();
  loop {
    drain_rustls_plaintext(conn, &mut response)?;
    if http1_response_complete(&response)? {
      break;
    }

    flush_rustls(conn, stream)?;
    let read = conn
      .read_tls(stream)
      .context("failed to read TLS response bytes")?;
    if read == 0 {
      break;
    }
    conn
      .process_new_packets()
      .context("failed to process TLS response bytes")?;
  }

  let head_end = find_http1_head_end(&response)
    .ok_or_else(|| anyhow!("HTTP/1 response did not contain a complete header block"))?;
  let head =
    std::str::from_utf8(&response[..head_end]).context("HTTP/1 response headers were not UTF-8")?;
  let status = parse_http1_status(&response)?;
  let headers = parse_http1_headers(head);
  let body = response[(head_end + 4)..].to_vec();
  Ok((status, headers, body))
}

fn drain_rustls_plaintext(
  conn: &mut ClientConnection,
  response: &mut Vec<u8>,
) -> anyhow::Result<()> {
  let mut buffer = [0u8; 8192];
  loop {
    match conn.reader().read(&mut buffer) {
      Ok(0) => return Ok(()),
      Ok(read) => response.extend_from_slice(&buffer[..read]),
      Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
      Err(error) => return Err(error).context("failed to drain TLS plaintext"),
    }
  }
}

fn http1_response_complete(response: &[u8]) -> anyhow::Result<bool> {
  let Some((body_start, content_length)) = http1_body_bounds(response)? else {
    return Ok(false);
  };
  let Some(content_length) = content_length else {
    return Ok(false);
  };
  Ok(response.len() >= body_start + content_length)
}

fn http1_body_bounds(response: &[u8]) -> anyhow::Result<Option<(usize, Option<usize>)>> {
  let Some(head_end) = find_http1_head_end(response) else {
    return Ok(None);
  };
  let head =
    std::str::from_utf8(&response[..head_end]).context("HTTP/1 response headers were not UTF-8")?;
  let headers = parse_http1_headers(head);
  let content_length = headers
    .get("content-length")
    .map(|value| value.parse().context("invalid HTTP/1 Content-Length"))
    .transpose()?;
  Ok(Some((head_end + 4, content_length)))
}

fn find_http1_head_end(response: &[u8]) -> Option<usize> {
  response.windows(4).position(|window| window == b"\r\n\r\n")
}

fn dpi_tls_write_plan(
  profile: DpiTlsProfile,
  client_hello: &[u8],
) -> anyhow::Result<DpiTlsWritePlan> {
  let view = client_hello_view(client_hello)?;
  let sni_midpoint = view.sni_name.start + (view.sni_name.len() / 2).max(1);
  let (chunks, tls_record_count) = match profile {
    DpiTlsProfile::ByedpiSplitSni => {
      let chunks = chunk_by_offsets(client_hello, &[sni_midpoint]);
      let tls_record_count = tls_record_count(client_hello)?;
      (chunks, tls_record_count)
    }
    DpiTlsProfile::ByedpiTlsrecSni => {
      let split = split_first_tls_record(client_hello, &[view.sni_name.start + 1])?;
      let tls_record_count = tls_record_count(&split)?;
      (vec![split], tls_record_count)
    }
    DpiTlsProfile::GoodbyeDpiNativeFrag => {
      let chunks = chunk_by_offsets(client_hello, &[2]);
      let tls_record_count = tls_record_count(client_hello)?;
      (chunks, tls_record_count)
    }
    DpiTlsProfile::GoodbyeDpiFragBySni => {
      let chunks = chunk_by_offsets(client_hello, &[view.sni_name.start]);
      let tls_record_count = tls_record_count(client_hello)?;
      (chunks, tls_record_count)
    }
    DpiTlsProfile::DpibreakSegment01 => {
      let chunks = chunk_by_offsets(client_hello, &[1]);
      let tls_record_count = tls_record_count(client_hello)?;
      (chunks, tls_record_count)
    }
    DpiTlsProfile::DpibreakSegment05 => {
      let chunks = chunk_by_offsets(client_hello, &[5]);
      let tls_record_count = tls_record_count(client_hello)?;
      (chunks, tls_record_count)
    }
  };

  Ok(DpiTlsWritePlan {
    tcp_chunk_count: chunks.len(),
    tls_record_count,
    sni_offset: view.sni_name.start,
    chunks,
  })
}

fn chunk_by_offsets(bytes: &[u8], offsets: &[usize]) -> Vec<Vec<u8>> {
  let mut offsets = offsets
    .iter()
    .copied()
    .filter(|offset| *offset > 0 && *offset < bytes.len())
    .collect::<Vec<_>>();
  offsets.sort_unstable();
  offsets.dedup();

  let mut chunks = Vec::with_capacity(offsets.len() + 1);
  let mut start = 0usize;
  for offset in offsets {
    chunks.push(bytes[start..offset].to_vec());
    start = offset;
  }
  chunks.push(bytes[start..].to_vec());
  chunks
}

fn split_first_tls_record(bytes: &[u8], offsets: &[usize]) -> anyhow::Result<Vec<u8>> {
  let view = first_tls_record_view(bytes)?;
  let mut payload_offsets = offsets
    .iter()
    .copied()
    .filter(|offset| *offset > view.payload.start && *offset < view.payload.end)
    .collect::<Vec<_>>();
  payload_offsets.sort_unstable();
  payload_offsets.dedup();
  if payload_offsets.is_empty() {
    return Ok(bytes.to_vec());
  }

  let mut output = Vec::with_capacity(bytes.len() + payload_offsets.len() * 5);
  output.extend_from_slice(&bytes[..view.record.start]);
  let mut start = view.payload.start;
  for offset in payload_offsets
    .into_iter()
    .chain(std::iter::once(view.payload.end))
  {
    append_tls_record(
      &mut output,
      bytes[view.record.start],
      &bytes[(view.record.start + 1)..(view.record.start + 3)],
      &bytes[start..offset],
    )?;
    start = offset;
  }
  output.extend_from_slice(&bytes[view.record.end..]);
  Ok(output)
}

fn append_tls_record(
  output: &mut Vec<u8>,
  content_type: u8,
  version: &[u8],
  payload: &[u8],
) -> anyhow::Result<()> {
  if payload.len() > u16::MAX as usize {
    bail!("TLS record payload is too large: {}", payload.len());
  }
  output.push(content_type);
  output.extend_from_slice(version);
  output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
  output.extend_from_slice(payload);
  Ok(())
}

fn tls_record_count(bytes: &[u8]) -> anyhow::Result<usize> {
  let mut offset = 0usize;
  let mut count = 0usize;
  while offset < bytes.len() {
    let header_end = offset
      .checked_add(5)
      .ok_or_else(|| anyhow!("TLS record offset overflow"))?;
    if header_end > bytes.len() {
      bail!("truncated TLS record header at byte {offset}");
    }
    let len = u16::from_be_bytes([bytes[offset + 3], bytes[offset + 4]]) as usize;
    offset = header_end
      .checked_add(len)
      .ok_or_else(|| anyhow!("TLS record length overflow"))?;
    if offset > bytes.len() {
      bail!("truncated TLS record payload");
    }
    count += 1;
  }
  Ok(count)
}

fn first_tls_record_view(bytes: &[u8]) -> anyhow::Result<ClientHelloView> {
  if bytes.len() < 5 {
    bail!("ClientHello is missing the TLS record header");
  }
  if bytes[0] != 0x16 {
    bail!(
      "expected TLS handshake record, got content type {}",
      bytes[0]
    );
  }
  let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
  let record_end = 5usize
    .checked_add(record_len)
    .ok_or_else(|| anyhow!("TLS record length overflow"))?;
  if record_end > bytes.len() {
    bail!("ClientHello TLS record is truncated");
  }
  Ok(ClientHelloView {
    record: 0..record_end,
    payload: 5..record_end,
    sni_name: 0..0,
  })
}

fn client_hello_view(bytes: &[u8]) -> anyhow::Result<ClientHelloView> {
  let mut view = first_tls_record_view(bytes)?;
  let mut cursor = view.payload.start;
  if read_u8_at(bytes, cursor, "handshake type")? != 0x01 {
    bail!("first TLS handshake message is not a ClientHello");
  }
  cursor += 1;
  let handshake_len = read_u24_at(bytes, cursor, "ClientHello length")?;
  cursor += 3;
  let body_end = cursor
    .checked_add(handshake_len)
    .ok_or_else(|| anyhow!("ClientHello length overflow"))?;
  if body_end > view.payload.end {
    bail!("ClientHello handshake message spans beyond the first TLS record");
  }

  cursor = cursor
    .checked_add(2 + 32)
    .ok_or_else(|| anyhow!("ClientHello legacy header overflow"))?;
  ensure_len(bytes, cursor, 1, "session id length")?;
  let session_len = bytes[cursor] as usize;
  cursor += 1;
  cursor = cursor
    .checked_add(session_len)
    .ok_or_else(|| anyhow!("ClientHello session id overflow"))?;
  let cipher_suites_len = read_u16_at(bytes, cursor, "cipher suites length")?;
  cursor += 2;
  cursor = cursor
    .checked_add(cipher_suites_len)
    .ok_or_else(|| anyhow!("ClientHello cipher suites overflow"))?;
  ensure_len(bytes, cursor, 1, "compression methods length")?;
  let compression_len = bytes[cursor] as usize;
  cursor += 1;
  cursor = cursor
    .checked_add(compression_len)
    .ok_or_else(|| anyhow!("ClientHello compression methods overflow"))?;
  let extensions_len = read_u16_at(bytes, cursor, "extensions length")?;
  cursor += 2;
  let extensions_end = cursor
    .checked_add(extensions_len)
    .ok_or_else(|| anyhow!("ClientHello extensions overflow"))?;
  if extensions_end > body_end {
    bail!("ClientHello extensions exceed handshake body");
  }

  while cursor < extensions_end {
    ensure_len(bytes, cursor, 4, "extension header")?;
    let extension_type = read_u16_at(bytes, cursor, "extension type")?;
    let extension_len = read_u16_at(bytes, cursor + 2, "extension length")?;
    cursor += 4;
    let extension_end = cursor
      .checked_add(extension_len)
      .ok_or_else(|| anyhow!("ClientHello extension overflow"))?;
    if extension_end > extensions_end {
      bail!("ClientHello extension exceeds extension block");
    }
    if extension_type == 0x0000 {
      view.sni_name = parse_sni_extension(bytes, cursor, extension_end)?;
      return Ok(view);
    }
    cursor = extension_end;
  }

  bail!("ClientHello did not contain a server_name extension")
}

fn parse_sni_extension(bytes: &[u8], start: usize, end: usize) -> anyhow::Result<Range<usize>> {
  let list_len = read_u16_at(bytes, start, "server_name list length")?;
  let mut cursor = start + 2;
  let list_end = cursor
    .checked_add(list_len)
    .ok_or_else(|| anyhow!("server_name list length overflow"))?;
  if list_end > end {
    bail!("server_name list exceeds extension length");
  }

  while cursor < list_end {
    ensure_len(bytes, cursor, 3, "server_name entry")?;
    let name_type = bytes[cursor];
    let name_len = read_u16_at(bytes, cursor + 1, "server_name length")?;
    cursor += 3;
    let name_end = cursor
      .checked_add(name_len)
      .ok_or_else(|| anyhow!("server_name length overflow"))?;
    if name_end > list_end {
      bail!("server_name entry exceeds list length");
    }
    if name_type == 0 {
      return Ok(cursor..name_end);
    }
    cursor = name_end;
  }

  bail!("server_name extension did not contain a host_name entry")
}

fn read_u8_at(bytes: &[u8], offset: usize, context: &str) -> anyhow::Result<u8> {
  ensure_len(bytes, offset, 1, context)?;
  Ok(bytes[offset])
}

fn read_u16_at(bytes: &[u8], offset: usize, context: &str) -> anyhow::Result<usize> {
  ensure_len(bytes, offset, 2, context)?;
  Ok(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize)
}

fn read_u24_at(bytes: &[u8], offset: usize, context: &str) -> anyhow::Result<usize> {
  ensure_len(bytes, offset, 3, context)?;
  Ok(
    ((bytes[offset] as usize) << 16)
      | ((bytes[offset + 1] as usize) << 8)
      | bytes[offset + 2] as usize,
  )
}

fn ensure_len(bytes: &[u8], offset: usize, len: usize, context: &str) -> anyhow::Result<()> {
  let end = offset
    .checked_add(len)
    .ok_or_else(|| anyhow!("{context} offset overflow"))?;
  if end > bytes.len() {
    bail!("{context} is truncated");
  }
  Ok(())
}

async fn run_tls_resumption_load(args: TlsResumptionLoadArgs) -> anyhow::Result<()> {
  let mut client_config = downstream_client_config(Path::new(&args.ca_cert), b"http/1.1")?;
  client_config.resumption = Resumption::in_memory_sessions(args.connections.max(8));
  let connector = TlsConnector::from(Arc::new(client_config));
  let mut full = 0usize;
  let mut resumed = 0usize;
  let mut unknown = 0usize;
  let mut tickets_received = 0u32;

  for index in 0..args.connections {
    let (kind, status, tickets) = tls_resumption_http1_request(&connector, &args, index).await?;
    tickets_received = tickets_received.saturating_add(tickets);
    match kind {
      Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest) => full += 1,
      Some(HandshakeKind::Resumed) => resumed += 1,
      None => unknown += 1,
    }
    if status != 200 {
      bail!("TLS resumption probe request {index} returned status {status}");
    }
  }

  let output = serde_json::json!({
    "connections": args.connections,
    "full": full,
    "resumed": resumed,
    "unknown": unknown,
    "tickets_received": tickets_received,
  });
  if resumed < args.expect_resumed_min {
    eprintln!("{}", serde_json::to_string(&output)?);
    bail!(
      "expected at least {} resumed TLS handshakes, got {resumed}",
      args.expect_resumed_min
    );
  }

  println!("{}", serde_json::to_string(&output)?);
  Ok(())
}

async fn run_webtransport_multiplex_client(args: WebTransportMultiplexArgs) -> anyhow::Result<()> {
  let client_config = downstream_client_config(Path::new(&args.ca_cert), b"h3")?;
  let quic_crypto =
    QuicClientConfig::try_from(client_config).context("failed to build QUIC TLS client")?;
  let quic_config = QuinnClientConfig::new(Arc::new(quic_crypto));
  let remote_addr = resolve_remote_addr(&args.host, args.port).await?;
  let endpoint = Endpoint::client(client_bind_addr(remote_addr))
    .context("failed to create downstream QUIC endpoint")?;
  let quinn_connection = endpoint
    .connect_with(quic_config, remote_addr, &args.server_name)
    .with_context(|| {
      format!(
        "failed to start downstream WebTransport connection to {}",
        args.host
      )
    })?
    .await
    .context("failed to connect downstream WebTransport")?;
  let close_connection = quinn_connection.clone();
  let h3_connection = h3_quinn::Connection::new(quinn_connection);
  let (mut driver, mut send_request) = h3::client::builder()
    .enable_extended_connect(true)
    .enable_datagram(true)
    .build::<_, _, Bytes>(h3_connection)
    .await
    .context("failed to establish downstream HTTP/3 client")?;
  let driver_task = tokio::spawn(async move {
    let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
  });

  let mut statuses = Vec::with_capacity(args.sessions);
  let mut held_streams = Vec::new();
  for index in 0..args.sessions {
    let request = webtransport_connect_request(&args, index)?;
    let mut stream = send_request
      .send_request(request)
      .await
      .with_context(|| format!("failed to send WebTransport CONNECT #{index}"))?;
    let response = tokio::time::timeout(Duration::from_secs(10), stream.recv_response())
      .await
      .with_context(|| format!("timed out waiting for WebTransport CONNECT #{index}"))?
      .with_context(|| format!("failed to receive WebTransport CONNECT #{index} response"))?;
    let status = response.status().as_u16();
    statuses.push(status);
    held_streams.push(stream);
  }

  if statuses != args.expect_statuses {
    eprintln!(
      "{}",
      serde_json::json!({
        "statuses": statuses,
        "expected_statuses": args.expect_statuses,
      })
    );
    bail!("WebTransport multiplex statuses did not match expected statuses");
  }

  close_connection.close(0u32.into(), b"probe complete");
  drop(held_streams);
  let _ = driver_task.await;

  println!(
    "{}",
    serde_json::json!({
      "statuses": statuses,
    })
  );
  Ok(())
}

async fn run_webtransport_reload_gated_client(
  args: WebTransportReloadGatedArgs,
) -> anyhow::Result<()> {
  let client_config = downstream_client_config(Path::new(&args.ca_cert), b"h3")?;
  let quic_crypto =
    QuicClientConfig::try_from(client_config).context("failed to build QUIC TLS client")?;
  let quic_config = QuinnClientConfig::new(Arc::new(quic_crypto));
  let remote_addr = resolve_remote_addr(&args.host, args.port).await?;
  let endpoint = Endpoint::client(client_bind_addr(remote_addr))
    .context("failed to create downstream QUIC endpoint")?;
  let quinn_connection = endpoint
    .connect_with(quic_config, remote_addr, &args.server_name)
    .with_context(|| {
      format!(
        "failed to start downstream WebTransport connection to {}",
        args.host
      )
    })?
    .await
    .context("failed to connect downstream WebTransport")?;
  let close_connection = quinn_connection.clone();
  let h3_connection = h3_quinn::Connection::new(quinn_connection);
  let (mut driver, mut send_request) = h3::client::builder()
    .enable_extended_connect(true)
    .enable_datagram(true)
    .build::<_, _, Bytes>(h3_connection)
    .await
    .context("failed to establish downstream HTTP/3 client")?;
  let driver_task = tokio::spawn(async move {
    let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
  });

  let initial_request = webtransport_reload_connect_request(&args, 0)?;
  let mut initial_stream = send_request
    .send_request(initial_request)
    .await
    .context("failed to send initial WebTransport CONNECT")?;
  let initial_response =
    tokio::time::timeout(Duration::from_secs(10), initial_stream.recv_response())
      .await
      .context("timed out waiting for initial WebTransport CONNECT")?
      .context("failed to receive initial WebTransport CONNECT response")?;
  let initial_status = initial_response.status().as_u16();
  if initial_status != args.expect_initial_status {
    eprintln!(
      "{}",
      serde_json::json!({
        "initial_webtransport_status": initial_status,
        "expected_initial_status": args.expect_initial_status,
      })
    );
    bail!("initial WebTransport status did not match expected status");
  }

  fs::write(&args.first_ready_path, b"ready").with_context(|| {
    format!(
      "failed to write first-ready marker {}",
      args.first_ready_path
    )
  })?;
  wait_for_path(&args.resume_path, Duration::from_secs(30))
    .await
    .with_context(|| format!("timed out waiting for resume marker {}", args.resume_path))?;

  let drained_webtransport_request = webtransport_reload_connect_request(&args, 1)?;
  let mut drained_webtransport_stream = send_request
    .send_request(drained_webtransport_request)
    .await
    .context("failed to send drained WebTransport CONNECT")?;
  let drained_webtransport_response = tokio::time::timeout(
    Duration::from_secs(10),
    drained_webtransport_stream.recv_response(),
  )
  .await
  .context("timed out waiting for drained WebTransport CONNECT")?
  .context("failed to receive drained WebTransport CONNECT response")?;
  let drained_webtransport_status = drained_webtransport_response.status().as_u16();
  drain_h3_response_body(&mut drained_webtransport_stream)
    .await
    .context("failed to drain rejected WebTransport response body")?;

  let http_request = h3_get_request(&args.authority, &args.http_path, &args.headers)?;
  let mut http_stream = send_request
    .send_request(http_request)
    .await
    .context("failed to send drained HTTP/3 request")?;
  http_stream
    .finish()
    .await
    .context("failed to finish drained HTTP/3 request")?;
  let http_response = tokio::time::timeout(Duration::from_secs(10), http_stream.recv_response())
    .await
    .context("timed out waiting for drained HTTP/3 response")?
    .context("failed to receive drained HTTP/3 response")?;
  let drained_http_status = http_response.status().as_u16();
  drain_h3_response_body(&mut http_stream)
    .await
    .context("failed to drain rejected HTTP/3 response body")?;

  if drained_webtransport_status != args.expect_drained_status
    || drained_http_status != args.expect_drained_status
  {
    eprintln!(
      "{}",
      serde_json::json!({
        "initial_webtransport_status": initial_status,
        "drained_webtransport_status": drained_webtransport_status,
        "drained_http_status": drained_http_status,
        "expected_drained_status": args.expect_drained_status,
      })
    );
    bail!("drained WebTransport connection accepted a stale-snapshot request");
  }

  close_connection.close(0u32.into(), b"probe complete");
  drop(initial_stream);
  let _ = driver_task.await;

  println!(
    "{}",
    serde_json::json!({
      "initial_webtransport_status": initial_status,
      "drained_webtransport_status": drained_webtransport_status,
      "drained_http_status": drained_http_status,
    })
  );
  Ok(())
}

async fn run_admin_operation_wt_events_client(
  args: AdminOperationWtEventsArgs,
) -> anyhow::Result<()> {
  let timeout = Duration::from_millis(args.timeout_ms);
  let certs = load_certs(Path::new(&args.ca_cert))?;
  let client = web_transport_quinn::ClientBuilder::new()
    .with_server_certificates(certs)
    .context("failed to build Admin WebTransport client")?;
  let url = url::Url::parse(&format!("https://{}:{}{}", args.host, args.port, args.path))
    .context("failed to build Admin WebTransport URL")?;
  let request = web_transport_quinn::proto::ConnectRequest::new(url).with_headers(args.headers);
  let session = tokio::time::timeout(timeout, client.connect(request))
    .await
    .context("timed out connecting to Admin WebTransport operation events")?
    .context("failed to connect to Admin WebTransport operation events")?;
  let mut stream = tokio::time::timeout(timeout, session.accept_uni())
    .await
    .context("timed out waiting for Admin WebTransport event stream")?
    .context("failed to accept Admin WebTransport event stream")?;
  let bytes = read_admin_webtransport_event_stream(&mut stream, timeout)
    .await
    .context("failed to read Admin WebTransport event stream")?;
  let body = String::from_utf8(bytes).context("Admin WebTransport event stream was not UTF-8")?;

  let mut events = Vec::new();
  let mut terminal_state = None;
  for line in body.lines().filter(|line| !line.trim().is_empty()) {
    let value: serde_json::Value = serde_json::from_str(line)
      .with_context(|| format!("Admin WebTransport event line was not JSON: {line}"))?;
    if let Some(event) = value.get("event").and_then(|value| value.as_str()) {
      events.push(event.to_string());
    }
    if let Some(state) = value
      .pointer("/operation/state")
      .and_then(|value| value.as_str())
    {
      if matches!(state, "succeeded" | "failed" | "cancelled" | "expired") {
        terminal_state = Some(state.to_string());
      }
    }
  }

  for expected in &args.expect_events {
    if !events.iter().any(|event| event == expected) {
      eprintln!(
        "{}",
        serde_json::json!({
          "events": events,
          "expected_event": expected,
          "body": body,
        })
      );
      bail!("Admin WebTransport event stream missed expected event");
    }
  }
  if let Some(expected) = &args.expect_terminal_state {
    if terminal_state.as_deref() != Some(expected.as_str()) {
      eprintln!(
        "{}",
        serde_json::json!({
          "events": events,
          "terminal_state": terminal_state,
          "expected_terminal_state": expected,
          "body": body,
        })
      );
      bail!("Admin WebTransport event stream terminal state did not match");
    }
  }

  println!(
    "{}",
    serde_json::json!({
      "events": events,
      "terminal_state": terminal_state,
      "body_bytes": body.len(),
    })
  );
  Ok(())
}

async fn read_admin_webtransport_event_stream<R>(
  stream: &mut R,
  timeout: Duration,
) -> anyhow::Result<Vec<u8>>
where
  R: tokio::io::AsyncRead + Unpin,
{
  let mut bytes = Vec::new();
  let mut chunk = [0u8; 4096];
  loop {
    let read = tokio::time::timeout(timeout, stream.read(&mut chunk))
      .await
      .context("timed out reading Admin WebTransport event stream")?;
    match read {
      Ok(0) => return Ok(bytes),
      Ok(len) => {
        bytes.extend_from_slice(&chunk[..len]);
        if bytes.len() > 1024 * 1024 {
          bail!("Admin WebTransport event stream exceeded 1 MiB");
        }
      }
      Err(error) if !bytes.is_empty() && is_admin_webtransport_terminal_read_error(&error) => {
        return Ok(bytes);
      }
      Err(error) => return Err(error).context("failed to read Admin WebTransport event stream"),
    }
  }
}

fn is_admin_webtransport_terminal_read_error(error: &io::Error) -> bool {
  let message = error.to_string();
  message.contains("connection error: closed") || message.contains("session error")
}

async fn tls_resumption_http1_request(
  connector: &TlsConnector,
  args: &TlsResumptionLoadArgs,
  index: usize,
) -> anyhow::Result<(Option<HandshakeKind>, u16, u32)> {
  let stream = TcpStream::connect((args.host.as_str(), args.port))
    .await
    .with_context(|| format!("failed to connect to {}:{}", args.host, args.port))?;
  let server_name = ServerName::try_from(args.server_name.clone())
    .map_err(|_| anyhow!("invalid server name: {}", args.server_name))?;
  let mut tls_stream = connector
    .connect(server_name, stream)
    .await
    .context("failed to establish downstream TLS")?;
  let kind = tls_stream.get_ref().1.handshake_kind();
  let path = append_query_param(&args.path, "resumption_probe", index);
  let request = format!(
    "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
    args.authority
  );
  tls_stream
    .write_all(request.as_bytes())
    .await
    .context("failed to write TLS resumption probe request")?;
  tls_stream
    .flush()
    .await
    .context("failed to flush TLS resumption probe request")?;

  let mut response = Vec::new();
  tokio::time::timeout(
    Duration::from_secs(10),
    tls_stream.read_to_end(&mut response),
  )
  .await
  .context("timed out reading TLS resumption probe response")?
  .context("failed to read TLS resumption probe response")?;
  let status = parse_http1_status(&response)?;
  let tickets = tls_stream.get_ref().1.tls13_tickets_received();
  Ok((kind, status, tickets))
}

fn append_query_param(path: &str, name: &str, value: usize) -> String {
  let separator = if path.contains('?') { '&' } else { '?' };
  format!("{path}{separator}{name}={value}")
}

fn parse_http1_status(response: &[u8]) -> anyhow::Result<u16> {
  let status_line = response
    .split(|byte| *byte == b'\n')
    .next()
    .ok_or_else(|| anyhow!("HTTP/1 response was empty"))?;
  let status_line = std::str::from_utf8(status_line)
    .context("HTTP/1 status line was not UTF-8")?
    .trim_end_matches('\r');
  let mut parts = status_line.split_whitespace();
  let version = parts
    .next()
    .ok_or_else(|| anyhow!("HTTP/1 response status line missing version"))?;
  if !version.starts_with("HTTP/1.") {
    bail!("unexpected HTTP response version in status line: {status_line}");
  }
  let status = parts
    .next()
    .ok_or_else(|| anyhow!("HTTP/1 response status line missing status"))?
    .parse()
    .context("invalid HTTP/1 response status")?;
  Ok(status)
}

fn webtransport_connect_request(
  args: &WebTransportMultiplexArgs,
  index: usize,
) -> anyhow::Result<Request<()>> {
  let separator = if args.path.contains('?') { '&' } else { '?' };
  let uri: Uri = format!(
    "https://{}{}{}probe_session={}",
    args.authority, args.path, separator, index
  )
  .parse()
  .context("failed to build WebTransport CONNECT URI")?;
  let mut request = Request::builder()
    .method(Method::CONNECT)
    .uri(uri)
    .version(Version::HTTP_3)
    .header("sec-webtransport-http3-draft", "draft02")
    .body(())
    .context("failed to build WebTransport CONNECT request")?;
  request.headers_mut().extend(args.headers.clone());
  request
    .extensions_mut()
    .insert(h3::ext::Protocol::WEB_TRANSPORT);
  Ok(request)
}

fn webtransport_reload_connect_request(
  args: &WebTransportReloadGatedArgs,
  index: usize,
) -> anyhow::Result<Request<()>> {
  let separator = if args.path.contains('?') { '&' } else { '?' };
  let uri: Uri = format!(
    "https://{}{}{}probe_session={}",
    args.authority, args.path, separator, index
  )
  .parse()
  .context("failed to build WebTransport CONNECT URI")?;
  let mut request = Request::builder()
    .method(Method::CONNECT)
    .uri(uri)
    .version(Version::HTTP_3)
    .header("sec-webtransport-http3-draft", "draft02")
    .body(())
    .context("failed to build WebTransport CONNECT request")?;
  request.headers_mut().extend(args.headers.clone());
  request
    .extensions_mut()
    .insert(h3::ext::Protocol::WEB_TRANSPORT);
  Ok(request)
}

fn h3_get_request(authority: &str, path: &str, headers: &HeaderMap) -> anyhow::Result<Request<()>> {
  let uri: Uri = format!("https://{authority}{path}")
    .parse()
    .context("failed to build HTTP/3 GET URI")?;
  let mut request = Request::builder()
    .method(Method::GET)
    .uri(uri)
    .version(Version::HTTP_3)
    .body(())
    .context("failed to build HTTP/3 GET request")?;
  request.headers_mut().extend(headers.clone());
  Ok(request)
}

async fn drain_h3_response_body(
  stream: &mut h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> anyhow::Result<()> {
  while let Some(mut chunk) = tokio::time::timeout(Duration::from_secs(10), stream.recv_data())
    .await
    .context("timed out reading HTTP/3 response body")?
    .context("failed to read HTTP/3 response body")?
  {
    let len = chunk.remaining();
    let _ = chunk.copy_to_bytes(len);
  }
  Ok(())
}

async fn wait_for_path(path: &str, timeout: Duration) -> anyhow::Result<()> {
  tokio::time::timeout(timeout, async {
    loop {
      if Path::new(path).exists() {
        return;
      }
      tokio::time::sleep(Duration::from_millis(100)).await;
    }
  })
  .await
  .context("timed out waiting for path")?;
  Ok(())
}

async fn h2_downstream_request(args: &DownstreamArgs) -> anyhow::Result<serde_json::Value> {
  let mut client_config = downstream_client_config(Path::new(&args.ca_cert), b"h2")?;
  client_config.enable_sni = true;
  let connector = TlsConnector::from(Arc::new(client_config));
  let stream = TcpStream::connect((args.host.as_str(), args.port))
    .await
    .with_context(|| format!("failed to connect to {}:{}", args.host, args.port))?;
  let server_name = ServerName::try_from(args.server_name.clone())
    .map_err(|_| anyhow!("invalid server name: {}", args.server_name))?;
  let tls_stream = connector
    .connect(server_name, stream)
    .await
    .context("failed to establish downstream TLS")?;
  let negotiated = tls_stream
    .get_ref()
    .1
    .alpn_protocol()
    .map(|protocol| protocol.to_vec())
    .unwrap_or_default();
  if negotiated != b"h2" {
    bail!(
      "expected downstream ALPN h2, got {}",
      String::from_utf8_lossy(&negotiated)
    );
  }

  let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
    .handshake(TokioIo::new(tls_stream))
    .await
    .context("failed to establish downstream HTTP/2 client")?;
  tokio::spawn(async move {
    if let Err(error) = connection.await {
      eprintln!("downstream HTTP/2 connection failed: {error}");
    }
  });

  let request = downstream_request(args, Version::HTTP_2, downstream_h2_body(args))?;
  let response = sender
    .send_request(request)
    .await
    .context("failed to send downstream HTTP/2 request")?;
  let (parts, body) = response.into_parts();
  let body = body
    .collect()
    .await
    .context("failed to read downstream HTTP/2 response body")?
    .to_bytes();
  Ok(response_json(
    args.protocol.label(),
    parts.status,
    &parts.headers,
    &body,
  ))
}

async fn h3_downstream_request(args: &DownstreamArgs) -> anyhow::Result<serde_json::Value> {
  let client_config = downstream_client_config(Path::new(&args.ca_cert), b"h3")?;
  let quic_crypto =
    QuicClientConfig::try_from(client_config).context("failed to build QUIC TLS client")?;
  let quic_config = QuinnClientConfig::new(Arc::new(quic_crypto));
  let remote_addr = resolve_remote_addr(&args.host, args.port).await?;
  let endpoint = Endpoint::client(client_bind_addr(remote_addr))
    .context("failed to create downstream QUIC endpoint")?;
  let quinn_connection = endpoint
    .connect_with(quic_config, remote_addr, &args.server_name)
    .with_context(|| {
      format!(
        "failed to start downstream HTTP/3 connection to {}",
        args.host
      )
    })?
    .await
    .context("failed to connect downstream HTTP/3")?;
  let close_connection = quinn_connection.clone();
  let h3_connection = h3_quinn::Connection::new(quinn_connection);
  let (mut driver, mut send_request) = h3::client::builder()
    .build(h3_connection)
    .await
    .context("failed to establish downstream HTTP/3 client")?;
  let driver_task = tokio::spawn(async move {
    let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
  });

  let request = downstream_request(args, Version::HTTP_3, ())?;
  let mut stream = send_request
    .send_request(request)
    .await
    .context("failed to send downstream HTTP/3 request")?;
  if let Some(total) = args.body_bytes {
    let mut sent = 0usize;
    while sent < total {
      let len = (total - sent).min(args.body_chunk_size);
      stream
        .send_data(Bytes::from(vec![b'x'; len]))
        .await
        .context("failed to send downstream HTTP/3 request body")?;
      sent += len;
    }
  } else if !args.body.is_empty() {
    stream
      .send_data(Bytes::from(args.body.clone()))
      .await
      .context("failed to send downstream HTTP/3 request body")?;
  }
  stream
    .finish()
    .await
    .context("failed to finish downstream HTTP/3 request")?;

  let response = stream
    .recv_response()
    .await
    .context("failed to receive downstream HTTP/3 response")?;
  let mut response_body = BytesMut::new();
  while let Some(mut chunk) = stream
    .recv_data()
    .await
    .context("failed to read downstream HTTP/3 response body")?
  {
    let len = chunk.remaining();
    response_body.extend_from_slice(&chunk.copy_to_bytes(len));
  }

  close_connection.close(0u32.into(), b"probe complete");
  let _ = driver_task.await;

  let (parts, _) = response.into_parts();
  Ok(response_json(
    args.protocol.label(),
    parts.status,
    &parts.headers,
    &response_body.freeze(),
  ))
}

fn downstream_h2_body(args: &DownstreamArgs) -> BoxBody<Bytes, Infallible> {
  if let Some(delay_ms) = args.zero_length_body_end_delay_ms {
    return DelayedEndZeroLengthBody::new(Duration::from_millis(delay_ms)).boxed();
  }

  if let Some(total) = args.body_bytes {
    let chunk_size = args.body_chunk_size;
    return StreamBody::new(futures_util::stream::unfold(
      0usize,
      move |sent| async move {
        if sent >= total {
          None
        } else {
          let len = (total - sent).min(chunk_size);
          Some((Ok(Frame::data(Bytes::from(vec![b'x'; len]))), sent + len))
        }
      },
    ))
    .boxed();
  }

  Full::new(Bytes::from(args.body.clone())).boxed()
}

struct DelayedEndZeroLengthBody {
  sleep: Pin<Box<tokio::time::Sleep>>,
  finished: bool,
}

impl DelayedEndZeroLengthBody {
  fn new(delay: Duration) -> Self {
    Self {
      sleep: Box::pin(tokio::time::sleep(delay)),
      finished: false,
    }
  }
}

impl hyper::body::Body for DelayedEndZeroLengthBody {
  type Data = Bytes;
  type Error = Infallible;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut TaskContext<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    if self.finished {
      return Poll::Ready(None);
    }

    if self.sleep.as_mut().poll(cx).is_ready() {
      self.finished = true;
      return Poll::Ready(None);
    }

    Poll::Pending
  }

  fn is_end_stream(&self) -> bool {
    self.finished
  }

  fn size_hint(&self) -> SizeHint {
    let mut size_hint = SizeHint::new();
    size_hint.set_exact(0);
    size_hint
  }
}

fn downstream_client_config(path: &Path, alpn: &[u8]) -> anyhow::Result<ClientConfig> {
  let mut config =
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
      .with_safe_default_protocol_versions()
      .context("failed to configure downstream TLS versions")?
      .with_root_certificates(load_root_store(path)?)
      .with_no_client_auth();
  config.alpn_protocols = vec![alpn.to_vec()];
  Ok(config)
}

fn downstream_request<B>(
  args: &DownstreamArgs,
  version: Version,
  body: B,
) -> anyhow::Result<Request<B>> {
  let uri: Uri = format!("https://{}{}", args.authority, args.path)
    .parse()
    .context("failed to build request URI")?;
  let mut request = Request::builder()
    .method(args.method.clone())
    .uri(uri)
    .version(version);
  if !args.omit_content_length {
    request = request.header(CONTENT_LENGTH, args.body_len().to_string());
  }
  for (name, value) in &args.headers {
    request = request.header(name, value);
  }
  request.body(body).map_err(Into::into)
}

async fn resolve_remote_addr(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
  lookup_host((host, port))
    .await
    .with_context(|| format!("failed to resolve {host}:{port}"))?
    .next()
    .ok_or_else(|| anyhow!("host resolved no addresses: {host}:{port}"))
}

fn client_bind_addr(remote_addr: SocketAddr) -> SocketAddr {
  if remote_addr.is_ipv4() {
    "0.0.0.0:0".parse().expect("valid IPv4 bind address")
  } else {
    "[::]:0".parse().expect("valid IPv6 bind address")
  }
}

async fn turn_udp_round_trip(
  args: &TurnClientArgs,
  request: &[u8],
) -> anyhow::Result<Option<Vec<u8>>> {
  let remote = resolve_remote_addr(&args.host, args.port).await?;
  let socket = tokio::net::UdpSocket::bind(client_bind_addr(remote))
    .await
    .context("failed to bind TURN UDP client socket")?;
  socket
    .send_to(request, remote)
    .await
    .context("failed to send TURN UDP request")?;
  let mut response = vec![0u8; 65_536];
  match tokio::time::timeout(Duration::from_millis(750), socket.recv(&mut response)).await {
    Ok(Ok(len)) => {
      response.truncate(len);
      Ok(Some(response))
    }
    Ok(Err(error)) => Err(error).context("failed to receive TURN UDP response"),
    Err(_) => Ok(None),
  }
}

async fn turn_tcp_round_trip(
  args: &TurnClientArgs,
  request: &[u8],
) -> anyhow::Result<Option<Vec<u8>>> {
  let mut stream = TcpStream::connect((args.host.as_str(), args.port))
    .await
    .with_context(|| format!("failed to connect TURN TCP to {}:{}", args.host, args.port))?;
  stream
    .write_all(request)
    .await
    .context("failed to write TURN TCP request")?;
  match tokio::time::timeout(Duration::from_millis(750), read_turn_frame(&mut stream)).await {
    Ok(Ok(response)) => Ok(Some(response)),
    Ok(Err(_)) | Err(_) => Ok(None),
  }
}

async fn turn_tls_round_trip(
  args: &TurnClientArgs,
  request: &[u8],
) -> anyhow::Result<Option<Vec<u8>>> {
  let ca_cert = args
    .ca_cert
    .as_ref()
    .ok_or_else(|| anyhow!("TURN TLS requires --ca-cert"))?;
  let config =
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
      .with_safe_default_protocol_versions()
      .context("failed to configure TURN TLS client versions")?
      .with_root_certificates(load_root_store(Path::new(ca_cert))?)
      .with_no_client_auth();
  let connector = TlsConnector::from(Arc::new(config));
  let stream = TcpStream::connect((args.host.as_str(), args.port))
    .await
    .with_context(|| format!("failed to connect TURN TLS to {}:{}", args.host, args.port))?;
  let server_name = ServerName::try_from(args.server_name.clone())
    .map_err(|_| anyhow!("invalid server name: {}", args.server_name))?;
  let mut stream = connector
    .connect(server_name, stream)
    .await
    .context("failed to establish TURN TLS")?;
  stream
    .write_all(request)
    .await
    .context("failed to write TURN TLS request")?;
  match tokio::time::timeout(Duration::from_millis(750), read_turn_frame(&mut stream)).await {
    Ok(Ok(response)) => Ok(Some(response)),
    Ok(Err(_)) | Err(_) => Ok(None),
  }
}

async fn read_turn_frame<S>(stream: &mut S) -> anyhow::Result<Vec<u8>>
where
  S: tokio::io::AsyncRead + Unpin,
{
  let mut header = [0u8; 4];
  stream
    .read_exact(&mut header)
    .await
    .context("failed to read TURN frame header")?;
  if header[0] & 0b1100_0000 == 0b0100_0000 {
    let len = u16::from_be_bytes([header[2], header[3]]) as usize;
    let padded = len + turn_padding(len);
    let mut frame = Vec::with_capacity(4 + padded);
    frame.extend_from_slice(&header);
    frame.resize(4 + padded, 0);
    stream
      .read_exact(&mut frame[4..])
      .await
      .context("failed to read TURN ChannelData frame")?;
    return Ok(frame);
  }
  let len = u16::from_be_bytes([header[2], header[3]]) as usize;
  let mut frame = Vec::with_capacity(20 + len);
  frame.extend_from_slice(&header);
  frame.resize(20 + len, 0);
  stream
    .read_exact(&mut frame[4..])
    .await
    .context("failed to read STUN frame")?;
  Ok(frame)
}

const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_HEADER_LEN: usize = 20;
const STUN_ALLOCATE_REQUEST: u16 = 0x0003;
const STUN_ATTR_USERNAME: u16 = 0x0006;
const STUN_ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const STUN_ATTR_REALM: u16 = 0x0014;

fn turn_request(args: &TurnClientArgs) -> Vec<u8> {
  let transaction_id = *b"oxibeltprobe";
  let mut attrs = vec![
    (STUN_ATTR_USERNAME, args.username.as_bytes().to_vec()),
    (STUN_ATTR_REALM, args.realm.as_bytes().to_vec()),
  ];
  match args.auth {
    TurnClientAuth::Missing => encode_stun_message(STUN_ALLOCATE_REQUEST, transaction_id, &attrs),
    TurnClientAuth::Invalid => {
      attrs.push((STUN_ATTR_MESSAGE_INTEGRITY, vec![0u8; 20]));
      encode_stun_message(STUN_ALLOCATE_REQUEST, transaction_id, &attrs)
    }
    TurnClientAuth::Valid => {
      let key = turn_long_term_key(&args.username, &args.realm, &args.password);
      with_turn_message_integrity(
        encode_stun_message(STUN_ALLOCATE_REQUEST, transaction_id, &attrs),
        &key,
      )
    }
  }
}

fn encode_stun_message(
  message_type: u16,
  transaction_id: [u8; 12],
  attrs: &[(u16, Vec<u8>)],
) -> Vec<u8> {
  let mut out = Vec::with_capacity(STUN_HEADER_LEN + attrs.len() * 16);
  out.extend_from_slice(&message_type.to_be_bytes());
  out.extend_from_slice(&0u16.to_be_bytes());
  out.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
  out.extend_from_slice(&transaction_id);
  for (kind, value) in attrs {
    append_stun_attr(&mut out, *kind, value);
  }
  let len = (out.len() - STUN_HEADER_LEN) as u16;
  out[2..4].copy_from_slice(&len.to_be_bytes());
  out
}

fn with_turn_message_integrity(mut message: Vec<u8>, key: &[u8]) -> Vec<u8> {
  let final_len = (message.len() + 24 - STUN_HEADER_LEN) as u16;
  message[2..4].copy_from_slice(&final_len.to_be_bytes());
  let integrity = hmac_sha1(key, &message);
  append_stun_attr(&mut message, STUN_ATTR_MESSAGE_INTEGRITY, &integrity);
  message
}

fn append_stun_attr(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
  out.extend_from_slice(&kind.to_be_bytes());
  out.extend_from_slice(&(value.len() as u16).to_be_bytes());
  out.extend_from_slice(value);
  out.resize(out.len() + turn_padding(value.len()), 0);
}

fn turn_padding(len: usize) -> usize {
  (4 - (len % 4)) % 4
}

fn hmac_sha1(key: &[u8], value: &[u8]) -> [u8; 20] {
  let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
  let tag = hmac::sign(&key, value);
  let mut out = [0u8; 20];
  out.copy_from_slice(tag.as_ref());
  out
}

fn turn_long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
  let value = format!("{username}:{realm}:{password}");
  let mut digest = Md5::new();
  digest.update(value.as_bytes());
  digest.finalize().into()
}

fn response_json(
  negotiated_protocol: &str,
  status: StatusCode,
  headers: &HeaderMap,
  body: &[u8],
) -> serde_json::Value {
  serde_json::json!({
    "negotiated_protocol": negotiated_protocol,
    "status": status.as_u16(),
    "reason": status.canonical_reason().unwrap_or(""),
    "headers": header_json(headers),
    "body": String::from_utf8_lossy(body),
  })
}

fn header_json(headers: &HeaderMap) -> BTreeMap<String, String> {
  let mut values = BTreeMap::new();
  for (name, value) in headers {
    if let Ok(value) = value.to_str() {
      values.insert(name.as_str().to_ascii_lowercase(), value.to_string());
    }
  }
  values
}

fn json_response(
  status: StatusCode,
  body: String,
  upstream_marker: Option<&str>,
) -> Response<Full<Bytes>> {
  let mut response = Response::new(Full::new(Bytes::from(body.clone())));
  *response.status_mut() = status;
  response
    .headers_mut()
    .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
  if let Ok(value) = HeaderValue::from_str(&body.len().to_string()) {
    response.headers_mut().insert(CONTENT_LENGTH, value);
  }
  if let Some(marker) = upstream_marker {
    if let Ok(value) = HeaderValue::from_str(marker) {
      response
        .headers_mut()
        .insert(HeaderName::from_static("x-upstream-marker"), value);
    }
  }
  response
}

fn text_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
  let mut response = Response::new(Full::new(Bytes::from(body.to_string())));
  *response.status_mut() = status;
  response
    .headers_mut()
    .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
  response
}

fn version_label(version: Version) -> &'static str {
  match version {
    Version::HTTP_09 => "HTTP/0.9",
    Version::HTTP_10 => "HTTP/1.0",
    Version::HTTP_11 => "HTTP/1.1",
    Version::HTTP_2 => "HTTP/2.0",
    Version::HTTP_3 => "HTTP/3.0",
    _ => "HTTP/unknown",
  }
}

fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
  let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
  CertificateDer::pem_slice_iter(&bytes)
    .collect::<Result<Vec<CertificateDer<'static>>, _>>()
    .with_context(|| format!("failed to parse PEM certificates from {}", path.display()))
}

fn load_private_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
  let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
  PrivateKeyDer::from_pem_slice(&bytes).map_err(|error| match error {
    rustls::pki_types::pem::Error::NoItemsFound => {
      anyhow!("no private key found in {}", path.display())
    }
    error => anyhow!(
      "failed to parse private key from {}: {error}",
      path.display()
    ),
  })
}

fn load_root_store(path: &Path) -> anyhow::Result<RootCertStore> {
  let certs = load_certs(path)?;
  let mut roots = RootCertStore::empty();
  let (added, _ignored) = roots.add_parsable_certificates(certs);
  if added == 0 {
    bail!("no parsable certificates found in {}", path.display());
  }
  Ok(roots)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn chunk_by_offsets_sorts_deduplicates_and_bounds_offsets() {
    let chunks = chunk_by_offsets(b"abcdef", &[3, 0, 3, 9, 1]);
    assert_eq!(chunks, vec![b"a".to_vec(), b"bc".to_vec(), b"def".to_vec()]);
  }

  #[test]
  fn client_hello_view_finds_sni_name() {
    let hello = synthetic_client_hello("example.test");
    let view = client_hello_view(&hello).expect("parse ClientHello");
    assert_eq!(&hello[view.sni_name], b"example.test");
    assert_eq!(view.record.start, 0);
    assert_eq!(view.payload.start, 5);
  }

  #[test]
  fn split_first_tls_record_preserves_handshake_payload() {
    let hello = synthetic_client_hello("example.test");
    let view = client_hello_view(&hello).expect("parse ClientHello");
    let split =
      split_first_tls_record(&hello, &[view.sni_name.start + 1]).expect("split first TLS record");
    assert_eq!(tls_record_count(&hello).expect("count original"), 1);
    assert_eq!(tls_record_count(&split).expect("count split"), 2);
    assert_eq!(
      collect_tls_record_payloads(&split),
      hello[view.payload].to_vec()
    );
  }

  #[test]
  fn dpi_tls_profile_names_round_trip() {
    for name in [
      "byedpi-split-sni",
      "byedpi-tlsrec-sni",
      "goodbyedpi-native-frag",
      "goodbyedpi-frag-by-sni",
      "dpibreak-segment-0-1",
      "dpibreak-segment-0-5",
    ] {
      assert_eq!(DpiTlsProfile::parse(name).unwrap().label(), name);
    }
  }

  fn synthetic_client_hello(server_name: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1);
    body.push(0);

    let mut name_list = Vec::new();
    name_list.push(0);
    name_list.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
    name_list.extend_from_slice(server_name.as_bytes());

    let mut sni_extension = Vec::new();
    sni_extension.extend_from_slice(&(name_list.len() as u16).to_be_bytes());
    sni_extension.extend_from_slice(&name_list);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_extension.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_extension);

    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    push_u24(&mut handshake, body.len());
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
  }

  fn push_u24(output: &mut Vec<u8>, value: usize) {
    assert!(value <= 0xFF_FFFF);
    output.push(((value >> 16) & 0xFF) as u8);
    output.push(((value >> 8) & 0xFF) as u8);
    output.push((value & 0xFF) as u8);
  }

  fn collect_tls_record_payloads(records: &[u8]) -> Vec<u8> {
    let mut cursor = 0usize;
    let mut payloads = Vec::new();
    while cursor < records.len() {
      let len = u16::from_be_bytes([records[cursor + 3], records[cursor + 4]]) as usize;
      let payload_start = cursor + 5;
      let payload_end = payload_start + len;
      payloads.extend_from_slice(&records[payload_start..payload_end]);
      cursor = payload_end;
    }
    payloads
  }
}

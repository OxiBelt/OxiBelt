use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use bytes::{Buf, Bytes};
use h3_quinn::quinn::crypto::rustls::QuicClientConfig;
use h3_quinn::quinn::{ClientConfig as QuinnClientConfig, Endpoint};
use hdrhistogram::Histogram;
use http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ETAG, HOST, IF_NONE_MATCH};
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, HandshakeKind, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::time::Instant;
use tokio_rustls::client::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const MAX_ERROR_SAMPLES: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Protocol {
  H1,
  H1c,
  H2,
  H3,
}

impl Protocol {
  fn parse(raw: &str) -> anyhow::Result<Self> {
    match raw {
      "h1" | "http1" | "http/1.1" => Ok(Self::H1),
      "h1c" | "http1-cleartext" | "http/1.1-cleartext" => Ok(Self::H1c),
      "h2" | "http2" | "http/2" => Ok(Self::H2),
      "h3" | "http3" | "http/3" => Ok(Self::H3),
      _ => bail!("unsupported protocol: {raw}"),
    }
  }

  fn label(self) -> &'static str {
    match self {
      Self::H1 => "h1",
      Self::H1c => "h1c",
      Self::H2 => "h2",
      Self::H3 => "h3",
    }
  }

  fn alpn(self) -> &'static [u8] {
    match self {
      Self::H1 | Self::H1c => b"http/1.1",
      Self::H2 => b"h2",
      Self::H3 => b"h3",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientResumptionMode {
  Fresh,
  Worker,
}

impl ClientResumptionMode {
  fn parse(raw: &str) -> anyhow::Result<Self> {
    match raw {
      "fresh" => Ok(Self::Fresh),
      "worker" => Ok(Self::Worker),
      _ => bail!("unsupported client resumption mode: {raw}"),
    }
  }

  fn label(self) -> &'static str {
    match self {
      Self::Fresh => "fresh",
      Self::Worker => "worker",
    }
  }
}

#[derive(Clone)]
struct LoadArgs {
  label: String,
  protocol: Protocol,
  host: String,
  port: u16,
  server_name: String,
  authority: String,
  path: String,
  ca_cert: String,
  duration: Duration,
  warmup: Duration,
  concurrency: usize,
  expect_status: u16,
  unique_query_param: Option<String>,
  request_serial: Arc<AtomicU64>,
}

#[derive(Clone)]
struct HandshakeArgs {
  label: String,
  protocol: Protocol,
  host: String,
  port: u16,
  server_name: String,
  ca_cert: String,
  duration: Duration,
  concurrency: usize,
  client_resumption: ClientResumptionMode,
  post_handshake_observe: Duration,
}

#[derive(Clone, Debug)]
struct StressArgs {
  label: String,
  mode: String,
  protocol: Protocol,
  host: String,
  port: u16,
  server_name: Option<String>,
  authority: String,
  path: String,
  ca_cert: Option<String>,
  expect_status: Option<u16>,
  connections: usize,
  duration: Duration,
  bytes: usize,
  chunk_bytes: usize,
  chunk_delay: Duration,
  streams_per_connection: usize,
}

#[derive(Clone)]
struct MetricsArgs {
  label: String,
  host: String,
  port: u16,
  authority: String,
  path: String,
}

struct UpstreamArgs {
  listen: SocketAddr,
  name: String,
  protocol: UpstreamProtocol,
  cert: Option<String>,
  key: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UpstreamProtocol {
  H1,
  H2c,
  H2,
}

impl UpstreamProtocol {
  fn parse(raw: &str) -> anyhow::Result<Self> {
    match raw {
      "h1" | "http1" | "http/1.1" => Ok(Self::H1),
      "h2c" | "http2-cleartext" | "http/2-cleartext" => Ok(Self::H2c),
      "h2" | "http2" | "http/2" => Ok(Self::H2),
      _ => bail!("unsupported upstream protocol: {raw}"),
    }
  }
}

struct H3ClientConnection {
  _endpoint: Endpoint,
  connection: h3_quinn::quinn::Connection,
}

#[derive(Clone, Copy, Debug, Default)]
struct HandshakeKindCounts {
  full: u64,
  full_with_hello_retry_request: u64,
  resumed: u64,
  unknown: u64,
}

impl HandshakeKindCounts {
  fn record(&mut self, kind: Option<HandshakeKind>) {
    match kind {
      Some(HandshakeKind::Full) => self.full += 1,
      Some(HandshakeKind::FullWithHelloRetryRequest) => {
        self.full_with_hello_retry_request += 1;
      }
      Some(HandshakeKind::Resumed) => self.resumed += 1,
      None => self.unknown += 1,
    }
  }
}

#[derive(Debug, Default)]
struct HandshakeObservation {
  kind: Option<HandshakeKind>,
  tls13_tickets_received: u32,
  negotiated_key_exchange_group: Option<String>,
}

#[derive(Clone)]
struct SharedStats {
  inner: Arc<Mutex<StatsInner>>,
}

struct StatsInner {
  requests: u64,
  errors: u64,
  statuses: BTreeMap<u16, u64>,
  latency: Histogram<u64>,
  error_samples: Vec<String>,
  handshake_kinds: HandshakeKindCounts,
  tls13_tickets_received: u64,
  negotiated_key_exchange_groups: BTreeMap<String, u64>,
}

impl SharedStats {
  fn new() -> anyhow::Result<Self> {
    Ok(Self {
      inner: Arc::new(Mutex::new(StatsInner {
        requests: 0,
        errors: 0,
        statuses: BTreeMap::new(),
        latency: Histogram::new(3).context("failed to create latency histogram")?,
        error_samples: Vec::new(),
        handshake_kinds: HandshakeKindCounts::default(),
        tls13_tickets_received: 0,
        negotiated_key_exchange_groups: BTreeMap::new(),
      })),
    })
  }

  fn record_response(&self, status: u16, elapsed: Duration, expect_status: u16) {
    let mut inner = self
      .inner
      .lock()
      .expect("stats mutex should not be poisoned");
    inner.requests += 1;
    *inner.statuses.entry(status).or_insert(0) += 1;
    if status != expect_status {
      inner.errors += 1;
      push_error_sample(
        &mut inner,
        format!("unexpected status {status}, expected {expect_status}"),
      );
    }
    let micros = elapsed.as_micros().min(u128::from(u64::MAX)) as u64;
    let _ = inner.latency.record(micros.max(1));
  }

  fn record_handshake_success(&self, elapsed: Duration, observation: HandshakeObservation) {
    let mut inner = self
      .inner
      .lock()
      .expect("stats mutex should not be poisoned");
    inner.requests += 1;
    inner.handshake_kinds.record(observation.kind);
    inner.tls13_tickets_received += u64::from(observation.tls13_tickets_received);
    if let Some(group) = observation.negotiated_key_exchange_group {
      *inner
        .negotiated_key_exchange_groups
        .entry(group)
        .or_insert(0) += 1;
    }
    let micros = elapsed.as_micros().min(u128::from(u64::MAX)) as u64;
    let _ = inner.latency.record(micros.max(1));
  }

  fn record_success(&self, elapsed: Duration) {
    let mut inner = self
      .inner
      .lock()
      .expect("stats mutex should not be poisoned");
    inner.requests += 1;
    let micros = elapsed.as_micros().min(u128::from(u64::MAX)) as u64;
    let _ = inner.latency.record(micros.max(1));
  }

  fn record_status(&self, status: u16) {
    let mut inner = self
      .inner
      .lock()
      .expect("stats mutex should not be poisoned");
    inner.requests += 1;
    *inner.statuses.entry(status).or_insert(0) += 1;
  }

  fn record_error_sample(&self, message: impl Into<String>) {
    let mut inner = self
      .inner
      .lock()
      .expect("stats mutex should not be poisoned");
    inner.errors += 1;
    push_error_sample(&mut inner, message);
  }

  fn snapshot(&self) -> StatsSnapshot {
    let inner = self
      .inner
      .lock()
      .expect("stats mutex should not be poisoned");
    StatsSnapshot {
      requests: inner.requests,
      errors: inner.errors,
      statuses: inner.statuses.clone(),
      p50_ms: percentile_ms(&inner.latency, 50.0),
      p95_ms: percentile_ms(&inner.latency, 95.0),
      p99_ms: percentile_ms(&inner.latency, 99.0),
      error_samples: inner.error_samples.clone(),
      handshake_kinds: inner.handshake_kinds,
      tls13_tickets_received: inner.tls13_tickets_received,
      negotiated_key_exchange_groups: inner.negotiated_key_exchange_groups.clone(),
    }
  }
}

fn push_error_sample(inner: &mut StatsInner, message: impl Into<String>) {
  if inner.error_samples.len() < MAX_ERROR_SAMPLES {
    inner.error_samples.push(message.into());
  }
}

struct StatsSnapshot {
  requests: u64,
  errors: u64,
  statuses: BTreeMap<u16, u64>,
  p50_ms: f64,
  p95_ms: f64,
  p99_ms: f64,
  error_samples: Vec<String>,
  handshake_kinds: HandshakeKindCounts,
  tls13_tickets_received: u64,
  negotiated_key_exchange_groups: BTreeMap<String, u64>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let mut args = std::env::args().skip(1);
  let Some(command) = args.next() else {
    usage();
    bail!("missing command");
  };

  match command.as_str() {
    "upstream" => serve_upstream(parse_upstream_args(args)?).await,
    "load" => run_load(parse_load_args(args)?).await,
    "handshake" => run_handshake(parse_handshake_args(args)?).await,
    "stress" => run_stress(parse_stress_args(args)?).await,
    "metrics" => run_metrics(parse_metrics_args(args)?).await,
    _ => {
      usage();
      bail!("unknown command: {command}");
    }
  }
}

fn usage() {
  eprintln!(
        "usage:
  perf-probe upstream --listen <addr:port> [--name <name>] [--protocol <h1|h2c|h2>] [--cert <pem> --key <pem>]
  perf-probe load --protocol <h1|h1c|h2|h3> --host <host> --port <port> --server-name <name> --authority <authority> --path <path> --ca-cert <pem> --duration-seconds <n> --warmup-seconds <n> --concurrency <n> [--expect-status <status>] [--label <label>] [--unique-query-param <name>]
  perf-probe handshake --protocol <h1|h2|h3> --host <host> --port <port> --server-name <name> --ca-cert <pem> --duration-seconds <n> --concurrency <n> [--label <label>] [--client-resumption fresh|worker] [--post-handshake-observe-ms <n>]
  perf-probe stress --mode <slowloris|large-header|large-body|idle|half-close|slow-post|slow-response|h2-rapid-stream-churn|h2-cl0-data|h3-cl0-data> --host <host> --port <port> --authority <authority> --connections <n> --duration-seconds <n> [--bytes <n>] [--label <label>] [--protocol <h1c|h1|h2|h3>] [--server-name <name>] [--ca-cert <pem>] [--path <path>] [--expect-status <status>] [--chunk-bytes <n>] [--chunk-delay-ms <n>] [--streams-per-connection <n>]
  perf-probe metrics --host <host> --port <port> --authority <authority> --path <path> [--label <label>]"
    );
}

fn parse_upstream_args(args: impl Iterator<Item = String>) -> anyhow::Result<UpstreamArgs> {
  let values = flag_map(args)?;
  Ok(UpstreamArgs {
    listen: required(&values, "--listen")?
      .parse()
      .context("invalid --listen value")?,
    name: values
      .get("--name")
      .cloned()
      .unwrap_or_else(|| "perf-upstream".to_owned()),
    protocol: values
      .get("--protocol")
      .map(|value| UpstreamProtocol::parse(value))
      .transpose()?
      .unwrap_or(UpstreamProtocol::H1),
    cert: values.get("--cert").cloned(),
    key: values.get("--key").cloned(),
  })
}

fn parse_load_args(args: impl Iterator<Item = String>) -> anyhow::Result<LoadArgs> {
  let values = flag_map(args)?;
  let protocol = Protocol::parse(required(&values, "--protocol")?)?;
  let host = required(&values, "--host")?.to_owned();
  let port = parse_u16(&values, "--port")?;
  let authority = values
    .get("--authority")
    .cloned()
    .unwrap_or_else(|| host.clone());
  let unique_query_param = values
    .get("--unique-query-param")
    .map(|value| validate_unique_query_param(value))
    .transpose()?;
  Ok(LoadArgs {
    label: values
      .get("--label")
      .cloned()
      .unwrap_or_else(|| format!("load-{}", protocol.label())),
    protocol,
    host,
    port,
    server_name: required(&values, "--server-name")?.to_owned(),
    authority,
    path: required(&values, "--path")?.to_owned(),
    ca_cert: required(&values, "--ca-cert")?.to_owned(),
    duration: Duration::from_secs(parse_u64(&values, "--duration-seconds")?),
    warmup: Duration::from_secs(parse_u64(&values, "--warmup-seconds")?),
    concurrency: parse_usize(&values, "--concurrency")?,
    expect_status: values
      .get("--expect-status")
      .map(|value| value.parse().context("invalid --expect-status value"))
      .transpose()?
      .unwrap_or(200),
    unique_query_param,
    request_serial: Arc::new(AtomicU64::new(0)),
  })
}

fn parse_handshake_args(args: impl Iterator<Item = String>) -> anyhow::Result<HandshakeArgs> {
  let values = flag_map(args)?;
  let protocol = Protocol::parse(required(&values, "--protocol")?)?;
  let client_resumption = values
    .get("--client-resumption")
    .map(|value| ClientResumptionMode::parse(value))
    .transpose()?
    .unwrap_or(ClientResumptionMode::Fresh);
  let post_handshake_observe = values
    .get("--post-handshake-observe-ms")
    .map(|value| {
      value
        .parse::<u64>()
        .context("invalid --post-handshake-observe-ms value")
    })
    .transpose()?
    .unwrap_or(0);
  if client_resumption == ClientResumptionMode::Worker
    && !matches!(protocol, Protocol::H1 | Protocol::H2)
  {
    bail!("--client-resumption worker is only supported for h1 and h2 handshake probes");
  }
  Ok(HandshakeArgs {
    label: values
      .get("--label")
      .cloned()
      .unwrap_or_else(|| format!("handshake-{}", protocol.label())),
    protocol,
    host: required(&values, "--host")?.to_owned(),
    port: parse_u16(&values, "--port")?,
    server_name: required(&values, "--server-name")?.to_owned(),
    ca_cert: required(&values, "--ca-cert")?.to_owned(),
    duration: Duration::from_secs(parse_u64(&values, "--duration-seconds")?),
    concurrency: parse_usize(&values, "--concurrency")?,
    client_resumption,
    post_handshake_observe: Duration::from_millis(post_handshake_observe),
  })
}

fn parse_stress_args(args: impl Iterator<Item = String>) -> anyhow::Result<StressArgs> {
  let values = flag_map(args)?;
  let mode = required(&values, "--mode")?.to_owned();
  let protocol = values
    .get("--protocol")
    .map(|value| Protocol::parse(value))
    .transpose()?
    .unwrap_or_else(|| default_stress_protocol(&mode));
  validate_stress_protocol(&mode, protocol)?;
  let chunk_bytes = values
    .get("--chunk-bytes")
    .map(|value| value.parse().context("invalid --chunk-bytes value"))
    .transpose()?
    .unwrap_or(1024usize);
  if chunk_bytes == 0 {
    bail!("--chunk-bytes must be greater than zero");
  }
  let streams_per_connection = values
    .get("--streams-per-connection")
    .map(|value| {
      value
        .parse()
        .context("invalid --streams-per-connection value")
    })
    .transpose()?
    .unwrap_or(64usize);
  if streams_per_connection == 0 {
    bail!("--streams-per-connection must be greater than zero");
  }
  Ok(StressArgs {
    label: values
      .get("--label")
      .cloned()
      .unwrap_or_else(|| format!("stress-{mode}")),
    mode,
    protocol,
    host: required(&values, "--host")?.to_owned(),
    port: parse_u16(&values, "--port")?,
    server_name: values.get("--server-name").cloned(),
    authority: required(&values, "--authority")?.to_owned(),
    path: values
      .get("--path")
      .cloned()
      .unwrap_or_else(|| "/perf/stress?body=ok".to_owned()),
    ca_cert: values.get("--ca-cert").cloned(),
    expect_status: values
      .get("--expect-status")
      .map(|value| value.parse().context("invalid --expect-status value"))
      .transpose()?,
    connections: parse_usize(&values, "--connections")?,
    duration: Duration::from_secs(parse_u64(&values, "--duration-seconds")?),
    bytes: values
      .get("--bytes")
      .map(|value| value.parse().context("invalid --bytes value"))
      .transpose()?
      .unwrap_or(1024 * 1024),
    chunk_bytes,
    chunk_delay: Duration::from_millis(
      values
        .get("--chunk-delay-ms")
        .map(|value| value.parse().context("invalid --chunk-delay-ms value"))
        .transpose()?
        .unwrap_or(50),
    ),
    streams_per_connection,
  })
}

fn default_stress_protocol(mode: &str) -> Protocol {
  match mode {
    "h2-rapid-stream-churn" | "h2-cl0-data" => Protocol::H2,
    "h3-cl0-data" => Protocol::H3,
    _ => Protocol::H1c,
  }
}

fn validate_stress_protocol(mode: &str, protocol: Protocol) -> anyhow::Result<()> {
  match mode {
    "slowloris" | "large-header" | "large-body" | "idle" | "half-close" | "slow-post"
    | "slow-response" => {
      if protocol != Protocol::H1c {
        bail!("{mode} stress mode currently supports only protocol h1c");
      }
    }
    "h2-rapid-stream-churn" | "h2-cl0-data" => {
      if protocol != Protocol::H2 {
        bail!("{mode} stress mode requires protocol h2");
      }
    }
    "h3-cl0-data" => {
      if protocol != Protocol::H3 {
        bail!("{mode} stress mode requires protocol h3");
      }
    }
    _ => bail!("unsupported stress mode: {mode}"),
  }
  Ok(())
}

fn parse_metrics_args(args: impl Iterator<Item = String>) -> anyhow::Result<MetricsArgs> {
  let values = flag_map(args)?;
  Ok(MetricsArgs {
    label: values
      .get("--label")
      .cloned()
      .unwrap_or_else(|| "metrics".to_owned()),
    host: required(&values, "--host")?.to_owned(),
    port: parse_u16(&values, "--port")?,
    authority: required(&values, "--authority")?.to_owned(),
    path: required(&values, "--path")?.to_owned(),
  })
}

fn flag_map(args: impl Iterator<Item = String>) -> anyhow::Result<BTreeMap<String, String>> {
  let mut values = BTreeMap::new();
  let mut args = args.peekable();
  while let Some(flag) = args.next() {
    if !flag.starts_with("--") {
      bail!("expected flag, got {flag}");
    }
    let value = args
      .next()
      .ok_or_else(|| anyhow!("missing value for {flag}"))?;
    values.insert(flag, value);
  }
  Ok(values)
}

fn required<'a>(values: &'a BTreeMap<String, String>, flag: &str) -> anyhow::Result<&'a str> {
  values
    .get(flag)
    .map(String::as_str)
    .ok_or_else(|| anyhow!("missing {flag}"))
}

fn parse_u64(values: &BTreeMap<String, String>, flag: &str) -> anyhow::Result<u64> {
  required(values, flag)?
    .parse()
    .with_context(|| format!("invalid {flag} value"))
}

fn parse_u16(values: &BTreeMap<String, String>, flag: &str) -> anyhow::Result<u16> {
  required(values, flag)?
    .parse()
    .with_context(|| format!("invalid {flag} value"))
}

fn parse_usize(values: &BTreeMap<String, String>, flag: &str) -> anyhow::Result<usize> {
  let value = required(values, flag)?
    .parse()
    .with_context(|| format!("invalid {flag} value"))?;
  if value == 0 {
    bail!("{flag} must be greater than zero");
  }
  Ok(value)
}

fn validate_unique_query_param(value: &str) -> anyhow::Result<String> {
  if value.is_empty()
    || !value
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
  {
    bail!("--unique-query-param must be a non-empty ASCII query parameter name");
  }
  Ok(value.to_owned())
}

async fn serve_upstream(args: UpstreamArgs) -> anyhow::Result<()> {
  let listener = TcpListener::bind(args.listen)
    .await
    .with_context(|| format!("failed to bind upstream to {}", args.listen))?;
  let name = Arc::<str>::from(args.name);
  let tls_acceptor = match args.protocol {
    UpstreamProtocol::H1 | UpstreamProtocol::H2c => None,
    UpstreamProtocol::H2 => Some(upstream_tls_acceptor(
      args
        .cert
        .as_deref()
        .ok_or_else(|| anyhow!("--cert is required for h2 upstream"))?,
      args
        .key
        .as_deref()
        .ok_or_else(|| anyhow!("--key is required for h2 upstream"))?,
    )?),
  };

  loop {
    let (stream, peer_addr) = listener.accept().await.context("failed to accept TCP")?;
    let name = name.clone();
    match (args.protocol, tls_acceptor.clone()) {
      (UpstreamProtocol::H1, _) => {
        tokio::spawn(async move {
          let service = service_fn(move |request| {
            let name = name.clone();
            async move { Ok::<_, Infallible>(upstream_response(request, name).await) }
          });
          if let Err(error) = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await
          {
            eprintln!("upstream HTTP/1.1 connection from {peer_addr} failed: {error}");
          }
        });
      }
      (UpstreamProtocol::H2c, _) => {
        tokio::spawn(async move {
          let service = service_fn(move |request| {
            let name = name.clone();
            async move { Ok::<_, Infallible>(upstream_response(request, name).await) }
          });
          if let Err(error) = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await
          {
            eprintln!("upstream h2c connection from {peer_addr} failed: {error}");
          }
        });
      }
      (UpstreamProtocol::H2, Some(acceptor)) => {
        tokio::spawn(async move {
          let service = service_fn(move |request| {
            let name = name.clone();
            async move { Ok::<_, Infallible>(upstream_response(request, name).await) }
          });
          let stream = match acceptor.accept(stream).await {
            Ok(stream) => stream,
            Err(error) => {
              eprintln!("upstream TLS handshake from {peer_addr} failed: {error}");
              return;
            }
          };
          if let Err(error) = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await
          {
            eprintln!("upstream HTTP/2 connection from {peer_addr} failed: {error}");
          }
        });
      }
      (UpstreamProtocol::H2, None) => {
        eprintln!("upstream HTTP/2 connection from {peer_addr} skipped: TLS is not configured");
      }
    }
  }
}

fn upstream_tls_acceptor(cert_path: &str, key_path: &str) -> anyhow::Result<TlsAcceptor> {
  let certs = load_certs(Path::new(cert_path))?;
  let key = load_private_key(Path::new(key_path))?;
  let mut config = ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .context("failed to build upstream TLS server config")?;
  config.alpn_protocols = vec![b"h2".to_vec()];
  Ok(TlsAcceptor::from(Arc::new(config)))
}

async fn upstream_response(
  request: Request<Incoming>,
  name: Arc<str>,
) -> Response<BoxBody<Bytes, Infallible>> {
  let (parts, body) = request.into_parts();
  let query = parse_query(parts.uri.query().unwrap_or(""));
  if let Some(delay) = query_duration(&query, "response_delay_ms") {
    tokio::time::sleep(delay).await;
  }
  let status = query
    .get("status")
    .and_then(|value| value.parse::<u16>().ok())
    .and_then(|value| StatusCode::from_u16(value).ok())
    .or_else(|| status_from_path(parts.uri.path()))
    .unwrap_or(StatusCode::OK);
  let etag = query.get("etag").cloned().unwrap_or_default();
  if !etag.is_empty()
    && parts
      .headers
      .get(IF_NONE_MATCH)
      .and_then(|value| value.to_str().ok())
      == Some(etag.as_str())
  {
    let mut response = Response::new(Full::new(Bytes::new()).boxed());
    *response.status_mut() = StatusCode::NOT_MODIFIED;
    response.headers_mut().insert(
      ETAG,
      etag.parse().unwrap_or_else(|_| "\"perf\"".parse().unwrap()),
    );
    return response;
  }

  let request_body = body
    .collect()
    .await
    .map(|collected| collected.to_bytes())
    .unwrap_or_default();
  let body = response_body(&query, &parts.uri, &parts.headers, &request_body, &name);
  let body = Bytes::from(body);
  let streaming_response = query.contains_key("response_chunk_delay_ms");
  let response_body = response_body_stream(&query, body.clone());
  let mut response = Response::new(response_body);
  *response.status_mut() = status;
  response.headers_mut().insert(
    CONTENT_TYPE,
    query
      .get("content_type")
      .map(String::as_str)
      .unwrap_or("text/plain")
      .parse()
      .unwrap_or_else(|_| "text/plain".parse().unwrap()),
  );
  if !streaming_response {
    response.headers_mut().insert(
      CONTENT_LENGTH,
      body
        .len()
        .to_string()
        .parse()
        .expect("valid content-length"),
    );
  }
  response
    .headers_mut()
    .insert("x-upstream-marker", "perf-upstream".parse().unwrap());
  if let Some(cache_control) = cache_control_value(&query) {
    response
      .headers_mut()
      .insert(CACHE_CONTROL, cache_control.parse().unwrap());
  }
  if !etag.is_empty() {
    response.headers_mut().insert(
      ETAG,
      etag.parse().unwrap_or_else(|_| "\"perf\"".parse().unwrap()),
    );
  }
  response
}

fn response_body_stream(
  query: &BTreeMap<String, String>,
  body: Bytes,
) -> BoxBody<Bytes, Infallible> {
  let Some(chunk_delay) = query_duration(query, "response_chunk_delay_ms") else {
    return Full::new(body).boxed();
  };
  let chunk_bytes = query
    .get("response_chunk_bytes")
    .and_then(|value| value.parse::<usize>().ok())
    .filter(|value| *value > 0)
    .unwrap_or(1024);
  StreamBody::new(futures_util::stream::unfold(
    (0usize, body, false),
    move |(sent, body, delayed)| async move {
      if sent >= body.len() {
        return None;
      }
      if delayed {
        tokio::time::sleep(chunk_delay).await;
      }
      let next = (sent + chunk_bytes).min(body.len());
      let chunk = body.slice(sent..next);
      Some((Ok(Frame::data(chunk)), (next, body, true)))
    },
  ))
  .boxed()
}

fn response_body(
  query: &BTreeMap<String, String>,
  uri: &Uri,
  headers: &HeaderMap,
  request_body: &[u8],
  name: &str,
) -> String {
  if let Some(repeat) = query.get("body_repeat") {
    if let Ok(count) = repeat.parse::<usize>() {
      let byte = query
        .get("body_repeat_char")
        .and_then(|value| value.as_bytes().first().copied())
        .unwrap_or(b'x');
      return String::from_utf8(vec![byte; count]).unwrap_or_default();
    }
  }
  if let Some(body) = query.get("body") {
    return body.clone();
  }
  if query.get("json").map(String::as_str) == Some("1") {
    return serde_json::json!({
        "upstream": name,
        "method": uri.path(),
        "path": uri.path_and_query().map(|value| value.as_str()).unwrap_or("/"),
        "host": headers.get(HOST).and_then(|value| value.to_str().ok()).unwrap_or(""),
        "body_bytes": request_body.len(),
    })
    .to_string();
  }
  "ok\n".to_owned()
}

fn cache_control_value(query: &BTreeMap<String, String>) -> Option<&str> {
  match query.get("cache_control").map(String::as_str) {
    Some("public") => Some("public, max-age=60"),
    Some("public-max-age-1") => Some("public, max-age=1"),
    Some("public-stale-revalidate") => Some("public, max-age=1, stale-while-revalidate=30"),
    Some("public-stale-error") => Some("public, max-age=1, stale-if-error=30"),
    Some("private") => Some("private"),
    Some("no-store") => Some("no-store"),
    _ => query.get("cache_control_value").map(String::as_str),
  }
}

fn query_duration(query: &BTreeMap<String, String>, key: &str) -> Option<Duration> {
  query
    .get(key)
    .and_then(|value| value.parse::<u64>().ok())
    .map(Duration::from_millis)
}

fn parse_query(raw: &str) -> BTreeMap<String, String> {
  raw
    .split('&')
    .filter(|part| !part.is_empty())
    .map(|part| part.split_once('=').unwrap_or((part, "")))
    .map(|(key, value)| (key.to_owned(), value.replace('+', " ")))
    .collect()
}

fn status_from_path(path: &str) -> Option<StatusCode> {
  let raw_status = path.strip_prefix("/status/")?.split('/').next()?;
  raw_status
    .parse::<u16>()
    .ok()
    .and_then(|status| StatusCode::from_u16(status).ok())
}

async fn run_load(args: LoadArgs) -> anyhow::Result<()> {
  if args.warmup > Duration::ZERO {
    let _ = run_load_phase(args.clone(), args.warmup, false).await?;
  }
  let stats = run_load_phase(args.clone(), args.duration, true).await?;
  let snapshot = stats.snapshot();
  let elapsed = args.duration.as_secs_f64();
  println!(
    "{}",
    serde_json::json!({
        "type": "load",
        "label": args.label,
        "protocol": args.protocol.label(),
        "duration_seconds": args.duration.as_secs(),
        "warmup_seconds": args.warmup.as_secs(),
        "concurrency": args.concurrency,
        "requests": snapshot.requests,
        "errors": snapshot.errors,
        "rps": rate(snapshot.requests, elapsed),
        "p50_ms": snapshot.p50_ms,
        "p95_ms": snapshot.p95_ms,
        "p99_ms": snapshot.p99_ms,
        "statuses": status_json(snapshot.statuses),
        "error_samples": snapshot.error_samples,
        "unique_query_param": args.unique_query_param,
    })
  );
  Ok(())
}

async fn run_load_phase(
  args: LoadArgs,
  duration: Duration,
  record: bool,
) -> anyhow::Result<SharedStats> {
  let deadline = Instant::now() + duration;
  let stats = SharedStats::new()?;
  let mut tasks = Vec::with_capacity(args.concurrency);
  for _ in 0..args.concurrency {
    let args = args.clone();
    let stats = stats.clone();
    tasks.push(tokio::spawn(async move {
      match args.protocol {
        Protocol::H1 => h1_load_worker(args, deadline, stats, record).await,
        Protocol::H1c => h1c_load_worker(args, deadline, stats, record).await,
        Protocol::H2 => h2_load_worker(args, deadline, stats, record).await,
        Protocol::H3 => h3_load_worker(args, deadline, stats, record).await,
      }
    }));
  }
  for task in tasks {
    task.await.context("load worker task panicked")?;
  }
  Ok(stats)
}

async fn h1_load_worker(args: LoadArgs, deadline: Instant, stats: SharedStats, record: bool) {
  while Instant::now() < deadline {
    if let Err(error) = h1_connection_loop(&args, deadline, &stats, record).await {
      if record_worker_error("h1", &error, deadline, &stats, record) {
        tokio::time::sleep(Duration::from_millis(50)).await;
      }
    }
  }
}

fn worker_error_is_in_window(record: bool, deadline: Instant) -> bool {
  record && Instant::now() < deadline
}

fn record_worker_error(
  protocol: &str,
  error: &anyhow::Error,
  deadline: Instant,
  stats: &SharedStats,
  record: bool,
) -> bool {
  let message = format!("{error:#}");
  let before_deadline = Instant::now() < deadline;
  if worker_error_is_in_window(record, deadline) {
    stats.record_error_sample(message.clone());
    eprintln!("{protocol} worker reconnecting after error: {message}");
    true
  } else if before_deadline {
    eprintln!("{protocol} worker reconnecting after unrecorded error: {message}");
    true
  } else {
    eprintln!("{protocol} worker stopped after phase-boundary error: {message}");
    false
  }
}

async fn h1c_load_worker(args: LoadArgs, deadline: Instant, stats: SharedStats, record: bool) {
  while Instant::now() < deadline {
    if let Err(error) = h1c_connection_loop(&args, deadline, &stats, record).await {
      if record_worker_error("h1c", &error, deadline, &stats, record) {
        tokio::time::sleep(Duration::from_millis(50)).await;
      }
    }
  }
}

async fn h1c_connection_loop(
  args: &LoadArgs,
  deadline: Instant,
  stats: &SharedStats,
  record: bool,
) -> anyhow::Result<()> {
  let stream = TcpStream::connect((args.host.as_str(), args.port))
    .await
    .context("failed to connect cleartext HTTP/1.1 socket")?;
  let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
    .await
    .context("failed to establish cleartext HTTP/1.1 client")?;
  let connection_task = tokio::spawn(async move {
    let _ = connection.await;
  });

  while Instant::now() < deadline {
    let started = Instant::now();
    let response = sender
      .send_request(request(args, Version::HTTP_11, Full::new(Bytes::new()))?)
      .await
      .context("failed to send cleartext HTTP/1.1 request")?;
    let status = response.status().as_u16();
    response
      .into_body()
      .collect()
      .await
      .context("failed to read cleartext HTTP/1.1 response body")?;
    if record {
      stats.record_response(status, started.elapsed(), args.expect_status);
    }
  }

  drop(sender);
  let _ = connection_task.await;
  Ok(())
}

async fn h1_connection_loop(
  args: &LoadArgs,
  deadline: Instant,
  stats: &SharedStats,
  record: bool,
) -> anyhow::Result<()> {
  let tls_stream = tls_connect(
    &args.host,
    args.port,
    &args.server_name,
    &args.ca_cert,
    args.protocol.alpn(),
  )
  .await?;
  let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
    .await
    .context("failed to establish HTTP/1.1 client")?;
  let connection_task = tokio::spawn(async move {
    let _ = connection.await;
  });

  while Instant::now() < deadline {
    let started = Instant::now();
    let response = sender
      .send_request(request(args, Version::HTTP_11, Full::new(Bytes::new()))?)
      .await
      .context("failed to send HTTP/1.1 request")?;
    let status = response.status().as_u16();
    response
      .into_body()
      .collect()
      .await
      .context("failed to read HTTP/1.1 response body")?;
    if record {
      stats.record_response(status, started.elapsed(), args.expect_status);
    }
  }

  drop(sender);
  let _ = connection_task.await;
  Ok(())
}

async fn h2_load_worker(args: LoadArgs, deadline: Instant, stats: SharedStats, record: bool) {
  while Instant::now() < deadline {
    if let Err(error) = h2_connection_loop(&args, deadline, &stats, record).await {
      if record_worker_error("h2", &error, deadline, &stats, record) {
        tokio::time::sleep(Duration::from_millis(50)).await;
      }
    }
  }
}

async fn h2_connection_loop(
  args: &LoadArgs,
  deadline: Instant,
  stats: &SharedStats,
  record: bool,
) -> anyhow::Result<()> {
  let tls_stream = tls_connect(
    &args.host,
    args.port,
    &args.server_name,
    &args.ca_cert,
    args.protocol.alpn(),
  )
  .await?;
  let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
    .handshake(TokioIo::new(tls_stream))
    .await
    .context("failed to establish HTTP/2 client")?;
  let connection_task = tokio::spawn(async move {
    let _ = connection.await;
  });

  while Instant::now() < deadline {
    let started = Instant::now();
    let response = sender
      .send_request(request(args, Version::HTTP_2, Full::new(Bytes::new()))?)
      .await
      .context("failed to send HTTP/2 request")?;
    let status = response.status().as_u16();
    response
      .into_body()
      .collect()
      .await
      .context("failed to read HTTP/2 response body")?;
    if record {
      stats.record_response(status, started.elapsed(), args.expect_status);
    }
  }

  drop(sender);
  let _ = connection_task.await;
  Ok(())
}

async fn h3_load_worker(args: LoadArgs, deadline: Instant, stats: SharedStats, record: bool) {
  while Instant::now() < deadline {
    if let Err(error) = h3_connection_loop(&args, deadline, &stats, record).await {
      if record_worker_error("h3", &error, deadline, &stats, record) {
        tokio::time::sleep(Duration::from_millis(50)).await;
      }
    }
  }
}

async fn h3_connection_loop(
  args: &LoadArgs,
  deadline: Instant,
  stats: &SharedStats,
  record: bool,
) -> anyhow::Result<()> {
  let h3_client = h3_connect(
    &args.host,
    args.port,
    &args.server_name,
    &args.ca_cert,
    args.protocol.alpn(),
  )
  .await?;
  let close_connection = h3_client.connection.clone();
  let h3_connection = h3_quinn::Connection::new(h3_client.connection);
  let mut builder = h3::client::builder();
  builder.send_grease(false);
  let (mut driver, mut send_request) = builder
    .build::<_, _, Bytes>(h3_connection)
    .await
    .context("failed to establish HTTP/3 client")?;
  let driver_task = tokio::spawn(async move {
    let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
  });

  while Instant::now() < deadline {
    let started = Instant::now();
    let mut stream = send_request
      .send_request(request(args, Version::HTTP_3, ())?)
      .await
      .context("failed to send HTTP/3 request")?;
    stream
      .finish()
      .await
      .context("failed to finish HTTP/3 request")?;
    let response = stream
      .recv_response()
      .await
      .context("failed to receive HTTP/3 response")?;
    while let Some(mut chunk) = stream
      .recv_data()
      .await
      .context("failed to read HTTP/3 response body")?
    {
      let len = chunk.remaining();
      let _ = chunk.copy_to_bytes(len);
    }
    if record {
      stats.record_response(
        response.status().as_u16(),
        started.elapsed(),
        args.expect_status,
      );
    }
  }

  close_connection.close(0u32.into(), b"perf-probe complete");
  let _ = driver_task.await;
  Ok(())
}

fn request<B>(args: &LoadArgs, version: Version, body: B) -> anyhow::Result<Request<B>> {
  let path = request_path(args);
  let uri: Uri = if version == Version::HTTP_11 {
    path.parse().context("failed to build HTTP/1.1 URI")?
  } else {
    format!("https://{}{}", args.authority, path)
      .parse()
      .context("failed to build request URI")?
  };
  let mut request = Request::builder()
    .method(Method::GET)
    .uri(uri)
    .version(version);
  if version == Version::HTTP_11 {
    request = request.header(HOST, args.authority.as_str());
  }
  request.body(body).map_err(Into::into)
}

fn request_path(args: &LoadArgs) -> String {
  let Some(param) = &args.unique_query_param else {
    return args.path.clone();
  };
  let serial = args.request_serial.fetch_add(1, Ordering::Relaxed);
  let separator = if args.path.contains('?') { '&' } else { '?' };
  format!("{}{separator}{param}={serial}", args.path)
}

async fn run_handshake(args: HandshakeArgs) -> anyhow::Result<()> {
  let deadline = Instant::now() + args.duration;
  let stats = SharedStats::new()?;
  let mut tasks = Vec::with_capacity(args.concurrency);
  for _ in 0..args.concurrency {
    let args = args.clone();
    let stats = stats.clone();
    tasks.push(tokio::spawn(async move {
      let worker_tls_config = match worker_tls_config(&args) {
        Ok(config) => config,
        Err(error) => {
          let message = format!("{error:#}");
          stats.record_error_sample(message.clone());
          eprintln!("handshake worker failed to initialize: {message}");
          return;
        }
      };
      while Instant::now() < deadline {
        let started = Instant::now();
        let result = run_single_handshake(&args, worker_tls_config.clone()).await;
        match result {
          Ok(observation) => stats.record_handshake_success(started.elapsed(), observation),
          Err(error) => {
            let message = format!("{error:#}");
            stats.record_error_sample(message.clone());
            eprintln!("handshake failed: {message}");
            tokio::time::sleep(Duration::from_millis(50)).await;
          }
        }
      }
    }));
  }
  for task in tasks {
    task.await.context("handshake worker task panicked")?;
  }

  let snapshot = stats.snapshot();
  println!(
    "{}",
    serde_json::json!({
        "type": "handshake",
        "label": args.label,
        "protocol": args.protocol.label(),
        "duration_seconds": args.duration.as_secs(),
        "concurrency": args.concurrency,
        "client_resumption": args.client_resumption.label(),
        "post_handshake_observe_ms": args.post_handshake_observe.as_millis() as u64,
        "handshakes": snapshot.requests,
        "errors": snapshot.errors,
        "handshake_per_sec": rate(snapshot.requests, args.duration.as_secs_f64()),
        "p50_ms": snapshot.p50_ms,
        "p95_ms": snapshot.p95_ms,
        "p99_ms": snapshot.p99_ms,
        "handshake_kinds": handshake_kind_json(snapshot.handshake_kinds),
        "tls13_tickets_received": snapshot.tls13_tickets_received,
        "negotiated_key_exchange_groups": count_json(snapshot.negotiated_key_exchange_groups),
        "error_samples": snapshot.error_samples,
    })
  );
  Ok(())
}

fn worker_tls_config(args: &HandshakeArgs) -> anyhow::Result<Option<Arc<ClientConfig>>> {
  if matches!(args.protocol, Protocol::H1 | Protocol::H2)
    && args.client_resumption == ClientResumptionMode::Worker
  {
    return Ok(Some(tcp_tls_config(&args.ca_cert, args.protocol.alpn())?));
  }
  Ok(None)
}

async fn run_single_handshake(
  args: &HandshakeArgs,
  worker_tls_config: Option<Arc<ClientConfig>>,
) -> anyhow::Result<HandshakeObservation> {
  match args.protocol {
    Protocol::H1 | Protocol::H2 => tcp_handshake(args, worker_tls_config).await,
    Protocol::H1c => {
      TcpStream::connect((args.host.as_str(), args.port))
        .await
        .context("failed to connect cleartext HTTP/1.1 socket")?;
      Ok(HandshakeObservation::default())
    }
    Protocol::H3 => {
      let connection = h3_connect(
        &args.host,
        args.port,
        &args.server_name,
        &args.ca_cert,
        args.protocol.alpn(),
      )
      .await;
      if let Ok(connection) = &connection {
        connection
          .connection
          .close(0u32.into(), b"handshake complete");
      }
      connection.map(|_| HandshakeObservation::default())
    }
  }
}

async fn tcp_handshake(
  args: &HandshakeArgs,
  worker_tls_config: Option<Arc<ClientConfig>>,
) -> anyhow::Result<HandshakeObservation> {
  let config = match worker_tls_config {
    Some(config) => config,
    None => tcp_tls_config(&args.ca_cert, args.protocol.alpn())?,
  };
  let mut stream =
    tls_connect_with_config(&args.host, args.port, &args.server_name, config).await?;
  observe_post_handshake(&mut stream, args.post_handshake_observe).await;
  Ok(tcp_handshake_observation(&stream))
}

async fn observe_post_handshake(stream: &mut TlsStream<TcpStream>, duration: Duration) {
  if duration == Duration::ZERO {
    return;
  }
  let mut buffer = [0u8; 1];
  let _ = tokio::time::timeout(duration, stream.read(&mut buffer)).await;
}

fn tcp_handshake_observation(stream: &TlsStream<TcpStream>) -> HandshakeObservation {
  let (_, connection) = stream.get_ref();
  HandshakeObservation {
    kind: connection.handshake_kind(),
    tls13_tickets_received: connection.tls13_tickets_received(),
    negotiated_key_exchange_group: connection
      .negotiated_key_exchange_group()
      .map(|group| format!("{:?}", group.name()).to_ascii_lowercase()),
  }
}

async fn run_stress(args: StressArgs) -> anyhow::Result<()> {
  validate_stress_protocol(&args.mode, args.protocol)?;
  let stats = SharedStats::new()?;
  let mut tasks = Vec::with_capacity(args.connections);
  for _ in 0..args.connections {
    let args = args.clone();
    let stats = stats.clone();
    tasks.push(tokio::spawn(async move {
      let result = match args.mode.as_str() {
        "slowloris" => stress_slowloris(&args).await,
        "large-header" => stress_large_header(&args).await,
        "large-body" => stress_large_body(&args).await,
        "idle" => stress_idle(&args).await,
        "half-close" => stress_half_close(&args).await,
        "slow-post" => stress_slow_post(&args).await,
        "slow-response" => stress_slow_response(&args).await,
        "h2-rapid-stream-churn" => stress_h2_rapid_stream_churn(&args).await,
        "h2-cl0-data" => stress_h2_cl0_data(&args).await,
        "h3-cl0-data" => stress_h3_cl0_data(&args).await,
        _ => unreachable!("mode already validated"),
      };
      record_stress_result(&stats, &args, result);
    }));
  }
  for task in tasks {
    task.await.context("stress worker task panicked")?;
  }
  let snapshot = stats.snapshot();
  println!(
    "{}",
    serde_json::json!({
        "type": "stress",
        "label": args.label,
        "mode": args.mode,
        "protocol": args.protocol.label(),
        "duration_seconds": args.duration.as_secs(),
        "connections": args.connections,
        "requests": snapshot.requests,
        "errors": snapshot.errors,
        "statuses": status_json(snapshot.statuses),
        "error_samples": snapshot.error_samples,
    })
  );
  Ok(())
}

fn record_stress_result(
  stats: &SharedStats,
  args: &StressArgs,
  result: anyhow::Result<Option<u16>>,
) {
  match result {
    Ok(Some(status)) => match args.expect_status {
      Some(expect_status) => {
        stats.record_response(status, args.duration, expect_status);
      }
      None => stats.record_status(status),
    },
    Ok(None) => stats.record_success(args.duration),
    Err(error) => {
      let message = format!("{error:#}");
      stats.record_error_sample(message.clone());
      eprintln!("stress connection failed: {message}");
    }
  }
}

async fn run_metrics(args: MetricsArgs) -> anyhow::Result<()> {
  let body = fetch_plaintext_http1(&args).await?;
  println!(
    "{}",
    serde_json::json!({
        "type": "metrics",
        "label": args.label,
        "mode": "prometheus",
        "server_session_storage": server_session_storage_metrics_json(&body),
        "fast_path": fast_path_metrics_json(&body),
    })
  );
  Ok(())
}

async fn fetch_plaintext_http1(args: &MetricsArgs) -> anyhow::Result<String> {
  let mut stream = TcpStream::connect((args.host.as_str(), args.port))
    .await
    .with_context(|| {
      format!(
        "failed to connect metrics endpoint {}:{}",
        args.host, args.port
      )
    })?;
  let request = format!(
    "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
    args.path, args.authority
  );
  stream
    .write_all(request.as_bytes())
    .await
    .context("failed to write metrics request")?;
  stream
    .flush()
    .await
    .context("failed to flush metrics request")?;
  let mut raw = Vec::new();
  stream
    .read_to_end(&mut raw)
    .await
    .context("failed to read metrics response")?;
  decode_http_response_body(&raw)
}

fn decode_http_response_body(raw: &[u8]) -> anyhow::Result<String> {
  let header_end = raw
    .windows(4)
    .position(|window| window == b"\r\n\r\n")
    .ok_or_else(|| anyhow!("metrics response did not contain HTTP headers"))?;
  let headers = std::str::from_utf8(&raw[..header_end])
    .context("metrics response headers were not valid UTF-8")?;
  let status = headers
    .lines()
    .next()
    .ok_or_else(|| anyhow!("metrics response was missing a status line"))?;
  if !status.contains(" 200 ") {
    bail!("metrics endpoint returned unexpected status line: {status}");
  }

  let body = &raw[(header_end + 4)..];
  let lower_headers = headers.to_ascii_lowercase();
  let decoded = if lower_headers.contains("transfer-encoding: chunked") {
    decode_chunked_body(body)?
  } else if let Some(length) = content_length(headers)? {
    body
      .get(..length)
      .ok_or_else(|| anyhow!("metrics response body was shorter than Content-Length"))?
      .to_vec()
  } else {
    body.to_vec()
  };
  String::from_utf8(decoded).context("metrics response body was not valid UTF-8")
}

fn content_length(headers: &str) -> anyhow::Result<Option<usize>> {
  for line in headers.lines() {
    let Some((name, value)) = line.split_once(':') else {
      continue;
    };
    if name.eq_ignore_ascii_case("content-length") {
      return value
        .trim()
        .parse::<usize>()
        .map(Some)
        .context("invalid metrics Content-Length");
    }
  }
  Ok(None)
}

fn decode_chunked_body(mut input: &[u8]) -> anyhow::Result<Vec<u8>> {
  let mut output = Vec::new();
  loop {
    let line_end = find_crlf(input).ok_or_else(|| anyhow!("invalid chunk header"))?;
    let size_text =
      std::str::from_utf8(&input[..line_end]).context("chunk size was not valid UTF-8")?;
    let size_hex = size_text
      .split_once(';')
      .map_or(size_text, |(size, _)| size);
    let size =
      usize::from_str_radix(size_hex.trim(), 16).context("chunk size was not valid hexadecimal")?;
    input = &input[(line_end + 2)..];
    if size == 0 {
      break;
    }
    if input.len() < size + 2 {
      bail!("chunk body was shorter than declared size");
    }
    output.extend_from_slice(&input[..size]);
    if &input[size..(size + 2)] != b"\r\n" {
      bail!("chunk body was not followed by CRLF");
    }
    input = &input[(size + 2)..];
  }
  Ok(output)
}

fn find_crlf(input: &[u8]) -> Option<usize> {
  input.windows(2).position(|window| window == b"\r\n")
}

fn server_session_storage_metrics_json(metrics: &str) -> serde_json::Value {
  serde_json::json!({
      "put_count": prometheus_u64(metrics, "oxibelt_tls_server_session_storage_put_total"),
      "get_count": prometheus_u64(metrics, "oxibelt_tls_server_session_storage_get_total"),
      "take_count": prometheus_u64(metrics, "oxibelt_tls_server_session_storage_take_total"),
      "lock_wait_ns": prometheus_u64(metrics, "oxibelt_tls_server_session_storage_lock_wait_ns_total"),
      "put_duration_ns": prometheus_u64(metrics, "oxibelt_tls_server_session_storage_put_duration_ns_total"),
  })
}

fn fast_path_metrics_json(metrics: &str) -> serde_json::Value {
  let mut plain_proxy = serde_json::Map::new();
  for protocol in ["h1", "h2", "h3"] {
    plain_proxy.insert(
      protocol.to_owned(),
      fast_path_protocol_metrics_json(metrics, "plain_proxy", protocol),
    );
  }
  let mut direct_h1 = serde_json::Map::new();
  let mut direct_h2 = serde_json::Map::new();
  for protocol in ["h1", "h2", "h3"] {
    direct_h1.insert(
      protocol.to_owned(),
      fast_path_transport_metrics_json(metrics, "direct_h1", protocol),
    );
    direct_h2.insert(
      protocol.to_owned(),
      fast_path_transport_metrics_json(metrics, "direct_h2", protocol),
    );
  }
  serde_json::json!({
      "plain_proxy": plain_proxy,
      "transport": {
          "direct_h1": direct_h1,
          "direct_h2": direct_h2
      },
      "pool": {
          "direct_h1": direct_h1_pool_metrics_json(metrics)
      },
      "static_responses": static_fast_path_responses_json(metrics)
  })
}

fn fast_path_protocol_metrics_json(metrics: &str, path: &str, protocol: &str) -> serde_json::Value {
  let mut hits = 0;
  let mut miss_reasons = BTreeMap::new();
  for (labels, value) in
    prometheus_labeled_u64_samples(metrics, "oxibelt_http_fast_path_decisions_total")
  {
    if labels.get("path").map(String::as_str) != Some(path)
      || labels.get("protocol").map(String::as_str) != Some(protocol)
    {
      continue;
    }
    match labels.get("outcome").map(String::as_str) {
      Some("hit") => hits += value,
      Some("miss") => {
        let reason = labels
          .get("reason")
          .cloned()
          .unwrap_or_else(|| "unknown".to_owned());
        *miss_reasons.entry(reason).or_insert(0) += value;
      }
      _ => {}
    }
  }
  let misses = miss_reasons.values().sum::<u64>();
  let attempts = hits + misses;
  let hit_rate = if attempts == 0 {
    serde_json::Value::Null
  } else {
    serde_json::json!(hits as f64 / attempts as f64)
  };
  serde_json::json!({
      "hits": hits,
      "misses": misses,
      "attempts": attempts,
      "hit_rate": hit_rate,
      "miss_reasons": miss_reasons,
  })
}

fn fast_path_transport_metrics_json(
  metrics: &str,
  transport: &str,
  protocol: &str,
) -> serde_json::Value {
  let mut hits = 0;
  let mut miss_reasons = BTreeMap::new();
  for (labels, value) in
    prometheus_labeled_u64_samples(metrics, "oxibelt_http_fast_path_transports_total")
  {
    if labels.get("transport").map(String::as_str) != Some(transport)
      || labels.get("protocol").map(String::as_str) != Some(protocol)
    {
      continue;
    }
    match labels.get("outcome").map(String::as_str) {
      Some("hit") => hits += value,
      Some("miss") => {
        let reason = labels
          .get("reason")
          .cloned()
          .unwrap_or_else(|| "unknown".to_owned());
        *miss_reasons.entry(reason).or_insert(0) += value;
      }
      _ => {}
    }
  }
  let misses = miss_reasons.values().sum::<u64>();
  let attempts = hits + misses;
  let hit_rate = if attempts == 0 {
    serde_json::Value::Null
  } else {
    serde_json::json!(hits as f64 / attempts as f64)
  };
  serde_json::json!({
      "hits": hits,
      "misses": misses,
      "attempts": attempts,
      "hit_rate": hit_rate,
      "miss_reasons": miss_reasons,
  })
}

fn direct_h1_pool_metrics_json(metrics: &str) -> serde_json::Value {
  let mut events = BTreeMap::new();
  for (labels, value) in
    prometheus_labeled_u64_samples(metrics, "oxibelt_http_direct_h1_pool_events_total")
  {
    let event = labels
      .get("event")
      .cloned()
      .unwrap_or_else(|| "unknown".to_owned());
    *events.entry(event).or_insert(0) += value;
  }
  serde_json::json!(events)
}

fn static_fast_path_responses_json(metrics: &str) -> serde_json::Value {
  let mut responses = serde_json::Map::new();
  for (labels, value) in
    prometheus_labeled_u64_samples(metrics, "oxibelt_http_static_fast_path_responses_total")
  {
    let Some(source) = labels.get("source") else {
      continue;
    };
    let Some(outcome) = labels.get("outcome") else {
      continue;
    };
    let source_entry = responses
      .entry(source.clone())
      .or_insert_with(|| serde_json::json!({}));
    if let Some(source_object) = source_entry.as_object_mut() {
      let current = source_object
        .get(outcome)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
      source_object.insert(outcome.clone(), serde_json::json!(current + value));
    }
  }
  serde_json::Value::Object(responses)
}

fn prometheus_labeled_u64_samples(
  metrics: &str,
  name: &str,
) -> Vec<(BTreeMap<String, String>, u64)> {
  metrics
    .lines()
    .filter_map(|line| {
      let line = line.trim();
      if line.is_empty() || line.starts_with('#') {
        return None;
      }
      let mut parts = line.split_whitespace();
      let sample = parts.next()?;
      let value = parts.next()?.parse::<f64>().ok()?;
      if !value.is_finite() || value < 0.0 {
        return None;
      }
      let labels = sample
        .strip_prefix(name)?
        .strip_prefix('{')?
        .strip_suffix('}')?;
      Some((parse_prometheus_labels(labels), value as u64))
    })
    .collect()
}

fn parse_prometheus_labels(raw: &str) -> BTreeMap<String, String> {
  let mut labels = BTreeMap::new();
  for part in raw.split(',') {
    let Some((key, value)) = part.split_once('=') else {
      continue;
    };
    let value = value
      .strip_prefix('"')
      .and_then(|value| value.strip_suffix('"'))
      .unwrap_or(value);
    labels.insert(key.to_owned(), unescape_prometheus_label(value));
  }
  labels
}

fn unescape_prometheus_label(value: &str) -> String {
  let mut output = String::new();
  let mut chars = value.chars();
  while let Some(ch) = chars.next() {
    if ch != '\\' {
      output.push(ch);
      continue;
    }
    match chars.next() {
      Some('n') => output.push('\n'),
      Some(other) => output.push(other),
      None => output.push('\\'),
    }
  }
  output
}

fn prometheus_u64(metrics: &str, name: &str) -> u64 {
  metrics
    .lines()
    .find_map(|line| {
      let line = line.trim();
      if line.is_empty() || line.starts_with('#') {
        return None;
      }
      let mut parts = line.split_whitespace();
      if parts.next()? != name {
        return None;
      }
      let value = parts.next()?.parse::<f64>().ok()?;
      if value.is_finite() && value >= 0.0 {
        Some(value as u64)
      } else {
        None
      }
    })
    .unwrap_or(0)
}

async fn stress_slowloris(args: &StressArgs) -> anyhow::Result<Option<u16>> {
  let mut stream = TcpStream::connect((args.host.as_str(), args.port))
    .await
    .context("failed to connect slowloris socket")?;
  stream
    .write_all(
      format!(
        "GET /perf/slow HTTP/1.1\r\nHost: {}\r\nX-Slow: ",
        args.authority
      )
      .as_bytes(),
    )
    .await
    .context("failed to write slowloris prefix")?;
  tokio::time::sleep(args.duration).await;
  stream
    .write_all(b"done\r\n\r\n")
    .await
    .context("failed to finish slowloris request")?;
  read_http_status(&mut stream).await
}

async fn stress_large_header(args: &StressArgs) -> anyhow::Result<Option<u16>> {
  let mut stream = TcpStream::connect((args.host.as_str(), args.port))
    .await
    .context("failed to connect large-header socket")?;
  stream
    .write_all(
      format!(
        "GET /perf/large-header HTTP/1.1\r\nHost: {}\r\nX-Large: {}\r\n\r\n",
        args.authority,
        "a".repeat(args.bytes)
      )
      .as_bytes(),
    )
    .await
    .context("failed to write large-header request")?;
  read_http_status(&mut stream).await
}

async fn stress_large_body(args: &StressArgs) -> anyhow::Result<Option<u16>> {
  let mut stream = TcpStream::connect((args.host.as_str(), args.port))
    .await
    .context("failed to connect large-body socket")?;
  stream
    .write_all(
      format!(
        "POST /perf/large-body HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\n",
        args.authority, args.bytes
      )
      .as_bytes(),
    )
    .await
    .context("failed to write large-body headers")?;
  let chunk = vec![b'x'; 16 * 1024];
  let mut remaining = args.bytes;
  while remaining > 0 {
    let len = remaining.min(chunk.len());
    stream
      .write_all(&chunk[..len])
      .await
      .context("failed to write large-body chunk")?;
    remaining -= len;
  }
  read_http_status(&mut stream).await
}

async fn stress_idle(args: &StressArgs) -> anyhow::Result<Option<u16>> {
  let _stream = TcpStream::connect((args.host.as_str(), args.port))
    .await
    .context("failed to connect idle socket")?;
  tokio::time::sleep(args.duration).await;
  Ok(None)
}

async fn stress_half_close(args: &StressArgs) -> anyhow::Result<Option<u16>> {
  let mut stream = TcpStream::connect((args.host.as_str(), args.port))
    .await
    .context("failed to connect half-close socket")?;
  stream
    .write_all(
      format!(
        "GET /perf/half-close HTTP/1.1\r\nHost: {}\r\n\r\n",
        args.authority
      )
      .as_bytes(),
    )
    .await
    .context("failed to write half-close request")?;
  stream
    .shutdown()
    .await
    .context("failed to half-close socket")?;
  read_http_status(&mut stream).await
}

async fn stress_slow_post(args: &StressArgs) -> anyhow::Result<Option<u16>> {
  let mut stream = TcpStream::connect((args.host.as_str(), args.port))
    .await
    .context("failed to connect slow-post socket")?;
  stream
    .write_all(
      format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\n",
        args.path, args.authority, args.bytes
      )
      .as_bytes(),
    )
    .await
    .context("failed to write slow-post headers")?;
  let deadline = Instant::now() + args.duration;
  let chunk = vec![b'x'; args.chunk_bytes];
  let mut remaining = args.bytes;
  while remaining > 0 && Instant::now() < deadline {
    let len = remaining.min(chunk.len());
    stream
      .write_all(&chunk[..len])
      .await
      .context("failed to write slow-post chunk")?;
    remaining -= len;
    if remaining > 0 {
      tokio::time::sleep(args.chunk_delay).await;
    }
  }
  if remaining > 0 {
    stream
      .shutdown()
      .await
      .context("failed to close incomplete slow-post body")?;
    return Ok(None);
  }
  read_http_status_with_timeout(&mut stream, args.duration + Duration::from_secs(10)).await
}

async fn stress_slow_response(args: &StressArgs) -> anyhow::Result<Option<u16>> {
  let mut stream = TcpStream::connect((args.host.as_str(), args.port))
    .await
    .context("failed to connect slow-response socket")?;
  stream
    .write_all(
      format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        args.path, args.authority
      )
      .as_bytes(),
    )
    .await
    .context("failed to write slow-response request")?;
  read_http_status_with_timeout(&mut stream, args.duration + Duration::from_secs(10)).await
}

async fn stress_h2_rapid_stream_churn(args: &StressArgs) -> anyhow::Result<Option<u16>> {
  let (mut sender, connection_task) = h2_sender(args).await?;
  let mut responses = Vec::with_capacity(args.streams_per_connection);
  for index in 0..args.streams_per_connection {
    let path = append_query_param(&args.path, "churn_id", index);
    let request = stress_h2_request(args, Method::GET, &path, false)?;
    let (response, _) = sender
      .send_request(request, true)
      .context("failed to send H2 churn request")?;
    responses.push(response);
  }
  let mut last_status = None;
  let responses = tokio::time::timeout(
    stress_response_timeout(args),
    futures_util::future::try_join_all(responses),
  )
  .await
  .context("timed out receiving H2 churn responses")?
  .context("failed to receive H2 churn response")?;
  for response in responses {
    let status = response.status().as_u16();
    if let Some(expect_status) = args.expect_status {
      if status != expect_status {
        bail!("unexpected H2 churn status {status}, expected {expect_status}");
      }
    }
    last_status = Some(status);
  }
  drop(sender);
  connection_task.abort();
  let _ = connection_task.await;
  Ok(last_status)
}

async fn stress_h2_cl0_data(args: &StressArgs) -> anyhow::Result<Option<u16>> {
  let (mut sender, connection_task) = h2_sender(args).await?;
  let request = stress_h2_request(args, Method::POST, &args.path, true)?;
  let (response, mut stream) = sender
    .send_request(request, false)
    .context("failed to send H2 CL0 request")?;
  if stream
    .send_data(Bytes::from(vec![b'x'; args.chunk_bytes]), true)
    .is_err()
  {
    drop(sender);
    connection_task.abort();
    let _ = connection_task.await;
    return Ok(None);
  }
  let status = match tokio::time::timeout(stress_response_timeout(args), response).await {
    Ok(Ok(response)) => Some(response.status().as_u16()),
    Ok(Err(_)) | Err(_) => None,
  };
  drop(sender);
  connection_task.abort();
  let _ = connection_task.await;
  Ok(status)
}

async fn stress_h3_cl0_data(args: &StressArgs) -> anyhow::Result<Option<u16>> {
  let server_name = stress_server_name(args)?;
  let ca_cert = stress_ca_cert(args)?;
  let h3_client = h3_connect(
    &args.host,
    args.port,
    &server_name,
    &ca_cert,
    args.protocol.alpn(),
  )
  .await?;
  let close_connection = h3_client.connection.clone();
  let h3_connection = h3_quinn::Connection::new(h3_client.connection);
  let mut builder = h3::client::builder();
  builder.send_grease(false);
  let (mut driver, mut send_request) = builder
    .build::<_, _, Bytes>(h3_connection)
    .await
    .context("failed to establish HTTP/3 CL0 client")?;
  let driver_task = tokio::spawn(async move {
    let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
  });

  let request = stress_h3_request(args, Method::POST, &args.path, true)?;
  let timeout = stress_response_timeout(args);
  let status = tokio::time::timeout(timeout, async {
    match send_request.send_request(request).await {
      Ok(mut stream) => {
        if stream
          .send_data(Bytes::from(vec![b'x'; args.chunk_bytes]))
          .await
          .is_err()
          || stream.finish().await.is_err()
        {
          None
        } else {
          match stream.recv_response().await {
            Ok(response) => Some(response.status().as_u16()),
            Err(_) => None,
          }
        }
      }
      Err(_) => None,
    }
  })
  .await
  .unwrap_or(None);
  close_connection.close(0u32.into(), b"stress complete");
  driver_task.abort();
  let _ = driver_task.await;
  Ok(status)
}

fn stress_response_timeout(args: &StressArgs) -> Duration {
  args.duration + Duration::from_secs(10)
}

async fn h2_sender(
  args: &StressArgs,
) -> anyhow::Result<(h2::client::SendRequest<Bytes>, tokio::task::JoinHandle<()>)> {
  let server_name = stress_server_name(args)?;
  let ca_cert = stress_ca_cert(args)?;
  let tls_stream = tls_connect(
    &args.host,
    args.port,
    &server_name,
    &ca_cert,
    args.protocol.alpn(),
  )
  .await?;
  let (sender, connection) = h2::client::handshake(tls_stream)
    .await
    .context("failed to establish direct H2 client")?;
  let task = tokio::spawn(async move {
    let _ = connection.await;
  });
  Ok((sender, task))
}

fn stress_server_name(args: &StressArgs) -> anyhow::Result<String> {
  args.server_name.clone().ok_or_else(|| {
    anyhow!(
      "--server-name is required for {} stress",
      args.protocol.label()
    )
  })
}

fn stress_ca_cert(args: &StressArgs) -> anyhow::Result<String> {
  args
    .ca_cert
    .clone()
    .ok_or_else(|| anyhow!("--ca-cert is required for {} stress", args.protocol.label()))
}

fn stress_h2_request(
  args: &StressArgs,
  method: Method,
  path: &str,
  content_length_zero: bool,
) -> anyhow::Result<Request<()>> {
  let mut builder = Request::builder()
    .method(method)
    .uri(format!("https://{}{}", args.authority, path))
    .version(Version::HTTP_2);
  if content_length_zero {
    builder = builder.header(CONTENT_LENGTH, "0");
  }
  builder.body(()).map_err(Into::into)
}

fn stress_h3_request(
  args: &StressArgs,
  method: Method,
  path: &str,
  content_length_zero: bool,
) -> anyhow::Result<Request<()>> {
  let mut builder = Request::builder()
    .method(method)
    .uri(format!("https://{}{}", args.authority, path))
    .version(Version::HTTP_3);
  if content_length_zero {
    builder = builder.header(CONTENT_LENGTH, "0");
  }
  builder.body(()).map_err(Into::into)
}

fn append_query_param(path: &str, name: &str, value: usize) -> String {
  let separator = if path.contains('?') { '&' } else { '?' };
  format!("{path}{separator}{name}={value}")
}

async fn read_http_status(stream: &mut TcpStream) -> anyhow::Result<Option<u16>> {
  read_http_status_with_timeout(stream, Duration::from_secs(10)).await
}

async fn read_http_status_with_timeout(
  stream: &mut TcpStream,
  timeout: Duration,
) -> anyhow::Result<Option<u16>> {
  let mut buffer = vec![0u8; 1024];
  let read = tokio::time::timeout(timeout, stream.read(&mut buffer))
    .await
    .context("timed out reading HTTP status")?
    .context("failed to read HTTP status")?;
  if read == 0 {
    return Ok(None);
  }
  let text = String::from_utf8_lossy(&buffer[..read]);
  Ok(
    text
      .lines()
      .next()
      .and_then(|line| line.split_whitespace().nth(1))
      .and_then(|status| status.parse::<u16>().ok()),
  )
}

async fn tls_connect(
  host: &str,
  port: u16,
  server_name: &str,
  ca_cert: &str,
  alpn: &[u8],
) -> anyhow::Result<TlsStream<TcpStream>> {
  let config = tcp_tls_config(ca_cert, alpn)?;
  tls_connect_with_config(host, port, server_name, config).await
}

fn tcp_tls_config(ca_cert: &str, alpn: &[u8]) -> anyhow::Result<Arc<ClientConfig>> {
  let mut config = tls_config(Path::new(ca_cert), alpn)?;
  config.enable_sni = true;
  Ok(Arc::new(config))
}

async fn tls_connect_with_config(
  host: &str,
  port: u16,
  server_name: &str,
  config: Arc<ClientConfig>,
) -> anyhow::Result<TlsStream<TcpStream>> {
  let connector = TlsConnector::from(config);
  let stream = TcpStream::connect((host, port))
    .await
    .with_context(|| format!("failed to connect to {host}:{port}"))?;
  let server_name = ServerName::try_from(server_name.to_owned())
    .map_err(|_| anyhow!("invalid server name: {server_name}"))?;
  connector
    .connect(server_name, stream)
    .await
    .context("failed to establish TLS")
}

async fn h3_connect(
  host: &str,
  port: u16,
  server_name: &str,
  ca_cert: &str,
  alpn: &[u8],
) -> anyhow::Result<H3ClientConnection> {
  let client_config = tls_config(Path::new(ca_cert), alpn)?;
  let quic_crypto =
    QuicClientConfig::try_from(client_config).context("failed to build QUIC TLS client")?;
  let quic_config = QuinnClientConfig::new(Arc::new(quic_crypto));
  let remote_addr = resolve_remote_addr(host, port).await?;
  let endpoint =
    Endpoint::client(client_bind_addr(remote_addr)).context("failed to create QUIC endpoint")?;
  let connection = endpoint
    .connect_with(quic_config, remote_addr, server_name)
    .with_context(|| format!("failed to start QUIC connection to {host}:{port}"))?
    .await
    .context("failed to connect QUIC")?;
  Ok(H3ClientConnection {
    _endpoint: endpoint,
    connection,
  })
}

fn tls_config(path: &Path, alpn: &[u8]) -> anyhow::Result<ClientConfig> {
  let mut config =
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
      .with_safe_default_protocol_versions()
      .context("failed to configure TLS versions")?
      .with_root_certificates(load_root_store(path)?)
      .with_no_client_auth();
  config.alpn_protocols = vec![alpn.to_vec()];
  Ok(config)
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

fn load_root_store(path: &Path) -> anyhow::Result<RootCertStore> {
  let certs = load_certs(path)?;
  let mut roots = RootCertStore::empty();
  let (added, _ignored) = roots.add_parsable_certificates(certs);
  if added == 0 {
    bail!("no parsable certificates found in {}", path.display());
  }
  Ok(roots)
}

fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
  let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
  CertificateDer::pem_slice_iter(&bytes)
    .collect::<Result<Vec<CertificateDer<'static>>, _>>()
    .with_context(|| format!("failed to parse PEM certificates from {}", path.display()))
}

#[allow(dead_code)]
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

fn percentile_ms(histogram: &Histogram<u64>, percentile: f64) -> f64 {
  if histogram.is_empty() {
    0.0
  } else {
    histogram.value_at_percentile(percentile) as f64 / 1000.0
  }
}

fn rate(count: u64, elapsed_seconds: f64) -> f64 {
  if elapsed_seconds <= 0.0 {
    0.0
  } else {
    count as f64 / elapsed_seconds
  }
}

fn status_json(statuses: BTreeMap<u16, u64>) -> serde_json::Value {
  serde_json::Value::Object(
    statuses
      .into_iter()
      .map(|(status, count)| (status.to_string(), serde_json::json!(count)))
      .collect(),
  )
}

fn count_json(counts: BTreeMap<String, u64>) -> serde_json::Value {
  serde_json::Value::Object(
    counts
      .into_iter()
      .map(|(name, count)| (name, serde_json::json!(count)))
      .collect(),
  )
}

fn handshake_kind_json(counts: HandshakeKindCounts) -> serde_json::Value {
  serde_json::json!({
      "full": counts.full,
      "full_with_hello_retry_request": counts.full_with_hello_retry_request,
      "resumed": counts.resumed,
      "unknown": counts.unknown,
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn sampled_error_messages_are_bounded() {
    let stats = SharedStats::new().expect("stats should initialize");

    for index in 0..(MAX_ERROR_SAMPLES + 3) {
      stats.record_error_sample(format!("error-{index}"));
    }

    let snapshot = stats.snapshot();
    assert_eq!(snapshot.errors, (MAX_ERROR_SAMPLES + 3) as u64);
    assert_eq!(snapshot.error_samples.len(), MAX_ERROR_SAMPLES);
    assert_eq!(snapshot.error_samples[0], "error-0");
    assert_eq!(
      snapshot.error_samples[MAX_ERROR_SAMPLES - 1],
      format!("error-{}", MAX_ERROR_SAMPLES - 1)
    );
  }

  #[test]
  fn status_mismatch_is_sampled_as_request_error() {
    let stats = SharedStats::new().expect("stats should initialize");

    stats.record_response(503, Duration::from_millis(1), 200);

    let snapshot = stats.snapshot();
    assert_eq!(snapshot.requests, 1);
    assert_eq!(snapshot.errors, 1);
    assert_eq!(snapshot.statuses.get(&503), Some(&1));
    assert_eq!(
      snapshot.error_samples,
      vec!["unexpected status 503, expected 200"]
    );
  }

  #[test]
  fn handshake_args_parse_resumption_observation_options() {
    let args = parse_handshake_args(
      [
        "--label",
        "diagnostic",
        "--protocol",
        "h2",
        "--host",
        "proxy",
        "--port",
        "8443",
        "--server-name",
        "proxy",
        "--ca-cert",
        "/tls/proxy-ca.pem",
        "--duration-seconds",
        "5",
        "--concurrency",
        "2",
        "--client-resumption",
        "worker",
        "--post-handshake-observe-ms",
        "25",
      ]
      .into_iter()
      .map(str::to_owned),
    )
    .expect("handshake args should parse");

    assert_eq!(args.label, "diagnostic");
    assert_eq!(args.protocol, Protocol::H2);
    assert_eq!(args.client_resumption, ClientResumptionMode::Worker);
    assert_eq!(args.post_handshake_observe, Duration::from_millis(25));
  }

  #[test]
  fn handshake_args_default_to_fresh_without_post_handshake_observation() {
    let args = parse_handshake_args(
      [
        "--protocol",
        "h1",
        "--host",
        "proxy",
        "--port",
        "8443",
        "--server-name",
        "proxy",
        "--ca-cert",
        "/tls/proxy-ca.pem",
        "--duration-seconds",
        "5",
        "--concurrency",
        "2",
      ]
      .into_iter()
      .map(str::to_owned),
    )
    .expect("handshake args should parse");

    assert_eq!(args.client_resumption, ClientResumptionMode::Fresh);
    assert_eq!(args.post_handshake_observe, Duration::ZERO);
  }

  #[test]
  fn metrics_args_parse_plaintext_endpoint() {
    let args = parse_metrics_args(
      [
        "--label",
        "tls-storage",
        "--host",
        "oxibelt",
        "--port",
        "9090",
        "--authority",
        "ops.test",
        "--path",
        "/metrics",
      ]
      .into_iter()
      .map(str::to_owned),
    )
    .expect("metrics args should parse");

    assert_eq!(args.label, "tls-storage");
    assert_eq!(args.host, "oxibelt");
    assert_eq!(args.port, 9090);
    assert_eq!(args.authority, "ops.test");
    assert_eq!(args.path, "/metrics");
  }

  #[test]
  fn load_args_accept_unique_query_param() {
    let args = parse_load_args(
      [
        "--label",
        "cold-fill",
        "--protocol",
        "h2",
        "--host",
        "oxibelt",
        "--port",
        "8443",
        "--server-name",
        "proxy",
        "--authority",
        "example.test",
        "--path",
        "/perf/cache-cold-fill?cache_control=public",
        "--ca-cert",
        "/tls/proxy-ca.pem",
        "--duration-seconds",
        "1",
        "--warmup-seconds",
        "0",
        "--concurrency",
        "1",
        "--unique-query-param",
        "fill_id",
      ]
      .into_iter()
      .map(str::to_owned),
    )
    .expect("load args should parse");

    assert_eq!(args.unique_query_param.as_deref(), Some("fill_id"));
    let first =
      request(&args, Version::HTTP_2, Full::new(Bytes::new())).expect("first request should build");
    let second = request(&args, Version::HTTP_2, Full::new(Bytes::new()))
      .expect("second request should build");
    assert_eq!(
      first.uri().to_string(),
      "https://example.test/perf/cache-cold-fill?cache_control=public&fill_id=0"
    );
    assert_eq!(
      second.uri().to_string(),
      "https://example.test/perf/cache-cold-fill?cache_control=public&fill_id=1"
    );
  }

  #[test]
  fn stress_args_parse_aggressive_options() {
    let args = parse_stress_args(
      [
        "--label",
        "slow-post",
        "--mode",
        "slow-post",
        "--protocol",
        "h1c",
        "--host",
        "oxibelt",
        "--port",
        "8080",
        "--authority",
        "example.test",
        "--path",
        "/perf/slow-post",
        "--connections",
        "4",
        "--duration-seconds",
        "30",
        "--bytes",
        "4096",
        "--chunk-bytes",
        "128",
        "--chunk-delay-ms",
        "25",
        "--expect-status",
        "200",
        "--streams-per-connection",
        "8",
      ]
      .into_iter()
      .map(str::to_owned),
    )
    .expect("stress args should parse");

    assert_eq!(args.label, "slow-post");
    assert_eq!(args.mode, "slow-post");
    assert_eq!(args.protocol, Protocol::H1c);
    assert_eq!(args.path, "/perf/slow-post");
    assert_eq!(args.expect_status, Some(200));
    assert_eq!(args.connections, 4);
    assert_eq!(args.duration, Duration::from_secs(30));
    assert_eq!(args.bytes, 4096);
    assert_eq!(args.chunk_bytes, 128);
    assert_eq!(args.chunk_delay, Duration::from_millis(25));
    assert_eq!(args.streams_per_connection, 8);
  }

  #[test]
  fn stress_args_default_protocols_for_abuse_modes() {
    for (mode, protocol) in [
      ("h2-rapid-stream-churn", Protocol::H2),
      ("h2-cl0-data", Protocol::H2),
      ("h3-cl0-data", Protocol::H3),
      ("slow-response", Protocol::H1c),
    ] {
      let args = parse_stress_args(
        [
          "--mode",
          mode,
          "--host",
          "oxibelt",
          "--port",
          "8443",
          "--authority",
          "example.test",
          "--connections",
          "1",
          "--duration-seconds",
          "1",
        ]
        .into_iter()
        .map(str::to_owned),
      )
      .expect("stress args should parse");
      assert_eq!(args.protocol, protocol, "mode {mode}");
    }
  }

  #[test]
  fn stress_args_reject_incompatible_protocols() {
    let error = parse_stress_args(
      [
        "--mode",
        "h2-cl0-data",
        "--protocol",
        "h3",
        "--host",
        "oxibelt",
        "--port",
        "8443",
        "--authority",
        "example.test",
        "--connections",
        "1",
        "--duration-seconds",
        "1",
      ]
      .into_iter()
      .map(str::to_owned),
    )
    .expect_err("h2-cl0-data should reject h3");

    assert!(
      format!("{error:#}").contains("requires protocol h2"),
      "error should explain the protocol requirement"
    );
  }

  #[test]
  fn stress_result_accounting_handles_statuses_resets_and_errors() {
    let args = parse_stress_args(
      [
        "--mode",
        "h2-cl0-data",
        "--host",
        "oxibelt",
        "--port",
        "8443",
        "--authority",
        "example.test",
        "--connections",
        "1",
        "--duration-seconds",
        "1",
        "--expect-status",
        "200",
      ]
      .into_iter()
      .map(str::to_owned),
    )
    .expect("stress args should parse");
    let stats = SharedStats::new().expect("stats should initialize");

    record_stress_result(&stats, &args, Ok(Some(200)));
    record_stress_result(&stats, &args, Ok(Some(503)));
    record_stress_result(&stats, &args, Ok(None));
    record_stress_result(&stats, &args, Err(anyhow!("stream closed")));

    let snapshot = stats.snapshot();
    assert_eq!(snapshot.requests, 3);
    assert_eq!(snapshot.errors, 2);
    assert_eq!(snapshot.statuses.get(&200), Some(&1));
    assert_eq!(snapshot.statuses.get(&503), Some(&1));
    assert_eq!(
      snapshot.error_samples,
      vec!["unexpected status 503, expected 200", "stream closed"]
    );
  }

  #[tokio::test]
  async fn slow_response_body_stream_replays_delayed_chunks() {
    let query = parse_query("response_chunk_delay_ms=1&response_chunk_bytes=2");

    assert_eq!(
      query_duration(&query, "response_chunk_delay_ms"),
      Some(Duration::from_millis(1))
    );
    let body = response_body_stream(&query, Bytes::from_static(b"hello"))
      .collect()
      .await
      .expect("streaming body should collect")
      .to_bytes();

    assert_eq!(body, Bytes::from_static(b"hello"));
  }

  #[test]
  fn metrics_parser_extracts_tls_session_storage_counters() {
    let metrics = "\
# TYPE oxibelt_tls_server_session_storage_put_total counter
oxibelt_tls_server_session_storage_put_total 11
# TYPE oxibelt_tls_server_session_storage_get_total counter
oxibelt_tls_server_session_storage_get_total 13
# TYPE oxibelt_tls_server_session_storage_take_total counter
oxibelt_tls_server_session_storage_take_total 17
# TYPE oxibelt_tls_server_session_storage_lock_wait_ns_total counter
oxibelt_tls_server_session_storage_lock_wait_ns_total 19
# TYPE oxibelt_tls_server_session_storage_put_duration_ns_total counter
oxibelt_tls_server_session_storage_put_duration_ns_total 23
";

    let parsed = server_session_storage_metrics_json(metrics);

    assert_eq!(parsed["put_count"], 11);
    assert_eq!(parsed["get_count"], 13);
    assert_eq!(parsed["take_count"], 17);
    assert_eq!(parsed["lock_wait_ns"], 19);
    assert_eq!(parsed["put_duration_ns"], 23);
  }

  #[test]
  fn metrics_parser_extracts_fast_path_counters() {
    let metrics = "\
# TYPE oxibelt_http_fast_path_decisions_total counter
oxibelt_http_fast_path_decisions_total{path=\"plain_proxy\",protocol=\"h1\",outcome=\"hit\",reason=\"eligible\"} 99
# TYPE oxibelt_http_fast_path_decisions_total counter
oxibelt_http_fast_path_decisions_total{path=\"plain_proxy\",protocol=\"h1\",outcome=\"miss\",reason=\"cache_policy\"} 1
# TYPE oxibelt_http_fast_path_decisions_total counter
oxibelt_http_fast_path_decisions_total{path=\"plain_proxy\",protocol=\"h2\",outcome=\"hit\",reason=\"eligible\"} 17
# TYPE oxibelt_http_fast_path_decisions_total counter
oxibelt_http_fast_path_decisions_total{path=\"plain_proxy\",protocol=\"h3\",outcome=\"hit\",reason=\"eligible\"} 23
# TYPE oxibelt_http_fast_path_transports_total counter
oxibelt_http_fast_path_transports_total{transport=\"direct_h1\",protocol=\"h1\",outcome=\"hit\",reason=\"used\"} 97
# TYPE oxibelt_http_fast_path_transports_total counter
oxibelt_http_fast_path_transports_total{transport=\"direct_h1\",protocol=\"h1\",outcome=\"miss\",reason=\"send_error\"} 3
# TYPE oxibelt_http_fast_path_transports_total counter
oxibelt_http_fast_path_transports_total{transport=\"direct_h1\",protocol=\"h2\",outcome=\"hit\",reason=\"used\"} 19
# TYPE oxibelt_http_fast_path_transports_total counter
oxibelt_http_fast_path_transports_total{transport=\"direct_h1\",protocol=\"h3\",outcome=\"hit\",reason=\"used\"} 29
# TYPE oxibelt_http_fast_path_transports_total counter
oxibelt_http_fast_path_transports_total{transport=\"direct_h2\",protocol=\"h2\",outcome=\"hit\",reason=\"used\"} 31
# TYPE oxibelt_http_direct_h1_pool_events_total counter
oxibelt_http_direct_h1_pool_events_total{event=\"hit\"} 113
# TYPE oxibelt_http_direct_h1_pool_events_total counter
oxibelt_http_direct_h1_pool_events_total{event=\"reconnect\"} 2
# TYPE oxibelt_http_static_fast_path_responses_total counter
oxibelt_http_static_fast_path_responses_total{source=\"hot_object\",outcome=\"served\"} 41
# TYPE oxibelt_http_static_fast_path_responses_total counter
oxibelt_http_static_fast_path_responses_total{source=\"sendfile\",outcome=\"fallback\"} 3
";

    let parsed = fast_path_metrics_json(metrics);
    let h1 = &parsed["plain_proxy"]["h1"];
    let direct_h1 = &parsed["transport"]["direct_h1"]["h1"];

    assert_eq!(h1["hits"], 99);
    assert_eq!(h1["misses"], 1);
    assert_eq!(h1["attempts"], 100);
    assert_eq!(h1["hit_rate"], 0.99);
    assert_eq!(h1["miss_reasons"]["cache_policy"], 1);
    assert_eq!(parsed["plain_proxy"]["h2"]["hits"], 17);
    assert_eq!(parsed["plain_proxy"]["h3"]["hits"], 23);
    assert_eq!(direct_h1["hits"], 97);
    assert_eq!(direct_h1["misses"], 3);
    assert_eq!(direct_h1["attempts"], 100);
    assert_eq!(direct_h1["hit_rate"], 0.97);
    assert_eq!(direct_h1["miss_reasons"]["send_error"], 3);
    assert_eq!(parsed["transport"]["direct_h1"]["h2"]["hits"], 19);
    assert_eq!(parsed["transport"]["direct_h1"]["h3"]["hits"], 29);
    assert_eq!(parsed["transport"]["direct_h2"]["h2"]["hits"], 31);
    assert_eq!(parsed["pool"]["direct_h1"]["hit"], 113);
    assert_eq!(parsed["pool"]["direct_h1"]["reconnect"], 2);
    assert_eq!(parsed["static_responses"]["hot_object"]["served"], 41);
    assert_eq!(parsed["static_responses"]["sendfile"]["fallback"], 3);
  }

  #[test]
  fn metrics_response_decoder_handles_chunked_bodies() {
    let response = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    let body = decode_http_response_body(response).expect("chunked body should decode");

    assert_eq!(body, "hello world");
  }

  #[test]
  fn handshake_observations_are_aggregated() {
    let stats = SharedStats::new().expect("stats should initialize");

    stats.record_handshake_success(
      Duration::from_millis(1),
      HandshakeObservation {
        kind: Some(HandshakeKind::Full),
        tls13_tickets_received: 2,
        negotiated_key_exchange_group: Some("x25519".to_owned()),
      },
    );
    stats.record_handshake_success(
      Duration::from_millis(1),
      HandshakeObservation {
        kind: Some(HandshakeKind::Resumed),
        tls13_tickets_received: 1,
        negotiated_key_exchange_group: Some("x25519".to_owned()),
      },
    );
    stats.record_handshake_success(Duration::from_millis(1), HandshakeObservation::default());

    let snapshot = stats.snapshot();
    assert_eq!(snapshot.requests, 3);
    assert_eq!(snapshot.handshake_kinds.full, 1);
    assert_eq!(snapshot.handshake_kinds.resumed, 1);
    assert_eq!(snapshot.handshake_kinds.unknown, 1);
    assert_eq!(snapshot.tls13_tickets_received, 3);
    assert_eq!(
      snapshot.negotiated_key_exchange_groups.get("x25519"),
      Some(&2)
    );
  }

  #[test]
  fn phase_boundary_worker_errors_are_not_counted() {
    let stats = SharedStats::new().expect("stats should initialize");
    let error = anyhow!("connection reset by peer");
    let future_deadline = Instant::now() + Duration::from_secs(1);
    let past_deadline = Instant::now()
      .checked_sub(Duration::from_millis(1))
      .expect("one millisecond before now should be representable");

    assert!(!record_worker_error(
      "h1",
      &error,
      past_deadline,
      &stats,
      true
    ));
    assert_eq!(stats.snapshot().errors, 0);

    assert!(record_worker_error(
      "h1",
      &error,
      future_deadline,
      &stats,
      false
    ));
    assert_eq!(stats.snapshot().errors, 0);

    assert!(record_worker_error(
      "h1",
      &error,
      future_deadline,
      &stats,
      true
    ));
    let snapshot = stats.snapshot();
    assert_eq!(snapshot.errors, 1);
    assert_eq!(snapshot.error_samples, vec!["connection reset by peer"]);
  }
}

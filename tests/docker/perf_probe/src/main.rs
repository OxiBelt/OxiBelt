use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use bytes::{Buf, Bytes};
use h3_quinn::quinn::crypto::rustls::QuicClientConfig;
use h3_quinn::quinn::{ClientConfig as QuinnClientConfig, Endpoint};
use hdrhistogram::Histogram;
use http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ETAG, HOST, IF_NONE_MATCH};
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri, Version};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::time::Instant;
use tokio_rustls::TlsConnector;

const MAX_ERROR_SAMPLES: usize = 8;

#[derive(Clone, Copy)]
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
}

#[derive(Clone)]
struct StressArgs {
    label: String,
    mode: String,
    host: String,
    port: u16,
    authority: String,
    connections: usize,
    duration: Duration,
    bytes: usize,
}

struct UpstreamArgs {
    listen: SocketAddr,
    name: String,
}

struct H3ClientConnection {
    _endpoint: Endpoint,
    connection: h3_quinn::quinn::Connection,
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
        _ => {
            usage();
            bail!("unknown command: {command}");
        }
    }
}

fn usage() {
    eprintln!(
        "usage:
  perf-probe upstream --listen <addr:port> [--name <name>]
  perf-probe load --protocol <h1|h1c|h2|h3> --host <host> --port <port> --server-name <name> --authority <authority> --path <path> --ca-cert <pem> --duration-seconds <n> --warmup-seconds <n> --concurrency <n> [--expect-status <status>] [--label <label>]
  perf-probe handshake --protocol <h1|h2|h3> --host <host> --port <port> --server-name <name> --ca-cert <pem> --duration-seconds <n> --concurrency <n> [--label <label>]
  perf-probe stress --mode <slowloris|large-header|large-body|idle|half-close> --host <host> --port <port> --authority <authority> --connections <n> --duration-seconds <n> [--bytes <n>] [--label <label>]"
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
    })
}

fn parse_handshake_args(args: impl Iterator<Item = String>) -> anyhow::Result<HandshakeArgs> {
    let values = flag_map(args)?;
    let protocol = Protocol::parse(required(&values, "--protocol")?)?;
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
    })
}

fn parse_stress_args(args: impl Iterator<Item = String>) -> anyhow::Result<StressArgs> {
    let values = flag_map(args)?;
    let mode = required(&values, "--mode")?.to_owned();
    Ok(StressArgs {
        label: values
            .get("--label")
            .cloned()
            .unwrap_or_else(|| format!("stress-{mode}")),
        mode,
        host: required(&values, "--host")?.to_owned(),
        port: parse_u16(&values, "--port")?,
        authority: required(&values, "--authority")?.to_owned(),
        connections: parse_usize(&values, "--connections")?,
        duration: Duration::from_secs(parse_u64(&values, "--duration-seconds")?),
        bytes: values
            .get("--bytes")
            .map(|value| value.parse().context("invalid --bytes value"))
            .transpose()?
            .unwrap_or(1024 * 1024),
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

async fn serve_upstream(args: UpstreamArgs) -> anyhow::Result<()> {
    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("failed to bind upstream to {}", args.listen))?;
    let name = Arc::<str>::from(args.name);

    loop {
        let (stream, peer_addr) = listener.accept().await.context("failed to accept TCP")?;
        let name = name.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let name = name.clone();
                async move { Ok::<_, Infallible>(upstream_response(request, name).await) }
            });
            if let Err(error) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                eprintln!("upstream connection from {peer_addr} failed: {error}");
            }
        });
    }
}

async fn upstream_response(request: Request<Incoming>, name: Arc<str>) -> Response<Full<Bytes>> {
    let (parts, body) = request.into_parts();
    let query = parse_query(parts.uri.query().unwrap_or(""));
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
        let mut response = Response::new(Full::new(Bytes::new()));
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
    let mut response = Response::new(Full::new(Bytes::from(body.clone())));
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
    response.headers_mut().insert(
        CONTENT_LENGTH,
        body.len()
            .to_string()
            .parse()
            .expect("valid content-length"),
    );
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

fn parse_query(raw: &str) -> BTreeMap<String, String> {
    raw.split('&')
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
    let (mut driver, mut send_request) = h3::client::builder()
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
    let uri: Uri = if version == Version::HTTP_11 {
        args.path.parse().context("failed to build HTTP/1.1 URI")?
    } else {
        format!("https://{}{}", args.authority, args.path)
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

async fn run_handshake(args: HandshakeArgs) -> anyhow::Result<()> {
    let deadline = Instant::now() + args.duration;
    let stats = SharedStats::new()?;
    let mut tasks = Vec::with_capacity(args.concurrency);
    for _ in 0..args.concurrency {
        let args = args.clone();
        let stats = stats.clone();
        tasks.push(tokio::spawn(async move {
            while Instant::now() < deadline {
                let started = Instant::now();
                let result = match args.protocol {
                    Protocol::H1 | Protocol::H2 => tls_connect(
                        &args.host,
                        args.port,
                        &args.server_name,
                        &args.ca_cert,
                        args.protocol.alpn(),
                    )
                    .await
                    .map(|_| ()),
                    Protocol::H1c => TcpStream::connect((args.host.as_str(), args.port))
                        .await
                        .map(|_| ())
                        .context("failed to connect cleartext HTTP/1.1 socket"),
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
                        connection.map(|_| ())
                    }
                };
                match result {
                    Ok(()) => stats.record_success(started.elapsed()),
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
            "handshakes": snapshot.requests,
            "errors": snapshot.errors,
            "handshake_per_sec": rate(snapshot.requests, args.duration.as_secs_f64()),
            "p50_ms": snapshot.p50_ms,
            "p95_ms": snapshot.p95_ms,
            "p99_ms": snapshot.p99_ms,
            "error_samples": snapshot.error_samples,
        })
    );
    Ok(())
}

async fn run_stress(args: StressArgs) -> anyhow::Result<()> {
    match args.mode.as_str() {
        "slowloris" | "large-header" | "large-body" | "idle" | "half-close" => {}
        _ => bail!("unsupported stress mode: {}", args.mode),
    }
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
                _ => unreachable!("mode already validated"),
            };
            match result {
                Ok(Some(status)) => stats.record_status(status),
                Ok(None) => stats.record_success(args.duration),
                Err(error) => {
                    let message = format!("{error:#}");
                    stats.record_error_sample(message.clone());
                    eprintln!("stress connection failed: {message}");
                }
            }
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

async fn read_http_status(stream: &mut TcpStream) -> anyhow::Result<Option<u16>> {
    let mut buffer = vec![0u8; 1024];
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buffer))
        .await
        .context("timed out reading HTTP status")?
        .context("failed to read HTTP status")?;
    if read == 0 {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&buffer[..read]);
    Ok(text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok()))
}

async fn tls_connect(
    host: &str,
    port: u16,
    server_name: &str,
    ca_cert: &str,
    alpn: &[u8],
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut config = tls_config(Path::new(ca_cert), alpn)?;
    config.enable_sni = true;
    let connector = TlsConnector::from(Arc::new(config));
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
    let endpoint = Endpoint::client(client_bind_addr(remote_addr))
        .context("failed to create QUIC endpoint")?;
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
    let mut config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
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
    let mut cursor = io::Cursor::new(bytes);
    rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .with_context(|| format!("failed to parse PEM certificates from {}", path.display()))
}

#[allow(dead_code)]
fn load_private_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut cursor = io::Cursor::new(bytes);
    rustls_pemfile::private_key(&mut cursor)
        .with_context(|| format!("failed to parse private key from {}", path.display()))?
        .ok_or_else(|| anyhow!("no private key found in {}", path.display()))
}

fn percentile_ms(histogram: &Histogram<u64>, percentile: f64) -> f64 {
    if histogram.len() == 0 {
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

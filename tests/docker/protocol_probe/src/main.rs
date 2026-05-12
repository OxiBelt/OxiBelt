use std::collections::BTreeMap;
use std::convert::Infallible;
use std::env;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context};
use bytes::{Buf, Bytes, BytesMut};
use h3_quinn::quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use h3_quinn::quinn::{
    ClientConfig as QuinnClientConfig, Endpoint, ServerConfig as QuinnServerConfig,
};
use http::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_LENGTH, CONTENT_TYPE};
use http::{Method, Request, Response, StatusCode, Uri, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
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
    omit_content_length: bool,
    headers: HeaderMap,
    ca_cert: String,
    expect_status: Option<u16>,
}

struct WebTransportMultiplexArgs {
    host: String,
    port: u16,
    server_name: String,
    authority: String,
    path: String,
    ca_cert: String,
    sessions: usize,
    expect_statuses: Vec<u16>,
}

impl DownstreamArgs {
    fn body_len(&self) -> usize {
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
        "downstream" => run_downstream_client(parse_downstream_args(args)?).await,
        "webtransport-multiplex" => {
            run_webtransport_multiplex_client(parse_webtransport_multiplex_args(args)?).await
        }
        _ => {
            usage();
            bail!("unknown command: {command}");
        }
    }
}

fn usage() {
    eprintln!(
    "usage:\n  protocol-probe h2-upstream --listen <addr:port> --cert <pem> --key <pem> --name <name>\n  protocol-probe h2c-upstream --listen <addr:port> --name <name>\n  protocol-probe h1-stall-upstream --listen <addr:port> --name <name> --read-delay-ms <ms>\n  protocol-probe h3-upstream --listen <addr:port> --cert <pem> --key <pem> --name <name>\n  protocol-probe webtransport-upstream --listen <addr:port> --cert <pem> --key <pem> --name <name>\n  protocol-probe downstream --protocol <h2|h3> --host <host> --port <port> --server-name <sni> --authority <authority> --path <path> --ca-cert <pem> [--body <text>|--body-bytes <n>] [--body-chunk-size <n>] [--omit-content-length] [--header <name:value>] [--expect-status <status>]\n  protocol-probe webtransport-multiplex --host <host> --port <port> --server-name <sni> --authority <authority> --path <path> --ca-cert <pem> --sessions <n> --expect-statuses <csv>"
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

fn parse_webtransport_multiplex_args(
    mut args: impl Iterator<Item = String>,
) -> anyhow::Result<WebTransportMultiplexArgs> {
    let mut host = None;
    let mut port = None;
    let mut server_name = None;
    let mut authority = None;
    let mut path = None;
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
    let expect_statuses =
        expect_statuses.ok_or_else(|| anyhow!("--expect-statuses is required"))?;
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
        ca_cert: ca_cert.ok_or_else(|| anyhow!("--ca-cert is required"))?,
        sessions,
        expect_statuses,
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
            "--header" => {
                let (name, value) = value
                    .split_once(':')
                    .ok_or_else(|| anyhow!("invalid --header value; expected name:value"))?;
                headers.insert(
                    HeaderName::try_from(name.trim()).context("invalid --header name")?,
                    HeaderValue::from_str(value.trim()).context("invalid --header value")?,
                );
            }
            "--ca-cert" => ca_cert = Some(value),
            "--expect-status" => {
                expect_status = Some(value.parse().context("invalid --expect-status value")?);
            }
            _ => bail!("unknown downstream flag: {flag}"),
        }
    }

    let server_name = server_name.ok_or_else(|| anyhow!("--server-name is required"))?;
    Ok(DownstreamArgs {
        protocol: protocol.ok_or_else(|| anyhow!("--protocol is required"))?,
        host: host.ok_or_else(|| anyhow!("--host is required"))?,
        port: port.ok_or_else(|| anyhow!("--port is required"))?,
        authority: authority.unwrap_or_else(|| server_name.clone()),
        server_name,
        path: path.ok_or_else(|| anyhow!("--path is required"))?,
        method,
        body,
        body_bytes,
        body_chunk_size,
        omit_content_length,
        headers,
        ca_cert: ca_cert.ok_or_else(|| anyhow!("--ca-cert is required"))?,
        expect_status,
    })
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
    let mut server_config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
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
            if let Err(error) = handle_h2c_upstream_connection(stream, upstream_name, scheme).await
            {
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

async fn read_chunked_body_observation(stream: &mut TcpStream) -> anyhow::Result<(usize, bool)> {
    let started = tokio::time::Instant::now();
    let mut body_bytes = 0usize;
    let mut tail = Vec::new();

    loop {
        if started.elapsed() > Duration::from_secs(10) {
            return Ok((body_bytes, false));
        }

        let mut chunk = [0u8; 8192];
        let read =
            match tokio::time::timeout(Duration::from_millis(250), stream.read(&mut chunk)).await {
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
    let mut server_config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
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

    loop {
        let Some(incoming) = endpoint.accept().await else {
            return Ok(());
        };
        let upstream_name = upstream_name.clone();
        let scheme = scheme.clone();
        let instance_id = instance_id.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    let connection_id = connection.stable_id();
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

async fn handle_h3_upstream_connection(
    connection: h3_quinn::quinn::Connection,
    upstream_name: Arc<str>,
    scheme: Arc<str>,
    instance_id: Arc<str>,
    connection_id: usize,
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
    connection_id: usize,
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

async fn run_webtransport_multiplex_client(
    args: WebTransportMultiplexArgs,
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
    request
        .extensions_mut()
        .insert(h3::ext::Protocol::WEB_TRANSPORT);
    Ok(request)
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

fn downstream_client_config(path: &Path, alpn: &[u8]) -> anyhow::Result<ClientConfig> {
    let mut config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
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
    let mut cursor = io::Cursor::new(bytes);
    rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .with_context(|| format!("failed to parse PEM certificates from {}", path.display()))
}

fn load_private_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut cursor = io::Cursor::new(bytes);
    rustls_pemfile::private_key(&mut cursor)
        .with_context(|| format!("failed to parse private key from {}", path.display()))?
        .ok_or_else(|| anyhow!("no private key found in {}", path.display()))
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

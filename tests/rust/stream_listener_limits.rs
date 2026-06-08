#[path = "common/mod.rs"]
mod common;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use oxibelt::config::{Config, RuntimeOverrides};
use oxibelt::server;
use oxibelt::state::{AppHandle, AppSnapshot};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

#[tokio::test]
async fn stream_listener_enforces_global_connection_limit() {
    let temp_dir = common::TempDir::new("stream-limit");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "stream-limit");
    let (https_port, stream_port) = unused_loopback_ports().await;
    let stream_addr: SocketAddr = format!("127.0.0.1:{stream_port}")
        .parse()
        .expect("stream listener address should parse");

    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream should bind");
    let upstream_addr = upstream_listener
        .local_addr()
        .expect("upstream address should be available");
    let upstream_accepts = Arc::new(AtomicUsize::new(0));
    let upstream_notify = Arc::new(Notify::new());
    let upstream_task = hold_upstream_connections(
        upstream_listener,
        upstream_accepts.clone(),
        upstream_notify.clone(),
    );

    let mut raw = common::minimal_config_toml(&cert_path, &key_path).replace(
        "https_bind = \"127.0.0.1:8443\"",
        &format!("https_bind = \"127.0.0.1:{https_port}\""),
    );
    raw.push_str(&format!(
        r#"

[limits]
max_connections = 1
max_connections_per_ip = 1

[[stream_listeners]]
name = "tcp"
bind = "{stream_addr}"
target = "{upstream_addr}"
connect_timeout_ms = 1000
idle_timeout_ms = 5000
"#
    ));

    let config = parse_config(&raw);
    let snapshot = AppSnapshot::new(config)
        .await
        .expect("application snapshot should initialize");
    let state = AppHandle::new(snapshot);
    let server_task = tokio::spawn(server::serve(state, None, RuntimeOverrides::default()));

    let first_client = connect_with_retry(stream_addr, &server_task).await;
    wait_for_accepts(&upstream_accepts, &upstream_notify, 1).await;

    let mut second_client = TcpStream::connect(stream_addr)
        .await
        .expect("second client should reach the listener before being rejected");
    let mut buffer = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(1), second_client.read(&mut buffer)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(read)) => panic!("rejected stream unexpectedly returned {read} bytes"),
        Err(_) => panic!("second stream connection stayed open instead of being rejected"),
    }

    assert_eq!(
        upstream_accepts.load(Ordering::SeqCst),
        1,
        "rejected stream connection must not open another upstream connection"
    );

    drop(first_client);
    server_task.abort();
    upstream_task.abort();
}

#[tokio::test]
async fn udp_stream_listener_proxies_datagrams_to_default_target() {
    let temp_dir = common::TempDir::new("udp-stream-echo");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "udp-stream-echo");
    let https_port = unused_loopback_port().await;
    let stream_port = unused_udp_loopback_port().await;
    let stream_addr: SocketAddr = format!("127.0.0.1:{stream_port}")
        .parse()
        .expect("UDP stream listener address should parse");

    let upstream_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("UDP echo upstream should bind");
    let upstream_addr = upstream_socket
        .local_addr()
        .expect("UDP upstream address should be available");
    let upstream_task = udp_echo_upstream(upstream_socket);

    let mut raw = common::minimal_config_toml(&cert_path, &key_path).replace(
        "https_bind = \"127.0.0.1:8443\"",
        &format!("https_bind = \"127.0.0.1:{https_port}\""),
    );
    raw.push_str(&format!(
        r#"

[[stream_listeners]]
name = "udp"
network = "udp"
bind = "{stream_addr}"
target = "{upstream_addr}"
connect_timeout_ms = 1000
idle_timeout_ms = 1000
max_udp_flows = 32
"#
    ));

    let config = parse_config(&raw);
    let snapshot = AppSnapshot::new(config)
        .await
        .expect("application snapshot should initialize");
    let state = AppHandle::new(snapshot);
    let server_task = tokio::spawn(server::serve(state, None, RuntimeOverrides::default()));

    let client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("UDP client should bind");
    let response = udp_exchange_with_retry(&client, stream_addr, b"hello", &server_task).await;
    assert_eq!(&response, b"hello");

    server_task.abort();
    upstream_task.abort();
}

#[tokio::test]
async fn first_request_real_ip_connection_limit_uses_resolved_client_ip() {
    let temp_dir = common::TempDir::new("first-request-real-ip-limit");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "first-request-real-ip-limit");
    let (state, http_addr, upstream_task) =
        start_http_proxy_with_connection_identity(&cert_path, &key_path, "first_request_real_ip")
            .await;
    let server_task = tokio::spawn(server::serve(state, None, RuntimeOverrides::default()));

    let mut first = connect_with_retry(http_addr, &server_task).await;
    write_http_request(
        &mut first,
        "example.com",
        "/hold-first",
        "203.0.113.10",
        "keep-alive",
    )
    .await;
    assert_eq!(read_response_status(&mut first).await, 200);

    assert_eq!(
        one_shot_http_status(http_addr, "example.com", "/same-client", "203.0.113.10").await,
        429
    );
    assert_eq!(
        one_shot_http_status(http_addr, "example.com", "/other-client", "203.0.113.11").await,
        200
    );

    drop(first);
    server_task.abort();
    upstream_task.abort();
}

#[tokio::test]
async fn per_request_real_ip_connection_limit_releases_after_response_body() {
    let temp_dir = common::TempDir::new("per-request-real-ip-limit");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "per-request-real-ip-limit");
    let (state, http_addr, upstream_task) =
        start_http_proxy_with_connection_identity(&cert_path, &key_path, "per_request_real_ip")
            .await;
    let server_task = tokio::spawn(server::serve(state, None, RuntimeOverrides::default()));

    let mut first = connect_with_retry(http_addr, &server_task).await;
    write_http_request(
        &mut first,
        "example.com",
        "/hold-per-request",
        "203.0.113.20",
        "keep-alive",
    )
    .await;
    assert_eq!(read_response_status(&mut first).await, 200);

    assert_eq!(
        one_shot_http_status(http_addr, "example.com", "/blocked", "203.0.113.20").await,
        429
    );

    let mut body = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(2), first.read_exact(&mut body))
        .await
        .expect("first response body should not time out")
        .expect("first response body should finish");
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(
        one_shot_http_status(http_addr, "example.com", "/after-release", "203.0.113.20").await,
        200
    );

    server_task.abort();
    upstream_task.abort();
}

fn parse_config(raw: &str) -> Config {
    let config: Config = toml::from_str(raw).expect("config should parse");
    config.validate().expect("config should validate");
    config
}

async fn unused_loopback_ports() -> (u16, u16) {
    let first = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral port should bind");
    let second = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("second ephemeral port should bind");
    let first_port = first
        .local_addr()
        .expect("first ephemeral listener address should be available")
        .port();
    let second_port = second
        .local_addr()
        .expect("second ephemeral listener address should be available")
        .port();
    (first_port, second_port)
}

async fn unused_loopback_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral port should bind");
    listener
        .local_addr()
        .expect("ephemeral listener address should be available")
        .port()
}

async fn unused_udp_loopback_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("ephemeral UDP port should bind");
    socket
        .local_addr()
        .expect("ephemeral UDP listener address should be available")
        .port()
}

async fn start_http_proxy_with_connection_identity(
    cert_path: &Path,
    key_path: &Path,
    identity_mode: &str,
) -> (AppHandle, SocketAddr, JoinHandle<()>) {
    let https_port = unused_loopback_port().await;
    let http_port = unused_loopback_port().await;
    let http_addr: SocketAddr = format!("127.0.0.1:{http_port}")
        .parse()
        .expect("HTTP listener address should parse");
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("delayed upstream should bind");
    let upstream_addr = upstream_listener
        .local_addr()
        .expect("delayed upstream address should be available");
    let upstream_task = delayed_http_upstream(
        upstream_listener,
        Duration::from_millis(600),
        b"hello".to_vec(),
    );

    let mut raw = common::minimal_config_toml(cert_path, key_path)
        .replace(
            "https_bind = \"127.0.0.1:8443\"",
            &format!("https_bind = \"127.0.0.1:{https_port}\""),
        )
        .replace(
            "http3 = false",
            &format!("http3 = false\nhttp_bind = \"{http_addr}\"\nhttp_mode = \"proxy\""),
        )
        .replace(
            "origin = \"https://app.internal.example\"",
            &format!("origin = \"http://{upstream_addr}/origin\""),
        )
        .replace("max_http_version = \"h2\"", "max_http_version = \"h1\"");
    raw.push_str(&format!(
        r#"

[proxy.real_ip]
enabled = true
trusted_proxies = ["127.0.0.1/32"]
header = "x-forwarded-for"
recursive = true
fail_on_untrusted_forwarded_headers = true

[limits]
max_connections = 64
max_connections_per_ip = 1
connection_limit_identity = "{identity_mode}"
"#
    ));

    let config = parse_config(&raw);
    let snapshot = AppSnapshot::new(config)
        .await
        .expect("application snapshot should initialize");
    (AppHandle::new(snapshot), http_addr, upstream_task)
}

fn delayed_http_upstream(
    listener: TcpListener,
    body_delay: Duration,
    body: Vec<u8>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((mut stream, _peer_addr)) = listener.accept().await {
            let body = body.clone();
            tokio::spawn(async move {
                let mut received = Vec::new();
                let mut buffer = [0u8; 1024];
                loop {
                    let read = stream
                        .read(&mut buffer)
                        .await
                        .expect("upstream request read should succeed");
                    if read == 0 {
                        return;
                    }
                    received.extend_from_slice(&buffer[..read]);
                    if received.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let headers = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream
                    .write_all(headers.as_bytes())
                    .await
                    .expect("upstream response headers should write");
                tokio::time::sleep(body_delay).await;
                stream
                    .write_all(&body)
                    .await
                    .expect("upstream response body should write");
            });
        }
    })
}

async fn one_shot_http_status(
    addr: SocketAddr,
    host: &str,
    path: &str,
    x_forwarded_for: &str,
) -> u16 {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("client should connect to HTTP listener");
    write_http_request(&mut stream, host, path, x_forwarded_for, "close").await;
    read_response_status(&mut stream).await
}

async fn write_http_request(
    stream: &mut TcpStream,
    host: &str,
    path: &str,
    x_forwarded_for: &str,
    connection: &str,
) {
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nX-Forwarded-For: {x_forwarded_for}\r\nContent-Length: 0\r\nConnection: {connection}\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("client request should write");
}

async fn read_response_status(stream: &mut TcpStream) -> u16 {
    let mut received = Vec::new();
    let mut buffer = [0u8; 256];
    let deadline = Duration::from_secs(2);
    let result = tokio::time::timeout(deadline, async {
        loop {
            let read = stream
                .read(&mut buffer)
                .await
                .expect("response read should succeed");
            assert!(read > 0, "connection closed before response headers");
            received.extend_from_slice(&buffer[..read]);
            if received.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
    })
    .await;
    assert!(result.is_ok(), "response headers timed out");
    let headers = String::from_utf8_lossy(&received);
    headers
        .lines()
        .next()
        .and_then(|status| status.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("invalid HTTP response status line: {headers}"))
}

fn hold_upstream_connections(
    listener: TcpListener,
    accepts: Arc<AtomicUsize>,
    notify: Arc<Notify>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _peer_addr)) = listener.accept().await {
            held.push(stream);
            accepts.fetch_add(1, Ordering::SeqCst);
            notify.notify_waiters();
        }
    })
}

fn udp_echo_upstream(socket: UdpSocket) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = [0u8; 2048];
        while let Ok((read, peer_addr)) = socket.recv_from(&mut buffer).await {
            socket
                .send_to(&buffer[..read], peer_addr)
                .await
                .expect("UDP echo response should send");
        }
    })
}

async fn udp_exchange_with_retry(
    socket: &UdpSocket,
    target: SocketAddr,
    payload: &[u8],
    server_task: &JoinHandle<anyhow::Result<()>>,
) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut buffer = [0u8; 2048];
    loop {
        assert!(
            !server_task.is_finished(),
            "server exited before UDP stream listener responded"
        );
        socket
            .send_to(payload, target)
            .await
            .expect("UDP client datagram should send");
        match tokio::time::timeout(Duration::from_millis(100), socket.recv_from(&mut buffer)).await
        {
            Ok(Ok((read, _peer))) => return buffer[..read].to_vec(),
            Ok(Err(error)) if Instant::now() < deadline => {
                let _ = error;
            }
            Err(_) if Instant::now() < deadline => {}
            Ok(Err(error)) => panic!("UDP stream listener receive failed: {error}"),
            Err(_) => panic!("UDP stream listener did not respond before timeout"),
        }
    }
}

async fn connect_with_retry(
    addr: SocketAddr,
    server_task: &JoinHandle<anyhow::Result<()>>,
) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        assert!(
            !server_task.is_finished(),
            "server exited before listener accepted connections"
        );
        match TcpStream::connect(addr).await {
            Ok(stream) => return stream,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => panic!("stream listener did not become ready: {error}"),
        }
    }
}

async fn wait_for_accepts(accepts: &AtomicUsize, notify: &Notify, expected: usize) {
    let result = tokio::time::timeout(Duration::from_secs(2), async {
        while accepts.load(Ordering::SeqCst) < expected {
            notify.notified().await;
        }
    })
    .await;
    assert!(
        result.is_ok(),
        "upstream accepted {} connections, expected at least {expected}",
        accepts.load(Ordering::SeqCst)
    );
}

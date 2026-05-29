#[path = "common/mod.rs"]
mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use oxibelt::config::{Config, RuntimeOverrides};
use oxibelt::server;
use oxibelt::state::{AppHandle, AppSnapshot};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

#[tokio::test]
async fn tcp_sni_forward_peeks_and_tunnels_client_hello() {
    let temp_dir = common::TempDir::new("sni-forward-tcp");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "sni-forward-tcp");
    let https_port = unused_loopback_port().await;
    let proxy_addr: SocketAddr = format!("127.0.0.1:{https_port}")
        .parse()
        .expect("proxy address should parse");

    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("raw upstream should bind");
    let upstream_addr = upstream_listener
        .local_addr()
        .expect("raw upstream address should be available");
    let upstream_task = tokio::spawn(read_one_tls_record(upstream_listener));

    let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
        "https_bind = \"127.0.0.1:8443\"",
        &format!("https_bind = \"127.0.0.1:{https_port}\""),
    ) + &format!(
        r#"

[sni_forward]
enabled = true
client_hello_max_bytes = 4096
idle_timeout_ms = 5000

[[sni_forward.rules]]
name = "raw-upstream"
server_names = ["forward.example.com"]
target = "{upstream_addr}"
protocols = ["tcp_tls"]
connect_timeout_ms = 1000
idle_timeout_ms = 5000
"#
    );

    let config = parse_config(&raw);
    let snapshot = AppSnapshot::new(config)
        .await
        .expect("application snapshot should initialize");
    let state = AppHandle::new(snapshot);
    let server_task = tokio::spawn(server::serve(state, None, RuntimeOverrides::default()));

    let mut client = connect_with_retry(proxy_addr, &server_task).await;
    let client_hello = tls_client_hello_record("forward.example.com");
    client
        .write_all(&client_hello)
        .await
        .expect("client hello should write");

    let forwarded = tokio::time::timeout(Duration::from_secs(2), upstream_task)
        .await
        .expect("raw upstream should receive forwarded ClientHello")
        .expect("raw upstream task should not panic")
        .expect("raw upstream should read TLS record");

    assert_eq!(forwarded, client_hello);
    server_task.abort();
}

#[tokio::test]
async fn tcp_sni_forward_rejects_ambiguous_client_hello() {
    let temp_dir = common::TempDir::new("sni-forward-ambiguous-tcp");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "sni-forward-ambiguous-tcp");
    let https_port = unused_loopback_port().await;
    let proxy_addr: SocketAddr = format!("127.0.0.1:{https_port}")
        .parse()
        .expect("proxy address should parse");

    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("raw upstream should bind");
    let upstream_addr = upstream_listener
        .local_addr()
        .expect("raw upstream address should be available");
    let upstream_accepts = Arc::new(AtomicUsize::new(0));
    let upstream_notify = Arc::new(Notify::new());
    let upstream_task = hold_upstream_connections(
        upstream_listener,
        upstream_accepts.clone(),
        upstream_notify.clone(),
    );

    let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
        "https_bind = \"127.0.0.1:8443\"",
        &format!("https_bind = \"127.0.0.1:{https_port}\""),
    ) + &format!(
        r#"

[[routes]]
name = "secret-local"
hosts = ["secret.example.com"]
path_prefix = "/"
upstream = "app"

[sni_forward]
enabled = true
client_hello_max_bytes = 4096
idle_timeout_ms = 5000

[[sni_forward.rules]]
name = "raw-upstream"
server_names = ["forward.example.com"]
target = "{upstream_addr}"
protocols = ["tcp_tls"]
connect_timeout_ms = 1000
idle_timeout_ms = 5000
"#
    );

    let config = parse_config(&raw);
    let snapshot = AppSnapshot::new(config)
        .await
        .expect("application snapshot should initialize");
    let state = AppHandle::new(snapshot);
    let server_task = tokio::spawn(server::serve(state, None, RuntimeOverrides::default()));

    let mut client = connect_with_retry(proxy_addr, &server_task).await;
    let client_hello =
        tls_client_hello_record_with_duplicate_sni("forward.example.com", "secret.example.com");
    client
        .write_all(&client_hello)
        .await
        .expect("ambiguous ClientHello should write");

    let mut read_buffer = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(2), client.read(&mut read_buffer)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(read)) => panic!("ambiguous SNI should close, read {read} bytes instead"),
        Err(_) => panic!("ambiguous SNI connection stayed open"),
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        upstream_accepts.load(Ordering::SeqCst),
        0,
        "ambiguous forwarded SNI session must not reach upstream"
    );
    server_task.abort();
    upstream_task.abort();
}

#[tokio::test]
async fn tcp_sni_forward_honors_real_ip_connection_limits() {
    let temp_dir = common::TempDir::new("sni-forward-tcp-limits");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "sni-forward-tcp-limits");
    let https_port = unused_loopback_port().await;
    let proxy_addr: SocketAddr = format!("127.0.0.1:{https_port}")
        .parse()
        .expect("proxy address should parse");

    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("raw upstream should bind");
    let upstream_addr = upstream_listener
        .local_addr()
        .expect("raw upstream address should be available");
    let upstream_accepts = Arc::new(AtomicUsize::new(0));
    let upstream_notify = Arc::new(Notify::new());
    let upstream_task = hold_upstream_connections(
        upstream_listener,
        upstream_accepts.clone(),
        upstream_notify.clone(),
    );

    let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
        "https_bind = \"127.0.0.1:8443\"",
        &format!("https_bind = \"127.0.0.1:{https_port}\""),
    ) + &format!(
        r#"

[limits]
max_connections = 64
max_connections_per_ip = 1
connection_limit_identity = "first_request_real_ip"

[sni_forward]
enabled = true
client_hello_max_bytes = 4096
idle_timeout_ms = 5000

[[sni_forward.rules]]
name = "raw-upstream"
server_names = ["limit.example.com"]
target = "{upstream_addr}"
protocols = ["tcp_tls"]
connect_timeout_ms = 1000
idle_timeout_ms = 5000
"#
    );

    let config = parse_config(&raw);
    let snapshot = AppSnapshot::new(config)
        .await
        .expect("application snapshot should initialize");
    let state = AppHandle::new(snapshot);
    let server_task = tokio::spawn(server::serve(state, None, RuntimeOverrides::default()));
    let client_hello = tls_client_hello_record("limit.example.com");

    let mut first = connect_with_retry(proxy_addr, &server_task).await;
    first
        .write_all(&client_hello)
        .await
        .expect("first ClientHello should write");
    wait_for_accept_count(&upstream_accepts, &upstream_notify, 1).await;

    let mut second = TcpStream::connect(proxy_addr)
        .await
        .expect("second client should connect");
    second
        .write_all(&client_hello)
        .await
        .expect("second ClientHello should write before limit rejection");
    let mut read_buffer = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(2), second.read(&mut read_buffer)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(read)) => panic!("limited SNI forward should close, read {read} bytes instead"),
        Err(_) => panic!("limited SNI forward stayed open"),
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        upstream_accepts.load(Ordering::SeqCst),
        1,
        "rejected forwarded SNI session must not reach upstream"
    );
    server_task.abort();
    upstream_task.abort();
}

fn parse_config(raw: &str) -> Config {
    let config: Config = toml::from_str(raw).expect("config should parse");
    config.validate().expect("config should validate");
    config
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

async fn connect_with_retry(
    addr: SocketAddr,
    server_task: &JoinHandle<anyhow::Result<()>>,
) -> TcpStream {
    let start = std::time::Instant::now();
    loop {
        assert!(
            !server_task.is_finished(),
            "server task exited before connect"
        );
        match TcpStream::connect(addr).await {
            Ok(stream) => return stream,
            Err(error) if start.elapsed() < Duration::from_secs(3) => {
                let _ = error;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => panic!("failed to connect to {addr}: {error}"),
        }
    }
}

async fn read_one_tls_record(listener: TcpListener) -> std::io::Result<Vec<u8>> {
    let (mut stream, _) = listener.accept().await?;
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut record = header.to_vec();
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    record.extend_from_slice(&body);
    Ok(record)
}

fn hold_upstream_connections(
    listener: TcpListener,
    accepts: Arc<AtomicUsize>,
    notify: Arc<Notify>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((mut stream, _peer_addr)) = listener.accept().await {
            accepts.fetch_add(1, Ordering::SeqCst);
            notify.notify_waiters();
            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                let _ = stream.read(&mut buffer).await;
                std::future::pending::<()>().await;
            });
        }
    })
}

async fn wait_for_accept_count(accepts: &AtomicUsize, notify: &Notify, expected: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if accepts.load(Ordering::SeqCst) >= expected {
                return;
            }
            notify.notified().await;
        }
    })
    .await
    .expect("upstream should accept expected forwarded sessions");
}

fn tls_client_hello_record(host: &str) -> Vec<u8> {
    tls_client_hello_record_with_extensions(&server_name_extension(host))
}

fn tls_client_hello_record_with_duplicate_sni(first: &str, second: &str) -> Vec<u8> {
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&server_name_extension(first));
    extensions.extend_from_slice(&server_name_extension(second));
    tls_client_hello_record_with_extensions(&extensions)
}

fn server_name_extension(host: &str) -> Vec<u8> {
    let mut extension = Vec::new();
    let sni_list_len = 1 + 2 + host.len();
    push_u16(&mut extension, 0x0000);
    push_u16(&mut extension, (2 + sni_list_len) as u16);
    push_u16(&mut extension, sni_list_len as u16);
    extension.push(0x00);
    push_u16(&mut extension, host.len() as u16);
    extension.extend_from_slice(host.as_bytes());
    extension
}

fn tls_client_hello_record_with_extensions(extensions: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    push_u16(&mut body, 0x0303);
    body.extend_from_slice(&[0x11; 32]);
    body.push(0);
    push_u16(&mut body, 2);
    push_u16(&mut body, 0x1301);
    body.push(1);
    body.push(0);
    push_u16(&mut body, extensions.len() as u16);
    body.extend_from_slice(extensions);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    push_u24(&mut handshake, body.len());
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16);
    push_u16(&mut record, 0x0301);
    push_u16(&mut record, handshake.len() as u16);
    record.extend_from_slice(&handshake);
    record
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u24(out: &mut Vec<u8>, value: usize) {
    out.push(((value >> 16) & 0xff) as u8);
    out.push(((value >> 8) & 0xff) as u8);
    out.push((value & 0xff) as u8);
}

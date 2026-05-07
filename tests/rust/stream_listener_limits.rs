#[path = "common/mod.rs"]
mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use oxibelt::config::{Config, RuntimeOverrides};
use oxibelt::server;
use oxibelt::state::{AppHandle, AppSnapshot};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
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

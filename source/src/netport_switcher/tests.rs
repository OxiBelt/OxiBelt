use std::net::TcpStream;
use std::sync::atomic::AtomicBool;

use super::*;

#[test]
fn broker_denies_unlisted_bind() {
  let broker = NetportBroker {
    allowlist: HashSet::new(),
    socket_path: PathBuf::from("/tmp/unused.sock"),
    io_timeout: Duration::from_millis(100),
    allowed_uid: 10001,
    allowed_gid: 10001,
  };
  let request = BindRequest {
    transport: SwitcherTransport::Tcp,
    bind: "127.0.0.1:443".parse().expect("bind should parse"),
    purpose: "downstream HTTPS".to_string(),
    workers: 1,
    worker_index: 0,
    reuse_port: false,
    backlog: Some(16),
    udp: None,
  };

  let error = broker
    .bind_allowed_socket(&request)
    .expect_err("unlisted bind must be denied");

  assert!(error.to_string().contains("startup allowlist"));
}

#[test]
fn broker_denies_mismatched_socket_options() {
  let allowed_bind: SocketAddr = "127.0.0.1:443".parse().expect("bind should parse");
  let broker = NetportBroker {
    allowlist: HashSet::from([AllowedBind {
      transport: SwitcherTransport::Tcp,
      bind: allowed_bind,
      purpose: "downstream HTTPS".to_string(),
      workers: 1,
      reuse_port: false,
      backlog: Some(16),
      udp: None,
    }]),
    socket_path: PathBuf::from("/tmp/unused.sock"),
    io_timeout: Duration::from_millis(100),
    allowed_uid: 10001,
    allowed_gid: 10001,
  };
  let request = BindRequest {
    transport: SwitcherTransport::Tcp,
    bind: allowed_bind,
    purpose: "downstream HTTPS".to_string(),
    workers: 1,
    worker_index: 0,
    reuse_port: true,
    backlog: Some(16),
    udp: None,
  };

  let error = broker
    .bind_allowed_socket(&request)
    .expect_err("mismatched reuse_port must be denied");

  assert!(error.to_string().contains("startup allowlist"));
}

#[test]
fn fd_passing_returns_usable_tcp_listener() {
  let listener = StdTcpListener::bind("127.0.0.1:0").expect("listener should bind");
  listener
    .set_nonblocking(true)
    .expect("listener should become nonblocking");
  let addr = listener.local_addr().expect("listener addr");
  let (mut server, mut client) = UnixStream::pair().expect("Unix pair should create");

  std::thread::spawn(move || {
    write_frame(&mut server, &BindResponse::Ok).expect("response frame should write");
    send_fd(&server, listener.as_fd()).expect("fd should send");
  });

  let response: BindResponse = read_frame(&mut client).expect("response should read");
  assert!(matches!(response, BindResponse::Ok));
  let fd = recv_fd(&client).expect("fd should receive");
  let received = StdTcpListener::from(fd);
  received
    .set_nonblocking(false)
    .expect("received listener should become blocking");
  let connect = std::thread::spawn(move || TcpStream::connect(addr));
  let (_accepted, _) = received.accept().expect("received listener should accept");
  connect
    .join()
    .expect("connect thread should join")
    .expect("client should connect");
}

#[test]
fn fd_passing_returns_usable_udp_socket() {
  let socket = StdUdpSocket::bind("127.0.0.1:0").expect("UDP socket should bind");
  socket
    .set_nonblocking(true)
    .expect("UDP socket should become nonblocking");
  let addr = socket.local_addr().expect("UDP addr");
  let (mut server, mut client) = UnixStream::pair().expect("Unix pair should create");

  std::thread::spawn(move || {
    write_frame(&mut server, &BindResponse::Ok).expect("response frame should write");
    send_fd(&server, socket.as_fd()).expect("fd should send");
  });

  let response: BindResponse = read_frame(&mut client).expect("response should read");
  assert!(matches!(response, BindResponse::Ok));
  let fd = recv_fd(&client).expect("fd should receive");
  let received = StdUdpSocket::from(fd);
  received
    .set_nonblocking(false)
    .expect("received UDP socket should become blocking");
  let sender = StdUdpSocket::bind("127.0.0.1:0").expect("sender should bind");
  sender
    .send_to(b"ok", addr)
    .expect("sender should send datagram");
  let mut buf = [0u8; 8];
  let (read, _) = received
    .recv_from(&mut buf)
    .expect("received socket should read");
  assert_eq!(&buf[..read], b"ok");
}

#[test]
fn serve_loop_exits_when_stopped() {
  let broker = Arc::new(NetportBroker {
    allowlist: HashSet::new(),
    socket_path: PathBuf::from("/tmp/unused.sock"),
    io_timeout: Duration::from_millis(100),
    allowed_uid: 10001,
    allowed_gid: 10001,
  });
  let dir = tempfile::tempdir().expect("temporary directory should create");
  let listener =
    UnixListener::bind(dir.path().join("control.sock")).expect("test listener should bind");
  listener
    .set_nonblocking(true)
    .expect("listener should become nonblocking");
  let stopped = Arc::new(AtomicBool::new(true));
  broker
    .serve_until_stopped(listener, stopped)
    .expect("stopped broker should exit");
}

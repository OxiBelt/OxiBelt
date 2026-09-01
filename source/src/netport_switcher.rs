//! Privileged data-plane socket broker for containerized low-port binds.
//! The broker runs as root, binds only startup-allowed sockets, and passes FDs to OxiBelt.

use std::collections::HashSet;
use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{
  Arc,
  atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Duration;

use anyhow::{Context, bail};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use rustix::net::{
  RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer, SendAncillaryMessage,
  SendFlags, recvmsg, sendmsg,
};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::TcpListener;
use tracing::{debug, warn};

use crate::config::{Config, NetportSwitcherConfig, QuicSocketConfig, StreamNetwork};

pub const SOCKET_ENV: &str = "OXIBELT_NETPORT_SWITCHER_SOCKET";

const CONTROL_SOCKET_NAME: &str = "control.sock";
const PRIVILEGED_PORT_MAX: u16 = 1023;
const MAX_FRAME_LEN: usize = 64 * 1024;
static SWITCHER_CLIENT_ENABLED: AtomicBool = AtomicBool::new(false);
static SWITCHER_IO_TIMEOUT_MS: AtomicU64 = AtomicU64::new(5000);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct SwitcherTcpOptions {
  pub(crate) workers: usize,
  pub(crate) reuse_port: bool,
  pub(crate) backlog: u32,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct SwitcherUdpOptions {
  pub(crate) workers: usize,
  pub(crate) reuse_address: bool,
  pub(crate) reuse_port: bool,
  pub(crate) receive_buffer_bytes: usize,
  pub(crate) send_buffer_bytes: usize,
}

impl SwitcherUdpOptions {
  pub(crate) fn simple() -> Self {
    Self {
      workers: 1,
      reuse_address: true,
      reuse_port: false,
      receive_buffer_bytes: 0,
      send_buffer_bytes: 0,
    }
  }

  pub(crate) fn quic(config: &QuicSocketConfig) -> Self {
    Self {
      workers: config.workers,
      reuse_address: false,
      reuse_port: config.reuse_port,
      receive_buffer_bytes: config.receive_buffer_bytes,
      send_buffer_bytes: config.send_buffer_bytes,
    }
  }
}

#[derive(Debug, Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SwitcherTransport {
  Tcp,
  Udp,
}

#[derive(Debug, Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
struct UdpRequestOptions {
  reuse_address: bool,
  reuse_port: bool,
  receive_buffer_bytes: usize,
  send_buffer_bytes: usize,
}

#[derive(Debug, Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
struct BindRequest {
  transport: SwitcherTransport,
  bind: SocketAddr,
  purpose: String,
  workers: usize,
  worker_index: usize,
  reuse_port: bool,
  backlog: Option<u32>,
  udp: Option<UdpRequestOptions>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum BindResponse {
  Ok,
  Error { message: String },
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct AllowedBind {
  transport: SwitcherTransport,
  bind: SocketAddr,
  purpose: String,
  workers: usize,
  reuse_port: bool,
  backlog: Option<u32>,
  udp: Option<UdpRequestOptions>,
}

impl AllowedBind {
  fn from_request(request: &BindRequest) -> Self {
    Self {
      transport: request.transport.clone(),
      bind: request.bind,
      purpose: request.purpose.clone(),
      workers: request.workers,
      reuse_port: request.reuse_port,
      backlog: request.backlog,
      udp: request.udp.clone(),
    }
  }
}

pub fn control_socket_path(config: &NetportSwitcherConfig) -> PathBuf {
  config.socket_dir.join(CONTROL_SOCKET_NAME)
}

pub fn ensure_required_runtime_socket(config: &Config) -> anyhow::Result<()> {
  if config.runtime.netport_switcher.enabled && std::env::var_os(SOCKET_ENV).is_none() {
    bail!(
      "runtime.netport_switcher.enabled=true requires {SOCKET_ENV}; start OxiBelt through oxibelt-netport-switcher"
    );
  }
  SWITCHER_CLIENT_ENABLED.store(config.runtime.netport_switcher.enabled, Ordering::Relaxed);
  SWITCHER_IO_TIMEOUT_MS.store(
    config.runtime.netport_switcher.io_timeout_ms,
    Ordering::Relaxed,
  );
  Ok(())
}

pub(crate) fn bind_tcp_listener(
  bind: SocketAddr,
  options: SwitcherTcpOptions,
  purpose: &str,
  worker_index: usize,
) -> anyhow::Result<Option<TcpListener>> {
  if !should_request_switcher(bind) {
    return Ok(None);
  }
  let request = BindRequest {
    transport: SwitcherTransport::Tcp,
    bind,
    purpose: purpose.to_string(),
    workers: options.workers,
    worker_index,
    reuse_port: options.reuse_port,
    backlog: Some(options.backlog),
    udp: None,
  };
  let fd = request_fd(&request)?;
  let listener = StdTcpListener::from(fd);
  listener
    .set_nonblocking(true)
    .with_context(|| format!("failed to set {purpose} broker TCP listener nonblocking"))?;
  TcpListener::from_std(listener)
    .with_context(|| format!("failed to register {purpose} broker TCP listener"))
    .map(Some)
}

pub(crate) fn bind_udp_socket(
  bind: SocketAddr,
  options: SwitcherUdpOptions,
  purpose: &str,
  worker_index: usize,
) -> anyhow::Result<Option<StdUdpSocket>> {
  if !should_request_switcher(bind) {
    return Ok(None);
  }
  let request = BindRequest {
    transport: SwitcherTransport::Udp,
    bind,
    purpose: purpose.to_string(),
    workers: options.workers,
    worker_index,
    reuse_port: options.reuse_port,
    backlog: None,
    udp: Some(UdpRequestOptions {
      reuse_address: options.reuse_address,
      reuse_port: options.reuse_port,
      receive_buffer_bytes: options.receive_buffer_bytes,
      send_buffer_bytes: options.send_buffer_bytes,
    }),
  };
  let fd = request_fd(&request)?;
  let socket = StdUdpSocket::from(fd);
  socket
    .set_nonblocking(true)
    .with_context(|| format!("failed to set {purpose} broker UDP socket nonblocking"))?;
  Ok(Some(socket))
}

fn should_request_switcher(bind: SocketAddr) -> bool {
  SWITCHER_CLIENT_ENABLED.load(Ordering::Relaxed)
    && is_privileged_port(bind)
    && std::env::var_os(SOCKET_ENV).is_some()
}

fn is_privileged_port(bind: SocketAddr) -> bool {
  (1..=PRIVILEGED_PORT_MAX).contains(&bind.port())
}

fn request_fd(request: &BindRequest) -> anyhow::Result<OwnedFd> {
  let path = std::env::var_os(SOCKET_ENV)
    .map(PathBuf::from)
    .ok_or_else(|| anyhow::anyhow!("{SOCKET_ENV} is required for privileged bind request"))?;
  let mut stream = UnixStream::connect(&path)
    .with_context(|| format!("failed to connect to netport switcher {}", path.display()))?;
  let timeout = Duration::from_millis(SWITCHER_IO_TIMEOUT_MS.load(Ordering::Relaxed));
  stream
    .set_read_timeout(Some(timeout))
    .context("failed to set netport switcher client read timeout")?;
  stream
    .set_write_timeout(Some(timeout))
    .context("failed to set netport switcher client write timeout")?;
  write_frame(&mut stream, request)?;
  let response: BindResponse = read_frame(&mut stream)?;
  match response {
    BindResponse::Ok => recv_fd(&stream).context("failed to receive netport switcher socket FD"),
    BindResponse::Error { message } => bail!("netport switcher denied bind: {message}"),
  }
}

#[derive(Debug)]
pub struct NetportBroker {
  allowlist: HashSet<AllowedBind>,
  socket_path: PathBuf,
  io_timeout: Duration,
  allowed_uid: u32,
  allowed_gid: u32,
}

impl NetportBroker {
  pub fn from_config(config: &Config) -> anyhow::Result<Self> {
    let switcher = &config.runtime.netport_switcher;
    if !switcher.enabled {
      bail!("runtime.netport_switcher.enabled must be true for oxibelt-netport-switcher");
    }
    Ok(Self {
      allowlist: allowlist_from_config(config),
      socket_path: control_socket_path(switcher),
      io_timeout: Duration::from_millis(switcher.io_timeout_ms),
      allowed_uid: switcher.main_uid,
      allowed_gid: switcher.main_gid,
    })
  }

  pub fn socket_path(&self) -> &Path {
    &self.socket_path
  }

  pub fn bind_control_listener(&self) -> anyhow::Result<UnixListener> {
    let Some(parent) = self.socket_path.parent() else {
      bail!("netport switcher socket path must have a parent directory");
    };
    let parent_exists = parent.exists();
    std::fs::create_dir_all(parent)
      .with_context(|| format!("failed to create {}", parent.display()))?;
    if !parent_exists {
      std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o711))
        .with_context(|| format!("failed to chmod {}", parent.display()))?;
    }

    match std::fs::symlink_metadata(&self.socket_path) {
      Ok(metadata) if metadata.file_type().is_socket() => {
        std::fs::remove_file(&self.socket_path)
          .with_context(|| format!("failed to remove stale {}", self.socket_path.display()))?;
      }
      Ok(_) => bail!(
        "{} exists and is not a Unix socket",
        self.socket_path.display()
      ),
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
      Err(error) => {
        return Err(error)
          .with_context(|| format!("failed to inspect {}", self.socket_path.display()));
      }
    }

    let listener = UnixListener::bind(&self.socket_path)
      .with_context(|| format!("failed to bind {}", self.socket_path.display()))?;
    std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o666))
      .with_context(|| format!("failed to chmod {}", self.socket_path.display()))?;
    listener
      .set_nonblocking(true)
      .context("failed to set netport switcher listener nonblocking")?;
    Ok(listener)
  }

  pub fn serve_until_stopped(
    self: Arc<Self>,
    listener: UnixListener,
    stopped: Arc<AtomicBool>,
  ) -> anyhow::Result<()> {
    while !stopped.load(Ordering::Relaxed) {
      match listener.accept() {
        Ok((stream, _)) => {
          let broker = self.clone();
          std::thread::spawn(move || {
            if let Err(error) = broker.handle_client(stream) {
              warn!(error = %error, "netport switcher request failed");
            }
          });
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
          std::thread::sleep(Duration::from_millis(25));
        }
        Err(error) => return Err(error).context("failed to accept netport switcher client"),
      }
    }
    Ok(())
  }

  fn handle_client(&self, mut stream: UnixStream) -> anyhow::Result<()> {
    stream
      .set_read_timeout(Some(self.io_timeout))
      .context("failed to set netport switcher read timeout")?;
    stream
      .set_write_timeout(Some(self.io_timeout))
      .context("failed to set netport switcher write timeout")?;
    if !self.peer_is_allowed(&stream)? {
      write_frame(
        &mut stream,
        &BindResponse::Error {
          message: "peer credentials are not allowed".to_string(),
        },
      )?;
      return Ok(());
    }
    let request: BindRequest = read_frame(&mut stream)?;
    let response = match self.bind_allowed_socket(&request) {
      Ok(fd) => {
        write_frame(&mut stream, &BindResponse::Ok)?;
        send_fd(&stream, fd.as_fd())?;
        return Ok(());
      }
      Err(error) => BindResponse::Error {
        message: error.to_string(),
      },
    };
    write_frame(&mut stream, &response)?;
    Ok(())
  }

  fn peer_is_allowed(&self, stream: &UnixStream) -> anyhow::Result<bool> {
    let credentials = getsockopt(stream, PeerCredentials)
      .context("failed to read netport switcher peer credentials")?;
    Ok(credentials.uid() == self.allowed_uid || credentials.gid() == self.allowed_gid)
  }

  fn bind_allowed_socket(&self, request: &BindRequest) -> anyhow::Result<OwnedFd> {
    if !is_privileged_port(request.bind) {
      bail!("request is not for a privileged port: {}", request.bind);
    }
    if request.workers == 0 || request.worker_index >= request.workers {
      bail!(
        "invalid worker index {} of {}",
        request.worker_index,
        request.workers
      );
    }
    let allowed = AllowedBind::from_request(request);
    if !self.allowlist.contains(&allowed) {
      bail!(
        "bind not in startup allowlist: {:?} {} purpose={}",
        request.transport,
        request.bind,
        request.purpose
      );
    }
    match request.transport {
      SwitcherTransport::Tcp => {
        let listener = bind_tcp_socket(request)?;
        Ok(OwnedFd::from(listener))
      }
      SwitcherTransport::Udp => {
        let socket = bind_udp_socket_for_request(request)?;
        Ok(OwnedFd::from(socket))
      }
    }
  }
}

fn allowlist_from_config(config: &Config) -> HashSet<AllowedBind> {
  let mut allowlist = HashSet::new();
  let tcp = &config.runtime.accept;
  let tcp_options = SwitcherTcpOptions {
    workers: tcp.workers,
    reuse_port: tcp.reuse_port,
    backlog: tcp.backlog,
  };

  if config.needs_https_listener() {
    for bind in &config.listeners.https_binds {
      insert_tcp(&mut allowlist, *bind, tcp_options, "downstream HTTPS");
    }
  }
  if config.listeners.http_mode != crate::config::HttpListenerMode::Off {
    for bind in &config.listeners.http_binds {
      insert_tcp(&mut allowlist, *bind, tcp_options, "downstream plain HTTP");
    }
  }
  if config.listeners.http3 {
    for bind in &config.listeners.https_binds {
      insert_udp(
        &mut allowlist,
        *bind,
        SwitcherUdpOptions::quic(&config.quic.socket),
        "downstream HTTP/3",
      );
    }
  }
  for listener in &config.stream_listeners {
    match listener.network {
      StreamNetwork::Tcp => insert_tcp(&mut allowlist, listener.bind, tcp_options, "stream"),
      StreamNetwork::Udp => insert_udp(
        &mut allowlist,
        listener.bind,
        SwitcherUdpOptions::simple(),
        "stream UDP",
      ),
    }
  }
  for listener in &config.webrtc_turn_listeners {
    for bind in listener.udp_binds() {
      insert_udp(
        &mut allowlist,
        bind,
        SwitcherUdpOptions::simple(),
        "TURN UDP",
      );
    }
    for bind in listener.tcp_binds() {
      insert_tcp(&mut allowlist, bind, tcp_options, "TURN TCP");
    }
    for bind in listener.tls_binds() {
      insert_tcp(&mut allowlist, bind, tcp_options, "TURN TLS");
    }
  }
  allowlist
}

fn insert_tcp(
  allowlist: &mut HashSet<AllowedBind>,
  bind: SocketAddr,
  options: SwitcherTcpOptions,
  purpose: &str,
) {
  if !is_privileged_port(bind) {
    return;
  }
  allowlist.insert(AllowedBind {
    transport: SwitcherTransport::Tcp,
    bind,
    purpose: purpose.to_string(),
    workers: options.workers,
    reuse_port: options.reuse_port,
    backlog: Some(options.backlog),
    udp: None,
  });
}

fn insert_udp(
  allowlist: &mut HashSet<AllowedBind>,
  bind: SocketAddr,
  options: SwitcherUdpOptions,
  purpose: &str,
) {
  if !is_privileged_port(bind) {
    return;
  }
  allowlist.insert(AllowedBind {
    transport: SwitcherTransport::Udp,
    bind,
    purpose: purpose.to_string(),
    workers: options.workers,
    reuse_port: options.reuse_port,
    backlog: None,
    udp: Some(UdpRequestOptions {
      reuse_address: options.reuse_address,
      reuse_port: options.reuse_port,
      receive_buffer_bytes: options.receive_buffer_bytes,
      send_buffer_bytes: options.send_buffer_bytes,
    }),
  });
}

fn bind_tcp_socket(request: &BindRequest) -> anyhow::Result<StdTcpListener> {
  let socket = Socket::new(
    Domain::for_address(request.bind),
    Type::STREAM,
    Some(Protocol::TCP),
  )
  .with_context(|| format!("failed to create broker TCP socket for {}", request.bind))?;
  socket
    .set_reuse_address(true)
    .context("failed to set broker TCP SO_REUSEADDR")?;
  if request.bind.is_ipv6() {
    socket
      .set_only_v6(true)
      .context("failed to set broker TCP IPV6_V6ONLY")?;
  }
  if request.reuse_port {
    socket
      .set_reuse_port(true)
      .context("failed to set broker TCP SO_REUSEPORT")?;
  }
  socket
    .bind(&SockAddr::from(request.bind))
    .with_context(|| format!("failed to bind broker TCP socket to {}", request.bind))?;
  socket
    .listen(request.backlog.unwrap_or(1024) as i32)
    .context("failed to listen on broker TCP socket")?;
  let listener: StdTcpListener = socket.into();
  listener
    .set_nonblocking(true)
    .context("failed to set broker TCP socket nonblocking")?;
  Ok(listener)
}

fn bind_udp_socket_for_request(request: &BindRequest) -> anyhow::Result<StdUdpSocket> {
  let options = request
    .udp
    .as_ref()
    .ok_or_else(|| anyhow::anyhow!("UDP request is missing UDP options"))?;
  let socket = Socket::new(
    Domain::for_address(request.bind),
    Type::DGRAM,
    Some(Protocol::UDP),
  )
  .with_context(|| format!("failed to create broker UDP socket for {}", request.bind))?;
  if options.reuse_address {
    socket
      .set_reuse_address(true)
      .context("failed to set broker UDP SO_REUSEADDR")?;
  }
  if request.bind.is_ipv6() {
    socket
      .set_only_v6(true)
      .context("failed to set broker UDP IPV6_V6ONLY")?;
  }
  if options.receive_buffer_bytes > 0 {
    socket
      .set_recv_buffer_size(options.receive_buffer_bytes)
      .context("failed to set broker UDP receive buffer size")?;
  }
  if options.send_buffer_bytes > 0 {
    socket
      .set_send_buffer_size(options.send_buffer_bytes)
      .context("failed to set broker UDP send buffer size")?;
  }
  if options.reuse_port {
    socket
      .set_reuse_port(true)
      .context("failed to set broker UDP SO_REUSEPORT")?;
  }
  socket
    .bind(&SockAddr::from(request.bind))
    .with_context(|| format!("failed to bind broker UDP socket to {}", request.bind))?;
  let socket: StdUdpSocket = socket.into();
  socket
    .set_nonblocking(true)
    .context("failed to set broker UDP socket nonblocking")?;
  Ok(socket)
}

fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> anyhow::Result<()> {
  let bytes = serde_json::to_vec(value)?;
  if bytes.len() > MAX_FRAME_LEN {
    bail!("netport switcher frame is too large");
  }
  stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
  stream.write_all(&bytes)?;
  Ok(())
}

fn read_frame<T: for<'de> Deserialize<'de>>(stream: &mut UnixStream) -> anyhow::Result<T> {
  let mut len = [0u8; 4];
  stream.read_exact(&mut len)?;
  let len = u32::from_be_bytes(len) as usize;
  if len > MAX_FRAME_LEN {
    bail!("netport switcher frame is too large");
  }
  let mut bytes = vec![0u8; len];
  stream.read_exact(&mut bytes)?;
  Ok(serde_json::from_slice(&bytes)?)
}

fn send_fd(stream: &UnixStream, fd: std::os::fd::BorrowedFd<'_>) -> anyhow::Result<()> {
  let fds = [fd];
  let mut control_bytes = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
  let mut control = SendAncillaryBuffer::new(&mut control_bytes);
  if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
    bail!("failed to encode netport switcher SCM_RIGHTS response");
  }
  let payload = *b"F";
  let iov = [IoSlice::new(&payload)];
  let written = sendmsg(stream, &iov, &mut control, SendFlags::empty())?;
  if written != payload.len() {
    bail!("short netport switcher SCM_RIGHTS response");
  }
  Ok(())
}

fn recv_fd(stream: &UnixStream) -> anyhow::Result<OwnedFd> {
  let mut payload = [0u8; 1];
  let mut iov = [IoSliceMut::new(&mut payload)];
  let mut control_bytes = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
  let mut control = RecvAncillaryBuffer::new(&mut control_bytes);
  // Ask the kernel to set FD_CLOEXEC while it installs SCM_RIGHTS descriptors.
  // Setting it after receipt leaves a window where a concurrent exec can inherit
  // a privileged data-plane socket.
  let message = recvmsg(stream, &mut iov, &mut control, RecvFlags::CMSG_CLOEXEC)?;
  if message.bytes == 0 {
    bail!("netport switcher closed before sending socket FD");
  }
  for item in control.drain() {
    if let RecvAncillaryMessage::ScmRights(mut fds) = item
      && let Some(fd) = fds.next()
    {
      debug!("received netport switcher socket FD");
      return Ok(fd);
    }
  }
  bail!("netport switcher response did not include a socket FD")
}

#[cfg(test)]
mod tests;

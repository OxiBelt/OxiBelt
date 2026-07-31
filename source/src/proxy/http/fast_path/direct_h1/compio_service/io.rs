//! Owned Compio socket operations with cancellation and deadline control.
//!
//! # Receive buffer invariants
//!
//! - `BytesMut` initializes the complete bounded receive range before ownership
//!   crosses into a Compio operation, so neither completion path needs to
//!   expose uninitialized storage.
//! - The receive count is checked against that range before the initialized
//!   buffer is truncated to the exact appended length.
//! - Cancellation and timeout await terminal driver ownership before this
//!   module truncates or drops a submitted buffer.

use std::cell::Cell;
use std::future::Future;
use std::io;
use std::net::{Shutdown, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use compio::BufResult;
use compio::buf::{IntoInner, IoBuf, IoBufMut};
use compio::runtime::{CancelToken as DriverCancelToken, FutureExt as _, Runtime};
use compio_driver::op::{Connect, Recv, RecvFlags, Send, SendFlags};
use compio_driver::{Extra, OpCode, PollFirst, SharedFd};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use super::super::compio_transport::cancellation::CancellationToken;

pub(super) async fn connect(
  addresses: &Arc<[SocketAddr]>,
  timeout: Duration,
  cancellation: &CancellationToken,
) -> io::Result<(SharedFd<Socket>, SocketAddr)> {
  let end = deadline(timeout);
  let mut last_error = None;
  for address in addresses.iter().copied() {
    if cancellation.is_cancelled() {
      return Err(cancelled());
    }
    let socket = Socket::new(
      Domain::for_address(address),
      Type::STREAM,
      Some(Protocol::TCP),
    )?;
    socket.set_nonblocking(true)?;
    socket.set_tcp_nodelay(true)?;
    let fd = SharedFd::new(socket);
    Runtime::current().attach(fd.as_raw_fd())?;
    let remaining = remaining(end)?;
    let result = submit_controlled(
      Connect::new(fd.clone(), SockAddr::from(address)),
      &fd,
      remaining,
      cancellation,
    )
    .await;
    match result {
      Ok((BufResult(Ok(_), _), _)) => return Ok((fd, address)),
      Ok((BufResult(Err(error), _), _)) => {
        let _ = fd.shutdown(Shutdown::Both);
        last_error = Some(error);
      }
      Err(error) => {
        let _ = fd.shutdown(Shutdown::Both);
        if matches!(
          error.kind(),
          io::ErrorKind::Interrupted | io::ErrorKind::TimedOut
        ) {
          return Err(error);
        }
        last_error = Some(error);
      }
    }
  }
  Err(last_error.unwrap_or_else(|| {
    io::Error::new(
      io::ErrorKind::AddrNotAvailable,
      "direct-H1 upstream resolved no socket addresses",
    )
  }))
}

pub(super) async fn send_all(
  fd: &SharedFd<Socket>,
  buffer: Vec<u8>,
  timeout: Duration,
  cancellation: &CancellationToken,
) -> Result<(Vec<u8>, usize), SendAllError> {
  let end = deadline(timeout);
  let mut buffer = buffer.slice(..);
  let mut bytes_written = 0usize;
  while !buffer.is_empty() {
    if let Err(source) = remaining(end) {
      return Err(SendAllError {
        source,
        bytes_written,
      });
    }
    if cancellation.is_cancelled() {
      return Err(SendAllError {
        source: cancelled(),
        bytes_written,
      });
    }
    let bytes = &buffer.as_inner()[buffer.begin()..];
    match rustix::net::send(fd, bytes, SendFlags::NOSIGNAL) {
      Ok(count) => {
        if count == 0 {
          return Err(SendAllError {
            source: io::Error::new(
              io::ErrorKind::WriteZero,
              "Compio direct-H1 upstream send wrote zero bytes",
            ),
            bytes_written,
          });
        }
        let next = buffer.begin().saturating_add(count);
        if next > buffer.as_inner().len() {
          return Err(SendAllError {
            source: io::Error::new(
              io::ErrorKind::InvalidData,
              "Compio direct-H1 upstream send reported an invalid byte count",
            ),
            bytes_written,
          });
        }
        bytes_written = bytes_written.saturating_add(count);
        buffer.set_begin(next);
        continue;
      }
      Err(rustix::io::Errno::INTR) => continue,
      Err(rustix::io::Errno::WOULDBLOCK) => {}
      Err(source) => {
        return Err(SendAllError {
          source: io::Error::from(source),
          bytes_written,
        });
      }
    }
    let driver_timeout = match remaining(end) {
      Ok(remaining) => remaining,
      Err(source) => {
        return Err(SendAllError {
          source,
          bytes_written,
        });
      }
    };
    let (result, _) = submit_controlled(
      Send::new(fd.clone(), buffer, SendFlags::NOSIGNAL),
      fd,
      driver_timeout,
      cancellation,
    )
    .await
    .map_err(|source| SendAllError {
      source,
      bytes_written,
    })?;
    let (result, operation) = result.into_parts();
    buffer = operation.into_inner();
    let count = result.map_err(|source| SendAllError {
      source,
      bytes_written,
    })?;
    if count == 0 {
      return Err(SendAllError {
        source: io::Error::new(
          io::ErrorKind::WriteZero,
          "Compio direct-H1 upstream send wrote zero bytes",
        ),
        bytes_written,
      });
    }
    let next = buffer.begin().saturating_add(count);
    if next > buffer.as_inner().len() {
      return Err(SendAllError {
        source: io::Error::new(
          io::ErrorKind::InvalidData,
          "Compio direct-H1 upstream send reported an invalid byte count",
        ),
        bytes_written,
      });
    }
    bytes_written = bytes_written.saturating_add(count);
    buffer.set_begin(next);
  }
  Ok((buffer.into_inner(), bytes_written))
}

pub(super) struct SendAllError {
  pub(super) source: io::Error,
  pub(super) bytes_written: usize,
}

pub(super) async fn recv_once(
  fd: &SharedFd<Socket>,
  mut buffer: BytesMut,
  capacity: usize,
  socket_nonempty: Option<bool>,
  timeout: Duration,
  cancellation: &CancellationToken,
) -> io::Result<(BytesMut, usize, Option<bool>)> {
  let end = deadline(timeout);
  let capacity = capacity.max(1);
  let begin = buffer.len();
  let end_offset = begin.checked_add(capacity).ok_or_else(|| {
    io::Error::new(
      io::ErrorKind::InvalidInput,
      "Compio direct-H1 upstream receive buffer length overflow",
    )
  })?;
  buffer.resize(end_offset, 0);
  let mut buffer = IoBuf::slice(buffer, begin..end_offset);
  if socket_nonempty != Some(false) {
    loop {
      remaining(end)?;
      if cancellation.is_cancelled() {
        return Err(cancelled());
      }
      match rustix::net::recv(fd, buffer.as_uninit(), RecvFlags::empty()) {
        Ok((_, count)) => {
          if count > capacity {
            return Err(io::Error::new(
              io::ErrorKind::InvalidData,
              "Compio direct-H1 upstream receive reported an invalid byte count",
            ));
          }
          let mut buffer = buffer.into_inner();
          buffer.truncate(begin + count);
          return Ok((buffer, count, None));
        }
        Err(rustix::io::Errno::INTR) => continue,
        Err(rustix::io::Errno::WOULDBLOCK) => break,
        Err(source) => return Err(io::Error::from(source)),
      }
    }
  }
  let mut operation = Recv::new(fd.clone(), buffer, RecvFlags::empty());
  if socket_nonempty == Some(false) {
    operation.poll_first();
  }
  let (result, extra) = submit_controlled(operation, fd, remaining(end)?, cancellation).await?;
  let (result, operation) = result.into_parts();
  let buffer = operation.into_inner();
  let count = result?;
  if count > capacity {
    return Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "Compio direct-H1 upstream receive reported an invalid byte count",
    ));
  }
  let mut buffer = buffer.into_inner();
  buffer.truncate(begin + count);
  Ok((buffer, count, extra.sock_nonempty().ok()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReuseReadiness {
  Clean,
  Residual,
  Eof,
}

/// Prove that no response bytes are already waiting before an HTTP/1.1
/// connection is returned to the idle pool.
///
/// io_uring reports exact post-receive socket state through `Extra`. Polling
/// and the optimistic syscall path cannot provide that bit, so they use a
/// nonblocking one-byte peek. Any present byte, EOF, or probe error prevents
/// reuse; a later unsolicited peer write remains outside the completed
/// request/response transaction just as it does for the established pool.
pub(super) fn reuse_readiness(
  fd: &SharedFd<Socket>,
  socket_nonempty: Option<bool>,
) -> io::Result<ReuseReadiness> {
  if socket_nonempty == Some(true) {
    return Ok(ReuseReadiness::Residual);
  }
  // `IORING_CQE_F_SOCK_NONEMPTY` exists only on newer kernels, and Compio
  // cannot distinguish an empty socket from a kernel that never reports the
  // flag. Therefore `false` is only a hint; prove cleanliness with the same
  // nonblocking peek used by polling and the optimistic syscall path.
  let mut byte = [0u8; 1];
  loop {
    match rustix::net::recv(fd, byte.as_mut_slice(), RecvFlags::PEEK) {
      Ok((_, 0)) => return Ok(ReuseReadiness::Eof),
      Ok((_, _)) => return Ok(ReuseReadiness::Residual),
      Err(rustix::io::Errno::INTR) => continue,
      Err(rustix::io::Errno::WOULDBLOCK) => return Ok(ReuseReadiness::Clean),
      Err(source) => return Err(io::Error::from(source)),
    }
  }
}

async fn submit_controlled<O>(
  operation: O,
  fd: &SharedFd<Socket>,
  timeout: Duration,
  cancellation: &CancellationToken,
) -> io::Result<(BufResult<usize, O>, Extra)>
where
  O: OpCode + 'static,
{
  if cancellation.is_cancelled() {
    return Err(cancelled());
  }
  submit_controlled_inner(operation, fd, timeout, cancellation.cancelled()).await
}

async fn submit_controlled_inner<O, C>(
  operation: O,
  fd: &SharedFd<Socket>,
  timeout: Duration,
  cancellation: C,
) -> io::Result<(BufResult<usize, O>, Extra)>
where
  O: OpCode + 'static,
  C: Future<Output = ()>,
{
  let sleep = compio::time::sleep(timeout);
  let driver_cancellation = DriverCancelToken::new();
  let submission_started = Cell::new(false);
  let started = &submission_started;
  let submission_cancellation = driver_cancellation.clone();
  let submission = async move {
    started.set(true);
    Runtime::current()
      .submit(operation)
      .with_extra()
      .with_cancel(submission_cancellation)
      .await
  };
  tokio::pin!(cancellation);
  tokio::pin!(sleep);
  tokio::pin!(submission);
  let control_error = tokio::select! {
    biased;
    _ = &mut cancellation => cancelled(),
    _ = &mut sleep => timed_out(),
    result = &mut submission => return Ok(result),
  };

  if !submission_started.get() {
    // The biased control branch can win before the submission future is ever
    // polled. In that case no physical operation exists to fence, and polling
    // it after cancellation would incorrectly dispatch new I/O.
    return Err(control_error);
  }

  // Compio cancellation is explicitly fail-slow: the driver may continue an
  // operation after cancellation is requested. Shutting down the socket makes
  // pending socket I/O terminal, while retaining and awaiting `submission`
  // keeps its FD and buffer ownership charged until the driver returns them.
  let _ = fd.shutdown(Shutdown::Both);
  driver_cancellation.cancel();
  drop(submission.await);
  Err(control_error)
}

fn deadline(timeout: Duration) -> Instant {
  Instant::now()
    .checked_add(timeout)
    .unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400 * 365))
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
  let now = Instant::now();
  if now >= deadline {
    return Err(io::Error::new(
      io::ErrorKind::TimedOut,
      "Compio direct-H1 operation timed out",
    ));
  }
  Ok(deadline.duration_since(now))
}

fn cancelled() -> io::Error {
  io::Error::new(
    io::ErrorKind::Interrupted,
    "Compio direct-H1 operation cancelled",
  )
}

fn timed_out() -> io::Error {
  io::Error::new(
    io::ErrorKind::TimedOut,
    "Compio direct-H1 operation timed out",
  )
}

#[cfg(test)]
mod tests {
  use std::io::{Read, Write};
  use std::net::{TcpListener, TcpStream};

  use compio_driver::ProactorBuilder;

  use super::*;

  fn compio_runtime() -> compio::runtime::Runtime {
    let mut proactor = ProactorBuilder::new();
    proactor.thread_pool_limit(0);
    let mut runtime_builder = compio::runtime::RuntimeBuilder::new();
    runtime_builder.with_proactor(proactor);
    runtime_builder.build().unwrap()
  }

  fn connected_sockets() -> (SharedFd<Socket>, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (peer, _) = listener.accept().unwrap();
    client.set_nonblocking(true).unwrap();
    (SharedFd::new(Socket::from(client)), peer)
  }

  #[test]
  fn timeout_waits_for_driver_to_release_socket_ownership() {
    let (fd, _peer) = connected_sockets();
    let runtime = compio_runtime();
    let result = runtime.block_on(async {
      Runtime::current().attach(fd.as_raw_fd()).unwrap();
      submit_controlled_inner(
        Recv::new(fd.clone(), vec![0; 64], RecvFlags::empty()),
        &fd,
        Duration::from_millis(20),
        std::future::pending(),
      )
      .await
    });

    let error = match result {
      Ok(_) => panic!("pending receive unexpectedly completed before its timeout"),
      Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(
      fd.try_unwrap().is_ok(),
      "terminal completion must release the operation's SharedFd clone before timeout returns"
    );
  }

  #[test]
  fn control_exit_before_submission_does_not_dispatch_io() {
    let (fd, mut peer) = connected_sockets();
    peer
      .set_read_timeout(Some(Duration::from_millis(20)))
      .unwrap();
    let runtime = compio_runtime();
    let result = runtime.block_on(async {
      Runtime::current().attach(fd.as_raw_fd()).unwrap();
      submit_controlled_inner(
        Send::new(fd.clone(), b"must-not-send".to_vec(), SendFlags::empty()),
        &fd,
        Duration::from_secs(1),
        std::future::ready(()),
      )
      .await
    });

    let error = match result {
      Ok(_) => panic!("pre-cancelled operation unexpectedly completed"),
      Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    let _socket = fd
      .try_unwrap()
      .expect("unsubmitted operation must release its SharedFd clone");
    let mut received = [0; 16];
    match peer.read(&mut received) {
      Ok(0) | Err(_) => {}
      Ok(count) => panic!(
        "control exit before submission wrote {count} unexpected byte(s): {:?}",
        &received[..count]
      ),
    }
  }

  #[test]
  fn reuse_probe_rejects_socket_resident_bytes_without_consuming_them() {
    let (fd, mut peer) = connected_sockets();
    assert_eq!(reuse_readiness(&fd, None).unwrap(), ReuseReadiness::Clean);

    peer.write_all(b"prefabricated-next-response").unwrap();
    assert_eq!(
      reuse_readiness(&fd, None).unwrap(),
      ReuseReadiness::Residual
    );
    assert_eq!(
      reuse_readiness(&fd, Some(false)).unwrap(),
      ReuseReadiness::Residual,
      "a false io_uring hint is not proof on kernels without SOCK_NONEMPTY support"
    );

    let mut received = [0; 27];
    let count = rustix::net::recv(&fd, received.as_mut_slice(), RecvFlags::empty())
      .map(|(_, count)| count)
      .unwrap();
    assert_eq!(&received[..count], b"prefabricated-next-response");
  }

  #[test]
  fn receive_appends_into_owned_bytesmut_without_overwriting_prefix() {
    for socket_nonempty in [None, Some(false)] {
      let (fd, mut peer) = connected_sockets();
      peer.write_all(b"-response").unwrap();
      let (cancellation, _guard) = CancellationToken::pair();
      let runtime = compio_runtime();
      let (buffer, count, _) = runtime
        .block_on(async {
          Runtime::current().attach(fd.as_raw_fd()).unwrap();
          recv_once(
            &fd,
            BytesMut::from(&b"prefix"[..]),
            32,
            socket_nonempty,
            Duration::from_secs(1),
            &cancellation,
          )
          .await
        })
        .unwrap();

      assert_eq!(count, b"-response".len());
      assert_eq!(buffer.len(), b"prefix-response".len());
      assert_eq!(&buffer[..], b"prefix-response");
    }
  }

  #[test]
  fn receive_eof_preserves_prefix_without_initialized_tail() {
    for socket_nonempty in [None, Some(false)] {
      let (fd, peer) = connected_sockets();
      drop(peer);
      let (cancellation, _guard) = CancellationToken::pair();
      let runtime = compio_runtime();
      let (buffer, count, _) = runtime
        .block_on(async {
          Runtime::current().attach(fd.as_raw_fd()).unwrap();
          recv_once(
            &fd,
            BytesMut::from(&b"prefix"[..]),
            32,
            socket_nonempty,
            Duration::from_secs(1),
            &cancellation,
          )
          .await
        })
        .unwrap();

      assert_eq!(count, 0);
      assert_eq!(&buffer[..], b"prefix");
    }
  }
}

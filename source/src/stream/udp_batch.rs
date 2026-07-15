//! Linux UDP batch syscalls for stream listeners.

use std::io;
#[cfg(target_os = "linux")]
use std::io::{IoSlice, IoSliceMut};
use std::net::SocketAddr;

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

#[cfg(target_os = "linux")]
use nix::sys::socket::{
  ControlMessage, MsgFlags, MultiHeaders, SockaddrStorage, recvmmsg, sendmmsg,
};

use tokio::io::Interest;
use tokio::net::UdpSocket;

#[derive(Debug)]
pub(super) struct UdpBatchDatagram {
  pub(super) peer: SocketAddr,
  pub(super) bytes: Vec<u8>,
}

pub(super) async fn recv_from_batch(
  socket: &UdpSocket,
  batch_size: usize,
  max_datagram_bytes: usize,
) -> io::Result<Vec<UdpBatchDatagram>> {
  recv_from_batch_impl(socket, batch_size, max_datagram_bytes).await
}

pub(super) async fn recv_connected_batch(
  socket: &UdpSocket,
  batch_size: usize,
  max_datagram_bytes: usize,
) -> io::Result<Vec<Vec<u8>>> {
  recv_connected_batch_impl(socket, batch_size, max_datagram_bytes).await
}

pub(super) async fn sendmmsg_to(
  socket: &UdpSocket,
  peer: SocketAddr,
  datagrams: &[Vec<u8>],
) -> io::Result<usize> {
  sendmmsg_to_impl(socket, peer, datagrams).await
}

#[cfg(target_os = "linux")]
async fn recv_from_batch_impl(
  socket: &UdpSocket,
  batch_size: usize,
  max_datagram_bytes: usize,
) -> io::Result<Vec<UdpBatchDatagram>> {
  loop {
    socket.readable().await?;
    match socket.try_io(Interest::READABLE, || {
      recvmmsg_from_once(socket.as_raw_fd(), batch_size, max_datagram_bytes)
    }) {
      Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
      result => return result,
    }
  }
}

#[cfg(not(target_os = "linux"))]
async fn recv_from_batch_impl(
  _socket: &UdpSocket,
  _batch_size: usize,
  _max_datagram_bytes: usize,
) -> io::Result<Vec<UdpBatchDatagram>> {
  Err(io::Error::new(
    io::ErrorKind::Unsupported,
    "recvmmsg is Linux-only",
  ))
}

#[cfg(target_os = "linux")]
async fn recv_connected_batch_impl(
  socket: &UdpSocket,
  batch_size: usize,
  max_datagram_bytes: usize,
) -> io::Result<Vec<Vec<u8>>> {
  loop {
    socket.readable().await?;
    match socket.try_io(Interest::READABLE, || {
      recvmmsg_connected_once(socket.as_raw_fd(), batch_size, max_datagram_bytes)
    }) {
      Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
      result => return result,
    }
  }
}

#[cfg(not(target_os = "linux"))]
async fn recv_connected_batch_impl(
  _socket: &UdpSocket,
  _batch_size: usize,
  _max_datagram_bytes: usize,
) -> io::Result<Vec<Vec<u8>>> {
  Err(io::Error::new(
    io::ErrorKind::Unsupported,
    "recvmmsg is Linux-only",
  ))
}

#[cfg(target_os = "linux")]
async fn sendmmsg_to_impl(
  socket: &UdpSocket,
  peer: SocketAddr,
  datagrams: &[Vec<u8>],
) -> io::Result<usize> {
  if datagrams.is_empty() {
    return Ok(0);
  }
  loop {
    socket.writable().await?;
    match socket.try_io(Interest::WRITABLE, || {
      sendmmsg_to_once(socket.as_raw_fd(), peer, datagrams)
    }) {
      Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
      result => return result,
    }
  }
}

#[cfg(not(target_os = "linux"))]
async fn sendmmsg_to_impl(
  _socket: &UdpSocket,
  _peer: SocketAddr,
  _datagrams: &[Vec<u8>],
) -> io::Result<usize> {
  Err(io::Error::new(
    io::ErrorKind::Unsupported,
    "sendmmsg is Linux-only",
  ))
}

#[cfg(target_os = "linux")]
fn recvmmsg_from_once(
  fd: std::os::fd::RawFd,
  batch_size: usize,
  max_datagram_bytes: usize,
) -> io::Result<Vec<UdpBatchDatagram>> {
  let batch_size = batch_size.max(1);
  let mut buffers = vec![vec![0_u8; max_datagram_bytes]; batch_size];
  let mut iovecs = buffers
    .iter_mut()
    .map(|buffer| [IoSliceMut::new(buffer)])
    .collect::<Vec<_>>();
  let mut headers = MultiHeaders::<SockaddrStorage>::preallocate(batch_size, None);
  let received = recvmmsg(
    fd,
    &mut headers,
    iovecs.iter_mut(),
    MsgFlags::MSG_DONTWAIT,
    None,
  )
  .map_err(io::Error::from)?
  .map(|message| (message.bytes, message.address))
  .collect::<Vec<_>>();
  let mut datagrams = Vec::with_capacity(received.len());
  for (index, (len, peer)) in received.into_iter().enumerate() {
    let peer = peer
      .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing UDP peer address"))
      .and_then(sockaddr_to_addr)?;
    datagrams.push(UdpBatchDatagram {
      peer,
      bytes: buffers[index][..len.min(max_datagram_bytes)].to_vec(),
    });
  }
  Ok(datagrams)
}

#[cfg(target_os = "linux")]
fn recvmmsg_connected_once(
  fd: std::os::fd::RawFd,
  batch_size: usize,
  max_datagram_bytes: usize,
) -> io::Result<Vec<Vec<u8>>> {
  let batch_size = batch_size.max(1);
  let mut buffers = vec![vec![0_u8; max_datagram_bytes]; batch_size];
  let mut iovecs = buffers
    .iter_mut()
    .map(|buffer| [IoSliceMut::new(buffer)])
    .collect::<Vec<_>>();
  let mut headers = MultiHeaders::<SockaddrStorage>::preallocate(batch_size, None);
  let received = recvmmsg(
    fd,
    &mut headers,
    iovecs.iter_mut(),
    MsgFlags::MSG_DONTWAIT,
    None,
  )
  .map_err(io::Error::from)?
  .map(|message| message.bytes)
  .collect::<Vec<_>>();
  Ok(
    received
      .into_iter()
      .enumerate()
      .map(|(index, len)| buffers[index][..len.min(max_datagram_bytes)].to_vec())
      .collect(),
  )
}

#[cfg(target_os = "linux")]
fn sendmmsg_to_once(
  fd: std::os::fd::RawFd,
  peer: SocketAddr,
  datagrams: &[Vec<u8>],
) -> io::Result<usize> {
  let peer = SockaddrStorage::from(peer);
  let iovecs = datagrams
    .iter()
    .map(|datagram| [IoSlice::new(datagram)])
    .collect::<Vec<_>>();
  let addresses = vec![Some(peer); datagrams.len()];
  let control_messages: [ControlMessage<'_>; 0] = [];
  let mut headers = MultiHeaders::<SockaddrStorage>::preallocate(datagrams.len(), None);
  sendmmsg(
    fd,
    &mut headers,
    iovecs.iter(),
    &addresses,
    control_messages,
    MsgFlags::MSG_DONTWAIT,
  )
  .map(|results| results.count())
  .map_err(io::Error::from)
}

#[cfg(target_os = "linux")]
fn sockaddr_to_addr(storage: SockaddrStorage) -> io::Result<SocketAddr> {
  if let Some(address) = storage.as_sockaddr_in() {
    return Ok(SocketAddr::from(*address));
  }
  if let Some(address) = storage.as_sockaddr_in6() {
    return Ok(SocketAddr::from(*address));
  }
  Err(io::Error::new(
    io::ErrorKind::InvalidData,
    "unsupported UDP peer address family",
  ))
}

#[cfg(all(target_os = "linux", feature = "fuzzing"))]
pub(crate) fn fuzz_socket_address_boundary(address: SocketAddr, batch_size: usize) {
  let storage = SockaddrStorage::from(address);
  let _ = sockaddr_to_addr(storage);
  let _ = MultiHeaders::<SockaddrStorage>::preallocate(batch_size.min(32), None);
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
  use super::*;

  async fn bind(address: &str) -> UdpSocket {
    UdpSocket::bind(address)
      .await
      .unwrap_or_else(|error| panic!("bind {address}: {error}"))
  }

  #[tokio::test]
  async fn unconnected_ipv4_batch_preserves_payloads_and_peer() {
    let receiver = bind("127.0.0.1:0").await;
    let sender = bind("127.0.0.1:0").await;
    let receiver_addr = receiver.local_addr().expect("receiver address");
    let sender_addr = sender.local_addr().expect("sender address");
    let payloads = vec![b"first".to_vec(), b"second".to_vec()];

    let sent = sendmmsg_to(&sender, receiver_addr, &payloads)
      .await
      .expect("send batch");
    assert_eq!(sent, payloads.len());

    let received = recv_from_batch(&receiver, payloads.len(), 64)
      .await
      .expect("receive batch");
    assert_eq!(received.len(), payloads.len());
    assert!(received.iter().all(|datagram| datagram.peer == sender_addr));
    assert_eq!(
      received
        .into_iter()
        .map(|datagram| datagram.bytes)
        .collect::<Vec<_>>(),
      payloads
    );
  }

  #[tokio::test]
  async fn connected_ipv4_batch_truncates_to_configured_limit() {
    let receiver = bind("127.0.0.1:0").await;
    let sender = bind("127.0.0.1:0").await;
    receiver
      .connect(sender.local_addr().expect("sender address"))
      .await
      .expect("connect receiver");
    sender
      .connect(receiver.local_addr().expect("receiver address"))
      .await
      .expect("connect sender");
    sender.send(b"abcdefgh").await.expect("send datagram");

    let received = recv_connected_batch(&receiver, 1, 4)
      .await
      .expect("receive connected batch");
    assert_eq!(received, vec![b"abcd".to_vec()]);
  }

  #[tokio::test]
  async fn unconnected_ipv6_batch_preserves_address_family() {
    let receiver = bind("[::1]:0").await;
    let sender = bind("[::1]:0").await;
    let receiver_addr = receiver.local_addr().expect("receiver address");
    let sender_addr = sender.local_addr().expect("sender address");

    assert_eq!(
      sendmmsg_to(&sender, receiver_addr, &[b"ipv6".to_vec()])
        .await
        .expect("send IPv6 batch"),
      1
    );
    let received = recv_from_batch(&receiver, 1, 64)
      .await
      .expect("receive IPv6 batch");
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].peer, sender_addr);
    assert_eq!(received[0].bytes, b"ipv6");
  }
}

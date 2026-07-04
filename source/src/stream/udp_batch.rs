//! Linux UDP batch syscalls for stream listeners.

#![allow(unsafe_code)]

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

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
  let mut addrs = vec![zeroed_sockaddr_storage(); batch_size];
  let mut iovecs = Vec::<libc::iovec>::with_capacity(batch_size);
  let mut messages = Vec::<libc::mmsghdr>::with_capacity(batch_size);
  for index in 0..batch_size {
    iovecs.push(libc::iovec {
      iov_base: buffers[index].as_mut_ptr().cast(),
      iov_len: buffers[index].len(),
    });
    let mut message = zeroed_mmsghdr();
    message.msg_hdr.msg_name = (&mut addrs[index] as *mut libc::sockaddr_storage).cast();
    message.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    message.msg_hdr.msg_iov = &mut iovecs[index];
    message.msg_hdr.msg_iovlen = 1;
    messages.push(message);
  }
  let received = unsafe {
    libc::recvmmsg(
      fd,
      messages.as_mut_ptr(),
      batch_size as libc::c_uint,
      libc::MSG_DONTWAIT,
      std::ptr::null_mut(),
    )
  };
  if received < 0 {
    return Err(io::Error::last_os_error());
  }
  let mut datagrams = Vec::with_capacity(received as usize);
  for index in 0..received as usize {
    let len = messages[index].msg_len as usize;
    let peer = sockaddr_to_addr(&addrs[index], messages[index].msg_hdr.msg_namelen)?;
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
  let mut iovecs = Vec::<libc::iovec>::with_capacity(batch_size);
  let mut messages = Vec::<libc::mmsghdr>::with_capacity(batch_size);
  for buffer in &mut buffers {
    iovecs.push(libc::iovec {
      iov_base: buffer.as_mut_ptr().cast(),
      iov_len: buffer.len(),
    });
  }
  for iovec in &mut iovecs {
    let mut message = zeroed_mmsghdr();
    message.msg_hdr.msg_iov = iovec;
    message.msg_hdr.msg_iovlen = 1;
    messages.push(message);
  }
  let received = unsafe {
    libc::recvmmsg(
      fd,
      messages.as_mut_ptr(),
      batch_size as libc::c_uint,
      libc::MSG_DONTWAIT,
      std::ptr::null_mut(),
    )
  };
  if received < 0 {
    return Err(io::Error::last_os_error());
  }
  Ok(
    (0..received as usize)
      .map(|index| {
        buffers[index][..(messages[index].msg_len as usize).min(max_datagram_bytes)].to_vec()
      })
      .collect(),
  )
}

#[cfg(target_os = "linux")]
fn sendmmsg_to_once(
  fd: std::os::fd::RawFd,
  peer: SocketAddr,
  datagrams: &[Vec<u8>],
) -> io::Result<usize> {
  let (mut storage, storage_len) = sockaddr_from_addr(peer);
  let mut iovecs = Vec::<libc::iovec>::with_capacity(datagrams.len());
  let mut messages = Vec::<libc::mmsghdr>::with_capacity(datagrams.len());
  for datagram in datagrams {
    iovecs.push(libc::iovec {
      iov_base: datagram.as_ptr().cast_mut().cast(),
      iov_len: datagram.len(),
    });
  }
  for iovec in &mut iovecs {
    let mut message = zeroed_mmsghdr();
    message.msg_hdr.msg_name = (&mut storage as *mut libc::sockaddr_storage).cast();
    message.msg_hdr.msg_namelen = storage_len;
    message.msg_hdr.msg_iov = iovec;
    message.msg_hdr.msg_iovlen = 1;
    messages.push(message);
  }
  let sent = unsafe {
    libc::sendmmsg(
      fd,
      messages.as_mut_ptr(),
      messages.len() as libc::c_uint,
      libc::MSG_DONTWAIT,
    )
  };
  if sent < 0 {
    Err(io::Error::last_os_error())
  } else {
    Ok(sent as usize)
  }
}

#[cfg(target_os = "linux")]
fn sockaddr_to_addr(
  storage: &libc::sockaddr_storage,
  len: libc::socklen_t,
) -> io::Result<SocketAddr> {
  match storage.ss_family as libc::c_int {
    libc::AF_INET if len as usize >= std::mem::size_of::<libc::sockaddr_in>() => {
      let addr = unsafe { *(storage as *const _ as *const libc::sockaddr_in) };
      let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
      let port = u16::from_be(addr.sin_port);
      Ok(SocketAddr::from((ip, port)))
    }
    libc::AF_INET6 if len as usize >= std::mem::size_of::<libc::sockaddr_in6>() => {
      let addr = unsafe { *(storage as *const _ as *const libc::sockaddr_in6) };
      let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
      let port = u16::from_be(addr.sin6_port);
      Ok(SocketAddr::from((ip, port)))
    }
    _ => Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "unsupported UDP peer address family",
    )),
  }
}

#[cfg(target_os = "linux")]
fn sockaddr_from_addr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
  let mut storage = zeroed_sockaddr_storage();
  match addr {
    SocketAddr::V4(addr) => {
      let sockaddr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: addr.port().to_be(),
        sin_addr: libc::in_addr {
          s_addr: u32::from(*addr.ip()).to_be(),
        },
        sin_zero: [0; 8],
      };
      unsafe {
        std::ptr::write(
          (&mut storage as *mut libc::sockaddr_storage).cast(),
          sockaddr,
        );
      }
      (
        storage,
        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
      )
    }
    SocketAddr::V6(addr) => {
      let sockaddr = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: addr.port().to_be(),
        sin6_flowinfo: addr.flowinfo(),
        sin6_addr: libc::in6_addr {
          s6_addr: addr.ip().octets(),
        },
        sin6_scope_id: addr.scope_id(),
      };
      unsafe {
        std::ptr::write(
          (&mut storage as *mut libc::sockaddr_storage).cast(),
          sockaddr,
        );
      }
      (
        storage,
        std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
      )
    }
  }
}

#[cfg(target_os = "linux")]
fn zeroed_sockaddr_storage() -> libc::sockaddr_storage {
  unsafe { std::mem::zeroed() }
}

#[cfg(target_os = "linux")]
fn zeroed_mmsghdr() -> libc::mmsghdr {
  unsafe { std::mem::zeroed() }
}

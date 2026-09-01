//! Exclusive RFC 6062 TCP relay-port reservation and socket binding.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};

use anyhow::bail;
use socket2::{Domain, Protocol, Socket, Type};

use crate::config::TurnRelayFamilyConfig;

use super::relay::randomized_relay_ports;

static TCP_RELAY_PORT_RESERVATIONS: OnceLock<Mutex<HashSet<SocketAddr>>> = OnceLock::new();

#[derive(Debug)]
pub(super) struct TcpRelayPortReservation {
  bind: SocketAddr,
}

impl TcpRelayPortReservation {
  fn try_acquire(bind: SocketAddr) -> anyhow::Result<Option<Self>> {
    let mut reservations = TCP_RELAY_PORT_RESERVATIONS
      .get_or_init(|| Mutex::new(HashSet::new()))
      .lock()
      .map_err(|_| anyhow::anyhow!("TURN TCP relay port reservation unavailable"))?;
    let overlaps = reservations.iter().any(|reserved| {
      reserved.port() == bind.port()
        && reserved.is_ipv4() == bind.is_ipv4()
        && (reserved.ip() == bind.ip()
          || reserved.ip().is_unspecified()
          || bind.ip().is_unspecified())
    });
    if overlaps {
      return Ok(None);
    }
    reservations.insert(bind);
    Ok(Some(Self { bind }))
  }
}

impl Drop for TcpRelayPortReservation {
  fn drop(&mut self) {
    if let Ok(mut reservations) = TCP_RELAY_PORT_RESERVATIONS
      .get_or_init(|| Mutex::new(HashSet::new()))
      .lock()
    {
      reservations.remove(&self.bind);
    }
  }
}

pub(super) fn bind_tcp_relay_socket(
  config: &TurnRelayFamilyConfig,
) -> anyhow::Result<(std::net::TcpListener, TcpRelayPortReservation)> {
  for port in randomized_relay_ports(config)? {
    let bind = SocketAddr::new(config.relay_bind_ip, port);
    let Some(reservation) = TcpRelayPortReservation::try_acquire(bind)? else {
      continue;
    };
    if let Ok(socket) = bind_tcp_socket(bind) {
      return Ok((socket, reservation));
    }
  }
  bail!(
    "no available TURN relay TCP ports in configured range {}..={}",
    config.relay_port_range.start,
    config.relay_port_range.end
  )
}

fn bind_tcp_socket(bind: SocketAddr) -> anyhow::Result<std::net::TcpListener> {
  let socket = Socket::new(Domain::for_address(bind), Type::STREAM, Some(Protocol::TCP))?;
  socket.set_reuse_address(true)?;
  #[cfg(unix)]
  socket.set_reuse_port(true)?;
  if bind.is_ipv6() {
    socket.set_only_v6(true)?;
  }
  socket.bind(&bind.into())?;
  socket.listen(128)?;
  let socket: std::net::TcpListener = socket.into();
  socket.set_nonblocking(true)?;
  Ok(socket)
}

#[cfg(test)]
mod tests {
  use crate::config::{TurnRelayAddressFamily, TurnRelayPortRange};

  use super::*;

  #[test]
  fn tcp_relay_reservations_are_exclusive_and_release_on_drop() -> anyhow::Result<()> {
    let probe = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = probe.local_addr()?.port();
    drop(probe);
    let config = TurnRelayFamilyConfig {
      family: TurnRelayAddressFamily::Ipv4,
      public_ip: "127.0.0.1".parse()?,
      relay_bind_ip: "127.0.0.1".parse()?,
      relay_port_range: TurnRelayPortRange {
        start: port,
        end: port,
      },
    };
    let (first, reservation) = bind_tcp_relay_socket(&config)?;
    let error = bind_tcp_relay_socket(&config)
      .expect_err("an allocated TCP relay port must not admit a second listener");
    assert!(
      error
        .to_string()
        .contains("no available TURN relay TCP ports")
    );

    drop(first);
    drop(reservation);
    let (_rebound, _rebound_reservation) = bind_tcp_relay_socket(&config)
      .expect("dropping the allocation reservation must release its TCP relay port");
    Ok(())
  }
}

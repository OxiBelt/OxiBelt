//! RFC 8656 UDP relay-port selection and short-lived reservation tokens.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::bail;

use crate::config::{TurnRelayAddressFamily, TurnRelayFamilyConfig};

use super::relay::{bind_relay_socket, bind_udp_socket, randomized_relay_ports};
use super::request::UdpRelayRequest;

const RESERVATION_LIFETIME: Duration = Duration::from_secs(30);
const MAX_PROCESS_UDP_RELAY_RESERVATIONS: usize = 4_096;
const TOKEN_GENERATION_ATTEMPTS: usize = 16;

type ReservationToken = [u8; 8];

static UDP_RELAY_RESERVATIONS: OnceLock<
  Mutex<HashMap<ReservationToken, Option<UdpRelayReservation>>>,
> = OnceLock::new();

struct UdpRelayReservation {
  socket: UdpSocket,
  family: TurnRelayAddressFamily,
  relayed_addr: SocketAddr,
  expires_at: Instant,
}

pub(super) struct PreparedUdpRelay {
  socket: UdpSocket,
  family: TurnRelayAddressFamily,
  relayed_addr: SocketAddr,
  reserved: Option<UdpRelayReservation>,
}

impl PreparedUdpRelay {
  pub(super) fn finalize(self) -> anyhow::Result<FinalizedUdpRelay> {
    let issued = self.reserved.map(issue_reservation).transpose()?;
    Ok(FinalizedUdpRelay {
      socket: self.socket,
      family: self.family,
      relayed_addr: self.relayed_addr,
      issued,
    })
  }
}

pub(super) struct FinalizedUdpRelay {
  pub(super) socket: UdpSocket,
  pub(super) family: TurnRelayAddressFamily,
  pub(super) relayed_addr: SocketAddr,
  issued: Option<IssuedUdpReservation>,
}

impl FinalizedUdpRelay {
  pub(super) fn into_install_ready(self) -> std::io::Result<InstallReadyUdpRelay> {
    let Self {
      socket,
      family,
      relayed_addr,
      issued,
    } = self;
    let socket = tokio::net::UdpSocket::from_std(socket)?;
    Ok(InstallReadyUdpRelay {
      socket,
      family,
      relayed_addr,
      issued,
    })
  }
}

pub(super) struct InstallReadyUdpRelay {
  socket: tokio::net::UdpSocket,
  family: TurnRelayAddressFamily,
  relayed_addr: SocketAddr,
  issued: Option<IssuedUdpReservation>,
}

impl InstallReadyUdpRelay {
  pub(super) fn into_parts(
    self,
  ) -> (
    tokio::net::UdpSocket,
    TurnRelayAddressFamily,
    SocketAddr,
    Option<ReservationToken>,
  ) {
    let Self {
      socket,
      family,
      relayed_addr,
      issued,
    } = self;
    let token = issued.map(IssuedUdpReservation::commit);
    (socket, family, relayed_addr, token)
  }
}

struct IssuedUdpReservation {
  token: ReservationToken,
  committed: bool,
}

impl IssuedUdpReservation {
  fn commit(mut self) -> ReservationToken {
    self.committed = true;
    self.token
  }
}

impl Drop for IssuedUdpReservation {
  fn drop(&mut self) {
    if !self.committed
      && let Ok(mut reservations) = reservations().lock()
    {
      reservations.remove(&self.token);
    }
  }
}

pub(super) struct ClaimedUdpRelay {
  token: ReservationToken,
  reservation: Option<UdpRelayReservation>,
}

impl ClaimedUdpRelay {
  pub(super) fn family(&self) -> TurnRelayAddressFamily {
    self
      .reservation
      .as_ref()
      .expect("claimed TURN UDP reservation must be present")
      .family
  }

  pub(super) fn into_finalized(mut self) -> FinalizedUdpRelay {
    let reservation = self
      .reservation
      .take()
      .expect("claimed TURN UDP reservation must be present");
    if let Ok(mut reservations) = reservations().lock() {
      reservations.remove(&self.token);
    }
    FinalizedUdpRelay {
      socket: reservation.socket,
      family: reservation.family,
      relayed_addr: reservation.relayed_addr,
      issued: None,
    }
  }
}

impl Drop for ClaimedUdpRelay {
  fn drop(&mut self) {
    let Some(reservation) = self.reservation.take() else {
      return;
    };
    if let Ok(mut reservations) = reservations().lock() {
      if reservation.expires_at > Instant::now() {
        if let Some(slot) = reservations.get_mut(&self.token) {
          *slot = Some(reservation);
        }
      } else {
        reservations.remove(&self.token);
      }
    }
  }
}

pub(super) fn prepare_udp_relay(
  config: &TurnRelayFamilyConfig,
  request: UdpRelayRequest,
) -> anyhow::Result<PreparedUdpRelay> {
  match request {
    UdpRelayRequest::Any => {
      let socket = bind_relay_socket(config)?;
      let port = socket.local_addr()?.port();
      Ok(PreparedUdpRelay {
        socket,
        family: config.family,
        relayed_addr: SocketAddr::new(config.public_ip, port),
        reserved: None,
      })
    }
    UdpRelayRequest::Even { reserve_next } => prepare_even_udp_relay(config, reserve_next),
    UdpRelayRequest::Reservation(_) => {
      bail!("TURN UDP reservation tokens must be claimed before relay preparation")
    }
  }
}

pub(super) fn claim_udp_relay(token: ReservationToken) -> anyhow::Result<Option<ClaimedUdpRelay>> {
  let now = Instant::now();
  let mut reservations = reservations()
    .lock()
    .map_err(|_| anyhow::anyhow!("TURN UDP relay reservation state unavailable"))?;
  expire_locked(&mut reservations, now);
  let Some(slot) = reservations.get_mut(&token) else {
    return Ok(None);
  };
  let Some(reservation) = slot.take() else {
    return Ok(None);
  };
  if reservation.expires_at <= now {
    reservations.remove(&token);
    return Ok(None);
  }
  Ok(Some(ClaimedUdpRelay {
    token,
    reservation: Some(reservation),
  }))
}

pub(super) fn expire_udp_relay_reservations() {
  if let Ok(mut reservations) = reservations().lock() {
    expire_locked(&mut reservations, Instant::now());
  }
}

fn prepare_even_udp_relay(
  config: &TurnRelayFamilyConfig,
  reserve_next: bool,
) -> anyhow::Result<PreparedUdpRelay> {
  for port in randomized_relay_ports(config)? {
    if port % 2 != 0 {
      continue;
    }
    if reserve_next && port == config.relay_port_range.end {
      continue;
    }
    let bind = SocketAddr::new(config.relay_bind_ip, port);
    let Ok(socket) = bind_udp_socket(bind) else {
      continue;
    };
    let reserved = if reserve_next {
      let reserved_port = port + 1;
      let reserved_bind = SocketAddr::new(config.relay_bind_ip, reserved_port);
      let Ok(reserved_socket) = bind_udp_socket(reserved_bind) else {
        continue;
      };
      Some(UdpRelayReservation {
        socket: reserved_socket,
        family: config.family,
        relayed_addr: SocketAddr::new(config.public_ip, reserved_port),
        expires_at: Instant::now() + RESERVATION_LIFETIME,
      })
    } else {
      None
    };
    return Ok(PreparedUdpRelay {
      socket,
      family: config.family,
      relayed_addr: SocketAddr::new(config.public_ip, port),
      reserved,
    });
  }
  bail!(
    "no available TURN relay UDP ports with requested properties in configured range {}..={}",
    config.relay_port_range.start,
    config.relay_port_range.end
  )
}

fn issue_reservation(reservation: UdpRelayReservation) -> anyhow::Result<IssuedUdpReservation> {
  let expires_at = reservation.expires_at;
  let mut reservation = Some(reservation);
  let token = {
    let mut reservations = reservations()
      .lock()
      .map_err(|_| anyhow::anyhow!("TURN UDP relay reservation state unavailable"))?;
    expire_locked(&mut reservations, Instant::now());
    if reservations.len() >= MAX_PROCESS_UDP_RELAY_RESERVATIONS {
      bail!("TURN UDP relay reservation capacity exhausted");
    }
    let mut selected = None;
    for _ in 0..TOKEN_GENERATION_ATTEMPTS {
      let mut candidate = [0u8; 8];
      crate::crypto::random_fill(&mut candidate)
        .map_err(|_| anyhow::anyhow!("failed to generate TURN UDP reservation token"))?;
      if !reservations.contains_key(&candidate) {
        reservations.insert(
          candidate,
          Some(
            reservation
              .take()
              .expect("TURN UDP reservation inserted only once"),
          ),
        );
        selected = Some(candidate);
        break;
      }
    }
    selected
      .ok_or_else(|| anyhow::anyhow!("failed to allocate unique TURN UDP reservation token"))?
  };
  tokio::spawn(async move {
    tokio::time::sleep_until(expires_at.into()).await;
    expire_udp_relay_reservations();
  });
  Ok(IssuedUdpReservation {
    token,
    committed: false,
  })
}

fn reservations() -> &'static Mutex<HashMap<ReservationToken, Option<UdpRelayReservation>>> {
  UDP_RELAY_RESERVATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn expire_locked(
  reservations: &mut HashMap<ReservationToken, Option<UdpRelayReservation>>,
  now: Instant,
) {
  reservations.retain(|_, reservation| {
    reservation
      .as_ref()
      .is_none_or(|reservation| reservation.expires_at > now)
  });
}

#[cfg(test)]
mod tests {
  use crate::config::TurnRelayPortRange;

  use super::*;

  fn loopback_config(start: u16, end: u16) -> TurnRelayFamilyConfig {
    TurnRelayFamilyConfig {
      family: TurnRelayAddressFamily::Ipv4,
      public_ip: "127.0.0.1".parse().expect("public IP"),
      relay_bind_ip: "127.0.0.1".parse().expect("relay IP"),
      relay_port_range: TurnRelayPortRange { start, end },
    }
  }

  fn prepare_available_pair(reserve_next: bool) -> PreparedUdpRelay {
    for _ in 0..128 {
      let probe = UdpSocket::bind("127.0.0.1:0").expect("probe UDP port");
      let port = probe.local_addr().expect("probe address").port();
      let even = if port % 2 == 0 {
        port
      } else {
        port.saturating_sub(1)
      };
      drop(probe);
      if even == 0 || even == u16::MAX {
        continue;
      }
      let config = loopback_config(even, even + 1);
      if let Ok(prepared) = prepare_udp_relay(&config, UdpRelayRequest::Even { reserve_next }) {
        return prepared;
      }
    }
    panic!("failed to find an available adjacent UDP port pair")
  }

  #[test]
  fn even_port_without_reservation_binds_an_even_relay() {
    let prepared = prepare_available_pair(false);
    assert_eq!(prepared.relayed_addr.port() % 2, 0);
    assert_eq!(prepared.family, TurnRelayAddressFamily::Ipv4);
  }

  #[tokio::test]
  async fn adjacent_reservation_is_single_use_and_claim_rollback_is_safe() {
    let prepared = prepare_available_pair(true);
    let allocation_port = prepared.relayed_addr.port();
    let finalized = prepared.finalize().expect("issue reservation");
    let (_allocation, _, _, token) = finalized
      .into_install_ready()
      .expect("prepare allocation")
      .into_parts();
    let token = token.expect("R bit must issue a reservation token");

    let claim = claim_udp_relay(token)
      .expect("claim reservation")
      .expect("reservation must exist");
    assert_eq!(claim.family(), TurnRelayAddressFamily::Ipv4);
    assert!(
      claim_udp_relay(token)
        .expect("second claim lookup")
        .is_none(),
      "a claimed reservation cannot be consumed concurrently"
    );
    drop(claim);

    let claim = claim_udp_relay(token)
      .expect("reclaim reservation")
      .expect("failed allocation must restore its claim");
    let finalized = claim.into_finalized();
    assert_eq!(finalized.relayed_addr.port(), allocation_port + 1);
    let (_reserved, _, _, replacement) = finalized
      .into_install_ready()
      .expect("prepare reserved allocation")
      .into_parts();
    assert!(replacement.is_none());
    assert!(claim_udp_relay(token).expect("consumed lookup").is_none());
  }

  #[tokio::test]
  async fn expired_reservation_cannot_be_consumed() {
    let finalized = prepare_available_pair(true)
      .finalize()
      .expect("issue reservation");
    let (_allocation, _, _, token) = finalized
      .into_install_ready()
      .expect("prepare allocation")
      .into_parts();
    let token = token.expect("reservation token");
    {
      let mut reservations = reservations().lock().expect("reservation state");
      reservations
        .get_mut(&token)
        .and_then(Option::as_mut)
        .expect("stored reservation")
        .expires_at = Instant::now() - Duration::from_millis(1);
    }
    assert!(claim_udp_relay(token).expect("expired lookup").is_none());
  }
}

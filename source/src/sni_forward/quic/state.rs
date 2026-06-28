use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::limits::ConnectionPermit;

#[derive(Debug)]
pub(super) enum DatagramAction {
  QueueLocal(usize),
  SendTo(SocketAddr),
  Classify,
}

#[derive(Default)]
pub(super) struct QuicForwardState {
  pub(super) forward_by_client: HashMap<SocketAddr, QuicForwardSession>,
  pub(super) cid_to_client: HashMap<Vec<u8>, SocketAddr>,
  pub(super) local_clients: HashMap<SocketAddr, LocalQuicSession>,
  pub(super) local_cids: HashMap<Vec<u8>, SocketAddr>,
}

impl QuicForwardState {
  pub(super) fn known_action(&mut self, datagram: &[u8], peer: SocketAddr) -> DatagramAction {
    if let Some(client) = self.client_for_upstream_response(peer, datagram)
      && let Some(session) = self.forward_by_client.get_mut(&client)
    {
      session.last_seen = Instant::now();
      session.target_to_client = session
        .target_to_client
        .saturating_add(datagram.len() as u64);
      return DatagramAction::SendTo(client);
    }
    if let Some(session) = self.forward_by_client.get_mut(&peer) {
      session.last_seen = Instant::now();
      session.client_to_target = session
        .client_to_target
        .saturating_add(datagram.len() as u64);
      return DatagramAction::SendTo(session.target_addr);
    }
    if let Some(local) = self.local_clients.get_mut(&peer) {
      local.last_seen = Instant::now();
      return DatagramAction::QueueLocal(local.policy_index);
    }
    DatagramAction::Classify
  }

  pub(super) fn client_for_upstream_response(
    &mut self,
    peer: SocketAddr,
    datagram: &[u8],
  ) -> Option<SocketAddr> {
    let mut matching_clients = self
      .forward_by_client
      .iter()
      .filter_map(|(client, session)| (session.target_addr == peer).then_some(*client));
    let first_matching_client = matching_clients.next()?;
    let has_multiple_clients = matching_clients.next().is_some();

    if let Ok(header) = quic_parser::parse_initial(datagram)
      && let Some(client) = self.cid_to_client.get(header.dcid).copied()
    {
      if !header.scid.is_empty() {
        self.cid_to_client.insert(header.scid.to_vec(), client);
      }
      return Some(client);
    }
    if let Some(dcid) = quic_parser::peek_long_header_dcid(datagram)
      && let Some(client) = self.cid_to_client.get(dcid).copied()
    {
      return Some(client);
    }
    for (cid, client) in &self.cid_to_client {
      if datagram.len() > cid.len() && datagram.get(1..1 + cid.len()) == Some(cid.as_slice()) {
        return Some(*client);
      }
    }
    // QUIC peers can switch to encrypted NEW_CONNECTION_ID values that are
    // invisible to this L4 demux. A single active client for the target is
    // still unambiguous; shared targets without a known CID fail closed.
    if !has_multiple_clients {
      return Some(first_matching_client);
    }
    None
  }

  pub(super) fn enforce_pre_classification_limit(
    &mut self,
    max_sessions: usize,
  ) -> Vec<QuicForwardSession> {
    let mut evicted = Vec::new();
    while self.pre_classification_session_count() > max_sessions {
      let oldest_forward = self
        .forward_by_client
        .iter()
        .min_by_key(|(_, session)| session.last_seen)
        .map(|(client, session)| (*client, session.last_seen));
      let oldest_local = self
        .local_clients
        .iter()
        .min_by_key(|(_, session)| session.last_seen)
        .map(|(client, session)| (*client, session.last_seen));

      match (oldest_forward, oldest_local) {
        (Some((client, forward_seen)), Some((_local, local_seen)))
          if forward_seen <= local_seen =>
        {
          if let Some(session) = self.remove_forward_client(client) {
            evicted.push(session);
          }
        }
        (Some(_), Some((local, _))) => {
          self.remove_local_client(local);
        }
        (Some((client, _)), None) => {
          if let Some(session) = self.remove_forward_client(client) {
            evicted.push(session);
          }
        }
        (None, Some((local, _))) => {
          self.remove_local_client(local);
        }
        (None, None) => break,
      }
    }
    self.prune_cid_maps(max_sessions);
    evicted
  }

  fn pre_classification_session_count(&self) -> usize {
    self
      .forward_by_client
      .len()
      .saturating_add(self.local_clients.len())
  }

  pub(super) fn remove_forward_client(&mut self, client: SocketAddr) -> Option<QuicForwardSession> {
    let session = self.forward_by_client.remove(&client)?;
    self
      .cid_to_client
      .retain(|_, mapped_client| *mapped_client != client);
    Some(session)
  }

  fn remove_local_client(&mut self, client: SocketAddr) {
    self.local_clients.remove(&client);
    self
      .local_cids
      .retain(|_, mapped_client| *mapped_client != client);
  }

  fn prune_cid_maps(&mut self, max_sessions: usize) {
    self
      .cid_to_client
      .retain(|_, client| self.forward_by_client.contains_key(client));
    self
      .local_cids
      .retain(|_, client| self.local_clients.contains_key(client));
    trim_cid_map(&mut self.cid_to_client, max_sessions);
    trim_cid_map(&mut self.local_cids, max_sessions);
  }

  pub(super) fn expire_forward(&mut self, now: Instant, force: bool) -> Vec<QuicForwardSession> {
    self.local_clients.retain(|_, session| {
      !force && now.duration_since(session.last_seen) < Duration::from_secs(300)
    });
    self
      .local_cids
      .retain(|_, client| self.local_clients.contains_key(client));
    let mut expired_clients = Vec::new();
    for (client, session) in &self.forward_by_client {
      if force || now.duration_since(session.last_seen) >= session.idle_timeout {
        expired_clients.push(*client);
      }
    }
    let mut expired = Vec::with_capacity(expired_clients.len());
    for client in expired_clients {
      if let Some(session) = self.forward_by_client.remove(&client) {
        expired.push(session);
      }
    }
    self
      .cid_to_client
      .retain(|_, client| self.forward_by_client.contains_key(client));
    expired
  }
}

fn trim_cid_map(map: &mut HashMap<Vec<u8>, SocketAddr>, max_entries: usize) {
  while map.len() > max_entries {
    let Some(key) = map.keys().next().cloned() else {
      break;
    };
    map.remove(&key);
  }
}

pub(super) struct QuicForwardSession {
  pub(super) target_addr: SocketAddr,
  pub(super) rule_name: String,
  pub(super) target: String,
  pub(super) sni: String,
  pub(super) started: Instant,
  pub(super) last_seen: Instant,
  pub(super) idle_timeout: Duration,
  pub(super) client_to_target: u64,
  pub(super) target_to_client: u64,
  pub(super) _connection_permit: Option<ConnectionPermit>,
}

#[derive(Clone, Copy)]
pub(super) struct LocalQuicSession {
  pub(super) policy_index: usize,
  pub(super) last_seen: Instant,
}

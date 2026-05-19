use std::net::SocketAddr;

use crate::limits::ConnectionPermit;
use crate::sni_forward::SniForwardRule;

pub(super) struct QuicForwardRecord<'a> {
  pub(super) peer: SocketAddr,
  pub(super) target: SocketAddr,
  pub(super) client_scid: Vec<u8>,
  pub(super) sni: Option<&'a str>,
  pub(super) rule: &'a SniForwardRule,
  pub(super) connection_permit: ConnectionPermit,
}

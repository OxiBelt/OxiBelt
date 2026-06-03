//! SNI-based forwarding for TCP and QUIC flows.

pub(crate) mod client_hello;
pub(crate) mod connection_limits;
pub(crate) mod matcher;
pub(crate) mod quic;
pub(crate) mod tcp;

pub(crate) use matcher::{SniForwardDecision, SniForwardRule, SniForwardTable};

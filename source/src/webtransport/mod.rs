//! Bounded WebTransport capsule transport, shared by public and Admin endpoints.
//! This layer owns protocol state and never makes routing or authorization decisions.

mod budget;
pub(crate) mod codec;
pub(crate) mod handshake;
mod session;
mod streams;

pub(crate) use budget::{Budget, Reservation};
pub(crate) use session::{Role, Session, SessionOptions};
pub(crate) use streams::{RecvStream, SendStream, StreamResetCode, stream_reset_code};

#[cfg(test)]
mod tests;

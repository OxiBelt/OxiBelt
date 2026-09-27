//! Certificate Transparency protocol primitives.
//!
//! This module contains deterministic encoders, bounded decoders, and Merkle
//! proof helpers. It deliberately owns no networking, persistence, clock, or
//! private-key policy.

pub mod codec;
pub mod merkle;
pub mod rfc6962;
pub mod rfc9162;
pub mod static_ct;

use std::fmt;

/// A fail-closed CT wire-format or proof validation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CtError(pub(crate) &'static str);

impl CtError {
  pub const fn new(message: &'static str) -> Self {
    Self(message)
  }
}

impl fmt::Display for CtError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(self.0)
  }
}

impl std::error::Error for CtError {}

pub type Result<T> = std::result::Result<T, CtError>;

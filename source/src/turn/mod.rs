//! TURN listener, auth, and upstream-pool runtime.

mod auth;
mod edge;
mod listener;
mod pools;
pub mod protocol;

pub use listener::{BoundTurnListener, TurnListenerTask};
pub use pools::TurnPoolState;

#[cfg(feature = "fuzzing")]
pub(crate) mod fuzzing {
  use crate::config::TurnAuthConfig;

  use super::auth;
  use super::protocol::StunMessage;

  pub(crate) fn exercise_auth(auth: &TurnAuthConfig, realm: &str, message: &StunMessage<'_>) {
    let _ = auth::validate_message(auth, realm, message);
    let _ = auth::enforce_message(auth, realm, message);
  }

  pub(crate) fn create_nonce(auth: &TurnAuthConfig, realm: &str) -> Option<String> {
    auth::create_nonce(realm, auth).ok()
  }
}

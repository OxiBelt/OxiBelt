use std::io;
use std::net::SocketAddr;

use tracing::{debug, warn};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum DownstreamConnectionErrorClass {
  NormalClose,
  Failure,
}

pub(super) fn classify(error: &anyhow::Error) -> DownstreamConnectionErrorClass {
  if error.chain().any(cause_is_normal_close) {
    DownstreamConnectionErrorClass::NormalClose
  } else {
    DownstreamConnectionErrorClass::Failure
  }
}

pub(super) fn log_tcp(peer: SocketAddr, error: &anyhow::Error) {
  match classify(error) {
    DownstreamConnectionErrorClass::NormalClose => {
      debug!(peer = %peer, error = %error, "downstream connection closed");
    }
    DownstreamConnectionErrorClass::Failure => {
      warn!(peer = %peer, error = %error, "downstream connection closed with error");
    }
  }
}

pub(super) fn log_http3(peer: SocketAddr, error: &anyhow::Error) {
  match classify(error) {
    DownstreamConnectionErrorClass::NormalClose => {
      debug!(peer = %peer, error = %error, "HTTP/3 downstream connection closed");
    }
    DownstreamConnectionErrorClass::Failure => {
      warn!(peer = %peer, error = %error, "HTTP/3 downstream connection closed with error");
    }
  }
}

fn cause_is_normal_close(cause: &(dyn std::error::Error + 'static)) -> bool {
  if let Some(error) = cause.downcast_ref::<io::Error>()
    && matches!(
      error.kind(),
      io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::UnexpectedEof
    )
  {
    return true;
  }

  if let Some(error) = cause.downcast_ref::<hyper::Error>()
    && (error.is_canceled() || error.is_closed())
  {
    return true;
  }

  message_is_normal_close(&cause.to_string())
}

fn message_is_normal_close(message: &str) -> bool {
  let message = message.to_ascii_lowercase();
  [
    "body write aborted",
    "broken pipe",
    "cancelled",
    "canceled",
    "closed before message completed",
    "closed before request headers completed",
    "closed by peer",
    "connection reset",
    "connection closed",
    "graceful shutdown",
    "incomplete message",
    "reset by peer",
    "stream closed",
    "unexpected eof",
  ]
  .iter()
  .any(|needle| message.contains(needle))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn classifies_common_client_disconnects_as_normal_close() {
    let error = anyhow::anyhow!(io::Error::new(
      io::ErrorKind::ConnectionReset,
      "reset by peer"
    ));
    assert_eq!(
      classify(&error),
      DownstreamConnectionErrorClass::NormalClose
    );

    let error = anyhow::anyhow!("connection closed before message completed");
    assert_eq!(
      classify(&error),
      DownstreamConnectionErrorClass::NormalClose
    );

    let error = anyhow::anyhow!("body write aborted");
    assert_eq!(
      classify(&error),
      DownstreamConnectionErrorClass::NormalClose
    );
  }

  #[test]
  fn preserves_unknown_failures_as_warnable() {
    let error = anyhow::anyhow!("TLS handshake failed: certificate verify failed");
    assert_eq!(classify(&error), DownstreamConnectionErrorClass::Failure);
  }
}

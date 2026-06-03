//! TCP socket option helpers shared by listeners.
//! Platform-specific socket setup stays isolated from protocol handlers.

use std::net::SocketAddr;

use tokio::net::TcpStream;
use tracing::warn;

pub(crate) fn enable_tcp_nodelay(stream: &TcpStream, peer_addr: SocketAddr, purpose: &'static str) {
  if let Err(error) = stream.set_nodelay(true) {
    warn!(
      peer = %peer_addr,
      purpose = purpose,
      error = %error,
      "failed to enable TCP_NODELAY"
    );
  }
}

#[cfg(test)]
mod tests {
  use tokio::net::{TcpListener, TcpStream};

  use super::enable_tcp_nodelay;

  #[tokio::test]
  async fn accepted_stream_can_enable_tcp_nodelay() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let bind = listener.local_addr()?;
    let client = tokio::spawn(async move { TcpStream::connect(bind).await });

    let (accepted, peer_addr) = listener.accept().await?;
    let _client = client.await.expect("client task should not panic")?;

    enable_tcp_nodelay(&accepted, peer_addr, "test listener");

    assert!(accepted.nodelay()?);
    Ok(())
  }
}

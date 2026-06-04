use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub async fn spawn_if_configured(
  bind: Option<SocketAddr>,
) -> anyhow::Result<Option<tokio::task::JoinHandle<()>>> {
  let Some(bind) = bind else {
    return Ok(None);
  };
  let listener = TcpListener::bind(bind).await?;
  let handle = tokio::spawn(async move {
    loop {
      let Ok((mut stream, _)) = listener.accept().await else {
        continue;
      };
      tokio::spawn(async move {
        let mut buffer = [0_u8; 1024];
        let _ = stream.read(&mut buffer).await;
        let body = b"ok\n";
        let response = format!(
          "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
          body.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.write_all(body).await;
      });
    }
  });
  Ok(Some(handle))
}

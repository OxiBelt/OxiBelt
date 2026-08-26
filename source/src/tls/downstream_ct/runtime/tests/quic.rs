use super::*;

pub(super) async fn quic_connect(
  client_endpoint: &Endpoint,
  server_endpoint: &Endpoint,
  address: std::net::SocketAddr,
) -> Result<(Connection, Connection), String> {
  let client = async {
    client_endpoint
      .connect(address, SERVER_NAME)
      .map_err(|error| error.to_string())?
      .await
      .map_err(|error| error.to_string())
  };
  let server = async {
    server_endpoint
      .accept()
      .await
      .ok_or_else(|| "QUIC server endpoint closed".to_string())?
      .await
      .map_err(|error| error.to_string())
  };
  let (client, server) = tokio::time::timeout(IO_TIMEOUT, async { tokio::join!(client, server) })
    .await
    .map_err(|_| "QUIC handshake timed out".to_string())?;
  Ok((client?, server?))
}

pub(super) async fn quic_resume(
  client_endpoint: &Endpoint,
  server_endpoint: &Endpoint,
  address: std::net::SocketAddr,
  send_early_data: bool,
) -> Result<(Connection, Connection, bool), String> {
  let connecting = client_endpoint
    .connect(address, SERVER_NAME)
    .map_err(|error| error.to_string())?;
  if send_early_data {
    let (client, accepted) = connecting
      .into_0rtt()
      .map_err(|_| "QUIC client did not offer 0-RTT on resumed handshake".to_string())?;
    let client_send = quic_send(&client, SENTINEL);
    let server = async {
      let connection = server_endpoint
        .accept()
        .await
        .ok_or_else(|| "QUIC server endpoint closed".to_string())?
        .await
        .map_err(|error| error.to_string())?;
      let received = quic_receive(&connection).await?;
      Ok::<_, String>((connection, received))
    };
    let (accepted, sent, server) = tokio::time::timeout(IO_TIMEOUT, async {
      tokio::join!(accepted, client_send, server)
    })
    .await
    .map_err(|_| "QUIC 0-RTT handshake timed out".to_string())?;
    sent?;
    let (server, received) = server?;
    if received != SENTINEL {
      return Err("QUIC application received unexpected early data".to_string());
    }
    Ok((client, server, accepted))
  } else {
    let server = async {
      server_endpoint
        .accept()
        .await
        .ok_or_else(|| "QUIC server endpoint closed".to_string())?
        .await
        .map_err(|error| error.to_string())
    };
    let (client, server) =
      tokio::time::timeout(IO_TIMEOUT, async { tokio::join!(connecting, server) })
        .await
        .map_err(|_| "QUIC resumed handshake timed out".to_string())?;
    Ok((client.map_err(|error| error.to_string())?, server?, false))
  }
}

pub(super) async fn quic_rejected_resume(
  client_endpoint: &Endpoint,
  server_endpoint: &Endpoint,
  address: std::net::SocketAddr,
  send_early_data: bool,
  delivered: Arc<AtomicUsize>,
) -> Result<(), String> {
  let connecting = client_endpoint
    .connect(address, SERVER_NAME)
    .map_err(|error| error.to_string())?;
  let client = async {
    if send_early_data {
      let (connection, accepted) = connecting
        .into_0rtt()
        .map_err(|_| "QUIC client did not offer 0-RTT on rejected resume".to_string())?;
      let send_result = quic_send(&connection, SENTINEL).await;
      let accepted = accepted.await;
      if accepted || send_result.is_ok() {
        connection.closed().await;
      }
      Err::<(), String>("QUIC resumed handshake was rejected".to_string())
    } else {
      connecting
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
    }
  };
  let server = async {
    let incoming = server_endpoint
      .accept()
      .await
      .ok_or_else(|| "QUIC server endpoint closed".to_string())?;
    match incoming.await {
      Ok(connection) => quic_receive_and_record(&connection, &delivered).await,
      Err(error) => Err(error.to_string()),
    }
  };
  let (client, server) = tokio::time::timeout(IO_TIMEOUT, async { tokio::join!(client, server) })
    .await
    .map_err(|_| "rejected QUIC resume timed out".to_string())?;
  match (client, server) {
    (Ok(()), Ok(())) => Ok(()),
    _ => Err("QUIC resumed handshake did not reach the application".to_string()),
  }
}

pub(super) async fn quic_roundtrip(client: &Connection, server: &Connection, byte: u8) {
  tokio::time::timeout(IO_TIMEOUT, async {
    quic_send(client, &[byte])
      .await
      .expect("QUIC client should send");
    assert_eq!(
      quic_receive(server)
        .await
        .expect("QUIC server should receive"),
      [byte]
    );
    quic_send(server, &[byte])
      .await
      .expect("QUIC server should send");
    assert_eq!(
      quic_receive(client)
        .await
        .expect("QUIC client should receive"),
      [byte]
    );
  })
  .await
  .expect("QUIC roundtrip should not time out");
}

async fn quic_send(connection: &Connection, bytes: &[u8]) -> Result<(), String> {
  let mut stream = connection
    .open_uni()
    .await
    .map_err(|error| error.to_string())?;
  stream
    .write_all(bytes)
    .await
    .map_err(|error| error.to_string())?;
  stream.finish().map_err(|error| error.to_string())
}

async fn quic_receive(connection: &Connection) -> Result<Vec<u8>, String> {
  let mut stream = connection
    .accept_uni()
    .await
    .map_err(|error| error.to_string())?;
  stream
    .read_to_end(SENTINEL.len() + 1)
    .await
    .map_err(|error| error.to_string())
}

async fn quic_receive_and_record(
  connection: &Connection,
  delivered: &AtomicUsize,
) -> Result<(), String> {
  let mut stream = connection
    .accept_uni()
    .await
    .map_err(|error| error.to_string())?;
  let mut buffer = [0u8; 64];
  while let Some(read) = stream
    .read(&mut buffer)
    .await
    .map_err(|error| error.to_string())?
  {
    delivered.fetch_add(read, Ordering::AcqRel);
  }
  Ok(())
}

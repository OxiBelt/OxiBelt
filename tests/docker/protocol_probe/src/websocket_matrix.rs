//! Wire-level RFC 8441 and RFC 9220 WebSocket probes and echo peers.

use super::*;

const FRAME_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) fn is_h2_websocket(request: &Request<Incoming>) -> bool {
  request.method() == Method::CONNECT
    && request
      .extensions()
      .get::<hyper::ext::Protocol>()
      .is_some_and(|protocol| protocol.as_str() == "websocket")
}

pub(super) fn h2_echo_response(request: Request<Incoming>) -> Response<Full<Bytes>> {
  if request.headers().get("sec-websocket-version") != Some(&HeaderValue::from_static("13"))
    || request.headers().contains_key("sec-websocket-key")
  {
    return Response::builder()
      .status(StatusCode::BAD_REQUEST)
      .body(Full::new(Bytes::new()))
      .expect("static response");
  }
  tokio::spawn(async move {
    match hyper::upgrade::on(request).await {
      Ok(upgraded) => {
        let mut stream = TokioIo::new(upgraded);
        loop {
          let frame =
            match tokio::time::timeout(FRAME_TIMEOUT, read_websocket_frame(&mut stream)).await {
              Ok(Ok(Some(frame))) => frame,
              Ok(Ok(None)) => break,
              Ok(Err(error)) => {
                eprintln!("h2 WebSocket frame error: {error:#}");
                break;
              }
              Err(_) => break,
            };
          if !frame.masked || frame.rsv != 0 {
            break;
          }
          let response_opcode = if frame.opcode == 0x9 {
            0xa
          } else {
            frame.opcode
          };
          if write_websocket_frame(&mut stream, response_opcode, &frame.payload, false)
            .await
            .is_err()
          {
            break;
          }
          if frame.opcode == 0x8 {
            break;
          }
        }
      }
      Err(error) => eprintln!("h2 WebSocket upgrade failed: {error:#}"),
    }
  });
  Response::builder()
    .status(StatusCode::OK)
    .body(Full::new(Bytes::new()))
    .expect("static response")
}

pub(super) fn is_h3_websocket(request: &Request<()>) -> bool {
  request.method() == Method::CONNECT
    && request.extensions().get::<h3::ext::Protocol>() == Some(&h3::ext::Protocol::WEBSOCKET)
}

pub(super) async fn h3_echo_response(
  request: Request<()>,
  stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> anyhow::Result<()> {
  if request.headers().get("sec-websocket-version") != Some(&HeaderValue::from_static("13"))
    || request.headers().contains_key("sec-websocket-key")
  {
    stream
      .send_response(
        Response::builder()
          .status(StatusCode::BAD_REQUEST)
          .body(())?,
      )
      .await?;
    stream.finish().await?;
    return Ok(());
  }
  stream
    .send_response(Response::builder().status(StatusCode::OK).body(())?)
    .await?;
  let mut buffered = BytesMut::new();
  while let Some(mut data) = tokio::time::timeout(FRAME_TIMEOUT, stream.recv_data()).await?? {
    let len = data.remaining();
    buffered.extend_from_slice(&data.copy_to_bytes(len));
    while let Some(frame) = take_frame(&mut buffered)? {
      if !frame.masked || frame.rsv != 0 {
        bail!("invalid client WebSocket frame on h3 upstream");
      }
      let response_opcode = if frame.opcode == 0x9 {
        0xa
      } else {
        frame.opcode
      };
      stream
        .send_data(Bytes::from(frame_bytes(
          response_opcode,
          &frame.payload,
          false,
        )))
        .await?;
      if frame.opcode == 0x8 {
        stream.finish().await?;
        return Ok(());
      }
    }
  }
  stream.finish().await?;
  Ok(())
}

pub(super) async fn h2_client(args: WebSocketClientArgs) -> anyhow::Result<()> {
  let mut config = downstream_client_config_with_client_identity(
    Path::new(&args.ca_cert),
    b"h2",
    None,
    args.client_identity.as_ref(),
  )?;
  config.enable_sni = true;
  let tcp = TcpStream::connect((args.host.as_str(), args.port)).await?;
  let name = ServerName::try_from(args.server_name.clone())?;
  let tls = TlsConnector::from(Arc::new(config))
    .connect(name, tcp)
    .await?;
  if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
    bail!("WebSocket probe did not negotiate h2");
  }
  let (mut sender, connection) = h2::client::handshake(tls).await?;
  let driver = tokio::spawn(connection);
  tokio::time::timeout(FRAME_TIMEOUT, async {
    while !sender.is_extended_connect_protocol_enabled() {
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
  })
  .await
  .context("h2 peer did not advertise extended CONNECT")?;
  let mut request = Request::builder()
    .method(Method::CONNECT)
    .uri(format!("https://{}{}", args.authority, args.path))
    .version(Version::HTTP_2)
    .header("sec-websocket-version", "13")
    .body(())?;
  request.headers_mut().extend(args.headers.clone());
  request
    .extensions_mut()
    .insert(h2::ext::Protocol::from_static("websocket"));
  let (response, mut send) = sender.send_request(request, false)?;
  let response = tokio::time::timeout(FRAME_TIMEOUT, response).await??;
  let status = response.status().as_u16();
  if status != args.expect_status {
    bail!(
      "h2 WebSocket status {status}, expected {}",
      args.expect_status
    );
  }
  if status != 200 {
    println!(
      "{}",
      serde_json::json!({"protocol":"h2","status":status,"upgraded":false})
    );
    driver.abort();
    return Ok(());
  }
  if response.headers().contains_key("sec-websocket-accept") {
    bail!("h2 extended CONNECT response carried HTTP/1 accept key");
  }
  let mut recv = response.into_body();
  send.send_data(Bytes::from(frame_bytes(0x2, &args.payload, true)), false)?;
  let echoed = recv_h2_frame(&mut recv).await.context("h2 echo frame")?;
  if echoed.opcode != 0x2 || echoed.masked || echoed.payload != args.payload {
    bail!("invalid h2 WebSocket echo");
  }
  let unsupported_connect_status = if args.probe_unsupported_connect {
    Some(probe_h2_non_websocket_connect(&mut sender, &args.authority).await?)
  } else {
    None
  };
  send.send_data(Bytes::from(frame_bytes(0x9, b"probe-ping", true)), false)?;
  let pong = recv_h2_frame(&mut recv).await.context("h2 pong frame")?;
  if pong.opcode != 0xa || pong.payload != b"probe-ping" || pong.masked {
    bail!("invalid h2 WebSocket pong");
  }
  send.send_data(Bytes::from(frame_bytes(0x8, &[], true)), false)?;
  let close = recv_h2_frame(&mut recv).await.context("h2 close frame")?;
  if close.opcode != 0x8 || close.masked {
    bail!("invalid h2 WebSocket close");
  }
  println!(
    "{}",
    serde_json::json!({"protocol":"h2","status":status,"upgraded":true,"echoed_bytes":args.payload.len(),"ping_pong":true,"closed":true,"unsupported_connect_status":unsupported_connect_status})
  );
  driver.abort();
  Ok(())
}

pub(super) async fn h3_client(args: WebSocketClientArgs) -> anyhow::Result<()> {
  let config = downstream_client_config_with_client_identity(
    Path::new(&args.ca_cert),
    b"h3",
    None,
    args.client_identity.as_ref(),
  )?;
  let crypto = QuicClientConfig::try_from(config)?;
  let remote = resolve_remote_addr(&args.host, args.port).await?;
  let endpoint = Endpoint::client(client_bind_addr(remote))?;
  let quinn = endpoint
    .connect_with(
      QuinnClientConfig::new(Arc::new(crypto)),
      remote,
      &args.server_name,
    )?
    .await?;
  let close_connection = quinn.clone();
  let (mut driver, mut sender) = h3::client::builder()
    .enable_extended_connect(true)
    .build::<_, _, Bytes>(h3_quinn::Connection::new(quinn))
    .await?;
  let driver_task = tokio::spawn(async move {
    let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
  });
  let mut request = Request::builder()
    .method(Method::CONNECT)
    .uri(format!("https://{}{}", args.authority, args.path))
    .version(Version::HTTP_3)
    .header("sec-websocket-version", "13")
    .body(())?;
  request.headers_mut().extend(args.headers.clone());
  request
    .extensions_mut()
    .insert(h3::ext::Protocol::WEBSOCKET);
  let mut stream = sender.send_request(request).await?;
  let response = tokio::time::timeout(FRAME_TIMEOUT, stream.recv_response()).await??;
  let status = response.status().as_u16();
  if status != args.expect_status {
    bail!(
      "h3 WebSocket status {status}, expected {}",
      args.expect_status
    );
  }
  if status != 200 {
    println!(
      "{}",
      serde_json::json!({"protocol":"h3","status":status,"upgraded":false})
    );
    close_connection.close(0u32.into(), b"probe complete");
    driver_task.abort();
    return Ok(());
  }
  if response.headers().contains_key("sec-websocket-accept") {
    bail!("h3 extended CONNECT response carried HTTP/1 accept key");
  }
  stream
    .send_data(Bytes::from(frame_bytes(0x2, &args.payload, true)))
    .await?;
  let mut buffered = BytesMut::new();
  let echoed = recv_h3_frame(&mut stream, &mut buffered)
    .await
    .context("h3 echo frame")?;
  if echoed.opcode != 0x2 || echoed.masked || echoed.payload != args.payload {
    bail!("invalid h3 WebSocket echo");
  }
  let unsupported_connect_status = if args.probe_unsupported_connect {
    Some(probe_h3_unsupported_connect(&mut sender, &args.authority).await?)
  } else {
    None
  };
  stream
    .send_data(Bytes::from(frame_bytes(0x9, b"probe-ping", true)))
    .await?;
  let pong = recv_h3_frame(&mut stream, &mut buffered)
    .await
    .context("h3 pong frame")?;
  if pong.opcode != 0xa || pong.payload != b"probe-ping" || pong.masked {
    bail!("invalid h3 WebSocket pong");
  }
  stream
    .send_data(Bytes::from(frame_bytes(0x8, &[], true)))
    .await?;
  let close = recv_h3_frame(&mut stream, &mut buffered)
    .await
    .context("h3 close frame")?;
  if close.opcode != 0x8 || close.masked {
    bail!("invalid h3 WebSocket close");
  }
  println!(
    "{}",
    serde_json::json!({"protocol":"h3","status":status,"upgraded":true,"echoed_bytes":args.payload.len(),"ping_pong":true,"closed":true,"unsupported_connect_status":unsupported_connect_status})
  );
  close_connection.close(0u32.into(), b"probe complete");
  driver_task.abort();
  Ok(())
}

async fn probe_h2_non_websocket_connect(
  sender: &mut h2::client::SendRequest<Bytes>,
  authority: &str,
) -> anyhow::Result<u16> {
  let mut request = Request::builder()
    .method(Method::CONNECT)
    .uri(format!("https://{authority}/ws/unsupported"))
    .version(Version::HTTP_2)
    .body(())?;
  request
    .extensions_mut()
    .insert(h2::ext::Protocol::from_static("connect-udp"));
  let (response, _) = sender.send_request(request, true)?;
  let response = tokio::time::timeout(FRAME_TIMEOUT, response).await??;
  let status = response.status().as_u16();
  if response.status().is_success() {
    bail!("non-WebSocket typed h2 CONNECT was accepted as a tunnel ({status})");
  }
  Ok(status)
}

async fn probe_h3_unsupported_connect(
  sender: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
  authority: &str,
) -> anyhow::Result<u16> {
  let mut request = Request::builder()
    .method(Method::CONNECT)
    .uri(format!("https://{authority}/ws/unsupported"))
    .version(Version::HTTP_3)
    .body(())?;
  request
    .extensions_mut()
    .insert(h3::ext::Protocol::CONNECT_UDP);
  let mut stream = sender.send_request(request).await?;
  let response = tokio::time::timeout(FRAME_TIMEOUT, stream.recv_response()).await??;
  let status = response.status().as_u16();
  if status != 501 {
    bail!("unsupported typed h3 CONNECT returned {status}, expected 501");
  }
  Ok(status)
}

fn frame_bytes(opcode: u8, payload: &[u8], masked: bool) -> Vec<u8> {
  let mut out = vec![0x80 | opcode];
  let flag = if masked { 0x80 } else { 0 };
  if payload.len() < 126 {
    out.push(flag | payload.len() as u8);
  } else {
    out.push(flag | 126);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
  }
  if masked {
    let key = [0x10, 0x20, 0x30, 0x40];
    out.extend_from_slice(&key);
    out.extend(
      payload
        .iter()
        .enumerate()
        .map(|(i, byte)| byte ^ key[i % 4]),
    );
  } else {
    out.extend_from_slice(payload);
  }
  out
}

fn take_frame(buffer: &mut BytesMut) -> anyhow::Result<Option<WebSocketFrame>> {
  if buffer.len() < 2 {
    return Ok(None);
  }
  let fin = buffer[0] & 0x80 != 0;
  let rsv = buffer[0] & 0x70;
  let opcode = buffer[0] & 0x0f;
  let masked = buffer[1] & 0x80 != 0;
  let (payload_len, header_len) = match buffer[1] & 0x7f {
    len @ 0..=125 => (usize::from(len), 2),
    126 if buffer.len() >= 4 => (usize::from(u16::from_be_bytes([buffer[2], buffer[3]])), 4),
    126 => return Ok(None),
    127 => bail!("WebSocket probe frame exceeds bounded size"),
    _ => unreachable!(),
  };
  if payload_len > 1024 * 1024 {
    bail!("WebSocket probe frame too large");
  }
  let total = header_len + if masked { 4 } else { 0 } + payload_len;
  if buffer.len() < total {
    return Ok(None);
  }
  let mut frame = buffer.split_to(total);
  let mask = if masked {
    Some(frame[header_len..header_len + 4].to_vec())
  } else {
    None
  };
  let start = header_len + if masked { 4 } else { 0 };
  let mut payload = frame.split_off(start).to_vec();
  if let Some(mask) = mask {
    for (i, byte) in payload.iter_mut().enumerate() {
      *byte ^= mask[i % 4];
    }
  }
  Ok(Some(WebSocketFrame {
    fin,
    rsv,
    opcode,
    masked,
    payload,
  }))
}

async fn recv_h2_frame(recv: &mut h2::RecvStream) -> anyhow::Result<WebSocketFrame> {
  let mut buffer = BytesMut::new();
  loop {
    let bytes = tokio::time::timeout(FRAME_TIMEOUT, recv.data())
      .await?
      .ok_or_else(|| anyhow!("h2 WebSocket stream ended before frame"))??;
    buffer.extend_from_slice(&bytes);
    recv.flow_control().release_capacity(bytes.len())?;
    if let Some(frame) = take_frame(&mut buffer)? {
      return Ok(frame);
    }
  }
}

async fn recv_h3_frame(
  stream: &mut h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
  buffer: &mut BytesMut,
) -> anyhow::Result<WebSocketFrame> {
  loop {
    if let Some(frame) = take_frame(buffer)? {
      return Ok(frame);
    }
    let mut data = tokio::time::timeout(FRAME_TIMEOUT, stream.recv_data())
      .await??
      .ok_or_else(|| anyhow!("h3 WebSocket stream ended before frame"))?;
    let len = data.remaining();
    buffer.extend_from_slice(&data.copy_to_bytes(len));
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn masked_frame_can_arrive_in_fragments() {
    let wire = frame_bytes(0x2, b"websocket-payload", true);
    let mut buffer = BytesMut::from(&wire[..3]);
    assert!(take_frame(&mut buffer).unwrap().is_none());
    buffer.extend_from_slice(&wire[3..]);
    let frame = take_frame(&mut buffer).unwrap().unwrap();
    assert_eq!(frame.opcode, 0x2);
    assert!(frame.masked);
    assert_eq!(frame.payload, b"websocket-payload");
    assert!(buffer.is_empty());
  }

  #[test]
  fn oversized_frame_is_rejected_before_allocation() {
    let mut buffer = BytesMut::from(&[0x82, 0x7f][..]);
    assert!(take_frame(&mut buffer).is_err());
  }
}

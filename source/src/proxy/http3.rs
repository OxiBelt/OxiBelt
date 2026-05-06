use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use ::http::{Method, Request, Response, StatusCode};
use anyhow::Context;
use bytes::{Buf, Bytes};
use futures_util::future::select_all;
use h3::ext::Protocol;
use h3_webtransport::server::{AcceptedBi, WebTransportSession};
use http_body_util::BodyExt;
use hyper::body::Frame;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::oneshot;
use tracing::{debug, warn};

use crate::config::UpstreamConfig;
use crate::proxy::http as http_proxy;
use crate::proxy::http::body::{ProxyBody, boxed_error, channel_body};
use crate::proxy::http::response::text_response;
use crate::server::downstream_quic_tls_metadata;
use crate::state::{AppHandle, AppSnapshot};
use crate::tls;

type H3BidiStream = h3_quinn::BidiStream<Bytes>;
type H3RequestStream = h3::server::RequestStream<H3BidiStream, Bytes>;
type H3WebTransportSession = WebTransportSession<h3_quinn::Connection, Bytes>;

const H3_BODY_CHANNEL_CAPACITY: usize = 16;

pub(crate) async fn handle_downstream_connection(
  connection: h3_quinn::quinn::Connection,
  state: AppHandle,
) -> anyhow::Result<()> {
  let peer_addr = connection.remote_address();
  let tls_metadata = Arc::new(downstream_quic_tls_metadata(&connection));
  let quic_connection = h3_quinn::Connection::new(connection);
  let mut h3_connection = h3::server::builder()
    .enable_extended_connect(true)
    .enable_datagram(true)
    .enable_webtransport(true)
    .max_webtransport_sessions(256)
    .build(quic_connection)
    .await
    .context("failed to establish downstream HTTP/3 connection")?;

  loop {
    let Some(resolver) = h3_connection
      .accept()
      .await
      .context("failed to accept downstream HTTP/3 request")?
    else {
      return Ok(());
    };

    let (request, stream) = resolver
      .resolve_request()
      .await
      .context("failed to resolve downstream HTTP/3 request")?;

    if is_webtransport_request(&request) {
      let prepared = match http_proxy::prepare_webtransport(
        &request,
        peer_addr,
        tls_metadata.as_ref(),
        state.snapshot().as_ref(),
      ) {
        Ok(prepared) => prepared,
        Err(response) => {
          respond_to_h3_request(stream, *response).await?;
          continue;
        }
      };

      let upstream_session =
        match connect_upstream_webtransport(&prepared, state.snapshot().as_ref()).await {
          Ok(session) => session,
          Err(error) => {
            warn!(
                upstream = %prepared.upstream.name,
                error = %error,
                "failed to connect upstream WebTransport session"
            );
            respond_to_h3_request(
              stream,
              text_response(
                StatusCode::BAD_GATEWAY,
                "upstream WebTransport session failed",
              ),
            )
            .await?;
            continue;
          }
        };

      let downstream_session = WebTransportSession::accept(request, stream, h3_connection)
        .await
        .context("failed to accept downstream WebTransport session")?;
      bridge_webtransport(
        downstream_session,
        upstream_session,
        peer_addr,
        tls_metadata,
        state,
      )
      .await?;
      return Ok(());
    }

    let status = handle_h3_request(
      request,
      stream,
      peer_addr,
      tls_metadata.clone(),
      state.clone(),
    )
    .await?;
    debug!(peer = %peer_addr, %status, "handled downstream HTTP/3 request");
  }
}

pub(crate) async fn forward_request(
  request: Request<ProxyBody>,
  upstream: &UpstreamConfig,
  state: &AppSnapshot,
) -> anyhow::Result<Response<ProxyBody>> {
  let quic_config =
    tls::build_upstream_quic_client_config(&state.config.proxy.trusted_ca_certs, &upstream.tls.ech)
      .with_context(|| format!("failed to build upstream QUIC client for {}", upstream.name))?;
  let uri = request.uri().clone();
  let (server_name, remote_addr) = resolve_upstream_addr(&upstream.origin).await?;
  let endpoint = h3_quinn::quinn::Endpoint::client(client_bind_addr(remote_addr))
    .context("failed to create upstream QUIC endpoint")?;
  let quinn_connection = endpoint
    .connect_with(quic_config, remote_addr, &server_name)
    .with_context(|| format!("failed to start upstream HTTP/3 connection to {server_name}"))?
    .await
    .with_context(|| format!("failed to connect upstream HTTP/3 to {server_name}"))?;
  let close_connection = quinn_connection.clone();
  let h3_connection = h3_quinn::Connection::new(quinn_connection);
  let (mut driver, mut send_request) = h3::client::builder()
    .enable_datagram(true)
    .enable_extended_connect(true)
    .build(h3_connection)
    .await
    .context("failed to establish upstream HTTP/3 connection")?;
  let driver_task = tokio::spawn(async move {
    let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
  });

  let (parts, mut body) = request.into_parts();
  let h3_request = Request::from_parts(parts, ());
  let mut stream = send_request
    .send_request(h3_request)
    .await
    .with_context(|| format!("failed to send upstream HTTP/3 request {uri}"))?;

  while let Some(frame) = body.frame().await {
    let frame = frame.map_err(|error| {
      anyhow::anyhow!("failed to read request body for upstream HTTP/3: {error}")
    })?;
    match frame.into_data() {
      Ok(data) => {
        stream
          .send_data(data)
          .await
          .context("failed to send upstream HTTP/3 request data")?;
      }
      Err(frame) => {
        if let Ok(trailers) = frame.into_trailers() {
          stream
            .send_trailers(trailers)
            .await
            .context("failed to send upstream HTTP/3 request trailers")?;
        }
      }
    }
  }
  stream
    .finish()
    .await
    .context("failed to finish upstream HTTP/3 request")?;

  let response = stream
    .recv_response()
    .await
    .context("failed to receive upstream HTTP/3 response")?;

  let (parts, _) = response.into_parts();
  let (body_sender, body) = channel_body(H3_BODY_CHANNEL_CAPACITY);
  tokio::spawn(async move {
    loop {
      match stream.recv_data().await {
        Ok(Some(mut chunk)) => {
          let len = chunk.remaining();
          if body_sender
            .send(Ok(Frame::data(chunk.copy_to_bytes(len))))
            .await
            .is_err()
          {
            break;
          }
        }
        Ok(None) => break,
        Err(error) => {
          let _ = body_sender
            .send(Err(boxed_error(std::io::Error::other(format!(
              "failed to receive upstream HTTP/3 response data: {error}"
            )))))
            .await;
          break;
        }
      }
    }

    close_connection.close(0u32.into(), b"request complete");
    let _ = driver_task.await;
    drop(endpoint);
  });
  Ok(Response::from_parts(parts, body))
}

async fn handle_h3_request(
  request: Request<()>,
  stream: H3RequestStream,
  peer_addr: SocketAddr,
  tls_metadata: Arc<crate::waf::WafTlsMetadata>,
  state: AppHandle,
) -> anyhow::Result<StatusCode> {
  let (request, stream_receiver) = stream_h3_request_body(request, stream);
  let response = http_proxy::handle_http3(request, peer_addr, tls_metadata, state).await;
  let status = response.status();
  let stream = stream_receiver
    .await
    .map_err(|_| anyhow::anyhow!("downstream HTTP/3 request body task did not return stream"))?;
  respond_to_h3_request(stream, response).await?;
  Ok(status)
}

fn stream_h3_request_body(
  request: Request<()>,
  stream: H3RequestStream,
) -> (Request<ProxyBody>, oneshot::Receiver<H3RequestStream>) {
  let (parts, _) = request.into_parts();
  let (body_sender, body) = channel_body(H3_BODY_CHANNEL_CAPACITY);
  let (stream_sender, stream_receiver) = oneshot::channel();
  let mut stream = stream;
  tokio::spawn(async move {
    loop {
      match stream.recv_data().await {
        Ok(Some(mut chunk)) => {
          let len = chunk.remaining();
          if body_sender
            .send(Ok(Frame::data(chunk.copy_to_bytes(len))))
            .await
            .is_err()
          {
            break;
          }
        }
        Ok(None) => break,
        Err(error) => {
          let _ = body_sender
            .send(Err(boxed_error(std::io::Error::other(format!(
              "failed to receive downstream HTTP/3 request data: {error}"
            )))))
            .await;
          break;
        }
      }
    }
    let _ = stream_sender.send(stream);
  });
  (Request::from_parts(parts, body), stream_receiver)
}

async fn respond_to_h3_request(
  mut stream: H3RequestStream,
  response: Response<ProxyBody>,
) -> anyhow::Result<()> {
  let (parts, mut body) = response.into_parts();
  let head = Response::from_parts(parts, ());
  stream
    .send_response(head)
    .await
    .context("failed to send downstream HTTP/3 response headers")?;

  while let Some(frame) = body.frame().await {
    let frame = frame.map_err(|error| {
      anyhow::anyhow!("failed to read downstream HTTP/3 response body: {error}")
    })?;
    match frame.into_data() {
      Ok(data) => {
        stream
          .send_data(data)
          .await
          .context("failed to send downstream HTTP/3 response data")?;
      }
      Err(frame) => {
        if let Ok(trailers) = frame.into_trailers() {
          stream
            .send_trailers(trailers)
            .await
            .context("failed to send downstream HTTP/3 response trailers")?;
        }
      }
    }
  }
  stream
    .finish()
    .await
    .context("failed to finish downstream HTTP/3 response")?;

  Ok(())
}

async fn connect_upstream_webtransport(
  prepared: &http_proxy::PreparedWebTransport,
  state: &AppSnapshot,
) -> anyhow::Result<web_transport_quinn::Session> {
  let quic_config = tls::build_upstream_quic_client_config(
    &state.config.proxy.trusted_ca_certs,
    &prepared.upstream.tls.ech,
  )
  .with_context(|| {
    format!(
      "failed to build upstream WebTransport QUIC client for {}",
      prepared.upstream.name
    )
  })?;
  let mut request = web_transport_quinn::proto::ConnectRequest::new(prepared.target_url.clone())
    .with_headers(prepared.headers.clone());
  if !prepared.protocols.is_empty() {
    request = request.with_protocols(prepared.protocols.clone());
  }
  let (server_name, remote_addr) = resolve_upstream_addr(&prepared.target_url).await?;
  let endpoint = web_transport_quinn::quinn::Endpoint::client(client_bind_addr(remote_addr))
    .context("failed to create upstream WebTransport endpoint")?;
  let connection = endpoint
    .connect_with(quic_config, remote_addr, &server_name)
    .with_context(|| format!("failed to start upstream WebTransport connection to {server_name}"))?
    .await
    .with_context(|| format!("failed to connect upstream WebTransport to {server_name}"))?;
  web_transport_quinn::Session::connect(connection, request)
    .await
    .context("upstream WebTransport CONNECT failed")
}

async fn bridge_webtransport(
  downstream: H3WebTransportSession,
  upstream: web_transport_quinn::Session,
  peer_addr: SocketAddr,
  tls_metadata: Arc<crate::waf::WafTlsMetadata>,
  state: AppHandle,
) -> anyhow::Result<()> {
  let downstream = Arc::new(downstream);
  let upstream = Arc::new(upstream);
  let tasks = vec![
    tokio::spawn(bridge_downstream_bidi(
      downstream.clone(),
      upstream.clone(),
      peer_addr,
      tls_metadata,
      state,
    )),
    tokio::spawn(bridge_upstream_bidi(downstream.clone(), upstream.clone())),
    tokio::spawn(bridge_downstream_uni(downstream.clone(), upstream.clone())),
    tokio::spawn(bridge_upstream_uni(downstream.clone(), upstream.clone())),
    tokio::spawn(bridge_downstream_datagrams(
      downstream.clone(),
      upstream.clone(),
    )),
    tokio::spawn(bridge_upstream_datagrams(downstream, upstream)),
  ];

  let (result, _index, remaining) = select_all(tasks).await;
  for task in remaining {
    task.abort();
  }
  result.context("WebTransport bridge task panicked")?
}

async fn bridge_downstream_bidi(
  downstream: Arc<H3WebTransportSession>,
  upstream: Arc<web_transport_quinn::Session>,
  peer_addr: SocketAddr,
  tls_metadata: Arc<crate::waf::WafTlsMetadata>,
  state: AppHandle,
) -> anyhow::Result<()> {
  loop {
    match downstream.accept_bi().await? {
      Some(AcceptedBi::BidiStream(_session_id, stream)) => {
        let (upstream_send, upstream_recv) = upstream.open_bi().await?;
        tokio::spawn(copy_bidi_stream(stream, upstream_send, upstream_recv));
      }
      Some(AcceptedBi::Request(request, stream)) => {
        if is_webtransport_request(&request) {
          respond_to_h3_request(
            stream,
            text_response(
              StatusCode::CONFLICT,
              "additional WebTransport sessions on an active connection are not supported",
            ),
          )
          .await?;
        } else {
          handle_h3_request(
            request,
            stream,
            peer_addr,
            tls_metadata.clone(),
            state.clone(),
          )
          .await?;
        }
      }
      None => return Ok(()),
    }
  }
}

async fn bridge_upstream_bidi(
  downstream: Arc<H3WebTransportSession>,
  upstream: Arc<web_transport_quinn::Session>,
) -> anyhow::Result<()> {
  loop {
    let (upstream_send, upstream_recv) = upstream.accept_bi().await?;
    let stream = downstream.open_bi(downstream.session_id()).await?;
    tokio::spawn(copy_bidi_stream(stream, upstream_send, upstream_recv));
  }
}

async fn bridge_downstream_uni(
  downstream: Arc<H3WebTransportSession>,
  upstream: Arc<web_transport_quinn::Session>,
) -> anyhow::Result<()> {
  loop {
    let Some((_session_id, downstream_recv)) = downstream.accept_uni().await? else {
      return Ok(());
    };
    let upstream_send = upstream.open_uni().await?;
    tokio::spawn(copy_one_way(downstream_recv, upstream_send));
  }
}

async fn bridge_upstream_uni(
  downstream: Arc<H3WebTransportSession>,
  upstream: Arc<web_transport_quinn::Session>,
) -> anyhow::Result<()> {
  loop {
    let upstream_recv = upstream.accept_uni().await?;
    let downstream_send = downstream.open_uni(downstream.session_id()).await?;
    tokio::spawn(copy_one_way(upstream_recv, downstream_send));
  }
}

async fn bridge_downstream_datagrams(
  downstream: Arc<H3WebTransportSession>,
  upstream: Arc<web_transport_quinn::Session>,
) -> anyhow::Result<()> {
  let mut reader = downstream.datagram_reader();
  loop {
    let datagram = reader.read_datagram().await?;
    let mut payload = datagram.into_payload();
    let len = payload.remaining();
    upstream.send_datagram(payload.copy_to_bytes(len))?;
  }
}

async fn bridge_upstream_datagrams(
  downstream: Arc<H3WebTransportSession>,
  upstream: Arc<web_transport_quinn::Session>,
) -> anyhow::Result<()> {
  let mut sender = downstream.datagram_sender();
  loop {
    let datagram = upstream.read_datagram().await?;
    sender.send_datagram(datagram)?;
  }
}

async fn copy_bidi_stream<D>(
  downstream: D,
  mut upstream_send: web_transport_quinn::SendStream,
  mut upstream_recv: web_transport_quinn::RecvStream,
) -> anyhow::Result<()>
where
  D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  let (mut downstream_recv, mut downstream_send) = tokio::io::split(downstream);
  let downstream_to_upstream = async {
    tokio::io::copy(&mut downstream_recv, &mut upstream_send).await?;
    upstream_send.shutdown().await
  };
  let upstream_to_downstream = async {
    tokio::io::copy(&mut upstream_recv, &mut downstream_send).await?;
    downstream_send.shutdown().await
  };
  tokio::try_join!(downstream_to_upstream, upstream_to_downstream)?;
  Ok(())
}

async fn copy_one_way<R, W>(mut recv: R, mut send: W) -> anyhow::Result<()>
where
  R: AsyncRead + Unpin + Send + 'static,
  W: AsyncWrite + Unpin + Send + 'static,
{
  tokio::io::copy(&mut recv, &mut send).await?;
  send.shutdown().await?;
  Ok(())
}

async fn resolve_upstream_addr(origin: &url::Url) -> anyhow::Result<(String, SocketAddr)> {
  let port = origin
    .port_or_known_default()
    .ok_or_else(|| anyhow::anyhow!("upstream origin has no port: {origin}"))?;
  let host = origin
    .host_str()
    .ok_or_else(|| anyhow::anyhow!("upstream origin has no host: {origin}"))?
    .to_string();
  let remote = tokio::net::lookup_host((host.as_str(), port))
    .await
    .with_context(|| format!("failed to resolve upstream HTTP/3 host {host}:{port}"))?
    .next()
    .ok_or_else(|| anyhow::anyhow!("upstream HTTP/3 host resolved no addresses: {host}:{port}"))?;
  Ok((host, remote))
}

fn client_bind_addr(remote_addr: SocketAddr) -> SocketAddr {
  match remote_addr.ip() {
    IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
  }
}

fn is_webtransport_request(request: &Request<()>) -> bool {
  request.method() == Method::CONNECT
    && request
      .extensions()
      .get::<Protocol>()
      .is_some_and(|protocol| protocol == &Protocol::WEB_TRANSPORT)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn detects_webtransport_extended_connect() {
    let mut request = Request::builder()
      .method(Method::CONNECT)
      .uri("https://example.com/session")
      .body(())
      .unwrap();
    request.extensions_mut().insert(Protocol::WEB_TRANSPORT);

    assert!(is_webtransport_request(&request));
  }

  #[test]
  fn plain_connect_is_not_webtransport() {
    let request = Request::builder()
      .method(Method::CONNECT)
      .uri("https://example.com/session")
      .body(())
      .unwrap();

    assert!(!is_webtransport_request(&request));
  }
}

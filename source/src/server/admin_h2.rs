//! TLS Admin HTTP/2, including the operation-event WebTransport endpoint.

use std::convert::Infallible;
use std::net::SocketAddr;

use ::http::header::{HOST, ORIGIN};
use ::http::{Method, Request, StatusCode};
use anyhow::Context;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::AsyncWriteExt;

use super::admin_listener::AdminConnectionContext;
use super::{AdminOperationRuntime, admin_response};
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::AppHandle;
use crate::webtransport::{Session, SessionOptions};

use super::admin_webtransport as webtransport;

pub(super) async fn serve_admin_http2<I>(
  io: I,
  context: AdminConnectionContext,
  tls13: bool,
) -> anyhow::Result<()>
where
  I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
  let AdminConnectionContext {
    peer_addr,
    listener_bind,
    state,
    admin_control,
    admin_operations,
    scheme,
    client_certificate,
  } = context;
  let webtransport_enabled = state.snapshot().config.admin.operations.webtransport;
  let service = service_fn(move |mut request: Request<Incoming>| {
    let state = state.clone();
    let admin_control = admin_control.clone();
    let admin_operations = admin_operations.clone();
    let client_certificate = client_certificate.clone();
    async move {
      if let Some(client_certificate) = client_certificate {
        request.extensions_mut().insert(client_certificate);
      }
      if webtransport::matches_operation_event_path(request.uri().path()) {
        return Ok::<_, Infallible>(
          operation_event_webtransport_response(
            &mut request,
            state,
            admin_operations,
            peer_addr,
            listener_bind,
            tls13,
          )
          .await,
        );
      }
      Ok::<_, Infallible>(
        admin_response(
          request,
          state,
          admin_control,
          admin_operations,
          peer_addr,
          listener_bind,
          scheme,
        )
        .await,
      )
    }
  });
  let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
  builder.timer(TokioTimer::new());
  if tls13 && webtransport_enabled {
    builder.webtransport_settings(hyper::ext::WebTransportSettings {
      enabled: true,
      initial_max_data: Some(0),
      initial_max_stream_data_uni: Some(0),
      initial_max_stream_data_bidi_local: Some(0),
      initial_max_stream_data_bidi_remote: Some(0),
      initial_max_streams_uni: Some(0),
      initial_max_streams_bidi: Some(0),
    });
  }
  // The peer's SETTINGS grant the server's sole unidirectional event stream. Our
  // advertised credits stay at zero because the Admin role accepts no app streams.
  builder
    .serve_connection(TokioIo::new(io), service)
    .await
    .map_err(|error| anyhow::anyhow!(error))
}

async fn operation_event_webtransport_response(
  request: &mut Request<Incoming>,
  state: AppHandle,
  operations: AdminOperationRuntime,
  peer_addr: SocketAddr,
  listener_bind: SocketAddr,
  tls13: bool,
) -> ::http::Response<ProxyBody> {
  let Some(_control_request) = state
    .snapshot()
    .overload
    .try_admit_control_request(crate::overload::ControlPlane::Admin)
  else {
    return text_response(
      StatusCode::SERVICE_UNAVAILABLE,
      "control capacity exhausted",
    );
  };
  let (audit, reservation) =
    match super::admin_audit_gate::reserve_or_reject(request, &state, peer_addr, "https") {
      Ok(value) => value,
      Err(response) => return *response,
    };
  if !is_operation_event_webtransport_request(request) {
    let response = if request.method() != Method::CONNECT {
      text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
    } else {
      text_response(StatusCode::BAD_REQUEST, "WebTransport CONNECT required")
    };
    return finalize_error(response, audit, reservation, &state).await;
  }
  if let Err(error) = crate::webtransport::handshake::validate_request(request) {
    return finalize_error(
      text_response(
        StatusCode::BAD_REQUEST,
        &format!("invalid WebTransport CONNECT: {error}"),
      ),
      audit,
      reservation,
      &state,
    )
    .await;
  }
  if !tls13 {
    return finalize_error(
      text_response(StatusCode::BAD_REQUEST, "WebTransport requires TLS 1.3"),
      audit,
      reservation,
      &state,
    )
    .await;
  }
  if !supplied_origin_is_same_origin(request) {
    return finalize_error(
      text_response(StatusCode::FORBIDDEN, "cross-origin WebTransport request"),
      audit,
      reservation,
      &state,
    )
    .await;
  }
  let subscription = match webtransport::prepare_operation_event_subscription(
    request,
    &state,
    &operations,
    peer_addr,
    super::admin_audit_gate::listener_current(&state.snapshot(), listener_bind),
  )
  .await
  {
    Ok(subscription) => subscription,
    Err(response) => return finalize_error(response, audit, reservation, &state).await,
  };
  let mut options = SessionOptions::admin(
    state
      .snapshot()
      .config
      .admin
      .http2
      .webtransport
      .outbound_queue_bytes_per_session,
    state
      .snapshot()
      .config
      .admin
      .http2
      .webtransport
      .outbound_queue_bytes_total,
  );
  options.peer_stream_limits =
    match crate::webtransport::handshake::peer_stream_limits(request.headers()) {
      Ok(limits) => limits,
      Err(error) => {
        return finalize_error(
          text_response(
            StatusCode::BAD_REQUEST,
            &format!("invalid WebTransport-Init header: {error}"),
          ),
          audit,
          reservation,
          &state,
        )
        .await;
      }
    };
  let buffer_reservation = match Session::reserve(options, operations.webtransport_h2_budget()) {
    Ok(reservation) => reservation,
    Err(_) => {
      return finalize_error(
        text_response(
          StatusCode::SERVICE_UNAVAILABLE,
          "WebTransport buffer capacity exhausted",
        ),
        audit,
        reservation,
        &state,
      )
      .await;
    }
  };
  let on_webtransport = hyper::ext::on_webtransport(request);
  let response = super::admin_error::finalize_response(empty_connect_response(), &audit).await;
  tokio::spawn(async move {
    let carrier = match on_webtransport.await {
      Ok(carrier) => carrier,
      Err(error) => {
        let event = audit.finish_with_error(StatusCode::BAD_REQUEST, "WebTransport session failed");
        if let Err(error) = reservation.commit(&audit, event).await {
          tracing::warn!(error = %error, "required Admin HTTP/2 audit persistence failed");
        }
        tracing::debug!(error = %error, "admin HTTP/2 WebTransport carrier failed");
        return;
      }
    };
    let (session, driver) = match Session::start_reserved(carrier, options, buffer_reservation) {
      Ok(session) => session,
      Err(error) => {
        let event =
          audit.finish_with_error(StatusCode::BAD_REQUEST, "invalid WebTransport session");
        if let Err(commit_error) = reservation.commit(&audit, event).await {
          tracing::warn!(error = %commit_error, "required Admin HTTP/2 audit persistence failed");
        }
        tracing::debug!(error = %error, "admin HTTP/2 WebTransport session start failed");
        return;
      }
    };
    if let Err(error) = reservation
      .commit(&audit, audit.finish(StatusCode::OK))
      .await
    {
      tracing::warn!(error = %error, "required Admin HTTP/2 audit persistence failed");
      session.silent_close();
      let _ = driver.await;
      return;
    }
    let webtransport::OperationEventSubscription {
      history,
      receiver,
      permit,
    } = subscription;
    if let Err(error) = write_operation_events(session.clone(), history, receiver, options).await {
      tracing::debug!(error = %error, "admin HTTP/2 WebTransport operation event stream ended");
      session.silent_close();
    }
    let _ = driver.await;
    drop(permit);
  });
  response
}

async fn write_operation_events(
  session: Session,
  history: Vec<super::admin_operations::AdminOperationEvent>,
  receiver: tokio::sync::broadcast::Receiver<super::admin_operations::AdminOperationEvent>,
  options: SessionOptions,
) -> anyhow::Result<()> {
  let mut stream = session
    .open_uni()
    .await
    .context("failed to open Admin HTTP/2 WebTransport event stream")?;
  let (sender, mut chunks) = tokio::sync::mpsc::channel(1);
  let producer = tokio::spawn(produce_operation_events(
    history,
    receiver,
    sender,
    options.outbound_chunk_bytes(),
  ));
  while let Some(chunk) = chunks.recv().await {
    if let Err(error) = stream.write_all(&chunk.bytes).await {
      producer.abort();
      return Err(error).context("failed to write Admin HTTP/2 WebTransport event");
    }
    if chunk.terminal {
      if let Err(error) = stream.shutdown().await {
        producer.abort();
        return Err(error).context("failed to close Admin HTTP/2 WebTransport event stream");
      }
      session.drain();
      session.close(0, b"");
      tokio::time::sleep(webtransport::TERMINAL_EVENT_DRAIN_DELAY).await;
      return producer
        .await
        .context("Admin HTTP/2 event producer stopped")?;
    }
  }
  if let Err(error) = stream.shutdown().await {
    producer.abort();
    return Err(error).context("failed to close Admin HTTP/2 WebTransport event stream");
  }
  session.close(0, b"");
  producer
    .await
    .context("Admin HTTP/2 event producer stopped")?
}

struct EventChunk {
  bytes: Bytes,
  terminal: bool,
}

async fn produce_operation_events(
  history: Vec<super::admin_operations::AdminOperationEvent>,
  mut receiver: tokio::sync::broadcast::Receiver<super::admin_operations::AdminOperationEvent>,
  sender: tokio::sync::mpsc::Sender<EventChunk>,
  chunk_bytes: usize,
) -> anyhow::Result<()> {
  for event in history {
    let terminal = event.operation.state.is_terminal();
    serialize_event_chunks(event, terminal, &sender, chunk_bytes).await?;
    if terminal {
      return Ok(());
    }
  }
  let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(15));
  loop {
    tokio::select! {
      biased;
      received = receiver.recv() => match received {
        Ok(event) => {
          let terminal = event.operation.state.is_terminal();
          serialize_event_chunks(event, terminal, &sender, chunk_bytes).await?;
          if terminal { return Ok(()); }
        }
        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => anyhow::bail!("admin WebTransport operation event stream lagged"),
        Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
      },
      _ = heartbeat.tick() => {
        sender.send(EventChunk {
          bytes: Bytes::from_static(b"{\"event\":\"heartbeat\"}\n"), terminal: false,
        }).await.map_err(|_| anyhow::anyhow!("Admin HTTP/2 event consumer closed"))?;
      }
    }
  }
}

async fn serialize_event_chunks(
  event: super::admin_operations::AdminOperationEvent,
  terminal: bool,
  sender: &tokio::sync::mpsc::Sender<EventChunk>,
  chunk_bytes: usize,
) -> anyhow::Result<()> {
  let sender = sender.clone();
  tokio::task::spawn_blocking(move || {
    let mut writer = EventChunkWriter {
      sender,
      terminal,
      buffer: Vec::with_capacity(chunk_bytes),
      chunk_bytes,
    };
    serde_json::to_writer(&mut writer, &event)?;
    std::io::Write::write_all(&mut writer, b"\n")?;
    writer.finish()
  })
  .await
  .context("Admin HTTP/2 event serializer stopped")??;
  Ok(())
}

struct EventChunkWriter {
  sender: tokio::sync::mpsc::Sender<EventChunk>,
  terminal: bool,
  buffer: Vec<u8>,
  chunk_bytes: usize,
}

impl EventChunkWriter {
  fn flush_chunk(&mut self, terminal: bool) -> std::io::Result<()> {
    if self.buffer.is_empty() {
      return Ok(());
    }
    let bytes = Bytes::from(std::mem::take(&mut self.buffer));
    self
      .sender
      .blocking_send(EventChunk { bytes, terminal })
      .map_err(|_| {
        std::io::Error::new(
          std::io::ErrorKind::BrokenPipe,
          "Admin HTTP/2 event consumer closed",
        )
      })
  }

  fn finish(&mut self) -> std::io::Result<()> {
    if self.buffer.is_empty() && self.terminal {
      return self
        .sender
        .blocking_send(EventChunk {
          bytes: Bytes::new(),
          terminal: true,
        })
        .map_err(|_| {
          std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "Admin HTTP/2 event consumer closed",
          )
        });
    }
    self.flush_chunk(self.terminal)
  }
}

impl std::io::Write for EventChunkWriter {
  fn write(&mut self, mut bytes: &[u8]) -> std::io::Result<usize> {
    let written = bytes.len();
    while !bytes.is_empty() {
      let space = self.chunk_bytes.saturating_sub(self.buffer.len());
      let take = space.min(bytes.len());
      self.buffer.extend_from_slice(&bytes[..take]);
      bytes = &bytes[take..];
      if self.buffer.len() == self.chunk_bytes {
        self.flush_chunk(false)?;
      }
    }
    Ok(written)
  }

  fn flush(&mut self) -> std::io::Result<()> {
    Ok(())
  }
}

fn empty_connect_response() -> ::http::Response<ProxyBody> {
  let body = Empty::<Bytes>::new()
    .map_err(|never| -> crate::proxy::http::body::BoxError { match never {} })
    .boxed();
  let mut response = ::http::Response::new(body);
  response
    .headers_mut()
    .insert("capsule-protocol", ::http::HeaderValue::from_static("?1"));
  response
}

async fn finalize_error(
  response: ::http::Response<ProxyBody>,
  audit: crate::admin_audit::AdminAuditHandle,
  reservation: crate::admin_audit::AdminAuditReservation,
  state: &AppHandle,
) -> ::http::Response<ProxyBody> {
  let response = super::admin_error::finalize_response(response, &audit).await;
  if let Err(error) = reservation
    .commit(&audit, audit.finish(response.status()))
    .await
  {
    tracing::warn!(error = %error, "required Admin HTTP/2 audit persistence failed");
    return super::admin_error::error_envelope_response(
      StatusCode::SERVICE_UNAVAILABLE,
      "required Admin audit persistence failed",
      &audit.request_id(),
      None,
    );
  }
  let _ = state;
  response
}

fn is_operation_event_webtransport_request(request: &Request<Incoming>) -> bool {
  request.method() == Method::CONNECT
    && webtransport::matches_operation_event_path(request.uri().path())
    && request
      .extensions()
      .get::<hyper::ext::Protocol>()
      .is_some_and(|protocol| protocol.as_str() == "webtransport")
}

fn supplied_origin_is_same_origin<B>(request: &Request<B>) -> bool {
  let Some(origin) = request.headers().get(ORIGIN) else {
    return true;
  };
  let Ok(origin) = origin.to_str() else {
    return false;
  };
  let Ok(origin) = url::Url::parse(origin) else {
    return false;
  };
  if origin.scheme() != "https"
    || !origin.username().is_empty()
    || origin.password().is_some()
    || origin.path() != "/"
    || origin.query().is_some()
    || origin.fragment().is_some()
  {
    return false;
  }
  let Some(host) = origin.host_str() else {
    return false;
  };
  let authority = request
    .uri()
    .authority()
    .map(|authority| authority.as_str())
    .or_else(|| {
      request
        .headers()
        .get(HOST)
        .and_then(|host| host.to_str().ok())
    });
  let Some(authority) = authority.and_then(|value| value.parse::<::http::uri::Authority>().ok())
  else {
    return false;
  };
  authority.host().eq_ignore_ascii_case(host)
    && authority.port_u16().unwrap_or(443) == origin.port_or_known_default().unwrap_or(443)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn successful_connect_response_declares_capsule_protocol_without_body_framing() {
    let response = empty_connect_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
      response
        .headers()
        .get("capsule-protocol")
        .and_then(|value| value.to_str().ok()),
      Some("?1")
    );
    assert!(
      !response
        .headers()
        .contains_key(::http::header::CONTENT_LENGTH)
    );
    assert!(
      !response
        .headers()
        .contains_key(::http::header::CONTENT_TYPE)
    );
    assert!(
      !response
        .headers()
        .contains_key(::http::header::TRANSFER_ENCODING)
    );
  }

  #[test]
  fn origin_policy_allows_non_web_and_same_origin_requests() {
    let request = Request::builder()
      .uri("/admin/v1/operations/op/events/wt")
      .header(HOST, "admin.example.test")
      .body(())
      .unwrap();
    assert!(supplied_origin_is_same_origin(&request));
    let request = Request::builder()
      .uri("/admin/v1/operations/op/events/wt")
      .header(HOST, "admin.example.test")
      .header(ORIGIN, "https://admin.example.test")
      .body(())
      .unwrap();
    assert!(supplied_origin_is_same_origin(&request));
  }

  #[test]
  fn origin_policy_rejects_cross_origin_requests() {
    let request = Request::builder()
      .uri("/admin/v1/operations/op/events/wt")
      .header(HOST, "admin.example.test")
      .header(ORIGIN, "https://other.example.test")
      .body(())
      .unwrap();
    assert!(!supplied_origin_is_same_origin(&request));
  }
}

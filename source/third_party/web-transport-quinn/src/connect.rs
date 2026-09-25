use std::ops::Deref;

use web_transport_proto::{ConnectRequest, ConnectResponse, VarInt};

use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum ConnectError {
  #[error("quic stream was closed early")]
  UnexpectedEnd,

  #[error("protocol error: {0}")]
  ProtoError(#[from] web_transport_proto::ConnectError),

  #[error("connection error")]
  ConnectionError(#[from] quinn::ConnectionError),

  #[error("read error")]
  ReadError(#[from] quinn::ReadError),

  #[error("write error")]
  WriteError(#[from] quinn::WriteError),

  #[error("http error status: {0}")]
  ErrorStatus(http::StatusCode),

  #[error("server returned protocol not in request: {0}")]
  ProtocolMismatch(String),
}

/// An HTTP/3 CONNECT request/response for establishing a WebTransport session.
pub struct Connecting {
  // The request that was sent by the client.
  pub request: ConnectRequest,

  // A reference to the send/recv stream, so we don't close it until dropped.
  pub(crate) send: quinn::SendStream,
  pub(crate) recv: quinn::RecvStream,
}

impl Connecting {
  pub async fn accept(conn: &quinn::Connection) -> Result<Self, ConnectError> {
    // Accept the stream that will be used to send the HTTP CONNECT request.
    // If they try to send any other type of HTTP request, we will error out.
    let (send, mut recv) = conn.accept_bi().await?;

    let request = web_transport_proto::ConnectRequest::read(&mut recv).await?;
    tracing::debug!(?request, "received CONNECT request");

    // The request was successfully decoded, so we can send a response.
    Ok(Self {
      request,
      send,
      recv,
    })
  }

  // Called by the server to send a response to the client and establish the session.
  pub async fn respond(
    mut self,
    response: impl Into<ConnectResponse>,
  ) -> Result<Connected, ConnectError> {
    let response = response.into();

    // Validate that our protocol was in the client's request.
    if let Some(protocol) = &response.protocol {
      if !self.request.protocols.contains(protocol) {
        return Err(ConnectError::ProtocolMismatch(protocol.clone()));
      }
    }

    tracing::debug!(?response, "sending CONNECT response");
    response.write(&mut self.send).await?;

    Ok(Connected {
      request: self.request,
      response,
      send: self.send,
      recv: self.recv,
    })
  }

  pub async fn reject(self, status: http::StatusCode) -> Result<(), ConnectError> {
    let mut connect = self.respond(status).await?;
    connect.send.finish().ok();
    Ok(())
  }
}

impl Deref for Connecting {
  type Target = ConnectRequest;

  fn deref(&self) -> &Self::Target {
    &self.request
  }
}

pub struct Connected {
  // The request that was sent by the client.
  pub request: ConnectRequest,

  // The response sent by the server.
  pub response: ConnectResponse,

  // A reference to the send/recv stream, so we don't close it until dropped.
  pub(crate) send: quinn::SendStream,
  pub(crate) recv: quinn::RecvStream,
}

impl Connected {
  /// Open a new WebTransport session on the given connection for the given URL.
  ///
  /// You may add any number of subprotocols allowing the server to select from.
  /// If the list is empty the field will be omitted in the request header.
  pub async fn open(
    conn: &quinn::Connection,
    request: impl Into<ConnectRequest>,
  ) -> Result<Self, ConnectError> {
    let request = request.into();

    // Create a new stream that will be used to send the CONNECT frame.
    let (mut send, mut recv) = conn.open_bi().await?;

    tracing::debug!(?request, "sending CONNECT request");
    request.write(&mut send).await?;

    let mut response = web_transport_proto::ConnectResponse::read(&mut recv).await?;
    tracing::debug!(?response, "received CONNECT response");

    validate_response(&request, &response)?;
    sanitize_response_protocol(&request, &mut response);

    Ok(Self {
      request,
      response,
      send,
      recv,
    })
  }

  // The session ID is the stream ID of the CONNECT request.
  pub fn session_id(&self) -> VarInt {
    // We gotta convert from the Quinn VarInt to the (forked) WebTransport VarInt.
    // We don't use the quinn::VarInt because that would mean a quinn dependency in web-transport-proto
    let stream_id = quinn::VarInt::from(self.send.id());
    VarInt::try_from(stream_id.into_inner()).unwrap()
  }
}

fn validate_response(
  request: &ConnectRequest,
  response: &ConnectResponse,
) -> Result<(), ConnectError> {
  match request.draft {
    web_transport_proto::WebTransportDraft::Draft02 => {
      if response.draft_marker.as_deref() != Some("draft02") {
        return Err(ConnectError::ProtoError(
          web_transport_proto::ConnectError::DraftMismatch,
        ));
      }
    }
    web_transport_proto::WebTransportDraft::Draft16 => {
      if response.draft_marker.is_some() {
        return Err(ConnectError::ProtoError(
          web_transport_proto::ConnectError::DraftMismatch,
        ));
      }
    }
  }

  // A successful CONNECT can use any 2xx status (for example, 204).
  if !response.status.is_success() {
    return Err(ConnectError::ErrorStatus(response.status));
  }

  Ok(())
}

fn sanitize_response_protocol(request: &ConnectRequest, response: &mut ConnectResponse) {
  // An unoffered selected protocol is ignored by WebTransport clients.
  // Keep the session established, but never expose that value as negotiated.
  if response
    .protocol
    .as_ref()
    .is_some_and(|protocol| !request.protocols.contains(protocol))
  {
    response.protocol = None;
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use web_transport_proto::WebTransportDraft;

  #[test]
  fn successful_non_200_connect_is_accepted_for_both_drafts() {
    let url = url::Url::parse("https://example.com/echo").expect("test URL");
    for draft in [WebTransportDraft::Draft02, WebTransportDraft::Draft16] {
      let request = ConnectRequest::new(url.clone()).with_draft(draft);
      let response = ConnectResponse::new(http::StatusCode::NO_CONTENT).for_draft(draft);
      assert!(validate_response(&request, &response).is_ok());
      let failure = ConnectResponse::new(http::StatusCode::BAD_GATEWAY).for_draft(draft);
      assert!(matches!(
        validate_response(&request, &failure),
        Err(ConnectError::ErrorStatus(_))
      ));
      let mismatch = ConnectResponse::new(http::StatusCode::NO_CONTENT).for_draft(match draft {
        WebTransportDraft::Draft02 => WebTransportDraft::Draft16,
        WebTransportDraft::Draft16 => WebTransportDraft::Draft02,
      });
      assert!(matches!(
        validate_response(&request, &mismatch),
        Err(ConnectError::ProtoError(_))
      ));
    }
  }

  #[test]
  fn unoffered_protocol_does_not_fail_connect_or_become_negotiated() {
    let url = url::Url::parse("https://example.com/echo").expect("test URL");
    let request = ConnectRequest::new(url).with_protocols(vec!["a".into(), "b".into()]);
    let mut selected = ConnectResponse::new(http::StatusCode::OK)
      .for_draft(WebTransportDraft::Draft02)
      .with_protocol("b");
    assert!(validate_response(&request, &selected).is_ok());
    sanitize_response_protocol(&request, &mut selected);
    assert_eq!(selected.protocol.as_deref(), Some("b"));

    let mut unoffered = ConnectResponse::new(http::StatusCode::OK)
      .for_draft(WebTransportDraft::Draft02)
      .with_protocol("c");
    assert!(validate_response(&request, &unoffered).is_ok());
    sanitize_response_protocol(&request, &mut unoffered);
    assert_eq!(unoffered.protocol, None);
  }
}

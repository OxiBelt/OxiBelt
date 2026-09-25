use futures::try_join;

use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum SettingsError {
    #[error("quic stream was closed early")]
    UnexpectedEnd,

    #[error("protocol error: {0}")]
    ProtoError(#[from] web_transport_proto::SettingsError),

    #[error("WebTransport is not supported")]
    WebTransportUnsupported,

    #[error("WebTransport draft 16 requires RESET_STREAM_AT support")]
    ResetAtUnsupported,

    #[error("WebTransport requires QUIC datagrams")]
    DatagramUnsupported,

    #[error("WebTransport draft 16 initial stream credit exceeds 2^60")]
    InvalidInitialCredit,

    #[error("connection error")]
    ConnectionError(#[from] quinn::ConnectionError),

    #[error("read error")]
    ReadError(#[from] quinn::ReadError),

    #[error("write error")]
    WriteError(#[from] quinn::WriteError),
}

pub struct Settings {
    // A reference to the send/recv stream, so we don't close it until dropped.
    #[allow(dead_code)]
    send: quinn::SendStream,

    #[allow(dead_code)]
    recv: quinn::RecvStream,
    /// Initial per-session stream and byte credit from the peer.
    pub(crate) peer_credit: (u64, u64, u64),
}

impl Settings {
    // Establish the H3 connection.
    pub async fn connect(
        conn: &quinn::Connection,
        draft: web_transport_proto::WebTransportDraft,
    ) -> Result<Self, SettingsError> {
        if conn.max_datagram_size().is_none() {
            return Err(SettingsError::DatagramUnsupported);
        }
        if draft == web_transport_proto::WebTransportDraft::Draft16
            && !conn.peer_supports_reset_stream_at()
        {
            return Err(SettingsError::ResetAtUnsupported);
        }
        let recv = Self::accept(conn, draft);
        let send = Self::open(conn, draft);

        // Run both tasks concurrently until one errors or they both complete.
        let (send, (recv, peer_credit)) = try_join!(send, recv)?;
        Ok(Self { send, recv, peer_credit })
    }

    async fn accept(
        conn: &quinn::Connection,
        draft: web_transport_proto::WebTransportDraft,
    ) -> Result<(quinn::RecvStream, (u64, u64, u64)), SettingsError> {
        let mut recv = conn.accept_uni().await?;
        let settings = web_transport_proto::Settings::read(&mut recv).await?;

        tracing::debug!(?settings, "received SETTINGS frame");

        let supported = match draft {
            web_transport_proto::WebTransportDraft::Draft02 => settings.supports_webtransport() > 0,
            web_transport_proto::WebTransportDraft::Draft16 => settings.supports_webtransport_draft16(),
        };
        if !supported {
            return Err(SettingsError::WebTransportUnsupported);
        }

        let credit = settings.draft16_initial_credit();
        if draft == web_transport_proto::WebTransportDraft::Draft16
            && (credit.0 > web_transport_proto::MAX_STREAMS || credit.1 > web_transport_proto::MAX_STREAMS)
        {
            return Err(SettingsError::InvalidInitialCredit);
        }
        Ok((recv, credit))
    }

    async fn open(
        conn: &quinn::Connection,
        draft: web_transport_proto::WebTransportDraft,
    ) -> Result<quinn::SendStream, SettingsError> {
        let mut settings = web_transport_proto::Settings::default();
        match draft {
            web_transport_proto::WebTransportDraft::Draft02 => settings.enable_webtransport(1),
            web_transport_proto::WebTransportDraft::Draft16 => {
                settings.enable_webtransport_draft16(0, 0, 0);
            }
        }

        tracing::debug!(?settings, "sending SETTINGS frame");

        let mut send = conn.open_uni().await?;
        settings.write(&mut send).await?;

        Ok(send)
    }
}

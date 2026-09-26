use std::{
    fmt,
    future::Future,
    io::Cursor,
    ops::Deref,
    pin::Pin,
    sync::{Arc, Mutex, OnceLock},
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use futures::stream::{FuturesUnordered, Stream, StreamExt};
use kio::{Fan, Waiter};
use tokio::sync::watch;

use crate::flow::SessionFlow;
use crate::{
    proto::{ConnectRequest, ConnectResponse, Frame, StreamUni, VarInt},
    waiters::Parked,
    ClientError, Connected, RecvStream, SendStream, SessionError, Settings, WebTransportError,
};

const H3_MESSAGE_ERROR: u64 = 0x10e;
const WT_DRAIN_SESSION: u64 = 0x78ae;

fn record_drain_capsule(
    capsule: &web_transport_proto::Capsule,
    draining: &watch::Sender<bool>,
) -> Result<bool, u64> {
    let web_transport_proto::Capsule::Unknown { typ, payload } = capsule else {
        return Ok(false);
    };
    if typ.into_inner() != WT_DRAIN_SESSION {
        return Ok(false);
    }
    if !payload.is_empty() {
        return Err(H3_MESSAGE_ERROR);
    }
    draining.send_replace(true);
    Ok(true)
}

async fn validated_remote_close<S: tokio::io::AsyncRead + Unpin>(
    reader: &mut web_transport_proto::Http3CapsuleReader<S>,
    code: u32,
    reason: String,
) -> Result<Option<(u32, String)>, u64> {
    if reason.len() > 1024 {
        return Err(H3_MESSAGE_ERROR);
    }
    // The close capsule must be the final CONNECT data. A zero-length DATA
    // frame followed by FIN is allowed.
    match reader.read().await {
        Ok(None) => Ok(Some((code, reason))),
        Ok(Some(_)) | Err(_) => Err(H3_MESSAGE_ERROR),
    }
}

/// The ALPN the QUIC handshake negotiated, or `None` if there was none, the handshake
/// has not completed, or it is not valid UTF-8.
///
/// Quinn only exposes the ALPN via a downcast of the boxed handshake data, so the result
/// is owned rather than borrowed from the connection.
#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
fn negotiated_alpn(conn: &quinn::Connection) -> Option<String> {
    let data = conn.handshake_data()?;
    let data = data
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()?;

    String::from_utf8(data.protocol?).ok()
}

/// `quinn::crypto::rustls` only exists once a TLS backend is enabled, so there is no
/// handshake data type to name here.
///
/// This crate's own builders are gated the same way, so normally there is no connection
/// to read an ALPN from either. A caller that enables a provider on `quinn` directly and
/// brings its own endpoint can still establish one, and [`Session::protocol`] reports
/// `None` for those raw sessions. Enable this crate's `aws-lc-rs` or `ring` feature to
/// get the ALPN.
#[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
fn negotiated_alpn(_conn: &quinn::Connection) -> Option<String> {
    None
}

/// An established WebTransport session, acting like a full QUIC connection. See [`quinn::Connection`].
///
/// It is important to remember that WebTransport is layered on top of QUIC:
///   1. Each stream starts with a few bytes identifying the stream type and session ID.
///   2. Errors codes are encoded with the session ID, so they aren't full QUIC error codes.
///   3. Stream IDs may have gaps in them, used by HTTP/3 transparant to the application.
///
/// Deref is used to expose non-overloaded methods on [`quinn::Connection`].
/// These should be safe to use with WebTransport, but file a PR if you find one that isn't.
#[derive(Clone)]
pub struct Session {
    conn: quinn::Connection,

    // The session ID, as determined by the stream ID of the connect request.
    session_id: Option<VarInt>,
    datagram_id: Option<VarInt>,
    draft16: bool,
    flow: Option<Arc<SessionFlow>>,
    credit_writer: Option<Arc<CreditWriterTask>>,

    // The accept logic is stateful, so use an Arc<Mutex> to share it.
    accept: Option<Arc<Mutex<SessionAccept>>>,

    // Cache the headers in front of each stream we open.
    header_uni: Bytes,
    header_bi: Bytes,
    header_datagram: Bytes,

    // Keep a reference to the settings and connect stream to avoid closing them until dropped.
    #[allow(dead_code)]
    settings: Option<Arc<Settings>>,

    // The send side of the CONNECT stream, used to write the CloseWebTransportSession capsule.
    // Wrapped in Arc<Mutex<Option<...>>> so close() can take it exactly once.
    connect_send: Option<Arc<tokio::sync::Mutex<quinn::SendStream>>>,

    // Session error, set once by either local close() or the background task
    // when a remote CloseWebTransportSession capsule is received.
    // Uses OnceLock for set-once, first-writer-wins semantics with lock-free reads.
    error: Arc<OnceLock<SessionError>>,
    draining: Arc<watch::Sender<bool>>,

    // The request sent by the client, or None for a raw QUIC session.
    request: Option<ConnectRequest>,

    // The response sent by the server, or None for a raw QUIC session.
    response: Option<ConnectResponse>,

    // The ALPN negotiated by the QUIC handshake, for raw QUIC sessions. Quinn only
    // exposes it behind an allocating downcast, so `protocol()` has nothing in the
    // connection to borrow from and needs somewhere to keep the result.
    //
    // Resolved on first read rather than at construction: `raw()` accepts any
    // connection, including one from `into_0rtt()` whose handshake has not completed
    // and so has no ALPN yet. Only a successful read is latched, so an early call
    // cannot pin `None` for the life of the session. Shared across clones.
    //
    // Unused by HTTP/3 sessions, which read the subprotocol out of the response.
    alpn: Arc<OnceLock<String>>,

    // Quinn exposes these only as futures, and those futures hold the `Notify`
    // registration that will wake us — rebuilding one per poll would drop the
    // registration and we would never be woken. Each is per-clone, so cloning the
    // session is what gives you concurrent operations.
    //
    // Only used by `Session::raw`, where there is no `SessionAccept` to forward to
    // and Quinn's own accept futures hold the registration.
    op_accept_uni: crate::op::Op<Result<RecvStream, SessionError>>,
    op_accept_bi: crate::op::Op<Result<(SendStream, RecvStream), SessionError>>,
    op_open_uni: crate::op::Op<Result<SendStream, SessionError>>,
    op_open_bi: crate::op::Op<Result<(SendStream, RecvStream), SessionError>>,
    op_send_datagram: crate::op::Op<Result<(), SessionError>>,
    op_recv_datagram: crate::op::Op<Result<Bytes, SessionError>>,
    op_closed: crate::op::Op<SessionError>,

    // `SessionAccept` holds its waiters weakly, so the handle this clone registered
    // with has to outlive the poll that made it. Per-clone, for the same reason as the
    // ops above.
    parked_accept_uni: Parked,
    parked_accept_bi: Parked,
}

// A session can be cloned, so the final clone owns cancellation of the writer.
// The task itself does not retain this guard.
struct CreditWriterTask(tokio::task::JoinHandle<()>);

impl Drop for CreditWriterTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Session {
    /// Grant draft-16 receive credit after the caller has reserved capacity for
    /// this session. The HTTP/3 SETTINGS credit remains zero until this call.
    pub fn grant_receive_credit(
        &self,
        uni: u64,
        bidi: u64,
        data: u64,
    ) -> Result<(), web_transport_proto::FlowError> {
        if let Some(flow) = &self.flow {
            flow.grant_initial(uni, bidi, data)?;
        }
        Ok(())
    }

    pub(crate) fn new(conn: quinn::Connection, settings: Settings, connect: Connected) -> Self {
        // The session ID is the stream ID of the CONNECT request.
        let session_id = connect.session_id();
        let draft16 = connect.request.draft == web_transport_proto::WebTransportDraft::Draft16;
        let datagram_id = if draft16 {
            VarInt::try_from(session_id.into_inner() / 4)
                .expect("quarter stream ID fits QUIC varint")
        } else {
            session_id
        };

        // Cache the tiny header we write in front of each stream we open.
        let mut header_uni = Vec::new();
        StreamUni::WEBTRANSPORT.encode(&mut header_uni);
        session_id.encode(&mut header_uni);

        let mut header_bi = Vec::new();
        Frame::WEBTRANSPORT.encode(&mut header_bi);
        session_id.encode(&mut header_bi);

        let mut header_datagram = Vec::new();
        datagram_id.encode(&mut header_datagram);

        let error: Arc<OnceLock<SessionError>> = Arc::new(OnceLock::new());
        let draining = Arc::new(watch::channel(false).0);
        let flow = if draft16 {
            Some(
                SessionFlow::new(conn.clone(), settings.peer_credit)
                    .expect("validated draft16 initial credit"),
            )
        } else {
            None
        };

        // Accept logic is stateful, so use an Arc<Mutex> to share it.
        let accept = SessionAccept::new(conn.clone(), session_id, error.clone());

        let connect_send = Arc::new(tokio::sync::Mutex::new(connect.send));
        let mut this = Self {
            conn,
            accept: Some(Arc::new(Mutex::new(accept))),
            session_id: Some(session_id),
            datagram_id: Some(datagram_id),
            draft16,
            flow: flow.clone(),
            credit_writer: None,
            header_uni: header_uni.into(),
            header_bi: header_bi.into(),
            header_datagram: header_datagram.into(),
            settings: Some(Arc::new(settings)),
            connect_send: Some(connect_send.clone()),
            error: error.clone(),
            draining: draining.clone(),
            request: Some(connect.request.clone()),
            response: Some(connect.response.clone()),
            alpn: Default::default(),
            op_accept_uni: Default::default(),
            op_accept_bi: Default::default(),
            op_open_uni: Default::default(),
            op_open_bi: Default::default(),
            op_send_datagram: Default::default(),
            op_recv_datagram: Default::default(),
            op_closed: Default::default(),
            parked_accept_uni: Default::default(),
            parked_accept_bi: Default::default(),
        };

        // Run a background task to read capsules from the CONNECT recv stream.
        let conn2 = this.conn.clone();
        tokio::spawn(Self::run_recv(
            conn2.clone(),
            connect.recv,
            error.clone(),
            flow.clone(),
            draining,
        ));
        if let Some(flow) = flow {
            let writer = tokio::spawn(Self::run_credit_writer(conn2, connect_send, error, flow));
            this.credit_writer = Some(Arc::new(CreditWriterTask(writer)));
        }

        this
    }

    // Read capsules from the CONNECT recv stream until it's closed,
    // then record the close error and tear down the connection.
    async fn run_recv(
        conn: quinn::Connection,
        recv: quinn::RecvStream,
        error: Arc<OnceLock<SessionError>>,
        flow: Option<Arc<SessionFlow>>,
        draining: Arc<watch::Sender<bool>>,
    ) {
        let close_info = Self::read_capsules(recv, flow.as_ref(), &draining).await;
        let code = close_info
            .as_ref()
            .ok()
            .and_then(Option::as_ref)
            .map_or(0, |(c, _)| *c);

        let http3_code: quinn::VarInt = web_transport_proto::error_to_http3(code)
            .try_into()
            .unwrap();

        // Try to record the remote close error. If close() already set
        // the error, it owns the connection teardown, so we bail out.
        match close_info {
            Ok(Some((code, reason))) => {
                let err = WebTransportError::Closed(code, reason.clone());
                let recorded = error.set(err.into()).is_ok();
                if let Some(flow) = &flow {
                    flow.incoming_notify.notify_one();
                }
                if !recorded {
                    return;
                }
                conn.close(http3_code, reason.as_bytes());
            }
            Ok(None) => {
                // A clean CONNECT FIN without a close capsule is the default
                // WebTransport application close, with code zero and no reason.
                let recorded = error
                    .set(WebTransportError::Closed(0, String::new()).into())
                    .is_ok();
                if let Some(flow) = &flow {
                    flow.incoming_notify.notify_one();
                }
                if !recorded {
                    return;
                }
                conn.close(http3_code, b"");
            }
            Err(error_code) => {
                let err = quinn::ConnectionError::LocallyClosed.into();
                let recorded = error.set(err).is_ok();
                if let Some(flow) = &flow {
                    flow.incoming_notify.notify_one();
                }
                if !recorded {
                    return;
                }
                conn.close(
                    quinn::VarInt::try_from(error_code).unwrap(),
                    b"invalid CONNECT capsule",
                );
            }
        };
    }

    // Keep reading capsules from the CONNECT recv stream until it's closed.
    // Returns Some((code, reason)) for a close capsule, None for a clean FIN,
    // and Err for a capsule or transport read failure.
    async fn read_capsules(
        recv: quinn::RecvStream,
        flow: Option<&Arc<SessionFlow>>,
        draining: &watch::Sender<bool>,
    ) -> Result<Option<(u32, String)>, u64> {
        let mut reader = web_transport_proto::Http3CapsuleReader::new(recv);
        loop {
            match reader.read().await {
                Ok(Some(web_transport_proto::Capsule::CloseWebTransportSession {
                    code,
                    reason,
                })) => {
                    return validated_remote_close(&mut reader, code, reason).await;
                }
                Ok(Some(web_transport_proto::Capsule::Grease { .. })) => {}
                Ok(Some(capsule @ web_transport_proto::Capsule::Unknown { .. })) => {
                    if record_drain_capsule(&capsule, draining)? {
                        continue;
                    }
                    if let Some(flow) = flow {
                        match flow.received_capsule(&capsule) {
                            Ok(true) => continue,
                            Ok(false) => {}
                            Err(error) => {
                                tracing::warn!(?error, "invalid WebTransport draft16 flow capsule");
                                return Err(web_transport_proto::WT_FLOW_CONTROL_ERROR);
                            }
                        }
                    }
                    tracing::warn!(?capsule, "unknown capsule");
                }
                Ok(None) => return Ok(None),
                Err(e) => {
                    tracing::warn!(?e, "failed to read capsule");
                    return Err(H3_MESSAGE_ERROR);
                }
            }
        }
    }

    /// Connect using an established QUIC connection if you want to create the connection yourself.
    /// This will only work with a brand new QUIC connection using the HTTP/3 ALPN.
    pub async fn connect(
        conn: quinn::Connection,
        request: impl Into<ConnectRequest>,
    ) -> Result<Session, ClientError> {
        let request = request.into();
        Self::connect_with_draft(
            conn,
            request,
            web_transport_proto::WebTransportDraft::Draft02,
        )
        .await
    }

    /// Connect using the explicitly selected HTTP/3 WebTransport wire dialect.
    pub async fn connect_with_draft(
        conn: quinn::Connection,
        request: impl Into<ConnectRequest>,
        draft: web_transport_proto::WebTransportDraft,
    ) -> Result<Session, ClientError> {
        let request = request.into().with_draft(draft);

        // Perform the H3 handshake by sending/reciving SETTINGS frames.
        let settings = Settings::connect(&conn, draft).await?;

        // Send the HTTP/3 CONNECT request.
        let connect = Connected::open(&conn, request).await?;

        // Return the resulting session with a reference to the control/connect streams.
        // If either stream is closed, then the session will be closed, so we need to keep them around.
        let session = Session::new(conn, settings, connect);

        Ok(session)
    }

    /// Accept a new unidirectional stream. See [`quinn::Connection::accept_uni`].
    pub async fn accept_uni(&self) -> Result<RecvStream, SessionError> {
        if let Some(accept) = &self.accept {
            // `kio::wait` owns the waiter, so dropping this future — a `timeout` that
            // expires, say — also drops its registration in `SessionAccept`.
            let mut recv = kio::wait(|waiter| poll_accept_uni_shared(accept, waiter))
                .await
                .map_err(|e| self.map_error(e))?;
            if let Some(flow) = &self.flow {
                if recv.set_flow(flow.clone(), false).is_err() {
                    flow.fail();
                    return Err(quinn::ConnectionError::LocallyClosed.into());
                }
            }
            Ok(recv)
        } else {
            let recv = self
                .conn
                .accept_uni()
                .await
                .map_err(|e| self.map_error(e))?;
            let mut recv = RecvStream::new(recv, self.error.clone());
            if let Some(flow) = &self.flow {
                if recv.set_flow(flow.clone(), false).is_err() {
                    flow.fail();
                    return Err(quinn::ConnectionError::LocallyClosed.into());
                }
            }
            Ok(recv)
        }
    }

    /// Accept a new bidirectional stream. See [`quinn::Connection::accept_bi`].
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), SessionError> {
        if let Some(accept) = &self.accept {
            let (mut send, mut recv) = kio::wait(|waiter| poll_accept_bi_shared(accept, waiter))
                .await
                .map_err(|e| self.map_error(e))?;
            if self.draft16 {
                send.set_reliable_prefix(0);
                if let Some(flow) = &self.flow {
                    if recv.set_flow(flow.clone(), true).is_err() {
                        flow.fail();
                        return Err(quinn::ConnectionError::LocallyClosed.into());
                    }
                }
            }
            Ok((send, recv))
        } else {
            let (send, recv) = self.conn.accept_bi().await.map_err(|e| self.map_error(e))?;
            let mut send = SendStream::new(send, self.error.clone());
            if self.draft16 {
                send.set_reliable_prefix(0);
            }
            let mut recv = RecvStream::new(recv, self.error.clone());
            if let Some(flow) = &self.flow {
                if recv.set_flow(flow.clone(), true).is_err() {
                    flow.fail();
                    return Err(quinn::ConnectionError::LocallyClosed.into());
                }
            }
            Ok((send, recv))
        }
    }

    /// Open a new unidirectional stream. See [`quinn::Connection::open_uni`].
    pub async fn open_uni(&self) -> Result<SendStream, SessionError> {
        Self::open_uni_owned(
            self.conn.clone(),
            self.header_uni.clone(),
            self.error.clone(),
            self.draft16,
            self.flow.clone(),
        )
        .await
    }

    /// Open a new bidirectional stream. See [`quinn::Connection::open_bi`].
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), SessionError> {
        Self::open_bi_owned(
            self.conn.clone(),
            self.header_bi.clone(),
            self.error.clone(),
            self.draft16,
            self.flow.clone(),
        )
        .await
    }

    /// Asynchronously receives an application datagram from the remote peer.
    ///
    /// This method is used to receive an application datagram sent by the remote
    /// peer over the connection.
    /// It waits for a datagram to become available and returns the received bytes.
    pub async fn read_datagram(&self) -> Result<Bytes, SessionError> {
        Self::read_datagram_owned(self.conn.clone(), self.datagram_id, self.error.clone()).await
    }

    /// Sends an application datagram to the remote peer.
    ///
    /// Datagrams are unreliable and may be dropped or delivered out of order.
    /// The data must be smaller than [`max_datagram_size`](Self::max_datagram_size).
    pub fn send_datagram(&self, data: Bytes) -> Result<(), SessionError> {
        let result = if !self.header_datagram.is_empty() {
            // Unfortunately, we need to allocate/copy each datagram because of the Quinn API.
            // Pls go +1 if you care: https://github.com/quinn-rs/quinn/issues/1724
            let mut buf = BytesMut::with_capacity(self.header_datagram.len() + data.len());

            // Prepend the datagram with the header indicating the session ID.
            buf.extend_from_slice(&self.header_datagram);
            buf.extend_from_slice(&data);

            self.conn.send_datagram(buf.into())
        } else {
            self.conn.send_datagram(data)
        };

        result.map_err(|e| self.map_error(e))?;
        Ok(())
    }

    /// Sends an application datagram, waiting for buffer space if the send buffer is full.
    ///
    /// Unlike [`send_datagram`](Self::send_datagram), this applies backpressure instead of
    /// returning an error when there are too many outstanding datagrams.
    ///
    /// Datagrams are unreliable and may be dropped or delivered out of order.
    /// The data must be smaller than [`max_datagram_size`](Self::max_datagram_size).
    pub async fn send_datagram_wait(&self, data: Bytes) -> Result<(), SessionError> {
        let result = if !self.header_datagram.is_empty() {
            // Unfortunately, we need to allocate/copy each datagram because of the Quinn API.
            // Pls go +1 if you care: https://github.com/quinn-rs/quinn/issues/1724
            let mut buf = BytesMut::with_capacity(self.header_datagram.len() + data.len());

            // Prepend the datagram with the header indicating the session ID.
            buf.extend_from_slice(&self.header_datagram);
            buf.extend_from_slice(&data);

            self.conn.send_datagram_wait(buf.into()).await
        } else {
            self.conn.send_datagram_wait(data).await
        };

        result.map_err(|e| self.map_error(e))?;
        Ok(())
    }

    /// Computes the maximum size of datagrams that may be passed to
    /// [`send_datagram`](Self::send_datagram).
    pub fn max_datagram_size(&self) -> usize {
        let mtu = self
            .conn
            .max_datagram_size()
            .expect("datagram support is required");
        mtu.saturating_sub(self.header_datagram.len())
    }

    /// The number of bytes of available space in the outgoing datagram buffer.
    ///
    /// The session-ID header is subtracted, so this reflects the payload bytes that may be
    /// passed to [`send_datagram`](Self::send_datagram) before it starts dropping datagrams.
    pub fn datagram_send_buffer_space(&self) -> usize {
        self.conn
            .datagram_send_buffer_space()
            .saturating_sub(self.header_datagram.len())
    }

    /// Close the session with an error code and reason.
    ///
    /// When there is a session ID (WebTransport over HTTP/3), a `CloseWebTransportSession`
    /// capsule is written on the CONNECT stream before the QUIC connection is closed.
    /// This allows browser clients to receive the close code and reason via `WebTransport.closed`.
    ///
    /// The capsule write and connection close happen asynchronously in a spawned task.
    /// Callers should `await` [`Session::closed()`] to ensure the capsule has been
    /// delivered. Session operations will fail once the QUIC connection is closed.
    pub fn close(&self, code: u32, reason: &[u8]) {
        // Record the local close error. First writer wins — if the background
        // task already set a remote close error, or close() was already called,
        // this is a no-op.
        let err = SessionError::ConnectionError(quinn::ConnectionError::LocallyClosed);
        let recorded = self.error.set(err).is_ok();
        if let Some(flow) = &self.flow {
            flow.incoming_notify.notify_one();
        }
        if !recorded {
            return;
        }

        if self.session_id.is_some() {
            let send = self
                .connect_send
                .as_ref()
                .expect("HTTP/3 session has a CONNECT stream")
                .clone();
            let reason = String::from_utf8_lossy(reason).into_owned();
            let conn = self.conn.clone();
            let capsule = web_transport_proto::Capsule::CloseWebTransportSession { code, reason };
            let timeout = (self.rtt() * 3).max(Duration::from_millis(100));
            tokio::spawn(async move {
                Self::close_with_capsule(conn, send, capsule, code, timeout).await;
            });
        } else {
            // Raw QUIC mode: no capsule needed.
            self.conn.close(code.into(), reason);
        }
    }

    /// Write the CloseWebTransportSession capsule, finish the stream, wait for
    /// the peer to close the connection (or timeout), then force-close.
    async fn close_with_capsule(
        conn: quinn::Connection,
        send: Arc<tokio::sync::Mutex<quinn::SendStream>>,
        capsule: web_transport_proto::Capsule,
        code: u32,
        timeout: std::time::Duration,
    ) {
        let http3_code: quinn::VarInt = web_transport_proto::error_to_http3(code)
            .try_into()
            .unwrap();

        // Encode the capsule, then wrap it in an HTTP/3 DATA frame.
        // In HTTP/3, capsule data is carried inside DATA frames on the CONNECT
        // stream (RFC 9297 Section 3.2).
        let mut capsule_bytes = Vec::new();
        capsule.encode(&mut capsule_bytes);

        let mut frame = Vec::new();
        Frame::DATA.encode(&mut frame);
        let Ok(len) = VarInt::try_from(capsule_bytes.len()) else {
            tracing::warn!("capsule too large to encode as DATA frame");
            conn.close(http3_code, b"");
            return;
        };
        len.encode(&mut frame);
        frame.extend_from_slice(&capsule_bytes);

        // Bound the entire graceful-close sequence (capsule write, FIN,
        // waiting for the peer) with a single timeout.  Without this, an
        // unresponsive peer can cause write_all to block indefinitely when
        // the send buffer fills up and no idle timeout is configured.
        let graceful = async {
            let mut send = send.lock().await;
            // Write the DATA frame to the CONNECT send stream.
            if let Err(e) = send.write_all(&frame).await {
                tracing::warn!(?e, "failed to write CloseWebTransportSession capsule");
                conn.close(http3_code, b"");
                return;
            }

            // FIN the send stream so the peer knows no more capsules are coming.
            if let Err(e) = send.finish() {
                tracing::warn!(?e, "failed to finish CONNECT send stream");
                conn.close(http3_code, b"");
                return;
            }

            // Wait for the peer to close the CONNECT stream after receiving the capsule.
            conn.closed().await;
        };

        if tokio::time::timeout(timeout, graceful).await.is_err() {
            tracing::debug!("timeout waiting for peer to close; force-closing connection");
            conn.close(http3_code, b"");
        }
    }

    async fn run_credit_writer(
        conn: quinn::Connection,
        send: Arc<tokio::sync::Mutex<quinn::SendStream>>,
        error: Arc<OnceLock<SessionError>>,
        flow: Arc<SessionFlow>,
    ) {
        loop {
            if error.get().is_some() {
                return;
            }
            tokio::select! {
                biased;
                _ = conn.closed() => return,
                _ = flow.incoming_notify.notified() => {},
            }
            if error.get().is_some() {
                return;
            }
            while let Some((kind, value, capsule)) = flow.next_capsule() {
                if error.get().is_some() || conn.close_reason().is_some() {
                    return;
                }
                let mut encoded = Vec::new();
                capsule.encode(&mut encoded);
                let mut frame = Vec::new();
                Frame::DATA.encode(&mut frame);
                VarInt::try_from(encoded.len())
                    .expect("small credit capsule")
                    .encode(&mut frame);
                frame.extend_from_slice(&encoded);
                let result = send.lock().await.write_all(&frame).await;
                if result.is_err() {
                    conn.close(
                        quinn::VarInt::try_from(web_transport_proto::WT_FLOW_CONTROL_ERROR)
                            .unwrap(),
                        b"failed to send WebTransport credit",
                    );
                    return;
                }
                flow.mark_sent(kind, value);
            }
        }
    }

    /// Wait until the session is closed, returning the error. See [`quinn::Connection::closed`].
    ///
    /// If the peer sent a `CloseWebTransportSession` capsule, the returned error will be
    /// [`WebTransportError::Closed`] with the code and reason from the capsule.
    ///
    /// Unlike [`quinn::Connection::closed`], this does **not** return early when
    /// [`close()`](Self::close) has been called. It waits for the underlying QUIC
    /// connection to shut down, ensuring the `CloseWebTransportSession` capsule has
    /// been delivered. Use [`close_reason()`](Self::close_reason) for a non-blocking check.
    pub async fn closed(&self) -> SessionError {
        self.map_error(self.conn.closed().await)
    }

    /// Return why the session was closed, or None if it's not closed. See [`quinn::Connection::close_reason`].
    pub fn close_reason(&self) -> Option<SessionError> {
        self.conn.close_reason().map(|e| self.map_error(e))
    }

    /// Replace connection-level errors with the stored session error if available.
    fn map_error(&self, e: impl Into<SessionError>) -> SessionError {
        map_error_with(&self.error, e)
    }

    // The owned-argument form, for futures that outlive the borrow that created them.
    fn map_error_owned(error: &OnceLock<SessionError>, e: impl Into<SessionError>) -> SessionError {
        map_error_with(error, e)
    }
}

/// Replace connection-level errors with the stored session error if available.
fn map_error_with(stored: &OnceLock<SessionError>, e: impl Into<SessionError>) -> SessionError {
    {
        let e = e.into();
        if let Some(err) = stored.get() {
            if matches!(
                &e,
                SessionError::ConnectionError(_)
                    | SessionError::WebTransportError(WebTransportError::Closed(..))
                    | SessionError::SendDatagramError(quinn::SendDatagramError::ConnectionLost(_))
            ) {
                return err.clone();
            }
        }
        e
    }
}

impl Session {
    async fn write_full(send: &mut quinn::SendStream, buf: &[u8]) -> Result<(), SessionError> {
        match send.write_all(buf).await {
            Ok(_) => Ok(()),
            Err(quinn::WriteError::ConnectionLost(err)) => Err(err.into()),
            Err(err) => Err(WebTransportError::WriteError(err).into()),
        }
    }

    /// Create a new session from a raw QUIC connection.
    ///
    /// This is used to pretend like a QUIC connection is a WebTransport session,
    /// making it easier to support WebTransport and raw QUIC simultaneously.
    ///
    /// There is no HTTP/3 exchange, so [`Self::request`] and [`Self::response`] both
    /// return `None`. [`Self::protocol`] reports the ALPN negotiated by the QUIC
    /// handshake, read from `conn` on demand — a connection that is still handshaking
    /// (from `into_0rtt`, say) is fine, it just has no ALPN to report until it is done.
    pub fn raw(conn: quinn::Connection) -> Self {
        Self {
            conn,
            session_id: None,
            datagram_id: None,
            draft16: false,
            flow: None,
            credit_writer: None,
            header_uni: Default::default(),
            header_bi: Default::default(),
            header_datagram: Default::default(),
            accept: None,
            op_accept_uni: Default::default(),
            op_accept_bi: Default::default(),
            op_open_uni: Default::default(),
            op_open_bi: Default::default(),
            op_send_datagram: Default::default(),
            op_recv_datagram: Default::default(),
            op_closed: Default::default(),
            parked_accept_uni: Default::default(),
            parked_accept_bi: Default::default(),
            settings: None,
            connect_send: None,
            error: Arc::new(OnceLock::new()),
            draining: Arc::new(watch::channel(false).0),
            request: None,
            response: None,
            alpn: Default::default(),
        }
    }

    /// Returns the [`ConnectRequest`] if this session was established over HTTP/3,
    /// or `None` for a raw QUIC session.
    pub fn request(&self) -> Option<&ConnectRequest> {
        self.request.as_ref()
    }

    /// Returns the [`ConnectResponse`] if this session was established over HTTP/3,
    /// or `None` for a raw QUIC session.
    pub fn response(&self) -> Option<&ConnectResponse> {
        self.response.as_ref()
    }

    /// Wait for the peer's WT_DRAIN_SESSION capsule. A session close by itself
    /// does not complete this future.
    pub async fn draining(&self) {
        let mut draining = self.draining.subscribe();
        while !*draining.borrow_and_update() {
            if draining.changed().await.is_err() {
                return;
            }
        }
    }

    /// Returns the application protocol negotiated for this session.
    ///
    /// For an HTTP/3 session this is the subprotocol the server selected via
    /// `WT-Available-Protocols`; for a raw QUIC session it is the negotiated ALPN.
    /// `None` if neither was negotiated, the ALPN is not valid UTF-8, or the raw
    /// connection is still handshaking.
    pub fn protocol(&self) -> Option<&str> {
        if let Some(response) = &self.response {
            return response.protocol.as_deref();
        }

        if let Some(alpn) = self.alpn.get() {
            return Some(alpn);
        }

        // Latch only a successful read, so a call made while the connection is still
        // handshaking cannot pin `None` for the life of the session.
        let alpn = negotiated_alpn(&self.conn)?;
        Some(self.alpn.get_or_init(|| alpn))
    }

    /// Return connection-level statistics.
    pub fn stats(&self) -> SessionStats {
        SessionStats {
            stats: self.conn.stats(),
            rtt: self.conn.rtt(),
        }
    }
}

impl Deref for Session {
    type Target = quinn::Connection;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.conn.fmt(f)
    }
}

impl PartialEq for Session {
    fn eq(&self, other: &Self) -> bool {
        self.conn.stable_id() == other.conn.stable_id()
    }
}

impl Eq for Session {}

// Poll the shared accept state, then wake the *other* accepters once the lock is
// released.
//
// `SessionAccept` does not wake them itself: a waker is free to resume its task
// inline, and the first thing a resumed accepter does is take this same lock. An
// arrival or a failure is exactly what the others are parked waiting to retry
// after, so `Ready` is the signal.
fn poll_accept_uni_shared(
    accept: &Mutex<SessionAccept>,
    waiter: &Waiter,
) -> Poll<Result<RecvStream, SessionError>> {
    let (result, waiters, hold) = {
        let mut accept = accept.lock().unwrap();
        let waiters = accept.uni_waiters.clone();

        // The poll below drives the shared accept futures with this list's waker, and one
        // of them may wake it inline. `Fan` holds those back while this guard is alive.
        let hold = waiters.hold();
        let result = accept.poll_accept_uni(waiter);

        (result, waiters, hold)
    };

    // Dropped after the accept lock, never before: that is where a held-back wake is
    // delivered, and delivering it under the lock is the hazard the hold exists for.
    drop(hold);

    if result.is_ready() {
        waiters.wake();
    }

    result
}

fn poll_accept_bi_shared(
    accept: &Mutex<SessionAccept>,
    waiter: &Waiter,
) -> Poll<Result<(SendStream, RecvStream), SessionError>> {
    let (result, waiters, hold) = {
        let mut accept = accept.lock().unwrap();
        let waiters = accept.bi_waiters.clone();

        // The poll below drives the shared accept futures with this list's waker, and one
        // of them may wake it inline. `Fan` holds those back while this guard is alive.
        let hold = waiters.hold();
        let result = accept.poll_accept_bi(waiter);

        (result, waiters, hold)
    };

    // Dropped after the accept lock, never before: that is where a held-back wake is
    // delivered, and delivering it under the lock is the hazard the hold exists for.
    drop(hold);

    if result.is_ready() {
        waiters.wake();
    }

    result
}

// Type aliases just so clippy doesn't complain about the complexity.
type AcceptUni = dyn Stream<Item = Result<quinn::RecvStream, quinn::ConnectionError>> + Send;
type AcceptBi = dyn Stream<Item = Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError>>
    + Send;
type PendingUni =
    dyn Future<Output = Result<(StreamUni, quinn::RecvStream, u64), SessionError>> + Send;
type PendingBi = dyn Future<Output = Result<Option<(quinn::SendStream, quinn::RecvStream, u64)>, SessionError>>
    + Send;

// Logic just for accepting streams, which is annoying because of the stream header.
pub struct SessionAccept {
    session_id: VarInt,

    // Shared session error for propagation to accepted streams.
    error: Arc<OnceLock<SessionError>>,

    // We also need to keep a reference to the qpack streams if the endpoint (incorrectly) creates them.
    // Again, this is just so they don't get closed until we drop the session.
    qpack_encoder: Option<quinn::RecvStream>,
    qpack_decoder: Option<quinn::RecvStream>,

    accept_uni: Pin<Box<AcceptUni>>,
    accept_bi: Pin<Box<AcceptBi>>,

    // Keep track of work being done to read/write the WebTransport stream header.
    pending_uni: FuturesUnordered<Pin<Box<PendingUni>>>,
    pending_bi: FuturesUnordered<Pin<Box<PendingBi>>>,

    // Waiters from concurrent callers of accept_bi / accept_uni.
    // Every clone of the session polls this one struct, so an arrival has to be fanned
    // out: each caller registers here and all of them are woken when a stream lands —
    // by the caller that saw it, once it has released the lock on this struct.
    bi_waiters: Fan,
    uni_waiters: Fan,

    // `Waker::from(waiters.clone())`, cached so Quinn's accept futures are polled with
    // the same waker every time. That waker outlives every caller, so an accepter that
    // drops its future cannot take the wakeup path with it, and Quinn holds one
    // registration rather than one per caller.
    bi_waker: Waker,
    uni_waker: Waker,
}

impl SessionAccept {
    pub(crate) fn new(
        conn: quinn::Connection,
        session_id: VarInt,
        error: Arc<OnceLock<SessionError>>,
    ) -> Self {
        // Create a stream that just outputs new streams, so it's easy to call from poll.
        let accept_uni = Box::pin(futures::stream::unfold(conn.clone(), |conn| async {
            Some((conn.accept_uni().await, conn))
        }));

        let accept_bi = Box::pin(futures::stream::unfold(conn, |conn| async {
            Some((conn.accept_bi().await, conn))
        }));

        let bi_waiters = Fan::new();
        let uni_waiters = Fan::new();
        let bi_waker = bi_waiters.waker();
        let uni_waker = uni_waiters.waker();

        Self {
            session_id,
            error,

            qpack_decoder: None,
            qpack_encoder: None,

            accept_uni,
            accept_bi,

            pending_uni: FuturesUnordered::new(),
            pending_bi: FuturesUnordered::new(),

            bi_waiters,
            uni_waiters,
            bi_waker,
            uni_waker,
        }
    }

    /// Poll for the next unidirectional WebTransport stream.
    ///
    /// `waiter` is parked until a stream arrives, the accept fails, or the caller drops
    /// it. The registration is weak and owned by the caller: keep the [`Waiter`] alive
    /// until it is woken, or it will be reclaimed and nothing will wake you. Drive this
    /// with [`kio::wait`], which holds the waiter inside the future it builds.
    ///
    /// A `Ready` here means every *other* parked accepter should be woken so it can
    /// retry. This does not do that itself — see `poll_accept_uni_shared`, which wakes
    /// them once the lock on this struct is released.
    //
    // Poll-based because we accept and decode streams in parallel. In async land this
    // would be a `tokio::JoinSet`, but that needs a runtime; `FuturesUnordered` is
    // runtime-agnostic.
    pub fn poll_accept_uni(&mut self, waiter: &Waiter) -> Poll<Result<RecvStream, SessionError>> {
        // Register before polling, not on the way out: the shared waker can fire from
        // Quinn's driver at any point below, and a wake that lands before the caller is
        // on the list would be lost.
        self.uni_waiters.register(waiter);

        let waker = self.uni_waker.clone();
        let cx = &mut Context::from_waker(&waker);

        loop {
            // Accept any new streams.
            if let Poll::Ready(Some(res)) = self.accept_uni.poll_next_unpin(cx) {
                // Start decoding the header and add the future to the list of pending streams.
                let recv = match res {
                    Ok(recv) => recv,
                    Err(e) => {
                        return Poll::Ready(Err(e.into()));
                    }
                };
                let pending = Self::decode_uni(recv, self.session_id);
                self.pending_uni.push(Box::pin(pending));

                continue;
            }

            // Poll the list of pending streams.
            let (typ, recv, header_size) = match self.pending_uni.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(res))) => res,
                Poll::Ready(Some(Err(err))) => {
                    // Ignore the error, the stream was probably reset early.
                    tracing::warn!(?err, "failed to decode unidirectional stream");
                    continue;
                }
                Poll::Ready(None) | Poll::Pending => return Poll::Pending,
            };

            // Decide if we keep looping based on the type.
            match typ {
                StreamUni::WEBTRANSPORT => {
                    let recv = RecvStream::new(recv, self.error.clone())
                        .with_association_header_size(header_size);
                    return Poll::Ready(Ok(recv));
                }
                StreamUni::QPACK_DECODER => {
                    self.qpack_decoder = Some(recv);
                }
                StreamUni::QPACK_ENCODER => {
                    self.qpack_encoder = Some(recv);
                }
                _ => {
                    // ignore unknown streams
                    tracing::debug!(?typ, "ignoring unknown unidirectional stream");
                }
            }
        }
    }

    // Reads the stream header, returning the stream type.
    async fn decode_uni(
        mut recv: quinn::RecvStream,
        expected_session: VarInt,
    ) -> Result<(StreamUni, quinn::RecvStream, u64), SessionError> {
        // Read the VarInt at the start of the stream.
        let (typ, type_width) = VarInt::read_with_width(&mut recv)
            .await
            .map_err(|_| WebTransportError::UnknownSession)?;
        let typ = StreamUni(typ);
        let mut header_size = type_width as u64;

        if typ == StreamUni::WEBTRANSPORT {
            // Read the session_id and validate it
            let (session_id, id_width) = VarInt::read_with_width(&mut recv)
                .await
                .map_err(|_| WebTransportError::UnknownSession)?;
            if session_id != expected_session {
                return Err(WebTransportError::UnknownSession.into());
            }
            header_size += id_width as u64;
        }

        // We need to keep a reference to the qpack streams if the endpoint (incorrectly) creates them, so return everything.
        Ok((typ, recv, header_size))
    }

    /// Poll for the next bidirectional WebTransport stream.
    ///
    /// The same contract as [`poll_accept_uni`](Self::poll_accept_uni): the `waiter`
    /// registration is weak and owned by the caller, and a `Ready` is what the other
    /// parked accepters need to be woken for.
    pub fn poll_accept_bi(
        &mut self,
        waiter: &Waiter,
    ) -> Poll<Result<(SendStream, RecvStream), SessionError>> {
        // Register before polling; see `poll_accept_uni`.
        self.bi_waiters.register(waiter);

        let waker = self.bi_waker.clone();
        let cx = &mut Context::from_waker(&waker);

        loop {
            // Accept any new streams.
            if let Poll::Ready(Some(res)) = self.accept_bi.poll_next_unpin(cx) {
                // Start decoding the header and add the future to the list of pending streams.
                let (send, recv) = match res {
                    Ok(pair) => pair,
                    Err(e) => {
                        return Poll::Ready(Err(e.into()));
                    }
                };
                let pending = Self::decode_bi(send, recv, self.session_id);
                self.pending_bi.push(Box::pin(pending));

                continue;
            }

            // Poll the list of pending streams.
            let res = match self.pending_bi.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(res))) => res,
                Poll::Ready(Some(Err(err))) => {
                    // Ignore the error, the stream was probably reset early.
                    tracing::warn!(?err, "failed to decode bidirectional stream");
                    continue;
                }
                Poll::Ready(None) | Poll::Pending => return Poll::Pending,
            };

            if let Some((send, recv, header_size)) = res {
                // Wrap the streams in our own types for correct error codes.
                let send = SendStream::new(send, self.error.clone());
                let recv = RecvStream::new(recv, self.error.clone())
                    .with_association_header_size(header_size);
                return Poll::Ready(Ok((send, recv)));
            }

            // Keep looping if it's a stream we want to ignore.
        }
    }

    // Reads the stream header, returning Some if it's a WebTransport stream.
    async fn decode_bi(
        send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        expected_session: VarInt,
    ) -> Result<Option<(quinn::SendStream, quinn::RecvStream, u64)>, SessionError> {
        let (typ, type_width) = VarInt::read_with_width(&mut recv)
            .await
            .map_err(|_| WebTransportError::UnknownSession)?;
        if Frame(typ) != Frame::WEBTRANSPORT {
            tracing::debug!(?typ, "ignoring unknown bidirectional stream");
            return Ok(None);
        }

        // Read the session ID and validate it.
        let (session_id, id_width) = VarInt::read_with_width(&mut recv)
            .await
            .map_err(|_| WebTransportError::UnknownSession)?;
        if session_id != expected_session {
            return Err(WebTransportError::UnknownSession.into());
        }

        Ok(Some((send, recv, (type_width + id_width) as u64)))
    }
}

pub struct SessionStats {
    stats: quinn::ConnectionStats,
    rtt: std::time::Duration,
}

impl web_transport_trait::Stats for SessionStats {
    fn bytes_sent(&self) -> Option<u64> {
        Some(self.stats.udp_tx.bytes)
    }

    fn bytes_received(&self) -> Option<u64> {
        Some(self.stats.udp_rx.bytes)
    }

    fn bytes_lost(&self) -> Option<u64> {
        Some(self.stats.path.lost_bytes)
    }

    fn packets_sent(&self) -> Option<u64> {
        Some(self.stats.udp_tx.datagrams)
    }

    fn packets_received(&self) -> Option<u64> {
        Some(self.stats.udp_rx.datagrams)
    }

    fn packets_lost(&self) -> Option<u64> {
        Some(self.stats.path.lost_packets)
    }

    fn rtt(&self) -> Option<std::time::Duration> {
        Some(self.rtt)
    }

    fn estimated_send_rate(&self) -> Option<u64> {
        let rtt_secs = self.rtt.as_secs_f64();
        if self.stats.path.cwnd > 0 && rtt_secs > 0.0 {
            Some((self.stats.path.cwnd as f64 * 8.0 / rtt_secs) as u64)
        } else {
            None
        }
    }
}

impl web_transport_trait::Session for Session {
    type SendStream = SendStream;
    type RecvStream = RecvStream;
    type Error = SessionError;

    async fn accept_uni(&self) -> Result<Self::RecvStream, Self::Error> {
        Self::accept_uni(self).await
    }

    async fn accept_bi(&self) -> Result<(Self::SendStream, Self::RecvStream), Self::Error> {
        Self::accept_bi(self).await
    }

    async fn open_bi(&self) -> Result<(Self::SendStream, Self::RecvStream), Self::Error> {
        Self::open_bi(self).await
    }

    async fn open_uni(&self) -> Result<Self::SendStream, Self::Error> {
        Self::open_uni(self).await
    }

    fn close(&self, code: u32, reason: &str) {
        Self::close(self, code, reason.as_bytes());
    }

    async fn closed(&self) -> Self::Error {
        Self::closed(self).await
    }

    fn send_datagram(&self, data: Bytes) -> Result<(), Self::Error> {
        Self::send_datagram(self, data)
    }

    async fn recv_datagram(&self) -> Result<Bytes, Self::Error> {
        Self::read_datagram(self).await
    }

    fn max_datagram_size(&self) -> usize {
        Self::max_datagram_size(self)
    }

    fn protocol(&self) -> Option<&str> {
        Self::protocol(self)
    }

    #[allow(refining_impl_trait)]
    fn stats(&self) -> SessionStats {
        Self::stats(self)
    }
}

#[cfg(test)]
mod remote_close_tests {
    use super::{record_drain_capsule, validated_remote_close, H3_MESSAGE_ERROR, WT_DRAIN_SESSION};
    use crate::proto::{Capsule, Frame, Http3CapsuleReader, VarInt};

    #[tokio::test]
    async fn drain_capsule_latches_without_closing_the_session() {
        let (draining, mut observed) = tokio::sync::watch::channel(false);
        let capsule = Capsule::Unknown {
            typ: VarInt::from_u64(WT_DRAIN_SESSION).expect("valid drain type"),
            payload: bytes::Bytes::new(),
        };
        assert_eq!(record_drain_capsule(&capsule, &draining), Ok(true));
        observed.changed().await.expect("drain signal");
        assert!(*observed.borrow());
        assert_eq!(record_drain_capsule(&capsule, &draining), Ok(true));

        let malformed = Capsule::Unknown {
            typ: VarInt::from_u64(WT_DRAIN_SESSION).expect("valid drain type"),
            payload: bytes::Bytes::from_static(b"x"),
        };
        assert_eq!(
            record_drain_capsule(&malformed, &draining),
            Err(H3_MESSAGE_ERROR)
        );
    }

    #[tokio::test]
    async fn close_capsule_requires_final_data_and_bounded_reason() {
        let mut clean = Http3CapsuleReader::new(tokio::io::empty());
        assert_eq!(
            validated_remote_close(&mut clean, 32, "abc".into()).await,
            Ok(Some((32, "abc".into())))
        );

        let mut oversized = Http3CapsuleReader::new(tokio::io::empty());
        assert_eq!(
            validated_remote_close(&mut oversized, 32, "x".repeat(1025)).await,
            Err(H3_MESSAGE_ERROR)
        );

        let mut capsule = Vec::new();
        Capsule::Grease { num: 0 }.encode(&mut capsule);
        let mut trailing_data = Vec::new();
        Frame::DATA.encode(&mut trailing_data);
        VarInt::try_from(capsule.len())
            .expect("small capsule")
            .encode(&mut trailing_data);
        trailing_data.extend_from_slice(&capsule);
        let mut trailing = Http3CapsuleReader::new(trailing_data.as_slice());
        assert_eq!(
            validated_remote_close(&mut trailing, 32, "abc".into()).await,
            Err(H3_MESSAGE_ERROR)
        );
    }
}

#[cfg(all(test, any(feature = "aws-lc-rs", feature = "ring")))]
mod credit_writer_lifetime_tests;

impl Session {
    // Open plus stream-header write, over owned arguments so the result can live in
    // a retained future. Mirrors `open_uni`/`open_bi`, including the priority dance.
    async fn open_uni_owned(
        conn: quinn::Connection,
        header: Bytes,
        error: Arc<OnceLock<SessionError>>,
        draft16: bool,
        flow: Option<Arc<SessionFlow>>,
    ) -> Result<SendStream, SessionError> {
        if let Some(flow) = &flow {
            if flow.open(false).await.is_err() {
                flow.fail();
                return Err(quinn::ConnectionError::LocallyClosed.into());
            }
        }
        let mut send = conn
            .open_uni()
            .await
            .map_err(|e| Self::map_error_owned(&error, e))?;

        // Max priority for the header so the application cannot queue lower-priority
        // data in front of it, then back to the default.
        send.set_priority(i32::MAX).ok();
        Self::write_full(&mut send, &header)
            .await
            .map_err(|e| Self::map_error_owned(&error, e))?;
        send.set_priority(0).ok();

        let mut send = SendStream::new(send, error);
        if draft16 {
            send.set_reliable_prefix(header.len() as u64);
            if let Some(flow) = flow {
                send.set_flow(flow);
            }
        }
        Ok(send)
    }

    async fn open_bi_owned(
        conn: quinn::Connection,
        header: Bytes,
        error: Arc<OnceLock<SessionError>>,
        draft16: bool,
        flow: Option<Arc<SessionFlow>>,
    ) -> Result<(SendStream, RecvStream), SessionError> {
        if let Some(flow) = &flow {
            if flow.open(true).await.is_err() {
                flow.fail();
                return Err(quinn::ConnectionError::LocallyClosed.into());
            }
        }
        let (mut send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| Self::map_error_owned(&error, e))?;

        send.set_priority(i32::MAX).ok();
        Self::write_full(&mut send, &header)
            .await
            .map_err(|e| Self::map_error_owned(&error, e))?;
        send.set_priority(0).ok();

        let mut send = SendStream::new(send, error.clone());
        if draft16 {
            send.set_reliable_prefix(header.len() as u64);
            if let Some(flow) = flow {
                send.set_flow(flow);
            }
        }
        Ok((send, RecvStream::new(recv, error)))
    }

    fn send_datagram_framed(
        &mut self,
        cx: &mut Context<'_>,
        payload: &[u8],
    ) -> Poll<Result<(), SessionError>> {
        // Resume an in-flight send before touching `payload`. Framing first would
        // allocate on every poll and then discard it, and would quietly ignore a
        // caller that retried with a different datagram — the retained future
        // already owns the one it started with.
        if let Some(result) = self.op_send_datagram.poll_pending(cx) {
            return result;
        }

        let conn = self.conn.clone();
        // Quinn's datagram API needs an owned `Bytes` either way, and the HTTP/3 path
        // has to copy regardless to prepend the session ID.
        let payload = Self::frame_datagram(&self.header_datagram, payload);
        let error = self.error.clone();

        // `send_datagram_wait` is what makes this pollable rather than a drop: it
        // parks until the transport has room. Retained, because its `Notify`
        // registration lives in the future.
        self.op_send_datagram.poll(cx, move || async move {
            conn.send_datagram_wait(payload)
                .await
                .map_err(|e| Session::map_error_owned(&error, e))
        })
    }

    // Prepend the session ID, as `send_datagram`/`send_datagram_wait` do.
    //
    // Unfortunately, we need to allocate/copy each datagram because of the Quinn API.
    // Pls go +1 if you care: https://github.com/quinn-rs/quinn/issues/1724
    fn frame_datagram(header: &Bytes, data: &[u8]) -> Bytes {
        let mut buf = BytesMut::with_capacity(header.len() + data.len());
        buf.extend_from_slice(header);
        buf.extend_from_slice(data);
        buf.into()
    }

    async fn read_datagram_owned(
        conn: quinn::Connection,
        session_id: Option<VarInt>,
        error: Arc<OnceLock<SessionError>>,
    ) -> Result<Bytes, SessionError> {
        let mut datagram = conn
            .read_datagram()
            .await
            .map_err(|e| Self::map_error_owned(&error, e))?;

        let mut cursor = Cursor::new(&datagram);

        if let Some(session_id) = session_id {
            // We have to check and strip the session ID from the datagram.
            let actual_id =
                VarInt::decode(&mut cursor).map_err(|_| WebTransportError::UnknownSession)?;
            if actual_id != session_id {
                return Err(WebTransportError::UnknownSession.into());
            }
        }

        // Return the datagram without the session ID.
        Ok(datagram.split_off(cursor.position() as usize))
    }
}

impl web_transport_trait::poll::Session for Session {
    type SendStream = SendStream;
    type RecvStream = RecvStream;
    type Error = SessionError;

    // Accept forwards natively: `SessionAccept` already drives a persistent stream and
    // keeps a waiter list, so the only thing to retain is our registration in it.
    fn poll_accept_uni(&mut self, cx: &mut Context<'_>) -> Poll<Result<RecvStream, SessionError>> {
        if let Some(accept) = self.accept.clone() {
            let result = self
                .parked_accept_uni
                .poll(cx, |waiter| poll_accept_uni_shared(&accept, waiter));
            return result.map(|result| {
                let mut recv = result?;
                if let Some(flow) = &self.flow {
                    recv.set_flow(flow.clone(), false).map_err(|_| {
                        flow.fail();
                        SessionError::ConnectionError(quinn::ConnectionError::LocallyClosed)
                    })?;
                }
                Ok(recv)
            });
        }

        let conn = self.conn.clone();
        let error = self.error.clone();

        self.op_accept_uni.poll(cx, move || async move {
            let recv = conn
                .accept_uni()
                .await
                .map_err(|e| Session::map_error_owned(&error, e))?;
            Ok(RecvStream::new(recv, error))
        })
    }

    fn poll_accept_bi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(SendStream, RecvStream), SessionError>> {
        if let Some(accept) = self.accept.clone() {
            let result = self
                .parked_accept_bi
                .poll(cx, |waiter| poll_accept_bi_shared(&accept, waiter));
            return result.map(|result| {
                let (mut send, mut recv) = result?;
                if let Some(flow) = &self.flow {
                    send.set_reliable_prefix(0);
                    recv.set_flow(flow.clone(), true).map_err(|_| {
                        flow.fail();
                        SessionError::ConnectionError(quinn::ConnectionError::LocallyClosed)
                    })?;
                }
                Ok((send, recv))
            });
        }

        let conn = self.conn.clone();
        let error = self.error.clone();

        self.op_accept_bi.poll(cx, move || async move {
            let (send, recv) = conn
                .accept_bi()
                .await
                .map_err(|e| Session::map_error_owned(&error, e))?;
            Ok((
                SendStream::new(send, error.clone()),
                RecvStream::new(recv, error),
            ))
        })
    }

    fn poll_open_uni(&mut self, cx: &mut Context<'_>) -> Poll<Result<SendStream, SessionError>> {
        let conn = self.conn.clone();
        let header = self.header_uni.clone();
        let error = self.error.clone();
        let draft16 = self.draft16;
        let flow = self.flow.clone();

        self.op_open_uni.poll(cx, move || async move {
            Session::open_uni_owned(conn, header, error, draft16, flow).await
        })
    }

    fn poll_open_bi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(SendStream, RecvStream), SessionError>> {
        let conn = self.conn.clone();
        let header = self.header_bi.clone();
        let error = self.error.clone();
        let draft16 = self.draft16;
        let flow = self.flow.clone();

        self.op_open_bi.poll(cx, move || async move {
            Session::open_bi_owned(conn, header, error, draft16, flow).await
        })
    }

    fn poll_send_datagram(
        &mut self,
        cx: &mut Context<'_>,
        payload: &[u8],
    ) -> Poll<Result<(), SessionError>> {
        self.send_datagram_framed(cx, payload)
    }

    fn poll_recv_datagram(&mut self, cx: &mut Context<'_>) -> Poll<Result<Bytes, SessionError>> {
        let conn = self.conn.clone();
        let session_id = self.datagram_id;
        let error = self.error.clone();

        self.op_recv_datagram.poll(cx, move || {
            Session::read_datagram_owned(conn, session_id, error)
        })
    }

    fn max_datagram_size(&self) -> usize {
        Self::max_datagram_size(self)
    }

    fn protocol(&self) -> Option<&str> {
        Self::protocol(self)
    }

    fn close(&mut self, code: u32, reason: &str) {
        Self::close(self, code, reason.as_bytes());
    }

    fn poll_closed(&mut self, cx: &mut Context<'_>) -> Poll<SessionError> {
        let conn = self.conn.clone();
        let error = self.error.clone();

        self.op_closed.poll(cx, move || async move {
            Session::map_error_owned(&error, conn.closed().await)
        })
    }

    #[allow(refining_impl_trait)]
    fn stats(&self) -> SessionStats {
        Self::stats(self)
    }
}

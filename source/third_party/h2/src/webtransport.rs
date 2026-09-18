//! WebTransport over HTTP/2 settings.
//!
//! This module contains the HTTP/2 SETTINGS values defined by
//! `draft-ietf-webtrans-http2`.  It intentionally only models the wire
//! settings.  WebTransport capsules and their session state remain the
//! responsibility of the user of an HTTP/2 stream.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

/// The WebTransport-specific portion of an HTTP/2 SETTINGS frame.
///
/// Each optional initial limit is omitted from the SETTINGS frame when it is
/// `None`; HTTP/2 then applies the WebTransport default of zero.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Settings {
  /// Whether this endpoint supports WebTransport over HTTP/2.
  pub enabled: bool,
  /// Initial `WT_MAX_DATA` credit.
  pub initial_max_data: Option<u32>,
  /// Initial credit for unidirectional stream data.
  pub initial_max_stream_data_uni: Option<u32>,
  /// Initial credit for bidirectional streams opened by the setting sender.
  pub initial_max_stream_data_bidi_local: Option<u32>,
  /// Initial credit for bidirectional streams opened by the setting receiver.
  pub initial_max_stream_data_bidi_remote: Option<u32>,
  /// Initial cumulative limit for unidirectional streams.
  pub initial_max_streams_uni: Option<u32>,
  /// Initial cumulative limit for bidirectional streams.
  pub initial_max_streams_bidi: Option<u32>,
}

impl Settings {
  /// Creates disabled WebTransport settings with no initial credit.
  pub const fn disabled() -> Self {
    Self {
      enabled: false,
      initial_max_data: None,
      initial_max_stream_data_uni: None,
      initial_max_stream_data_bidi_local: None,
      initial_max_stream_data_bidi_remote: None,
      initial_max_streams_uni: None,
      initial_max_streams_bidi: None,
    }
  }

  /// Creates enabled WebTransport settings with no initial credit.
  pub const fn enabled() -> Self {
    Self {
      enabled: true,
      ..Self::disabled()
    }
  }
}

/// An acknowledged WebTransport settings snapshot.
///
/// The snapshot is immutable so callers can retain the values that governed a
/// particular CONNECT request or response while later SETTINGS updates are in
/// flight.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SettingsSnapshot(Settings);

impl SettingsSnapshot {
  /// Returns the acknowledged WebTransport settings.
  pub const fn settings(self) -> Settings {
    self.0
  }

  pub(crate) const fn new(settings: Settings) -> Self {
    Self(settings)
  }
}

/// The locally acknowledged WebTransport settings captured while processing
/// an inbound HTTP/2 HEADERS frame.
///
/// This extension travels with the corresponding request or response so a
/// later SETTINGS acknowledgement processed in the same connection poll
/// cannot alter the values associated with that message.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReceivedSettingsSnapshot {
  local: Option<SettingsSnapshot>,
}

impl ReceivedSettingsSnapshot {
  /// Returns the locally sent settings acknowledged when the HEADERS frame
  /// was processed.
  pub const fn local_settings(self) -> Option<SettingsSnapshot> {
    self.local
  }

  pub(crate) const fn new(local: Option<SettingsSnapshot>) -> Self {
    Self { local }
  }
}

/// Shared, acknowledged WebTransport SETTINGS state for one HTTP/2 connection.
///
/// A clone of this handle can be retained by a request or response owner. It
/// only reports settings after the corresponding HTTP/2 SETTINGS acknowledgement
/// boundary has been crossed.
#[derive(Clone, Debug, Default)]
pub struct SettingsHandle {
  inner: Arc<SettingsInner>,
}

#[derive(Debug, Default)]
struct SettingsInner {
  state: Mutex<SettingsState>,
  waiters: Mutex<SettingsWaiters>,
}

#[derive(Debug, Default)]
struct SettingsState {
  local: Settings,
  peer: Settings,
  local_acknowledged: bool,
  peer_acknowledged: bool,
  peer_extended_connect_protocol: bool,
  closed: bool,
}

#[derive(Debug, Default)]
struct SettingsWaiters {
  next_id: u64,
  entries: BTreeMap<u64, std::task::Waker>,
}

/// The connection closed before the requested SETTINGS state was observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettingsWaitError {
  /// The HTTP/2 connection ended before the requested SETTINGS state arrived.
  Closed,
}

impl fmt::Display for SettingsWaitError {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Closed => fmt.write_str("HTTP/2 connection closed before WebTransport SETTINGS were observed"),
    }
  }
}

impl std::error::Error for SettingsWaitError {}

#[derive(Clone, Copy, Debug)]
enum SettingsWaitKind {
  Peer,
  PeerWebTransport,
}

/// A per-caller future waiting for acknowledged peer WebTransport SETTINGS.
///
/// Every instance owns its own waker, so several request owners can wait on
/// one connection without replacing each other's wakeup registration.
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct SettingsWait {
  handle: SettingsHandle,
  kind: SettingsWaitKind,
  waiter_id: Option<u64>,
}

impl SettingsWait {
  fn new(handle: SettingsHandle, kind: SettingsWaitKind) -> Self {
    Self {
      handle,
      kind,
      waiter_id: None,
    }
  }
}

impl Future for SettingsWait {
  type Output = Result<SettingsSnapshot, SettingsWaitError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    if let Some(result) = this.handle.wait_result(this.kind) {
      this.unregister();
      return Poll::Ready(result);
    }

    match this.waiter_id {
      Some(waiter_id) => this.handle.inner.update_waiter(waiter_id, cx.waker()),
      None => this.waiter_id = this.handle.inner.register_waiter(cx.waker()),
    }

    match this.handle.wait_result(this.kind) {
      Some(result) => {
        this.unregister();
        Poll::Ready(result)
      }
      None => Poll::Pending,
    }
  }
}

impl SettingsWait {
  fn unregister(&mut self) {
    if let Some(waiter_id) = self.waiter_id.take() {
      self.handle.inner.remove_waiter(waiter_id);
    }
  }
}

impl Drop for SettingsWait {
  fn drop(&mut self) {
    self.unregister();
  }
}

impl SettingsInner {
  fn register_waiter(&self, waker: &std::task::Waker) -> Option<u64> {
    self.waiters.lock().ok().map(|mut waiters| {
      let waiter_id = waiters.next_id;
      waiters.next_id = waiters
        .next_id
        .checked_add(1)
        .expect("WebTransport SETTINGS waiter ID overflow");
      waiters.entries.insert(waiter_id, waker.clone());
      waiter_id
    })
  }

  fn update_waiter(&self, waiter_id: u64, waker: &std::task::Waker) {
    if let Ok(mut waiters) = self.waiters.lock() {
      if let Some(entry) = waiters.entries.get_mut(&waiter_id) {
        if !entry.will_wake(waker) {
          *entry = waker.clone();
        }
      }
    }
  }

  fn remove_waiter(&self, waiter_id: u64) {
    if let Ok(mut waiters) = self.waiters.lock() {
      waiters.entries.remove(&waiter_id);
    }
  }

  fn wake_waiters(&self) {
    let waiters = self
      .waiters
      .lock()
      .map(|waiters| waiters.entries.values().cloned().collect::<Vec<_>>())
      .unwrap_or_default();
    for waiter in waiters {
      waiter.wake();
    }
  }

  #[cfg(test)]
  fn waiter_count(&self) -> usize {
    self.waiters.lock().map(|waiters| waiters.entries.len()).unwrap_or(0)
  }
}

impl SettingsHandle {
  pub(crate) fn new() -> Self {
    Self::default()
  }

  /// Returns the latest locally sent settings acknowledged by the peer.
  pub fn local_acknowledged(&self) -> Option<SettingsSnapshot> {
    self.inner.state.lock().ok().and_then(|state| {
      state
        .local_acknowledged
        .then(|| SettingsSnapshot::new(state.local))
    })
  }

  /// Returns the latest peer settings this endpoint has acknowledged.
  pub fn peer_acknowledged(&self) -> Option<SettingsSnapshot> {
    self.inner.state.lock().ok().and_then(|state| {
      state
        .peer_acknowledged
        .then(|| SettingsSnapshot::new(state.peer))
    })
  }

  /// Returns whether the peer has acknowledged `SETTINGS_ENABLE_CONNECT_PROTOCOL`.
  pub fn peer_extended_connect_protocol_enabled(&self) -> bool {
    self
      .inner
      .state
      .lock()
      .map(|state| state.peer_extended_connect_protocol)
      .unwrap_or(false)
  }

  /// Returns the peer settings that currently permit a new WebTransport
  /// CONNECT request.
  ///
  /// The capability and its snapshot are read under one lock so a caller can
  /// retain the exact values that governed the request it is about to send.
  /// A later SETTINGS update cannot change that retained snapshot.
  pub fn peer_webtransport_settings(&self) -> Option<SettingsSnapshot> {
    self.inner.state.lock().ok().and_then(|state| {
      (state.peer_acknowledged && state.peer.enabled && state.peer_extended_connect_protocol)
        .then(|| SettingsSnapshot::new(state.peer))
    })
  }

  /// Waits for the peer's acknowledged WebTransport SETTINGS.
  ///
  /// The returned future fails if the HTTP/2 connection closes first.
  pub fn wait_peer_settings(&self) -> SettingsWait {
    SettingsWait::new(self.clone(), SettingsWaitKind::Peer)
  }

  /// Waits until the peer enables both WebTransport and extended CONNECT.
  ///
  /// The returned future fails if the HTTP/2 connection closes first. A peer
  /// that has not enabled the capability remains pending because it may send
  /// a later SETTINGS update that enables it.
  pub fn wait_peer_webtransport_settings(&self) -> SettingsWait {
    SettingsWait::new(self.clone(), SettingsWaitKind::PeerWebTransport)
  }

  pub(crate) fn apply_local(&self, update: &crate::frame::Settings) {
    if let Ok(mut state) = self.inner.state.lock() {
      update.apply_webtransport_settings_to(&mut state.local);
      state.local_acknowledged = true;
    }
    self.inner.wake_waiters();
  }

  pub(crate) fn apply_peer(&self, update: &crate::frame::Settings) {
    if let Ok(mut state) = self.inner.state.lock() {
      update.apply_webtransport_settings_to(&mut state.peer);
      if let Some(enabled) = update.is_extended_connect_protocol_enabled() {
        state.peer_extended_connect_protocol = enabled;
      }
      state.peer_acknowledged = true;
    }
    self.inner.wake_waiters();
  }

  pub(crate) fn close(&self) {
    let changed = self
      .inner
      .state
      .lock()
      .map(|mut state| {
        if state.closed {
          false
        } else {
          state.closed = true;
          true
        }
      })
      .unwrap_or(true);
    if changed {
      self.inner.wake_waiters();
    }
  }

  fn wait_result(
    &self,
    kind: SettingsWaitKind,
  ) -> Option<Result<SettingsSnapshot, SettingsWaitError>> {
    let state = match self.inner.state.lock() {
      Ok(state) => state,
      Err(_) => return Some(Err(SettingsWaitError::Closed)),
    };
    if state.closed {
      return Some(Err(SettingsWaitError::Closed));
    }
    let snapshot = match kind {
      SettingsWaitKind::Peer => state
        .peer_acknowledged
        .then(|| SettingsSnapshot::new(state.peer)),
      SettingsWaitKind::PeerWebTransport => {
        (state.peer_acknowledged && state.peer.enabled && state.peer_extended_connect_protocol)
          .then(|| SettingsSnapshot::new(state.peer))
      }
    };
    snapshot.map(Ok)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  async fn wait_for_waiter_count(handle: &SettingsHandle, expected: usize) {
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
      while handle.inner.waiter_count() != expected {
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("settings waiter registrations should reach the expected count");
  }

  #[test]
  fn snapshots_merge_acknowledged_settings_updates() {
    let handle = SettingsHandle::new();
    let initial = Settings {
      enabled: true,
      initial_max_data: Some(10),
      initial_max_stream_data_uni: Some(11),
      initial_max_stream_data_bidi_local: Some(12),
      initial_max_stream_data_bidi_remote: Some(13),
      initial_max_streams_uni: Some(14),
      initial_max_streams_bidi: Some(15),
    };
    let mut frame = crate::frame::Settings::default();
    frame.set_webtransport_settings(initial);
    frame.set_enable_connect_protocol(Some(1));
    handle.apply_peer(&frame);
    assert_eq!(handle.peer_acknowledged().unwrap().settings(), initial);
    assert!(handle.peer_extended_connect_protocol_enabled());

    let update = Settings {
      enabled: true,
      initial_max_data: Some(20),
      ..Settings::disabled()
    };
    let mut update_frame = crate::frame::Settings::default();
    update_frame.set_webtransport_settings(update);
    handle.apply_peer(&update_frame);

    let expected = Settings {
      initial_max_data: Some(20),
      ..initial
    };
    assert_eq!(handle.peer_acknowledged().unwrap().settings(), expected);
  }

  #[tokio::test]
  async fn settings_waits_wake_each_concurrent_waiter_and_report_closure() {
    let handle = SettingsHandle::new();
    let first = tokio::spawn(handle.wait_peer_settings());
    let second = tokio::spawn(handle.wait_peer_webtransport_settings());
    wait_for_waiter_count(&handle, 2).await;

    let mut enabled = crate::frame::Settings::default();
    enabled.set_webtransport_settings(Settings::enabled());
    enabled.set_enable_connect_protocol(Some(1));
    handle.apply_peer(&enabled);

    assert!(first.await.expect("peer settings waiter task").is_ok());
    assert!(second
      .await
      .expect("WebTransport settings waiter task")
      .is_ok());
    assert_eq!(handle.inner.waiter_count(), 0);

    let closed = SettingsHandle::new();
    let first = tokio::spawn(closed.wait_peer_webtransport_settings());
    let second = tokio::spawn(closed.wait_peer_webtransport_settings());
    wait_for_waiter_count(&closed, 2).await;
    closed.close();

    assert_eq!(
      first.await.expect("first closed waiter task"),
      Err(SettingsWaitError::Closed)
    );
    assert_eq!(
      second.await.expect("second closed waiter task"),
      Err(SettingsWaitError::Closed)
    );
    assert_eq!(closed.inner.waiter_count(), 0);
  }

  #[tokio::test]
  async fn disabled_settings_stay_pending_and_cancelled_waiters_are_removed() {
    let handle = SettingsHandle::new();
    let disabled = crate::frame::Settings::default();
    handle.apply_peer(&disabled);
    assert!(
      tokio::time::timeout(
        std::time::Duration::from_millis(25),
        handle.wait_peer_webtransport_settings(),
      )
      .await
      .is_err(),
      "disabled SETTINGS can be updated later and must not fail the wait"
    );
    assert_eq!(handle.inner.waiter_count(), 0);

    let waiter = tokio::spawn(handle.wait_peer_webtransport_settings());
    wait_for_waiter_count(&handle, 1).await;
    waiter.abort();
    let _ = waiter.await;
    assert_eq!(handle.inner.waiter_count(), 0);
  }

  #[tokio::test]
  async fn connection_eof_closes_pending_settings_wait() {
    let (client_io, server_io) = tokio::io::duplex(4096);
    let (client, connection) = crate::client::handshake(client_io)
      .await
      .expect("HTTP/2 client handshake");
    let settings = client.webtransport_settings();
    let driver = tokio::spawn(async move { connection.await });
    let waiter = tokio::spawn(settings.wait_peer_webtransport_settings());
    tokio::task::yield_now().await;
    drop(server_io);

    assert_eq!(
      tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
        .await
        .expect("settings waiter should wake after EOF")
        .expect("settings waiter task"),
      Err(SettingsWaitError::Closed)
    );
    let _ = driver.await;
  }

  #[tokio::test]
  async fn remote_go_away_closes_pending_settings_wait() {
    use tokio::io::AsyncWriteExt;

    let (client_io, mut peer_io) = tokio::io::duplex(4096);
    let (client, connection) = crate::client::handshake(client_io)
      .await
      .expect("HTTP/2 client handshake");
    let settings = client.webtransport_settings();
    let driver = tokio::spawn(async move { connection.await });
    let waiter = tokio::spawn(settings.wait_peer_webtransport_settings());
    tokio::task::yield_now().await;

    peer_io
      .write_all(&[
        0, 0, 0, 4, 0, 0, 0, 0, 0, // SETTINGS
        0, 0, 8, 7, 0, 0, 0, 0, 0, // GOAWAY frame header
        0, 0, 0, 0, 0, 0, 0, 0, // last-stream-id and NO_ERROR
      ])
      .await
      .expect("send peer SETTINGS and GOAWAY");

    assert_eq!(
      tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
        .await
        .expect("settings waiter should wake after GOAWAY")
        .expect("settings waiter task"),
      Err(SettingsWaitError::Closed)
    );
    drop(peer_io);
    let _ = driver.await;
  }

  #[tokio::test]
  async fn dropped_connection_driver_closes_pending_settings_wait() {
    let (client_io, _peer_io) = tokio::io::duplex(4096);
    let (client, connection) = crate::client::handshake(client_io)
      .await
      .expect("HTTP/2 client handshake");
    let settings = client.webtransport_settings();
    let driver = tokio::spawn(async move { connection.await });
    let waiter = tokio::spawn(settings.wait_peer_webtransport_settings());
    tokio::task::yield_now().await;
    driver.abort();
    let _ = driver.await;

    assert_eq!(
      tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
        .await
        .expect("settings waiter should wake after driver abort")
        .expect("settings waiter task"),
      Err(SettingsWaitError::Closed)
    );
  }

  #[tokio::test]
  async fn local_abrupt_shutdown_closes_pending_settings_wait() {
    use tokio::io::AsyncWriteExt;

    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let (server_io, mut peer_io) = tokio::io::duplex(4096);
    peer_io
      .write_all(&[PREFACE, &[0, 0, 0, 4, 0, 0, 0, 0, 0]].concat())
      .await
      .expect("send HTTP/2 client preface");
    let mut server = crate::server::handshake(server_io)
      .await
      .expect("HTTP/2 server handshake");
    let settings = server.webtransport_settings();
    let waiter = tokio::spawn(settings.wait_peer_webtransport_settings());
    wait_for_waiter_count(&settings, 1).await;

    server.abrupt_shutdown(crate::Reason::NO_ERROR);
    assert_eq!(
      waiter.await.expect("abrupt-shutdown waiter task"),
      Err(SettingsWaitError::Closed)
    );
  }

  #[tokio::test]
  async fn stream_reset_does_not_close_pending_settings_wait() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client_io, mut peer_io) = tokio::io::duplex(4096);
    let (mut client, connection) = crate::client::handshake(client_io)
      .await
      .expect("HTTP/2 client handshake");
    let settings = client.webtransport_settings();
    let request = http::Request::builder()
      .uri("https://example.test/")
      .body(())
      .expect("HTTP/2 request");
    let (_response, _send) = client.send_request(request, true).expect("queue request");
    let driver = tokio::spawn(async move { connection.await });

    let mut preface = [0; 24];
    peer_io.read_exact(&mut preface).await.expect("read client preface");
    let mut settings_head = [0; 9];
    peer_io
      .read_exact(&mut settings_head)
      .await
      .expect("read client SETTINGS header");
    assert_eq!(settings_head[3], 4);
    let settings_len = u32::from_be_bytes([0, settings_head[0], settings_head[1], settings_head[2]]) as usize;
    let mut settings_body = vec![0; settings_len];
    peer_io
      .read_exact(&mut settings_body)
      .await
      .expect("read client SETTINGS body");
    let mut request_head = [0; 9];
    peer_io
      .read_exact(&mut request_head)
      .await
      .expect("read request header");
    assert_eq!(request_head[3], 1);
    let request_len = u32::from_be_bytes([0, request_head[0], request_head[1], request_head[2]]) as usize;
    let mut request_body = vec![0; request_len];
    peer_io
      .read_exact(&mut request_body)
      .await
      .expect("read request body");

    peer_io
      .write_all(&[
        0, 0, 0, 4, 0, 0, 0, 0, 0, // SETTINGS
        0, 0, 4, 3, 0, 0, 0, 0, 1, // RST_STREAM for stream 1
        0, 0, 0, 8, // CANCEL
      ])
      .await
      .expect("send peer SETTINGS and stream reset");

    assert!(
      tokio::time::timeout(
        std::time::Duration::from_millis(50),
        settings.wait_peer_webtransport_settings(),
      )
      .await
      .is_err(),
      "a stream-local reset must not terminate connection-level SETTINGS waits"
    );
    driver.abort();
    let _ = driver.await;
  }

  #[tokio::test]
  async fn request_headers_snapshot_precedes_a_coalesced_settings_ack() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let initial = Settings {
      enabled: true,
      initial_max_data: Some(10),
      ..Settings::disabled()
    };
    let (server_io, mut peer_io) = tokio::io::duplex(4096);

    // Send the client preface and an empty initial SETTINGS frame first.
    peer_io
      .write_all(&[PREFACE, &[0, 0, 0, 4, 0, 0, 0, 0, 0]].concat())
      .await
      .expect("send HTTP/2 client preface");
    let mut builder = crate::server::Builder::new();
    builder.enable_connect_protocol();
    builder.webtransport_settings(initial);
    let mut server = builder
      .handshake::<_, bytes::Bytes>(server_io)
      .await
      .expect("HTTP/2 server handshake");

    // The following write deliberately coalesces the CONNECT HEADERS and
    // the ACK for the server's initial SETTINGS frame.
    let header_block = [
      0x02, 0x07, b'C', b'O', b'N', b'N', b'E', b'C', b'T', // :method = CONNECT
      0x87, // :scheme = https
      0x84, // :path = /
      0x01, 0x0c, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b't', b'e', b's', b't', 0x00,
      0x09, b':', b'p', b'r', b'o', b't', b'o', b'c', b'o', b'l', 0x0c, b'w', b'e', b'b', b't',
      b'r', b'a', b'n', b's', b'p', b'o', b'r', b't',
    ];
    let mut frames = Vec::with_capacity(9 + header_block.len() + 9);
    frames.extend_from_slice(&[0, 0, header_block.len() as u8, 1, 4, 0, 0, 0, 1]);
    frames.extend_from_slice(&header_block);
    frames.extend_from_slice(&[0, 0, 0, 4, 1, 0, 0, 0, 0]);
    peer_io
      .write_all(&frames)
      .await
      .expect("send coalesced CONNECT and SETTINGS ACK");
    let peer_drain = tokio::spawn(async move {
      let mut bytes = [0; 4096];
      loop {
        let received = peer_io.read(&mut bytes).await.expect("read server frames");
        if received == 0 {
          return;
        }
      }
    });

    let (request, _respond) = server
      .accept()
      .await
      .expect("connection remains open")
      .expect("CONNECT request");
    let snapshot = request
      .extensions()
      .get::<ReceivedSettingsSnapshot>()
      .copied()
      .expect("request settings snapshot");
    assert_eq!(snapshot.local_settings(), None);
    assert_eq!(
      server
        .webtransport_settings()
        .local_acknowledged()
        .map(|value| value.settings()),
      Some(initial)
    );
    peer_drain.abort();
  }

  #[tokio::test]
  async fn response_headers_snapshot_precedes_a_coalesced_settings_ack() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let initial = Settings {
      enabled: true,
      initial_max_data: Some(10),
      ..Settings::disabled()
    };
    let (client_io, mut peer_io) = tokio::io::duplex(4096);
    let mut builder = crate::client::Builder::new();
    builder.webtransport_settings(initial);
    let (mut client, connection) = builder
      .handshake::<_, bytes::Bytes>(client_io)
      .await
      .expect("HTTP/2 client handshake");
    let settings = client.webtransport_settings();
    let request = http::Request::builder()
      .uri("https://example.test/")
      .body(())
      .expect("HTTP/2 request");
    let (response, _send_stream) = client
      .send_request(request, true)
      .expect("send HTTP/2 request");
    let client_driver = tokio::spawn(async move { connection.await });

    // Let the client preface, SETTINGS, and request leave the connection.
    let mut preface = [0; 24];
    peer_io
      .read_exact(&mut preface)
      .await
      .expect("read client preface");
    let mut settings_head = [0; 9];
    peer_io
      .read_exact(&mut settings_head)
      .await
      .expect("read client settings header");
    assert_eq!(settings_head[3], 4);
    let settings_len =
      u32::from_be_bytes([0, settings_head[0], settings_head[1], settings_head[2]]) as usize;
    let mut settings_body = vec![0; settings_len];
    peer_io
      .read_exact(&mut settings_body)
      .await
      .expect("read client settings body");
    let mut request_head = [0; 9];
    peer_io
      .read_exact(&mut request_head)
      .await
      .expect("read client request header");
    let request_len =
      u32::from_be_bytes([0, request_head[0], request_head[1], request_head[2]]) as usize;
    let mut request_body = vec![0; request_len];
    peer_io
      .read_exact(&mut request_body)
      .await
      .expect("read client request body");
    assert_eq!(request_head[3], 1);

    // A server SETTINGS frame, final response HEADERS, and ACK of the
    // client's initial SETTINGS are delivered in one write. `poll_closed`
    // drains the ACK before the response future is exposed.
    peer_io
      .write_all(&[
        0, 0, 0, 4, 0, 0, 0, 0, 0, // server SETTINGS
        0, 0, 1, 1, 4, 0, 0, 0, 1, 0x88, // :status = 200
        0, 0, 0, 4, 1, 0, 0, 0, 0, // SETTINGS ACK
      ])
      .await
      .expect("send coalesced response and SETTINGS ACK");

    let response = response.await.expect("HTTP/2 response");
    let snapshot = response
      .extensions()
      .get::<ReceivedSettingsSnapshot>()
      .copied()
      .expect("response settings snapshot");
    assert_eq!(snapshot.local_settings(), None);
    assert_eq!(
      settings.local_acknowledged().map(|value| value.settings()),
      Some(initial)
    );
    client_driver.abort();
  }

  #[tokio::test]
  async fn queued_webtransport_connect_is_not_emitted_after_peer_disables_it() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client_io, mut peer_io) = tokio::io::duplex(4096);
    let (mut client, mut connection) = crate::client::handshake(client_io)
      .await
      .expect("HTTP/2 client handshake");
    // First establish enabled, acknowledged peer settings. Keep the driver
    // under test control while CONNECT and the subsequent update are queued.
    peer_io
      .write_all(&[
        0, 0, 12, 4, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 1, 0x2b, 0x60, 0, 0, 0, 1,
      ])
      .await
      .expect("enable extended CONNECT and WebTransport");
    let settings = client.webtransport_settings();
    crate::poll_fn(|cx| {
      use std::future::Future;
      assert!(std::pin::Pin::new(&mut connection).poll(cx).is_pending());
      if settings.peer_webtransport_settings().is_some() {
        Poll::Ready(())
      } else {
        Poll::Pending
      }
    })
    .await;
    let mut request = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("https://example.test/webtransport")
      .body(())
      .expect("WebTransport CONNECT");
    request
      .extensions_mut()
      .insert(crate::ext::Protocol::from_static("webtransport"));
    let (response, mut send_stream) = client
      .send_request(request, false)
      .expect("queue WebTransport CONNECT");

    // SETTINGS_WT_ENABLE=0 arrives before the driver has emitted stream 1.
    peer_io
      .write_all(&[0, 0, 6, 4, 0, 0, 0, 0, 0, 0x2b, 0x60, 0, 0, 0, 0])
      .await
      .expect("send disabling SETTINGS");
    let driver = tokio::spawn(async move { connection.await });

    assert!(
      crate::poll_fn(|cx| send_stream.poll_webtransport_peer_settings(cx))
        .await
        .is_err()
    );
    assert!(response.await.is_err());

    // The peer may receive SETTINGS ACK but must never receive stream-1
    // HEADERS or RST_STREAM: stream 1 was never opened on the wire.
    let mut outbound = [0; 128];
    let received = peer_io
      .read(&mut outbound)
      .await
      .expect("read client output");
    let mut offset = 24; // client connection preface
    while offset + 9 <= received {
      let len = u32::from_be_bytes([
        0,
        outbound[offset],
        outbound[offset + 1],
        outbound[offset + 2],
      ]) as usize;
      let kind = outbound[offset + 3];
      let stream = u32::from_be_bytes([
        outbound[offset + 5],
        outbound[offset + 6],
        outbound[offset + 7],
        outbound[offset + 8],
      ]) & 0x7fff_ffff;
      assert!(!(stream == 1 && (kind == 1 || kind == 3)));
      offset += 9 + len;
    }
    driver.abort();
  }
  #[tokio::test]
  async fn queued_response_receipt_uses_settings_acknowledged_before_emission() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
      let (server_io, mut peer_io) = tokio::io::duplex(4096);
      peer_io
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .expect("client preface");
      peer_io
        .write_all(&[0, 0, 6, 4, 0, 0, 0, 0, 0, 0x2b, 0x61, 0, 0, 0, 10])
        .await
        .expect("initial client limits");
      let mut builder = crate::server::Builder::new();
      builder
        .enable_connect_protocol()
        .webtransport_settings(Settings::enabled());
      let mut server = builder
        .handshake::<_, bytes::Bytes>(server_io)
        .await
        .unwrap();
      let headers = [
        0x02, 7, b'C', b'O', b'N', b'N', b'E', b'C', b'T', 0x87, 0x84, 0x01, 12, b'e', b'x', b'a',
        b'm', b'p', b'l', b'e', b'.', b't', b'e', b's', b't', 0, 9, b':', b'p', b'r', b'o', b't',
        b'o', b'c', b'o', b'l', 12, b'w', b'e', b'b', b't', b'r', b'a', b'n', b's', b'p', b'o',
        b'r', b't',
      ];
      peer_io
        .write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0])
        .await
        .unwrap();
      peer_io
        .write_all(&[0, 0, headers.len() as u8, 1, 4, 0, 0, 0, 1])
        .await
        .unwrap();
      peer_io.write_all(&headers).await.unwrap();
      let (_request, mut respond) = server.accept().await.unwrap().unwrap();
      assert_eq!(
        server
          .webtransport_settings()
          .peer_acknowledged()
          .unwrap()
          .settings()
          .initial_max_data,
        Some(10)
      );
      let mut send = respond
        .send_response(http::Response::new(()), false)
        .unwrap();
      // This ACK will be emitted before the already-queued response HEADERS.
      peer_io
        .write_all(&[0, 0, 6, 4, 0, 0, 0, 0, 0, 0x2b, 0x61, 0, 0, 0, 42])
        .await
        .expect("update client limits before response emission");
      let driver = tokio::spawn(async move { while server.accept().await.is_some() {} });
      let receipt = crate::poll_fn(|cx| send.poll_webtransport_peer_settings(cx))
        .await
        .unwrap()
        .unwrap();
      assert_eq!(receipt.settings().initial_max_data, Some(42));
      let mut acknowledgements = 0;
      loop {
        let mut head = [0; 9];
        peer_io.read_exact(&mut head).await.unwrap();
        let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        let mut body = vec![0; len];
        peer_io.read_exact(&mut body).await.unwrap();
        if head[3] == 4 && head[4] == 1 {
          acknowledgements += 1;
        }
        if head[3] == 1 {
          assert_eq!(head[8], 1);
          assert_eq!(
            acknowledgements, 2,
            "both SETTINGS ACKs precede response HEADERS"
          );
          break;
        }
      }
      driver.abort();
    })
    .await
    .expect("queued response receipt must make progress");
  }
}

//! Per-session draft-16 credit and CONNECT capsule handling.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use bytes::{Buf, Bytes, BytesMut};
use h3::error::Code;
use h3_webtransport::SessionId;
use tokio::sync::{Notify, mpsc};

use super::super::super::{H3RequestRecvStream, H3RequestSendStream};
use super::super::upstream_adapter::web_transport_proto::{
  self, Capsule, FlowCredit, FlowError, WT_MAX_DATA, WT_MAX_STREAMS_BIDI, WT_MAX_STREAMS_UNI,
};
use super::super::{DispatcherEvent, UpstreamWebTransportSession};

pub(super) const FLOW_ERROR_CODE: u64 = web_transport_proto::WT_FLOW_CONTROL_ERROR;
const WT_DRAIN_SESSION: u32 = 0x78ae;
const MAX_CONNECT_CAPSULE_BUFFER: usize = 65_536;

fn decode_pending_capsule(
  pending: &[u8],
) -> Result<Option<(Capsule, usize)>, web_transport_proto::CapsuleError> {
  let mut slice = pending;
  match Capsule::decode(&mut slice) {
    Ok(capsule) => Ok(Some((capsule, pending.len() - slice.len()))),
    Err(
      web_transport_proto::CapsuleError::UnexpectedEnd
      | web_transport_proto::CapsuleError::VarInt(_),
    ) => Ok(None),
    Err(error) => Err(error),
  }
}

fn validate_close_capsule(
  reason: &str,
  used: usize,
  buffered: usize,
) -> Result<(), web_transport_proto::CapsuleError> {
  if reason.len() > 1024 {
    return Err(web_transport_proto::CapsuleError::MessageTooLong);
  }
  if used != buffered {
    return Err(web_transport_proto::CapsuleError::InvalidLength);
  }
  Ok(())
}

pub(super) struct ConnectStream {
  pub send: Arc<tokio::sync::Mutex<H3RequestSendStream>>,
  pub recv: Arc<tokio::sync::Mutex<H3RequestRecvStream>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
  mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl ConnectStream {
  pub async fn write_drain(send: Arc<tokio::sync::Mutex<H3RequestSendStream>>) -> bool {
    send
      .lock()
      .await
      .send_data(encode_drain_capsule())
      .await
      .is_ok()
  }

  pub async fn write_close(&mut self, code: u32, reason: &str) -> bool {
    let payload = encode_close_capsule(code, reason);
    let mut send = self.send.lock().await;
    if send.send_data(payload).await.is_err() || send.finish().await.is_err() {
      send.stop_stream(Code::H3_NO_ERROR);
      return false;
    }
    true
  }

  pub async fn drain_after_close(&mut self) {
    // A graceful close must not send STOP_SENDING to the peer's CONNECT half:
    // browsers surface that as a stream error even after receiving the close
    // capsule. Keep the receive half alive until its FIN so dropping it does
    // not implicitly send STOP_SENDING either.
    let mut recv = self.recv.lock().await;
    if matches!(recv.recv_data().await, Ok(Some(_))) {
      recv.stop_sending(Code::H3_MESSAGE_ERROR);
    }
  }

  pub async fn reset_abrupt_send(&mut self) {
    // An upstream connection failure belongs to this CONNECT stream. Reset
    // its send half before retiring child streams, so browsers can process
    // the session failure before any child receive halves are dropped.
    self.send.lock().await.stop_stream(Code::H3_INTERNAL_ERROR);
  }

  pub async fn drain_after_abrupt_reset(&mut self) {
    // Keep the CONNECT receive half alive briefly so dropping it does not
    // turn the peer's stream into a second STOP_SENDING error.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
      let mut recv = self.recv.lock().await;
      while matches!(recv.recv_data().await, Ok(Some(_))) {}
    })
    .await;
  }

  pub fn stop_stream(&mut self, code: Code) {
    if let Ok(mut locked) = self.send.try_lock() {
      locked.stop_stream(code);
    } else {
      let send = self.send.clone();
      tokio::spawn(async move {
        stop_locked(send, |stream| stream.stop_stream(code)).await;
      });
    }
  }

  pub fn stop_sending(&mut self, code: Code) {
    if let Ok(mut locked) = self.recv.try_lock() {
      locked.stop_sending(code);
    } else {
      let recv = self.recv.clone();
      tokio::spawn(async move {
        stop_locked(recv, |stream| stream.stop_sending(code)).await;
      });
    }
  }

  pub async fn stop_both(&mut self, code: Code) {
    stop_locked(self.send.clone(), |stream| stream.stop_stream(code)).await;
    stop_locked(self.recv.clone(), |stream| stream.stop_sending(code)).await;
  }
}

fn encode_drain_capsule() -> Bytes {
  let mut encoded = Vec::new();
  Capsule::Unknown {
    typ: web_transport_proto::VarInt::from_u32(WT_DRAIN_SESSION),
    payload: Bytes::new(),
  }
  .encode(&mut encoded);
  Bytes::from(encoded)
}

fn encode_close_capsule(code: u32, reason: &str) -> Bytes {
  let capsule = Capsule::CloseWebTransportSession {
    code,
    reason: reason.to_owned(),
  };
  let mut encoded = Vec::new();
  capsule.encode(&mut encoded);
  Bytes::from(encoded)
}

async fn stop_locked<T>(stream: Arc<tokio::sync::Mutex<T>>, stop: impl FnOnce(&mut T)) {
  let mut stream = stream.lock().await;
  stop(&mut stream);
}

pub(in crate::proxy::http3::webtransport_bridge) struct SessionFlow {
  pub outgoing: Mutex<FlowCredit>,
  pub incoming: Mutex<FlowCredit>,
  outgoing_wakers: Mutex<Vec<std::task::Waker>>,
  pub outgoing_notify: Notify,
  pub incoming_notify: Notify,
  desired: Mutex<(u64, u64, u64)>,
}

impl SessionFlow {
  pub fn new(peer_initial: (u64, u64, u64)) -> Result<Arc<Self>, FlowError> {
    Ok(Arc::new(Self {
      outgoing: Mutex::new(FlowCredit::new(
        peer_initial.0,
        peer_initial.1,
        peer_initial.2,
      )?),
      incoming: Mutex::new(FlowCredit::new(0, 0, 0)?),
      outgoing_wakers: Mutex::new(Vec::new()),
      outgoing_notify: Notify::new(),
      incoming_notify: Notify::new(),
      desired: Mutex::new((0, 0, 0)),
    }))
  }

  pub fn grant_initial(&self, uni: u64, bidi: u64, data: u64) -> Result<(), FlowError> {
    if uni > web_transport_proto::MAX_STREAMS
      || bidi > web_transport_proto::MAX_STREAMS
      || data > web_transport_proto::VarInt::MAX.into_inner()
    {
      return Err(FlowError::Exceeded);
    }
    *lock(&self.desired) = (uni, bidi, data);
    self.incoming_notify.notify_one();
    Ok(())
  }

  pub(in crate::proxy::http3::webtransport_bridge) async fn open(
    &self,
    bidi: bool,
  ) -> Result<(), FlowError> {
    loop {
      let notified = self.outgoing_notify.notified();
      tokio::pin!(notified);
      notified.as_mut().enable();
      let result = {
        let mut credit = lock(&self.outgoing);
        if bidi {
          credit.open_bidi()
        } else {
          credit.open_uni()
        }
      };
      match result {
        Ok(()) => return Ok(()),
        Err(FlowError::Exceeded) => notified.await,
        Err(error) => return Err(error),
      }
    }
  }

  pub fn incoming_open(&self, bidi: bool) -> Result<(), FlowError> {
    let mut credit = lock(&self.incoming);
    if bidi {
      credit.open_bidi()
    } else {
      credit.open_uni()
    }
  }

  pub fn incoming_data(&self, bytes: u64) -> Result<(), FlowError> {
    let mut credit = lock(&self.incoming);
    credit.use_data(bytes)?;
    let mut desired = lock(&self.desired);
    desired.2 = desired
      .2
      .checked_add(bytes)
      .filter(|value| *value <= web_transport_proto::VarInt::MAX.into_inner())
      .ok_or(FlowError::Exceeded)?;
    drop(credit);
    self.incoming_notify.notify_one();
    Ok(())
  }

  pub fn incoming_reset(
    &self,
    seen: u64,
    final_size: u64,
    header_size: u64,
  ) -> Result<(), FlowError> {
    let discarded = final_size
      .checked_sub(header_size)
      .and_then(|body| body.checked_sub(seen))
      .ok_or(FlowError::InvalidCapsule)?;
    let mut credit = lock(&self.incoming);
    credit.reset_final_size(seen, final_size, header_size)?;
    let mut desired = lock(&self.desired);
    desired.2 = desired
      .2
      .checked_add(discarded)
      .filter(|value| *value <= web_transport_proto::VarInt::MAX.into_inner())
      .ok_or(FlowError::Exceeded)?;
    drop(credit);
    self.incoming_notify.notify_one();
    Ok(())
  }

  pub fn incoming_closed(&self, bidi: bool) -> Result<(), FlowError> {
    let mut desired = lock(&self.desired);
    let limit = if bidi { &mut desired.1 } else { &mut desired.0 };
    *limit = limit
      .checked_add(1)
      .filter(|value| *value <= web_transport_proto::MAX_STREAMS)
      .ok_or(FlowError::Exceeded)?;
    drop(desired);
    self.incoming_notify.notify_one();
    Ok(())
  }

  pub fn apply_capsule(&self, capsule: &Capsule) -> Result<bool, FlowError> {
    let applied = lock(&self.outgoing).apply_capsule(capsule)?;
    if applied {
      self.wake_outgoing();
      self.outgoing_notify.notify_waiters();
    }
    Ok(applied)
  }

  pub fn register_outgoing(&self, waker: &std::task::Waker) {
    let mut waiters = lock(&self.outgoing_wakers);
    if !waiters.iter().any(|waiting| waiting.will_wake(waker)) {
      waiters.push(waker.clone());
    }
  }

  fn wake_outgoing(&self) {
    let wakers = std::mem::take(&mut *lock(&self.outgoing_wakers));
    for waker in wakers {
      waker.wake();
    }
  }

  fn next_capsule(&self) -> Option<(u64, u64, Capsule)> {
    let advertised = lock(&self.incoming);
    let desired = lock(&self.desired);
    let (kind, value) = if desired.0 > advertised.max_uni {
      (WT_MAX_STREAMS_UNI, desired.0)
    } else if desired.1 > advertised.max_bidi {
      (WT_MAX_STREAMS_BIDI, desired.1)
    } else if desired.2 > advertised.max_data {
      (WT_MAX_DATA, desired.2)
    } else {
      return None;
    };
    Some((kind, value, FlowCredit::credit_capsule(kind, value).ok()?))
  }

  fn mark_sent(&self, kind: u64, value: u64) {
    let mut advertised = lock(&self.incoming);
    match kind {
      WT_MAX_STREAMS_UNI => advertised.max_uni = value,
      WT_MAX_STREAMS_BIDI => advertised.max_bidi = value,
      WT_MAX_DATA => advertised.max_data = value,
      _ => unreachable!(),
    }
  }
}

pub(super) async fn read_connect_capsules(
  session_id: SessionId,
  recv: Arc<tokio::sync::Mutex<H3RequestRecvStream>>,
  flow: Option<Arc<SessionFlow>>,
  upstream: Arc<UpstreamWebTransportSession>,
  events: mpsc::Sender<DispatcherEvent>,
) {
  let mut pending = BytesMut::new();
  let mut pending_close = None;
  loop {
    let next = recv.lock().await.recv_data().await;
    let Some(mut data) = (match next {
      Ok(next) => next,
      Err(_) => {
        let _ = events
          .send(connect_read_failure_event(
            session_id,
            pending_close.is_some(),
          ))
          .await;
        return;
      }
    }) else {
      let event = connect_eof_event(session_id, pending_close.take(), pending.is_empty());
      let _ = events.send(event).await;
      return;
    };
    if pending_close.is_some() {
      let _ = events
        .send(DispatcherEvent::ProtocolError(session_id))
        .await;
      return;
    }
    if pending.len().saturating_add(data.remaining()) > MAX_CONNECT_CAPSULE_BUFFER {
      let _ = events
        .send(DispatcherEvent::ProtocolError(session_id))
        .await;
      return;
    }
    pending.extend_from_slice(&data.copy_to_bytes(data.remaining()));
    loop {
      match decode_pending_capsule(&pending) {
        Ok(Some((Capsule::CloseWebTransportSession { code, reason }, used))) => {
          if validate_close_capsule(&reason, used, pending.len()).is_err() {
            let _ = events
              .send(DispatcherEvent::ProtocolError(session_id))
              .await;
            return;
          }
          pending.clear();
          if !claim_client_close_before_dispatch(&events, session_id, || {
            upstream.close(code, reason.as_bytes());
          })
          .await
          {
            return;
          }
          pending_close = Some((code, reason));
          break;
        }
        Ok(Some((capsule, used))) => {
          pending.advance(used);
          if let Some(flow) = &flow
            && flow.apply_capsule(&capsule).is_err()
          {
            let _ = events.send(DispatcherEvent::FlowError(session_id)).await;
            return;
          }
        }
        Ok(None) => break,
        Err(_) => {
          let _ = events
            .send(DispatcherEvent::ProtocolError(session_id))
            .await;
          return;
        }
      }
    }
  }
}

async fn claim_client_close_before_dispatch(
  events: &mpsc::Sender<DispatcherEvent>,
  session_id: SessionId,
  close_upstream: impl FnOnce(),
) -> bool {
  // A peer can close its QUIC connection immediately after sending CLOSE.
  // Claim the upstream close code before awaiting dispatcher capacity;
  // otherwise connection cleanup may claim vendored Session::close with 0.
  close_upstream();
  events
    .send(DispatcherEvent::ClientCloseStarted(session_id))
    .await
    .is_ok()
}

fn connect_eof_event(
  session_id: SessionId,
  pending_close: Option<(u32, String)>,
  pending_empty: bool,
) -> DispatcherEvent {
  match pending_close {
    Some((code, reason)) => DispatcherEvent::ClientCloseFinished(session_id, code, reason),
    None if pending_empty => DispatcherEvent::ClientFinished(session_id),
    None => DispatcherEvent::ProtocolError(session_id),
  }
}

fn connect_read_failure_event(session_id: SessionId, close_received: bool) -> DispatcherEvent {
  if close_received {
    DispatcherEvent::ProtocolError(session_id)
  } else {
    DispatcherEvent::SessionEnded(session_id)
  }
}

pub(super) async fn write_credit_capsules(
  session_id: SessionId,
  send: Arc<tokio::sync::Mutex<H3RequestSendStream>>,
  flow: Arc<SessionFlow>,
  events: mpsc::Sender<DispatcherEvent>,
) {
  loop {
    flow.incoming_notify.notified().await;
    while let Some((kind, value, capsule)) = flow.next_capsule() {
      let mut encoded = Vec::new();
      capsule.encode(&mut encoded);
      if send
        .lock()
        .await
        .send_data(Bytes::from(encoded))
        .await
        .is_err()
      {
        let _ = events.send(DispatcherEvent::SessionEnded(session_id)).await;
        return;
      }
      flow.mark_sent(kind, value);
    }
  }
}

#[cfg(test)]
mod tests {
  use std::sync::atomic::{AtomicU32, Ordering};

  use super::*;

  #[tokio::test]
  async fn validated_client_close_claims_upstream_code_before_dispatch_backpressure() {
    let session_id = SessionId::try_from(0_u64).expect("valid session ID");
    let (events, mut received) = mpsc::channel(1);
    events
      .send(DispatcherEvent::Activity(session_id))
      .await
      .expect("fill dispatcher channel");
    let claimed = Arc::new(AtomicU32::new(0));
    let task_claimed = claimed.clone();
    let task_events = events.clone();
    let task = tokio::spawn(async move {
      claim_client_close_before_dispatch(&task_events, session_id, || {
        task_claimed.store(99, Ordering::SeqCst);
      })
      .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
      while claimed.load(Ordering::SeqCst) != 99 {
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("validated code was claimed without dispatcher capacity");
    assert!(!task.is_finished(), "dispatcher is still backpressured");
    assert!(matches!(
      received.recv().await,
      Some(DispatcherEvent::Activity(id)) if id == session_id
    ));
    assert!(task.await.expect("close task"));
    assert!(matches!(
      received.recv().await,
      Some(DispatcherEvent::ClientCloseStarted(id)) if id == session_id
    ));
  }

  #[test]
  fn clean_connect_fin_waits_for_peer_close_instead_of_failing_session() {
    let session_id = SessionId::try_from(0_u64).expect("valid session ID");
    assert!(matches!(
      connect_eof_event(session_id, None, true),
      DispatcherEvent::ClientFinished(id) if id == session_id
    ));
    assert!(matches!(
      connect_eof_event(session_id, None, false),
      DispatcherEvent::ProtocolError(id) if id == session_id
    ));
  }

  #[test]
  fn downstream_drain_capsule_has_empty_payload() {
    let encoded = encode_drain_capsule();
    let mut wire = encoded.as_ref();
    assert!(matches!(
      Capsule::decode(&mut wire),
      Ok(Capsule::Unknown { typ, payload })
        if typ.into_inner() == u64::from(WT_DRAIN_SESSION) && payload.is_empty()
    ));
    assert!(wire.is_empty());
  }

  #[test]
  fn reset_after_complete_close_is_a_protocol_error_not_an_ignored_session_end() {
    let session_id = SessionId::try_from(0_u64).expect("valid test session ID");
    let mut close = Vec::new();
    Capsule::CloseWebTransportSession {
      code: 32,
      reason: "done".into(),
    }
    .encode(&mut close);
    let close_received = matches!(
      decode_pending_capsule(&close),
      Ok(Some((Capsule::CloseWebTransportSession { .. }, _)))
    );
    assert!(close_received);
    assert!(matches!(
      connect_read_failure_event(session_id, close_received),
      DispatcherEvent::ProtocolError(id) if id == session_id
    ));
    assert!(matches!(
      connect_read_failure_event(session_id, false),
      DispatcherEvent::SessionEnded(id) if id == session_id
    ));
  }

  #[test]
  fn complete_short_close_capsules_fail_without_waiting_for_eof() {
    for length in 0..4 {
      let capsule = Capsule::Unknown {
        typ: web_transport_proto::VarInt::from(0x2843_u16),
        payload: Bytes::from(vec![0; length]),
      };
      let mut encoded = Vec::new();
      capsule.encode(&mut encoded);
      assert!(matches!(
        decode_pending_capsule(&encoded),
        Err(web_transport_proto::CapsuleError::InvalidLength)
      ));
    }

    let mut valid = Vec::new();
    Capsule::CloseWebTransportSession {
      code: 0,
      reason: String::new(),
    }
    .encode(&mut valid);
    assert!(matches!(
      decode_pending_capsule(&valid),
      Ok(Some((Capsule::CloseWebTransportSession { .. }, _)))
    ));
    assert!(matches!(
      decode_pending_capsule(&valid[..valid.len() - 1]),
      Ok(None)
    ));
  }

  #[test]
  fn close_capsule_rejects_oversized_reason_and_extra_data() {
    assert!(matches!(
      validate_close_capsule(&"x".repeat(1025), 1031, 1031),
      Err(web_transport_proto::CapsuleError::MessageTooLong)
    ));
    assert!(matches!(
      validate_close_capsule("valid", 11, 12),
      Err(web_transport_proto::CapsuleError::InvalidLength)
    ));
    assert!(validate_close_capsule(&"x".repeat(1024), 1030, 1030).is_ok());

    let malformed = Capsule::Unknown {
      typ: web_transport_proto::VarInt::from(0x2843_u16),
      payload: Bytes::from_static(&[0, 0, 0, 0, 0xff]),
    };
    let mut encoded = Vec::new();
    malformed.encode(&mut encoded);
    assert!(matches!(
      decode_pending_capsule(&encoded),
      Err(web_transport_proto::CapsuleError::InvalidUtf8)
    ));
  }

  #[test]
  fn downstream_close_capsule_preserves_application_code_and_reason() {
    let encoded = encode_close_capsule(0x1234_5678, "upstream close reason");
    assert!(matches!(
      decode_pending_capsule(&encoded),
      Ok(Some((Capsule::CloseWebTransportSession { code: 0x1234_5678, reason }, used)))
        if reason == "upstream close reason" && used == encoded.len()
    ));
  }

  #[tokio::test]
  async fn reset_waits_for_busy_connect_stream_lock() {
    let stream = Arc::new(tokio::sync::Mutex::new(None));
    let held = stream.lock().await;
    let pending = tokio::spawn(stop_locked(stream.clone(), |slot| {
      *slot = Some(FLOW_ERROR_CODE)
    }));
    tokio::task::yield_now().await;
    assert!(!pending.is_finished());
    drop(held);
    pending.await.unwrap();
    assert_eq!(*stream.lock().await, Some(FLOW_ERROR_CODE));
  }

  #[test]
  fn unwritten_credit_does_not_allow_streams_or_data() {
    let flow = SessionFlow::new((0, 0, 0)).unwrap();
    flow.grant_initial(1, 1, 4).unwrap();
    assert_eq!(flow.incoming_open(false), Err(FlowError::Exceeded));
    assert_eq!(flow.incoming_data(1), Err(FlowError::Exceeded));
    while let Some((kind, value, _)) = flow.next_capsule() {
      flow.mark_sent(kind, value);
    }
    flow.incoming_open(false).unwrap();
    flow.incoming_data(4).unwrap();
    assert_eq!(flow.incoming_data(1), Err(FlowError::Exceeded));
    let (kind, value, _) = flow.next_capsule().unwrap();
    assert_eq!((kind, value), (WT_MAX_DATA, 8));
    flow.mark_sent(kind, value);
    flow.incoming_data(1).unwrap();
  }

  #[tokio::test]
  async fn draft16_session_credit_starts_at_zero_then_grants() {
    let flow = SessionFlow::new((0, 0, 0)).unwrap();
    assert!(
      tokio::time::timeout(std::time::Duration::from_millis(5), flow.open(false))
        .await
        .is_err()
    );
    let grant = FlowCredit::credit_capsule(WT_MAX_STREAMS_UNI, 1).unwrap();
    flow.apply_capsule(&grant).unwrap();
    flow.open(false).await.unwrap();
    assert_eq!(lock(&flow.outgoing).opened_uni, 1);
    assert!(
      tokio::time::timeout(std::time::Duration::from_millis(5), flow.open(false))
        .await
        .is_err()
    );
    assert_eq!(flow.apply_capsule(&grant), Err(FlowError::NonIncreasing));
  }

  #[test]
  fn draft16_body_and_reset_final_size_are_charged() {
    let flow = SessionFlow::new((0, 0, 0)).unwrap();
    flow.grant_initial(1, 1, 10).unwrap();
    assert_eq!(flow.incoming_open(false), Err(FlowError::Exceeded));
    while let Some((kind, value, _)) = flow.next_capsule() {
      flow.mark_sent(kind, value);
    }
    flow.incoming_open(false).unwrap();
    flow.incoming_data(2).unwrap();
    flow.incoming_reset(2, 14, 4).unwrap();
    assert_eq!(lock(&flow.incoming).used_data, 10);
    assert_eq!(lock(&flow.incoming).max_data, 10);
    flow.incoming_closed(false).unwrap();
    assert_eq!(flow.incoming_open(false), Err(FlowError::Exceeded));
    while let Some((kind, value, _)) = flow.next_capsule() {
      flow.mark_sent(kind, value);
    }
    assert_eq!(lock(&flow.incoming).max_data, 20);
    flow.incoming_open(false).unwrap();
    flow.incoming_data(10).unwrap();
    assert_eq!(lock(&flow.incoming).used_data, 20);
    assert_eq!(flow.incoming_data(11), Err(FlowError::Exceeded));
    assert_eq!(
      flow.incoming_reset(10, 13, 4),
      Err(FlowError::InvalidCapsule)
    );
    assert_eq!(lock(&flow.incoming).max_uni, 2);
  }
}

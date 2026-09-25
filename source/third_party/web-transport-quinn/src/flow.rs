use std::sync::{Arc, Mutex};

use tokio::sync::Notify;
use web_transport_proto::{Capsule, FlowCredit, FlowError, WT_MAX_DATA, WT_MAX_STREAMS_BIDI, WT_MAX_STREAMS_UNI};

pub(crate) struct SessionFlow {
    conn: quinn::Connection,
    pub outgoing: Mutex<FlowCredit>,
    pub incoming: Mutex<FlowCredit>,
    outgoing_wakers: Mutex<Vec<std::task::Waker>>,
    pub outgoing_notify: Notify,
    pub incoming_notify: Notify,
    desired: Mutex<(u64, u64, u64)>,
}

impl std::fmt::Debug for SessionFlow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SessionFlow").finish_non_exhaustive()
    }
}

impl SessionFlow {
    pub fn new(conn: quinn::Connection, peer: (u64, u64, u64)) -> Result<Arc<Self>, FlowError> {
        Ok(Arc::new(Self {
            conn,
            outgoing: Mutex::new(FlowCredit::new(peer.0, peer.1, peer.2)?),
            incoming: Mutex::new(FlowCredit::new(0, 0, 0)?),
            outgoing_wakers: Mutex::new(Vec::new()),
            outgoing_notify: Notify::new(),
            incoming_notify: Notify::new(),
            desired: Mutex::new((0, 0, 0)),
        }))
    }

    pub fn fail(&self) {
        self.conn.close(quinn::VarInt::try_from(web_transport_proto::WT_FLOW_CONTROL_ERROR).unwrap(), b"WebTransport flow control error");
    }

    pub fn grant_initial(&self, uni: u64, bidi: u64, data: u64) -> Result<(), FlowError> {
        if uni > web_transport_proto::MAX_STREAMS || bidi > web_transport_proto::MAX_STREAMS
            || data > web_transport_proto::VarInt::MAX.into_inner() {
            return Err(FlowError::Exceeded);
        }
        *self.desired.lock().unwrap() = (uni, bidi, data);
        self.incoming_notify.notify_one();
        Ok(())
    }

    pub fn received_capsule(&self, capsule: &Capsule) -> Result<bool, FlowError> {
        let result = self.outgoing.lock().unwrap().apply_capsule(capsule)?;
        if result {
            self.wake_outgoing();
            self.outgoing_notify.notify_waiters();
        }
        Ok(result)
    }

    pub fn register_outgoing(&self, waker: &std::task::Waker) {
        let mut waiters = self.outgoing_wakers.lock().unwrap();
        if !waiters.iter().any(|waiting| waiting.will_wake(waker)) {
            waiters.push(waker.clone());
        }
    }

    fn wake_outgoing(&self) {
        let wakers = std::mem::take(&mut *self.outgoing_wakers.lock().unwrap());
        for waker in wakers { waker.wake(); }
    }

    pub async fn open(&self, bidi: bool) -> Result<(), FlowError> {
        loop {
            let notified = self.outgoing_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let result = {
                let mut outgoing = self.outgoing.lock().unwrap();
                if bidi { outgoing.open_bidi() } else { outgoing.open_uni() }
            };
            match result {
                Ok(()) => return Ok(()),
                Err(FlowError::Exceeded) => notified.await,
                Err(error) => return Err(error),
            }
        }
    }

    pub fn next_capsule(&self) -> Option<(u64, u64, Capsule)> {
        let incoming = self.incoming.lock().unwrap();
        let desired = self.desired.lock().unwrap();
        if desired.0 > incoming.max_uni {
            return Some((WT_MAX_STREAMS_UNI, desired.0, FlowCredit::credit_capsule(WT_MAX_STREAMS_UNI, desired.0).ok()?));
        }
        if desired.1 > incoming.max_bidi {
            return Some((WT_MAX_STREAMS_BIDI, desired.1, FlowCredit::credit_capsule(WT_MAX_STREAMS_BIDI, desired.1).ok()?));
        }
        if desired.2 > incoming.max_data {
            return Some((WT_MAX_DATA, desired.2, FlowCredit::credit_capsule(WT_MAX_DATA, desired.2).ok()?));
        }
        None
    }

    pub fn mark_sent(&self, kind: u64, value: u64) {
        let mut incoming = self.incoming.lock().unwrap();
        match kind {
            WT_MAX_STREAMS_UNI => incoming.max_uni = value,
            WT_MAX_STREAMS_BIDI => incoming.max_bidi = value,
            WT_MAX_DATA => incoming.max_data = value,
            _ => unreachable!(),
        }
    }

    pub fn consumed_data(&self, n: u64) -> Result<(), FlowError> {
        let mut incoming = self.incoming.lock().unwrap();
        incoming.use_data(n)?;
        let mut desired = self.desired.lock().unwrap();
        desired.2 = desired.2.checked_add(n)
            .filter(|value| *value <= web_transport_proto::VarInt::MAX.into_inner())
            .ok_or(FlowError::Exceeded)?;
        drop(incoming);
        self.incoming_notify.notify_one();
        Ok(())
    }

    pub fn reset_final_size(&self, body_seen: u64, final_size: u64, header_size: u64) -> Result<(), FlowError> {
        let discarded = final_size.checked_sub(header_size)
            .and_then(|body| body.checked_sub(body_seen))
            .ok_or(FlowError::InvalidCapsule)?;
        let mut incoming = self.incoming.lock().unwrap();
        incoming.reset_final_size(body_seen, final_size, header_size)?;
        let mut desired = self.desired.lock().unwrap();
        desired.2 = desired.2.checked_add(discarded)
            .filter(|value| *value <= web_transport_proto::VarInt::MAX.into_inner())
            .ok_or(FlowError::Exceeded)?;
        drop(incoming);
        self.incoming_notify.notify_one();
        Ok(())
    }

    pub fn finished_stream(&self, bidi: bool) -> Result<(), FlowError> {
        let mut desired = self.desired.lock().unwrap();
        let limit = if bidi { &mut desired.1 } else { &mut desired.0 };
        *limit = limit.checked_add(1).filter(|v| *v <= web_transport_proto::MAX_STREAMS)
            .ok_or(FlowError::Exceeded)?;
        drop(desired);
        self.incoming_notify.notify_one();
        Ok(())
    }
}

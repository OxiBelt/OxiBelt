use std::future::Future;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::task::{Context, Poll};

use atomic_waker::AtomicWaker;
use bytes::{Buf, Bytes};
use futures_channel::{mpsc, oneshot};
use futures_core::{ready, Stream};
use h2::{Reason, RecvStream, SendStream};
use pin_project_lite::pin_project;

use super::ping::Recorder;
use super::SendBuf;
use crate::rt::{Read, ReadBufCursor, Write};

pub(crate) enum SendCommand {
    Data(Bytes),
    Finish,
}

pub(crate) struct ResetState {
    reason: Mutex<Option<Reason>>,
    task: AtomicWaker,
}

impl ResetState {
    fn new() -> Self {
        Self {
            reason: Mutex::new(None),
            task: AtomicWaker::new(),
        }
    }

    pub(crate) fn request(&self, reason: Reason) {
        if let Ok(mut pending) = self.reason.lock() {
            if pending.is_none() {
                *pending = Some(reason);
            }
        }
        self.task.wake();
    }

    fn take(&self) -> Option<Reason> {
        self.reason
            .lock()
            .ok()
            .and_then(|mut pending| pending.take())
    }

    fn register(&self, cx: &Context<'_>) {
        self.task.register(cx.waker());
    }
}

pub(super) fn pair<B>(
    send_stream: SendStream<SendBuf<B>>,
    recv_stream: RecvStream,
    ping: Recorder,
) -> (H2Upgraded, UpgradedSendStreamTask<B>) {
    let (tx, rx) = mpsc::channel(1);
    let (error_tx, error_rx) = oneshot::channel();
    let close_notify = Arc::new(UpgradedCloseNotify::new());
    let reset = Arc::new(ResetState::new());

    (
        H2Upgraded {
            send_stream: UpgradedSendStreamBridge {
                tx,
                error_rx,
                close_notify: close_notify.clone(),
            },
            recv_stream,
            ping,
            buf: Bytes::new(),
        },
        UpgradedSendStreamTask {
            h2_tx: send_stream,
            rx,
            close_notify,
            reset,
            buffered: None,
            error_tx: Some(error_tx),
        },
    )
}

pub(super) fn webtransport_pair<B>(
    send_stream: SendStream<SendBuf<B>>,
    recv_stream: RecvStream,
    local_settings: Option<crate::ext::WebTransportSettings>,
    peer_settings: Option<crate::ext::WebTransportSettings>,
) -> (crate::ext::WebTransportSession, UpgradedSendStreamTask<B>) {
    let (tx, rx) = mpsc::channel(1);
    let (error_tx, error_rx) = oneshot::channel();
    let reset = Arc::new(ResetState::new());
    (
        crate::ext::WebTransportSession::new(
            recv_stream,
            tx,
            error_rx,
            reset.clone(),
            local_settings,
            peer_settings,
        ),
        UpgradedSendStreamTask {
            h2_tx: send_stream,
            rx,
            close_notify: Arc::new(UpgradedCloseNotify::new()),
            reset,
            buffered: None,
            error_tx: Some(error_tx),
        },
    )
}

pub(super) struct H2Upgraded {
    ping: Recorder,
    send_stream: UpgradedSendStreamBridge,
    recv_stream: RecvStream,
    buf: Bytes,
}

struct UpgradedSendStreamBridge {
    tx: mpsc::Sender<SendCommand>,
    error_rx: oneshot::Receiver<crate::Error>,
    close_notify: Arc<UpgradedCloseNotify>,
}

impl Drop for UpgradedSendStreamBridge {
    fn drop(&mut self) {
        self.close_notify.close();
    }
}

struct UpgradedCloseNotify {
    closed: AtomicBool,
    task: AtomicWaker,
}

impl UpgradedCloseNotify {
    fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            task: AtomicWaker::new(),
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.task.wake();
    }

    fn poll_closed(&self, cx: &mut Context<'_>) -> Poll<()> {
        if self.closed.load(Ordering::Acquire) {
            return Poll::Ready(());
        }

        self.task.register(cx.waker());

        if self.closed.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

pin_project! {
    #[must_use = "futures do nothing unless polled"]
    pub struct UpgradedSendStreamTask<B> {
        #[pin]
        h2_tx: SendStream<SendBuf<B>>,
        #[pin]
        rx: mpsc::Receiver<SendCommand>,
        close_notify: Arc<UpgradedCloseNotify>,
        reset: Arc<ResetState>,
        buffered: Option<Cursor<Box<[u8]>>>,
        error_tx: Option<oneshot::Sender<crate::Error>>,
    }
}

// ===== impl UpgradedSendStreamTask =====

impl<B> UpgradedSendStreamTask<B>
where
    B: Buf,
{
    fn tick(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), crate::Error>> {
        let mut me = self.project();

        // this is a manual `select()` over 3 "futures", so we always need
        // to be sure they are ready and/or we are waiting notification of
        // one of the sides hanging up, so the task doesn't live around
        // longer than it's meant to.
        loop {
            if let Some(reason) = me.reset.take() {
                me.h2_tx.send_reset(reason);
                return Poll::Ready(Ok(()));
            }
            me.reset.register(cx);
            if let Some(reason) = me.reset.take() {
                me.h2_tx.send_reset(reason);
                return Poll::Ready(Ok(()));
            }
            match me.h2_tx.poll_reset(cx) {
                Poll::Ready(Ok(reason)) => {
                    trace!("stream received RST_STREAM: {:?}", reason);
                    return Poll::Ready(Err(crate::Error::new_body_write(::h2::Error::from(
                        reason,
                    ))));
                }
                Poll::Ready(Err(err)) => {
                    return Poll::Ready(Err(crate::Error::new_body_write(err)))
                }
                Poll::Pending => (),
            }

            // An accepted payload waits here for h2 credit; no further channel
            // item is taken while it is buffered. ResetState remains independently
            // wakeable, even when both this slot and the payload channel are full.
            if me.buffered.is_some() {
                let _ = me.close_notify.poll_closed(cx);
                while me.h2_tx.capacity() == 0 {
                    match ready!(me.h2_tx.poll_capacity(cx)) {
                        Some(Ok(0)) => {}
                        Some(Ok(_)) => break,
                        Some(Err(e)) => return Poll::Ready(Err(crate::Error::new_body_write(e))),
                        None => {
                            return Poll::Ready(Err(crate::Error::new_body_write(
                                "send stream capacity unexpectedly closed",
                            )))
                        }
                    }
                }
                let cursor = me.buffered.take().expect("checked is_some above");
                me.h2_tx
                    .send_data(SendBuf::Cursor(cursor), false)
                    .map_err(crate::Error::new_body_write)?;
                continue;
            }

            match me.rx.as_mut().poll_next(cx) {
                Poll::Ready(Some(SendCommand::Data(data))) => {
                    // Do not pin connection-level send credit while idle.
                    me.h2_tx.reserve_capacity(1);
                    *me.buffered = Some(Cursor::new(data.to_vec().into_boxed_slice()));
                }
                Poll::Ready(Some(SendCommand::Finish)) => {
                    me.h2_tx
                        .send_data(SendBuf::None, true)
                        .map_err(crate::Error::new_body_write)?;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(None) => {
                    me.h2_tx
                        .send_data(SendBuf::None, true)
                        .map_err(crate::Error::new_body_write)?;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_request_preempts_a_full_payload_channel() {
        let (mut payload, _receiver) = mpsc::channel(1);
        let mut full = false;
        for _ in 0..8 {
            if payload
                .try_send(SendCommand::Data(Bytes::from_static(b"blocked")))
                .is_err()
            {
                full = true;
                break;
            }
        }
        assert!(full);

        let reset = ResetState::new();
        reset.request(Reason::FLOW_CONTROL_ERROR);
        assert_eq!(reset.take(), Some(Reason::FLOW_CONTROL_ERROR));
    }
    async fn task_pair(
        window: u32,
    ) -> (
        H2Upgraded,
        UpgradedSendStreamTask<Bytes>,
        RecvStream,
        [tokio::task::JoinHandle<()>; 2],
    ) {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let client_builder = h2::client::Builder::new();
        let mut server_builder = h2::server::Builder::new();
        server_builder.initial_window_size(window);
        let (client, server) = tokio::join!(
            client_builder.handshake::<_, SendBuf<Bytes>>(client_io),
            server_builder.handshake::<_, Bytes>(server_io),
        );
        let (sender, connection) = client.unwrap();
        let client_driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut server = server.unwrap();
        let (peer_tx, peer_rx) = oneshot::channel();
        let server_driver = tokio::spawn(async move {
            let mut accepted = Vec::new();
            let mut peer_tx = Some(peer_tx);
            while let Some(Ok((request, mut respond))) = server.accept().await {
                let send = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                let body = request.into_body();
                if let Some(tx) = peer_tx.take() {
                    let _ = tx.send(body);
                    accepted.push(send);
                }
            }
        });
        let mut sender = sender.ready().await.unwrap();
        let request = http::Request::builder()
            .uri("https://example.test/")
            .body(())
            .unwrap();
        let (response, send) = sender.send_request(request, false).unwrap();
        let recv = response.await.unwrap().into_body();
        let (upgraded, task) = pair(send, recv, super::super::ping::disabled());
        (
            upgraded,
            task,
            peer_rx.await.unwrap(),
            [client_driver, server_driver],
        )
    }

    #[tokio::test]
    async fn idle_upgrade_does_not_reserve_send_credit() {
        let (_upgraded, mut task, _peer, drivers) =
            tokio::time::timeout(std::time::Duration::from_secs(1), task_pair(65_535))
                .await
                .unwrap();
        assert_eq!(task.h2_tx.capacity(), 0);
        futures_util::future::poll_fn(|cx| {
            assert!(Pin::new(&mut task).tick(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(
            task.h2_tx.capacity(),
            0,
            "idle upgraded streams must not pin connection credit"
        );
        for driver in drivers {
            driver.abort();
        }
    }

    #[tokio::test]
    async fn reset_preempts_buffered_payload_without_peer_credit() {
        let (mut upgraded, mut task, _peer, drivers) =
            tokio::time::timeout(std::time::Duration::from_secs(1), task_pair(0))
                .await
                .unwrap();
        upgraded
            .send_stream
            .tx
            .try_send(SendCommand::Data(Bytes::from_static(b"blocked")))
            .unwrap();
        futures_util::future::poll_fn(|cx| {
            assert!(Pin::new(&mut task).tick(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert!(task.buffered.is_some());
        let mut full = false;
        for _ in 0..8 {
            if upgraded
                .send_stream
                .tx
                .try_send(SendCommand::Data(Bytes::from_static(b"queued")))
                .is_err()
            {
                full = true;
                break;
            }
        }
        assert!(full, "the accepted payload queue remains bounded");
        task.reset.request(Reason::CANCEL);
        futures_util::future::poll_fn(|cx| {
            assert!(matches!(Pin::new(&mut task).tick(cx), Poll::Ready(Ok(()))));
            Poll::Ready(())
        })
        .await;
        for driver in drivers {
            driver.abort();
        }
    }

    #[tokio::test]
    async fn finish_without_payload_does_not_wait_for_peer_credit() {
        let (mut upgraded, mut task, _peer, drivers) =
            tokio::time::timeout(std::time::Duration::from_secs(1), task_pair(0))
                .await
                .unwrap();
        upgraded
            .send_stream
            .tx
            .try_send(SendCommand::Finish)
            .unwrap();
        futures_util::future::poll_fn(|cx| {
            assert!(matches!(Pin::new(&mut task).tick(cx), Poll::Ready(Ok(()))));
            Poll::Ready(())
        })
        .await;
        for driver in drivers {
            driver.abort();
        }
    }
    #[tokio::test]
    async fn accepted_payload_precedes_fin_on_the_wire() {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            let (mut upgraded, mut task, mut peer, drivers) = task_pair(65_535).await;
            upgraded
                .send_stream
                .tx
                .try_send(SendCommand::Data(Bytes::from_static(b"payload")))
                .unwrap();
            upgraded
                .send_stream
                .tx
                .try_send(SendCommand::Finish)
                .unwrap();
            futures_util::future::poll_fn(|cx| Pin::new(&mut task).tick(cx))
                .await
                .unwrap();
            let mut received = Vec::new();
            while let Some(chunk) = peer.data().await {
                received.extend_from_slice(&chunk.unwrap());
            }
            assert_eq!(received, b"payload");
            for driver in drivers {
                driver.abort();
            }
        })
        .await
        .expect("accepted payload and FIN must make progress in order");
    }
}

impl<B> Future for UpgradedSendStreamTask<B>
where
    B: Buf,
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.as_mut().tick(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(()),
            Poll::Ready(Err(err)) => {
                if let Some(tx) = self.error_tx.take() {
                    let _oh_well = tx.send(err);
                }
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

// ===== impl H2Upgraded =====

impl Read for H2Upgraded {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut read_buf: ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if self.buf.is_empty() {
            self.buf = loop {
                match ready!(self.recv_stream.poll_data(cx)) {
                    None => return Poll::Ready(Ok(())),
                    Some(Ok(buf)) if buf.is_empty() && !self.recv_stream.is_end_stream() => {}
                    Some(Ok(buf)) => {
                        self.ping.record_data(buf.len());
                        break buf;
                    }
                    Some(Err(e)) => {
                        return Poll::Ready(match e.reason() {
                            Some(Reason::NO_ERROR) | Some(Reason::CANCEL) => Ok(()),
                            Some(Reason::STREAM_CLOSED) => {
                                Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
                            }
                            _ => Err(h2_to_io_error(e)),
                        })
                    }
                }
            };
        }
        let cnt = std::cmp::min(self.buf.len(), read_buf.remaining());
        read_buf.put_slice(&self.buf[..cnt]);
        self.buf.advance(cnt);
        let _ = self.recv_stream.flow_control().release_capacity(cnt);
        Poll::Ready(Ok(()))
    }
}

impl Write for H2Upgraded {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        match self.send_stream.tx.poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(_task_dropped)) => {
                // if the task dropped, check if there was an error
                // otherwise i guess its a broken pipe
                return match Pin::new(&mut self.send_stream.error_rx).poll(cx) {
                    Poll::Ready(Ok(reason)) => Poll::Ready(Err(io_error(reason))),
                    Poll::Ready(Err(_task_dropped)) => {
                        Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
                    }
                    Poll::Pending => Poll::Pending,
                };
            }
            Poll::Pending => return Poll::Pending,
        }

        let n = buf.len();
        match self
            .send_stream
            .tx
            .start_send(SendCommand::Data(Bytes::copy_from_slice(buf)))
        {
            Ok(()) => Poll::Ready(Ok(n)),
            Err(_task_dropped) => {
                // if the task dropped, check if there was an error
                // otherwise i guess its a broken pipe
                match Pin::new(&mut self.send_stream.error_rx).poll(cx) {
                    Poll::Ready(Ok(reason)) => Poll::Ready(Err(io_error(reason))),
                    Poll::Ready(Err(_task_dropped)) => {
                        Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.send_stream.tx.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(_task_dropped)) => {
                // if the task dropped, check if there was an error
                // otherwise it was a clean close
                match Pin::new(&mut self.send_stream.error_rx).poll(cx) {
                    Poll::Ready(Ok(reason)) => Poll::Ready(Err(io_error(reason))),
                    Poll::Ready(Err(_task_dropped)) => Poll::Ready(Ok(())),
                    Poll::Pending => Poll::Pending,
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.send_stream.tx.close_channel();
        self.send_stream.close_notify.close();
        match Pin::new(&mut self.send_stream.error_rx).poll(cx) {
            Poll::Ready(Ok(reason)) => Poll::Ready(Err(io_error(reason))),
            Poll::Ready(Err(_task_dropped)) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn io_error(e: crate::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

fn h2_to_io_error(e: h2::Error) -> std::io::Error {
    if e.is_io() {
        e.into_io()
            .expect("h2 error reported io cause without an underlying io error")
    } else {
        std::io::Error::new(std::io::ErrorKind::Other, e)
    }
}

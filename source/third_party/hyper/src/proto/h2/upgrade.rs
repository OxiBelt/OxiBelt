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
        self.reason.lock().ok().and_then(|mut pending| pending.take())
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
            // we don't have the next chunk of data yet, so just reserve 1 byte to make
            // sure there's some capacity available. h2 will handle the capacity management
            // for the actual body chunk.
            me.h2_tx.reserve_capacity(1);

            let h2_has_capacity = if me.h2_tx.capacity() == 0 {
                // poll_capacity oddly needs a loop
                loop {
                    match me.h2_tx.poll_capacity(cx) {
                        Poll::Ready(Some(Ok(0))) => {}
                        Poll::Ready(Some(Ok(_))) => break true,
                        Poll::Ready(Some(Err(e))) => {
                            return Poll::Ready(Err(crate::Error::new_body_write(e)))
                        }
                        Poll::Ready(None) => {
                            // None means the stream is no longer in a
                            // streaming state, we either finished it
                            // somehow, or the remote reset us.
                            return Poll::Ready(Err(crate::Error::new_body_write(
                                "send stream capacity unexpectedly closed",
                            )));
                        }
                        Poll::Pending => break false,
                    }
                }
            } else {
                true
            };

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

            // If h2 has no capacity, don't pull another item from the mpsc
            // receiver. That would free a channel slot and let the writer
            // enqueue more data without h2 backpressure.
            //
            // Still allow the task to finish once the upgraded write side is
            // gone and the mpsc queue is empty.
            if !h2_has_capacity {
                // `size_hint` reads the queued message count without popping,
                // so an accepted write stays queued until h2 capacity returns.
                if me.rx.size_hint().0 == 0 && me.close_notify.poll_closed(cx).is_ready() {
                    me.h2_tx
                        .send_data(SendBuf::None, true)
                        .map_err(crate::Error::new_body_write)?;
                    return Poll::Ready(Ok(()));
                }

                return Poll::Pending;
            }

            match me.rx.as_mut().poll_next(cx) {
                Poll::Ready(Some(SendCommand::Data(data))) => {
                    me.h2_tx
                        .send_data(
                            SendBuf::Cursor(Cursor::new(data.to_vec().into_boxed_slice())),
                            false,
                        )
                        .map_err(crate::Error::new_body_write)?;
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

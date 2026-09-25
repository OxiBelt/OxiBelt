use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{ready, Context, Poll},
};

use bytes::Bytes;
use crate::flow::SessionFlow;

#[derive(Debug)]
struct ReceiveFlow {
    flow: Arc<SessionFlow>,
    header_size: u64,
    body_seen: u64,
    bidi: bool,
    complete: bool,
}

use crate::{ReadError, ReadExactError, ReadToEndError, SessionError};

/// A stream that can be used to recieve bytes. See [`quinn::RecvStream`].
#[derive(Debug)]
pub struct RecvStream {
    inner: quinn::RecvStream,
    error: Arc<OnceLock<SessionError>>,
    flow: Option<ReceiveFlow>,
    association_header_size: Option<u64>,
}

impl RecvStream {
    pub(crate) fn new(stream: quinn::RecvStream, error: Arc<OnceLock<SessionError>>) -> Self {
        Self {
            inner: stream,
            error,
            flow: None,
            association_header_size: None,
        }
    }

    pub(crate) fn with_association_header_size(mut self, size: u64) -> Self {
        self.association_header_size = Some(size);
        self
    }

    pub(crate) fn set_flow(&mut self, flow: Arc<SessionFlow>, bidi: bool) -> Result<(), web_transport_proto::FlowError> {
        let header_size = self.association_header_size.ok_or(web_transport_proto::FlowError::InvalidCapsule)?;
        let mut incoming = flow.incoming.lock().unwrap();
        let result = if bidi { incoming.open_bidi() } else { incoming.open_uni() };
        drop(incoming);
        result?;
        self.flow = Some(ReceiveFlow { flow, header_size, body_seen: 0, bidi, complete: false });
        Ok(())
    }

    fn account_read(&mut self, bytes: usize, completed: bool) -> io::Result<()> {
        let Some(state) = self.flow.as_mut() else { return Ok(()); };
        if state.complete { return Ok(()); }
        if bytes > 0 {
            state.body_seen = state.body_seen.checked_add(bytes as u64)
                .ok_or_else(|| io::Error::other("WebTransport body accounting overflow"))?;
            if let Err(err) = state.flow.consumed_data(bytes as u64) {
                state.flow.fail();
                return Err(io::Error::other(format!("WebTransport flow control: {err:?}")));
            }
        }
        if completed {
            state.complete = true;
            if let Err(err) = state.flow.finished_stream(state.bidi) {
                state.flow.fail();
                return Err(io::Error::other(format!("WebTransport flow control: {err:?}")));
            }
        }
        Ok(())
    }

    fn account_reset(&mut self) -> io::Result<()> {
        let Some(info) = self.inner.reset_info() else { return Ok(()); };
        let Some(state) = self.flow.as_mut() else { return Ok(()); };
        if state.complete { return Ok(()); }
        if let Err(err) = state.flow.reset_final_size(state.body_seen, info.final_size, state.header_size) {
            state.flow.fail();
            return Err(io::Error::other(format!("WebTransport reset final-size flow control: {err:?}")));
        }
        state.complete = true;
        if let Err(err) = state.flow.finished_stream(state.bidi) {
            state.flow.fail();
            return Err(io::Error::other(format!("WebTransport flow control: {err:?}")));
        }
        Ok(())
    }

    /// Replace connection-level errors with the stored session error if available.
    fn map_error(&self, e: impl Into<ReadError>) -> ReadError {
        let e = e.into();
        if let Some(err) = self.error.get() {
            if matches!(&e, ReadError::SessionError(_) | ReadError::InvalidReset(_)) {
                return ReadError::SessionError(err.clone());
            }
        }
        e
    }

    /// Tell the other end to stop sending data with the given error code. See [`quinn::RecvStream::stop`].
    /// This is a u32 with WebTransport since it shares the error space with HTTP/3.
    pub fn stop(&mut self, code: u32) -> Result<(), quinn::ClosedStream> {
        let code = web_transport_proto::error_to_http3(code);
        let code = quinn::VarInt::try_from(code).unwrap();
        self.inner.stop(code)
    }

    // Unfortunately, we have to wrap ReadError for a bunch of functions.

    /// Read some data into the buffer and return the amount read. See [`quinn::RecvStream::read`].
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ReadError> {
        let result = self.inner.read(buf).await.map_err(|e| self.map_error(e));
        match &result {
            Ok(Some(n)) => { if self.account_read(*n, false).is_err() { return Err(ReadError::SessionError(quinn::ConnectionError::LocallyClosed.into())); } }
            Ok(None) => { if self.account_read(0, true).is_err() { return Err(ReadError::SessionError(quinn::ConnectionError::LocallyClosed.into())); } }
            Err(_) => { if self.account_reset().is_err() { return Err(ReadError::SessionError(quinn::ConnectionError::LocallyClosed.into())); } }
        }
        result
    }

    /// Fill the entire buffer with data. See [`quinn::RecvStream::read_exact`].
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ReadExactError> {
        if self.flow.is_some() {
            let mut offset = 0;
            while offset < buf.len() {
                match self.read(&mut buf[offset..]).await? {
                    Some(n) => offset += n,
                    None => return Err(ReadExactError::FinishedEarly(offset)),
                }
            }
            Ok(())
        } else {
            self.inner.read_exact(buf).await.map_err(|e| match e {
                quinn::ReadExactError::ReadError(e) => self.map_error(e).into(),
                e => e.into(),
            })
        }
    }

    /// Read a chunk of data from the stream. See [`quinn::RecvStream::read_chunk`].
    pub async fn read_chunk(
        &mut self,
        max_length: usize,
        ordered: bool,
    ) -> Result<Option<quinn::Chunk>, ReadError> {
        let result = self.inner.read_chunk(max_length, ordered).await.map_err(|e| self.map_error(e));
        match &result {
            Ok(Some(chunk)) => { if self.account_read(chunk.bytes.len(), false).is_err() { return Err(ReadError::SessionError(quinn::ConnectionError::LocallyClosed.into())); } }
            Ok(None) => { if self.account_read(0, true).is_err() { return Err(ReadError::SessionError(quinn::ConnectionError::LocallyClosed.into())); } }
            Err(_) => { if self.account_reset().is_err() { return Err(ReadError::SessionError(quinn::ConnectionError::LocallyClosed.into())); } }
        }
        result
    }

    /// Read chunks of data from the stream. See [`quinn::RecvStream::read_chunks`].
    pub async fn read_chunks(&mut self, bufs: &mut [Bytes]) -> Result<Option<usize>, ReadError> {
        if self.flow.is_some() {
            if bufs.is_empty() { return Ok(Some(0)); }
            match self.read_chunk(usize::MAX, true).await? {
                Some(chunk) => { bufs[0] = chunk.bytes; Ok(Some(1)) }
                None => Ok(None),
            }
        } else {
            self.inner.read_chunks(bufs).await.map_err(|e| self.map_error(e))
        }
    }

    /// Read until the end of the stream or the limit is hit. See [`quinn::RecvStream::read_to_end`].
    pub async fn read_to_end(&mut self, size_limit: usize) -> Result<Vec<u8>, ReadToEndError> {
        if self.flow.is_some() {
            let mut out = Vec::new();
            let mut buf = [0u8; 16 * 1024];
            loop {
                match self.read(&mut buf).await? {
                    Some(n) => {
                        if out.len().checked_add(n).is_none_or(|length| length > size_limit) { return Err(ReadToEndError::TooLong); }
                        out.extend_from_slice(&buf[..n]);
                    }
                    None => return Ok(out),
                }
            }
        } else {
            self.inner.read_to_end(size_limit).await.map_err(|e| match e {
                quinn::ReadToEndError::Read(e) => self.map_error(e).into(),
                e => e.into(),
            })
        }
    }

    /// Block until the stream has been reset and return the error code. See [`quinn::RecvStream::received_reset`].
    ///
    /// Unlike Quinn, this returns a SessionError, not a ResetError, because 0-RTT is not supported.
    pub async fn received_reset(&mut self) -> Result<Option<u32>, SessionError> {
        match self.inner.received_reset().await {
            Ok(None) => Ok(None),
            Ok(Some(code)) => {
                if self.account_reset().is_err() {
                    return Err(quinn::ConnectionError::LocallyClosed.into());
                }
                Ok(web_transport_proto::error_from_http3(code.into_inner()))
            }
            Err(quinn::ResetError::ConnectionLost(conn_err)) => {
                Err(self.error.get().cloned().unwrap_or_else(|| conn_err.into()))
            }
            Err(quinn::ResetError::ZeroRttRejected) => unreachable!("0-RTT not supported"),
        }
    }

    /// Return the underlying QUIC stream ID.
    ///
    /// > **Warning**
    /// >
    /// > WebTransport sessions share the QUIC connection with HTTP/3 and potentially other sessions.
    /// > The [quinn::StreamId::index] might not increment by 1 like expected when using [quinn].
    /// > This is why the Javascript WebTransport API does not expose the Stream ID.
    pub fn quic_id(&self) -> quinn::StreamId {
        self.inner.id()
    }

    /// QUIC final size, including the WebTransport association header, when
    /// this stream was reset. It remains available after a partial read.
    pub fn reset_info(&self) -> Option<quinn::ResetInfo> {
        self.inner.reset_info()
    }

    // We purposely don't expose the 0RTT because it's not valid with WebTransport
}

impl tokio::io::AsyncRead for RecvStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 { return Poll::Ready(Ok(())); }
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let read = buf.filled().len() - before;
                Poll::Ready(self.account_read(read, read == 0))
            }
            Poll::Ready(Err(error)) => {
                if let Err(flow_error) = self.account_reset() { Poll::Ready(Err(flow_error)) }
                else { Poll::Ready(Err(error)) }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl web_transport_trait::RecvStream for RecvStream {
    type Error = ReadError;

    fn stop(&mut self, code: u32) {
        Self::stop(self, code).ok();
    }

    async fn read(&mut self, dst: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        self.read(dst).await
    }

    async fn read_chunk(&mut self, max: usize) -> Result<Option<Bytes>, Self::Error> {
        self.read_chunk(max, true)
            .await
            .map(|r| r.map(|chunk| chunk.bytes))
    }

    async fn closed(&mut self) -> Result<(), Self::Error> {
        self.received_reset().await?;
        Ok(())
    }
}

impl web_transport_trait::poll::RecvStream for RecvStream {
    type Error = ReadError;

    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        dst: &mut [u8],
    ) -> Poll<Result<Option<usize>, Self::Error>> {
        if dst.is_empty() {
            // Asking for no bytes is not end of stream.
            return Poll::Ready(Ok(Some(0)));
        }

        let size = match ready!(quinn::RecvStream::poll_read(&mut self.inner, cx, dst)) {
            Ok(size) => size,
            Err(error) => {
                if self.account_reset().is_err() {
                    return Poll::Ready(Err(ReadError::SessionError(quinn::ConnectionError::LocallyClosed.into())));
                }
                return Poll::Ready(Err(self.map_error(error)));
            }
        };
        if self.account_read(size, size == 0).is_err() {
            return Poll::Ready(Err(ReadError::SessionError(quinn::ConnectionError::LocallyClosed.into())));
        }

        // Quinn reports a finished stream as zero bytes into a non-empty buffer.
        Poll::Ready(Ok((size != 0).then_some(size)))
    }

    fn stop(&mut self, code: u32) {
        Self::stop(self, code).ok();
    }

    fn poll_closed(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Nothing to retain: Quinn parks this waker in the connection's
        // `blocked_readers` map keyed by stream ID, not inside the future, so the
        // registration outlives the future we build here and drop again.
        let mut reset = std::pin::pin!(self.received_reset());
        ready!(reset.as_mut().poll(cx))?;
        Poll::Ready(Ok(()))
    }
}

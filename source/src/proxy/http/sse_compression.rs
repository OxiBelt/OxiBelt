//! SSE-aware write-side compression shared by HTTP response producers.

use std::io;

use async_compression::Level as CompressionLevel;
use async_compression::tokio::write::{GzipEncoder, ZlibEncoder};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

use super::body::{BoxError, ProxyBody, boxed_error};

/// A downstream content-coding supported by SSE streaming compression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SseCompressionCoding {
  Br,
  Zstd,
  Gzip,
  Deflate,
}

enum Encoder<W> {
  Br(Box<StreamingBrotliEncoder<W>>),
  Zstd(Box<StreamingZstdEncoder<W>>),
  Gzip(GzipEncoder<W>),
  Deflate(ZlibEncoder<W>),
}

struct StreamingZstdEncoder<W> {
  writer: W,
  encoder: Option<zstd::stream::write::Encoder<'static, Vec<u8>>>,
  initialization_error: Option<io::Error>,
  level: u8,
  frame_has_input: bool,
}

impl<W: AsyncWrite + Unpin> StreamingZstdEncoder<W> {
  fn new(writer: W, level: u8) -> Self {
    match zstd::stream::write::Encoder::new(Vec::new(), i32::from(level)) {
      Ok(encoder) => Self {
        writer,
        encoder: Some(encoder),
        initialization_error: None,
        level,
        frame_has_input: false,
      },
      Err(error) => Self {
        writer,
        encoder: None,
        initialization_error: Some(error),
        level,
        frame_has_input: false,
      },
    }
  }

  async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
    std::io::Write::write_all(self.encoder()?, bytes)?;
    self.frame_has_input |= !bytes.is_empty();
    self.drain_output().await
  }

  async fn flush(&mut self) -> io::Result<()> {
    if self.frame_has_input {
      let output = self.take_encoder()?.finish()?;
      self.encoder = Some(zstd::stream::write::Encoder::new(
        Vec::new(),
        i32::from(self.level),
      )?);
      self.frame_has_input = false;
      self.writer.write_all(&output).await?;
    }
    self.writer.flush().await
  }

  async fn shutdown(&mut self) -> io::Result<()> {
    if self.frame_has_input {
      let output = self.take_encoder()?.finish()?;
      self.frame_has_input = false;
      self.writer.write_all(&output).await?;
    } else {
      let _ = self.take_encoder()?;
    }
    self.writer.shutdown().await
  }

  async fn drain_output(&mut self) -> io::Result<()> {
    let output = std::mem::take(self.encoder()?.get_mut());
    self.writer.write_all(&output).await
  }

  fn encoder(&mut self) -> io::Result<&mut zstd::stream::write::Encoder<'static, Vec<u8>>> {
    if let Some(error) = self.initialization_error.take() {
      return Err(error);
    }
    self
      .encoder
      .as_mut()
      .ok_or_else(|| io::Error::other("Zstandard encoder was already finalized"))
  }

  fn take_encoder(&mut self) -> io::Result<zstd::stream::write::Encoder<'static, Vec<u8>>> {
    if let Some(error) = self.initialization_error.take() {
      return Err(error);
    }
    self
      .encoder
      .take()
      .ok_or_else(|| io::Error::other("Zstandard encoder was already finalized"))
  }
}

struct StreamingBrotliEncoder<W> {
  writer: W,
  encoder: Option<brotli::CompressorWriter<Vec<u8>>>,
}

impl<W: AsyncWrite + Unpin> StreamingBrotliEncoder<W> {
  fn new(writer: W, level: u8) -> Self {
    Self {
      writer,
      encoder: Some(brotli::CompressorWriter::new(
        Vec::new(),
        4 * 1024,
        u32::from(level),
        22,
      )),
    }
  }

  async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
    std::io::Write::write_all(
      self
        .encoder
        .as_mut()
        .ok_or_else(|| io::Error::other("Brotli encoder was already finalized"))?,
      bytes,
    )?;
    self.drain_output().await
  }

  async fn flush(&mut self) -> io::Result<()> {
    std::io::Write::flush(
      self
        .encoder
        .as_mut()
        .ok_or_else(|| io::Error::other("Brotli encoder was already finalized"))?,
    )?;
    self.drain_output().await?;
    self.writer.flush().await
  }

  async fn shutdown(&mut self) -> io::Result<()> {
    let encoder = self
      .encoder
      .take()
      .ok_or_else(|| io::Error::other("Brotli encoder was already finalized"))?;
    let output = encoder.into_inner();
    self.writer.write_all(&output).await?;
    self.writer.shutdown().await
  }

  async fn drain_output(&mut self) -> io::Result<()> {
    let output = std::mem::take(
      self
        .encoder
        .as_mut()
        .ok_or_else(|| io::Error::other("Brotli encoder was already finalized"))?
        .get_mut(),
    );
    self.writer.write_all(&output).await
  }
}

impl<W: AsyncWrite + Unpin> Encoder<W> {
  async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
    match self {
      Self::Br(encoder) => encoder.write_all(bytes).await,
      Self::Zstd(encoder) => encoder.write_all(bytes).await,
      Self::Gzip(encoder) => encoder.write_all(bytes).await,
      Self::Deflate(encoder) => encoder.write_all(bytes).await,
    }
  }

  async fn flush(&mut self) -> io::Result<()> {
    match self {
      Self::Br(encoder) => encoder.flush().await,
      Self::Zstd(encoder) => encoder.flush().await,
      Self::Gzip(encoder) => encoder.flush().await,
      Self::Deflate(encoder) => encoder.flush().await,
    }
  }

  async fn shutdown(&mut self) -> io::Result<()> {
    match self {
      Self::Br(encoder) => encoder.shutdown().await,
      Self::Zstd(encoder) => encoder.shutdown().await,
      Self::Gzip(encoder) => encoder.shutdown().await,
      Self::Deflate(encoder) => encoder.shutdown().await,
    }
  }
}

/// Incrementally compresses SSE bytes and flushes each complete event.
///
/// A `write_all` call may end between the bytes of CRLF. CR is already a
/// complete SSE line ending, so it is written and observed immediately; the
/// scanner only remembers to fold an immediately following LF into that same
/// terminator. Writes are split into bounded chunks so an async writer's
/// backpressure remains observable to the source producer.
pub(crate) struct SseCompressionEncoder<W> {
  encoder: Encoder<W>,
  previous_line_ended: bool,
  previous_was_cr: bool,
  previous_cr_finished_event: bool,
}

impl<W: AsyncWrite + Unpin> SseCompressionEncoder<W> {
  pub(crate) fn new(writer: W, coding: SseCompressionCoding, level: u8) -> Self {
    let quality = CompressionLevel::Precise(i32::from(level));
    let encoder = match coding {
      SseCompressionCoding::Br => Encoder::Br(Box::new(StreamingBrotliEncoder::new(writer, level))),
      SseCompressionCoding::Zstd => {
        Encoder::Zstd(Box::new(StreamingZstdEncoder::new(writer, level)))
      }
      SseCompressionCoding::Gzip => Encoder::Gzip(GzipEncoder::with_quality(writer, quality)),
      SseCompressionCoding::Deflate => Encoder::Deflate(ZlibEncoder::with_quality(writer, quality)),
    };
    Self {
      encoder,
      previous_line_ended: false,
      previous_was_cr: false,
      previous_cr_finished_event: false,
    }
  }

  /// Writes source bytes and flushes after every LF, CRLF, or CR blank line.
  pub(crate) async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
    // Empty HTTP DATA frames do not separate adjacent source bytes. Keep the
    // CRLF-folding state so a later LF still belongs to the preceding CR.
    if bytes.is_empty() {
      return Ok(());
    }
    let mut index = 0;
    while index < bytes.len() {
      if self.previous_was_cr {
        self.previous_was_cr = false;
        if bytes[index] == b'\n' {
          self.write_bytes(b"\n").await?;
          if self.previous_cr_finished_event {
            self.flush_record().await?;
          }
          self.previous_cr_finished_event = false;
          index += 1;
          continue;
        }
        self.previous_cr_finished_event = false;
      }
      let start = index;
      while index < bytes.len() && !matches!(bytes[index], b'\r' | b'\n') {
        index += 1;
      }
      if start != index {
        self.write_bytes(&bytes[start..index]).await?;
        self.previous_line_ended = false;
      }
      if index == bytes.len() {
        break;
      }

      match bytes[index] {
        b'\n' => {
          self.write_bytes(b"\n").await?;
          self.finish_line().await?;
          index += 1;
        }
        b'\r' => {
          self.write_bytes(b"\r").await?;
          self.previous_cr_finished_event = self.previous_line_ended;
          self.finish_line().await?;
          self.previous_was_cr = true;
          index += 1;
        }
        _ => unreachable!("SSE scanner only stops at line endings"),
      }
    }
    Ok(())
  }

  /// Forces all bytes accepted so far through the selected content-coding.
  pub(crate) async fn flush_record(&mut self) -> io::Result<()> {
    self.encoder.flush().await
  }

  /// Completes the coding stream after the caller has observed clean source EOF.
  pub(crate) async fn shutdown(&mut self) -> io::Result<()> {
    self.encoder.shutdown().await
  }

  async fn write_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
    const MAX_WRITE_BYTES: usize = 16 * 1024;
    for chunk in bytes.chunks(MAX_WRITE_BYTES) {
      self.encoder.write_all(chunk).await?;
    }
    Ok(())
  }

  async fn finish_line(&mut self) -> io::Result<()> {
    if self.previous_line_ended {
      self.previous_line_ended = false;
      self.flush_record().await?;
    } else {
      self.previous_line_ended = true;
    }
    Ok(())
  }
}

/// Selects when the body adapter forces a compression flush in addition to
/// normal SSE blank-line boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SseFlushBoundary {
  Event,
  EveryFrame,
}

/// Converts a `ProxyBody` to a bounded, SSE-aware encoded body.
///
/// The owned guard lives in the producer task until clean EOF, an upstream
/// error, or cancellation.  Errors are delivered after any already-produced
/// bytes and the encoder is deliberately not finalized on an error.
pub(crate) fn compress_body<G>(
  body: ProxyBody,
  coding: SseCompressionCoding,
  level: u8,
  boundary: SseFlushBoundary,
  guard: G,
) -> ProxyBody
where
  G: Send + 'static,
{
  const PIPE_CAPACITY: usize = 64 * 1024;

  let (reader, writer) = tokio::io::duplex(PIPE_CAPACITY);
  let (sender, receiver) = mpsc::channel(1);
  let terminal_error = std::sync::Arc::new(std::sync::Mutex::new(None::<BoxError>));

  let producer_error = terminal_error.clone();
  let producer = tokio::spawn(async move {
    let _guard = guard;
    let mut body = body;
    let mut encoder = SseCompressionEncoder::new(writer, coding, level);
    loop {
      match std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await {
        Some(Ok(frame)) => match frame.into_data() {
          Ok(data) => {
            if let Err(error) = encoder.write_all(&data).await {
              store_terminal_error(&producer_error, boxed_error(error));
              return;
            }
            if boundary == SseFlushBoundary::EveryFrame
              && let Err(error) = encoder.flush_record().await
            {
              store_terminal_error(&producer_error, boxed_error(error));
              return;
            }
          }
          Err(frame) => {
            if frame.into_trailers().is_err() {
              store_terminal_error(
                &producer_error,
                boxed_error(io::Error::other("unexpected non-data HTTP body frame")),
              );
              return;
            }
          }
        },
        Some(Err(error)) => {
          store_terminal_error(&producer_error, error);
          return;
        }
        None => {
          if let Err(error) = encoder.shutdown().await {
            store_terminal_error(&producer_error, boxed_error(error));
          }
          return;
        }
      }
    }
  });

  tokio::spawn(forward_encoded_body(reader, sender, terminal_error));
  SseBody {
    receiver,
    producer: producer.abort_handle(),
  }
  .boxed()
}

struct SseBody {
  receiver: mpsc::Receiver<Result<Frame<Bytes>, BoxError>>,
  producer: tokio::task::AbortHandle,
}

impl Body for SseBody {
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    mut self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    match self.receiver.poll_recv(cx) {
      std::task::Poll::Ready(Some(frame)) => std::task::Poll::Ready(Some(frame)),
      std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
      std::task::Poll::Pending => std::task::Poll::Pending,
    }
  }
}

impl Drop for SseBody {
  fn drop(&mut self) {
    self.producer.abort();
    self.receiver.close();
  }
}

async fn forward_encoded_body(
  mut reader: DuplexStream,
  sender: mpsc::Sender<Result<Frame<Bytes>, BoxError>>,
  terminal_error: std::sync::Arc<std::sync::Mutex<Option<BoxError>>>,
) {
  let mut bytes = vec![0; 16 * 1024];
  loop {
    match reader.read(&mut bytes).await {
      Ok(0) => break,
      Ok(length) => {
        if sender
          .send(Ok(Frame::data(Bytes::copy_from_slice(&bytes[..length]))))
          .await
          .is_err()
        {
          return;
        }
      }
      Err(error) => {
        let _ = sender.send(Err(boxed_error(error))).await;
        return;
      }
    }
  }
  let error = {
    terminal_error
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .take()
  };
  if let Some(error) = error {
    let _ = sender.send(Err(error)).await;
  }
}

fn store_terminal_error(terminal_error: &std::sync::Mutex<Option<BoxError>>, error: BoxError) {
  let mut terminal_error = terminal_error
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner());
  if terminal_error.is_none() {
    *terminal_error = Some(error);
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;
  use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

  use async_compression::tokio::bufread::{BrotliDecoder, GzipDecoder, ZlibDecoder, ZstdDecoder};
  use http_body_util::{BodyExt, StreamBody};
  use tokio::io::{AsyncReadExt, BufReader};
  use tokio::time::{Duration, timeout};

  use super::*;

  struct DropMarker(Arc<AtomicBool>);

  struct FlushCounter(Arc<AtomicUsize>);

  impl AsyncWrite for FlushCounter {
    fn poll_write(
      self: std::pin::Pin<&mut Self>,
      _cx: &mut std::task::Context<'_>,
      bytes: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
      std::task::Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(
      self: std::pin::Pin<&mut Self>,
      _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
      self.0.fetch_add(1, Ordering::AcqRel);
      std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
      self: std::pin::Pin<&mut Self>,
      _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
      std::task::Poll::Ready(Ok(()))
    }
  }

  impl Drop for DropMarker {
    fn drop(&mut self) {
      self.0.store(true, Ordering::Release);
    }
  }

  #[tokio::test]
  async fn every_coding_preserves_lf_crlf_and_cr_events_split_across_writes() {
    let expected = b"data: lf\n\ndata: crlf\r\n\r\ndata: cr\r\r";
    for coding in [
      SseCompressionCoding::Br,
      SseCompressionCoding::Zstd,
      SseCompressionCoding::Gzip,
      SseCompressionCoding::Deflate,
    ] {
      let (mut reader, writer) = tokio::io::duplex(64 * 1024);
      let mut encoder = SseCompressionEncoder::new(writer, coding, 1);
      encoder.write_all(b"data: lf\n").await.unwrap();
      encoder.write_all(b"\n").await.unwrap();
      encoder.write_all(b"data: crlf\r").await.unwrap();
      encoder.write_all(b"\n\r").await.unwrap();
      encoder.write_all(b"\n").await.unwrap();
      encoder.write_all(b"data: cr\r").await.unwrap();
      encoder.write_all(b"\r").await.unwrap();
      encoder.shutdown().await.unwrap();
      drop(encoder);

      let mut compressed = Vec::new();
      reader.read_to_end(&mut compressed).await.unwrap();
      let reader = BufReader::new(compressed.as_slice());
      let mut decoded = Vec::new();
      match coding {
        SseCompressionCoding::Br => BrotliDecoder::new(reader)
          .read_to_end(&mut decoded)
          .await
          .unwrap(),
        SseCompressionCoding::Zstd => {
          let mut decoder = ZstdDecoder::new(reader);
          decoder.multiple_members(true);
          decoder.read_to_end(&mut decoded).await.unwrap()
        }
        SseCompressionCoding::Gzip => GzipDecoder::new(reader)
          .read_to_end(&mut decoded)
          .await
          .unwrap(),
        SseCompressionCoding::Deflate => ZlibDecoder::new(reader)
          .read_to_end(&mut decoded)
          .await
          .unwrap(),
      };
      assert_eq!(decoded, expected, "coding {coding:?}");
    }
  }

  #[tokio::test]
  async fn complete_event_flushes_before_clean_eof() {
    let (mut reader, writer) = tokio::io::duplex(64 * 1024);
    let mut encoder = SseCompressionEncoder::new(writer, SseCompressionCoding::Gzip, 1);
    encoder.write_all(b"data: ready\n\n").await.unwrap();

    let mut output = [0; 4_096];
    assert!(
      timeout(Duration::from_millis(250), reader.read(&mut output))
        .await
        .expect("complete event should flush before EOF")
        .expect("compressed stream should be readable")
        > 0
    );
  }

  #[tokio::test]
  async fn brotli_decodes_a_complete_event_before_clean_eof() {
    let event = b"data: ready\r\n\r\n";
    let (reader, writer) = tokio::io::duplex(64 * 1024);
    let mut encoder = SseCompressionEncoder::new(writer, SseCompressionCoding::Br, 1);
    encoder.write_all(event).await.unwrap();
    let mut decoder = BrotliDecoder::new(BufReader::new(reader));
    let mut decoded = vec![0; event.len()];
    timeout(Duration::from_millis(250), decoder.read_exact(&mut decoded))
      .await
      .expect("Brotli event should decode before EOF")
      .unwrap();
    assert_eq!(decoded, event);
  }

  #[tokio::test]
  async fn zstd_decodes_a_complete_event_before_clean_eof() {
    let event = b"data: ready\r\n\r\n";
    let (mut reader, writer) = tokio::io::duplex(64 * 1024);
    let mut encoder = SseCompressionEncoder::new(writer, SseCompressionCoding::Zstd, 1);
    encoder.write_all(event).await.unwrap();
    timeout(Duration::from_millis(250), async {
      let mut compressed = Vec::new();
      loop {
        let mut bytes = [0; 4_096];
        let length = reader.read(&mut bytes).await.unwrap();
        assert_ne!(length, 0, "Zstandard stream ended before clean source EOF");
        compressed.extend_from_slice(&bytes[..length]);
        if let Ok(decoded) = zstd::stream::decode_all(compressed.as_slice()) {
          assert_eq!(decoded, event);
          break;
        }
      }
    })
    .await
    .expect("Zstandard event should decode before EOF");
  }

  #[tokio::test]
  async fn cr_delimited_event_flushes_before_clean_eof() {
    let (mut reader, writer) = tokio::io::duplex(64 * 1024);
    let mut encoder = SseCompressionEncoder::new(writer, SseCompressionCoding::Gzip, 1);
    encoder.write_all(b"data: ready\r\r").await.unwrap();

    let mut output = [0; 4_096];
    assert!(
      timeout(Duration::from_millis(250), reader.read(&mut output))
        .await
        .expect("complete CR-delimited event should flush before EOF")
        .expect("compressed stream should be readable")
        > 0
    );
  }

  #[tokio::test]
  async fn empty_frames_do_not_split_crlf_boundaries() {
    let flushes = Arc::new(AtomicUsize::new(0));
    let mut encoder =
      SseCompressionEncoder::new(FlushCounter(flushes.clone()), SseCompressionCoding::Gzip, 1);
    encoder.write_all(b"data: one\r").await.unwrap();
    encoder.write_all(b"").await.unwrap();
    encoder.write_all(b"\n").await.unwrap();
    assert_eq!(flushes.load(Ordering::Acquire), 0);

    encoder.write_all(b"\r").await.unwrap();
    encoder.write_all(b"").await.unwrap();
    encoder.write_all(b"\n").await.unwrap();
    assert_eq!(flushes.load(Ordering::Acquire), 2);

    encoder.write_all(b"data: two\rX").await.unwrap();
    encoder.write_all(b"\n\r").await.unwrap();
    assert_eq!(flushes.load(Ordering::Acquire), 3);
  }

  #[tokio::test]
  async fn body_adapter_propagates_errors_and_releases_guards_on_error_or_cancellation() {
    let error_guard = Arc::new(AtomicBool::new(false));
    let source = StreamBody::new(futures_util::stream::iter(vec![Err::<Frame<Bytes>, _>(
      boxed_error(io::Error::other("source failed")),
    )]))
    .boxed();
    let error_body = compress_body(
      source,
      SseCompressionCoding::Gzip,
      1,
      SseFlushBoundary::Event,
      DropMarker(error_guard.clone()),
    );
    assert!(error_body.collect().await.is_err());
    assert!(error_guard.load(Ordering::Acquire));

    let cancellation_guard = Arc::new(AtomicBool::new(false));
    let source = StreamBody::new(futures_util::stream::pending::<
      Result<Frame<Bytes>, BoxError>,
    >())
    .boxed();
    let cancellation_body = compress_body(
      source,
      SseCompressionCoding::Gzip,
      1,
      SseFlushBoundary::Event,
      DropMarker(cancellation_guard.clone()),
    );
    drop(cancellation_body);
    tokio::task::yield_now().await;
    assert!(cancellation_guard.load(Ordering::Acquire));
  }
}

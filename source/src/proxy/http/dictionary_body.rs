//! Bounded asynchronous body bridge for synchronous dictionary codecs.

use std::io::{self, Read, Write};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use tokio::sync::{OwnedSemaphorePermit, mpsc};

use super::body::{BoxError, ProxyBody};
use crate::compression_dictionary::codec::{self, DecodeLimits, DictionaryCoding, EncodeOptions};

const CHUNK_BYTES: usize = 16 * 1024;
const CHANNEL_SLOTS: usize = 2;

pub(super) struct CodecBodyOptions {
  pub metrics: Option<Arc<crate::metrics::Metrics>>,
  pub coding: DictionaryCoding,
  pub decode: bool,
  pub level: i32,
  pub timeout: Duration,
  pub max_decoded_bytes: usize,
  pub max_expansion_ratio: usize,
}

/// The returned body owns cancellation of both the input pump and codec.
/// The codec owns the dictionary and permit until its last operation returns.
pub(super) fn transform(
  mut body: ProxyBody,
  dictionary: Arc<[u8]>,
  options: CodecBodyOptions,
  permit: OwnedSemaphorePermit,
) -> ProxyBody {
  let cancel = Arc::new(AtomicBool::new(false));
  let deadline = Instant::now()
    .checked_add(options.timeout)
    .unwrap_or_else(Instant::now);
  let (input_tx, input_rx) = mpsc::channel(CHANNEL_SLOTS);
  let (output_tx, output_rx) = mpsc::channel(CHANNEL_SLOTS);
  let terminal = Arc::new(Mutex::new(None));
  let worker_terminal = terminal.clone();
  let input_cancel = cancel.clone();
  let input_task = tokio::spawn(async move {
    let pump = async {
      while let Some(frame) = body.frame().await {
        if input_cancel.load(Ordering::Acquire) {
          break;
        }
        let frame = frame.map_err(|e| io::Error::other(e.to_string()))?;
        if frame.is_trailers() {
          return Err(io::Error::other(
            "dictionary coding cannot transform trailers",
          ));
        }
        if let Ok(mut bytes) = frame.into_data() {
          while !bytes.is_empty() {
            let chunk = bytes.split_to(bytes.len().min(CHUNK_BYTES));
            if input_tx.send(Ok(chunk)).await.is_err() {
              return Ok(());
            }
          }
        }
      }
      Ok::<_, io::Error>(())
    };
    let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), pump).await;
    let error = match result {
      Ok(Ok(())) => None,
      Ok(Err(error)) => Some(error),
      Err(_) => Some(io::Error::new(
        io::ErrorKind::TimedOut,
        "dictionary body input timed out",
      )),
    };
    if let Some(error) = error {
      // Deadline-aware output closes the worker even if this terminal message
      // cannot be queued. Dropping this sender always terminates a blocked read.
      let _ = input_tx.try_send(Err(error));
      input_cancel.store(true, Ordering::Release);
    }
  });
  if let Some(metrics) = &options.metrics {
    metrics.record_dictionary_codec_job(options.decode);
  }
  let worker_metrics = options.metrics.clone();
  let worker_cancel = cancel.clone();
  tokio::task::spawn_blocking(move || {
    let _permit = permit;
    let reader = Input {
      receiver: input_rx,
      current: Bytes::new(),
      cancel: worker_cancel.clone(),
      deadline,
    };
    let writer = Output {
      sender: output_tx.clone(),
      cancel: worker_cancel.clone(),
      deadline,
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      if options.decode {
        codec::decode(
          options.coding,
          &dictionary,
          reader,
          writer,
          &DecodeLimits {
            max_decoded_bytes: options.max_decoded_bytes,
            max_expansion_ratio: options.max_expansion_ratio,
            deadline: Some(deadline),
            cancel: Some(worker_cancel.clone()),
          },
        )
        .map(|_| ())
      } else {
        codec::encode_with_options(
          options.coding,
          &dictionary,
          reader,
          writer,
          &EncodeOptions {
            compression_level: options.level,
            deadline: Some(deadline),
            cancel: Some(worker_cancel.clone()),
          },
        )
        .map(|_| ())
      }
    }))
    .unwrap_or_else(|_| Err(io::Error::other("dictionary codec worker panicked")));
    if let Err(error) = result {
      if let Some(metrics) = &worker_metrics {
        metrics.record_dictionary_codec_error();
      }
      if let Ok(mut slot) = worker_terminal.lock() {
        *slot = Some(error);
      }
    }
  });
  CodecBody {
    receiver: output_rx,
    cancel,
    terminal,
    input_task: input_task.abort_handle(),
  }
  .boxed()
}

struct Input {
  receiver: mpsc::Receiver<io::Result<Bytes>>,
  current: Bytes,
  cancel: Arc<AtomicBool>,
  deadline: Instant,
}
impl Read for Input {
  fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
    check(&self.cancel, self.deadline)?;
    if output.is_empty() {
      return Ok(0);
    }
    while self.current.is_empty() {
      match self.receiver.blocking_recv() {
        Some(Ok(bytes)) => self.current = bytes,
        Some(Err(error)) => return Err(error),
        None => {
          check(&self.cancel, self.deadline)?;
          return Ok(0);
        }
      }
    }
    let count = output.len().min(self.current.len());
    output[..count].copy_from_slice(&self.current.split_to(count));
    Ok(count)
  }
}

struct Output {
  sender: mpsc::Sender<io::Result<Bytes>>,
  cancel: Arc<AtomicBool>,
  deadline: Instant,
}
impl Write for Output {
  fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
    check(&self.cancel, self.deadline)?;
    if bytes.is_empty() {
      return Ok(0);
    }
    let count = bytes.len().min(CHUNK_BYTES);
    let mut value = Ok(Bytes::copy_from_slice(&bytes[..count]));
    loop {
      check(&self.cancel, self.deadline)?;
      match self.sender.try_send(value) {
        Ok(()) => return Ok(count),
        Err(mpsc::error::TrySendError::Full(returned)) => {
          value = returned;
          std::thread::sleep(Duration::from_millis(1));
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
          return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "dictionary output closed",
          ));
        }
      }
    }
  }
  fn flush(&mut self) -> io::Result<()> {
    check(&self.cancel, self.deadline)
  }
}

fn check(cancel: &AtomicBool, deadline: Instant) -> io::Result<()> {
  if cancel.load(Ordering::Acquire) {
    return Err(io::Error::new(
      io::ErrorKind::Interrupted,
      "dictionary body cancelled",
    ));
  }
  if Instant::now() >= deadline {
    return Err(io::Error::new(
      io::ErrorKind::TimedOut,
      "dictionary body timed out",
    ));
  }
  Ok(())
}

struct CodecBody {
  receiver: mpsc::Receiver<io::Result<Bytes>>,
  cancel: Arc<AtomicBool>,
  terminal: Arc<Mutex<Option<io::Error>>>,
  input_task: tokio::task::AbortHandle,
}
impl Body for CodecBody {
  type Data = Bytes;
  type Error = BoxError;
  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
    match self.receiver.poll_recv(cx) {
      Poll::Ready(None) => match self.terminal.lock() {
        Ok(mut terminal) => Poll::Ready(
          terminal
            .take()
            .map(|error| Err(Box::new(error) as BoxError)),
        ),
        Err(_) => Poll::Ready(Some(Err(Box::new(io::Error::other(
          "dictionary terminal state poisoned",
        ))))),
      },
      result => result.map(|item| {
        item.map(|result| {
          result
            .map(Frame::data)
            .map_err(|error| Box::new(error) as BoxError)
        })
      }),
    }
  }
  fn size_hint(&self) -> SizeHint {
    SizeHint::default()
  }
}
impl Drop for CodecBody {
  fn drop(&mut self) {
    self.cancel.store(true, Ordering::Release);
    self.input_task.abort();
    self.receiver.close();
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  fn options(coding: DictionaryCoding, decode: bool) -> CodecBodyOptions {
    CodecBodyOptions {
      metrics: None,
      coding,
      decode,
      level: 3,
      timeout: Duration::from_secs(5),
      max_decoded_bytes: 4096,
      max_expansion_ratio: 1000,
    }
  }
  #[tokio::test]
  async fn bridges_both_codings_and_returns_permit() {
    for coding in [DictionaryCoding::Dcb, DictionaryCoding::Dcz] {
      let permits = Arc::new(tokio::sync::Semaphore::new(1));
      let dictionary: Arc<[u8]> = Arc::from(&b"public compression dictionary repeated words"[..]);
      let input = b"public compression dictionary repeated words public compression";
      let body = super::super::body::known_small_no_trailers_body(Bytes::copy_from_slice(input));
      let encoded = transform(
        body,
        dictionary.clone(),
        options(coding, false),
        permits.clone().try_acquire_owned().unwrap(),
      )
      .collect()
      .await
      .unwrap()
      .to_bytes();
      assert_eq!(permits.available_permits(), 1);
      let body = super::super::body::known_small_no_trailers_body(encoded);
      let decoded = transform(
        body,
        dictionary,
        options(coding, true),
        permits.clone().try_acquire_owned().unwrap(),
      )
      .collect()
      .await
      .unwrap()
      .to_bytes();
      assert_eq!(decoded.as_ref(), input);
      assert_eq!(permits.available_permits(), 1);
    }
  }
  #[tokio::test]
  async fn truncated_coded_body_reports_error() {
    let permits = Arc::new(tokio::sync::Semaphore::new(1));
    let body = super::super::body::known_small_no_trailers_body(Bytes::from_static(b"bad"));
    let decoded = transform(
      body,
      Arc::from(&b"dictionary"[..]),
      options(DictionaryCoding::Dcz, true),
      permits.clone().try_acquire_owned().unwrap(),
    );
    assert!(decoded.collect().await.is_err());
    assert_eq!(permits.available_permits(), 1);
  }
}

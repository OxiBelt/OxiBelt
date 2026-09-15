//! Bounded QUERY content capture. Original bytes are observed without retaining
//! them; replay storage contains only the final request sent to the origin.

use std::collections::VecDeque;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use http::{HeaderMap, Request};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};

use crate::config::BufferingMode;
use crate::overload::{OverloadRuntime, WorkKind, WorkLease};

use super::super::body::{BoxError, ProxyBody, boxed_error};
use super::super::buffering::{BodyBufferingPolicy, BufferingError};

const MAX_TRAILER_IDENTITY_BYTES: usize = 8192;

#[derive(Clone)]
pub(crate) struct OriginalQuery {
  pub(crate) scheme: String,
  pub(crate) authority: String,
  pub(crate) uri: http::Uri,
  pub(crate) headers: HeaderMap,
  digest: Arc<Mutex<ContentDigest>>,
}

#[derive(Default)]
struct ContentDigest {
  hash: Sha256,
  len: u64,
  trailers: HeaderMap,
  complete: bool,
  invalid: bool,
  saw_trailers: bool,
}

impl OriginalQuery {
  pub(crate) fn content(&self) -> Option<(u64, [u8; 32], HeaderMap)> {
    let digest = self
      .digest
      .lock()
      .unwrap_or_else(|error| error.into_inner());
    (digest.complete && !digest.invalid).then(|| {
      (
        digest.len,
        digest.hash.clone().finalize().into(),
        digest.trailers.clone(),
      )
    })
  }
}

pub(crate) fn track_original(
  mut request: Request<ProxyBody>,
  scheme: &str,
  authority: &str,
) -> Request<ProxyBody> {
  let digest = Arc::new(Mutex::new(ContentDigest {
    complete: request.body().is_end_stream(),
    ..ContentDigest::default()
  }));
  let original = OriginalQuery {
    scheme: scheme.to_string(),
    authority: authority.to_string(),
    uri: request.uri().clone(),
    headers: request.headers().clone(),
    digest: digest.clone(),
  };
  request.extensions_mut().insert(original);
  request.map(|body| OriginalBody { body, digest }.boxed())
}

struct OriginalBody {
  body: ProxyBody,
  digest: Arc<Mutex<ContentDigest>>,
}

impl Body for OriginalBody {
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
    let result = Pin::new(&mut self.body).poll_frame(cx);
    let mut digest = self
      .digest
      .lock()
      .unwrap_or_else(|error| error.into_inner());
    match &result {
      Poll::Ready(Some(Ok(frame))) => {
        if let Some(data) = frame.data_ref() {
          if digest.saw_trailers {
            digest.invalid = true;
          }
          digest.len = digest.len.saturating_add(data.len() as u64);
          digest.hash.update(data);
        }
        if let Some(trailers) = frame.trailers_ref() {
          if digest.saw_trailers || trailer_bytes(trailers) > MAX_TRAILER_IDENTITY_BYTES {
            digest.invalid = true;
          } else {
            digest.trailers = trailers.clone();
          }
          digest.saw_trailers = true;
        }
        digest.complete = self.body.is_end_stream();
      }
      Poll::Ready(Some(Err(_))) => digest.invalid = true,
      Poll::Ready(None) => digest.complete = true,
      Poll::Pending => {}
    }
    result
  }

  fn is_end_stream(&self) -> bool {
    self.body.is_end_stream()
  }
  fn size_hint(&self) -> SizeHint {
    self.body.size_hint()
  }
}

fn trailer_bytes(headers: &HeaderMap) -> usize {
  headers.iter().fold(0usize, |total, (name, value)| {
    total
      .saturating_add(name.as_str().len())
      .saturating_add(value.as_bytes().len())
  })
}

/// File ownership and the buffered-memory lease survive all replay consumers.
struct ReplayStorage {
  memory: Bytes,
  file: Option<tempfile::NamedTempFile>,
  trailers: HeaderMap,
  len: u64,
  hash: [u8; 32],
  _lease: WorkLease,
}

#[derive(Clone)]
pub(crate) struct QueryReplaySnapshot(Arc<ReplayStorage>);

impl QueryReplaySnapshot {
  pub(crate) fn len(&self) -> u64 {
    self.0.len
  }
  pub(crate) fn digest(&self) -> [u8; 32] {
    self.0.hash
  }
  pub(crate) fn trailers(&self) -> &HeaderMap {
    &self.0.trailers
  }

  pub(crate) async fn body(&self) -> Result<ProxyBody, std::io::Error> {
    let storage = self.0.clone();
    let file = if storage.file.is_some() {
      let for_open = storage.clone();
      Some(File::from_std(
        tokio::task::spawn_blocking(move || {
          for_open
            .file
            .as_ref()
            .ok_or_else(|| std::io::Error::other("QUERY replay storage unavailable"))?
            .reopen()
        })
        .await
        .map_err(std::io::Error::other)??,
      ))
    } else {
      None
    };
    Ok(
      ReplayBody {
        memory: Some(storage.memory.clone()),
        remaining: storage.len,
        trailers: (!storage.trailers.is_empty()).then(|| storage.trailers.clone()),
        file,
        _storage: storage,
      }
      .boxed(),
    )
  }
}

pub(crate) struct CaptureResult {
  pub(crate) body: ProxyBody,
  pub(crate) snapshot: Option<QueryReplaySnapshot>,
}

/// Streaming overflow is a cache miss, not a newly imposed upload limit.
pub(crate) async fn capture(
  mut body: ProxyBody,
  policy: BodyBufferingPolicy,
  temp_dir: Option<&Path>,
  overload: &Arc<OverloadRuntime>,
) -> Result<CaptureResult, BufferingError> {
  let lease = overload.lease(
    WorkKind::RequestBodyBufferedBytes,
    policy.max_memory_body_bytes as u64,
  );
  let max_total = if policy.mode == BufferingMode::Spool {
    policy
      .max_memory_body_bytes
      .saturating_add(policy.max_temp_file_bytes)
  } else {
    policy.max_memory_body_bytes
  };
  let mut memory = BytesMut::new();
  let mut file: Option<tempfile::NamedTempFile> = None;
  let mut writer: Option<File> = None;
  let mut trailers = HeaderMap::new();
  let mut saw_trailers = false;
  let mut hash = Sha256::new();
  let mut len = 0u64;
  while let Some(frame) = body.frame().await {
    let frame = frame.map_err(BufferingError::Body)?;
    match frame.into_data() {
      Ok(data) => {
        if saw_trailers {
          return Err(BufferingError::Body(boxed_error(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "QUERY DATA follows trailers",
          ))));
        }
        let next = len.saturating_add(data.len() as u64);
        if next > max_total as u64 {
          if policy.mode == BufferingMode::Streaming {
            let mut prefix = VecDeque::new();
            if !memory.is_empty() {
              prefix.push_back(Frame::data(memory.freeze()));
            }
            prefix.push_back(Frame::data(data));
            return Ok(CaptureResult {
              body: PrefixAndLiveBody {
                prefix,
                body,
                _lease: lease,
              }
              .boxed(),
              snapshot: None,
            });
          }
          return Err(BufferingError::TooLarge);
        }
        len = next;
        hash.update(&data);
        let keep = policy
          .max_memory_body_bytes
          .saturating_sub(memory.len())
          .min(data.len());
        memory.extend_from_slice(&data[..keep]);
        if keep < data.len() {
          if writer.is_none() {
            let directory = temp_dir
              .ok_or(BufferingError::MissingTempDir)?
              .to_path_buf();
            let (named, opened) = tokio::task::spawn_blocking(move || {
              let named = tempfile::Builder::new()
                .prefix("oxibelt-buffer-query-")
                .tempfile_in(directory)?;
              let opened = named.reopen()?;
              Ok::<_, std::io::Error>((named, opened))
            })
            .await
            .map_err(|error| BufferingError::Io(std::io::Error::other(error)))??;
            file = Some(named);
            writer = Some(File::from_std(opened));
          }
          writer
            .as_mut()
            .ok_or_else(|| {
              BufferingError::Io(std::io::Error::other("QUERY replay writer unavailable"))
            })?
            .write_all(&data[keep..])
            .await?;
        }
      }
      Err(frame) => {
        if let Ok(received) = frame.into_trailers() {
          if saw_trailers || trailer_bytes(&received) > MAX_TRAILER_IDENTITY_BYTES {
            // Replay all captured frames and retain the original trailer frame.
            // Spooling already has an explicit bounded contract; materialize a
            // replay reader without treating these trailers as cache identity.
            if let Some(writer) = &mut writer {
              writer.flush().await?;
            }
            let snapshot = QueryReplaySnapshot(Arc::new(ReplayStorage {
              memory: memory.freeze(),
              file,
              trailers,
              len,
              hash: hash.finalize().into(),
              _lease: lease,
            }));
            let prefix = snapshot.body().await?;
            use futures_util::{StreamExt, stream};
            let frames = http_body_util::BodyStream::new(prefix)
              .chain(stream::once(std::future::ready(Ok(Frame::trailers(
                received,
              )))))
              .chain(http_body_util::BodyStream::new(body));
            let prefix = BodyExt::boxed(http_body_util::StreamBody::new(frames));
            return Ok(CaptureResult {
              body: prefix,
              snapshot: None,
            });
          }
          trailers = received;
          saw_trailers = true;
        }
      }
    }
  }
  if let Some(writer) = &mut writer {
    writer.flush().await?;
  }
  drop(writer);
  let snapshot = QueryReplaySnapshot(Arc::new(ReplayStorage {
    memory: memory.freeze(),
    file,
    trailers,
    len,
    hash: hash.finalize().into(),
    _lease: lease,
  }));
  Ok(CaptureResult {
    body: snapshot.body().await?,
    snapshot: Some(snapshot),
  })
}

struct ReplayBody {
  memory: Option<Bytes>,
  file: Option<File>,
  trailers: Option<HeaderMap>,
  remaining: u64,
  _storage: Arc<ReplayStorage>,
}

impl Body for ReplayBody {
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
    if let Some(data) = self.memory.take().filter(|data| !data.is_empty()) {
      self.remaining = self.remaining.saturating_sub(data.len() as u64);
      return Poll::Ready(Some(Ok(Frame::data(data))));
    }
    if let Some(file) = &mut self.file {
      let mut bytes = vec![0; 16 * 1024];
      let mut buffer = ReadBuf::new(&mut bytes);
      match Pin::new(file).poll_read(cx, &mut buffer) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(error)) => {
          self.file = None;
          self.remaining = 0;
          self.trailers = None;
          return Poll::Ready(Some(Err(boxed_error(error))));
        }
        Poll::Ready(Ok(())) => {
          let count = buffer.filled().len();
          if count > 0 {
            bytes.truncate(count);
            self.remaining = self.remaining.saturating_sub(count as u64);
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from(bytes)))));
          }
          self.file = None;
          if self.remaining != 0 {
            self.remaining = 0;
            self.trailers = None;
            return Poll::Ready(Some(Err(boxed_error(std::io::Error::new(
              std::io::ErrorKind::UnexpectedEof,
              "QUERY replay spool is incomplete",
            )))));
          }
        }
      }
    }
    Poll::Ready(
      self
        .trailers
        .take()
        .map(|trailers| Ok(Frame::trailers(trailers))),
    )
  }

  fn is_end_stream(&self) -> bool {
    self.remaining == 0 && self.trailers.is_none()
  }
  fn size_hint(&self) -> SizeHint {
    if self.trailers.is_some() {
      SizeHint::default()
    } else {
      SizeHint::with_exact(self.remaining)
    }
  }
}

struct PrefixAndLiveBody {
  prefix: VecDeque<Frame<Bytes>>,
  body: ProxyBody,
  _lease: WorkLease,
}

impl Body for PrefixAndLiveBody {
  type Data = Bytes;
  type Error = BoxError;
  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
    if let Some(frame) = self.prefix.pop_front() {
      return Poll::Ready(Some(Ok(frame)));
    }
    Pin::new(&mut self.body).poll_frame(cx)
  }
  fn is_end_stream(&self) -> bool {
    self.prefix.is_empty() && self.body.is_end_stream()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn policy(mode: BufferingMode) -> BodyBufferingPolicy {
    BodyBufferingPolicy {
      mode,
      max_memory_body_bytes: 3,
      max_temp_file_bytes: 32,
    }
  }

  fn framed_body() -> ProxyBody {
    let mut trailers = HeaderMap::new();
    trailers.insert("x-query-proof", http::HeaderValue::from_static("complete"));
    BodyExt::boxed(http_body_util::StreamBody::new(futures_util::stream::iter(
      [
        Ok(Frame::data(Bytes::from_static(b"ab"))),
        Ok(Frame::data(Bytes::from_static(b"cdef"))),
        Ok(Frame::trailers(trailers)),
      ],
    )))
  }

  async fn assert_content(body: ProxyBody) {
    let collected = body.collect().await.unwrap();
    assert_eq!(collected.trailers().unwrap()["x-query-proof"], "complete");
    assert_eq!(collected.to_bytes(), "abcdef");
  }

  #[tokio::test]
  async fn streaming_overflow_restores_every_byte_and_trailer() {
    let overload = OverloadRuntime::new(&Default::default());
    let result = capture(
      framed_body(),
      policy(BufferingMode::Streaming),
      None,
      &overload,
    )
    .await
    .unwrap();
    assert!(result.snapshot.is_none());
    assert_content(result.body).await;
  }

  #[tokio::test]
  async fn spool_replays_independently_and_unlinks_after_last_consumer() {
    let overload = OverloadRuntime::new(&Default::default());
    let directory = tempfile::tempdir().unwrap();
    let result = capture(
      framed_body(),
      policy(BufferingMode::Spool),
      Some(directory.path()),
      &overload,
    )
    .await
    .unwrap();
    let snapshot = result.snapshot.unwrap();
    assert_eq!(snapshot.digest(), crate::crypto::sha256(b"abcdef"));
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    let second = snapshot.body().await.unwrap();
    drop(snapshot);
    assert_content(result.body).await;
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    assert_content(second).await;
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
  }

  #[tokio::test]
  async fn explicit_buffer_limit_still_rejects_and_cleans_up() {
    let overload = OverloadRuntime::new(&Default::default());
    assert!(matches!(
      capture(
        framed_body(),
        policy(BufferingMode::Memory),
        None,
        &overload
      )
      .await,
      Err(BufferingError::TooLarge)
    ));
    let directory = tempfile::tempdir().unwrap();
    let mut bounded = policy(BufferingMode::Spool);
    bounded.max_temp_file_bytes = 1;
    assert!(matches!(
      capture(framed_body(), bounded, Some(directory.path()), &overload).await,
      Err(BufferingError::TooLarge)
    ));
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
  }

  #[tokio::test]
  async fn original_digest_is_complete_only_after_full_stream() {
    let request = track_original(
      Request::builder()
        .method("QUERY")
        .uri("/query")
        .body(framed_body())
        .unwrap(),
      "https",
      "example.test",
    );
    let original = request.extensions().get::<OriginalQuery>().unwrap().clone();
    assert!(original.content().is_none());
    assert_content(request.into_body()).await;
    let (len, digest, trailers) = original.content().unwrap();
    assert_eq!(len, 6);
    assert_eq!(digest, crate::crypto::sha256(b"abcdef"));
    assert_eq!(trailers["x-query-proof"], "complete");
  }
}

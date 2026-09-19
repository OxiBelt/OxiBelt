//! Bounded, anonymous staging files. No client-derived path enters filesystem I/O.

use super::*;
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

pub(super) fn hold_admission(
  body: ProxyBody,
  admission: crate::uploads::UploadPartAdmission,
) -> ProxyBody {
  BodyExt::boxed(http_body_util::StreamBody::new(
    futures_util::stream::unfold((body, admission), |(mut body, admission)| async move {
      body.frame().await.map(|frame| (frame, (body, admission)))
    }),
  ))
}

pub(super) fn body_from_stream(input: crate::uploads::UploadByteStream) -> ProxyBody {
  // `ProxyBody` is Sync, while durable object streams only promise Send.
  // The bounded channel supplies the required body ownership boundary and
  // preserves backpressure instead of collecting decoded bytes in memory.
  let (sender, body) = body::channel_body(2);
  tokio::spawn(async move {
    let mut input = input;
    while let Some(item) = input.next().await {
      let frame = item
        .map(hyper::body::Frame::data)
        .map_err(|error| -> body::BoxError { Box::new(std::io::Error::other(error.to_string())) });
      if sender.send(frame).await.is_err() {
        break;
      }
    }
  });
  body
}

pub(super) struct Spool {
  file: Arc<tokio::sync::Mutex<tokio::fs::File>>,
  pub bytes: u64,
  pub digest: String,
  pub capture: Option<body::CapturedBody>,
  capture_buffer: Option<bytes::BytesMut>,
}

impl Spool {
  pub async fn read_body(
    mut input: ProxyBody,
    profile: &UploadProfileConfig,
    inspect: bool,
    maximum: u64,
  ) -> Result<Self, StatusCode> {
    let mut spool = Self::new(profile, inspect).await?;
    let mut digest = Sha256::new();
    while let Some(frame) = input.frame().await {
      let frame = frame.map_err(|error| {
        if body::error_is_body_length_limit(&error) {
          StatusCode::PAYLOAD_TOO_LARGE
        } else if error_is_timeout(&error, BodyTimeoutKind::DownstreamRequestRead) {
          StatusCode::REQUEST_TIMEOUT
        } else {
          StatusCode::BAD_REQUEST
        }
      })?;
      match frame.into_data() {
        Ok(bytes) => spool.write(&bytes, profile, maximum, &mut digest).await?,
        Err(frame) if frame.is_trailers() => return Err(StatusCode::BAD_REQUEST),
        Err(_) => return Err(StatusCode::BAD_REQUEST),
      }
    }
    spool.finish(digest).await
  }

  pub async fn read_stream(
    input: crate::uploads::UploadByteStream,
    profile: &UploadProfileConfig,
    inspect: bool,
  ) -> Result<Self, StatusCode> {
    Self::read_stream_bounded(input, profile, inspect, profile.max_upload_bytes).await
  }

  pub async fn read_stream_bounded(
    mut input: crate::uploads::UploadByteStream,
    profile: &UploadProfileConfig,
    inspect: bool,
    maximum: u64,
  ) -> Result<Self, StatusCode> {
    let mut spool = Self::new(profile, inspect).await?;
    let mut digest = Sha256::new();
    while let Some(bytes) = input.next().await {
      let bytes = bytes.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
      spool.write(&bytes, profile, maximum, &mut digest).await?;
    }
    spool.finish(digest).await
  }

  async fn new(profile: &UploadProfileConfig, inspect: bool) -> Result<Self, StatusCode> {
    let directory = profile.staging_dir.clone();
    let file = tokio::task::spawn_blocking(move || tempfile::tempfile_in(directory))
      .await
      .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
      .map_err(|_| StatusCode::INSUFFICIENT_STORAGE)?;
    Ok(Self {
      file: Arc::new(tokio::sync::Mutex::new(tokio::fs::File::from_std(file))),
      bytes: 0,
      digest: String::new(),
      capture: None,
      capture_buffer: inspect.then(bytes::BytesMut::new),
    })
  }

  async fn write(
    &mut self,
    bytes: &[u8],
    profile: &UploadProfileConfig,
    maximum: u64,
    digest: &mut Sha256,
  ) -> Result<(), StatusCode> {
    self.bytes = self
      .bytes
      .checked_add(bytes.len() as u64)
      .ok_or(StatusCode::PAYLOAD_TOO_LARGE)?;
    if self.bytes > maximum
      || self.bytes > profile.max_staging_bytes
      || (self.capture_buffer.is_some() && self.bytes > profile.inspection_bytes)
    {
      return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    if let Some(buffer) = &mut self.capture_buffer {
      buffer.extend_from_slice(bytes);
    }
    digest.update(bytes);
    self
      .file
      .lock()
      .await
      .write_all(bytes)
      .await
      .map_err(|_| StatusCode::INSUFFICIENT_STORAGE)
  }

  async fn finish(mut self, digest: Sha256) -> Result<Self, StatusCode> {
    self
      .file
      .lock()
      .await
      .flush()
      .await
      .map_err(|_| StatusCode::INSUFFICIENT_STORAGE)?;
    self
      .file
      .lock()
      .await
      .rewind()
      .await
      .map_err(|_| StatusCode::INSUFFICIENT_STORAGE)?;
    self.digest = hex_digest(digest.finalize().as_ref());
    self.capture = self.capture_buffer.take().map(|buffer| body::CapturedBody {
      bytes: buffer.freeze(),
      is_truncated: false,
    });
    Ok(self)
  }

  pub async fn stream(&mut self) -> Result<crate::uploads::UploadByteStream, StatusCode> {
    Ok(Self::reader(self.file.clone()))
  }

  fn reader(file: Arc<tokio::sync::Mutex<tokio::fs::File>>) -> crate::uploads::UploadByteStream {
    // File::try_clone shares the OS cursor. The body adapter eagerly reads,
    // so authentication and publication may consume this spool concurrently.
    // Give each reader a logical cursor and serialize each seek/read pair.
    Box::pin(futures_util::stream::try_unfold(
      (file, 0u64),
      |(file, offset)| async move {
        let mut bytes = vec![0; 64 * 1024];
        let length = {
          let mut reader = file.lock().await;
          reader.seek(std::io::SeekFrom::Start(offset)).await?;
          reader.read(&mut bytes).await?
        };
        if length == 0 {
          return Ok(None);
        }
        bytes.truncate(length);
        Ok(Some((
          bytes::Bytes::from(bytes),
          (file, offset + length as u64),
        )))
      },
    ))
  }

  pub fn into_body(self) -> ProxyBody {
    body_from_stream(Self::reader(self.file))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn spool_readers_keep_independent_cursors_when_interleaved() {
    let expected: Vec<u8> = (0..200_000).map(|index| (index % 251) as u8).collect();
    let file = tempfile::tempfile().unwrap();
    let file = Arc::new(tokio::sync::Mutex::new(tokio::fs::File::from_std(file)));
    file.lock().await.write_all(&expected).await.unwrap();
    file.lock().await.flush().await.unwrap();
    let mut first = Spool::reader(file.clone());
    let mut second = Spool::reader(file);
    let mut first_bytes = Vec::new();
    let mut second_bytes = Vec::new();
    loop {
      let a = first.next().await.transpose().unwrap();
      let b = second.next().await.transpose().unwrap();
      if a.is_none() && b.is_none() {
        break;
      }
      if let Some(bytes) = a {
        first_bytes.extend_from_slice(&bytes);
      }
      if let Some(bytes) = b {
        second_bytes.extend_from_slice(&bytes);
      }
    }
    assert_eq!(first_bytes, expected);
    assert_eq!(second_bytes, expected);
  }
}

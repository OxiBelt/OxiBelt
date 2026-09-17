//! Bounded, anonymous staging files. No client-derived path enters filesystem I/O.

use super::*;
use futures_util::{StreamExt, TryStreamExt};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

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

pub(super) struct Spool {
  file: tokio::fs::File,
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
    mut input: crate::uploads::UploadByteStream,
    profile: &UploadProfileConfig,
    inspect: bool,
  ) -> Result<Self, StatusCode> {
    let mut spool = Self::new(profile, inspect).await?;
    let mut digest = Sha256::new();
    while let Some(bytes) = input.next().await {
      let bytes = bytes.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
      spool
        .write(&bytes, profile, profile.max_upload_bytes, &mut digest)
        .await?;
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
      file: tokio::fs::File::from_std(file),
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
      .write_all(bytes)
      .await
      .map_err(|_| StatusCode::INSUFFICIENT_STORAGE)
  }

  async fn finish(mut self, digest: Sha256) -> Result<Self, StatusCode> {
    self
      .file
      .flush()
      .await
      .map_err(|_| StatusCode::INSUFFICIENT_STORAGE)?;
    self
      .file
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
    self
      .file
      .rewind()
      .await
      .map_err(|_| StatusCode::INSUFFICIENT_STORAGE)?;
    let file = self
      .file
      .try_clone()
      .await
      .map_err(|_| StatusCode::INSUFFICIENT_STORAGE)?;
    Ok(Box::pin(
      tokio_util::io::ReaderStream::new(file).map_err(anyhow::Error::from),
    ))
  }

  pub fn into_body(self) -> ProxyBody {
    BodyExt::boxed(http_body_util::StreamBody::new(
      tokio_util::io::ReaderStream::new(self.file)
        .map_ok(hyper::body::Frame::data)
        .map_err(|error| -> body::BoxError { Box::new(error) }),
    ))
  }
}

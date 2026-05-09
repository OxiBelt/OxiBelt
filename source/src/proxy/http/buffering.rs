use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::{Bytes, BytesMut};
use http::HeaderMap;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use tracing::warn;

use crate::config::{BufferingMode, Config, RouteConfig};

use super::body::{BoxError, ProxyBody, boxed_error};

const SPOOL_FILE_PREFIX: &str = "oxibelt-buffer-";
const SPOOL_READ_CHUNK_BYTES: usize = 16 * 1024;
static NEXT_SPOOL_FILE_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectiveBuffering {
  pub(crate) request: BodyBufferingPolicy,
  pub(crate) response: BodyBufferingPolicy,
  pub(crate) temp_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BodyBufferingPolicy {
  pub(crate) mode: BufferingMode,
  pub(crate) max_memory_body_bytes: usize,
  pub(crate) max_temp_file_bytes: usize,
}

impl EffectiveBuffering {
  pub(crate) fn new(config: &Config, route: &RouteConfig) -> Self {
    let global = &config.proxy.buffering;
    Self {
      request: BodyBufferingPolicy {
        mode: route.buffering.request.unwrap_or(global.request),
        max_memory_body_bytes: route
          .buffering
          .max_memory_body_bytes
          .unwrap_or(global.max_memory_body_bytes),
        max_temp_file_bytes: route
          .buffering
          .max_temp_file_bytes
          .unwrap_or(global.max_temp_file_bytes),
      },
      response: BodyBufferingPolicy {
        mode: route.buffering.response.unwrap_or(global.response),
        max_memory_body_bytes: route
          .buffering
          .max_memory_body_bytes
          .unwrap_or(global.max_memory_body_bytes),
        max_temp_file_bytes: route
          .buffering
          .max_temp_file_bytes
          .unwrap_or(global.max_temp_file_bytes),
      },
      temp_dir: global.temp_dir.clone(),
    }
  }
}

#[derive(Debug)]
pub(crate) enum BufferingError {
  TooLarge,
  Body(BoxError),
  Io(std::io::Error),
  MissingTempDir,
}

impl From<std::io::Error> for BufferingError {
  fn from(error: std::io::Error) -> Self {
    Self::Io(error)
  }
}

impl BodyBufferingPolicy {
  pub(crate) fn is_streaming(self) -> bool {
    self.mode == BufferingMode::Streaming
  }
}

pub(crate) async fn buffer_body(
  body: ProxyBody,
  policy: BodyBufferingPolicy,
  temp_dir: Option<&Path>,
) -> Result<ProxyBody, BufferingError> {
  match policy.mode {
    BufferingMode::Streaming => Ok(body),
    BufferingMode::Memory | BufferingMode::RejectIfTooLarge => {
      buffer_memory(body, policy.max_memory_body_bytes).await
    }
    BufferingMode::Spool => buffer_spooled(body, policy, temp_dir).await,
  }
}

pub(crate) fn cleanup_stale_temp_files(temp_dir: &Path) {
  let Ok(entries) = std::fs::read_dir(temp_dir) else {
    return;
  };
  for entry in entries.flatten() {
    let path = entry.path();
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
      continue;
    };
    if name.starts_with(SPOOL_FILE_PREFIX)
      && let Err(error) = std::fs::remove_file(&path)
    {
      warn!(
        path = %path.display(),
        error = %error,
        "failed to remove stale HTTP buffering temp file"
      );
    }
  }
}

async fn buffer_memory(
  mut body: ProxyBody,
  max_memory_body_bytes: usize,
) -> Result<ProxyBody, BufferingError> {
  let mut bytes = BytesMut::new();
  let mut trailers = None;
  while let Some(frame) = body.frame().await {
    let frame = frame.map_err(BufferingError::Body)?;
    match frame.into_data() {
      Ok(data) => {
        if bytes.len().saturating_add(data.len()) > max_memory_body_bytes {
          return Err(BufferingError::TooLarge);
        }
        bytes.extend_from_slice(&data);
      }
      Err(frame) => {
        if let Ok(frame_trailers) = frame.into_trailers() {
          trailers = Some(frame_trailers);
        }
      }
    }
  }
  buffered_body(vec![bytes.freeze()], None, trailers).await
}

async fn buffer_spooled(
  mut body: ProxyBody,
  policy: BodyBufferingPolicy,
  temp_dir: Option<&Path>,
) -> Result<ProxyBody, BufferingError> {
  let temp_dir = temp_dir.ok_or(BufferingError::MissingTempDir)?;
  let max_total = policy
    .max_memory_body_bytes
    .saturating_add(policy.max_temp_file_bytes);
  let mut memory = BytesMut::new();
  let mut temp_file = None;
  let mut temp_path = None;
  let mut total = 0usize;
  let mut trailers = None;

  while let Some(frame) = body.frame().await {
    let frame = frame.map_err(BufferingError::Body)?;
    match frame.into_data() {
      Ok(data) => {
        total = total.saturating_add(data.len());
        if total > max_total {
          return Err(BufferingError::TooLarge);
        }
        let memory_remaining = policy.max_memory_body_bytes.saturating_sub(memory.len());
        if memory_remaining >= data.len() {
          memory.extend_from_slice(&data);
          continue;
        }
        if memory_remaining > 0 {
          memory.extend_from_slice(&data[..memory_remaining]);
        }
        let tail = data.slice(memory_remaining..);
        let file = match temp_file.as_mut() {
          Some(file) => file,
          None => {
            let (path, file) = create_spool_file(temp_dir).await?;
            temp_path = Some(path);
            temp_file.insert(file)
          }
        };
        file.write_all(&tail).await?;
      }
      Err(frame) => {
        if let Ok(frame_trailers) = frame.into_trailers() {
          trailers = Some(frame_trailers);
        }
      }
    }
  }

  if let Some(mut file) = temp_file {
    file.flush().await?;
  }
  let file = if let Some(path) = temp_path.as_ref() {
    Some(File::open(path).await?)
  } else {
    None
  };
  buffered_body(
    vec![memory.freeze()],
    file.map(|file| (file, temp_path)),
    trailers,
  )
  .await
}

async fn buffered_body(
  chunks: Vec<Bytes>,
  file: Option<(File, Option<PathBuf>)>,
  trailers: Option<HeaderMap>,
) -> Result<ProxyBody, BufferingError> {
  let memory_bytes = chunks.iter().map(Bytes::len).sum::<usize>();
  let (file, cleanup_path, file_bytes) = match file {
    Some((file, cleanup_path)) => {
      let file_bytes = file.metadata().await?.len();
      (Some(file), cleanup_path, file_bytes)
    }
    None => (None, None, 0),
  };
  let total = memory_bytes.saturating_add(file_bytes as usize);
  let mut size_hint = SizeHint::new();
  size_hint.set_exact(total as u64);
  Ok(
    BufferedBody {
      memory: chunks
        .into_iter()
        .filter(|chunk| !chunk.is_empty())
        .collect(),
      file,
      cleanup_path,
      trailers,
      size_hint,
    }
    .boxed(),
  )
}

async fn create_spool_file(temp_dir: &Path) -> Result<(PathBuf, File), std::io::Error> {
  for _ in 0..64 {
    let path = temp_dir.join(spool_file_name());
    match OpenOptions::new()
      .write(true)
      .create_new(true)
      .open(&path)
      .await
    {
      Ok(file) => return Ok((path, file)),
      Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
      Err(error) => return Err(error),
    }
  }
  Err(std::io::Error::new(
    std::io::ErrorKind::AlreadyExists,
    "failed to allocate unique HTTP buffering temp file",
  ))
}

fn spool_file_name() -> String {
  let id = NEXT_SPOOL_FILE_ID.fetch_add(1, Ordering::Relaxed);
  let nanos = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_nanos();
  format!("{SPOOL_FILE_PREFIX}{}-{nanos}-{id}.tmp", std::process::id())
}

struct BufferedBody {
  memory: VecDeque<Bytes>,
  file: Option<File>,
  cleanup_path: Option<PathBuf>,
  trailers: Option<HeaderMap>,
  size_hint: SizeHint,
}

impl Drop for BufferedBody {
  fn drop(&mut self) {
    if let Some(path) = self.cleanup_path.take() {
      let _ = std::fs::remove_file(path);
    }
  }
}

impl BufferedBody {
  fn finish_file(&mut self) {
    self.file = None;
    if let Some(path) = self.cleanup_path.take() {
      let _ = std::fs::remove_file(path);
    }
  }
}

impl Body for BufferedBody {
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    if let Some(chunk) = self.memory.pop_front() {
      return Poll::Ready(Some(Ok(Frame::data(chunk))));
    }

    if let Some(file) = self.file.as_mut() {
      let mut chunk = vec![0u8; SPOOL_READ_CHUNK_BYTES];
      let mut read_buffer = ReadBuf::new(&mut chunk);
      match Pin::new(file).poll_read(cx, &mut read_buffer) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Ok(())) => {
          let read = read_buffer.filled().len();
          if read == 0 {
            self.finish_file();
          } else {
            chunk.truncate(read);
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from(chunk)))));
          }
        }
        Poll::Ready(Err(error)) => {
          self.finish_file();
          return Poll::Ready(Some(Err(boxed_error(error))));
        }
      }
    }

    if let Some(trailers) = self.trailers.take() {
      return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
    }
    Poll::Ready(None)
  }

  fn is_end_stream(&self) -> bool {
    self.memory.is_empty() && self.file.is_none() && self.trailers.is_none()
  }

  fn size_hint(&self) -> SizeHint {
    self.size_hint.clone()
  }
}

#[cfg(test)]
mod tests {
  use std::fs;

  use http_body_util::Full;

  use crate::config::{ProxyBufferingConfig, RouteBufferingConfig};
  use crate::proxy::http::body::channel_body;

  use super::*;

  fn full_proxy_body(bytes: &'static [u8]) -> ProxyBody {
    Full::new(Bytes::from_static(bytes))
      .map_err(|never| -> BoxError { match never {} })
      .boxed()
  }

  fn temp_dir(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/oxibelt-test-fixtures");
    fs::create_dir_all(&root).expect("test fixture root should be created");
    let path = root.join(format!(
      "buffering-{name}-{}-{}",
      std::process::id(),
      NEXT_SPOOL_FILE_ID.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).expect("buffering temp dir should be created");
    path
  }

  #[tokio::test]
  async fn memory_buffering_preserves_full_body() {
    let body = buffer_body(
      full_proxy_body(b"abcdef"),
      BodyBufferingPolicy {
        mode: BufferingMode::Memory,
        max_memory_body_bytes: 16,
        max_temp_file_bytes: 0,
      },
      None,
    )
    .await
    .expect("memory buffering should succeed");

    let bytes = body
      .collect()
      .await
      .expect("buffered body should collect")
      .to_bytes();
    assert_eq!(bytes.as_ref(), b"abcdef");
  }

  #[tokio::test]
  async fn spooling_buffers_to_temp_file_and_replays_body() {
    let dir = temp_dir("spool-replay");
    let body = buffer_body(
      full_proxy_body(b"abcdefgh"),
      BodyBufferingPolicy {
        mode: BufferingMode::Spool,
        max_memory_body_bytes: 3,
        max_temp_file_bytes: 16,
      },
      Some(&dir),
    )
    .await
    .expect("spooling should succeed");
    let files = fs::read_dir(&dir)
      .expect("temp dir should be readable")
      .count();
    assert_eq!(files, 1);

    let bytes = body
      .collect()
      .await
      .expect("spooled body should collect")
      .to_bytes();
    assert_eq!(bytes.as_ref(), b"abcdefgh");
    let files = fs::read_dir(&dir)
      .expect("temp dir should be readable")
      .count();
    assert_eq!(files, 0);
    let _ = fs::remove_dir_all(dir);
  }

  #[tokio::test]
  async fn spooling_temp_file_is_removed_on_drop() {
    let dir = temp_dir("spool-drop");
    let body = buffer_body(
      full_proxy_body(b"abcdefgh"),
      BodyBufferingPolicy {
        mode: BufferingMode::Spool,
        max_memory_body_bytes: 2,
        max_temp_file_bytes: 16,
      },
      Some(&dir),
    )
    .await
    .expect("spooling should succeed");
    assert_eq!(
      fs::read_dir(&dir)
        .expect("temp dir should be readable")
        .count(),
      1
    );
    drop(body);
    assert_eq!(
      fs::read_dir(&dir)
        .expect("temp dir should be readable")
        .count(),
      0
    );
    let _ = fs::remove_dir_all(dir);
  }

  #[tokio::test]
  async fn oversized_buffering_reports_too_large() {
    let error = match buffer_body(
      full_proxy_body(b"abcdef"),
      BodyBufferingPolicy {
        mode: BufferingMode::Memory,
        max_memory_body_bytes: 3,
        max_temp_file_bytes: 0,
      },
      None,
    )
    .await
    {
      Ok(_) => panic!("oversized memory body should fail"),
      Err(error) => error,
    };
    assert!(matches!(error, BufferingError::TooLarge));
  }

  #[tokio::test]
  async fn body_errors_are_classified_as_body_errors() {
    let (sender, body) = channel_body(1);
    sender
      .send(Err(boxed_error(std::io::Error::other("boom"))))
      .await
      .expect("body channel should accept error");
    drop(sender);
    let error = match buffer_body(
      body,
      BodyBufferingPolicy {
        mode: BufferingMode::Memory,
        max_memory_body_bytes: 8,
        max_temp_file_bytes: 0,
      },
      None,
    )
    .await
    {
      Ok(_) => panic!("body error should fail buffering"),
      Err(error) => error,
    };
    assert!(matches!(error, BufferingError::Body(_)));
  }

  #[test]
  fn route_buffering_overrides_global_defaults() {
    let mut config = toml::from_str::<Config>(
      r#"
[listeners]
https_bind = "127.0.0.1:8443"

[tls]
cert_chain = "/tmp/cert.pem"
private_key = "/tmp/key.pem"
"#,
    )
    .expect("minimal config fragment should parse");
    config.proxy.buffering = ProxyBufferingConfig {
      request: BufferingMode::Memory,
      response: BufferingMode::Streaming,
      max_memory_body_bytes: 10,
      max_temp_file_bytes: 20,
      temp_dir: Some(PathBuf::from("/tmp/oxibelt-buffering")),
    };
    let route = RouteConfig {
      name: "route".to_string(),
      hosts: vec!["example.com".to_string()],
      path_prefix: "/".to_string(),
      replace_prefix_with: None,
      upstream: Some("app".to_string()),
      upstream_pool: None,
      upstream_http_version: None,
      generic_http_upgrade: false,
      connect_tunneling: false,
      grpc_web: false,
      cache: None,
      compression: None,
      buffering: RouteBufferingConfig {
        request: Some(BufferingMode::Streaming),
        response: Some(BufferingMode::Spool),
        max_memory_body_bytes: Some(4),
        max_temp_file_bytes: Some(8),
      },
      timeouts: Default::default(),
      waf: Default::default(),
    };
    let effective = EffectiveBuffering::new(&config, &route);
    assert_eq!(effective.request.mode, BufferingMode::Streaming);
    assert_eq!(effective.request.max_memory_body_bytes, 4);
    assert_eq!(effective.response.mode, BufferingMode::Spool);
    assert_eq!(effective.response.max_temp_file_bytes, 8);
  }
}

use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use bytes::{Bytes, BytesMut};
use futures_util::{StreamExt, TryStreamExt};
use http::{Method, Request, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;
use url::Url;

use crate::config::ExternalCacheHandlerConfig;
use crate::tls;

use super::protocol::{
  ExternalCacheBody, ExternalCacheEntryMetadata, ExternalCacheLookupRequest,
  ExternalCachePurgeRequest, ExternalCachePurgeResponse, FRAME_PREFIX_BYTES,
  external_cache_metadata_frame, parse_metadata,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ExternalHttpBody = BoxBody<Bytes, BoxError>;

pub(crate) struct ExternalCacheLookupHit {
  pub(crate) metadata: ExternalCacheEntryMetadata,
  pub(crate) body: ExternalCacheBody,
}

#[derive(Clone)]
pub(crate) struct ExternalCacheHttpClient {
  client: Client<hyper_rustls::HttpsConnector<HttpConnector>, ExternalHttpBody>,
  endpoint: Url,
  token: Option<String>,
  request_timeout: Duration,
  max_metadata_bytes: usize,
  max_body_bytes: usize,
  memory_body_bytes: usize,
}

impl ExternalCacheHttpClient {
  pub(crate) fn new(
    config: &ExternalCacheHandlerConfig,
    trusted_ca_certs: &[PathBuf],
    memory_body_bytes: usize,
    max_body_bytes: usize,
  ) -> anyhow::Result<Self> {
    let tls_config = tls::build_upstream_client_config(
      trusted_ca_certs,
      &crate::config::UpstreamEchConfig::default(),
    )
    .context("failed to build external cache handler TLS client config")?;
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_connect_timeout(Some(Duration::from_millis(config.connect_timeout_ms)));
    http.set_nodelay(true);
    let connector = HttpsConnectorBuilder::new()
      .with_tls_config(tls_config)
      .https_or_http()
      .enable_http1()
      .enable_http2()
      .wrap_connector(http);
    let mut builder = Client::builder(TokioExecutor::new());
    builder.pool_timer(TokioTimer::new());
    builder.pool_idle_timeout(Duration::from_secs(30));
    builder.pool_max_idle_per_host(config.max_inflight_requests);
    let token = match config.token_env.as_deref() {
      Some(env_name) => {
        let token = std::env::var(env_name).with_context(|| {
          format!(
            "cache external handler {} token_env is not set",
            config.name
          )
        })?;
        let token = token.trim().to_string();
        if token.is_empty() {
          bail!("cache external handler {} token_env is empty", config.name);
        }
        Some(token)
      }
      None => None,
    };
    Ok(Self {
      client: builder.build(connector),
      endpoint: config.endpoint.clone(),
      token,
      request_timeout: Duration::from_millis(config.request_timeout_ms),
      max_metadata_bytes: config.max_metadata_bytes,
      max_body_bytes,
      memory_body_bytes,
    })
  }

  pub(crate) async fn lookup(
    &self,
    request: &ExternalCacheLookupRequest,
    temp_dir: Option<&Path>,
  ) -> anyhow::Result<Option<ExternalCacheLookupHit>> {
    let body = serde_json::to_vec(request).context("failed to encode external cache lookup")?;
    let request = self.request(Method::POST, "lookup", json_body(Bytes::from(body)))?;
    tokio::time::timeout(self.request_timeout, async {
      let response = self
        .client
        .request(request)
        .await
        .context("external cache lookup failed")?;
      match response.status() {
        StatusCode::NO_CONTENT | StatusCode::NOT_FOUND => Ok(None),
        status if status.is_success() => read_framed_lookup(
          response.into_body(),
          self.max_metadata_bytes,
          self.max_body_bytes,
          self.memory_body_bytes,
          temp_dir,
        )
        .await
        .map(Some),
        status => bail!("external cache lookup returned {status}"),
      }
    })
    .await
    .context("external cache lookup timed out")?
  }

  pub(crate) async fn fill(
    &self,
    metadata: ExternalCacheEntryMetadata,
    body: ExternalCachePublishBody,
  ) -> anyhow::Result<()> {
    if metadata.body_len > self.max_body_bytes {
      bail!("external cache fill body exceeds configured limit");
    }
    let request = self.request(
      Method::POST,
      "fill",
      framed_publish_body(&metadata, body).await?,
    )?;
    let response = tokio::time::timeout(self.request_timeout, self.client.request(request))
      .await
      .context("external cache fill timed out")?
      .context("external cache fill failed")?;
    if !response.status().is_success() {
      bail!("external cache fill returned {}", response.status());
    }
    Ok(())
  }

  pub(crate) async fn revalidate(
    &self,
    metadata: &ExternalCacheEntryMetadata,
  ) -> anyhow::Result<()> {
    let body =
      serde_json::to_vec(metadata).context("failed to encode external cache revalidation")?;
    let request = self.request(Method::POST, "revalidate", json_body(Bytes::from(body)))?;
    let response = tokio::time::timeout(self.request_timeout, self.client.request(request))
      .await
      .context("external cache revalidation timed out")?
      .context("external cache revalidation failed")?;
    if !response.status().is_success() {
      bail!("external cache revalidation returned {}", response.status());
    }
    Ok(())
  }

  pub(crate) async fn purge(
    &self,
    purge: &ExternalCachePurgeRequest,
  ) -> anyhow::Result<ExternalCachePurgeResponse> {
    let body = serde_json::to_vec(purge).context("failed to encode external cache purge")?;
    let request = self.request(Method::POST, "purge", json_body(Bytes::from(body)))?;
    tokio::time::timeout(self.request_timeout, async {
      let response = self
        .client
        .request(request)
        .await
        .context("external cache purge failed")?;
      if !response.status().is_success() {
        bail!("external cache purge returned {}", response.status());
      }
      let (parts, body) = response.into_parts();
      if parts.status == StatusCode::NO_CONTENT {
        return Ok(ExternalCachePurgeResponse::default());
      }
      let bytes = http_body_util::Limited::new(body, self.max_metadata_bytes)
        .collect()
        .await
        .map_err(|error| anyhow!("external cache purge response failed: {error}"))?
        .to_bytes();
      if bytes.is_empty() {
        return Ok(ExternalCachePurgeResponse::default());
      }
      serde_json::from_slice(&bytes).context("external cache purge response is not JSON")
    })
    .await
    .context("external cache purge timed out")?
  }

  fn request(
    &self,
    method: Method,
    operation: &str,
    body: ExternalHttpBody,
  ) -> anyhow::Result<Request<ExternalHttpBody>> {
    let uri = endpoint_url(&self.endpoint, operation)?;
    let mut builder = Request::builder()
      .method(method)
      .uri(uri.as_str())
      .header(http::header::ACCEPT, "application/json");
    if let Some(token) = &self.token {
      builder = builder.header(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(&format!("Bearer {token}"))
          .context("external cache bearer token is not header-safe")?,
      );
    }
    builder
      .body(body)
      .context("failed to build external cache request")
  }
}

pub(crate) enum ExternalCachePublishBody {
  Memory(Bytes),
  File(PathBuf),
}

fn endpoint_url(base: &Url, operation: &str) -> anyhow::Result<Url> {
  let mut root = base.clone();
  if !root.path().ends_with('/') {
    let path = format!("{}/", root.path());
    root.set_path(&path);
  }
  root
    .join(operation)
    .with_context(|| format!("failed to build external cache {operation} endpoint"))
}

fn empty_body() -> ExternalHttpBody {
  Empty::<Bytes>::new()
    .map_err(|never: Infallible| -> BoxError { match never {} })
    .boxed()
}

fn json_body(bytes: Bytes) -> ExternalHttpBody {
  if bytes.is_empty() {
    return empty_body();
  }
  Full::new(bytes)
    .map_err(|never: Infallible| -> BoxError { match never {} })
    .boxed()
}

async fn framed_publish_body(
  metadata: &ExternalCacheEntryMetadata,
  body: ExternalCachePublishBody,
) -> anyhow::Result<ExternalHttpBody> {
  let metadata_frame = external_cache_metadata_frame(metadata)?;
  match body {
    ExternalCachePublishBody::Memory(body) => {
      if body.len() != metadata.body_len {
        bail!("external cache fill memory body length mismatch");
      }
      let mut bytes = BytesMut::with_capacity(metadata_frame.len() + body.len());
      bytes.extend_from_slice(&metadata_frame);
      bytes.extend_from_slice(&body);
      Ok(json_body(bytes.freeze()))
    }
    ExternalCachePublishBody::File(path) => {
      let file = tokio::fs::File::open(&path)
        .await
        .with_context(|| format!("failed to open cache body {}", path.display()))?;
      let header = futures_util::stream::once(async move {
        Ok::<Frame<Bytes>, BoxError>(Frame::data(metadata_frame))
      });
      let file = ReaderStream::new(file)
        .map_ok(Frame::data)
        .map_err(|error| -> BoxError { Box::new(error) });
      Ok(BodyExt::boxed(StreamBody::new(header.chain(file))))
    }
  }
}

async fn read_framed_lookup(
  mut body: Incoming,
  max_metadata_bytes: usize,
  max_body_bytes: usize,
  memory_body_bytes: usize,
  temp_dir: Option<&Path>,
) -> anyhow::Result<ExternalCacheLookupHit> {
  let mut prefix = BytesMut::with_capacity(FRAME_PREFIX_BYTES);
  let mut metadata_len = None;
  let mut metadata_bytes = BytesMut::new();
  let mut metadata = None;
  let mut body_bytes = BytesMut::new();
  let mut body_file = None::<tokio::fs::File>;
  let mut temp_file = None::<tempfile::NamedTempFile>;
  let mut body_written = 0usize;

  while let Some(frame) = body.frame().await {
    let frame = frame.map_err(|error| anyhow!("external cache response body failed: {error}"))?;
    let Some(mut chunk) = frame.into_data().ok() else {
      continue;
    };
    while !chunk.is_empty() {
      if prefix.len() < FRAME_PREFIX_BYTES {
        let take = (FRAME_PREFIX_BYTES - prefix.len()).min(chunk.len());
        prefix.extend_from_slice(&chunk.split_to(take));
        if prefix.len() < FRAME_PREFIX_BYTES {
          continue;
        }
        let len = u64::from_be_bytes(prefix[..].try_into().expect("prefix length checked"));
        let len = usize::try_from(len).context("external cache metadata length overflows usize")?;
        if len == 0 || len > max_metadata_bytes {
          bail!("external cache metadata length exceeds configured limit");
        }
        metadata_len = Some(len);
      }
      let len = metadata_len.expect("metadata length set after prefix");
      if metadata_bytes.len() < len {
        let take = (len - metadata_bytes.len()).min(chunk.len());
        metadata_bytes.extend_from_slice(&chunk.split_to(take));
        if metadata_bytes.len() < len {
          continue;
        }
        let parsed = parse_metadata(&metadata_bytes)?;
        if parsed.body_len > max_body_bytes {
          bail!("external cache body length exceeds configured limit");
        }
        if parsed.body_len > memory_body_bytes {
          let file = match temp_dir {
            Some(temp_dir) => tempfile::NamedTempFile::new_in(temp_dir),
            None => tempfile::NamedTempFile::new(),
          }
          .context("failed to create external cache temporary body")?;
          body_file = Some(
            tokio::fs::File::create(file.path())
              .await
              .with_context(|| {
                format!(
                  "failed to open external cache temporary body {}",
                  file.path().display()
                )
              })?,
          );
          temp_file = Some(file);
        }
        metadata = Some(parsed);
      }
      let Some(parsed) = metadata.as_ref() else {
        continue;
      };
      if !chunk.is_empty() {
        if body_written.saturating_add(chunk.len()) > parsed.body_len {
          bail!("external cache body is longer than declared");
        }
        body_written += chunk.len();
        if let Some(file) = body_file.as_mut() {
          file
            .write_all(&chunk)
            .await
            .context("failed to write external cache temporary body")?;
        } else {
          body_bytes.extend_from_slice(&chunk);
        }
        chunk = Bytes::new();
      }
    }
  }

  let metadata = metadata.ok_or_else(|| anyhow!("external cache response omitted metadata"))?;
  if body_written != metadata.body_len {
    bail!("external cache body is shorter than declared");
  }
  if let Some(mut file) = body_file {
    file
      .flush()
      .await
      .context("failed to flush external cache temporary body")?;
    drop(file);
    let file = temp_file.expect("temporary file is retained with file body");
    return Ok(ExternalCacheLookupHit {
      metadata,
      body: ExternalCacheBody::TemporaryFile(file),
    });
  }
  Ok(ExternalCacheLookupHit {
    metadata,
    body: ExternalCacheBody::Memory(body_bytes.freeze()),
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  use tokio::net::TcpListener;

  fn handler_config(endpoint: &str) -> ExternalCacheHandlerConfig {
    ExternalCacheHandlerConfig {
      name: "massive".to_string(),
      kind: crate::config::ExternalCacheHandlerKind::Http,
      endpoint: Url::parse(endpoint).unwrap(),
      token_env: None,
      connect_timeout_ms: 50,
      request_timeout_ms: 50,
      max_metadata_bytes: 1024,
      max_body_bytes: Some(1024),
      max_inflight_requests: 1,
      fail_policy: crate::config::ExternalCacheHandlerFailPolicy::LocalOnly,
    }
  }

  fn lookup_request() -> ExternalCacheLookupRequest {
    ExternalCacheLookupRequest::new(
      "default".to_string(),
      String::new(),
      "key".to_string(),
      "https".to_string(),
      "example.test".to_string(),
      "/".to_string(),
      "GET".to_string(),
      false,
    )
  }

  fn purge_request() -> ExternalCachePurgeRequest {
    ExternalCachePurgeRequest::new(
      super::super::protocol::ExternalCachePurgeKind::Exact,
      "default".to_string(),
      Some("https".to_string()),
      Some("example.test".to_string()),
      Some("/".to_string()),
      None,
      None,
      Some(String::new()),
    )
  }

  #[tokio::test]
  #[ignore = "requires loopback sockets, which are unavailable in some sandboxes"]
  async fn lookup_timeout_maps_to_error() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let endpoint = format!(
      "http://{}/internal/v1/cache/",
      listener.local_addr().unwrap()
    );
    tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.unwrap();
      let mut buffer = [0u8; 1024];
      let _ = stream.read(&mut buffer).await;
      tokio::time::sleep(Duration::from_millis(200)).await;
      let _ = stream
        .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
        .await;
    });
    let config = handler_config(&endpoint);
    let client = ExternalCacheHttpClient::new(&config, &[], 1024, 1024).unwrap();
    let request = lookup_request();
    let error = match client.lookup(&request, None).await {
      Ok(_) => panic!("delayed lookup should time out"),
      Err(error) => error,
    };
    assert!(format!("{error:#}").contains("external cache lookup timed out"));
  }

  #[tokio::test]
  #[ignore = "requires loopback sockets, which are unavailable in some sandboxes"]
  async fn lookup_timeout_covers_stalled_response_body() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let endpoint = format!(
      "http://{}/internal/v1/cache/",
      listener.local_addr().unwrap()
    );
    tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.unwrap();
      let mut buffer = [0u8; 1024];
      let _ = stream.read(&mut buffer).await;
      let _ = stream
        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 64\r\n\r\n")
        .await;
      tokio::time::sleep(Duration::from_millis(200)).await;
    });
    let config = handler_config(&endpoint);
    let client = ExternalCacheHttpClient::new(&config, &[], 1024, 1024).unwrap();
    let request = lookup_request();
    let error = match client.lookup(&request, None).await {
      Ok(_) => panic!("stalled lookup body should time out"),
      Err(error) => error,
    };
    assert!(format!("{error:#}").contains("external cache lookup timed out"));
  }

  #[tokio::test]
  #[ignore = "requires loopback sockets, which are unavailable in some sandboxes"]
  async fn purge_timeout_covers_stalled_response_body() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let endpoint = format!(
      "http://{}/internal/v1/cache/",
      listener.local_addr().unwrap()
    );
    tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.unwrap();
      let mut buffer = [0u8; 1024];
      let _ = stream.read(&mut buffer).await;
      let _ = stream
        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 16\r\n\r\n{\"purged\":")
        .await;
      tokio::time::sleep(Duration::from_millis(200)).await;
    });
    let config = handler_config(&endpoint);
    let client = ExternalCacheHttpClient::new(&config, &[], 1024, 1024).unwrap();
    let request = purge_request();
    let error = match client.purge(&request).await {
      Ok(_) => panic!("stalled purge body should time out"),
      Err(error) => error,
    };
    assert!(format!("{error:#}").contains("external cache purge timed out"));
  }
}

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
use zeroize::Zeroizing;

use crate::config::{
  CryptoConfig, ExternalCacheHandlerConfig, UpstreamEchConfig, UpstreamTlsResumptionConfig,
};
use crate::tls;

use super::protocol::{
  ExternalCacheBody, ExternalCacheEntryMetadata, ExternalCacheLookupRequest,
  ExternalCacheQueryCleanupRequest, ExternalCacheQueryCleanupResponse,
  ExternalCacheQueryEpochRequest, ExternalCacheQueryEpochResponse, FRAME_PREFIX_BYTES,
  external_cache_metadata_frame, parse_metadata,
};
#[cfg(feature = "admin-runtime")]
use super::protocol::{ExternalCachePurgeRequest, ExternalCachePurgeResponse};

pub(super) type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub(super) type ExternalHttpBody = BoxBody<Bytes, BoxError>;

pub(crate) struct ExternalCacheLookupHit {
  pub(crate) metadata: ExternalCacheEntryMetadata,
  pub(crate) body: ExternalCacheBody,
}

#[derive(Clone)]
pub(crate) struct ExternalCacheHttpClient {
  pub(super) client: Client<hyper_rustls::HttpsConnector<HttpConnector>, ExternalHttpBody>,
  endpoint: Url,
  token: Option<Zeroizing<String>>,
  pub(super) request_timeout: Duration,
  pub(super) max_metadata_bytes: usize,
  max_body_bytes: usize,
  memory_body_bytes: usize,
}

impl ExternalCacheHttpClient {
  pub(crate) fn new(
    config: &ExternalCacheHandlerConfig,
    trusted_ca_certs: &[PathBuf],
    enable_auxiliary_tls_secp256r1mlkem768: bool,
    memory_body_bytes: usize,
    max_body_bytes: usize,
  ) -> anyhow::Result<Self> {
    // External cache is an auxiliary client. Keep the legacy default provider
    // and roots while selecting the optional auxiliary key-exchange group.
    let mut crypto = CryptoConfig::default();
    crypto.auxiliary_tls.enable_secp256r1mlkem768 = enable_auxiliary_tls_secp256r1mlkem768;
    let tls_config = tls::build_upstream_client_config_with_crypto_resumption_and_revocation(
      &crypto,
      trusted_ca_certs,
      &UpstreamEchConfig::default(),
      &UpstreamTlsResumptionConfig::default(),
      None,
      "cache-external-handler",
      None,
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
        Some(Zeroizing::new(token))
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

  pub(crate) async fn query_epoch(
    &self,
    request: &ExternalCacheQueryEpochRequest,
  ) -> anyhow::Result<ExternalCacheQueryEpochResponse> {
    let body = serde_json::to_vec(request).context("failed to encode external QUERY epoch")?;
    let request = self.request(Method::POST, "query-epoch", json_body(Bytes::from(body)))?;
    tokio::time::timeout(self.request_timeout, async {
      let response = self
        .client
        .request(request)
        .await
        .context("external QUERY epoch request failed")?;
      if !response.status().is_success() {
        bail!("external QUERY epoch returned {}", response.status());
      }
      let bytes = http_body_util::Limited::new(response.into_body(), self.max_metadata_bytes)
        .collect()
        .await
        .map_err(|error| anyhow!("external QUERY epoch response failed: {error}"))?
        .to_bytes();
      let response: ExternalCacheQueryEpochResponse =
        serde_json::from_slice(&bytes).context("external QUERY epoch response is not JSON")?;
      if !response.validates_q1() {
        bail!("external cache handler does not support Q1 target epochs");
      }
      Ok(response)
    })
    .await
    .context("external QUERY epoch request timed out")?
  }

  pub(crate) async fn query_cleanup(
    &self,
    request: &ExternalCacheQueryCleanupRequest,
  ) -> anyhow::Result<ExternalCacheQueryCleanupResponse> {
    let body = serde_json::to_vec(request).context("failed to encode external QUERY cleanup")?;
    if body.len() > self.max_metadata_bytes {
      bail!("external QUERY cleanup request exceeds configured limit");
    }
    let limit = request.limit;
    let request = self.request(Method::POST, "query-cleanup", json_body(Bytes::from(body)))?;
    tokio::time::timeout(self.request_timeout, async {
      let response = self
        .client
        .request(request)
        .await
        .context("external QUERY cleanup request failed")?;
      if !response.status().is_success() {
        bail!("external QUERY cleanup returned {}", response.status());
      }
      let bytes = http_body_util::Limited::new(response.into_body(), self.max_metadata_bytes)
        .collect()
        .await
        .map_err(|error| anyhow!("external QUERY cleanup response failed: {error}"))?
        .to_bytes();
      let response: ExternalCacheQueryCleanupResponse =
        serde_json::from_slice(&bytes).context("external QUERY cleanup response is not JSON")?;
      if !response.validates_q1_cleanup(limit) {
        bail!("external cache handler returned an invalid QUERY cleanup response");
      }
      Ok(response)
    })
    .await
    .context("external QUERY cleanup request timed out")?
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

  #[cfg(feature = "admin-runtime")]
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

  pub(super) fn request(
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
        http::HeaderValue::from_str(&format!("Bearer {}", token.as_str()))
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

pub(super) fn json_body(bytes: Bytes) -> ExternalHttpBody {
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
        let prefix: [u8; FRAME_PREFIX_BYTES] = prefix[..]
          .try_into()
          .map_err(|_| anyhow!("external cache frame prefix is incomplete"))?;
        let len = u64::from_be_bytes(prefix);
        let len = usize::try_from(len).context("external cache metadata length overflows usize")?;
        if len == 0 || len > max_metadata_bytes {
          bail!("external cache metadata length exceeds configured limit");
        }
        metadata_len = Some(len);
      }
      let len =
        metadata_len.ok_or_else(|| anyhow!("external cache frame omitted its metadata length"))?;
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
    let file =
      temp_file.ok_or_else(|| anyhow!("external cache temporary body file is unavailable"))?;
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
  use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
  use std::fs;
  use std::sync::Arc;
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  use tokio::net::TcpListener;
  use tokio_rustls::TlsAcceptor;

  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

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
      super::super::protocol::CACHE_KEY_VERSION.to_string(),
      "default".to_string(),
      String::new(),
      "key".to_string(),
      "https".to_string(),
      "example.test".to_string(),
      "/".to_string(),
      "GET".to_string(),
      false,
      None,
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

  fn query_cleanup_request() -> ExternalCacheQueryCleanupRequest {
    ExternalCacheQueryCleanupRequest::new(
      "default".to_string(),
      "https".to_string(),
      "example.test".to_string(),
      "/".to_string(),
      7,
      4,
    )
  }

  #[tokio::test]
  async fn external_cache_client_negotiates_secp256r1mlkem768_with_configured_ca() {
    let temp_dir = common::TempDir::new("external-cache-pq-interop");
    let (ca, ca_key) = common::create_self_signed_cert(temp_dir.path(), "external-cache-pq-ca");
    let (cert, key) =
      common::create_ca_signed_server_cert(temp_dir.path(), "localhost", &ca, &ca_key);
    let (endpoint, server) = spawn_secp256r1mlkem768_server(&cert, &key).await;
    let config = handler_config(&endpoint);
    let request = lookup_request();

    let default =
      ExternalCacheHttpClient::new(&config, std::slice::from_ref(&ca), false, 1024, 1024)
        .expect("default external cache client should build");
    assert!(
      default.lookup(&request, None).await.is_err(),
      "default-off external cache client must not negotiate the P-256 hybrid group"
    );

    let enabled =
      ExternalCacheHttpClient::new(&config, std::slice::from_ref(&ca), true, 1024, 1024)
        .expect("auxiliary external cache client should build");
    assert!(
      enabled
        .lookup(&request, None)
        .await
        .expect("auxiliary external cache client should negotiate the P-256 hybrid group")
        .is_none()
    );
    assert!(server.await.expect("PQ TLS server task should complete"));
  }

  #[tokio::test]
  async fn query_cleanup_rejects_an_oversized_request_body_before_network_io() {
    let client = ExternalCacheHttpClient::new(
      &handler_config("http://127.0.0.1:9/internal/v1/cache/"),
      &[],
      false,
      1024,
      1024,
    )
    .unwrap();
    let request = ExternalCacheQueryCleanupRequest::new(
      "default".to_string(),
      "https".to_string(),
      "example.test".to_string(),
      format!("/{}", "x".repeat(2048)),
      7,
      4,
    );

    let error = client
      .query_cleanup(&request)
      .await
      .expect_err("oversized cleanup request must fail before connecting");
    assert!(format!("{error:#}").contains("cleanup request exceeds configured limit"));
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
    let client = ExternalCacheHttpClient::new(&config, &[], false, 1024, 1024).unwrap();
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
    let client = ExternalCacheHttpClient::new(&config, &[], false, 1024, 1024).unwrap();
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
    let client = ExternalCacheHttpClient::new(&config, &[], false, 1024, 1024).unwrap();
    let request = purge_request();
    let error = match client.purge(&request).await {
      Ok(_) => panic!("stalled purge body should time out"),
      Err(error) => error,
    };
    assert!(format!("{error:#}").contains("external cache purge timed out"));
  }

  #[tokio::test]
  #[ignore = "requires loopback sockets, which are unavailable in some sandboxes"]
  async fn query_cleanup_rejects_missing_capability() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let endpoint = format!(
      "http://{}/internal/v1/cache/",
      listener.local_addr().unwrap()
    );
    tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.unwrap();
      let mut buffer = [0u8; 1024];
      let _ = stream.read(&mut buffer).await;
      let body = b"{\"purged\":0,\"complete\":true,\"capabilities\":[]}";
      let response = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len());
      let _ = stream.write_all(response.as_bytes()).await;
      let _ = stream.write_all(body).await;
    });
    let client =
      ExternalCacheHttpClient::new(&handler_config(&endpoint), &[], false, 1024, 1024).unwrap();
    let error = client
      .query_cleanup(&query_cleanup_request())
      .await
      .expect_err("cleanup response without capabilities must fail");
    assert!(format!("{error:#}").contains("invalid QUERY cleanup response"));
  }

  #[tokio::test]
  #[ignore = "requires loopback sockets, which are unavailable in some sandboxes"]
  async fn query_cleanup_timeout_covers_stalled_response_body() {
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
        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 64\r\n\r\n{\"purged\":")
        .await;
      tokio::time::sleep(Duration::from_millis(200)).await;
    });
    let client =
      ExternalCacheHttpClient::new(&handler_config(&endpoint), &[], false, 1024, 1024).unwrap();
    let error = client
      .query_cleanup(&query_cleanup_request())
      .await
      .expect_err("stalled cleanup body must time out");
    assert!(format!("{error:#}").contains("external QUERY cleanup request timed out"));
  }

  async fn spawn_secp256r1mlkem768_server(
    cert_path: &Path,
    key_path: &Path,
  ) -> (String, tokio::task::JoinHandle<bool>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
      .await
      .expect("PQ TLS server should bind");
    let port = listener
      .local_addr()
      .expect("PQ TLS listener should expose its address")
      .port();
    let cert_bytes = fs::read(cert_path).expect("PQ TLS certificate should be readable");
    let certificates = CertificateDer::pem_slice_iter(&cert_bytes)
      .collect::<Result<Vec<_>, _>>()
      .expect("PQ TLS certificate should parse");
    let key_bytes = fs::read(key_path).expect("PQ TLS key should be readable");
    let private_key =
      PrivateKeyDer::from_pem_slice(&key_bytes).expect("PQ TLS private key should parse");
    let mut provider = crate::tls::aws_lc_provider_with_secp256r1mlkem768(true);
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::SECP256R1MLKEM768];
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
      .with_safe_default_protocol_versions()
      .expect("PQ TLS versions should configure")
      .with_no_client_auth()
      .with_single_cert(certificates, private_key)
      .expect("PQ TLS server config should build");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let server = tokio::spawn(async move {
      for _ in 0..2 {
        let Ok(Ok((stream, _))) =
          tokio::time::timeout(Duration::from_secs(3), listener.accept()).await
        else {
          return false;
        };
        let Ok(mut stream) = acceptor.accept(stream).await else {
          continue;
        };
        let mut buffer = [0_u8; 1024];
        let _ = stream.read(&mut buffer).await;
        if stream
          .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
          .await
          .is_ok()
        {
          return true;
        }
      }
      false
    });
    (
      format!("https://localhost:{port}/internal/v1/cache/"),
      server,
    )
  }
}

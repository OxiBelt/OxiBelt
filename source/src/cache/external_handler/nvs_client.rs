//! No-Vary-Search extension calls for the external cache handler client.

use anyhow::{Context, anyhow, bail};
use bytes::Bytes;
use http::Method;
use http_body_util::BodyExt;

use super::client::{ExternalCacheHttpClient, json_body};
use super::nvs_protocol::{
  ExternalCacheNvsCandidatesRequest, ExternalCacheNvsCandidatesResponse,
  ExternalCacheNvsEpochRequest, ExternalCacheNvsEpochResponse,
};

impl ExternalCacheHttpClient {
  pub(crate) async fn nvs_epoch(
    &self,
    request: &ExternalCacheNvsEpochRequest,
  ) -> anyhow::Result<ExternalCacheNvsEpochResponse> {
    let body =
      serde_json::to_vec(request).context("failed to encode external No-Vary-Search epoch")?;
    if body.len() > self.max_metadata_bytes {
      bail!("external No-Vary-Search epoch request exceeds configured limit");
    }
    let request = self.request(Method::POST, "nvs-epoch", json_body(Bytes::from(body)))?;
    tokio::time::timeout(self.request_timeout, async {
      let response = self
        .client
        .request(request)
        .await
        .context("external No-Vary-Search epoch request failed")?;
      if !response.status().is_success() {
        bail!(
          "external No-Vary-Search epoch returned {}",
          response.status()
        );
      }
      let bytes = http_body_util::Limited::new(response.into_body(), self.max_metadata_bytes)
        .collect()
        .await
        .map_err(|error| anyhow!("external No-Vary-Search epoch response failed: {error}"))?
        .to_bytes();
      let response: ExternalCacheNvsEpochResponse = serde_json::from_slice(&bytes)
        .context("external No-Vary-Search epoch response is not JSON")?;
      if !response.validates_nvs() {
        bail!("external cache handler does not support No-Vary-Search epochs");
      }
      Ok(response)
    })
    .await
    .context("external No-Vary-Search epoch request timed out")?
  }

  pub(crate) async fn nvs_candidates(
    &self,
    request: &ExternalCacheNvsCandidatesRequest,
  ) -> anyhow::Result<ExternalCacheNvsCandidatesResponse> {
    let body =
      serde_json::to_vec(request).context("failed to encode external No-Vary-Search candidates")?;
    if body.len() > self.max_metadata_bytes {
      bail!("external No-Vary-Search candidates request exceeds configured limit");
    }
    let scope = request.scope.clone();
    let limit = request.limit;
    let request = self.request(Method::POST, "nvs-candidates", json_body(Bytes::from(body)))?;
    tokio::time::timeout(self.request_timeout, async {
      let response = self
        .client
        .request(request)
        .await
        .context("external No-Vary-Search candidates request failed")?;
      if !response.status().is_success() {
        bail!(
          "external No-Vary-Search candidates returned {}",
          response.status()
        );
      }
      let bytes = http_body_util::Limited::new(response.into_body(), self.max_metadata_bytes)
        .collect()
        .await
        .map_err(|error| anyhow!("external No-Vary-Search candidates response failed: {error}"))?
        .to_bytes();
      let response: ExternalCacheNvsCandidatesResponse = serde_json::from_slice(&bytes)
        .context("external No-Vary-Search candidates response is not JSON")?;
      if !response.validates_nvs(&scope, limit) {
        bail!("external cache handler returned invalid No-Vary-Search candidates");
      }
      Ok(response)
    })
    .await
    .context("external No-Vary-Search candidates request timed out")?
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  use tokio::net::TcpListener;
  use url::Url;

  use crate::config::{
    ExternalCacheHandlerConfig, ExternalCacheHandlerFailPolicy, ExternalCacheHandlerKind,
  };

  fn handler_config(endpoint: &str) -> ExternalCacheHandlerConfig {
    ExternalCacheHandlerConfig {
      name: "massive".to_string(),
      kind: ExternalCacheHandlerKind::Http,
      endpoint: Url::parse(endpoint).unwrap(),
      token_env: None,
      connect_timeout_ms: 50,
      request_timeout_ms: 50,
      max_metadata_bytes: 1024,
      max_body_bytes: Some(1024),
      max_inflight_requests: 1,
      fail_policy: ExternalCacheHandlerFailPolicy::LocalOnly,
    }
  }

  fn epoch_request() -> ExternalCacheNvsEpochRequest {
    ExternalCacheNvsEpochRequest::new(
      "default".to_string(),
      "nvs-v1:https".to_string(),
      "example.test".to_string(),
      "/".to_string(),
      false,
    )
  }

  fn candidates_request() -> ExternalCacheNvsCandidatesRequest {
    ExternalCacheNvsCandidatesRequest::new("default".to_string(), "a".repeat(64), 4)
  }

  fn candidate() -> crate::cache::CacheNvsCandidate {
    crate::cache::CacheNvsCandidate {
      metadata: crate::cache::CacheNvsMetadata {
        version: 1,
        scope: "a".repeat(64),
        owner_uri: "/owner?ignored=one".to_string(),
        effective_uri: "https://origin.test/owner?ignored=one".to_string(),
        epoch: 0,
        policy_epoch: 0,
        candidate_limit: 4,
      },
      fields: vec![b"params=(\"ignored\")".to_vec()],
      date_ms: 1,
    }
  }

  #[tokio::test]
  #[ignore = "requires loopback sockets, which are unavailable in some sandboxes"]
  async fn epoch_rejects_a_legacy_handler_capability_set() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let endpoint = format!(
      "http://{}/internal/v1/cache/",
      listener.local_addr().unwrap()
    );
    tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.unwrap();
      let mut buffer = [0u8; 1024];
      let _ = stream.read(&mut buffer).await;
      let body = b"{\"target_epoch\":1,\"capabilities\":[]}";
      let response = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len());
      let _ = stream.write_all(response.as_bytes()).await;
      let _ = stream.write_all(body).await;
    });
    let client =
      ExternalCacheHttpClient::new(&handler_config(&endpoint), &[], false, 1024, 1024).unwrap();
    let error = client
      .nvs_epoch(&epoch_request())
      .await
      .expect_err("legacy handler must not authorize No-Vary-Search aliases");
    assert!(format!("{error:#}").contains("does not support No-Vary-Search epochs"));
  }

  #[tokio::test]
  #[ignore = "requires loopback sockets, which are unavailable in some sandboxes"]
  async fn candidates_accept_bounded_capable_response() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let endpoint = format!(
      "http://{}/internal/v1/cache/",
      listener.local_addr().unwrap()
    );
    let response = ExternalCacheNvsCandidatesResponse {
      candidates: vec![candidate()],
      capabilities: vec![super::super::nvs_protocol::NO_VARY_SEARCH_CAPABILITY.to_string()],
    };
    tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.unwrap();
      let mut buffer = [0u8; 1024];
      let _ = stream.read(&mut buffer).await;
      let body = serde_json::to_vec(&response).unwrap();
      let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len());
      let _ = stream.write_all(head.as_bytes()).await;
      let _ = stream.write_all(&body).await;
    });
    let client =
      ExternalCacheHttpClient::new(&handler_config(&endpoint), &[], false, 1024, 1024).unwrap();
    let candidates = client
      .nvs_candidates(&candidates_request())
      .await
      .expect("capable handler should return bounded candidates");
    assert_eq!(candidates.candidates.len(), 1);
    assert_eq!(
      candidates.candidates[0].metadata.owner_uri,
      "/owner?ignored=one"
    );
  }
}

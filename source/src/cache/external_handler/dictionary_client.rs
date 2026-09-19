//! Capability-bound opaque dictionary storage. A handler never selects dictionaries.

use anyhow::{Context, ensure};
use bytes::Bytes;
use http::Method;
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};

use super::client::{ExternalCacheHttpClient, json_body};

const CAPABILITY: &str = "compression-dictionaries-v1";
const MAX_EXCHANGE_BYTES: usize = 24 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DictionaryStorageOperation {
  Read,
  CompareExchange,
  WriteIfManifestMatches,
  Delete,
}

#[derive(Serialize)]
pub(crate) struct DictionaryStorageRequest<'a> {
  pub capability: &'static str,
  pub operation: DictionaryStorageOperation,
  pub key: &'a str,
  pub manifest_key: Option<&'a str>,
  pub expected_base64: Option<String>,
  pub value_base64: Option<String>,
  pub ttl_ms: Option<u64>,
}

impl<'a> DictionaryStorageRequest<'a> {
  pub(crate) fn new(operation: DictionaryStorageOperation, key: &'a str) -> Self {
    Self {
      capability: CAPABILITY,
      operation,
      key,
      manifest_key: None,
      expected_base64: None,
      value_base64: None,
      ttl_ms: None,
    }
  }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DictionaryStorageResponse {
  pub capability: String,
  pub key: String,
  pub matched: bool,
  pub value_base64: Option<String>,
}

impl ExternalCacheHttpClient {
  pub(crate) async fn dictionary_storage(
    &self,
    message: &DictionaryStorageRequest<'_>,
  ) -> anyhow::Result<DictionaryStorageResponse> {
    ensure!(
      !message.key.is_empty() && message.key.len() <= 256,
      "invalid dictionary external key"
    );
    let body = serde_json::to_vec(message)?;
    ensure!(
      body.len() <= MAX_EXCHANGE_BYTES,
      "dictionary external request exceeds limit"
    );
    let request = self.request(
      Method::POST,
      "compression-dictionaries",
      json_body(Bytes::from(body)),
    )?;
    tokio::time::timeout(self.request_timeout, async {
      let response = self.client.request(request).await?;
      ensure!(
        response.status().is_success(),
        "dictionary external capability unavailable"
      );
      let bytes = http_body_util::Limited::new(response.into_body(), MAX_EXCHANGE_BYTES)
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("dictionary external response failed: {e}"))?
        .to_bytes();
      let reply: DictionaryStorageResponse = serde_json::from_slice(&bytes)?;
      ensure!(
        reply.capability == CAPABILITY && reply.key == message.key,
        "invalid dictionary external capability or key binding"
      );
      Ok(reply)
    })
    .await
    .context("dictionary external operation timed out")?
  }
}

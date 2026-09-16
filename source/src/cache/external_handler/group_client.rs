//! External cache-group authority requests.

use anyhow::{Context, anyhow, bail};
use bytes::Bytes;
use http::Method;
use http_body_util::BodyExt;

use super::UnsupportedCacheGroups;
use super::client::{ExternalCacheHttpClient, json_body};
use super::group_protocol::{
  ExternalCacheGroupStateMode, ExternalCacheGroupStateRequest, ExternalCacheGroupStateResponse,
};

impl ExternalCacheHttpClient {
  pub(crate) async fn group_read(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let request = ExternalCacheGroupStateRequest::read(key)?;
    let response = self.group_state(request).await?;
    response.read_value()
  }

  pub(crate) async fn group_compare_exchange(
    &self,
    key: &str,
    expected: Option<&[u8]>,
    replacement: &[u8],
  ) -> anyhow::Result<bool> {
    let request = ExternalCacheGroupStateRequest::compare_exchange(key, expected, replacement)?;
    let response = self.group_state(request).await?;
    response.compare_exchange_outcome()
  }

  async fn group_state(
    &self,
    group_request: ExternalCacheGroupStateRequest,
  ) -> anyhow::Result<ExternalCacheGroupStateResponse> {
    let mode = group_request.mode;
    let body = serde_json::to_vec(&group_request)
      .context("failed to encode external cache group state request")?;
    if body.len() > self.max_metadata_bytes {
      bail!("external cache group state request exceeds configured metadata limit");
    }
    let request = self.request(
      Method::POST,
      "cache-group-state",
      json_body(Bytes::from(body)),
    )?;
    tokio::time::timeout(self.request_timeout, async {
      let response = self
        .client
        .request(request)
        .await
        .context("external cache group state request failed")?;
      if matches!(
        response.status(),
        http::StatusCode::NOT_FOUND | http::StatusCode::NOT_IMPLEMENTED
      ) {
        return Err(UnsupportedCacheGroups.into());
      }
      if !response.status().is_success() {
        bail!("external cache group state returned {}", response.status());
      }
      let bytes = http_body_util::Limited::new(response.into_body(), self.max_metadata_bytes)
        .collect()
        .await
        .map_err(|error| anyhow!("external cache group state response failed: {error}"))?
        .to_bytes();
      let response: ExternalCacheGroupStateResponse = serde_json::from_slice(&bytes)
        .context("external cache group state response is not JSON")?;
      match mode {
        ExternalCacheGroupStateMode::Read => {
          let _ = response.read_value()?;
        }
        ExternalCacheGroupStateMode::CompareExchange => {
          let _ = response.compare_exchange_outcome()?;
        }
      }
      Ok(response)
    })
    .await
    .context("external cache group state request timed out")?
  }
}

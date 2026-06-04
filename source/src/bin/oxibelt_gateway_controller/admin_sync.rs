use std::time::Duration;

use anyhow::{Context, bail};
use http::Method;
use oxibelt::admin_client::{AdminClient, AdminClientOptions, read_token};
use serde_json::{Value, json};

use super::cli::SharedArgs;

pub struct AdminSync {
  client: AdminClient,
}

impl AdminSync {
  pub fn from_args(args: &SharedArgs) -> anyhow::Result<Self> {
    let token = read_token(&args.admin_token_env, args.admin_token_file.as_deref())?;
    let mut options =
      AdminClientOptions::new(args.admin_url.clone(), token, Duration::from_secs(10));
    options.ca_certs = args.ca_certs.clone();
    options.client_cert = args.client_cert.clone();
    options.client_key = args.client_key.clone();
    Ok(Self {
      client: AdminClient::new(options)?,
    })
  }

  pub async fn sync_managed_config(&self, path: &str, content: &str) -> anyhow::Result<Value> {
    let payload = file_sync_payload(path, content);
    let mut response = None;
    for attempt in 0..2 {
      let etag = self.current_config_etag().await?;
      let candidate = self
        .client
        .request_json(
          Method::POST,
          "/admin/v1/files/sync",
          Some(payload.clone()),
          Some(&etag),
        )
        .await?;
      if candidate.status == http::StatusCode::PRECONDITION_FAILED && attempt == 0 {
        continue;
      }
      response = Some(candidate);
      break;
    }
    let response = response.context("Admin files/sync did not return a response")?;
    if !response.status.is_success() {
      let body = String::from_utf8_lossy(&response.body);
      bail!("Admin files/sync failed with {}: {}", response.status, body);
    }
    serde_json::from_slice(&response.body).context("failed to parse Admin files/sync response")
  }

  async fn current_config_etag(&self) -> anyhow::Result<String> {
    let response = self
      .client
      .request_json(Method::GET, "/admin/v1/config/status", None, None)
      .await?;
    if !response.status.is_success() {
      let body = String::from_utf8_lossy(&response.body);
      bail!(
        "Admin config/status failed with {}: {}",
        response.status,
        body
      );
    }
    let body: Value =
      serde_json::from_slice(&response.body).context("failed to parse Admin status response")?;
    body
      .get("etag")
      .and_then(Value::as_str)
      .map(str::to_string)
      .context("Admin config/status response did not include etag")
  }
}

pub fn file_sync_payload(path: &str, content: &str) -> Value {
  json!({
    "apply": "full",
    "operations": [
      {
        "op": "put",
        "root": "config",
        "path": path,
        "content": content,
      }
    ],
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn file_sync_payload_writes_controller_owned_config() {
    let payload = file_sync_payload("conf.d/gateway-api.generated.toml", "[[routes]]\n");

    assert_eq!(payload["apply"], "full");
    assert_eq!(payload["operations"][0]["op"], "put");
    assert_eq!(payload["operations"][0]["root"], "config");
    assert_eq!(
      payload["operations"][0]["path"],
      "conf.d/gateway-api.generated.toml"
    );
  }
}

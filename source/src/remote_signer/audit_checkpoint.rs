//! Purpose-bound remote signing client for Admin audit checkpoint digests.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use base64::Engine;
use tokio::net::UnixStream;

use super::protocol::{
  RemoteSignerRequest, RemoteSignerResponse, read_async_frame_with_timeout,
  write_async_frame_with_timeout,
};
use super::token::{RemoteSignerTokenProvider, token_to_wire};

/// Domain prepended by the keysigner before signing a checkpoint digest.
pub const AUDIT_CHECKPOINT_SIGNING_DOMAIN: &str = "oxibelt.admin.audit.checkpoint.signature/v1\0";

/// Connection and token settings for the purpose-bound audit checkpoint signer.
#[derive(Clone, Debug)]
pub struct AuditCheckpointSignerConfig {
  pub socket_path: PathBuf,
  pub key_id: String,
  pub token_env: String,
  pub token_file: Option<PathBuf>,
  pub token_file_reload_base_dir: Option<PathBuf>,
  pub token_reload_interval: Duration,
  pub connect_timeout: Duration,
  pub sign_timeout: Duration,
}

/// Narrow async client that can describe one audit key and sign only 32-byte digests.
#[derive(Clone)]
pub struct AuditCheckpointSigner {
  socket_path: PathBuf,
  key_id: String,
  public_key: [u8; 32],
  token_provider: RemoteSignerTokenProvider,
  connect_timeout: Duration,
  sign_timeout: Duration,
}

impl AuditCheckpointSigner {
  /// Connects to the signer and verifies that the selected purpose-bound key is Ed25519.
  pub async fn connect(config: AuditCheckpointSignerConfig) -> anyhow::Result<Self> {
    if config.key_id.trim().is_empty() {
      bail!("audit checkpoint signer key id must not be empty");
    }
    if config.connect_timeout.is_zero() {
      bail!("audit checkpoint signer connect timeout must be greater than 0");
    }
    if config.sign_timeout.is_zero() {
      bail!("audit checkpoint signer sign timeout must be greater than 0");
    }
    let signer = Self {
      socket_path: config.socket_path,
      key_id: config.key_id,
      public_key: [0; 32],
      token_provider: RemoteSignerTokenProvider::from_sources(
        config.token_file,
        config.token_file_reload_base_dir,
        &config.token_env,
        config.token_reload_interval,
      )?,
      connect_timeout: config.connect_timeout,
      sign_timeout: config.sign_timeout,
    };
    let public_key = signer.describe_key().await?;
    Ok(Self {
      public_key,
      ..signer
    })
  }

  pub fn key_id(&self) -> &str {
    &self.key_id
  }

  /// Returns the normalized raw Ed25519 public key reported during activation.
  pub fn public_key(&self) -> &[u8; 32] {
    &self.public_key
  }

  /// Requests an Ed25519 signature over `AUDIT_CHECKPOINT_SIGNING_DOMAIN || digest`.
  pub async fn sign_digest(&self, digest: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    match self
      .request_authenticated(|token| RemoteSignerRequest::SignAuditCheckpointDigest {
        token: token_to_wire(&token),
        key_id: self.key_id.clone(),
        digest: base64::engine::general_purpose::STANDARD.encode(digest),
      })
      .await?
    {
      RemoteSignerResponse::SignAuditCheckpointDigest { signature } => {
        let signature = base64::engine::general_purpose::STANDARD
          .decode(signature)
          .context("audit checkpoint signer signature must contain base64")?;
        if signature.len() != 64 {
          bail!("audit checkpoint signer Ed25519 signature must be 64 bytes");
        }
        Ok(signature)
      }
      RemoteSignerResponse::Error { code, message } => {
        bail!("audit checkpoint signing failed: {code}: {message}")
      }
      _ => bail!("audit checkpoint signer returned an unexpected sign response"),
    }
  }

  async fn describe_key(&self) -> anyhow::Result<[u8; 32]> {
    match self
      .request_authenticated(|token| RemoteSignerRequest::DescribeAuditCheckpointKey {
        token: token_to_wire(&token),
        key_id: self.key_id.clone(),
      })
      .await?
    {
      RemoteSignerResponse::DescribeAuditCheckpointKey {
        public_key,
        algorithm,
        signing_domain,
      } => {
        if algorithm != "ed25519" {
          bail!("audit checkpoint signer key must use Ed25519");
        }
        if signing_domain != AUDIT_CHECKPOINT_SIGNING_DOMAIN {
          bail!("audit checkpoint signer uses an unsupported signing domain");
        }
        let public_key = base64::engine::general_purpose::STANDARD
          .decode(public_key)
          .context("audit checkpoint signer public key must contain base64")?;
        public_key
          .try_into()
          .map_err(|_| anyhow::anyhow!("audit checkpoint signer public key must be 32 bytes"))
      }
      RemoteSignerResponse::Error { code, message } => {
        bail!("audit checkpoint key description failed: {code}: {message}")
      }
      _ => bail!("audit checkpoint signer returned an unexpected describe response"),
    }
  }

  async fn request_authenticated<F>(&self, make_request: F) -> anyhow::Result<RemoteSignerResponse>
  where
    F: Fn([u8; 32]) -> RemoteSignerRequest,
  {
    let response = self
      .request(make_request(self.token_provider.current_token()))
      .await?;
    if !super::is_unauthorized_response(&response) || !self.token_provider.reloadable() {
      return Ok(response);
    }
    self.token_provider.force_refresh();
    self
      .request(make_request(self.token_provider.current_token()))
      .await
  }

  async fn request(&self, request: RemoteSignerRequest) -> anyhow::Result<RemoteSignerResponse> {
    let mut stream =
      tokio::time::timeout(self.connect_timeout, UnixStream::connect(&self.socket_path))
        .await
        .map_err(|_| anyhow::anyhow!("audit checkpoint signer connect timed out"))?
        .with_context(|| format!("failed to connect to {}", self.socket_path.display()))?;
    write_async_frame_with_timeout(&mut stream, &request, self.sign_timeout).await?;
    read_async_frame_with_timeout(&mut stream, self.sign_timeout).await
  }
}

impl fmt::Debug for AuditCheckpointSigner {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("AuditCheckpointSigner")
      .field("socket_path", &self.socket_path)
      .field("key_id", &self.key_id)
      .field("public_key", &"[REDACTED]")
      .field("token_source", &self.token_provider.source_label())
      .field("connect_timeout", &self.connect_timeout)
      .field("sign_timeout", &self.sign_timeout)
      .finish()
  }
}

pub(super) fn signing_message(digest: &[u8; 32]) -> Vec<u8> {
  let mut message = Vec::with_capacity(AUDIT_CHECKPOINT_SIGNING_DOMAIN.len() + digest.len());
  message.extend_from_slice(AUDIT_CHECKPOINT_SIGNING_DOMAIN.as_bytes());
  message.extend_from_slice(digest);
  message
}

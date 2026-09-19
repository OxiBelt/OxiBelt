//! Durable managed resumable-upload storage.
//!
//! HTTP framing, authentication, and WAF execution deliberately live above this
//! module.  Callers obtain a reservation before accepting a body and may commit
//! it only after the entire bounded part has passed inspection.

mod local;
mod postgres_s3;
mod runtime;

use std::pin::Pin;
use std::sync::Arc;

use anyhow::bail;
use bytes::Bytes;
use futures_util::Stream;
use http::{Method, Uri};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::compression_dictionary::codec::DictionaryCoding;
use crate::compression_dictionary::fields::DictionaryHash;
use crate::config::{UploadIdentityKind, UploadProfileConfig, UploadStoreConfig, UploadStoreKind};

pub use local::LocalUploadStore;
pub use postgres_s3::PostgresS3UploadStore;
pub use runtime::{UploadPartAdmission, UploadRuntime};

pub type UploadByteStream = Pin<Box<dyn Stream<Item = anyhow::Result<Bytes>> + Send>>;

/// Expected admission failures are distinguishable from I/O failures without
/// exposing storage details or turning backend outages into false 404s.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum UploadRejection {
  NotFound,
  Conflict,
  Capacity,
}

impl std::fmt::Display for UploadRejection {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str(match self {
      Self::NotFound => "managed upload not found",
      Self::Conflict => "managed upload state conflict",
      Self::Capacity => "managed upload capacity exhausted",
    })
  }
}

impl std::error::Error for UploadRejection {}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct UploadOwner {
  pub kind: UploadIdentityKind,
  pub source: String,
  pub subject: String,
}

#[derive(Debug, Clone)]
pub struct UploadCreate {
  pub profile: UploadProfileConfig,
  pub owner: UploadOwner,
  /// Opaque HTTP-layer route/auth/policy fingerprint.  It is compared exactly
  /// on every continuation and never interpreted by storage.
  pub binding: Value,
  pub method: Method,
  pub uri: Uri,
  /// Pre-filtered end-to-end request metadata for a one-shot upstream dispatch.
  pub safe_headers: Value,
  pub declared_total: Option<u64>,
  /// Immutable RFC 9842 session binding, selected before any `104` response.
  /// `None` retains ordinary identity-content managed-upload semantics.
  pub dictionary: Option<UploadDictionaryPin>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct UploadDictionaryPin {
  pub coding: UploadDictionaryCoding,
  pub profile: String,
  pub dictionary: String,
  pub hash: DictionaryHash,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UploadDictionaryCoding {
  Dcb,
  Dcz,
}

impl From<DictionaryCoding> for UploadDictionaryCoding {
  fn from(value: DictionaryCoding) -> Self {
    match value {
      DictionaryCoding::Dcb => Self::Dcb,
      DictionaryCoding::Dcz => Self::Dcz,
    }
  }
}

impl From<UploadDictionaryCoding> for DictionaryCoding {
  fn from(value: UploadDictionaryCoding) -> Self {
    match value {
      UploadDictionaryCoding::Dcb => Self::Dcb,
      UploadDictionaryCoding::Dcz => Self::Dcz,
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UploadState {
  Active,
  Completing,
  /// A compressed session has a durable completion fence while its encoded
  /// parts are decoded and the complete decoded representation is inspected.
  Validating,
  ValidationFailed,
  Ready,
  Dispatching,
  Complete,
  Indeterminate,
  Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct UploadObject {
  pub key: String,
  pub sha256: String,
  pub bytes: u64,
  pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadStatus {
  pub id: String,
  pub profile: String,
  pub offset: u64,
  pub declared_total: Option<u64>,
  pub state: UploadState,
  pub expires_at_ms: u64,
  pub object: Option<UploadObject>,
}

#[derive(Debug, Clone)]
pub struct AppendReservation {
  pub id: String,
  pub expected_offset: u64,
  pub length: u64,
  pub fence_epoch: u64,
  pub(crate) backend_token: String,
}

impl AppendReservation {
  pub fn backend_token(&self) -> &str {
    &self.backend_token
  }
}

/// Evidence from the HTTP/WAF layer that the exact complete part was accepted.
#[derive(Debug, Clone)]
pub struct InspectedPart {
  pub bytes: u64,
  pub sha256: String,
}

#[derive(Debug, Clone)]
pub struct DispatchClaim {
  pub id: String,
  pub fence_epoch: u64,
}

#[derive(Debug, Clone)]
pub struct UploadRequestMetadata {
  pub method: Method,
  pub uri: Uri,
  pub safe_headers: Value,
  pub dictionary: Option<UploadDictionaryPin>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DispatchTerminal {
  Complete,
  Indeterminate,
}

#[derive(Clone)]
pub enum UploadStore {
  Local(Arc<LocalUploadStore>),
  PostgresS3(Arc<PostgresS3UploadStore>),
}

impl UploadStore {
  pub async fn open(config: &UploadStoreConfig) -> anyhow::Result<Arc<Self>> {
    let store = match config.kind {
      UploadStoreKind::Local => Self::Local(Arc::new(LocalUploadStore::open(config).await?)),
      UploadStoreKind::PostgresS3 => {
        Self::PostgresS3(Arc::new(PostgresS3UploadStore::open(config).await?))
      }
    };
    Ok(Arc::new(store))
  }

  pub async fn create(&self, request: UploadCreate) -> anyhow::Result<UploadStatus> {
    match self {
      Self::Local(store) => store.create(request).await,
      Self::PostgresS3(store) => store.create(request).await,
    }
  }

  pub async fn lookup(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &Value,
  ) -> anyhow::Result<UploadStatus> {
    match self {
      Self::Local(store) => store.lookup(id, owner, binding).await,
      Self::PostgresS3(store) => store.lookup(id, owner, binding).await,
    }
  }

  pub async fn declare_length(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &Value,
    total: u64,
  ) -> anyhow::Result<UploadStatus> {
    match self {
      Self::Local(store) => store.declare_length(id, owner, binding, total).await,
      Self::PostgresS3(store) => store.declare_length(id, owner, binding, total).await,
    }
  }

  pub async fn begin_append(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &Value,
    expected_offset: u64,
    length: u64,
  ) -> anyhow::Result<AppendReservation> {
    if length == 0 {
      bail!("managed upload part length must be nonzero");
    }
    match self {
      Self::Local(store) => {
        store
          .begin_append(id, owner, binding, expected_offset, length)
          .await
      }
      Self::PostgresS3(store) => {
        store
          .begin_append(id, owner, binding, expected_offset, length)
          .await
      }
    }
  }

  pub async fn commit_fully_inspected_part(
    &self,
    reservation: &AppendReservation,
    inspected: &InspectedPart,
    body: UploadByteStream,
  ) -> anyhow::Result<UploadStatus> {
    if inspected.bytes > reservation.length || !is_sha256_hex(&inspected.sha256) {
      bail!("managed upload inspection evidence does not match reserved part");
    }
    match self {
      Self::Local(store) => {
        store
          .commit_fully_inspected_part(reservation, inspected, body)
          .await
      }
      Self::PostgresS3(store) => {
        store
          .commit_fully_inspected_part(reservation, inspected, body)
          .await
      }
    }
  }

  /// Commits an RFC 9842 encoded part.  Its bytes are deliberately not
  /// represented as WAF evidence: the complete decoded representation is
  /// inspected under the validation fence at completion time.
  pub async fn commit_encoded_part(
    &self,
    reservation: &AppendReservation,
    bytes: u64,
    sha256: String,
    body: UploadByteStream,
  ) -> anyhow::Result<UploadStatus> {
    if bytes == 0 || bytes > reservation.length || !is_sha256_hex(&sha256) {
      bail!("managed upload encoded part does not match reserved part");
    }
    // Backends still independently hash the stream and compare this durable
    // staging evidence; it is not a WAF acceptance proof.
    let staged = InspectedPart { bytes, sha256 };
    match self {
      Self::Local(store) => {
        store
          .commit_fully_inspected_part(reservation, &staged, body)
          .await
      }
      Self::PostgresS3(store) => {
        store
          .commit_fully_inspected_part(reservation, &staged, body)
          .await
      }
    }
  }

  pub async fn abort_append(&self, reservation: &AppendReservation) -> anyhow::Result<()> {
    match self {
      Self::Local(store) => store.abort_append(reservation).await,
      Self::PostgresS3(store) => store.abort_append(reservation).await,
    }
  }

  pub async fn request_metadata(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &Value,
  ) -> anyhow::Result<UploadRequestMetadata> {
    match self {
      Self::Local(store) => store.request_metadata(id, owner, binding).await,
      Self::PostgresS3(store) => store.request_metadata(id, owner, binding).await,
    }
  }

  pub async fn read_object(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &Value,
  ) -> anyhow::Result<UploadByteStream> {
    match self {
      Self::Local(store) => store.read_object(id, owner, binding).await,
      Self::PostgresS3(store) => store.read_object(id, owner, binding).await,
    }
  }

  pub async fn read_assembled(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &Value,
  ) -> anyhow::Result<UploadByteStream> {
    match self {
      Self::Local(store) => store.read_assembled(id, owner, binding).await,
      Self::PostgresS3(store) => store.read_assembled(id, owner, binding).await,
    }
  }

  pub async fn claim_complete(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &Value,
    expected_offset: u64,
  ) -> anyhow::Result<UploadStatus> {
    match self {
      Self::Local(store) => {
        store
          .claim_complete(id, owner, binding, expected_offset)
          .await
      }
      Self::PostgresS3(store) => {
        store
          .claim_complete(id, owner, binding, expected_offset)
          .await
      }
    }
  }

  pub async fn publish_object(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &Value,
  ) -> anyhow::Result<UploadStatus> {
    match self {
      Self::Local(store) => store.publish_object(id, owner, binding).await,
      Self::PostgresS3(store) => store.publish_object(id, owner, binding).await,
    }
  }

  /// Publishes the already-decoded, fully inspected representation retained by
  /// a `Validating` RFC 9842 session. The encoded chunks stay immutable for
  /// audit/recovery; delivery always uses this distinct identity object.
  pub async fn publish_decoded_object(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &Value,
    bytes: u64,
    sha256: &str,
    body: UploadByteStream,
  ) -> anyhow::Result<UploadStatus> {
    if !is_sha256_hex(sha256) {
      bail!("managed upload decoded object digest is invalid");
    }
    match self {
      Self::Local(store) => {
        store
          .publish_decoded_object(id, owner, binding, bytes, sha256, body)
          .await
      }
      Self::PostgresS3(store) => {
        store
          .publish_decoded_object(id, owner, binding, bytes, sha256, body)
          .await
      }
    }
  }

  /// Makes a compressed session terminal after its pinned dictionary cannot be
  /// recovered, its prelude does not match, decoding exceeds a budget, or the
  /// assembled decoded representation fails inspection.  It intentionally
  /// never resets the offset or reopens delivery.
  pub async fn fail_validation(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &Value,
  ) -> anyhow::Result<UploadStatus> {
    match self {
      Self::Local(store) => store.fail_validation(id, owner, binding).await,
      Self::PostgresS3(store) => store.fail_validation(id, owner, binding).await,
    }
  }

  pub async fn begin_dispatch(
    &self,
    id: &str,
    owner: &UploadOwner,
    binding: &Value,
  ) -> anyhow::Result<DispatchClaim> {
    match self {
      Self::Local(store) => store.begin_dispatch(id, owner, binding).await,
      Self::PostgresS3(store) => store.begin_dispatch(id, owner, binding).await,
    }
  }

  pub async fn finish_dispatch(
    &self,
    claim: &DispatchClaim,
    terminal: DispatchTerminal,
  ) -> anyhow::Result<UploadStatus> {
    match self {
      Self::Local(store) => store.finish_dispatch(claim, terminal).await,
      Self::PostgresS3(store) => store.finish_dispatch(claim, terminal).await,
    }
  }

  pub async fn delete(&self, id: &str, owner: &UploadOwner, binding: &Value) -> anyhow::Result<()> {
    match self {
      Self::Local(store) => store.delete(id, owner, binding).await,
      Self::PostgresS3(store) => store.delete(id, owner, binding).await,
    }
  }

  pub async fn collect_garbage(&self, now_ms: u64, limit: usize) -> anyhow::Result<usize> {
    match self {
      Self::Local(store) => store.collect_garbage(now_ms, limit).await,
      Self::PostgresS3(store) => store.collect_garbage(now_ms, limit).await,
    }
  }
}

pub(crate) fn is_sha256_hex(value: &str) -> bool {
  value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

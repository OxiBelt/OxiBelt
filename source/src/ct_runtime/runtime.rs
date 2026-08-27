//! Activated CT log runtimes and protocol endpoint dispatch.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use base64::Engine as _;
use bytes::Bytes;
use der::{Decode as _, Encode as _};
use futures_util::future::BoxFuture;
use http::{Method, StatusCode};
use object_store::UpdateVersion;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::{Mutex, OwnedMutexGuard, oneshot};
use x509_cert::Certificate;

use crate::config::{
  CertificateTransparencyConfig, CertificateTransparencyIdentityAlgorithm,
  CertificateTransparencyLogConfig, CertificateTransparencyLogRole, CertificateTransparencyProfile,
  CertificateTransparencyProtocol,
};
use crate::control_http::{ControlHttpClient, empty_body, full_body, uri_from_url};
use crate::ct::merkle::{self, Hash};
use crate::ct::rfc6962::{
  AddChainResponseV1, DigitallySigned, GetEntriesEntryV1, GetEntriesResponseV1,
  GetProofByHashResponseV1, GetSthConsistencyResponseV1, GetSthResponseV1, MerkleTreeLeafV1,
  SignedCertificateTimestampV1, SignedEntryV1, TimestampedEntryV1, encode_sct_signed_input,
  encode_sth_signed_input,
};
use crate::ct::rfc9162::{
  ConsistencyProofV2, ExtensionV2, InclusionProofV2, LogIdV2, SignedCertificateTimestampV2,
  SignedTreeHeadV2, SubmitEntryRequestV2, SubmitEntryResponseV2, TimestampedCertificateEntryV2,
  TransItemV2, TreeHeadV2, encode_trans_item_list,
};
use crate::ct::static_ct::{
  StaticCheckpoint, StaticTileLeaf, TileKind, TilePath, decode_data_tile, decode_hash_tile,
  encode_data_tile, encode_hash_tile, issuer_fingerprint, issuer_fingerprint_hex,
  leaf_index_extension, parse_leaf_index_extension,
};
use crate::metrics::{CtRejectionReason, Metrics};
use crate::remote_signer::{CtLogProfile, CtLogSigner, CtLogSignerConfig, CtTranscriptClass};

use super::{
  AcceptedRoot, AcceptedRootTrust, CtChainPolicy, CtLocalStore, CtLogBinding, CtObjectPublisher,
  CtObjectStoreConfig, CtPostgresStore, CtReservedEntry, CtStoredEntry, CtSubmissionKind,
  CtTreeState, S3ObjectStoreConfig, load_verified_root_bundle, validate_chain,
};

const MAX_PUBLIC_KEY_BYTES: u64 = 4096;
const MAX_ROOT_TRUST_KEY_BYTES: u64 = 4096;
const MAX_SUBMISSION_CERTIFICATES: usize = 16;
const MAX_QUERY_BYTES: usize = 8192;
const MAX_RETIRED_ARTIFACT_PATH_BYTES: usize = 4096;
const MAX_RETIRED_CHECKPOINT_BYTES: usize = 128 * 1024;
const MAX_RETIRED_ISSUER_BYTES: usize = 1024 * 1024;
const V2_LEAF_INDEX_EXTENSION: u16 = 0;

#[derive(Clone)]
pub struct CtRuntime {
  logs: Arc<HashMap<String, Arc<CtLogRuntime>>>,
}

pub struct CtHttpResponse {
  pub status: StatusCode,
  pub content_type: &'static str,
  pub body: Bytes,
  pub immutable: bool,
}

struct CtLogRuntime {
  config: CertificateTransparencyLogConfig,
  public_key_spki: Vec<u8>,
  v1_log_id: Hash,
  v2_log_id: Option<LogIdV2>,
  roots: Vec<AcceptedRoot>,
  signer: Option<CtLogSigner>,
  store: Option<CtStore>,
  object_publisher: Option<CtObjectPublisher>,
  checkpoint_version: Mutex<Option<UpdateVersion>>,
  publisher_run: Mutex<()>,
  submission_run: Arc<Mutex<()>>,
  last_publish_millis: AtomicU64,
  publish_failure_since_millis: AtomicU64,
  metrics: Arc<Metrics>,
  gateway_witness: Mutex<Option<GatewayWitness>>,
}

#[derive(Clone)]
enum CtStore {
  Local(CtLocalStore),
  Postgres(CtPostgresStore),
}

enum CtReservationCleanup {
  Local(CtLocalStore),
  Postgres(CtPostgresStore),
}

struct CtUnsignedReservationGuard {
  cleanup: Option<CtReservationCleanup>,
  leaf_index: u64,
  submission_guard: Option<OwnedMutexGuard<()>>,
}

impl CtUnsignedReservationGuard {
  fn new(store: &CtStore, leaf_index: u64, submission_guard: OwnedMutexGuard<()>) -> Self {
    let cleanup = match store {
      CtStore::Local(store) => CtReservationCleanup::Local(store.clone()),
      CtStore::Postgres(store) => CtReservationCleanup::Postgres(store.clone()),
    };
    Self {
      cleanup: Some(cleanup),
      leaf_index,
      submission_guard: Some(submission_guard),
    }
  }

  fn existing(submission_guard: OwnedMutexGuard<()>) -> Self {
    Self {
      cleanup: None,
      leaf_index: 0,
      submission_guard: Some(submission_guard),
    }
  }

  fn commit(mut self) {
    self.cleanup = None;
    self.submission_guard = None;
  }
}

async fn clean_up_cancelled_reservation(
  cleanup: CtReservationCleanup,
  leaf_index: u64,
  submission_guard: OwnedMutexGuard<()>,
) {
  let result = match cleanup {
    CtReservationCleanup::Local(store) => store.discard_unsigned_tail(leaf_index).await,
    CtReservationCleanup::Postgres(store) => store.discard_unsigned_tail(leaf_index).await,
  };
  if let Err(error) = result {
    tracing::error!(leaf_index, error = %error, "failed to clean up cancelled CT reservation");
  }
  drop(submission_guard);
}

impl Drop for CtUnsignedReservationGuard {
  fn drop(&mut self) {
    let (Some(cleanup), Some(submission_guard)) =
      (self.cleanup.take(), self.submission_guard.take())
    else {
      return;
    };
    let leaf_index = self.leaf_index;
    tokio::spawn(async move {
      clean_up_cancelled_reservation(cleanup, leaf_index, submission_guard).await;
    });
  }
}

#[derive(Clone, Copy)]
struct GatewayWitness {
  tree_size: u64,
  timestamp: u64,
  root_hash: Hash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RetiredArtifact {
  Checkpoint,
  Tile {
    path: TilePath,
    relative: String,
  },
  Issuer {
    fingerprint: String,
    relative: String,
  },
}

impl RetiredArtifact {
  fn relative_path(&self) -> &str {
    match self {
      Self::Checkpoint => "checkpoint",
      Self::Tile { relative, .. } => relative,
      Self::Issuer { relative, .. } => relative,
    }
  }
}

#[derive(Deserialize)]
struct AddChainRequestV1 {
  chain: Vec<String>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
  error: &'a str,
}

impl CtRuntime {
  pub async fn new(
    config: &CertificateTransparencyConfig,
    metrics: Arc<Metrics>,
  ) -> anyhow::Result<Self> {
    if !config.enabled {
      return Ok(Self {
        logs: Arc::new(HashMap::new()),
      });
    }
    let mut logs = HashMap::new();
    for log in &config.logs {
      let runtime = Arc::new(
        CtLogRuntime::new(config.profile, log.clone(), metrics.clone())
          .await
          .with_context(|| format!("failed to activate CT log {}", log.name))?,
      );
      CtLogRuntime::spawn_publisher(&runtime);
      logs.insert(log.name.clone(), runtime);
    }
    Ok(Self {
      logs: Arc::new(logs),
    })
  }

  pub fn is_empty(&self) -> bool {
    self.logs.is_empty()
  }

  pub fn is_ready(&self) -> bool {
    self.logs.values().all(|log| log.publication_within_mmd())
  }

  pub async fn handle(
    &self,
    log_name: &str,
    method: &Method,
    path: &str,
    query: Option<&str>,
    body: &[u8],
    control_http: &ControlHttpClient,
  ) -> CtHttpResponse {
    let Some(log) = self.logs.get(log_name) else {
      return json_error(StatusCode::NOT_FOUND, "unknown CT log");
    };
    match log.handle(method, path, query, body, control_http).await {
      Ok(response) => response,
      Err(error) => {
        tracing::warn!(log = log_name, error = %error, "CT request failed closed");
        log
          .metrics
          .record_ct_submission_rejected(classify_rejection(&error));
        if log.config.role == CertificateTransparencyLogRole::Gateway {
          log.metrics.record_ct_gateway_verification_failure();
        }
        json_error(
          StatusCode::SERVICE_UNAVAILABLE,
          "CT log temporarily unavailable",
        )
      }
    }
  }
}

impl CtLogRuntime {
  async fn new(
    profile: CertificateTransparencyProfile,
    config: CertificateTransparencyLogConfig,
    metrics: Arc<Metrics>,
  ) -> anyhow::Result<Self> {
    let public_key_path = config
      .identity
      .public_key_file
      .as_deref()
      .ok_or_else(|| anyhow!("CT public identity file is missing"))?;
    let public_key_spki = read_bounded(public_key_path, MAX_PUBLIC_KEY_BYTES)?;
    let v1_log_id = Sha256::digest(&public_key_spki).into();
    let v2_log_id = config
      .identity
      .oid
      .as_deref()
      .map(encode_oid_value)
      .transpose()?
      .map(LogIdV2::new)
      .transpose()
      .map_err(|error| anyhow!("invalid RFC 9162 LogID: {error}"))?;
    let identity_profile = match (config.protocol, config.identity.algorithm) {
      (CertificateTransparencyProtocol::StaticRfc6962V1, _) => CtLogProfile::Rfc6962P256Sha256,
      (
        CertificateTransparencyProtocol::Rfc9162V2,
        CertificateTransparencyIdentityAlgorithm::P256,
      ) => CtLogProfile::Rfc9162P256Sha256,
      (
        CertificateTransparencyProtocol::Rfc9162V2,
        CertificateTransparencyIdentityAlgorithm::Ed25519,
      ) => CtLogProfile::Rfc9162Ed25519,
    };
    crate::remote_signer::validate_ct_log_public_key(identity_profile, &public_key_spki)
      .context("configured CT public identity has the wrong canonical key shape")?;

    let root_config = &config.signed_root;
    let mut trusted_keys = BTreeMap::new();
    for key_path in &root_config.trusted_ed25519_keys {
      let key = load_ed25519_key(key_path)?;
      let key_id = short_key_id(&key);
      if trusted_keys.insert(key_id, key).is_some() {
        bail!("duplicate CT accepted-root trust key");
      }
    }
    let root_bundle = load_verified_root_bundle(
      root_config
        .bundle_path
        .as_deref()
        .ok_or_else(|| anyhow!("CT accepted-root bundle path is missing"))?,
      root_config
        .bundle_sha256
        .as_deref()
        .ok_or_else(|| anyhow!("CT accepted-root bundle digest is missing"))?,
      &AcceptedRootTrust {
        threshold: root_config.quorum,
        production: profile == CertificateTransparencyProfile::Production,
        keys: trusted_keys,
      },
    )?;

    let signer = if config.role == CertificateTransparencyLogRole::Operator {
      let signer_config = &config.signer;
      let signer = CtLogSigner::connect(CtLogSignerConfig {
        socket_path: signer_config
          .socket_path
          .clone()
          .ok_or_else(|| anyhow!("CT signer socket path is missing"))?,
        key_id: signer_config
          .key_id
          .clone()
          .ok_or_else(|| anyhow!("CT signer key id is missing"))?,
        profile: identity_profile,
        token_env: signer_config.token_env.clone().unwrap_or_default(),
        token_file: signer_config.token_file.clone(),
        token_file_reload_base_dir: None,
        token_reload_interval: Duration::from_secs(1),
        connect_timeout: Duration::from_millis(signer_config.io_timeout_ms),
        sign_timeout: Duration::from_millis(signer_config.io_timeout_ms),
      })
      .await?;
      if signer.public_key_spki() != public_key_spki {
        bail!("CT signer public key differs from configured immutable public identity");
      }
      Some(signer)
    } else {
      None
    };

    let (store, object_publisher) = if config.role == CertificateTransparencyLogRole::Operator {
      match profile {
        CertificateTransparencyProfile::Local => {
          let root = config
            .storage
            .posix_path
            .as_deref()
            .ok_or_else(|| anyhow!("local CT storage path is missing"))?;
          let store = CtLocalStore::open(
            root,
            &config.name,
            config.protocol.as_str(),
            &public_key_spki,
          )?;
          let publisher = CtObjectPublisher::from_config(
            &CtObjectStoreConfig::Local {
              root: root.join("objects"),
            },
            &config.name,
            false,
          )?;
          (Some(CtStore::Local(store)), Some(publisher))
        }
        CertificateTransparencyProfile::Production => {
          let database_url = secret_string(
            config.storage.postgres_url_env.as_deref(),
            config.storage.postgres_url_file.as_deref(),
            "CT PostgreSQL URL",
          )?;
          let binding = CtLogBinding {
            log_name: config.name.clone(),
            protocol: config.protocol.as_str().to_string(),
            public_identity: public_key_spki.clone(),
            log_identifier: config
              .identity
              .oid
              .clone()
              .unwrap_or_else(|| base64::engine::general_purpose::STANDARD.encode(v1_log_id)),
            mmd_millis: config.mmd_seconds.saturating_mul(1000),
          };
          let store = CtPostgresStore::connect_checked(&database_url, 16, &binding).await?;
          let publisher = CtObjectPublisher::from_config(
            &CtObjectStoreConfig::S3(S3ObjectStoreConfig {
              bucket: required_clone(&config.storage.s3_bucket, "CT S3 bucket")?,
              region: required_clone(&config.storage.s3_region, "CT S3 region")?,
              endpoint: config.storage.s3_endpoint.clone(),
              access_key_id: config
                .storage
                .s3_access_key_env
                .as_deref()
                .map(read_environment)
                .transpose()?,
              secret_access_key: config
                .storage
                .s3_secret_key_env
                .as_deref()
                .map(read_environment)
                .transpose()?,
              session_token: config
                .storage
                .s3_session_token_env
                .as_deref()
                .map(read_environment)
                .transpose()?,
              virtual_hosted_style: config.storage.s3_virtual_hosted_style,
              allow_http_for_local_development: false,
            }),
            config.storage.s3_prefix.as_deref().unwrap_or(&config.name),
            true,
          )?;
          publisher.probe_capabilities(&config.name).await?;
          (Some(CtStore::Postgres(store)), Some(publisher))
        }
      }
    } else {
      (None, None)
    };

    let runtime = Self {
      config,
      public_key_spki,
      v1_log_id,
      v2_log_id,
      roots: root_bundle.roots,
      signer,
      store,
      object_publisher,
      checkpoint_version: Mutex::new(None),
      publisher_run: Mutex::new(()),
      submission_run: Arc::new(Mutex::new(())),
      last_publish_millis: AtomicU64::new(0),
      publish_failure_since_millis: AtomicU64::new(0),
      metrics,
      gateway_witness: Mutex::new(None),
    };
    if runtime.config.role == CertificateTransparencyLogRole::Operator {
      runtime.integrate_and_publish().await?;
    }
    Ok(runtime)
  }

  fn spawn_publisher(runtime: &Arc<Self>) {
    if runtime.config.role != CertificateTransparencyLogRole::Operator {
      return;
    }
    let weak = Arc::downgrade(runtime);
    let period = Duration::from_secs((runtime.config.mmd_seconds / 4).clamp(1, 15));
    tokio::spawn(async move {
      let mut interval = tokio::time::interval(period);
      interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
      interval.tick().await;
      loop {
        interval.tick().await;
        let Some(runtime) = weak.upgrade() else {
          break;
        };
        if let Err(error) = runtime.integrate_and_publish().await {
          runtime.metrics.record_ct_publish_failure();
          runtime.mark_publish_failure();
          if runtime.publication_deadline_exceeded()
            && let Err(freeze_error) = runtime.freeze_for_mmd_violation().await
          {
            tracing::error!(
              log = runtime.config.name,
              error = %freeze_error,
              "failed to durably freeze CT log after an MMD violation"
            );
          }
          tracing::error!(
            log = runtime.config.name,
            error = %error,
            "CT background publisher failed closed"
          );
        }
      }
    });
  }

  async fn handle(
    &self,
    method: &Method,
    path: &str,
    query: Option<&str>,
    body: &[u8],
    control_http: &ControlHttpClient,
  ) -> anyhow::Result<CtHttpResponse> {
    if self.config.role == CertificateTransparencyLogRole::Operator
      && is_submission_path(path)
      && !self.publication_within_mmd()
    {
      bail!("CT publication health is outside the maximum merge delay");
    }
    if self.config.role == CertificateTransparencyLogRole::Gateway {
      return self.gateway(method, path, query, body, control_http).await;
    }
    if self.config.role == CertificateTransparencyLogRole::RetiredReadOnly {
      return self
        .retired_read_only(method, path, query, body, control_http)
        .await;
    }
    match self.config.protocol {
      CertificateTransparencyProtocol::StaticRfc6962V1 => {
        self.handle_v1(method, path, query, body).await
      }
      CertificateTransparencyProtocol::Rfc9162V2 => self.handle_v2(method, path, query, body).await,
    }
  }

  async fn retired_read_only(
    &self,
    method: &Method,
    path: &str,
    query: Option<&str>,
    body: &[u8],
    client: &ControlHttpClient,
  ) -> anyhow::Result<CtHttpResponse> {
    if method != Method::GET {
      return Ok(json_error(
        StatusCode::METHOD_NOT_ALLOWED,
        "retired CT log accepts GET only",
      ));
    }
    if query.is_some() || !body.is_empty() {
      return Ok(json_error(
        StatusCode::BAD_REQUEST,
        "retired CT artifacts do not accept a query or request body",
      ));
    }
    let artifact = match retired_artifact_path(self.config.protocol, path) {
      Ok(Some(artifact)) => artifact,
      Ok(None) => {
        return Ok(json_error(
          StatusCode::NOT_FOUND,
          "unknown retired CT artifact",
        ));
      }
      Err(_) => {
        return Ok(json_error(
          StatusCode::BAD_REQUEST,
          "retired CT artifact path is invalid",
        ));
      }
    };
    let source = self
      .config
      .storage
      .object_source_url
      .as_deref()
      .ok_or_else(|| anyhow!("retired CT object source is missing"))?;
    let url = retired_artifact_url(source, artifact.relative_path())?;
    let maximum = match &artifact {
      RetiredArtifact::Checkpoint => MAX_RETIRED_CHECKPOINT_BYTES,
      RetiredArtifact::Tile { path, .. } => match path.kind {
        TileKind::Hashes { .. } => path
          .partial_width
          .map_or(crate::ct::static_ct::TILE_WIDTH, usize::from)
          .saturating_mul(merkle::HASH_BYTES),
        TileKind::Data => self.config.gateway.max_response_bytes,
      },
      RetiredArtifact::Issuer { .. } => MAX_RETIRED_ISSUER_BYTES,
    };
    let request = http::Request::builder()
      .method(Method::GET)
      .uri(uri_from_url(&url)?)
      .header(
        http::header::ACCEPT,
        "text/plain, application/octet-stream, application/transitem+tls",
      )
      .body(empty_body())?;
    let response = client
      .request(request, Duration::from_secs(10), maximum)
      .await?;
    if response.status == StatusCode::NOT_FOUND {
      return Ok(json_error(
        StatusCode::NOT_FOUND,
        "retired CT artifact is unavailable",
      ));
    }
    if response.status != StatusCode::OK {
      bail!("retired CT object source returned {}", response.status);
    }
    self.validate_retired_artifact(&artifact, &response.body)?;
    let (content_type, immutable) = match artifact {
      RetiredArtifact::Checkpoint => (
        if self.config.protocol == CertificateTransparencyProtocol::Rfc9162V2 {
          "application/transitem+tls"
        } else {
          "text/plain; charset=utf-8"
        },
        false,
      ),
      RetiredArtifact::Tile { .. } | RetiredArtifact::Issuer { .. } => {
        ("application/octet-stream", true)
      }
    };
    Ok(CtHttpResponse {
      status: StatusCode::OK,
      content_type,
      body: response.body,
      immutable,
    })
  }

  fn validate_retired_artifact(
    &self,
    artifact: &RetiredArtifact,
    body: &[u8],
  ) -> anyhow::Result<()> {
    match artifact {
      RetiredArtifact::Checkpoint => match self.config.protocol {
        CertificateTransparencyProtocol::StaticRfc6962V1 => {
          let text = std::str::from_utf8(body).context("retired CT checkpoint is not UTF-8")?;
          let checkpoint = StaticCheckpoint::parse(text, &self.v1_log_id)
            .map_err(|error| anyhow!("retired CT checkpoint is malformed: {error}"))?;
          if checkpoint.origin != self.config.name {
            bail!("retired CT checkpoint origin differs from the configured log");
          }
          if checkpoint.tree_head_signature.hash_algorithm
            != crate::ct::rfc6962::HASH_ALGORITHM_SHA256
            || checkpoint.tree_head_signature.signature_algorithm
              != crate::ct::rfc6962::SIGNATURE_ALGORITHM_ECDSA
          {
            bail!("retired CT checkpoint uses an unsupported signature algorithm");
          }
          self.verify_log_signature(
            &checkpoint.signed_tree_head_input(),
            &checkpoint.tree_head_signature.signature,
          )
        }
        CertificateTransparencyProtocol::Rfc9162V2 => {
          let item = TransItemV2::decode(body)
            .map_err(|error| anyhow!("retired RFC 9162 checkpoint is malformed: {error}"))?;
          let TransItemV2::SignedTreeHead(sth) = item else {
            bail!("retired RFC 9162 checkpoint is not an STH TransItem");
          };
          if Some(&sth.log_id) != self.v2_log_id.as_ref() {
            bail!("retired RFC 9162 checkpoint has the wrong LogID");
          }
          let transcript = sth
            .tree_head
            .encode_signed_input()
            .map_err(|error| anyhow!("retired RFC 9162 checkpoint is malformed: {error}"))?;
          self.verify_log_signature(&transcript, &sth.signature)
        }
      },
      RetiredArtifact::Tile { path, .. } => {
        let expected_width = path
          .partial_width
          .map_or(crate::ct::static_ct::TILE_WIDTH, usize::from);
        match path.kind {
          TileKind::Hashes { .. } => decode_hash_tile(body, expected_width)
            .map(|_| ())
            .map_err(|error| anyhow!("retired Static CT hash tile is malformed: {error}")),
          TileKind::Data => decode_data_tile(body, expected_width)
            .map(|_| ())
            .map_err(|error| anyhow!("retired Static CT data tile is malformed: {error}")),
        }
      }
      RetiredArtifact::Issuer { fingerprint, .. } => {
        Certificate::from_der(body).context("retired Static CT issuer is not a DER certificate")?;
        if issuer_fingerprint_hex(body) != *fingerprint {
          bail!("retired Static CT issuer fingerprint differs from its path");
        }
        Ok(())
      }
    }
  }

  async fn handle_v1(
    &self,
    method: &Method,
    path: &str,
    query: Option<&str>,
    body: &[u8],
  ) -> anyhow::Result<CtHttpResponse> {
    match (method, path) {
      (&Method::POST, path) if path.ends_with("/ct/v1/add-chain") => {
        self.submit_v1(body, CtSubmissionKind::Certificate).await
      }
      (&Method::POST, path) if path.ends_with("/ct/v1/add-pre-chain") => {
        self.submit_v1(body, CtSubmissionKind::Precertificate).await
      }
      (&Method::GET, path) if path.ends_with("/ct/v1/get-sth") => self.get_sth_v1().await,
      (&Method::GET, path) if path.ends_with("/ct/v1/get-entries") => {
        self.get_entries_v1(query).await
      }
      (&Method::GET, path) if path.ends_with("/ct/v1/get-proof-by-hash") => {
        self.get_proof_v1(query).await
      }
      (&Method::GET, path) if path.ends_with("/ct/v1/get-sth-consistency") => {
        self.get_consistency_v1(query).await
      }
      (&Method::GET, path) if path.ends_with("/ct/v1/get-roots") => {
        let certificates = self
          .roots
          .iter()
          .map(|root| base64::engine::general_purpose::STANDARD.encode(&root.der))
          .collect::<Vec<_>>();
        json(
          StatusCode::OK,
          &serde_json::json!({ "certificates": certificates }),
          false,
        )
      }
      (&Method::GET, path) if path.ends_with("/checkpoint") => self.get_checkpoint().await,
      (&Method::GET, path) if path.contains("/tile/") || path.contains("/issuer/") => {
        self.get_static_object(path).await
      }
      _ => Ok(json_error(StatusCode::NOT_FOUND, "unknown CT v1 endpoint")),
    }
  }

  async fn gateway(
    &self,
    method: &Method,
    path: &str,
    query: Option<&str>,
    body: &[u8],
    client: &ControlHttpClient,
  ) -> anyhow::Result<CtHttpResponse> {
    if body.len() > self.config.gateway.max_request_bytes {
      bail!("CT gateway request exceeds its configured byte limit");
    }
    if let Some(artifact) = retired_artifact_path(self.config.protocol, path)? {
      return self
        .gateway_static_artifact(method, query, body, artifact, client)
        .await;
    }
    self.validate_gateway_query_bounds(path, query)?;
    let response = self
      .gateway_request(method, path, query, body, client)
      .await?;
    if !response.status.is_success() {
      bail!("CT gateway origin returned {}", response.status);
    }
    match self.config.protocol {
      CertificateTransparencyProtocol::StaticRfc6962V1 => {
        if path.ends_with("/ct/v1/get-sth") {
          self.verify_gateway_sth_v1(&response.body, client).await?;
        } else if path.ends_with("/ct/v1/add-chain") {
          self.verify_gateway_sct_v1(body, &response.body, CtSubmissionKind::Certificate)?;
        } else if path.ends_with("/ct/v1/add-pre-chain") {
          self.verify_gateway_sct_v1(body, &response.body, CtSubmissionKind::Precertificate)?;
        } else if path.ends_with("/ct/v1/get-proof-by-hash") {
          self
            .verify_gateway_inclusion_v1(query, &response.body, client)
            .await?;
        } else if path.ends_with("/ct/v1/get-sth-consistency") {
          self
            .verify_gateway_consistency_v1(query, &response.body)
            .await?;
        } else if path.ends_with("/ct/v1/get-roots") {
          self.verify_gateway_roots_v1(&response.body)?;
        } else {
          bail!("CT gateway cannot prove this RFC 6962 response from bounded local evidence");
        }
      }
      CertificateTransparencyProtocol::Rfc9162V2 => {
        if path.ends_with("/ct/v2/get-sth") {
          self.verify_gateway_sth_v2(&response.body)?;
        } else if path.ends_with("/ct/v2/submit-entry") {
          self.verify_gateway_sct_v2(body, &response.body)?;
        } else {
          bail!("CT gateway cannot verify this RFC 9162 response type");
        }
      }
    }
    Ok(CtHttpResponse {
      status: response.status,
      content_type: if self.config.protocol == CertificateTransparencyProtocol::Rfc9162V2
        && path.ends_with("/ct/v2/get-sth")
      {
        "application/transitem+tls"
      } else {
        "application/json"
      },
      body: response.body,
      immutable: false,
    })
  }

  async fn gateway_static_artifact(
    &self,
    method: &Method,
    query: Option<&str>,
    body: &[u8],
    artifact: RetiredArtifact,
    client: &ControlHttpClient,
  ) -> anyhow::Result<CtHttpResponse> {
    if method != Method::GET || query.is_some() || !body.is_empty() {
      bail!("CT gateway Static CT artifacts accept GET without query or body");
    }
    let source = self
      .config
      .gateway
      .static_origin_url
      .as_deref()
      .ok_or_else(|| anyhow!("CT gateway Static CT origin is missing"))?;
    let url = retired_artifact_url(source, artifact.relative_path())?;
    let maximum = match &artifact {
      RetiredArtifact::Checkpoint => MAX_RETIRED_CHECKPOINT_BYTES,
      RetiredArtifact::Tile { path, .. } => match path.kind {
        TileKind::Hashes { .. } => path
          .partial_width
          .map_or(crate::ct::static_ct::TILE_WIDTH, usize::from)
          .saturating_mul(merkle::HASH_BYTES),
        TileKind::Data => self.config.gateway.max_response_bytes,
      },
      RetiredArtifact::Issuer { .. } => MAX_RETIRED_ISSUER_BYTES,
    };
    let request = http::Request::builder()
      .method(Method::GET)
      .uri(uri_from_url(&url)?)
      .header(http::header::ACCEPT, "text/plain, application/octet-stream")
      .body(empty_body())?;
    let response = client
      .request(request, Duration::from_secs(10), maximum)
      .await?;
    if response.status != StatusCode::OK {
      bail!("CT gateway Static CT origin returned {}", response.status);
    }
    self.validate_retired_artifact(&artifact, &response.body)?;
    let immutable = !matches!(&artifact, RetiredArtifact::Checkpoint);
    Ok(CtHttpResponse {
      status: StatusCode::OK,
      content_type: match &artifact {
        RetiredArtifact::Checkpoint => "text/plain; charset=utf-8",
        RetiredArtifact::Tile { .. } | RetiredArtifact::Issuer { .. } => "application/octet-stream",
      },
      body: response.body,
      immutable,
    })
  }

  async fn gateway_request(
    &self,
    method: &Method,
    path: &str,
    query: Option<&str>,
    body: &[u8],
    client: &ControlHttpClient,
  ) -> anyhow::Result<crate::control_http::ControlHttpResponse> {
    let origin = self
      .config
      .gateway
      .origin_url
      .as_deref()
      .ok_or_else(|| anyhow!("CT gateway origin is missing"))?;
    let mut url = url::Url::parse(origin)?;
    let mut joined = url.path().trim_end_matches('/').to_string();
    joined.push('/');
    joined.push_str(path.trim_start_matches('/'));
    url.set_path(&joined);
    url.set_query(query);
    let request = http::Request::builder()
      .method(method.clone())
      .uri(uri_from_url(&url)?)
      .header(
        http::header::ACCEPT,
        "application/json, application/transitem+tls",
      )
      .header(http::header::CONTENT_TYPE, "application/json")
      .body(if body.is_empty() {
        empty_body()
      } else {
        full_body(Bytes::copy_from_slice(body))
      })?;
    let maximum = if path.ends_with("/get-proof-by-hash")
      || path.ends_with("/get-sth-consistency")
      || path.ends_with("/get-inclusion-proof")
      || path.ends_with("/get-consistency-proof")
    {
      self.config.gateway.max_proof_bytes
    } else {
      self.config.gateway.max_response_bytes
    };
    client
      .request(request, Duration::from_secs(10), maximum)
      .await
  }

  fn validate_gateway_query_bounds(&self, path: &str, query: Option<&str>) -> anyhow::Result<()> {
    if path.ends_with("/get-entries") {
      let query = parse_query(query)?;
      let start = required_u64(&query, "start")?;
      let end = required_u64(&query, "end")?;
      if end < start
        || end.saturating_sub(start).saturating_add(1)
          > u64::try_from(self.config.gateway.max_entries).unwrap_or(u64::MAX)
      {
        bail!("CT gateway entry range exceeds its configured limit");
      }
    }
    Ok(())
  }

  async fn verify_gateway_sth_v1(
    &self,
    body: &[u8],
    client: &ControlHttpClient,
  ) -> anyhow::Result<GatewayWitness> {
    let sth: GetSthResponseV1 = serde_json::from_slice(body)?;
    let (root_hash, signature) = sth
      .decode_root_and_signature()
      .map_err(|error| anyhow!("gateway STH is malformed: {error}"))?;
    let transcript = encode_sth_signed_input(sth.timestamp, sth.tree_size, &root_hash);
    self.verify_log_signature(&transcript, &signature.signature)?;
    let next = GatewayWitness {
      tree_size: sth.tree_size,
      timestamp: sth.timestamp,
      root_hash,
    };
    let mut witness = self.gateway_witness.lock().await;
    if let Some(prior) = *witness {
      if next.timestamp < prior.timestamp || next.tree_size < prior.tree_size {
        bail!("CT gateway observed an STH rollback");
      }
      if next.tree_size == prior.tree_size && next.root_hash != prior.root_hash {
        bail!("CT gateway observed an STH fork");
      }
      if next.tree_size > prior.tree_size {
        let consistency_path = "/ct/v1/get-sth-consistency".to_string();
        let query = format!("first={}&second={}", prior.tree_size, next.tree_size);
        let response = self
          .gateway_request(&Method::GET, &consistency_path, Some(&query), &[], client)
          .await?;
        self.verify_consistency_values(prior, next, &response.body)?;
      }
    }
    *witness = Some(next);
    Ok(next)
  }

  fn verify_gateway_sct_v1(
    &self,
    request_body: &[u8],
    response_body: &[u8],
    kind: CtSubmissionKind,
  ) -> anyhow::Result<()> {
    let request: AddChainRequestV1 = serde_json::from_slice(request_body)?;
    let chain = decode_chain(&request.chain)?;
    self.validate_submission(&chain, kind)?;
    let response: AddChainResponseV1 = serde_json::from_slice(response_body)?;
    let sct = response
      .into_sct()
      .map_err(|error| anyhow!("gateway SCT is malformed: {error}"))?;
    if sct.log_id != self.v1_log_id {
      bail!("CT gateway SCT has the wrong LogID");
    }
    let signed_entry = match kind {
      CtSubmissionKind::Certificate => SignedEntryV1::X509(chain[0].clone()),
      CtSubmissionKind::Precertificate => SignedEntryV1::Precertificate {
        issuer_key_hash: issuer_spki_hash(
          chain
            .get(1)
            .ok_or_else(|| anyhow!("precertificate issuer is missing"))?,
        )?,
        tbs_certificate: Certificate::from_der(&chain[0])?
          .tbs_certificate()
          .to_der()?,
      },
    };
    let transcript = encode_sct_signed_input(&TimestampedEntryV1 {
      timestamp: sct.timestamp,
      signed_entry,
      extensions: sct.extensions,
    })
    .map_err(|error| anyhow!("failed to encode gateway SCT input: {error}"))?;
    self.verify_log_signature(&transcript, &sct.signature.signature)
  }

  async fn verify_gateway_inclusion_v1(
    &self,
    query: Option<&str>,
    body: &[u8],
    client: &ControlHttpClient,
  ) -> anyhow::Result<()> {
    let query = parse_query(query)?;
    let tree_size = required_u64(&query, "tree_size")?;
    let leaf_hash = decode_hash_query(required(&query, "hash")?)?;
    let proof: GetProofByHashResponseV1 = serde_json::from_slice(body)?;
    let sth_response = self
      .gateway_request(&Method::GET, "/ct/v1/get-sth", None, &[], client)
      .await?;
    let sth = self
      .verify_gateway_sth_v1(&sth_response.body, client)
      .await?;
    if sth.tree_size != tree_size {
      bail!("CT gateway inclusion proof does not target the verified current STH");
    }
    let path = proof
      .audit_path
      .iter()
      .map(|value| decode_hash_query(value))
      .collect::<anyhow::Result<Vec<_>>>()?;
    if !merkle::verify_inclusion(
      &leaf_hash,
      usize::try_from(proof.leaf_index)?,
      usize::try_from(tree_size)?,
      &path,
      &sth.root_hash,
    ) {
      bail!("CT gateway inclusion proof is invalid");
    }
    Ok(())
  }

  async fn verify_gateway_consistency_v1(
    &self,
    query: Option<&str>,
    body: &[u8],
  ) -> anyhow::Result<()> {
    let query = parse_query(query)?;
    let first = required_u64(&query, "first")?;
    let second = required_u64(&query, "second")?;
    let witness = (*self.gateway_witness.lock().await)
      .ok_or_else(|| anyhow!("CT gateway has no witnessed STH for consistency verification"))?;
    if first != second || witness.tree_size != first {
      bail!("CT gateway requires both witnessed roots to relay a consistency proof");
    }
    let response: GetSthConsistencyResponseV1 = serde_json::from_slice(body)?;
    if first == second && !response.consistency.is_empty() {
      bail!("CT gateway equal-size consistency proof must be empty");
    }
    Ok(())
  }

  fn verify_consistency_values(
    &self,
    prior: GatewayWitness,
    next: GatewayWitness,
    body: &[u8],
  ) -> anyhow::Result<()> {
    let response: GetSthConsistencyResponseV1 = serde_json::from_slice(body)?;
    let proof = response
      .consistency
      .iter()
      .map(|value| decode_hash_query(value))
      .collect::<anyhow::Result<Vec<_>>>()?;
    if !merkle::verify_consistency(
      usize::try_from(prior.tree_size)?,
      usize::try_from(next.tree_size)?,
      &prior.root_hash,
      &next.root_hash,
      &proof,
    ) {
      bail!("CT gateway consistency proof is invalid");
    }
    Ok(())
  }

  fn verify_gateway_roots_v1(&self, body: &[u8]) -> anyhow::Result<()> {
    #[derive(Deserialize)]
    struct Roots {
      certificates: Vec<String>,
    }
    let roots: Roots = serde_json::from_slice(body)?;
    let decoded = decode_chain(&roots.certificates)?;
    let expected = self
      .roots
      .iter()
      .map(|root| root.sha256)
      .collect::<Vec<_>>();
    let actual = decoded
      .iter()
      .map(|root| Sha256::digest(root).into())
      .collect::<Vec<Hash>>();
    if actual != expected {
      bail!("CT gateway origin roots differ from the signed root snapshot");
    }
    Ok(())
  }

  fn verify_gateway_sth_v2(&self, body: &[u8]) -> anyhow::Result<()> {
    let item = TransItemV2::decode(body)
      .map_err(|error| anyhow!("gateway RFC 9162 STH is malformed: {error}"))?;
    let TransItemV2::SignedTreeHead(sth) = item else {
      bail!("gateway RFC 9162 response is not an STH TransItem");
    };
    if Some(&sth.log_id) != self.v2_log_id.as_ref() {
      bail!("gateway RFC 9162 STH has the wrong LogID");
    }
    let transcript = sth
      .tree_head
      .encode_signed_input()
      .map_err(|error| anyhow!("failed to encode gateway RFC 9162 STH: {error}"))?;
    self.verify_log_signature(&transcript, &sth.signature)
  }

  fn verify_gateway_sct_v2(&self, request_body: &[u8], response_body: &[u8]) -> anyhow::Result<()> {
    let request: SubmitEntryRequestV2 = serde_json::from_slice(request_body)?;
    let response: SubmitEntryResponseV2 = serde_json::from_slice(response_body)?;
    let (submission, mut issuers) = request
      .decode_der()
      .map_err(|error| anyhow!("gateway RFC 9162 request is malformed: {error}"))?;
    let mut chain = vec![submission];
    chain.append(&mut issuers);
    let sct_bytes = base64::engine::general_purpose::STANDARD.decode(response.sct)?;
    let sct_item = TransItemV2::decode(&sct_bytes)
      .map_err(|error| anyhow!("gateway RFC 9162 SCT is malformed: {error}"))?;
    let sct = match &sct_item {
      TransItemV2::X509Sct(sct) | TransItemV2::PrecertificateSct(sct) => sct,
      _ => bail!("gateway RFC 9162 receipt lacks an SCT"),
    };
    if Some(&sct.log_id) != self.v2_log_id.as_ref() {
      bail!("gateway RFC 9162 SCT has the wrong LogID");
    }
    let kind = if request.submission_type == crate::ct::rfc9162::SUBMISSION_TYPE_X509 {
      CtSubmissionKind::Certificate
    } else {
      CtSubmissionKind::Precertificate
    };
    self.validate_submission(&chain, kind)?;
    let certificate = Certificate::from_der(&chain[0])?;
    let value = TimestampedCertificateEntryV2 {
      timestamp: sct.timestamp,
      issuer_key_hash: issuer_spki_hash(
        chain
          .get(1)
          .ok_or_else(|| anyhow!("gateway RFC 9162 issuer is missing"))?,
      )?
      .to_vec(),
      tbs_certificate: certificate.tbs_certificate().to_der()?,
      extensions: sct.extensions.clone(),
    };
    let entry = match kind {
      CtSubmissionKind::Certificate => TransItemV2::X509Entry(value),
      CtSubmissionKind::Precertificate => TransItemV2::PrecertificateEntry(value),
    };
    let transcript = TransItemV2::sct_signed_input(&entry)
      .map_err(|error| anyhow!("failed to encode gateway RFC 9162 SCT input: {error}"))?;
    self.verify_log_signature(&transcript, &sct.signature)
  }

  fn verify_log_signature(&self, transcript: &[u8], signature: &[u8]) -> anyhow::Result<()> {
    crate::remote_signer::verify_ct_log_signature(
      self.signer_profile(),
      &self.public_key_spki,
      transcript,
      signature,
    )
    .map_err(|_| anyhow!("CT signature verification failed"))
  }

  fn signer_profile(&self) -> CtLogProfile {
    match (self.config.protocol, self.config.identity.algorithm) {
      (CertificateTransparencyProtocol::StaticRfc6962V1, _) => CtLogProfile::Rfc6962P256Sha256,
      (
        CertificateTransparencyProtocol::Rfc9162V2,
        CertificateTransparencyIdentityAlgorithm::P256,
      ) => CtLogProfile::Rfc9162P256Sha256,
      (
        CertificateTransparencyProtocol::Rfc9162V2,
        CertificateTransparencyIdentityAlgorithm::Ed25519,
      ) => CtLogProfile::Rfc9162Ed25519,
    }
  }

  fn verify_durable_v1_receipt(
    &self,
    sct: &SignedCertificateTimestampV1,
    entry: &TimestampedEntryV1,
  ) -> anyhow::Result<()> {
    if sct.log_id != self.v1_log_id
      || sct.timestamp != entry.timestamp
      || sct.extensions != entry.extensions
      || sct.signature.hash_algorithm != crate::ct::rfc6962::HASH_ALGORITHM_SHA256
      || sct.signature.signature_algorithm != crate::ct::rfc6962::SIGNATURE_ALGORITHM_ECDSA
    {
      bail!("durable SCT does not match its reserved CT entry");
    }
    let transcript = encode_sct_signed_input(entry)
      .map_err(|error| anyhow!("failed to encode durable SCT transcript: {error}"))?;
    self
      .verify_log_signature(&transcript, &sct.signature.signature)
      .context("durable SCT signature verification failed")
  }

  fn verify_durable_v2_receipt(
    &self,
    item: &TransItemV2,
    entry: &TransItemV2,
    log_id: &LogIdV2,
    leaf_index: u64,
    timestamp: u64,
    kind: CtSubmissionKind,
  ) -> anyhow::Result<()> {
    let sct = match (kind, item) {
      (CtSubmissionKind::Certificate, TransItemV2::X509Sct(sct))
      | (CtSubmissionKind::Precertificate, TransItemV2::PrecertificateSct(sct)) => sct,
      _ => bail!("durable RFC 9162 receipt has the wrong SCT type"),
    };
    let expected_extensions = vec![ExtensionV2 {
      extension_type: V2_LEAF_INDEX_EXTENSION,
      data: leaf_index.to_be_bytes().to_vec(),
    }];
    if &sct.log_id != log_id || sct.timestamp != timestamp || sct.extensions != expected_extensions
    {
      bail!("durable RFC 9162 SCT does not match its reserved CT entry");
    }
    let transcript = TransItemV2::sct_signed_input(entry)
      .map_err(|error| anyhow!("failed to encode durable RFC 9162 SCT transcript: {error}"))?;
    self
      .verify_log_signature(&transcript, &sct.signature)
      .context("durable RFC 9162 SCT signature verification failed")
  }

  fn verify_stored_entry(&self, entry: &CtStoredEntry) -> anyhow::Result<()> {
    match self.config.protocol {
      CertificateTransparencyProtocol::StaticRfc6962V1 => {
        let leaf = MerkleTreeLeafV1::decode(&entry.leaf_input)
          .map_err(|error| anyhow!("durable RFC 6962 leaf is invalid: {error}"))?;
        if leaf.0.timestamp != entry.timestamp_millis
          || parse_leaf_index_extension(&leaf.0.extensions)
            .map_err(|error| anyhow!("durable SCT leaf index extension is invalid: {error}"))?
            != entry.leaf_index
          || merkle::leaf_hash(&entry.leaf_input) != entry.leaf_hash
        {
          bail!("durable RFC 6962 entry does not match its stored identity");
        }
        let sct = SignedCertificateTimestampV1::decode(&entry.receipt)
          .map_err(|error| anyhow!("durable SCT is invalid: {error}"))?;
        self.verify_durable_v1_receipt(&sct, &leaf.0)
      }
      CertificateTransparencyProtocol::Rfc9162V2 => {
        let leaf = TransItemV2::decode(&entry.leaf_input)
          .map_err(|error| anyhow!("durable RFC 9162 leaf is invalid: {error}"))?;
        let (kind, timestamp, extensions) = match &leaf {
          TransItemV2::X509Entry(value) => (
            CtSubmissionKind::Certificate,
            value.timestamp,
            &value.extensions,
          ),
          TransItemV2::PrecertificateEntry(value) => (
            CtSubmissionKind::Precertificate,
            value.timestamp,
            &value.extensions,
          ),
          _ => bail!("durable RFC 9162 leaf is not a submission entry"),
        };
        let expected_extensions = vec![ExtensionV2 {
          extension_type: V2_LEAF_INDEX_EXTENSION,
          data: entry.leaf_index.to_be_bytes().to_vec(),
        }];
        if timestamp != entry.timestamp_millis
          || extensions != &expected_extensions
          || crate::ct::rfc9162::merkle_leaf_hash(&leaf)
            .map_err(|error| anyhow!("failed to hash durable RFC 9162 leaf: {error}"))?
            != entry.leaf_hash
        {
          bail!("durable RFC 9162 entry does not match its stored identity");
        }
        let receipt = TransItemV2::decode(&entry.receipt)
          .map_err(|error| anyhow!("durable RFC 9162 SCT is invalid: {error}"))?;
        let log_id = self
          .v2_log_id
          .as_ref()
          .ok_or_else(|| anyhow!("RFC 9162 LogID is missing"))?;
        self.verify_durable_v2_receipt(
          &receipt,
          &leaf,
          log_id,
          entry.leaf_index,
          entry.timestamp_millis,
          kind,
        )
      }
    }
  }

  async fn submit_v1(&self, body: &[u8], kind: CtSubmissionKind) -> anyhow::Result<CtHttpResponse> {
    let request: AddChainRequestV1 =
      serde_json::from_slice(body).context("invalid add-chain JSON")?;
    let chain = decode_chain(&request.chain)?;
    self.validate_submission(&chain, kind)?;
    let entry_key = submission_key(kind, &chain);
    let reservation_chain = chain.clone();
    let (reserved, reservation_guard) = self
      .reserve_entry_cancellation_safe(entry_key, move |index, timestamp| {
        build_v1_entry(&reservation_chain, kind, index, timestamp)
      })
      .await?;
    if let Some(receipt) = reserved.receipt {
      let sct = SignedCertificateTimestampV1::decode(&receipt)
        .map_err(|error| anyhow!("durable SCT is invalid: {error}"))?;
      let (entry, _, _) =
        v1_entry_parts(&chain, kind, reserved.leaf_index, reserved.timestamp_millis)?;
      self.verify_durable_v1_receipt(&sct, &entry)?;
      self
        .record_receipt_and_publish(reserved.leaf_index, &receipt)
        .await?;
      return json(StatusCode::OK, &AddChainResponseV1::from_sct(&sct)?, false);
    }
    // A signer timeout can occur after the index and timestamp are committed. Rebuild and sign
    // the exact same transcript so an identical retry repairs the durable unsigned reservation.
    let (timestamped_entry, _, _) =
      v1_entry_parts(&chain, kind, reserved.leaf_index, reserved.timestamp_millis)?;
    let transcript = encode_sct_signed_input(&timestamped_entry)
      .map_err(|error| anyhow!("failed to encode SCT transcript: {error}"))?;
    let signature = self
      .signer()?
      .sign_transcript(CtTranscriptClass::V1Sct, &transcript)
      .await?;
    let sct = SignedCertificateTimestampV1 {
      log_id: self.v1_log_id,
      timestamp: reserved.timestamp_millis,
      extensions: timestamped_entry.extensions.clone(),
      signature: DigitallySigned {
        hash_algorithm: crate::ct::rfc6962::HASH_ALGORITHM_SHA256,
        signature_algorithm: crate::ct::rfc6962::SIGNATURE_ALGORITHM_ECDSA,
        signature,
      },
    };
    let receipt = sct
      .encode()
      .map_err(|error| anyhow!("failed to encode SCT: {error}"))?;
    self
      .record_receipt_and_publish(reserved.leaf_index, &receipt)
      .await?;
    reservation_guard.commit();
    self.metrics.record_ct_submission_accepted();
    json(StatusCode::OK, &AddChainResponseV1::from_sct(&sct)?, false)
  }

  async fn get_sth_v1(&self) -> anyhow::Result<CtHttpResponse> {
    let state = self.public_tree_state().await?;
    let timestamp = self.reserve_sth_timestamp().await?;
    let transcript = encode_sth_signed_input(timestamp, state.tree_size, &state.root_hash);
    let signature = self
      .signer()?
      .sign_transcript(CtTranscriptClass::V1Sth, &transcript)
      .await?;
    let digitally_signed = DigitallySigned {
      hash_algorithm: crate::ct::rfc6962::HASH_ALGORITHM_SHA256,
      signature_algorithm: crate::ct::rfc6962::SIGNATURE_ALGORITHM_ECDSA,
      signature,
    };
    let response = GetSthResponseV1 {
      tree_size: state.tree_size,
      timestamp,
      sha256_root_hash: base64::engine::general_purpose::STANDARD.encode(state.root_hash),
      tree_head_signature: base64::engine::general_purpose::STANDARD.encode(
        digitally_signed
          .encode()
          .map_err(|error| anyhow!("failed to encode STH signature: {error}"))?,
      ),
    };
    json(StatusCode::OK, &response, false)
  }

  async fn get_entries_v1(&self, query: Option<&str>) -> anyhow::Result<CtHttpResponse> {
    let query = parse_query(query)?;
    let start = required_u64(&query, "start")?;
    let end = required_u64(&query, "end")?;
    let entries = self.public_entries(start, end).await?;
    let response = GetEntriesResponseV1 {
      entries: entries
        .into_iter()
        .map(|entry| GetEntriesEntryV1 {
          leaf_input: base64::engine::general_purpose::STANDARD.encode(entry.leaf_input),
          extra_data: base64::engine::general_purpose::STANDARD.encode(entry.extra_data),
        })
        .collect(),
    };
    json(StatusCode::OK, &response, false)
  }

  async fn get_proof_v1(&self, query: Option<&str>) -> anyhow::Result<CtHttpResponse> {
    let query = parse_query(query)?;
    let tree_size = required_u64(&query, "tree_size")?;
    self.ensure_public_tree_size(tree_size).await?;
    let leaf_hash = decode_hash_query(required(&query, "hash")?)?;
    let index = self
      .leaf_index_by_hash(&leaf_hash, tree_size)
      .await?
      .ok_or_else(|| anyhow!("leaf hash is absent from requested tree"))?;
    let proof = self.inclusion_path(tree_size, index).await?;
    json(
      StatusCode::OK,
      &GetProofByHashResponseV1 {
        leaf_index: index,
        audit_path: proof
          .iter()
          .map(|hash| base64::engine::general_purpose::STANDARD.encode(hash))
          .collect(),
      },
      false,
    )
  }

  async fn get_consistency_v1(&self, query: Option<&str>) -> anyhow::Result<CtHttpResponse> {
    let query = parse_query(query)?;
    let first = required_u64(&query, "first")?;
    let second = required_u64(&query, "second")?;
    self.ensure_public_tree_size(second).await?;
    let proof = self.consistency_path(first, second).await?;
    json(
      StatusCode::OK,
      &GetSthConsistencyResponseV1 {
        consistency: proof
          .iter()
          .map(|hash| base64::engine::general_purpose::STANDARD.encode(hash))
          .collect(),
      },
      false,
    )
  }

  async fn get_checkpoint(&self) -> anyhow::Result<CtHttpResponse> {
    let state = self.public_tree_state().await?;
    self.checkpoint_for_state(&state).await
  }

  async fn checkpoint_for_state(&self, state: &CtTreeState) -> anyhow::Result<CtHttpResponse> {
    let timestamp = self.reserve_sth_timestamp().await?;
    let transcript = encode_sth_signed_input(timestamp, state.tree_size, &state.root_hash);
    let signature = self
      .signer()?
      .sign_transcript(CtTranscriptClass::V1Sth, &transcript)
      .await?;
    let checkpoint = StaticCheckpoint {
      origin: self.config.name.clone(),
      tree_size: state.tree_size,
      root_hash: state.root_hash,
      timestamp,
      tree_head_signature: DigitallySigned {
        hash_algorithm: crate::ct::rfc6962::HASH_ALGORITHM_SHA256,
        signature_algorithm: crate::ct::rfc6962::SIGNATURE_ALGORITHM_ECDSA,
        signature,
      },
    }
    .render(&self.v1_log_id)
    .map_err(|error| anyhow!("failed to render Static CT checkpoint: {error}"))?;
    Ok(CtHttpResponse {
      status: StatusCode::OK,
      content_type: "text/plain; charset=utf-8",
      body: Bytes::from(checkpoint),
      immutable: false,
    })
  }

  async fn get_static_object(&self, path: &str) -> anyhow::Result<CtHttpResponse> {
    let relative = path
      .split_once("/tile/")
      .map(|(_, suffix)| format!("tile/{suffix}"))
      .or_else(|| {
        path
          .split_once("/issuer/")
          .map(|(_, suffix)| format!("issuer/{suffix}"))
      })
      .ok_or_else(|| anyhow!("invalid Static CT object path"))?;
    if let Some(tile) = relative.strip_prefix("tile/") {
      TilePath::parse(&format!("tile/{tile}"))
        .map_err(|error| anyhow!("invalid Static CT tile path: {error}"))?;
    } else if let Some(issuer) = relative.strip_prefix("issuer/")
      && (issuer.len() != 64
        || !issuer
          .bytes()
          .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    {
      bail!("invalid Static CT issuer path");
    }
    let bytes = self
      .object_publisher
      .as_ref()
      .ok_or_else(|| anyhow!("Static CT object publisher is unavailable"))?
      .read(&relative)
      .await?;
    Ok(CtHttpResponse {
      status: StatusCode::OK,
      content_type: "application/octet-stream",
      body: bytes,
      immutable: true,
    })
  }

  async fn handle_v2(
    &self,
    method: &Method,
    path: &str,
    _query: Option<&str>,
    body: &[u8],
  ) -> anyhow::Result<CtHttpResponse> {
    match (method, path) {
      (&Method::POST, path) if path.ends_with("/ct/v2/submit-entry") => self.submit_v2(body).await,
      (&Method::GET, path) if path.ends_with("/ct/v2/get-sth") => self.get_sth_v2().await,
      (&Method::GET, path) if path.ends_with("/ct/v2/get-final-sth") => {
        self.get_final_sth_v2().await
      }
      (&Method::GET, path) if path.ends_with("/ct/v2/get-entries") => {
        self.get_entries_v2(_query).await
      }
      (&Method::GET, path) if path.ends_with("/ct/v2/get-inclusion-proof") => {
        self.get_inclusion_v2(_query).await
      }
      (&Method::GET, path) if path.ends_with("/ct/v2/get-consistency-proof") => {
        self.get_consistency_v2(_query).await
      }
      _ => Ok(json_error(StatusCode::NOT_FOUND, "unknown CT v2 endpoint")),
    }
  }

  async fn submit_v2(&self, body: &[u8]) -> anyhow::Result<CtHttpResponse> {
    let request: SubmitEntryRequestV2 =
      serde_json::from_slice(body).context("invalid RFC 9162 submission JSON")?;
    let (submission, mut issuers) = request
      .decode_der()
      .map_err(|error| anyhow!("invalid RFC 9162 submission: {error}"))?;
    let kind = if request.submission_type == crate::ct::rfc9162::SUBMISSION_TYPE_X509 {
      CtSubmissionKind::Certificate
    } else {
      CtSubmissionKind::Precertificate
    };
    let mut chain = vec![submission];
    chain.append(&mut issuers);
    self.validate_submission(&chain, kind)?;
    let entry_key = submission_key(kind, &chain);
    let log_id = self
      .v2_log_id
      .clone()
      .ok_or_else(|| anyhow!("RFC 9162 LogID is missing"))?;
    let reservation_chain = chain.clone();
    let (reserved, reservation_guard) = self
      .reserve_entry_cancellation_safe(entry_key, move |index, timestamp| {
        build_v2_entry(&reservation_chain, kind, index, timestamp)
      })
      .await?;
    if let Some(receipt) = reserved.receipt {
      let item = TransItemV2::decode(&receipt)
        .map_err(|error| anyhow!("durable RFC 9162 SCT is invalid: {error}"))?;
      let (entry, _, _) =
        v2_entry_parts(&chain, kind, reserved.leaf_index, reserved.timestamp_millis)?;
      self.verify_durable_v2_receipt(
        &item,
        &entry,
        &log_id,
        reserved.leaf_index,
        reserved.timestamp_millis,
        kind,
      )?;
      self
        .record_receipt_and_publish(reserved.leaf_index, &receipt)
        .await?;
      return json(
        StatusCode::OK,
        &SubmitEntryResponseV2::from_items(&item, None, None)?,
        false,
      );
    }
    let (entry, _, _) =
      v2_entry_parts(&chain, kind, reserved.leaf_index, reserved.timestamp_millis)?;
    let transcript = TransItemV2::sct_signed_input(&entry)
      .map_err(|error| anyhow!("failed to encode RFC 9162 SCT input: {error}"))?;
    let signature = self
      .signer()?
      .sign_transcript(CtTranscriptClass::V2Sct, &transcript)
      .await?;
    let sct = SignedCertificateTimestampV2 {
      log_id,
      timestamp: reserved.timestamp_millis,
      extensions: vec![ExtensionV2 {
        extension_type: V2_LEAF_INDEX_EXTENSION,
        data: reserved.leaf_index.to_be_bytes().to_vec(),
      }],
      signature,
    };
    let sct_item = match kind {
      CtSubmissionKind::Certificate => TransItemV2::X509Sct(sct),
      CtSubmissionKind::Precertificate => TransItemV2::PrecertificateSct(sct),
    };
    let receipt = sct_item
      .encode()
      .map_err(|error| anyhow!("failed to encode RFC 9162 SCT: {error}"))?;
    self
      .record_receipt_and_publish(reserved.leaf_index, &receipt)
      .await?;
    reservation_guard.commit();
    self.metrics.record_ct_submission_accepted();
    json(
      StatusCode::OK,
      &SubmitEntryResponseV2::from_items(&sct_item, None, None)?,
      false,
    )
  }

  async fn get_sth_v2(&self) -> anyhow::Result<CtHttpResponse> {
    self.signed_sth_v2(CtTranscriptClass::V2Sth).await
  }

  async fn get_final_sth_v2(&self) -> anyhow::Result<CtHttpResponse> {
    self.signed_sth_v2(CtTranscriptClass::V2FinalSth).await
  }

  async fn signed_sth_v2(
    &self,
    transcript_class: CtTranscriptClass,
  ) -> anyhow::Result<CtHttpResponse> {
    let state = self.public_tree_state().await?;
    self.signed_sth_v2_for_state(transcript_class, &state).await
  }

  async fn signed_sth_v2_for_state(
    &self,
    transcript_class: CtTranscriptClass,
    state: &CtTreeState,
  ) -> anyhow::Result<CtHttpResponse> {
    let tree_head = TreeHeadV2 {
      timestamp: self.reserve_sth_timestamp().await?,
      tree_size: state.tree_size,
      root_hash: state.root_hash.to_vec(),
      extensions: Vec::new(),
    };
    let transcript = tree_head
      .encode_signed_input()
      .map_err(|error| anyhow!("failed to encode RFC 9162 STH input: {error}"))?;
    let signature = self
      .signer()?
      .sign_transcript(transcript_class, &transcript)
      .await?;
    let item = TransItemV2::SignedTreeHead(SignedTreeHeadV2 {
      log_id: self
        .v2_log_id
        .clone()
        .ok_or_else(|| anyhow!("RFC 9162 LogID is missing"))?,
      tree_head,
      signature,
    });
    Ok(CtHttpResponse {
      status: StatusCode::OK,
      content_type: "application/transitem+tls",
      body: Bytes::from(
        item
          .encode()
          .map_err(|error| anyhow!("failed to encode STH: {error}"))?,
      ),
      immutable: false,
    })
  }

  async fn get_entries_v2(&self, query: Option<&str>) -> anyhow::Result<CtHttpResponse> {
    let query = parse_query(query)?;
    let start = required_u64(&query, "start")?;
    let end = required_u64(&query, "end")?;
    let items = self
      .public_entries(start, end)
      .await?
      .into_iter()
      .map(|entry| {
        TransItemV2::decode(&entry.leaf_input)
          .map_err(|error| anyhow!("durable RFC 9162 entry is malformed: {error}"))
      })
      .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(CtHttpResponse {
      status: StatusCode::OK,
      content_type: "application/transitem-list+tls",
      body: Bytes::from(
        encode_trans_item_list(&items)
          .map_err(|error| anyhow!("failed to encode RFC 9162 entries: {error}"))?,
      ),
      immutable: false,
    })
  }

  async fn get_inclusion_v2(&self, query: Option<&str>) -> anyhow::Result<CtHttpResponse> {
    let query = parse_query(query)?;
    let tree_size = required_u64(&query, "tree_size")?;
    let leaf_index = required_u64(&query, "leaf_index")?;
    self.ensure_public_tree_size(tree_size).await?;
    let proof = self.inclusion_path(tree_size, leaf_index).await?;
    let item = TransItemV2::InclusionProof(InclusionProofV2 {
      log_id: self
        .v2_log_id
        .clone()
        .ok_or_else(|| anyhow!("RFC 9162 LogID is missing"))?,
      tree_size,
      leaf_index,
      path: proof.into_iter().map(|hash| hash.to_vec()).collect(),
    });
    Ok(CtHttpResponse {
      status: StatusCode::OK,
      content_type: "application/transitem+tls",
      body: Bytes::from(
        item
          .encode()
          .map_err(|error| anyhow!("failed to encode proof: {error}"))?,
      ),
      immutable: false,
    })
  }

  async fn get_consistency_v2(&self, query: Option<&str>) -> anyhow::Result<CtHttpResponse> {
    let query = parse_query(query)?;
    let first = required_u64(&query, "first")?;
    let second = required_u64(&query, "second")?;
    self.ensure_public_tree_size(second).await?;
    let proof = self.consistency_path(first, second).await?;
    let item = TransItemV2::ConsistencyProof(ConsistencyProofV2 {
      log_id: self
        .v2_log_id
        .clone()
        .ok_or_else(|| anyhow!("RFC 9162 LogID is missing"))?,
      tree_size_1: first,
      tree_size_2: second,
      path: proof.into_iter().map(|hash| hash.to_vec()).collect(),
    });
    Ok(CtHttpResponse {
      status: StatusCode::OK,
      content_type: "application/transitem+tls",
      body: Bytes::from(
        item
          .encode()
          .map_err(|error| anyhow!("failed to encode proof: {error}"))?,
      ),
      immutable: false,
    })
  }

  fn validate_submission(&self, chain: &[Vec<u8>], kind: CtSubmissionKind) -> anyhow::Result<()> {
    let maximum = match kind {
      CtSubmissionKind::Certificate => self.config.publication.max_chain_bytes,
      CtSubmissionKind::Precertificate => self.config.publication.max_pre_chain_bytes,
    };
    let chain_bytes = chain
      .iter()
      .try_fold(0_usize, |total, certificate| {
        total.checked_add(certificate.len())
      })
      .ok_or_else(|| anyhow!("CT submission chain length overflow"))?;
    if chain_bytes > maximum {
      bail!("CT submission chain exceeds its configured byte limit");
    }
    validate_chain(
      chain,
      &self.roots,
      kind,
      &CtChainPolicy {
        reject_expired: self.config.admission.reject_expired,
        require_server_auth_eku: self.config.admission.check_eku,
        reject_precertificate_signing_ca: true,
        shard_not_after_start_millis: self.config.shard.start_ms,
        shard_not_after_end_millis: self.config.shard.end_ms,
      },
    )?;
    Ok(())
  }

  async fn record_receipt_and_publish(
    &self,
    leaf_index: u64,
    receipt: &[u8],
  ) -> anyhow::Result<()> {
    let result = async {
      match self.store()? {
        CtStore::Local(store) => store.record_receipt(leaf_index, receipt).await?,
        CtStore::Postgres(store) => store.record_receipt(leaf_index, receipt).await?,
      }
      self.integrate_and_publish().await?;
      Ok(())
    }
    .await;
    if result.is_err() {
      self.metrics.record_ct_publish_failure();
      self.mark_publish_failure();
    }
    result
  }

  async fn integrate_and_publish(&self) -> anyhow::Result<()> {
    let _run = self.publisher_run.lock().await;
    match self.store()? {
      CtStore::Local(store) => {
        let state = store
          .integrate_ready(|entry| self.verify_stored_entry(entry))
          .await?;
        self.publish_immutable_objects(&state).await?;
        self.publish_checkpoint_for_state(&state).await?;
        store.record_published_tree_size(state.tree_size).await?;
      }
      CtStore::Postgres(store) => {
        let holder = publisher_holder();
        let Some(epoch) = store.try_acquire_publisher_lease(&holder, 60_000).await? else {
          return self.observe_standby_publication(store).await;
        };
        while let Some(entry) = store.next_unintegrated().await? {
          self.verify_stored_entry(&entry)?;
          store.integrate_next(&entry, &holder, epoch).await?;
        }
        let state = store.tree_state().await?;
        self.sync_checkpoint_version(&state).await;
        self.publish_immutable_objects(&state).await?;
        store.renew_publisher_lease(&holder, epoch, 60_000).await?;
        let published = self.publish_checkpoint_for_state(&state).await?;
        store
          .record_published_checkpoint(
            state.tree_size,
            state.root_hash,
            published.as_ref().and_then(|value| value.e_tag.as_deref()),
            published
              .as_ref()
              .and_then(|value| value.version.as_deref()),
            &holder,
            epoch,
          )
          .await?;
      }
    }
    self.mark_publish_success();
    Ok(())
  }

  async fn publish_immutable_objects(&self, state: &CtTreeState) -> anyhow::Result<()> {
    let Some(publisher) = &self.object_publisher else {
      return Ok(());
    };
    if self.config.protocol == CertificateTransparencyProtocol::StaticRfc6962V1
      && state.tree_size > state.published_tree_size
    {
      self.publish_static_tiles(publisher, state).await?;
    }
    Ok(())
  }

  async fn publish_checkpoint_for_state(
    &self,
    state: &CtTreeState,
  ) -> anyhow::Result<Option<UpdateVersion>> {
    let Some(publisher) = &self.object_publisher else {
      return Ok(None);
    };
    let checkpoint = match self.config.protocol {
      CertificateTransparencyProtocol::StaticRfc6962V1 => {
        self.checkpoint_for_state(state).await?.body
      }
      CertificateTransparencyProtocol::Rfc9162V2 => {
        self
          .signed_sth_v2_for_state(CtTranscriptClass::V2Sth, state)
          .await?
          .body
      }
    };
    let mut version = self.checkpoint_version.lock().await;
    let next = match publisher
      .publish_checkpoint(checkpoint.clone(), version.clone())
      .await
    {
      Ok(next) => next,
      Err(first_error) if self.config.role == CertificateTransparencyLogRole::Operator => {
        let (existing, current_version) = publisher
          .checkpoint_snapshot()
          .await
          .with_context(|| format!("failed to reconcile CT checkpoint after: {first_error:#}"))?;
        self
          .validate_checkpoint_predecessor(&existing, state)
          .await
          .with_context(|| {
            format!("refused CT checkpoint reconciliation after: {first_error:#}")
          })?;
        publisher
          .publish_checkpoint(checkpoint, Some(current_version))
          .await
          .context("failed to advance a verified predecessor CT checkpoint")?
      }
      Err(error) => return Err(error),
    };
    *version = Some(next);
    Ok(version.clone())
  }

  async fn validate_checkpoint_predecessor(
    &self,
    bytes: &[u8],
    state: &CtTreeState,
  ) -> anyhow::Result<()> {
    let (tree_size, root_hash) = match self.config.protocol {
      CertificateTransparencyProtocol::StaticRfc6962V1 => {
        let text = std::str::from_utf8(bytes).context("existing CT checkpoint is not UTF-8")?;
        let checkpoint = StaticCheckpoint::parse(text, &self.v1_log_id)
          .map_err(|error| anyhow!("existing Static CT checkpoint is malformed: {error}"))?;
        if checkpoint.origin != self.config.name
          || checkpoint.tree_head_signature.hash_algorithm
            != crate::ct::rfc6962::HASH_ALGORITHM_SHA256
          || checkpoint.tree_head_signature.signature_algorithm
            != crate::ct::rfc6962::SIGNATURE_ALGORITHM_ECDSA
        {
          bail!("existing Static CT checkpoint has the wrong immutable identity");
        }
        self.verify_log_signature(
          &checkpoint.signed_tree_head_input(),
          &checkpoint.tree_head_signature.signature,
        )?;
        (checkpoint.tree_size, checkpoint.root_hash)
      }
      CertificateTransparencyProtocol::Rfc9162V2 => {
        let item = TransItemV2::decode(bytes)
          .map_err(|error| anyhow!("existing RFC 9162 checkpoint is malformed: {error}"))?;
        let TransItemV2::SignedTreeHead(sth) = item else {
          bail!("existing RFC 9162 checkpoint is not a signed tree head");
        };
        if Some(&sth.log_id) != self.v2_log_id.as_ref() {
          bail!("existing RFC 9162 checkpoint has the wrong LogID");
        }
        let transcript = sth
          .tree_head
          .encode_signed_input()
          .map_err(|error| anyhow!("existing RFC 9162 tree head is malformed: {error}"))?;
        self.verify_log_signature(&transcript, &sth.signature)?;
        let root_hash: Hash = sth
          .tree_head
          .root_hash
          .try_into()
          .map_err(|_| anyhow!("existing RFC 9162 checkpoint root is not SHA-256"))?;
        (sth.tree_head.tree_size, root_hash)
      }
    };
    if tree_size < state.published_tree_size || tree_size > state.tree_size {
      bail!("existing CT checkpoint is outside the durable integrated prefix");
    }
    if self.tree_root_at(tree_size).await? != root_hash {
      bail!("existing CT checkpoint root differs from durable Merkle state");
    }
    Ok(())
  }

  async fn sync_checkpoint_version(&self, state: &CtTreeState) {
    let mut current = self.checkpoint_version.lock().await;
    *current = match (&state.checkpoint_etag, &state.checkpoint_version) {
      (None, None) => None,
      (etag, version) => Some(UpdateVersion {
        e_tag: etag.clone(),
        version: version.clone(),
      }),
    };
  }

  async fn observe_standby_publication(&self, store: &CtPostgresStore) -> anyhow::Result<()> {
    let state = store.tree_state().await?;
    if state.published_tree_size != state.tree_size
      || state.checkpoint_version.is_none()
      || state.checkpoint_published_millis.is_none()
    {
      bail!("CT standby has not observed a complete published checkpoint");
    }
    let published_at = state
      .checkpoint_published_millis
      .ok_or_else(|| anyhow!("CT checkpoint publication timestamp is missing"))?;
    if now_millis().saturating_sub(published_at) > self.config.mmd_seconds.saturating_mul(1000) {
      bail!("CT standby observed a checkpoint older than the maximum merge delay");
    }
    self.sync_checkpoint_version(&state).await;
    self
      .last_publish_millis
      .store(published_at, Ordering::Release);
    self
      .publish_failure_since_millis
      .store(0, Ordering::Release);
    Ok(())
  }

  async fn publish_static_tiles(
    &self,
    publisher: &CtObjectPublisher,
    state: &CtTreeState,
  ) -> anyhow::Result<()> {
    let tree_size = state.tree_size;
    if tree_size == 0 {
      return Ok(());
    }

    // Rebuild only the previously partial data tile and newly appended tiles.
    // Full earlier tiles are immutable and have already been published.
    let mut data_start = state.published_tree_size / 256 * 256;
    while data_start < tree_size {
      let data_end = data_start.saturating_add(255).min(tree_size - 1);
      let entries = self.entries(data_start, data_end).await?;
      let mut static_leaves = Vec::with_capacity(entries.len());
      for entry in &entries {
        let (leaf, issuers) = decode_static_leaf(entry)?;
        for issuer in &issuers {
          publisher
            .put_immutable(
              &format!("issuer/{}", issuer_fingerprint_hex(issuer)),
              Bytes::copy_from_slice(issuer),
            )
            .await?;
        }
        static_leaves.push(leaf);
      }
      let path = TilePath {
        kind: TileKind::Data,
        index: data_start / 256,
        partial_width: (static_leaves.len() < 256)
          .then(|| u8::try_from(static_leaves.len()).context("Static CT partial width overflow"))
          .transpose()?,
      }
      .render()
      .map_err(|error| anyhow!("failed to render Static CT data tile path: {error}"))?;
      publisher
        .put_immutable(
          &path,
          Bytes::from(
            encode_data_tile(&static_leaves)
              .map_err(|error| anyhow!("failed to encode Static CT data tile: {error}"))?,
          ),
        )
        .await?;
      data_start = data_end.saturating_add(1);
    }

    let mut level_factor = 1_u64;
    for level in 0_u8..=crate::ct::static_ct::MAX_TILE_LEVEL {
      let hash_count = tree_size / level_factor;
      if hash_count == 0 {
        break;
      }
      let prior_hash_count = state.published_tree_size / level_factor;
      let mut hash_start = prior_hash_count / 256 * 256;
      while hash_start < hash_count {
        let hash_end = hash_start.saturating_add(255).min(hash_count - 1);
        let hashes = self
          .static_level_hashes(level, hash_start, hash_end, tree_size)
          .await?;
        let path = TilePath {
          kind: TileKind::Hashes { level },
          index: hash_start / 256,
          partial_width: (hashes.len() < 256)
            .then(|| u8::try_from(hashes.len()).context("Static CT partial width overflow"))
            .transpose()?,
        }
        .render()
        .map_err(|error| anyhow!("failed to render Static CT hash tile path: {error}"))?;
        publisher
          .put_immutable(
            &path,
            Bytes::from(
              encode_hash_tile(&hashes)
                .map_err(|error| anyhow!("failed to encode Static CT hash tile: {error}"))?,
            ),
          )
          .await?;
        hash_start = hash_end.saturating_add(1);
      }
      if hash_count < 256 {
        break;
      }
      if level == crate::ct::static_ct::MAX_TILE_LEVEL {
        bail!("Static CT tree exceeds the supported tile level bound");
      }
      level_factor = level_factor
        .checked_mul(256)
        .ok_or_else(|| anyhow!("Static CT tile level factor overflow"))?;
    }
    Ok(())
  }

  async fn static_level_hashes(
    &self,
    level: u8,
    start: u64,
    end: u64,
    tree_size: u64,
  ) -> anyhow::Result<Vec<Hash>> {
    match self.store()? {
      CtStore::Postgres(store) => store.node_hashes(level.saturating_mul(8), start, end).await,
      CtStore::Local(store) => {
        // The local backend is development-only and bounded by its configured
        // capacity; keep its simple in-memory derivation while production uses
        // durable node ranges.
        let mut hashes = store.leaf_hashes(tree_size).await?;
        for _ in 0..level {
          hashes = complete_static_tile_roots(&hashes);
        }
        let start = usize::try_from(start).context("Static CT node start overflow")?;
        let end = usize::try_from(end).context("Static CT node end overflow")?;
        hashes
          .get(start..=end)
          .map(<[Hash]>::to_vec)
          .ok_or_else(|| anyhow!("local Static CT node range is incomplete"))
      }
    }
  }

  async fn tree_state(&self) -> anyhow::Result<CtTreeState> {
    let state = match self.store()? {
      CtStore::Local(store) => store.tree_state().await?,
      CtStore::Postgres(store) => store.tree_state().await?,
    };
    self.metrics.set_ct_tree_state(
      state.tree_size,
      state.published_tree_size,
      state.tree_size.saturating_sub(state.published_tree_size),
      now_millis().saturating_sub(self.last_publish_millis.load(Ordering::Acquire)),
      state.frozen_reason.is_some(),
    );
    Ok(state)
  }

  async fn public_tree_state(&self) -> anyhow::Result<CtTreeState> {
    let mut state = self.tree_state().await?;
    if state.published_tree_size > state.tree_size {
      bail!("CT published tree size exceeds the integrated tree");
    }
    if state.published_tree_size != state.tree_size {
      state.root_hash = self.tree_root_at(state.published_tree_size).await?;
      state.tree_size = state.published_tree_size;
    }
    Ok(state)
  }

  async fn ensure_public_tree_size(&self, requested: u64) -> anyhow::Result<()> {
    let published = self.tree_state().await?.published_tree_size;
    if requested > published {
      bail!("requested CT tree size is not published");
    }
    Ok(())
  }

  async fn public_entries(&self, start: u64, end: u64) -> anyhow::Result<Vec<CtStoredEntry>> {
    if end < start {
      bail!("CT entry range is reversed");
    }
    let published = self.tree_state().await?.published_tree_size;
    if start >= published {
      return Ok(Vec::new());
    }
    self.entries(start, end.min(published - 1)).await
  }

  async fn entries(&self, start: u64, end: u64) -> anyhow::Result<Vec<CtStoredEntry>> {
    match self.store()? {
      CtStore::Local(store) => store.entries(start, end).await,
      CtStore::Postgres(store) => store.entries(start, end).await,
    }
  }

  async fn tree_root_at(&self, tree_size: u64) -> anyhow::Result<Hash> {
    if tree_size == 0 {
      return Ok(merkle::empty_hash());
    }
    match self.store()? {
      CtStore::Local(store) => Ok(merkle::root_from_leaf_hashes(
        &store.leaf_hashes(tree_size).await?,
      )),
      CtStore::Postgres(store) => postgres_range_root(store, 0, tree_size).await,
    }
  }

  async fn leaf_index_by_hash(
    &self,
    leaf_hash: &Hash,
    tree_size: u64,
  ) -> anyhow::Result<Option<u64>> {
    match self.store()? {
      CtStore::Local(store) => Ok(
        store
          .leaf_hashes(tree_size)
          .await?
          .iter()
          .position(|hash| hash == leaf_hash)
          .map(|index| u64::try_from(index).unwrap_or(u64::MAX)),
      ),
      CtStore::Postgres(store) => store.leaf_index_by_hash(leaf_hash, tree_size).await,
    }
  }

  async fn inclusion_path(&self, tree_size: u64, leaf_index: u64) -> anyhow::Result<Vec<Hash>> {
    if tree_size == 0 || leaf_index >= tree_size {
      bail!("CT inclusion proof leaf index is outside the tree");
    }
    match self.store()? {
      CtStore::Local(store) => {
        let hashes = store.leaf_hashes(tree_size).await?;
        merkle::inclusion_proof(&hashes, usize::try_from(leaf_index)?)
          .map_err(|error| anyhow!("failed to build inclusion proof: {error}"))
      }
      CtStore::Postgres(store) => {
        let mut ranges = Vec::new();
        collect_inclusion_ranges(0, tree_size, leaf_index, &mut ranges);
        resolve_postgres_ranges(store, &ranges).await
      }
    }
  }

  async fn consistency_path(&self, first: u64, second: u64) -> anyhow::Result<Vec<Hash>> {
    if first > second {
      bail!("CT consistency proof old tree is larger than new tree");
    }
    if first == 0 || first == second {
      return Ok(Vec::new());
    }
    match self.store()? {
      CtStore::Local(store) => {
        let hashes = store.leaf_hashes(second).await?;
        merkle::consistency_proof(&hashes, usize::try_from(first)?)
          .map_err(|error| anyhow!("failed to build consistency proof: {error}"))
      }
      CtStore::Postgres(store) => {
        let mut ranges = Vec::new();
        collect_consistency_ranges(first, 0, second, true, &mut ranges);
        resolve_postgres_ranges(store, &ranges).await
      }
    }
  }

  fn signer(&self) -> anyhow::Result<&CtLogSigner> {
    self
      .signer
      .as_ref()
      .ok_or_else(|| anyhow!("CT signer is unavailable"))
  }

  fn store(&self) -> anyhow::Result<&CtStore> {
    self
      .store
      .as_ref()
      .ok_or_else(|| anyhow!("CT durable store is unavailable"))
  }

  async fn reserve_entry_cancellation_safe<F>(
    &self,
    entry_key: [u8; 32],
    build: F,
  ) -> anyhow::Result<(CtReservedEntry, CtUnsignedReservationGuard)>
  where
    F: FnOnce(u64, u64) -> anyhow::Result<(Vec<u8>, Vec<u8>, [u8; 32])> + Send + 'static,
  {
    let store = self.store()?.clone();
    let max_pending_entries = self.config.publication.max_pending_entries;
    // Waiters remain ordinary request futures and disappear immediately when their client goes
    // away. Only the single request that owns this lock detaches its commit-critical section.
    let submission_guard = self.submission_run.clone().lock_owned().await;
    let (sender, receiver) = oneshot::channel();
    tokio::spawn(async move {
      // Keep the per-log submission lock in the detached task until the caller takes ownership.
      // An HTTP/1 disconnect or HTTP/2 reset can otherwise drop the service future while a
      // PostgreSQL COMMIT is in flight, leaving a durable unsigned tail with no cleanup owner.
      let reserved = match &store {
        CtStore::Local(store) => {
          store
            .reserve_entry_with_limit(&entry_key, max_pending_entries, build)
            .await
        }
        CtStore::Postgres(store) => {
          store
            .reserve_entry_with_limit(&entry_key, max_pending_entries, build)
            .await
        }
      };
      let payload = reserved.map(|reserved| {
        let reservation_guard = if reserved.receipt.is_none() {
          CtUnsignedReservationGuard::new(&store, reserved.leaf_index, submission_guard)
        } else {
          CtUnsignedReservationGuard::existing(submission_guard)
        };
        (reserved, reservation_guard)
      });
      // The payload owns cleanup before it is enqueued. If the receiver is already closed, or is
      // dropped after a successful send but before its next poll, dropping the payload invokes the
      // same unsigned-tail cleanup while retaining the per-log submission lock.
      let _ = sender.send(payload);
    });
    receiver
      .await
      .context("CT reservation task stopped unexpectedly")?
  }

  async fn reserve_sth_timestamp(&self) -> anyhow::Result<u64> {
    match self.store()? {
      CtStore::Local(store) => store.reserve_sth_timestamp().await,
      CtStore::Postgres(store) => store.reserve_sth_timestamp().await,
    }
  }

  fn mark_publish_success(&self) {
    self
      .last_publish_millis
      .store(now_millis(), Ordering::Release);
    self
      .publish_failure_since_millis
      .store(0, Ordering::Release);
  }

  fn mark_publish_failure(&self) {
    let now = now_millis();
    let _ = self.publish_failure_since_millis.compare_exchange(
      0,
      now,
      Ordering::AcqRel,
      Ordering::Acquire,
    );
  }

  fn publication_deadline_exceeded(&self) -> bool {
    let failure_since = self.publish_failure_since_millis.load(Ordering::Acquire);
    failure_since != 0
      && now_millis().saturating_sub(failure_since) >= self.config.mmd_seconds.saturating_mul(1000)
  }

  fn publication_within_mmd(&self) -> bool {
    if self.config.role != CertificateTransparencyLogRole::Operator {
      return true;
    }
    let last_publish = self.last_publish_millis.load(Ordering::Acquire);
    last_publish != 0
      && now_millis().saturating_sub(last_publish) <= self.config.mmd_seconds.saturating_mul(1000)
      && !self.publication_deadline_exceeded()
  }

  async fn freeze_for_mmd_violation(&self) -> anyhow::Result<()> {
    match self.store()? {
      CtStore::Local(store) => store.freeze("maximum merge delay exceeded").await,
      CtStore::Postgres(store) => store.freeze("maximum merge delay exceeded").await,
    }
  }
}

fn postgres_range_root<'a>(
  store: &'a CtPostgresStore,
  offset: u64,
  count: u64,
) -> BoxFuture<'a, anyhow::Result<Hash>> {
  Box::pin(async move {
    if count == 0 {
      return Ok(merkle::empty_hash());
    }
    if count.is_power_of_two() && offset.is_multiple_of(count) {
      let level = u8::try_from(count.trailing_zeros()).context("CT node level overflow")?;
      return store.node_hash(level, offset / count).await;
    }
    let split = largest_power_of_two_less_than_u64(count);
    let left = postgres_range_root(store, offset, split).await?;
    let right = postgres_range_root(store, offset + split, count - split).await?;
    Ok(merkle::node_hash(&left, &right))
  })
}

async fn resolve_postgres_ranges(
  store: &CtPostgresStore,
  ranges: &[(u64, u64)],
) -> anyhow::Result<Vec<Hash>> {
  let mut hashes = Vec::with_capacity(ranges.len());
  for &(offset, count) in ranges {
    hashes.push(postgres_range_root(store, offset, count).await?);
  }
  Ok(hashes)
}

fn collect_inclusion_ranges(
  offset: u64,
  tree_size: u64,
  leaf_index: u64,
  ranges: &mut Vec<(u64, u64)>,
) {
  if tree_size == 1 {
    return;
  }
  let split = largest_power_of_two_less_than_u64(tree_size);
  if leaf_index < split {
    collect_inclusion_ranges(offset, split, leaf_index, ranges);
    ranges.push((offset + split, tree_size - split));
  } else {
    collect_inclusion_ranges(
      offset + split,
      tree_size - split,
      leaf_index - split,
      ranges,
    );
    ranges.push((offset, split));
  }
}

fn collect_consistency_ranges(
  old_size: u64,
  offset: u64,
  new_size: u64,
  complete: bool,
  ranges: &mut Vec<(u64, u64)>,
) {
  if old_size == new_size {
    if !complete {
      ranges.push((offset, new_size));
    }
    return;
  }
  let split = largest_power_of_two_less_than_u64(new_size);
  if old_size <= split {
    collect_consistency_ranges(old_size, offset, split, complete, ranges);
    ranges.push((offset + split, new_size - split));
  } else {
    collect_consistency_ranges(
      old_size - split,
      offset + split,
      new_size - split,
      false,
      ranges,
    );
    ranges.push((offset, split));
  }
}

fn largest_power_of_two_less_than_u64(value: u64) -> u64 {
  debug_assert!(value > 1);
  1_u64 << (u64::BITS - 1 - (value - 1).leading_zeros())
}

fn complete_static_tile_roots(hashes: &[Hash]) -> Vec<Hash> {
  hashes
    .chunks_exact(crate::ct::static_ct::TILE_WIDTH)
    .map(merkle::root_from_leaf_hashes)
    .collect()
}

fn retired_artifact_path(
  protocol: CertificateTransparencyProtocol,
  request_path: &str,
) -> anyhow::Result<Option<RetiredArtifact>> {
  if request_path.is_empty()
    || request_path.len() > MAX_RETIRED_ARTIFACT_PATH_BYTES
    || !request_path.starts_with('/')
    || request_path.contains('%')
    || request_path.contains('\\')
    || request_path.contains("//")
    || request_path
      .split('/')
      .any(|segment| matches!(segment, "." | ".."))
    || request_path.bytes().any(|byte| byte.is_ascii_control())
  {
    bail!("retired CT artifact path is not canonical");
  }
  if request_path.ends_with("/checkpoint")
    || (protocol == CertificateTransparencyProtocol::Rfc9162V2
      && request_path.ends_with("/ct/v2/get-final-sth"))
  {
    return Ok(Some(RetiredArtifact::Checkpoint));
  }
  if protocol != CertificateTransparencyProtocol::StaticRfc6962V1 {
    return Ok(None);
  }

  let tile_markers = request_path.match_indices("/tile/").collect::<Vec<_>>();
  if tile_markers.len() == 1 {
    let suffix = &request_path[tile_markers[0].0 + "/tile/".len()..];
    let relative = format!("tile/{suffix}");
    let path = TilePath::parse(&relative)
      .map_err(|error| anyhow!("retired Static CT tile path is invalid: {error}"))?;
    return Ok(Some(RetiredArtifact::Tile { path, relative }));
  }
  if tile_markers.len() > 1 {
    bail!("retired Static CT tile path contains multiple tile markers");
  }

  let issuer_markers = request_path.match_indices("/issuer/").collect::<Vec<_>>();
  if issuer_markers.len() == 1 {
    let fingerprint = &request_path[issuer_markers[0].0 + "/issuer/".len()..];
    if fingerprint.len() != 64
      || !fingerprint
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
      bail!("retired Static CT issuer path is invalid");
    }
    return Ok(Some(RetiredArtifact::Issuer {
      fingerprint: fingerprint.to_string(),
      relative: format!("issuer/{fingerprint}"),
    }));
  }
  if issuer_markers.len() > 1 {
    bail!("retired Static CT issuer path contains multiple issuer markers");
  }
  Ok(None)
}

fn retired_artifact_url(source: &str, relative: &str) -> anyhow::Result<url::Url> {
  if source.is_empty()
    || source.len() > MAX_RETIRED_ARTIFACT_PATH_BYTES
    || source.contains('%')
    || source.contains('\\')
    || source.contains("/./")
    || source.contains("/../")
    || source.ends_with("/.")
    || source.ends_with("/..")
    || source.bytes().any(|byte| byte.is_ascii_control())
  {
    bail!("retired CT object source URL is not canonical");
  }
  if relative.is_empty()
    || relative.len() > MAX_RETIRED_ARTIFACT_PATH_BYTES
    || relative.starts_with('/')
    || relative.contains('%')
    || relative.contains('\\')
    || relative.bytes().any(|byte| byte.is_ascii_control())
  {
    bail!("retired CT object path is not canonical");
  }
  let mut url = url::Url::parse(source).context("retired CT object source URL is invalid")?;
  if url.scheme() != "https"
    || url.host_str().is_none()
    || !url.username().is_empty()
    || url.password().is_some()
    || url.query().is_some()
    || url.fragment().is_some()
  {
    bail!("retired CT object source must be an HTTPS base URL without credentials or suffix data");
  }
  {
    let mut segments = url
      .path_segments_mut()
      .map_err(|_| anyhow!("retired CT object source cannot be used as a base URL"))?;
    segments.pop_if_empty();
    for segment in relative.split('/') {
      if segment.is_empty() || matches!(segment, "." | "..") {
        bail!("retired CT object path contains an invalid segment");
      }
      segments.push(segment);
    }
  }
  url.set_query(None);
  url.set_fragment(None);
  Ok(url)
}

fn build_v1_entry(
  chain: &[Vec<u8>],
  kind: CtSubmissionKind,
  leaf_index: u64,
  timestamp: u64,
) -> anyhow::Result<(Vec<u8>, Vec<u8>, Hash)> {
  let (entry, leaf, extra) = v1_entry_parts(chain, kind, leaf_index, timestamp)?;
  let leaf_hash = merkle::leaf_hash(&leaf);
  let _ = entry;
  Ok((leaf, extra, leaf_hash))
}

fn decode_static_leaf(entry: &CtStoredEntry) -> anyhow::Result<(StaticTileLeaf, Vec<Vec<u8>>)> {
  let leaf = MerkleTreeLeafV1::decode(&entry.leaf_input)
    .map_err(|error| anyhow!("durable RFC 6962 leaf is invalid: {error}"))?;
  let (pre_certificate, issuers) = match &leaf.0.signed_entry {
    SignedEntryV1::X509(_) => (None, decode_certificate_vector(&entry.extra_data)?),
    SignedEntryV1::Precertificate { .. } => {
      let mut offset = 0;
      let pre_certificate = take_u24_vector(&entry.extra_data, &mut offset)?.to_vec();
      let issuers = decode_certificate_vector(&entry.extra_data[offset..])?;
      (Some(pre_certificate), issuers)
    }
  };
  Ok((
    StaticTileLeaf {
      timestamped_entry: leaf.0,
      pre_certificate,
      certificate_chain: issuers
        .iter()
        .map(|issuer| issuer_fingerprint(issuer))
        .collect(),
    },
    issuers,
  ))
}

fn decode_certificate_vector(input: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
  let mut offset = 0;
  let contents = take_u24_vector(input, &mut offset)?;
  if offset != input.len() {
    bail!("RFC 6962 certificate vector has trailing bytes");
  }
  let mut certificates = Vec::new();
  let mut inner = 0;
  while inner < contents.len() {
    certificates.push(take_u24_vector(contents, &mut inner)?.to_vec());
  }
  Ok(certificates)
}

fn take_u24_vector<'a>(input: &'a [u8], offset: &mut usize) -> anyhow::Result<&'a [u8]> {
  let length_end = offset
    .checked_add(3)
    .ok_or_else(|| anyhow!("RFC 6962 vector length overflow"))?;
  let length = input
    .get(*offset..length_end)
    .ok_or_else(|| anyhow!("RFC 6962 vector is truncated"))?;
  *offset = length_end;
  let length =
    (usize::from(length[0]) << 16) | (usize::from(length[1]) << 8) | usize::from(length[2]);
  let end = offset
    .checked_add(length)
    .ok_or_else(|| anyhow!("RFC 6962 vector length overflow"))?;
  let value = input
    .get(*offset..end)
    .ok_or_else(|| anyhow!("RFC 6962 vector is truncated"))?;
  *offset = end;
  Ok(value)
}

fn v1_entry_parts(
  chain: &[Vec<u8>],
  kind: CtSubmissionKind,
  leaf_index: u64,
  timestamp: u64,
) -> anyhow::Result<(TimestampedEntryV1, Vec<u8>, Vec<u8>)> {
  let signed_entry = match kind {
    CtSubmissionKind::Certificate => SignedEntryV1::X509(chain[0].clone()),
    CtSubmissionKind::Precertificate => {
      let issuer = chain
        .get(1)
        .ok_or_else(|| anyhow!("precertificate issuer is missing"))?;
      SignedEntryV1::Precertificate {
        issuer_key_hash: issuer_spki_hash(issuer)?,
        tbs_certificate: reconstruct_v1_precertificate_tbs(&chain[0])?,
      }
    }
  };
  let entry = TimestampedEntryV1 {
    timestamp,
    signed_entry,
    extensions: leaf_index_extension(leaf_index)
      .map_err(|error| anyhow!("failed to encode Static CT leaf index: {error}"))?,
  };
  let leaf = MerkleTreeLeafV1(entry.clone())
    .encode()
    .map_err(|error| anyhow!("failed to encode RFC 6962 Merkle leaf: {error}"))?;
  let extra = encode_v1_extra_data(chain, kind)?;
  Ok((entry, leaf, extra))
}

fn reconstruct_v1_precertificate_tbs(precertificate_der: &[u8]) -> anyhow::Result<Vec<u8>> {
  use x509_cert_v2::der::{Decode as _, Encode as _};

  const CT_POISON_OID: &str = "1.3.6.1.4.1.11129.2.4.3";
  let certificate = x509_cert_v2::Certificate::from_der(precertificate_der)
    .context("failed to parse RFC 6962 precertificate DER")?;
  let mut tbs = certificate.tbs_certificate;
  let extensions = tbs
    .extensions
    .as_mut()
    .ok_or_else(|| anyhow!("RFC 6962 precertificate is missing extensions"))?;
  let initial_len = extensions.len();
  extensions.retain(|extension| extension.extn_id.to_string() != CT_POISON_OID);
  if initial_len.saturating_sub(extensions.len()) != 1 {
    bail!("RFC 6962 precertificate must contain exactly one poison extension");
  }
  tbs
    .to_der()
    .context("failed to reconstruct poison-free RFC 6962 TBSCertificate")
}

fn build_v2_entry(
  chain: &[Vec<u8>],
  kind: CtSubmissionKind,
  leaf_index: u64,
  timestamp: u64,
) -> anyhow::Result<(Vec<u8>, Vec<u8>, Hash)> {
  let (entry, encoded, extra) = v2_entry_parts(chain, kind, leaf_index, timestamp)?;
  let leaf_hash = crate::ct::rfc9162::merkle_leaf_hash(&entry)
    .map_err(|error| anyhow!("failed to hash RFC 9162 entry: {error}"))?;
  Ok((encoded, extra, leaf_hash))
}

fn v2_entry_parts(
  chain: &[Vec<u8>],
  kind: CtSubmissionKind,
  leaf_index: u64,
  timestamp: u64,
) -> anyhow::Result<(TransItemV2, Vec<u8>, Vec<u8>)> {
  let issuer = chain
    .get(1)
    .ok_or_else(|| anyhow!("certificate issuer is missing"))?;
  let certificate = Certificate::from_der(&chain[0])?;
  let value = TimestampedCertificateEntryV2 {
    timestamp,
    issuer_key_hash: issuer_spki_hash(issuer)?.to_vec(),
    tbs_certificate: certificate.tbs_certificate().to_der()?,
    extensions: vec![ExtensionV2 {
      extension_type: V2_LEAF_INDEX_EXTENSION,
      data: leaf_index.to_be_bytes().to_vec(),
    }],
  };
  let entry = match kind {
    CtSubmissionKind::Certificate => TransItemV2::X509Entry(value),
    CtSubmissionKind::Precertificate => TransItemV2::PrecertificateEntry(value),
  };
  let encoded = entry
    .encode()
    .map_err(|error| anyhow!("failed to encode RFC 9162 entry: {error}"))?;
  Ok((entry, encoded, encode_certificate_vector(&chain[1..])?))
}

fn encode_v1_extra_data(chain: &[Vec<u8>], kind: CtSubmissionKind) -> anyhow::Result<Vec<u8>> {
  match kind {
    CtSubmissionKind::Certificate => encode_certificate_vector(&chain[1..]),
    CtSubmissionKind::Precertificate => {
      let mut encoded = Vec::new();
      push_u24(&mut encoded, chain[0].len())?;
      encoded.extend_from_slice(&chain[0]);
      let issuers = encode_certificate_vector(&chain[1..])?;
      encoded.extend_from_slice(&issuers);
      Ok(encoded)
    }
  }
}

fn encode_certificate_vector(certificates: &[Vec<u8>]) -> anyhow::Result<Vec<u8>> {
  let mut contents = Vec::new();
  for certificate in certificates {
    push_u24(&mut contents, certificate.len())?;
    contents.extend_from_slice(certificate);
  }
  let mut encoded = Vec::new();
  push_u24(&mut encoded, contents.len())?;
  encoded.extend_from_slice(&contents);
  Ok(encoded)
}

fn push_u24(output: &mut Vec<u8>, value: usize) -> anyhow::Result<()> {
  if value > 0x00ff_ffff {
    bail!("CT TLS vector exceeds u24");
  }
  output.extend_from_slice(&[
    ((value >> 16) & 0xff) as u8,
    ((value >> 8) & 0xff) as u8,
    (value & 0xff) as u8,
  ]);
  Ok(())
}

fn issuer_spki_hash(certificate_der: &[u8]) -> anyhow::Result<Hash> {
  let certificate = Certificate::from_der(certificate_der)?;
  let spki = certificate
    .tbs_certificate()
    .subject_public_key_info()
    .to_der()?;
  Ok(Sha256::digest(spki).into())
}

fn decode_chain(encoded: &[String]) -> anyhow::Result<Vec<Vec<u8>>> {
  if encoded.is_empty() || encoded.len() > MAX_SUBMISSION_CERTIFICATES {
    bail!("CT submission chain count is invalid");
  }
  encoded
    .iter()
    .map(|value| {
      let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .context("CT chain certificate is not base64")?;
      if decoded.is_empty() {
        bail!("CT chain certificate is empty");
      }
      Ok(decoded)
    })
    .collect()
}

fn submission_key(kind: CtSubmissionKind, chain: &[Vec<u8>]) -> [u8; 32] {
  let mut digest = Sha256::new();
  digest.update([match kind {
    CtSubmissionKind::Certificate => 0,
    CtSubmissionKind::Precertificate => 1,
  }]);
  for certificate in chain {
    digest.update((certificate.len() as u64).to_be_bytes());
    digest.update(certificate);
  }
  digest.finalize().into()
}

fn parse_query(query: Option<&str>) -> anyhow::Result<HashMap<String, String>> {
  let query = query.unwrap_or_default();
  if query.len() > MAX_QUERY_BYTES {
    bail!("CT query is too large");
  }
  let mut values = HashMap::new();
  for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
    if values
      .insert(key.into_owned(), value.into_owned())
      .is_some()
    {
      bail!("CT query contains a duplicate field");
    }
  }
  Ok(values)
}

fn required<'a>(query: &'a HashMap<String, String>, key: &str) -> anyhow::Result<&'a str> {
  query
    .get(key)
    .map(String::as_str)
    .ok_or_else(|| anyhow!("missing CT query field {key}"))
}

fn required_u64(query: &HashMap<String, String>, key: &str) -> anyhow::Result<u64> {
  required(query, key)?
    .parse()
    .with_context(|| format!("invalid CT query field {key}"))
}

fn decode_hash_query(value: &str) -> anyhow::Result<Hash> {
  base64::engine::general_purpose::STANDARD
    .decode(value)
    .context("CT hash query is not base64")?
    .try_into()
    .map_err(|_| anyhow!("CT hash query must be 32 bytes"))
}

fn json<T: Serialize>(
  status: StatusCode,
  value: &T,
  immutable: bool,
) -> anyhow::Result<CtHttpResponse> {
  Ok(CtHttpResponse {
    status,
    content_type: "application/json",
    body: Bytes::from(serde_json::to_vec(value)?),
    immutable,
  })
}

fn json_error(status: StatusCode, message: &str) -> CtHttpResponse {
  let body = serde_json::to_vec(&ErrorBody { error: message })
    .unwrap_or_else(|_| b"{\"error\":\"internal error\"}".to_vec());
  CtHttpResponse {
    status,
    content_type: "application/json",
    body: Bytes::from(body),
    immutable: false,
  }
}

fn read_bounded(path: &Path, maximum: u64) -> anyhow::Result<Vec<u8>> {
  let metadata =
    std::fs::metadata(path).with_context(|| format!("failed to inspect {}", path.display()))?;
  if metadata.len() == 0 || metadata.len() > maximum {
    bail!("{} has an invalid bounded length", path.display());
  }
  std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))
}

fn load_ed25519_key(path: &Path) -> anyhow::Result<[u8; 32]> {
  let bytes = read_bounded(path, MAX_ROOT_TRUST_KEY_BYTES)?;
  if let Ok(raw) = <[u8; 32]>::try_from(bytes.as_slice()) {
    return Ok(raw);
  }
  let text = std::str::from_utf8(&bytes)?.trim();
  base64::engine::general_purpose::STANDARD
    .decode(text)
    .context("CT accepted-root key must be raw or canonical base64")?
    .try_into()
    .map_err(|_| anyhow!("CT accepted-root Ed25519 key must be 32 bytes"))
}

fn short_key_id(key: &[u8; 32]) -> String {
  let digest = Sha256::digest(key);
  digest[..8]
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect()
}

fn secret_string(
  environment: Option<&str>,
  file: Option<&Path>,
  label: &str,
) -> anyhow::Result<String> {
  match (environment, file) {
    (Some(name), None) => read_environment(name),
    (None, Some(path)) => {
      let value = String::from_utf8(read_bounded(path, 64 * 1024)?)?;
      let value = value.trim_end_matches(['\r', '\n']);
      if value.is_empty() {
        bail!("{label} file is empty");
      }
      Ok(value.to_string())
    }
    _ => bail!("{label} requires exactly one source"),
  }
}

fn read_environment(name: &str) -> anyhow::Result<String> {
  let value =
    std::env::var(name).with_context(|| format!("required environment {name} is absent"))?;
  if value.is_empty() {
    bail!("required environment {name} is empty");
  }
  Ok(value)
}

fn required_clone(value: &Option<String>, label: &str) -> anyhow::Result<String> {
  value.clone().ok_or_else(|| anyhow!("{label} is missing"))
}

fn publisher_holder() -> String {
  let hostname = std::env::var("HOSTNAME")
    .ok()
    .filter(|value| !value.is_empty() && value.len() <= 96)
    .unwrap_or_else(|| "oxibelt".to_string());
  format!("{hostname}-{}", std::process::id())
}

fn now_millis() -> u64 {
  std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .ok()
    .and_then(|duration| u64::try_from(duration.as_millis()).ok())
    .unwrap_or(0)
}

fn encode_oid_value(oid: &str) -> anyhow::Result<Vec<u8>> {
  let arcs = oid
    .split('.')
    .map(|arc| arc.parse::<u64>().context("invalid OID arc"))
    .collect::<anyhow::Result<Vec<_>>>()?;
  if arcs.len() < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39) {
    bail!("invalid RFC 9162 OID");
  }
  let mut encoded = Vec::new();
  let first = arcs[0]
    .checked_mul(40)
    .and_then(|value| value.checked_add(arcs[1]))
    .ok_or_else(|| anyhow!("RFC 9162 OID first subidentifier overflows"))?;
  encode_oid_arc(first, &mut encoded);
  for arc in &arcs[2..] {
    encode_oid_arc(*arc, &mut encoded);
  }
  Ok(encoded)
}

fn encode_oid_arc(mut value: u64, output: &mut Vec<u8>) {
  let mut buffer = [0_u8; 10];
  let mut offset = buffer.len() - 1;
  buffer[offset] = (value & 0x7f) as u8;
  while value >= 128 {
    value >>= 7;
    offset -= 1;
    buffer[offset] = ((value & 0x7f) as u8) | 0x80;
  }
  output.extend_from_slice(&buffer[offset..]);
}

fn classify_rejection(error: &anyhow::Error) -> CtRejectionReason {
  let message = format!("{error:#}").to_ascii_lowercase();
  if message.contains("frozen") {
    CtRejectionReason::Frozen
  } else if message.contains("expired") {
    CtRejectionReason::Expired
  } else if message.contains("shard") || message.contains("expiry") {
    CtRejectionReason::Shard
  } else if message.contains("accepted root") || message.contains("root bundle") {
    CtRejectionReason::Root
  } else if message.contains("certificate") || message.contains("chain") {
    CtRejectionReason::Chain
  } else if message.contains("rate") {
    CtRejectionReason::RateLimit
  } else if message.contains("json") || message.contains("base64") || message.contains("malformed")
  {
    CtRejectionReason::Malformed
  } else {
    CtRejectionReason::Dependency
  }
}

fn is_submission_path(path: &str) -> bool {
  path.ends_with("/ct/v1/add-chain")
    || path.ends_with("/ct/v1/add-pre-chain")
    || path.ends_with("/ct/v2/submit-entry")
}

#[cfg(test)]
mod tests {
  use super::*;

  fn resolve_ranges(leaves: &[Hash], ranges: &[(u64, u64)]) -> Vec<Hash> {
    ranges
      .iter()
      .map(|&(offset, count)| {
        let start = usize::try_from(offset).unwrap();
        let end = usize::try_from(offset + count).unwrap();
        merkle::root_from_leaf_hashes(&leaves[start..end])
      })
      .collect()
  }

  #[test]
  fn durable_range_plans_match_reference_merkle_proofs() {
    let tree_sizes = (1..=65_u64)
      .chain([127, 128, 129, 255, 256, 257])
      .collect::<Vec<_>>();
    for tree_size in tree_sizes {
      let leaves = (0..tree_size)
        .map(|index| merkle::leaf_hash(&index.to_be_bytes()))
        .collect::<Vec<_>>();
      let leaf_indexes = if tree_size <= 65 {
        (0..tree_size).collect::<Vec<_>>()
      } else {
        vec![0, tree_size / 2, tree_size - 1]
      };
      for leaf_index in leaf_indexes {
        let mut ranges = Vec::new();
        collect_inclusion_ranges(0, tree_size, leaf_index, &mut ranges);
        assert_eq!(
          resolve_ranges(&leaves, &ranges),
          merkle::inclusion_proof(&leaves, usize::try_from(leaf_index).unwrap()).unwrap()
        );
      }
      let old_sizes = if tree_size <= 65 {
        (0..=tree_size).collect::<Vec<_>>()
      } else {
        vec![0, 1, tree_size / 2, tree_size - 1, tree_size]
      };
      for old_size in old_sizes {
        let mut ranges = Vec::new();
        if old_size != 0 && old_size != tree_size {
          collect_consistency_ranges(old_size, 0, tree_size, true, &mut ranges);
        }
        assert_eq!(
          resolve_ranges(&leaves, &ranges),
          merkle::consistency_proof(&leaves, usize::try_from(old_size).unwrap()).unwrap()
        );
      }
    }
  }

  #[test]
  fn static_tile_promotion_ignores_partial_lower_tiles() {
    let hashes = (0..70_000_u64)
      .map(|index| merkle::leaf_hash(&index.to_be_bytes()))
      .collect::<Vec<_>>();

    assert!(complete_static_tile_roots(&hashes[..255]).is_empty());
    assert_eq!(complete_static_tile_roots(&hashes[..256]).len(), 1);
    assert_eq!(complete_static_tile_roots(&hashes[..257]).len(), 1);
    assert_eq!(complete_static_tile_roots(&hashes[..511]).len(), 1);
    assert_eq!(complete_static_tile_roots(&hashes[..512]).len(), 2);

    let level_one = complete_static_tile_roots(&hashes);
    assert_eq!(level_one.len(), 273);
    assert_eq!(
      level_one[0],
      merkle::root_from_leaf_hashes(&hashes[..crate::ct::static_ct::TILE_WIDTH])
    );
    assert_eq!(complete_static_tile_roots(&level_one).len(), 1);
  }

  #[test]
  fn retired_artifact_paths_are_narrow_and_canonical() {
    let checkpoint = retired_artifact_path(
      CertificateTransparencyProtocol::StaticRfc6962V1,
      "/logs/archive/checkpoint",
    )
    .unwrap()
    .unwrap();
    assert_eq!(checkpoint.relative_path(), "checkpoint");

    let tile = retired_artifact_path(
      CertificateTransparencyProtocol::StaticRfc6962V1,
      "/logs/archive/tile/0/000.p/7",
    )
    .unwrap()
    .unwrap();
    assert_eq!(tile.relative_path(), "tile/0/000.p/7");

    let fingerprint = "a".repeat(64);
    let issuer = retired_artifact_path(
      CertificateTransparencyProtocol::StaticRfc6962V1,
      &format!("/logs/archive/issuer/{fingerprint}"),
    )
    .unwrap()
    .unwrap();
    assert_eq!(issuer.relative_path(), format!("issuer/{fingerprint}"));

    let final_sth = retired_artifact_path(
      CertificateTransparencyProtocol::Rfc9162V2,
      "/logs/archive/ct/v2/get-final-sth",
    )
    .unwrap()
    .unwrap();
    assert_eq!(final_sth.relative_path(), "checkpoint");
    assert!(
      retired_artifact_path(
        CertificateTransparencyProtocol::Rfc9162V2,
        "/logs/archive/tile/0/000",
      )
      .unwrap()
      .is_none()
    );
  }

  #[test]
  fn retired_artifact_paths_reject_ambiguous_or_encoded_input() {
    for path in [
      "/logs//checkpoint",
      "/logs/%2e%2e/checkpoint",
      "/logs/../checkpoint",
      "/logs/tile/0/0",
      "/logs/tile/0/000/tile/0/000",
      "/logs/issuer/ABCDEF",
    ] {
      assert!(
        retired_artifact_path(CertificateTransparencyProtocol::StaticRfc6962V1, path).is_err(),
        "accepted {path}"
      );
    }
  }

  #[test]
  fn retired_artifact_url_appends_only_validated_relative_segments() {
    let url =
      retired_artifact_url("https://objects.example.test/tenant/log/", "tile/0/000.p/7").unwrap();
    assert_eq!(
      url.as_str(),
      "https://objects.example.test/tenant/log/tile/0/000.p/7"
    );
    for source in [
      "http://objects.example.test/log",
      "https://user@objects.example.test/log",
      "https://objects.example.test/log?version=1",
      "https://objects.example.test/log%2fescape",
      "https://objects.example.test/log/../escape",
    ] {
      assert!(retired_artifact_url(source, "checkpoint").is_err());
    }
    assert!(retired_artifact_url("https://objects.example.test/log", "../checkpoint").is_err());
    assert!(retired_artifact_url("https://objects.example.test/log", "%2e%2e/checkpoint").is_err());
  }
}

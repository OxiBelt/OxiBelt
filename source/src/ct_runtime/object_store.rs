//! Immutable CT object publication with conditional writes and readback verification.

use std::fmt;
use std::path::Path as FsPath;
use std::sync::Arc;

use anyhow::{Context, bail};
use bytes::Bytes;
use object_store::aws::AmazonS3Builder;
use object_store::local::LocalFileSystem;
use object_store::path::Path;
use object_store::{
  ClientOptions, ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload, UpdateVersion,
};
use sha2::{Digest as _, Sha256};

const MAX_CT_OBJECT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone)]
pub struct S3ObjectStoreConfig {
  pub bucket: String,
  pub region: String,
  pub endpoint: Option<String>,
  pub access_key_id: Option<String>,
  pub secret_access_key: Option<String>,
  pub session_token: Option<String>,
  pub virtual_hosted_style: bool,
  pub allow_http_for_local_development: bool,
}

impl fmt::Debug for S3ObjectStoreConfig {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("S3ObjectStoreConfig")
      .field("bucket", &self.bucket)
      .field("region", &self.region)
      .field("endpoint", &redacted_presence(&self.endpoint))
      .field("access_key_id", &redacted_presence(&self.access_key_id))
      .field(
        "secret_access_key",
        &redacted_presence(&self.secret_access_key),
      )
      .field("session_token", &redacted_presence(&self.session_token))
      .field("virtual_hosted_style", &self.virtual_hosted_style)
      .field(
        "allow_http_for_local_development",
        &self.allow_http_for_local_development,
      )
      .finish()
  }
}

#[derive(Clone, Debug)]
pub enum CtObjectStoreConfig {
  S3(S3ObjectStoreConfig),
  Local { root: std::path::PathBuf },
}

#[derive(Clone)]
pub struct CtObjectPublisher {
  store: Arc<dyn ObjectStore>,
  prefix: Path,
  production: bool,
  local_filesystem: bool,
}

impl CtObjectPublisher {
  pub fn from_config(
    config: &CtObjectStoreConfig,
    prefix: &str,
    production: bool,
  ) -> anyhow::Result<Self> {
    Self::from_config_with_client_options(config, prefix, production, None)
  }

  #[cfg(test)]
  pub fn from_config_with_test_root_certificate(
    config: &CtObjectStoreConfig,
    prefix: &str,
    production: bool,
    certificate: object_store::Certificate,
  ) -> anyhow::Result<Self> {
    Self::from_config_with_client_options(
      config,
      prefix,
      production,
      Some(
        ClientOptions::new()
          .with_root_certificate(certificate)
          .with_no_system_certificates(true),
      ),
    )
  }

  fn from_config_with_client_options(
    config: &CtObjectStoreConfig,
    prefix: &str,
    production: bool,
    client_options: Option<ClientOptions>,
  ) -> anyhow::Result<Self> {
    let prefix = parse_relative_path(prefix, "CT object prefix")?;
    let (store, local_filesystem): (Arc<dyn ObjectStore>, bool) = match config {
      CtObjectStoreConfig::S3(config) => {
        if config.bucket.trim().is_empty() || config.region.trim().is_empty() {
          bail!("CT S3 bucket and region must not be empty");
        }
        if production && config.allow_http_for_local_development {
          bail!("production CT object storage cannot allow plaintext HTTP");
        }
        if production
          && config.endpoint.as_deref().is_some_and(
            |endpoint| !matches!(url::Url::parse(endpoint), Ok(url) if url.scheme() == "https"),
          )
        {
          bail!("production CT object storage endpoint must use HTTPS");
        }
        let mut builder = AmazonS3Builder::new()
          .with_bucket_name(&config.bucket)
          .with_region(&config.region)
          .with_virtual_hosted_style_request(config.virtual_hosted_style)
          .with_allow_http(config.allow_http_for_local_development);
        if let Some(endpoint) = &config.endpoint {
          builder = builder.with_endpoint(endpoint);
        }
        if let Some(access_key_id) = &config.access_key_id {
          builder = builder.with_access_key_id(access_key_id);
        }
        if let Some(secret_access_key) = &config.secret_access_key {
          builder = builder.with_secret_access_key(secret_access_key);
        }
        if let Some(session_token) = &config.session_token {
          builder = builder.with_token(session_token);
        }
        if let Some(client_options) = client_options {
          builder = builder.with_client_options(client_options);
        }
        (
          Arc::new(
            builder
              .build()
              .map_err(|_| anyhow::anyhow!("failed to build CT S3 object store"))?,
          ),
          false,
        )
      }
      CtObjectStoreConfig::Local { root } => {
        if production {
          bail!("production CT logs require S3-compatible immutable object storage");
        }
        (
          Arc::new(
            LocalFileSystem::new_with_prefix(root)
              .with_context(|| format!("failed to open CT object root {}", root.display()))?
              .with_fsync(true),
          ),
          true,
        )
      }
    };
    Ok(Self {
      store,
      prefix,
      production,
      local_filesystem,
    })
  }

  #[cfg(test)]
  pub fn with_store(store: Arc<dyn ObjectStore>, prefix: &str, production: bool) -> Self {
    Self {
      store,
      prefix: Path::parse(prefix).expect("test prefix should be valid"),
      production,
      local_filesystem: false,
    }
  }

  pub async fn put_immutable(&self, relative: &str, bytes: Bytes) -> anyhow::Result<()> {
    validate_object_bytes(&bytes)?;
    let path = self.path(relative)?;
    let options = PutOptions {
      mode: PutMode::Create,
      ..PutOptions::default()
    };
    match self
      .store
      .put_opts(&path, PutPayload::from(bytes.clone()), options)
      .await
    {
      Ok(result) => {
        if self.production && result.version.is_none() {
          bail!("production CT object store did not return a version for immutable write");
        }
      }
      Err(object_store::Error::AlreadyExists { .. }) => {
        let existing = self.read_exact(&path).await?;
        if existing != bytes {
          bail!("CT immutable object path already contains different bytes");
        }
      }
      Err(error) => return Err(object_store_error("create immutable object", error)),
    }
    self.verify_readback(&path, &bytes).await
  }

  pub async fn publish_checkpoint(
    &self,
    bytes: Bytes,
    previous: Option<UpdateVersion>,
  ) -> anyhow::Result<UpdateVersion> {
    validate_object_bytes(&bytes)?;
    let path = self.path("checkpoint")?;
    if self.local_filesystem {
      let result = self
        .store
        .put(&path, PutPayload::from(bytes.clone()))
        .await
        .map_err(|error| object_store_error("publish local checkpoint", error))?;
      self.verify_readback(&path, &bytes).await?;
      return Ok(result.into());
    }
    let mode = previous.map_or(PutMode::Create, PutMode::Update);
    let first = self
      .store
      .put_opts(
        &path,
        PutPayload::from(bytes.clone()),
        PutOptions {
          mode,
          ..PutOptions::default()
        },
      )
      .await;
    let result = match first {
      Ok(result) => result,
      Err(object_store::Error::AlreadyExists { .. }) if !self.production => {
        let meta = self
          .store
          .head(&path)
          .await
          .map_err(|error| object_store_error("inspect local checkpoint", error))?;
        self
          .store
          .put_opts(
            &path,
            PutPayload::from(bytes.clone()),
            PutOptions {
              mode: PutMode::Update(UpdateVersion {
                e_tag: meta.e_tag,
                version: meta.version,
              }),
              ..PutOptions::default()
            },
          )
          .await
          .map_err(|error| object_store_error("replace local checkpoint", error))?
      }
      Err(object_store::Error::AlreadyExists { .. })
      | Err(object_store::Error::Precondition { .. }) => {
        return self.recover_matching_checkpoint(&path, &bytes).await;
      }
      Err(error) => {
        return Err(object_store_error(
          "conditionally publish checkpoint",
          error,
        ));
      }
    };
    if self.production && result.version.is_none() {
      bail!("production CT object store did not return a checkpoint version");
    }
    self.verify_readback(&path, &bytes).await?;
    Ok(result.into())
  }

  async fn recover_matching_checkpoint(
    &self,
    path: &Path,
    expected: &Bytes,
  ) -> anyhow::Result<UpdateVersion> {
    let before = self
      .store
      .head(path)
      .await
      .map_err(|error| object_store_error("inspect checkpoint conflict", error))?;
    let actual = self.read_exact(path).await?;
    let after = self
      .store
      .head(path)
      .await
      .map_err(|error| object_store_error("recheck checkpoint conflict", error))?;
    if before.e_tag != after.e_tag || before.version != after.version {
      bail!("CT checkpoint changed while recovering a conditional-write conflict");
    }
    if actual != *expected {
      bail!("CT checkpoint conditional-write conflict contains different bytes");
    }
    if self.production && after.version.is_none() {
      bail!("production CT checkpoint recovery did not observe object versioning");
    }
    Ok(UpdateVersion {
      e_tag: after.e_tag,
      version: after.version,
    })
  }

  pub async fn checkpoint_snapshot(&self) -> anyhow::Result<(Bytes, UpdateVersion)> {
    let path = self.path("checkpoint")?;
    let before = self
      .store
      .head(&path)
      .await
      .map_err(|error| object_store_error("inspect checkpoint", error))?;
    let bytes = self.read_exact(&path).await?;
    let after = self
      .store
      .head(&path)
      .await
      .map_err(|error| object_store_error("recheck checkpoint", error))?;
    if before.e_tag != after.e_tag || before.version != after.version {
      bail!("CT checkpoint changed while taking a reconciliation snapshot");
    }
    if self.production && after.version.is_none() {
      bail!("production CT checkpoint snapshot did not observe object versioning");
    }
    Ok((
      bytes,
      UpdateVersion {
        e_tag: after.e_tag,
        version: after.version,
      },
    ))
  }

  pub async fn read(&self, relative: &str) -> anyhow::Result<Bytes> {
    let path = self.path(relative)?;
    self.read_exact(&path).await
  }

  /// Probes create-only writes, conditional replacement, version reporting, and checksum
  /// readback without deleting evidence. The deterministic capability object is reused on
  /// every startup, so a successful probe leaves only a bounded logical key.
  pub async fn probe_capabilities(&self, log_identity: &str) -> anyhow::Result<()> {
    if log_identity.is_empty()
      || log_identity.len() > 128
      || !log_identity
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
      bail!("CT capability probe log identity is invalid");
    }
    let relative = format!(".capabilities/{log_identity}");
    let path = self.path(&relative)?;
    let payload = Bytes::from_static(b"oxibelt-ct-object-store-capability-v1\n");
    let create = self
      .store
      .put_opts(
        &path,
        PutPayload::from(payload.clone()),
        PutOptions {
          mode: PutMode::Create,
          ..PutOptions::default()
        },
      )
      .await;
    let version = match create {
      Ok(result) => UpdateVersion::from(result),
      Err(object_store::Error::AlreadyExists { .. }) => {
        let meta = self
          .store
          .head(&path)
          .await
          .map_err(|error| object_store_error("inspect capability object", error))?;
        UpdateVersion {
          e_tag: meta.e_tag,
          version: meta.version,
        }
      }
      Err(error) => return Err(object_store_error("create capability object", error)),
    };
    if self.production && version.version.is_none() {
      bail!("production CT object store capability probe did not observe versioning");
    }
    self.verify_readback(&path, &payload).await?;
    let update = self
      .store
      .put_opts(
        &path,
        PutPayload::from(payload.clone()),
        PutOptions {
          mode: PutMode::Update(version),
          ..PutOptions::default()
        },
      )
      .await
      .map_err(|error| object_store_error("conditionally update capability object", error))?;
    if self.production && update.version.is_none() {
      bail!("production CT object store update probe did not observe versioning");
    }
    self.verify_readback(&path, &payload).await
  }

  fn path(&self, relative: &str) -> anyhow::Result<Path> {
    let relative = parse_relative_path(relative, "CT object path")?;
    Ok(self.prefix.clone().join(relative.as_ref()))
  }

  async fn read_exact(&self, path: &Path) -> anyhow::Result<Bytes> {
    let result = self
      .store
      .get(path)
      .await
      .map_err(|error| object_store_error("read object", error))?;
    let bytes = result
      .bytes()
      .await
      .map_err(|_| anyhow::anyhow!("CT object store collect object bytes failed"))?;
    validate_object_bytes(&bytes)?;
    Ok(bytes)
  }

  async fn verify_readback(&self, path: &Path, expected: &Bytes) -> anyhow::Result<()> {
    let actual = self.read_exact(path).await?;
    let expected_digest: [u8; 32] = Sha256::digest(expected).into();
    let actual_digest: [u8; 32] = Sha256::digest(&actual).into();
    if expected_digest != actual_digest || actual.len() != expected.len() {
      bail!("CT object checksum readback mismatch");
    }
    Ok(())
  }
}

fn parse_relative_path(value: &str, label: &str) -> anyhow::Result<Path> {
  if value.is_empty()
    || value.len() > 1024
    || FsPath::new(value).is_absolute()
    || value
      .split('/')
      .any(|component| component.is_empty() || matches!(component, "." | ".."))
  {
    bail!("{label} must be a bounded relative path");
  }
  Path::parse(value).with_context(|| format!("{label} is invalid"))
}

fn validate_object_bytes(bytes: &Bytes) -> anyhow::Result<()> {
  if bytes.len() > MAX_CT_OBJECT_BYTES {
    bail!("CT object exceeds {MAX_CT_OBJECT_BYTES} bytes");
  }
  Ok(())
}

fn redacted_presence(value: &Option<String>) -> &'static str {
  if value.is_some() {
    "<redacted>"
  } else {
    "<unset>"
  }
}

fn object_store_error(operation: &'static str, error: object_store::Error) -> anyhow::Error {
  let class = match error {
    object_store::Error::AlreadyExists { .. } => "already-exists",
    object_store::Error::InvalidPath { .. } => "invalid-path",
    object_store::Error::NotFound { .. } => "not-found",
    object_store::Error::NotImplemented { .. } => "not-implemented",
    object_store::Error::NotModified { .. } => "not-modified",
    object_store::Error::NotSupported { .. } => "not-supported",
    object_store::Error::PermissionDenied { .. } => "permission-denied",
    object_store::Error::Precondition { .. } => "precondition",
    object_store::Error::Unauthenticated { .. } => "unauthenticated",
    object_store::Error::UnknownConfigurationKey { .. } => "configuration",
    object_store::Error::Generic { source, .. } => provider_error_class(source.as_ref()),
    _ => "unknown",
  };
  anyhow::anyhow!("CT object store {operation} failed ({class})")
}

fn provider_error_class(source: &(dyn std::error::Error + 'static)) -> &'static str {
  let mut current = Some(source);
  while let Some(error) = current {
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("not valid for name") || message.contains("certnotvalidforname") {
      return "transport-tls-name";
    }
    if message.contains("unknown issuer") || message.contains("unknownissuer") {
      return "transport-tls-issuer";
    }
    if message.contains("ca used as end entity") || message.contains("causedasendentity") {
      return "transport-tls-ca-role";
    }
    if message.contains("bad encoding") || message.contains("badencoding") {
      return "transport-tls-encoding";
    }
    if message.contains("not valid yet") {
      return "transport-tls-not-yet-valid";
    }
    if message.contains("expired") {
      return "transport-tls-expired";
    }
    if message.contains("certificate") || message.contains("tls") {
      return "transport-tls";
    }
    if message.contains("proxy") {
      return "transport-proxy";
    }
    if message.contains("timed out") || message.contains("timeout") {
      return "transport-timeout";
    }
    if message.contains("connect") || message.contains("dns") {
      return "transport-connect";
    }
    if message.contains("invalidaccesskeyid")
      || message.contains("signaturedoesnotmatch")
      || message.contains("accessdenied")
      || message.contains("status 401")
      || message.contains("status 403")
    {
      return "authentication";
    }
    if message.contains("nosuchbucket") || message.contains("status 404") {
      return "bucket-not-found";
    }
    if message.contains("status 5") {
      return "service";
    }
    current = error.source();
  }
  "provider"
}

#[cfg(test)]
mod tests {
  use std::io;

  use object_store::memory::InMemory;

  use super::*;

  #[tokio::test]
  async fn immutable_put_is_idempotent_but_rejects_different_bytes() {
    let publisher = CtObjectPublisher::with_store(Arc::new(InMemory::new()), "log", false);
    publisher
      .put_immutable("tile/0/0", Bytes::from_static(b"same"))
      .await
      .unwrap();
    publisher
      .put_immutable("tile/0/0", Bytes::from_static(b"same"))
      .await
      .unwrap();
    assert!(
      publisher
        .put_immutable("tile/0/0", Bytes::from_static(b"different"))
        .await
        .is_err()
    );
  }

  #[tokio::test]
  async fn stale_checkpoint_version_is_rejected() {
    let publisher = CtObjectPublisher::with_store(Arc::new(InMemory::new()), "log", false);
    let first = publisher
      .publish_checkpoint(Bytes::from_static(b"first"), None)
      .await
      .unwrap();
    let stale = first.clone();
    publisher
      .publish_checkpoint(Bytes::from_static(b"second"), Some(first))
      .await
      .unwrap();
    assert!(
      publisher
        .publish_checkpoint(Bytes::from_static(b"stale"), Some(stale))
        .await
        .is_err()
    );
  }

  #[tokio::test]
  async fn stale_checkpoint_version_recovers_only_identical_bytes() {
    let publisher = CtObjectPublisher::with_store(Arc::new(InMemory::new()), "log", false);
    let first = publisher
      .publish_checkpoint(Bytes::from_static(b"first"), None)
      .await
      .unwrap();
    publisher
      .publish_checkpoint(Bytes::from_static(b"second"), Some(first.clone()))
      .await
      .unwrap();
    publisher
      .publish_checkpoint(Bytes::from_static(b"second"), Some(first))
      .await
      .expect("an exact checkpoint written before a crash should be recoverable");
  }

  #[tokio::test]
  async fn local_checkpoint_uses_durable_overwrite_without_update_mode() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("objects");
    std::fs::create_dir_all(&root).unwrap();
    let publisher =
      CtObjectPublisher::from_config(&CtObjectStoreConfig::Local { root }, "log", false).unwrap();
    let first = publisher
      .publish_checkpoint(Bytes::from_static(b"first"), None)
      .await
      .unwrap();
    publisher
      .publish_checkpoint(Bytes::from_static(b"second"), Some(first))
      .await
      .unwrap();
    assert_eq!(
      publisher.read("checkpoint").await.unwrap(),
      Bytes::from_static(b"second")
    );
  }

  #[test]
  fn s3_config_debug_redacts_credentials() {
    let config = S3ObjectStoreConfig {
      bucket: "ct-bucket".into(),
      region: "us-east-1".into(),
      endpoint: Some("https://object.example.test".into()),
      access_key_id: Some("access-key-must-not-appear".into()),
      secret_access_key: Some("secret-must-not-appear".into()),
      session_token: Some("session-token-must-not-appear".into()),
      virtual_hosted_style: false,
      allow_http_for_local_development: false,
    };

    let rendered = format!("{config:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("object.example.test"));
    assert!(!rendered.contains("access-key-must-not-appear"));
    assert!(!rendered.contains("secret-must-not-appear"));
    assert!(!rendered.contains("session-token-must-not-appear"));
  }

  #[test]
  fn object_store_failures_do_not_expose_provider_context() {
    let error = object_store_error(
      "read object",
      object_store::Error::Generic {
        store: "S3",
        source: Box::new(io::Error::other("secret-must-not-appear")),
      },
    );
    assert_eq!(
      error.to_string(),
      "CT object store read object failed (provider)"
    );
    assert!(!error.to_string().contains("secret-must-not-appear"));
  }

  #[test]
  fn ct_object_paths_reject_absolute_and_traversal_forms() {
    for value in [
      "/absolute",
      "../escape",
      "prefix/../escape",
      "prefix//child",
    ] {
      assert!(
        parse_relative_path(value, "CT object path").is_err(),
        "{value}"
      );
    }
    assert_eq!(
      parse_relative_path(".capabilities/log_1", "CT object path").unwrap(),
      Path::from(".capabilities/log_1")
    );
  }

  #[test]
  fn production_rejects_local_and_plaintext_object_storage() {
    let local = CtObjectStoreConfig::Local {
      root: tempfile::tempdir().unwrap().path().to_path_buf(),
    };
    assert!(CtObjectPublisher::from_config(&local, "log", true).is_err());

    let mut plaintext = S3ObjectStoreConfig {
      bucket: "ct-bucket".into(),
      region: "us-east-1".into(),
      endpoint: Some("http://127.0.0.1:9000".into()),
      access_key_id: None,
      secret_access_key: None,
      session_token: None,
      virtual_hosted_style: false,
      allow_http_for_local_development: false,
    };
    assert!(
      CtObjectPublisher::from_config(&CtObjectStoreConfig::S3(plaintext.clone()), "log", true)
        .is_err()
    );
    plaintext.allow_http_for_local_development = true;
    assert!(
      CtObjectPublisher::from_config(&CtObjectStoreConfig::S3(plaintext), "log", true).is_err()
    );
  }

  #[tokio::test]
  async fn minio_tls_publishes_with_test_root_certificate() {
    let endpoint = match std::env::var("OXIBELT_TEST_CT_MINIO_ENDPOINT") {
      Ok(endpoint) => endpoint,
      Err(_) => return,
    };
    let bucket = std::env::var("OXIBELT_TEST_CT_MINIO_BUCKET")
      .expect("MinIO test bucket must be supplied with the endpoint");
    let access_key_id = std::env::var("OXIBELT_TEST_CT_MINIO_ACCESS_KEY_ID")
      .expect("MinIO test access key must be supplied with the endpoint");
    let secret_access_key = std::env::var("OXIBELT_TEST_CT_MINIO_SECRET_ACCESS_KEY")
      .expect("MinIO test secret key must be supplied with the endpoint");
    let ca_path = std::env::var("OXIBELT_TEST_CT_MINIO_CA_PEM")
      .expect("MinIO test CA path must be supplied with the endpoint");
    let certificate = object_store::Certificate::from_pem(
      &std::fs::read(ca_path).expect("MinIO test CA must be readable"),
    )
    .expect("MinIO test CA must be a PEM certificate");
    let config = CtObjectStoreConfig::S3(S3ObjectStoreConfig {
      bucket,
      region: "us-east-1".into(),
      endpoint: Some(endpoint),
      access_key_id: Some(access_key_id),
      secret_access_key: Some(secret_access_key),
      session_token: None,
      virtual_hosted_style: false,
      allow_http_for_local_development: false,
    });
    let publisher = CtObjectPublisher::from_config_with_test_root_certificate(
      &config,
      "integration",
      true,
      certificate,
    )
    .expect("MinIO TLS configuration must build");

    publisher.probe_capabilities("minio-tls").await.unwrap();
    publisher
      .put_immutable("tiles/0/0", Bytes::from_static(b"immutable tile"))
      .await
      .unwrap();
    publisher
      .put_immutable("tiles/0/0", Bytes::from_static(b"immutable tile"))
      .await
      .unwrap();
    let immutable_conflict = publisher
      .put_immutable("tiles/0/0", Bytes::from_static(b"different tile"))
      .await
      .expect_err("MinIO must preserve create-only immutable object semantics");
    assert!(
      immutable_conflict
        .to_string()
        .contains("already contains different bytes")
    );
    let first = publisher
      .publish_checkpoint(Bytes::from_static(b"checkpoint one"), None)
      .await
      .unwrap();
    publisher
      .publish_checkpoint(Bytes::from_static(b"checkpoint two"), Some(first.clone()))
      .await
      .unwrap();
    let stale_checkpoint = publisher
      .publish_checkpoint(Bytes::from_static(b"checkpoint three"), Some(first))
      .await
      .expect_err("MinIO must reject a stale checkpoint version");
    assert!(
      stale_checkpoint
        .to_string()
        .contains("conditional-write conflict contains different bytes")
    );
    assert_eq!(
      publisher.read("checkpoint").await.unwrap(),
      Bytes::from_static(b"checkpoint two")
    );
  }
}

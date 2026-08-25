//! Immutable CT object publication with conditional writes and readback verification.

use std::path::Path as FsPath;
use std::sync::Arc;

use anyhow::{Context, bail};
use bytes::Bytes;
use object_store::aws::AmazonS3Builder;
use object_store::local::LocalFileSystem;
use object_store::path::Path;
use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload, UpdateVersion};
use sha2::{Digest as _, Sha256};

const MAX_CT_OBJECT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug)]
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
    let prefix = parse_relative_path(prefix, "CT object prefix")?;
    let (store, local_filesystem): (Arc<dyn ObjectStore>, bool) = match config {
      CtObjectStoreConfig::S3(config) => {
        if config.bucket.trim().is_empty() || config.region.trim().is_empty() {
          bail!("CT S3 bucket and region must not be empty");
        }
        if production && config.allow_http_for_local_development {
          bail!("production CT object storage cannot allow plaintext HTTP");
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
        (
          Arc::new(
            builder
              .build()
              .context("failed to build CT S3 object store")?,
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
      Err(error) => return Err(error).context("failed to create immutable CT object"),
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
        .context("failed to publish local CT checkpoint")?;
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
          .context("failed to inspect existing local CT checkpoint")?;
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
          .context("failed to replace existing local CT checkpoint")?
      }
      Err(object_store::Error::AlreadyExists { .. })
      | Err(object_store::Error::Precondition { .. }) => {
        return self.recover_matching_checkpoint(&path, &bytes).await;
      }
      Err(error) => return Err(error).context("failed to conditionally publish CT checkpoint"),
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
      .context("failed to inspect checkpoint after conditional-write conflict")?;
    let actual = self.read_exact(path).await?;
    let after = self
      .store
      .head(path)
      .await
      .context("failed to recheck checkpoint after conditional-write conflict")?;
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
      .context("failed to inspect current CT checkpoint")?;
    let bytes = self.read_exact(&path).await?;
    let after = self
      .store
      .head(&path)
      .await
      .context("failed to recheck current CT checkpoint")?;
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
          .context("failed to inspect CT capability object")?;
        UpdateVersion {
          e_tag: meta.e_tag,
          version: meta.version,
        }
      }
      Err(error) => return Err(error).context("CT object store create-only probe failed"),
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
      .context("CT object store conditional-update probe failed")?;
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
      .context("failed to read CT object")?;
    let bytes = result
      .bytes()
      .await
      .context("failed to collect CT object bytes")?;
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
  if value.is_empty() || value.len() > 1024 || FsPath::new(value).is_absolute() {
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

#[cfg(test)]
mod tests {
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
}

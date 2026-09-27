//! Host adapters for durable managed-upload storage.
//!
//! The storage crate owns journals and leases; the host supplies validated
//! operator configuration and dictionary identities at the activation edge.

use crate::compression_dictionary::codec::DictionaryCoding;
use crate::config;

pub(crate) use oxibelt_upload_storage::{
  DispatchClaim, DispatchTerminal, InspectedPart, UploadByteStream, UploadCreate,
  UploadDictionaryCoding, UploadDictionaryHash, UploadDictionaryPin, UploadOptions, UploadOwner,
  UploadPartAdmission, UploadRejection, UploadRuntime, UploadState, UploadStatus, UploadStore,
};

pub(crate) fn options(config: &config::Config) -> UploadOptions {
  UploadOptions {
    upload_stores: config.upload_stores.iter().map(store_config).collect(),
    upload_profiles: config.upload_profiles.iter().map(profile_config).collect(),
  }
}

pub(crate) fn store_config(
  value: &config::UploadStoreConfig,
) -> oxibelt_upload_storage::config::UploadStoreConfig {
  oxibelt_upload_storage::config::UploadStoreConfig {
    name: value.name.clone(),
    kind: match value.kind {
      config::UploadStoreKind::Local => oxibelt_upload_storage::config::UploadStoreKind::Local,
      config::UploadStoreKind::PostgresS3 => {
        oxibelt_upload_storage::config::UploadStoreKind::PostgresS3
      }
    },
    local: value.local.as_ref().map(|local| {
      oxibelt_upload_storage::config::LocalUploadStoreConfig {
        root: local.root.clone(),
      }
    }),
    postgres_s3: value.postgres_s3.as_ref().map(|store| {
      oxibelt_upload_storage::config::PostgresS3UploadStoreConfig {
        postgres_url_env: store.postgres_url_env.clone(),
        max_connections: store.max_connections,
        s3_bucket: store.s3_bucket.clone(),
        s3_region: store.s3_region.clone(),
        s3_root_certificate: store.s3_root_certificate.clone(),
        s3_endpoint: store.s3_endpoint.clone(),
        s3_prefix: store.s3_prefix.clone(),
        s3_access_key_env: store.s3_access_key_env.clone(),
        s3_secret_key_env: store.s3_secret_key_env.clone(),
        s3_session_token_env: store.s3_session_token_env.clone(),
        s3_virtual_hosted_style: store.s3_virtual_hosted_style,
      }
    }),
  }
}

pub(crate) fn profile_config(
  value: &config::UploadProfileConfig,
) -> oxibelt_upload_storage::config::UploadProfileConfig {
  oxibelt_upload_storage::config::UploadProfileConfig {
    name: value.name.clone(),
    store: value.store.clone(),
    public_base_url: value.public_base_url.clone(),
    staging_dir: value.staging_dir.clone(),
    max_staging_bytes: value.max_staging_bytes,
    control_path_prefix: value.control_path_prefix.clone(),
    object_path_prefix: value.object_path_prefix.clone(),
    destination: match &value.destination {
      config::UploadDestinationConfig::Object => {
        oxibelt_upload_storage::config::UploadDestinationConfig::Object
      }
      config::UploadDestinationConfig::Upstream { upstream } => {
        oxibelt_upload_storage::config::UploadDestinationConfig::Upstream {
          upstream: upstream.clone(),
        }
      }
    },
    identity: oxibelt_upload_storage::config::UploadIdentityConfig {
      kind: identity_kind(value.identity.kind),
      source: value.identity.source.clone(),
      subject_field: value.identity.subject_field.clone(),
    },
    max_upload_bytes: value.max_upload_bytes,
    max_part_bytes: value.max_part_bytes,
    max_storage_bytes: value.max_storage_bytes,
    max_sessions: value.max_sessions,
    max_parts: value.max_parts,
    inspection_bytes: value.inspection_bytes,
    ttl_seconds: value.ttl_seconds,
    object_ttl_seconds: value.object_ttl_seconds,
    max_concurrent_uploads: value.max_concurrent_uploads,
    max_concurrent_parts: value.max_concurrent_parts,
    compression_dictionary: value.compression_dictionary.as_ref().map(|dictionary| {
      oxibelt_upload_storage::config::ManagedUploadDictionaryConfig {
        profile: dictionary.profile.clone(),
        dictionary: dictionary.dictionary.clone(),
      }
    }),
  }
}

pub(crate) fn identity_kind(
  value: config::UploadIdentityKind,
) -> oxibelt_upload_storage::config::UploadIdentityKind {
  match value {
    config::UploadIdentityKind::Ipm => oxibelt_upload_storage::config::UploadIdentityKind::Ipm,
    config::UploadIdentityKind::ExternalAuth => {
      oxibelt_upload_storage::config::UploadIdentityKind::ExternalAuth
    }
    config::UploadIdentityKind::Mtls => oxibelt_upload_storage::config::UploadIdentityKind::Mtls,
  }
}

pub(crate) fn upload_dictionary_coding(value: DictionaryCoding) -> UploadDictionaryCoding {
  match value {
    DictionaryCoding::Dcb => UploadDictionaryCoding::Dcb,
    DictionaryCoding::Dcz => UploadDictionaryCoding::Dcz,
  }
}

pub(crate) fn dictionary_coding(value: UploadDictionaryCoding) -> DictionaryCoding {
  match value {
    UploadDictionaryCoding::Dcb => DictionaryCoding::Dcb,
    UploadDictionaryCoding::Dcz => DictionaryCoding::Dcz,
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::*;

  #[tokio::test]
  async fn host_upload_config_preserves_storage_reuse_and_fencing() {
    let root = tempfile::tempdir().expect("temp root");
    let store = config::UploadStoreConfig {
      name: "local".to_string(),
      kind: config::UploadStoreKind::Local,
      local: Some(config::LocalUploadStoreConfig {
        root: root.path().join("store"),
      }),
      postgres_s3: None,
    };
    let profile: config::UploadProfileConfig = toml::from_str(
      r#"
name = "profile"
store = "local"
public_base_url = "https://uploads.example.test"
staging_dir = "/tmp"
max_staging_bytes = 64
control_path_prefix = "/uploads"
object_path_prefix = "/objects"
destination = {kind = "object"}
identity = {kind = "ipm", source = "test"}
max_upload_bytes = 64
max_part_bytes = 32
max_storage_bytes = 128
max_sessions = 8
max_parts = 8
inspection_bytes = 32
ttl_seconds = 60
object_ttl_seconds = 60
max_concurrent_uploads = 4
max_concurrent_parts = 4
"#,
    )
    .expect("host profile");
    let converted_store = store_config(&store);
    let converted_profile = profile_config(&profile);
    assert_eq!(
      serde_json::to_value(&store).expect("host store"),
      serde_json::to_value(&converted_store).expect("storage store")
    );
    assert_eq!(
      serde_json::to_value(&profile).expect("host profile"),
      serde_json::to_value(&converted_profile).expect("storage profile")
    );
    let options = UploadOptions {
      upload_stores: vec![converted_store],
      upload_profiles: vec![converted_profile],
    };
    let first = UploadRuntime::new(&options, None)
      .await
      .expect("first snapshot");
    let same = UploadRuntime::new(&options, Some(&first))
      .await
      .expect("unchanged snapshot");
    assert!(Arc::ptr_eq(
      first.profile("profile").expect("first profile").store(),
      same.profile("profile").expect("same profile").store(),
    ));
    let mut changed = options.clone();
    changed.upload_stores[0].name = "renamed".to_string();
    changed.upload_profiles[0].store = "renamed".to_string();
    assert!(UploadRuntime::new(&changed, Some(&first)).await.is_err());
  }

  #[test]
  fn dictionary_hash_retains_journal_byte_array_shape() {
    let bytes = [7_u8; 32];
    let old =
      crate::compression_dictionary::fields::DictionaryHash::from_slice(&bytes).expect("host hash");
    let new = UploadDictionaryHash::from(bytes);
    assert_eq!(
      serde_json::to_value(old).expect("host hash JSON"),
      serde_json::to_value(new).expect("storage hash JSON"),
    );
    let encoded = serde_json::to_string(&new).expect("stored hash JSON");
    assert_eq!(
      serde_json::from_str::<UploadDictionaryHash>(&encoded)
        .expect("reloaded storage hash")
        .as_bytes(),
      &bytes,
    );
  }
}

use super::DictionaryValidationGuard;
use crate::config::{
  LocalUploadStoreConfig, UploadDestinationConfig, UploadProfileConfig, UploadStoreConfig,
  UploadStoreKind,
};
use crate::uploads::{
  InspectedPart, UploadByteStream, UploadCreate, UploadDictionaryCoding, UploadDictionaryPin,
  UploadOwner, UploadState, UploadStore,
};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::sync::Arc;

struct Fixture {
  _root: tempfile::TempDir,
  store: Arc<UploadStore>,
  config: UploadStoreConfig,
  owner: UploadOwner,
  binding: serde_json::Value,
  id: String,
}

fn body(bytes: &'static [u8]) -> UploadByteStream {
  Box::pin(futures_util::stream::once(async move {
    Ok(Bytes::from_static(bytes))
  }))
}

async fn fixture(destination: UploadDestinationConfig, claim: bool) -> Fixture {
  let root = tempfile::tempdir().unwrap();
  let config = UploadStoreConfig {
    name: "local".into(),
    kind: UploadStoreKind::Local,
    local: Some(LocalUploadStoreConfig {
      root: root.path().join("store"),
    }),
    postgres_s3: None,
  };
  let store = UploadStore::open(&config).await.unwrap();
  let mut profile: UploadProfileConfig = toml::from_str(
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
  .unwrap();
  profile.destination = destination;
  let owner = UploadOwner {
    kind: crate::config::UploadIdentityKind::Ipm,
    source: "test".into(),
    subject: "alice".into(),
  };
  let binding = serde_json::json!({"route":"upload"});
  let upload = store
    .create(UploadCreate {
      profile,
      owner: owner.clone(),
      binding: binding.clone(),
      method: http::Method::POST,
      uri: http::Uri::from_static("/target"),
      safe_headers: serde_json::json!({}),
      declared_total: Some(4),
      dictionary: Some(UploadDictionaryPin {
        coding: UploadDictionaryCoding::Dcz,
        profile: "decode".into(),
        dictionary: "public".into(),
        hash: crate::compression_dictionary::fields::DictionaryHash::from_slice(&[7; 32]).unwrap(),
      }),
    })
    .await
    .unwrap();
  let reservation = store
    .begin_append(&upload.id, &owner, &binding, 0, 4)
    .await
    .unwrap();
  store
    .commit_fully_inspected_part(
      &reservation,
      &InspectedPart {
        bytes: 4,
        sha256: super::hex_digest(&Sha256::digest(b"wire")),
      },
      body(b"wire"),
    )
    .await
    .unwrap();
  if claim {
    store
      .claim_complete(&upload.id, &owner, &binding, 4)
      .await
      .unwrap();
  }
  Fixture {
    _root: root,
    store,
    config,
    owner,
    binding,
    id: upload.id,
  }
}

fn guard(fixture: &Fixture) -> DictionaryValidationGuard {
  DictionaryValidationGuard {
    store: fixture.store.clone(),
    id: fixture.id.clone(),
    owner: fixture.owner.clone(),
    binding: fixture.binding.clone(),
    armed: true,
  }
}

async fn wait_failed(fixture: &Fixture) {
  tokio::time::timeout(std::time::Duration::from_secs(5), async {
    loop {
      if fixture
        .store
        .lookup(&fixture.id, &fixture.owner, &fixture.binding)
        .await
        .unwrap()
        .state
        == UploadState::ValidationFailed
      {
        break;
      }
      tokio::task::yield_now().await;
    }
  })
  .await
  .unwrap();
}

#[tokio::test]
async fn cancelled_dictionary_validation_is_terminal() {
  let fixture = fixture(UploadDestinationConfig::Object, true).await;
  let guard = guard(&fixture);
  let (ready, started) = tokio::sync::oneshot::channel();
  let task = tokio::spawn(async move {
    let _guard = guard;
    ready.send(()).unwrap();
    std::future::pending::<()>().await;
  });
  started.await.unwrap();
  task.abort();
  assert!(task.await.unwrap_err().is_cancelled());
  wait_failed(&fixture).await;
  assert!(
    fixture
      .store
      .claim_complete(&fixture.id, &fixture.owner, &fixture.binding, 4)
      .await
      .is_err()
  );
}

#[tokio::test]
async fn cancellation_fences_a_decoded_publication_already_writing() {
  let fixture = fixture(UploadDestinationConfig::Object, true).await;
  let guard = guard(&fixture);
  let (started, ready) = tokio::sync::oneshot::channel();
  let (release, released) = tokio::sync::oneshot::channel();
  let stream: UploadByteStream = Box::pin(futures_util::stream::once(async move {
    started.send(()).unwrap();
    released.await.unwrap();
    Ok(Bytes::from_static(b"plain"))
  }));
  let (store, id, owner, binding) = (
    fixture.store.clone(),
    fixture.id.clone(),
    fixture.owner.clone(),
    fixture.binding.clone(),
  );
  let publish = tokio::spawn(async move {
    store
      .publish_decoded_object(
        &id,
        &owner,
        &binding,
        5,
        &super::hex_digest(&Sha256::digest(b"plain")),
        stream,
      )
      .await
  });
  ready.await.unwrap(); // Publication has captured its epoch and opened its temporary file.
  drop(guard);
  wait_failed(&fixture).await;
  release.send(()).unwrap();
  assert!(publish.await.unwrap().is_err());
  assert!(
    fixture
      .store
      .read_object(&fixture.id, &fixture.owner, &fixture.binding)
      .await
      .is_err()
  );
}

#[tokio::test]
async fn completed_validation_guard_preserves_ready_object_and_dispatch_claim() {
  let fixture = fixture(
    UploadDestinationConfig::Upstream {
      upstream: "origin".into(),
    },
    true,
  )
  .await;
  let mut guard = guard(&fixture);
  let ready = fixture
    .store
    .publish_decoded_object(
      &fixture.id,
      &fixture.owner,
      &fixture.binding,
      5,
      &super::hex_digest(&Sha256::digest(b"plain")),
      body(b"plain"),
    )
    .await
    .unwrap();
  assert_eq!(ready.state, UploadState::Ready);
  guard.armed = false;
  drop(guard);
  let mut stream = fixture
    .store
    .read_object(&fixture.id, &fixture.owner, &fixture.binding)
    .await
    .unwrap();
  use futures_util::StreamExt;
  assert_eq!(
    stream.next().await.unwrap().unwrap(),
    Bytes::from_static(b"plain")
  );
  assert!(stream.next().await.is_none());
  assert!(
    fixture
      .store
      .claim_complete(&fixture.id, &fixture.owner, &fixture.binding, 4)
      .await
      .is_err()
  );
  assert!(
    fixture
      .store
      .begin_dispatch(&fixture.id, &fixture.owner, &fixture.binding)
      .await
      .is_ok()
  );
}

#[tokio::test]
async fn revoked_pin_can_fail_an_active_session_without_claiming_it() {
  let fixture = fixture(UploadDestinationConfig::Object, false).await;
  assert_eq!(
    fixture
      .store
      .fail_validation(&fixture.id, &fixture.owner, &fixture.binding)
      .await
      .unwrap()
      .state,
    UploadState::ValidationFailed
  );
  assert!(
    fixture
      .store
      .claim_complete(&fixture.id, &fixture.owner, &fixture.binding, 4)
      .await
      .is_err()
  );
}

#[tokio::test]
async fn restart_terminalizes_an_abandoned_dictionary_validation() {
  let fixture = fixture(UploadDestinationConfig::Object, true).await;
  let Fixture {
    _root,
    store,
    config,
    owner,
    binding,
    id,
  } = fixture;
  drop(store);
  let reopened = UploadStore::open(&config).await.unwrap();
  assert_eq!(
    reopened.lookup(&id, &owner, &binding).await.unwrap().state,
    UploadState::ValidationFailed
  );
  assert!(
    reopened
      .claim_complete(&id, &owner, &binding, 4)
      .await
      .is_err()
  );
}

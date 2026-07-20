use std::collections::BTreeMap;
use std::fs;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use clap::Parser;
use oxibelt::admin_audit::anchor::{
  AUDIT_CHECKPOINT_FORMAT_VERSION, AUDIT_CHECKPOINT_GENESIS_DIGEST,
  AUDIT_CHECKPOINT_SIGNING_ALGORITHM, AuditCheckpointBodyV1, assemble_signed_checkpoint,
  checkpoint_signing_transcript,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::audit_verify::{
  AuditWitness, ExpectedSigningKeyRange, ExpectedStream, ExpectedStreamEpoch,
  ExpectedStreamsManifest, TrustedHmacKey, TrustedKey, VerificationStatus, WitnessHead,
  load_manifest_for_test, load_trusted_hmac_keys_for_test, load_trusted_keys_for_test,
  load_witness_for_test, new_witness,
};
use crate::audit_verify_evidence::{
  AuthorityHead, LocalAuditRow, StreamEvidence, VerificationEvidence,
  calculate_event_hash_for_test, verify_evidence,
};
use crate::cli::{AdminAuditSubcommand, Cli, Command};

const CHAIN_ID: &str = "00112233445566778899aabbccddeeff";
const STREAM_ID: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_ID: &str = "audit-2026-07";
const ROTATED_KEY_ID: &str = "audit-2026-08";
const HISTORICAL_MEMBERSHIP_EPOCH: &str = "membership-7";
const HISTORICAL_DEPLOYMENT_EPOCH: &str = "deployment-9";
const CURRENT_MEMBERSHIP_EPOCH: &str = "membership-8";
const CURRENT_DEPLOYMENT_EPOCH: &str = "deployment-10";

#[path = "audit_verify_tests/cli_tests.rs"]
mod cli_tests;
#[path = "audit_verify_tests/evidence_tests.rs"]
mod evidence_tests;

#[test]
fn expected_stream_manifest_rejects_duplicate_streams() {
  let file = tempfile::NamedTempFile::new().expect("manifest file");
  fs::write(
    file.path(),
    serde_json::to_vec(&json!({
      "schema_version": "oxibelt.admin.audit.expected-streams/v1",
      "namespace": "oxibelt",
      "streams": [
        expected_stream_json("edge-0"),
        expected_stream_json("edge-1"),
      ],
    }))
    .expect("manifest JSON"),
  )
  .expect("write manifest");
  let error = load_manifest_for_test(file.path()).expect_err("duplicate stream must fail");
  assert!(error.to_string().contains("duplicate stream ID"));
}

#[test]
fn expected_stream_manifest_accepts_ordered_epoch_history() {
  let file = tempfile::NamedTempFile::new().expect("manifest file");
  let mut stream = expected_stream_json("edge-0");
  stream["accepted_epoch_history"] = json!([
    {
      "membership_epoch": "membership-6",
      "deployment_epoch": "deployment-8",
    },
    {
      "membership_epoch": HISTORICAL_MEMBERSHIP_EPOCH,
      "deployment_epoch": HISTORICAL_DEPLOYMENT_EPOCH,
    },
  ]);
  stream["membership_epoch"] = json!(CURRENT_MEMBERSHIP_EPOCH);
  stream["deployment_epoch"] = json!(CURRENT_DEPLOYMENT_EPOCH);
  fs::write(
    file.path(),
    serde_json::to_vec(&json!({
      "schema_version": "oxibelt.admin.audit.expected-streams/v1",
      "namespace": "oxibelt",
      "streams": [stream],
    }))
    .expect("manifest JSON"),
  )
  .expect("write manifest");

  let manifest = load_manifest_for_test(file.path()).expect("epoch history is valid");
  let stream = &manifest.streams[0];
  assert_eq!(
    stream.epoch_position(HISTORICAL_MEMBERSHIP_EPOCH, HISTORICAL_DEPLOYMENT_EPOCH),
    Some(1)
  );
  assert_eq!(
    stream.epoch_position(CURRENT_MEMBERSHIP_EPOCH, CURRENT_DEPLOYMENT_EPOCH),
    Some(2)
  );
  assert_eq!(
    stream.epoch_position("membership-unknown", "deployment-unknown"),
    None
  );
}

#[test]
fn expected_stream_manifest_rejects_current_epoch_in_history() {
  let file = tempfile::NamedTempFile::new().expect("manifest file");
  let mut stream = expected_stream_json("edge-0");
  stream["accepted_epoch_history"] = json!([{
    "membership_epoch": HISTORICAL_MEMBERSHIP_EPOCH,
    "deployment_epoch": HISTORICAL_DEPLOYMENT_EPOCH,
  }]);
  fs::write(
    file.path(),
    serde_json::to_vec(&json!({
      "schema_version": "oxibelt.admin.audit.expected-streams/v1",
      "namespace": "oxibelt",
      "streams": [stream],
    }))
    .expect("manifest JSON"),
  )
  .expect("write manifest");

  let error = load_manifest_for_test(file.path()).expect_err("current epoch must remain unique");
  assert!(error.to_string().contains("current epoch duplicates"));
}

#[test]
fn trusted_keys_require_unique_raw_ed25519_public_keys() {
  let key = tempfile::NamedTempFile::new().expect("public key file");
  fs::write(key.path(), [7_u8; 32]).expect("write public key");
  let value = format!("{KEY_ID}={}", key.path().display());
  let keys = load_trusted_keys_for_test(std::slice::from_ref(&value)).expect("trusted key");
  assert_eq!(keys[KEY_ID].public_key, [7_u8; 32]);
  let error =
    load_trusted_keys_for_test(&[value.clone(), value]).expect_err("duplicate key ID must fail");
  assert!(error.to_string().contains("duplicated"));
}

#[test]
#[cfg(unix)]
fn trusted_hmac_keys_require_owner_only_raw_32_byte_files() {
  use std::os::unix::fs::PermissionsExt as _;

  let directory = tempfile::tempdir().expect("HMAC key directory");
  let path = directory.path().join("audit-hmac.key");
  fs::write(&path, [9_u8; 32]).expect("write HMAC key");
  fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("protect HMAC key");
  let value = format!("local-hmac={}", path.display());
  let keys = load_trusted_hmac_keys_for_test(std::slice::from_ref(&value)).expect("trusted HMAC");
  assert_eq!(&*keys["local-hmac"].key, &[9_u8; 32]);

  fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("weaken permissions");
  let error = match load_trusted_hmac_keys_for_test(&[value]) {
    Ok(_) => panic!("group-readable HMAC key must fail"),
    Err(error) => error,
  };
  assert!(error.to_string().contains("group or other"));
}

#[test]
fn explicit_witness_initialization_refuses_an_existing_witness() {
  let directory = tempfile::tempdir().expect("witness directory");
  let witness_path = directory.path().join("witness.json");
  let manifest = manifest();
  fs::write(
    &witness_path,
    serde_json::to_vec(&new_witness("oxibelt".to_string(), BTreeMap::new())).expect("witness JSON"),
  )
  .expect("write witness");
  let error = load_witness_for_test(&witness_path, &manifest, true)
    .expect_err("existing witness must not be replaced");
  assert!(error.to_string().contains("refuses to replace"));
}

struct Fixture {
  manifest: ExpectedStreamsManifest,
  trusted_keys: BTreeMap<String, TrustedKey>,
  trusted_hmac_keys: BTreeMap<String, TrustedHmacKey>,
  witness: AuditWitness,
  evidence: VerificationEvidence,
}

fn fixture(tamper: bool, add_unanchored_suffix: bool) -> Fixture {
  let key_pair = Ed25519KeyPair::generate().expect("generate key");
  let mut first = event(0, &"0".repeat(64));
  let first_hash = calculate_event_hash_for_test(&first).expect("first event hash");
  first["integrity"]["event_hash"] = Value::String(first_hash.clone());
  let mut rows = vec![LocalAuditRow {
    id: 1,
    payload: Some(first.clone()),
  }];
  if add_unanchored_suffix {
    let mut second = event(1, &first_hash);
    let second_hash = calculate_event_hash_for_test(&second).expect("second event hash");
    second["integrity"]["event_hash"] = Value::String(second_hash);
    rows.push(LocalAuditRow {
      id: 2,
      payload: Some(second),
    });
  }
  if tamper {
    rows[0].payload.as_mut().expect("payload")["operation"] = json!("forged");
  }
  let body = AuditCheckpointBodyV1 {
    format_version: AUDIT_CHECKPOINT_FORMAT_VERSION.to_string(),
    namespace: "oxibelt".to_string(),
    stream_id: STREAM_ID.to_string(),
    instance_id: "edge-0".to_string(),
    cluster_id: Some("edge".to_string()),
    membership_epoch: "membership-7".to_string(),
    deployment_epoch: "deployment-9".to_string(),
    checkpoint_ordinal: 1,
    chain_id: CHAIN_ID.to_string(),
    first_sequence: 0,
    last_sequence: 0,
    chain_head: format!("sha256:{first_hash}"),
    previous_checkpoint_digest: AUDIT_CHECKPOINT_GENESIS_DIGEST.to_string(),
    wall_timestamp: "2026-07-19T00:00:00.000Z".to_string(),
    source_database_timestamp: "2026-07-19 00:00:00+00".to_string(),
    signing_key_id: KEY_ID.to_string(),
    signing_algorithm: AUDIT_CHECKPOINT_SIGNING_ALGORITHM.to_string(),
  };
  let transcript = checkpoint_signing_transcript(&body).expect("checkpoint transcript");
  let checkpoint = assemble_signed_checkpoint(body, key_pair.sign(&transcript).as_ref())
    .expect("signed checkpoint");
  let head = WitnessHead {
    checkpoint_ordinal: 1,
    checkpoint_digest: checkpoint.checkpoint_digest.clone(),
  };
  let evidence = VerificationEvidence {
    streams: vec![StreamEvidence {
      expected: manifest().streams[0].clone(),
      local_rows: rows,
      checkpoints: vec![serde_json::to_value(&checkpoint).expect("checkpoint JSON")],
      authority_head: Some(AuthorityHead {
        checkpoint_ordinal: 1,
        checkpoint_digest: checkpoint.checkpoint_digest.clone(),
      }),
    }],
  };
  Fixture {
    manifest: manifest(),
    trusted_keys: BTreeMap::from([(
      KEY_ID.to_string(),
      TrustedKey {
        key_id: KEY_ID.to_string(),
        public_key: key_pair.public_key().as_ref().to_vec(),
      },
    )]),
    trusted_hmac_keys: BTreeMap::new(),
    witness: new_witness(
      "oxibelt".to_string(),
      BTreeMap::from([(STREAM_ID.to_string(), head)]),
    ),
    evidence,
  }
}

fn single_event_fixture(mut first: Value) -> Fixture {
  let key_pair = Ed25519KeyPair::generate().expect("generate key");
  let first_hash = calculate_event_hash_for_test(&first).expect("first event hash");
  first["integrity"]["event_hash"] = Value::String(first_hash.clone());
  let body = checkpoint_body(
    1,
    0,
    &first_hash,
    AUDIT_CHECKPOINT_GENESIS_DIGEST,
    KEY_ID,
    (HISTORICAL_MEMBERSHIP_EPOCH, HISTORICAL_DEPLOYMENT_EPOCH),
  );
  let checkpoint = sign_checkpoint(body, &key_pair);
  Fixture {
    manifest: manifest(),
    trusted_keys: BTreeMap::from([(
      KEY_ID.to_string(),
      TrustedKey {
        key_id: KEY_ID.to_string(),
        public_key: key_pair.public_key().as_ref().to_vec(),
      },
    )]),
    trusted_hmac_keys: BTreeMap::new(),
    witness: new_witness(
      "oxibelt".to_string(),
      BTreeMap::from([(
        STREAM_ID.to_string(),
        WitnessHead {
          checkpoint_ordinal: 1,
          checkpoint_digest: checkpoint.checkpoint_digest.clone(),
        },
      )]),
    ),
    evidence: VerificationEvidence {
      streams: vec![StreamEvidence {
        expected: manifest().streams[0].clone(),
        local_rows: vec![LocalAuditRow {
          id: 1,
          payload: Some(first),
        }],
        checkpoints: vec![serde_json::to_value(&checkpoint).expect("checkpoint JSON")],
        authority_head: Some(AuthorityHead {
          checkpoint_ordinal: 1,
          checkpoint_digest: checkpoint.checkpoint_digest,
        }),
      }],
    },
  }
}

fn hmac_fixture(include_key: bool) -> Fixture {
  const HMAC_KEY_ID: &str = "local-audit-hmac-2026-07";
  let key = vec![9_u8; 32];
  let mut first = event(0, &"0".repeat(64));
  first["integrity"]["algorithm"] = json!("hmac_sha256");
  first["integrity"]["key_id"] = json!(HMAC_KEY_ID);
  first["integrity"]["tag"] = json!("0".repeat(64));
  let event_hash = calculate_event_hash_for_test(&first).expect("HMAC event hash");
  let event_hash = decode_test_hex(&event_hash);
  let signing_key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &key);
  first["integrity"]["tag"] = json!(encode_test_hex(
    aws_lc_rs::hmac::sign(&signing_key, &event_hash).as_ref()
  ));
  let mut fixture = single_event_fixture(first);
  if include_key {
    fixture.trusted_hmac_keys.insert(
      HMAC_KEY_ID.to_string(),
      TrustedHmacKey {
        key_id: HMAC_KEY_ID.to_string(),
        key: Zeroizing::new(key),
      },
    );
  }
  fixture
}

fn three_checkpoint_key_rollback_fixture() -> Fixture {
  let first_key = Ed25519KeyPair::generate().expect("generate first key");
  let second_key = Ed25519KeyPair::generate().expect("generate second key");
  let mut rows = Vec::new();
  let mut checkpoints = Vec::new();
  let mut previous_event_hash = "0".repeat(64);
  let mut previous_checkpoint_digest = AUDIT_CHECKPOINT_GENESIS_DIGEST.to_string();
  for (sequence, (key_id, key_pair)) in [
    (KEY_ID, &first_key),
    (ROTATED_KEY_ID, &second_key),
    (KEY_ID, &first_key),
  ]
  .into_iter()
  .enumerate()
  {
    let sequence = u64::try_from(sequence).expect("small test sequence");
    let mut local_event = event(sequence, &previous_event_hash);
    let event_hash = calculate_event_hash_for_test(&local_event).expect("event hash");
    local_event["integrity"]["event_hash"] = Value::String(event_hash.clone());
    rows.push(LocalAuditRow {
      id: i64::try_from(sequence + 1).expect("small row ID"),
      payload: Some(local_event),
    });
    let checkpoint = sign_checkpoint(
      checkpoint_body(
        sequence + 1,
        sequence,
        &event_hash,
        &previous_checkpoint_digest,
        key_id,
        (HISTORICAL_MEMBERSHIP_EPOCH, HISTORICAL_DEPLOYMENT_EPOCH),
      ),
      key_pair,
    );
    previous_event_hash = event_hash;
    previous_checkpoint_digest = checkpoint.checkpoint_digest.clone();
    checkpoints.push(checkpoint);
  }
  let last = checkpoints.last().expect("checkpoint head");
  let witness = new_witness(
    "oxibelt".to_string(),
    BTreeMap::from([(
      STREAM_ID.to_string(),
      WitnessHead {
        checkpoint_ordinal: 1,
        checkpoint_digest: checkpoints[0].checkpoint_digest.clone(),
      },
    )]),
  );
  let authority_head = Some(AuthorityHead {
    checkpoint_ordinal: last.body.checkpoint_ordinal,
    checkpoint_digest: last.checkpoint_digest.clone(),
  });
  Fixture {
    manifest: rotated_key_manifest(false),
    trusted_keys: BTreeMap::from([
      (
        KEY_ID.to_string(),
        TrustedKey {
          key_id: KEY_ID.to_string(),
          public_key: first_key.public_key().as_ref().to_vec(),
        },
      ),
      (
        ROTATED_KEY_ID.to_string(),
        TrustedKey {
          key_id: ROTATED_KEY_ID.to_string(),
          public_key: second_key.public_key().as_ref().to_vec(),
        },
      ),
    ]),
    trusted_hmac_keys: BTreeMap::new(),
    witness,
    evidence: VerificationEvidence {
      streams: vec![StreamEvidence {
        expected: rotated_key_manifest(false).streams[0].clone(),
        local_rows: rows,
        checkpoints: checkpoints
          .into_iter()
          .map(|checkpoint| serde_json::to_value(checkpoint).expect("checkpoint JSON"))
          .collect(),
        authority_head,
      }],
    },
  }
}

fn two_checkpoint_fixture(rotate_key: bool, rollout_epochs: bool) -> Fixture {
  if rotate_key {
    two_checkpoint_fixture_with_epochs(
      true,
      rotated_key_manifest(rollout_epochs),
      (HISTORICAL_MEMBERSHIP_EPOCH, HISTORICAL_DEPLOYMENT_EPOCH),
      if rollout_epochs {
        (CURRENT_MEMBERSHIP_EPOCH, CURRENT_DEPLOYMENT_EPOCH)
      } else {
        (HISTORICAL_MEMBERSHIP_EPOCH, HISTORICAL_DEPLOYMENT_EPOCH)
      },
    )
  } else if rollout_epochs {
    two_checkpoint_fixture_with_epochs(
      rotate_key,
      rollout_manifest(),
      (HISTORICAL_MEMBERSHIP_EPOCH, HISTORICAL_DEPLOYMENT_EPOCH),
      (CURRENT_MEMBERSHIP_EPOCH, CURRENT_DEPLOYMENT_EPOCH),
    )
  } else {
    two_checkpoint_fixture_with_epochs(
      rotate_key,
      manifest(),
      (HISTORICAL_MEMBERSHIP_EPOCH, HISTORICAL_DEPLOYMENT_EPOCH),
      (HISTORICAL_MEMBERSHIP_EPOCH, HISTORICAL_DEPLOYMENT_EPOCH),
    )
  }
}

fn two_checkpoint_fixture_with_epochs(
  rotate_key: bool,
  manifest: ExpectedStreamsManifest,
  first_epoch: (&str, &str),
  second_epoch: (&str, &str),
) -> Fixture {
  let first_key = Ed25519KeyPair::generate().expect("generate first key");
  let rotated_key = rotate_key.then(|| Ed25519KeyPair::generate().expect("generate rotated key"));

  let mut first = event(0, &"0".repeat(64));
  let first_hash = calculate_event_hash_for_test(&first).expect("first event hash");
  first["integrity"]["event_hash"] = Value::String(first_hash.clone());
  let mut second = event(1, &first_hash);
  let second_hash = calculate_event_hash_for_test(&second).expect("second event hash");
  second["integrity"]["event_hash"] = Value::String(second_hash.clone());

  let first_checkpoint = sign_checkpoint(
    checkpoint_body(
      1,
      0,
      &first_hash,
      AUDIT_CHECKPOINT_GENESIS_DIGEST,
      KEY_ID,
      first_epoch,
    ),
    &first_key,
  );
  let second_key_id = if rotate_key { ROTATED_KEY_ID } else { KEY_ID };
  let second_checkpoint = sign_checkpoint(
    checkpoint_body(
      2,
      1,
      &second_hash,
      &first_checkpoint.checkpoint_digest,
      second_key_id,
      second_epoch,
    ),
    rotated_key.as_ref().unwrap_or(&first_key),
  );

  let mut trusted_keys = BTreeMap::from([(
    KEY_ID.to_string(),
    TrustedKey {
      key_id: KEY_ID.to_string(),
      public_key: first_key.public_key().as_ref().to_vec(),
    },
  )]);
  if let Some(rotated_key) = rotated_key {
    trusted_keys.insert(
      ROTATED_KEY_ID.to_string(),
      TrustedKey {
        key_id: ROTATED_KEY_ID.to_string(),
        public_key: rotated_key.public_key().as_ref().to_vec(),
      },
    );
  }

  let witness = new_witness(
    manifest.namespace.clone(),
    BTreeMap::from([(
      STREAM_ID.to_string(),
      WitnessHead {
        checkpoint_ordinal: first_checkpoint.body.checkpoint_ordinal,
        checkpoint_digest: first_checkpoint.checkpoint_digest.clone(),
      },
    )]),
  );
  let evidence = VerificationEvidence {
    streams: vec![StreamEvidence {
      expected: manifest.streams[0].clone(),
      local_rows: vec![
        LocalAuditRow {
          id: 1,
          payload: Some(first),
        },
        LocalAuditRow {
          id: 2,
          payload: Some(second),
        },
      ],
      checkpoints: vec![
        serde_json::to_value(&first_checkpoint).expect("first checkpoint JSON"),
        serde_json::to_value(&second_checkpoint).expect("second checkpoint JSON"),
      ],
      authority_head: Some(AuthorityHead {
        checkpoint_ordinal: second_checkpoint.body.checkpoint_ordinal,
        checkpoint_digest: second_checkpoint.checkpoint_digest.clone(),
      }),
    }],
  };
  Fixture {
    manifest,
    trusted_keys,
    trusted_hmac_keys: BTreeMap::new(),
    witness,
    evidence,
  }
}

fn checkpoint_body(
  checkpoint_ordinal: u64,
  sequence: u64,
  chain_head: &str,
  previous_checkpoint_digest: &str,
  signing_key_id: &str,
  epoch: (&str, &str),
) -> AuditCheckpointBodyV1 {
  AuditCheckpointBodyV1 {
    format_version: AUDIT_CHECKPOINT_FORMAT_VERSION.to_string(),
    namespace: "oxibelt".to_string(),
    stream_id: STREAM_ID.to_string(),
    instance_id: "edge-0".to_string(),
    cluster_id: Some("edge".to_string()),
    membership_epoch: epoch.0.to_string(),
    deployment_epoch: epoch.1.to_string(),
    checkpoint_ordinal,
    chain_id: CHAIN_ID.to_string(),
    first_sequence: sequence,
    last_sequence: sequence,
    chain_head: format!("sha256:{chain_head}"),
    previous_checkpoint_digest: previous_checkpoint_digest.to_string(),
    wall_timestamp: format!("2026-07-19T00:00:0{sequence}.000Z"),
    source_database_timestamp: format!("2026-07-19 00:00:0{sequence}+00"),
    signing_key_id: signing_key_id.to_string(),
    signing_algorithm: AUDIT_CHECKPOINT_SIGNING_ALGORITHM.to_string(),
  }
}

fn sign_checkpoint(
  body: AuditCheckpointBodyV1,
  key_pair: &Ed25519KeyPair,
) -> oxibelt::admin_audit::anchor::SignedAuditCheckpointV1 {
  let transcript = checkpoint_signing_transcript(&body).expect("checkpoint transcript");
  assemble_signed_checkpoint(body, key_pair.sign(&transcript).as_ref()).expect("signed checkpoint")
}

fn verify_fixture(fixture: Fixture) -> crate::audit_verify::VerificationReport {
  verify_evidence(
    &fixture.manifest,
    &fixture.trusted_keys,
    &fixture.trusted_hmac_keys,
    Some(&fixture.witness),
    fixture.evidence,
  )
  .expect("verification runs")
  .0
}

fn decode_test_hex(value: &str) -> Vec<u8> {
  value
    .as_bytes()
    .chunks_exact(2)
    .map(|pair| {
      let digit = |value: u8| match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("test hex must be lowercase"),
      };
      digit(pair[0]) << 4 | digit(pair[1])
    })
    .collect()
}

fn encode_test_hex(bytes: &[u8]) -> String {
  bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn manifest() -> ExpectedStreamsManifest {
  ExpectedStreamsManifest {
    schema_version: "oxibelt.admin.audit.expected-streams/v1".to_string(),
    namespace: "oxibelt".to_string(),
    streams: vec![ExpectedStream {
      stream_id: STREAM_ID.to_string(),
      instance_id: "edge-0".to_string(),
      cluster_id: Some("edge".to_string()),
      accepted_epoch_history: Vec::new(),
      membership_epoch: "membership-7".to_string(),
      deployment_epoch: "deployment-9".to_string(),
      signing_key_schedule: signing_key_schedule(false),
    }],
  }
}

fn rollout_manifest() -> ExpectedStreamsManifest {
  ExpectedStreamsManifest {
    schema_version: "oxibelt.admin.audit.expected-streams/v1".to_string(),
    namespace: "oxibelt".to_string(),
    streams: vec![ExpectedStream {
      stream_id: STREAM_ID.to_string(),
      instance_id: "edge-0".to_string(),
      cluster_id: Some("edge".to_string()),
      accepted_epoch_history: vec![ExpectedStreamEpoch {
        membership_epoch: HISTORICAL_MEMBERSHIP_EPOCH.to_string(),
        deployment_epoch: HISTORICAL_DEPLOYMENT_EPOCH.to_string(),
      }],
      membership_epoch: CURRENT_MEMBERSHIP_EPOCH.to_string(),
      deployment_epoch: CURRENT_DEPLOYMENT_EPOCH.to_string(),
      signing_key_schedule: signing_key_schedule(false),
    }],
  }
}

fn rotated_key_manifest(rollout_epochs: bool) -> ExpectedStreamsManifest {
  let mut manifest = if rollout_epochs {
    rollout_manifest()
  } else {
    manifest()
  };
  manifest.streams[0].signing_key_schedule = signing_key_schedule(true);
  manifest
}

fn signing_key_schedule(rotated: bool) -> Vec<ExpectedSigningKeyRange> {
  let mut schedule = vec![ExpectedSigningKeyRange {
    key_id: KEY_ID.to_string(),
    first_checkpoint_ordinal: 1,
    last_checkpoint_ordinal: rotated.then_some(1),
  }];
  if rotated {
    schedule.push(ExpectedSigningKeyRange {
      key_id: ROTATED_KEY_ID.to_string(),
      first_checkpoint_ordinal: 2,
      last_checkpoint_ordinal: None,
    });
  }
  schedule
}

fn expected_stream_json(instance_id: &str) -> Value {
  json!({
    "stream_id": STREAM_ID,
    "instance_id": instance_id,
    "cluster_id": "edge",
    "membership_epoch": "membership-7",
    "deployment_epoch": "deployment-9",
    "signing_key_schedule": [{
      "key_id": KEY_ID,
      "first_checkpoint_ordinal": 1
    }],
  })
}

fn event(sequence: u64, previous_hash: &str) -> Value {
  json!({
    "schema_version": "oxibelt.admin.audit/v1",
    "event_id": format!("event-{sequence}"),
    "instance_id": "edge-0",
    "operation": "post.config.load",
    "integrity": {
      "algorithm": "sha256",
      "chain_id": CHAIN_ID,
      "sequence": sequence,
      "previous_hash": previous_hash,
      "event_hash": "",
    },
  })
}

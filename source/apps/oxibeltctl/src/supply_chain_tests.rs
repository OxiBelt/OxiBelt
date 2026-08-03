use std::io::Write as _;
use std::path::PathBuf;

use flate2::{Compression, write::DeflateEncoder};
use serde_json::json;

use super::*;
use crate::cli::{SupplyChainReleaseChannel, SupplyChainRole};

const REVISION: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn args() -> SupplyChainAdmissionBundleArgs {
  SupplyChainAdmissionBundleArgs {
    repository: "ghcr.io/oxibelt/oxibelt-dataplane-strict".to_string(),
    role: SupplyChainRole::DataplaneStrict,
    digest: format!("sha256:{}", "a".repeat(64)),
    source_ref: "refs/tags/1.2.3".to_string(),
    source_revision: REVISION.to_string(),
    release_channel: SupplyChainReleaseChannel::Stable,
    independent_rebuild_run_id: 42,
    independent_rebuild_workflow_sha: "c".repeat(40),
    revocations: None,
    verification_time: None,
    max_evidence_age_seconds: 3600,
    expires_after_seconds: 1800,
    signing_key_file: PathBuf::from("key"),
    public_key_output: None,
    key_id: "test-key".to_string(),
    output: PathBuf::from("bundle.json"),
    force: false,
  }
}

#[test]
fn workflow_and_receipt_identity_are_exact() {
  let args = args();
  let run = GitHubWorkflowRun {
    id: 42,
    name: REBUILD_WORKFLOW_NAME.to_string(),
    path: REBUILD_WORKFLOW_PATH.to_string(),
    event: "workflow_run".to_string(),
    status: "completed".to_string(),
    conclusion: Some("success".to_string()),
    head_sha: "c".repeat(40),
    updated_at: "2026-08-01T00:00:00Z".to_string(),
    repository: GitHubRepository {
      full_name: SOURCE_REPOSITORY.to_string(),
    },
  };
  let now = parse_timestamp(&run.updated_at, "test timestamp").expect("timestamp") + 60;
  validate_workflow_run(&run, &args, now).expect("valid run");
  let receipt = json!({
    "schemaVersion": 1,
    "source": {"repository": SOURCE_REPOSITORY, "ref": args.source_ref, "revision": REVISION},
    "build": {"role": "dataplane-strict", "artifactArch": "amd64"},
    "workflow": {"repository": SOURCE_REPOSITORY, "path": REBUILD_WORKFLOW_PATH, "runId": 42}
  });
  validate_receipt_identity(&receipt, &args, 42, "amd64").expect("valid receipt");

  let mut manual = run;
  manual.event = "workflow_dispatch".to_string();
  assert!(validate_workflow_run(&manual, &args, now).is_err());
  let mut wrong_workflow_revision = manual;
  wrong_workflow_revision.event = "workflow_run".to_string();
  wrong_workflow_revision.head_sha = "d".repeat(40);
  assert!(validate_workflow_run(&wrong_workflow_revision, &args, now).is_err());
  let mut wrong = receipt;
  wrong["workflow"]["runId"] = json!(43);
  assert!(validate_receipt_identity(&wrong, &args, 42, "amd64").is_err());
}

#[test]
fn artifact_archive_requires_one_exact_bounded_receipt() {
  let name = "rebuild-receipt-dataplane-strict-amd64";
  for method in [0, 8] {
    let archive = test_zip(&format!("{name}.json"), br#"{"schemaVersion":1}"#, method);
    assert_eq!(
      extract_receipt(&archive, name).expect("receipt")["schemaVersion"],
      json!(1)
    );
    assert!(extract_receipt(&archive, "wrong-name").is_err());
  }
}

fn test_zip(name: &str, contents: &[u8], method: u16) -> Vec<u8> {
  let compressed = if method == 8 {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(contents).expect("compress test receipt");
    encoder.finish().expect("finish test receipt")
  } else {
    contents.to_vec()
  };
  let crc = crc32fast::hash(contents);
  let mut archive = Vec::new();
  archive.extend_from_slice(b"PK\x03\x04");
  push_u16(&mut archive, 20);
  push_u16(&mut archive, 0);
  push_u16(&mut archive, method);
  push_u16(&mut archive, 0);
  push_u16(&mut archive, 0);
  push_u32(&mut archive, crc);
  push_u32(
    &mut archive,
    u32::try_from(compressed.len()).expect("test compressed size"),
  );
  push_u32(
    &mut archive,
    u32::try_from(contents.len()).expect("test content size"),
  );
  push_u16(
    &mut archive,
    u16::try_from(name.len()).expect("test filename size"),
  );
  push_u16(&mut archive, 0);
  archive.extend_from_slice(name.as_bytes());
  archive.extend_from_slice(&compressed);
  let central_offset = u32::try_from(archive.len()).expect("test central offset");
  archive.extend_from_slice(b"PK\x01\x02");
  push_u16(&mut archive, 20);
  push_u16(&mut archive, 20);
  push_u16(&mut archive, 0);
  push_u16(&mut archive, method);
  push_u16(&mut archive, 0);
  push_u16(&mut archive, 0);
  push_u32(&mut archive, crc);
  push_u32(
    &mut archive,
    u32::try_from(compressed.len()).expect("test compressed size"),
  );
  push_u32(
    &mut archive,
    u32::try_from(contents.len()).expect("test content size"),
  );
  push_u16(
    &mut archive,
    u16::try_from(name.len()).expect("test filename size"),
  );
  push_u16(&mut archive, 0);
  push_u16(&mut archive, 0);
  push_u16(&mut archive, 0);
  push_u16(&mut archive, 0);
  push_u32(&mut archive, 0);
  push_u32(&mut archive, 0);
  archive.extend_from_slice(name.as_bytes());
  let central_size = u32::try_from(archive.len()).expect("test archive size") - central_offset;
  archive.extend_from_slice(b"PK\x05\x06");
  push_u16(&mut archive, 0);
  push_u16(&mut archive, 0);
  push_u16(&mut archive, 1);
  push_u16(&mut archive, 1);
  push_u32(&mut archive, central_size);
  push_u32(&mut archive, central_offset);
  push_u16(&mut archive, 0);
  archive
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
  output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
  output.extend_from_slice(&value.to_le_bytes());
}

#[tokio::test]
async fn github_stream_reader_stops_after_the_configured_limit() {
  let bytes = read_stream_bounded(Cursor::new(vec![0_u8; 18]), 16)
    .await
    .expect("bounded read");
  assert_eq!(bytes.len(), 17);
}

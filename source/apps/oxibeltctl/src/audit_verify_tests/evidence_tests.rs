use super::*;

#[test]
fn valid_local_chain_checkpoint_and_witness_verify() {
  let fixture = fixture(false, false);
  let (report, next_witness) = verify_evidence(
    &fixture.manifest,
    &fixture.trusted_keys,
    &fixture.trusted_hmac_keys,
    Some(&fixture.witness),
    fixture.evidence,
  )
  .expect("verification runs");
  assert_eq!(report.status, VerificationStatus::Valid);
  assert_eq!(report.events_verified, 1);
  assert_eq!(report.checkpoints_verified, 1);
  assert_eq!(report.streams_verified, 1);
  assert_eq!(next_witness.streams[STREAM_ID].checkpoint_ordinal, 1);
}

#[test]
fn fully_verified_manifest_stream_can_expand_an_existing_witness() {
  let fixture = fixture(false, false);
  let prior = new_witness("oxibelt".to_string(), BTreeMap::new());
  let (report, next_witness) = verify_evidence(
    &fixture.manifest,
    &fixture.trusted_keys,
    &fixture.trusted_hmac_keys,
    Some(&prior),
    fixture.evidence,
  )
  .expect("verification runs");

  assert_eq!(report.status, VerificationStatus::Valid);
  assert_eq!(next_witness.streams[STREAM_ID].checkpoint_ordinal, 1);
}

#[test]
fn local_event_forgery_is_invalid() {
  let fixture = fixture(true, false);
  let (report, _) = verify_evidence(
    &fixture.manifest,
    &fixture.trusted_keys,
    &fixture.trusted_hmac_keys,
    Some(&fixture.witness),
    fixture.evidence,
  )
  .expect("verification runs");
  assert_eq!(report.status, VerificationStatus::Invalid);
  assert!(report.findings.iter().any(|finding| {
    finding.code == "local_event_hash_mismatch"
      || finding.code == "checkpoint_local_evidence_mismatch"
  }));
}

#[test]
fn valid_hmac_local_chain_verifies_with_purpose_specific_key_material() {
  let fixture = hmac_fixture(true);

  let report = verify_fixture(fixture);
  assert_eq!(report.status, VerificationStatus::Valid);
}

#[test]
fn tampered_hmac_tag_is_invalid_with_trusted_hmac_key_material() {
  let mut fixture = hmac_fixture(true);

  fixture.evidence.streams[0].local_rows[0]
    .payload
    .as_mut()
    .expect("local event payload")["integrity"]["tag"] = json!("1".repeat(64));
  let report = verify_fixture(fixture);

  assert_eq!(report.status, VerificationStatus::Invalid);
  assert!(
    report
      .findings
      .iter()
      .any(|finding| finding.code == "local_event_hmac_invalid")
  );
}

#[test]
fn hmac_local_chain_without_historical_key_is_incomplete() {
  let fixture = hmac_fixture(false);

  let report = verify_fixture(fixture);
  assert_eq!(report.status, VerificationStatus::Incomplete);
  assert!(
    report
      .findings
      .iter()
      .any(|finding| finding.code == "local_hmac_integrity_key_unavailable")
  );
}

#[test]
fn unanchored_local_suffix_is_incomplete() {
  let fixture = fixture(false, true);
  let (report, _) = verify_evidence(
    &fixture.manifest,
    &fixture.trusted_keys,
    &fixture.trusted_hmac_keys,
    Some(&fixture.witness),
    fixture.evidence,
  )
  .expect("verification runs");
  assert_eq!(report.status, VerificationStatus::Incomplete);
  assert!(
    report
      .findings
      .iter()
      .any(|finding| finding.code == "local_events_not_externally_anchored")
  );
}

#[test]
fn prior_witness_detects_external_fork() {
  let mut fixture = fixture(false, false);
  fixture
    .witness
    .streams
    .get_mut(STREAM_ID)
    .expect("witness head")
    .checkpoint_digest = format!("sha256:{}", "f".repeat(64));
  let (report, _) = verify_evidence(
    &fixture.manifest,
    &fixture.trusted_keys,
    &fixture.trusted_hmac_keys,
    Some(&fixture.witness),
    fixture.evidence,
  )
  .expect("verification runs");
  assert_eq!(report.status, VerificationStatus::Invalid);
  assert!(
    report
      .findings
      .iter()
      .any(|finding| finding.code == "authority_rollback_or_fork_detected")
  );
}

#[test]
fn checkpoint_deletion_is_invalid() {
  let mut fixture = two_checkpoint_fixture(false, false);
  fixture.evidence.streams[0].checkpoints.remove(0);

  let report = verify_fixture(fixture);
  assert_eq!(report.status, VerificationStatus::Invalid);
  assert!(
    report
      .findings
      .iter()
      .any(|finding| finding.code == "checkpoint_continuity_invalid")
  );
}

#[test]
fn checkpoint_reordering_is_invalid() {
  let mut fixture = two_checkpoint_fixture(false, false);
  fixture.evidence.streams[0].checkpoints.swap(0, 1);

  let report = verify_fixture(fixture);
  assert_eq!(report.status, VerificationStatus::Invalid);
  assert!(
    report
      .findings
      .iter()
      .any(|finding| finding.code == "checkpoint_continuity_invalid")
  );
}

#[test]
fn forged_checkpoint_is_invalid() {
  let mut fixture = two_checkpoint_fixture(false, false);
  fixture.evidence.streams[0].checkpoints[1]["body"]["wall_timestamp"] =
    json!("2026-07-19T00:00:59.999Z");

  let report = verify_fixture(fixture);
  assert_eq!(report.status, VerificationStatus::Invalid);
  assert!(
    report
      .findings
      .iter()
      .any(|finding| finding.code == "checkpoint_signature_invalid")
  );
}

#[test]
fn signing_key_rotation_is_valid_when_both_keys_are_trusted() {
  let fixture = two_checkpoint_fixture(true, false);

  let report = verify_fixture(fixture);
  assert_eq!(report.status, VerificationStatus::Valid);
  assert_eq!(report.checkpoints_verified, 2);
}

#[test]
fn signing_key_rotation_requires_the_new_key_to_be_pinned() {
  let mut fixture = two_checkpoint_fixture(true, false);
  fixture.trusted_keys.remove(ROTATED_KEY_ID);

  let report = verify_fixture(fixture);
  assert_eq!(report.status, VerificationStatus::Invalid);
  assert!(
    report
      .findings
      .iter()
      .any(|finding| finding.code == "checkpoint_signing_key_untrusted")
  );
}

#[test]
fn signing_key_rotation_cannot_return_to_a_retired_key_id() {
  let fixture = three_checkpoint_key_rollback_fixture();

  let report = verify_fixture(fixture);
  assert_eq!(report.status, VerificationStatus::Invalid);
  assert!(
    report
      .findings
      .iter()
      .any(|finding| finding.code == "checkpoint_signing_key_out_of_policy")
  );
}

#[test]
fn local_tail_truncation_is_invalid() {
  let mut fixture = two_checkpoint_fixture(false, false);
  fixture.evidence.streams[0].local_rows.pop();

  let report = verify_fixture(fixture);
  assert_eq!(report.status, VerificationStatus::Invalid);
  assert!(
    report
      .findings
      .iter()
      .any(|finding| finding.code == "local_tail_truncation_detected")
  );
}

#[test]
fn cluster_checkpoint_continuity_spans_declared_rollout_epochs() {
  let fixture = two_checkpoint_fixture(false, true);

  let report = verify_fixture(fixture);
  assert_eq!(report.status, VerificationStatus::Valid);
  assert_eq!(report.checkpoints_verified, 2);
}

#[test]
fn cluster_checkpoint_epoch_rollback_is_invalid() {
  let fixture = two_checkpoint_fixture_with_epochs(
    false,
    rollout_manifest(),
    (CURRENT_MEMBERSHIP_EPOCH, CURRENT_DEPLOYMENT_EPOCH),
    (HISTORICAL_MEMBERSHIP_EPOCH, HISTORICAL_DEPLOYMENT_EPOCH),
  );

  let report = verify_fixture(fixture);
  assert_eq!(report.status, VerificationStatus::Invalid);
  assert!(
    report
      .findings
      .iter()
      .any(|finding| finding.code == "checkpoint_epoch_order_invalid")
  );
}

#[test]
fn undeclared_rollout_epoch_is_invalid() {
  let fixture = two_checkpoint_fixture_with_epochs(
    false,
    rollout_manifest(),
    (HISTORICAL_MEMBERSHIP_EPOCH, HISTORICAL_DEPLOYMENT_EPOCH),
    ("membership-attacker", "deployment-attacker"),
  );

  let report = verify_fixture(fixture);
  assert_eq!(report.status, VerificationStatus::Invalid);
  assert!(
    report
      .findings
      .iter()
      .any(|finding| finding.code == "checkpoint_epoch_unexpected")
  );
}

#[test]
fn declared_history_does_not_replace_the_required_current_epoch() {
  let mut fixture = two_checkpoint_fixture(false, true);
  let historical = fixture.evidence.streams[0].checkpoints.remove(0);
  let historical_digest = historical["checkpoint_digest"]
    .as_str()
    .expect("checkpoint digest")
    .to_string();
  fixture.evidence.streams[0].checkpoints = vec![historical];
  fixture.evidence.streams[0].authority_head = Some(AuthorityHead {
    checkpoint_ordinal: 1,
    checkpoint_digest: historical_digest,
  });

  let report = verify_fixture(fixture);
  assert_eq!(report.status, VerificationStatus::Incomplete);
  assert!(
    report
      .findings
      .iter()
      .any(|finding| finding.code == "checkpoint_current_epoch_missing")
  );
}

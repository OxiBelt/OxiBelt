use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use serde_json::{Value, json};

use super::*;

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const REVISION: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SOURCE_REF: &str = "refs/tags/1.2.3";
const TIMESTAMP: &str = "2026-08-01T00:00:00Z";

fn verification_time() -> u64 {
  u64::try_from(
    TIMESTAMP
      .parse::<Timestamp>()
      .expect("timestamp")
      .as_second(),
  )
  .expect("positive timestamp")
}

fn input() -> BundleVerificationInput {
  BundleVerificationInput {
    repository: "ghcr.io/oxibelt/oxibelt-dataplane-strict".to_string(),
    role: SupplyChainRole::DataplaneStrict,
    digest: DIGEST.to_string(),
    source_ref: SOURCE_REF.to_string(),
    source_revision: REVISION.to_string(),
    release_channel: SupplyChainReleaseChannel::Stable,
    verification_time: verification_time() + 60,
    max_evidence_age_seconds: 3600,
    expires_after_seconds: 1800,
    key_id: "deployment-admission-2026".to_string(),
  }
}

fn signer() -> String {
  format!("https://github.com/OxiBelt/OxiBelt/.github/workflows/release.yml@{SOURCE_REF}")
}

fn attestation(predicate_type: &str, predicate: Value) -> Value {
  json!([{
    "verificationResult": {
      "signature": {"certificate": {
        "subjectAlternativeName": signer(),
        "sourceRepositoryURI": "https://github.com/OxiBelt/OxiBelt",
        "sourceRepositoryRef": SOURCE_REF,
        "sourceRepositoryDigest": REVISION,
        "buildSignerDigest": REVISION,
        "runnerEnvironment": "github-hosted"
      }},
      "verifiedTimestamps": [{"timestamp": TIMESTAMP}],
      "statement": {
        "subject": [{"name": "ghcr.io/oxibelt/oxibelt-dataplane-strict", "digest": {"sha256": DIGEST.trim_start_matches("sha256:")}}],
        "predicateType": predicate_type,
        "predicate": predicate
      }
    }
  }])
}

fn provenance() -> Value {
  attestation(
    PROVENANCE_PREDICATE,
    json!({
      "buildDefinition": {
        "buildType": "https://actions.github.io/buildtypes/workflow/v1",
        "externalParameters": {"workflow": {
          "path": ".github/workflows/release.yml",
          "ref": SOURCE_REF,
          "repository": "https://github.com/OxiBelt/OxiBelt"
        }},
        "internalParameters": {"github": {"runner_environment": "github-hosted"}},
        "resolvedDependencies": [{
          "uri": format!("git+https://github.com/OxiBelt/OxiBelt@{SOURCE_REF}"),
          "digest": {"gitCommit": REVISION}
        }]
      },
      "runDetails": {"builder": {"id": signer()}}
    }),
  )
}

fn sbom() -> Value {
  attestation(
    SBOM_PREDICATE,
    json!({
      "bomFormat": "CycloneDX",
      "specVersion": "1.7",
      "metadata": {"component": {"properties": [
        {"name": "io.oxibelt.image.role", "value": "dataplane-strict"},
        {"name": "io.oxibelt.image.repository", "value": "ghcr.io/oxibelt/oxibelt-dataplane-strict"},
        {"name": "io.oxibelt.image.digest", "value": DIGEST},
        {"name": "io.oxibelt.release.revision", "value": REVISION},
        {"name": "io.oxibelt.release.ref", "value": SOURCE_REF}
      ]}}
    }),
  )
}

fn child_digest(character: char) -> String {
  format!("sha256:{}", character.to_string().repeat(64))
}

fn rebuild() -> Value {
  attestation(
    REBUILD_PREDICATE,
    json!({
      "schemaVersion": 1,
      "predicateType": REBUILD_PREDICATE,
      "kind": "index",
      "subject": {"name": "ghcr.io/oxibelt/oxibelt-dataplane-strict", "digest": DIGEST},
      "source": {"repository": "https://github.com/OxiBelt/OxiBelt", "ref": SOURCE_REF, "revision": REVISION},
      "output": {"children": [
        {"artifactArch": "amd64", "digest": child_digest('c'), "recipeSha256": child_digest('1')},
        {"artifactArch": "arm64", "digest": child_digest('d'), "recipeSha256": child_digest('2')},
        {"artifactArch": "riscv64", "digest": child_digest('e'), "recipeSha256": child_digest('3')}
      ]}
    }),
  )
}

fn receipts() -> IndependentRebuildVerificationInput {
  let receipts = [("amd64", 'c'), ("arm64", 'd'), ("riscv64", 'e')]
    .into_iter()
    .map(|(arch, character)| IndependentRebuildVerificationReceipt {
      artifact_arch: arch.to_string(),
      archive_sha256: child_digest('5'),
      receipt: json!({
        "schemaVersion": 1,
        "published": {"imageDigest": child_digest(character), "imageTarSha256": child_digest('4')},
        "rebuilt": {"imageDigest": child_digest(character), "imageTarSha256": child_digest('4')},
        "normalization": {"schemaVersion": 1, "ignored": []},
        "differences": [],
        "outcome": "exact",
        "guarantee": "exact"
      }),
    })
    .collect();
  IndependentRebuildVerificationInput {
    workflow_run_id: 42,
    workflow_path: ".github/workflows/verify-release-rebuild.yml".to_string(),
    workflow_sha: REVISION.to_string(),
    completed_at: verification_time(),
    receipts,
  }
}

fn empty_revocations() -> (RevocationSet, String) {
  let set = RevocationSet {
    schema_version: 1,
    revocations: Vec::new(),
  };
  let hash = sha256_value(&serde_json::to_value(&set).expect("revocations")).expect("hash");
  (set, hash)
}

fn valid_bundle() -> (AdmissionBundleEnvelope, Vec<u8>, RevocationSet) {
  let key = [7_u8; 32];
  let pair = Ed25519KeyPair::from_seed_unchecked(&key).expect("key");
  let (revocations, hash) = empty_revocations();
  let bundle = verify_and_sign_bundle(
    input(),
    BundleEvidenceInput {
      provenance: provenance(),
      sbom: sbom(),
      rebuild: rebuild(),
      independent_rebuild: receipts(),
    },
    &revocations,
    &hash,
    &key,
  )
  .expect("valid bundle");
  (bundle, pair.public_key().as_ref().to_vec(), revocations)
}

#[test]
fn exact_evidence_produces_a_deterministic_verifiable_bundle() {
  let (first, public_key, revocations) = valid_bundle();
  let (second, _, _) = valid_bundle();

  assert_eq!(
    serde_json::to_value(&first).expect("first"),
    serde_json::to_value(&second).expect("second")
  );
  assert_eq!(first.payload.artifact.digest, DIGEST);
  assert_eq!(first.payload.artifact.role, "dataplane-strict");
  assert_eq!(first.payload.independent_rebuild.receipts.len(), 3);
  verify_bundle(
    &first,
    &public_key,
    "deployment-admission-2026",
    &revocations,
    input().verification_time,
  )
  .expect("signature");
}

#[test]
fn wrong_identity_workflow_staleness_and_missing_rebuild_fail_closed() {
  let (revocations, hash) = empty_revocations();
  let key = [7_u8; 32];
  let mut cases = Vec::new();
  let mut wrong_digest = provenance();
  wrong_digest[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] =
    Value::String("f".repeat(64));
  cases.push((wrong_digest, input(), "no verified provenance"));
  let mut wrong_workflow = provenance();
  wrong_workflow[0]["verificationResult"]["signature"]["certificate"]["subjectAlternativeName"] =
    Value::String(format!("{}/extra", signer()));
  cases.push((wrong_workflow, input(), "no verified provenance"));
  let mut stale = input();
  stale.verification_time += 7200;
  cases.push((provenance(), stale, "stale"));

  for (provenance, input, expected) in cases {
    let error = verify_and_sign_bundle(
      input,
      BundleEvidenceInput {
        provenance,
        sbom: sbom(),
        rebuild: rebuild(),
        independent_rebuild: receipts(),
      },
      &revocations,
      &hash,
      &key,
    )
    .expect_err("invalid evidence must fail");
    assert!(error.to_string().contains(expected), "{error:#}");
  }

  let mut missing = receipts();
  missing.receipts.pop();
  let error = verify_and_sign_bundle(
    input(),
    BundleEvidenceInput {
      provenance: provenance(),
      sbom: sbom(),
      rebuild: rebuild(),
      independent_rebuild: missing,
    },
    &revocations,
    &hash,
    &key,
  )
  .expect_err("missing rebuild receipt");
  assert!(error.to_string().contains("exactly three"));
}

#[test]
fn revoked_replayed_or_tampered_bundles_fail_closed() {
  let (mut bundle, public_key, _) = valid_bundle();
  let revocations = RevocationSet {
    schema_version: 1,
    revocations: vec![RevocationEntry {
      repository: bundle.payload.artifact.repository.clone(),
      digest: bundle.payload.artifact.digest.clone(),
      effective_at: input().verification_time,
      reason: "withdrawn".to_string(),
    }],
  };
  let error = verify_bundle(
    &bundle,
    &public_key,
    "deployment-admission-2026",
    &revocations,
    input().verification_time,
  )
  .expect_err("revoked bundle");
  assert!(error.to_string().contains("revoked"));

  bundle.payload.artifact.digest = child_digest('f');
  let error = verify_bundle(
    &bundle,
    &public_key,
    "deployment-admission-2026",
    &RevocationSet {
      schema_version: 1,
      revocations: Vec::new(),
    },
    input().verification_time,
  )
  .expect_err("replayed or tampered bundle");
  assert!(
    error
      .to_string()
      .contains("image reference is inconsistent")
  );
}

#[test]
fn revocations_reject_non_official_repository_names() {
  let set = RevocationSet {
    schema_version: 1,
    revocations: vec![RevocationEntry {
      repository: "ghcr.io/oxibelt/oxibelt-dataplane-stric".to_string(),
      digest: child_digest('a'),
      effective_at: input().verification_time,
      reason: "withdrawn".to_string(),
    }],
  };
  let error = validate_revocations(&set).expect_err("repository typo must fail closed");
  assert!(error.to_string().contains("official OxiBelt repository"));
}

#[test]
fn release_channel_policy_rejects_mutable_or_cross_channel_refs() {
  let mut stable = input();
  stable.source_ref = "refs/heads/main".to_string();
  assert!(validate_input(&stable).is_err());
  stable.source_ref = "refs/tags/1.2.3-beta.1".to_string();
  assert!(validate_input(&stable).is_err());

  let mut beta = input();
  beta.release_channel = SupplyChainReleaseChannel::Beta;
  beta.source_ref = "refs/tags/1.2.3-beta.1".to_string();
  validate_input(&beta).expect("beta ref");
}

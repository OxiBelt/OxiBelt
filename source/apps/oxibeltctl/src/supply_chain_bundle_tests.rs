use aws_lc_rs::signature::Ed25519KeyPair;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::*;
use crate::supply_chain_workload_policy::{ContainerApproval, ContainerClass};

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
    workload_policy: AdmissionWorkloadPolicy::default(),
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

fn sbom_predicate() -> Value {
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
  })
}

fn sbom() -> Value {
  attestation(SBOM_PREDICATE, sbom_predicate())
}

fn child_digest(character: char) -> String {
  format!("sha256:{}", character.to_string().repeat(64))
}

fn rebuild_predicate() -> Value {
  let index_metadata = json!({
    "schemaVersion": 2,
    "role": "dataplane-strict",
    "image": "ghcr.io/oxibelt/oxibelt-dataplane-strict",
    "digest": DIGEST,
    "children": [
      {"artifactArch": "amd64", "digest": child_digest('c'), "os": "linux", "architecture": "amd64", "variant": null},
      {"artifactArch": "arm64", "digest": child_digest('d'), "os": "linux", "architecture": "arm64", "variant": null},
      {"artifactArch": "riscv64", "digest": child_digest('e'), "os": "linux", "architecture": "riscv64", "variant": null}
    ]
  });
  json!({
    "schemaVersion": 1,
    "predicateType": REBUILD_PREDICATE,
    "kind": "index",
    "subject": {"name": "ghcr.io/oxibelt/oxibelt-dataplane-strict", "digest": DIGEST},
    "source": {"repository": "https://github.com/OxiBelt/OxiBelt", "ref": SOURCE_REF, "revision": REVISION},
    "output": {
      "indexMetadataSha256": sha256_value(&index_metadata).expect("index metadata hash"),
      "indexMetadata": index_metadata,
      "children": [
        {"artifactArch": "amd64", "digest": child_digest('c'), "recipeSha256": child_digest('1')},
        {"artifactArch": "arm64", "digest": child_digest('d'), "recipeSha256": child_digest('2')},
        {"artifactArch": "riscv64", "digest": child_digest('e'), "recipeSha256": child_digest('3')}
      ],
      "sbomSha256": sha256_value(&sbom_predicate()).expect("SBOM predicate hash")
    }
  })
}

fn rebuild() -> Value {
  attestation(REBUILD_PREDICATE, rebuild_predicate())
}

fn receipts() -> IndependentRebuildVerificationInput {
  let receipts = [
    ("amd64", 'c', '1'),
    ("arm64", 'd', '2'),
    ("riscv64", 'e', '3'),
  ]
    .into_iter()
    .map(
      |(arch, digest_character, recipe_character)| IndependentRebuildVerificationReceipt {
      artifact_arch: arch.to_string(),
      archive_sha256: child_digest('5'),
      receipt: json!({
        "schemaVersion": 1,
        "published": {"imageDigest": child_digest(digest_character), "imageTarSha256": child_digest('4')},
        "rebuilt": {"imageDigest": child_digest(digest_character), "imageTarSha256": child_digest('4')},
        "normalization": {"schemaVersion": 1, "ignored": [
          "outer-archive-order",
          "layer-compression",
          "filesystem-mtime",
          "oci-created-and-history-timestamps"
        ]},
        "differences": [],
        "outcome": "exact",
        "guarantee": "published and rebuilt OCI manifest and image archive digests match exactly",
        "source": {"repository": SOURCE_REPOSITORY, "ref": SOURCE_REF, "revision": REVISION},
        "build": {"role": "dataplane-strict", "artifactArch": arch, "recipeSha256": child_digest(recipe_character)},
        "workflow": {
          "repository": SOURCE_REPOSITORY,
          "path": ".github/workflows/verify-release-rebuild.yml",
          "sha": REVISION,
          "runId": 42,
          "runAttempt": 1
        }
      }),
    },
    )
    .collect();
  IndependentRebuildVerificationInput {
    workflow_run_id: 42,
    workflow_run_attempt: 1,
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
  assert_eq!(first.payload.schema_version, 2);
  assert_eq!(first.payload.policy.version, POLICY_VERSION_V2);
  assert_eq!(
    first
      .payload
      .workload_policy
      .as_ref()
      .expect("v2 workload policy"),
    &AdmissionWorkloadPolicy::default()
  );
  assert_eq!(first.payload.independent_rebuild.receipts.len(), 3);
  assert!(
    first
      .payload
      .independent_rebuild
      .receipts
      .iter()
      .all(|receipt| receipt.platform_recipe_sha256.is_some())
  );
  assert_eq!(
    first.payload.independent_rebuild.workflow_run_attempt,
    Some(1)
  );
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
fn duplicate_attestation_selection_is_independent_of_response_order() {
  let mut first_result = provenance()[0].clone();
  first_result["githubResultOrdinal"] = json!(1);
  let mut second_result = provenance()[0].clone();
  second_result["githubResultOrdinal"] = json!(2);
  let selected_hash = [
    sha256_value(&first_result).expect("first result hash"),
    sha256_value(&second_result).expect("second result hash"),
  ]
  .into_iter()
  .max()
  .expect("selected result hash");
  let generate = |provenance| {
    let (revocations, hash) = empty_revocations();
    verify_and_sign_bundle(
      input(),
      BundleEvidenceInput {
        provenance,
        sbom: sbom(),
        rebuild: rebuild(),
        independent_rebuild: receipts(),
      },
      &revocations,
      &hash,
      &[7_u8; 32],
    )
    .expect("duplicate evidence bundle")
  };

  let forward = generate(json!([first_result.clone(), second_result.clone()]));
  let reverse = generate(json!([second_result, first_result]));
  assert_eq!(
    serde_json::to_value(&forward).expect("forward bundle"),
    serde_json::to_value(&reverse).expect("reverse bundle")
  );
  assert_eq!(forward.payload.evidence[0].object_sha256, selected_hash);
}

#[test]
fn generation_and_admission_enforce_the_earliest_evidence_horizon() {
  let (revocations, hash) = empty_revocations();
  let key = [7_u8; 32];
  let base = verification_time();
  let generate = |expires_after_seconds, independent_completed_at| {
    let mut bundle_input = input();
    bundle_input.expires_after_seconds = expires_after_seconds;
    let mut independent_rebuild = receipts();
    independent_rebuild.completed_at = independent_completed_at;
    verify_and_sign_bundle(
      bundle_input,
      BundleEvidenceInput {
        provenance: provenance(),
        sbom: sbom(),
        rebuild: rebuild(),
        independent_rebuild,
      },
      &revocations,
      &hash,
      &key,
    )
  };

  generate(3540, base).expect("expiry exactly at attestation horizon");
  assert!(
    generate(3541, base)
      .expect_err("expiry beyond attestation horizon")
      .to_string()
      .contains("freshness horizon")
  );
  generate(3440, base - 100).expect("expiry exactly at independent rebuild horizon");
  assert!(
    generate(3441, base - 100)
      .expect_err("expiry beyond independent rebuild horizon")
      .to_string()
      .contains("freshness horizon")
  );

  let (bundle, public_key, revocations) = valid_bundle();
  let mut legacy_payload = bundle.payload;
  legacy_payload.decision.expires_at = base + 4000;
  let legacy = sign_payload(legacy_payload, "deployment-admission-2026", &key)
    .expect("legacy later-expiry bundle");
  verify_bundle(
    &legacy,
    &public_key,
    "deployment-admission-2026",
    &revocations,
    base + 3600,
  )
  .expect("evidence is valid through its exact horizon");
  assert!(
    verify_bundle(
      &legacy,
      &public_key,
      "deployment-admission-2026",
      &revocations,
      base + 3601,
    )
    .expect_err("evidence one second beyond horizon")
    .to_string()
    .contains("evidence is stale")
  );
}

#[test]
fn rebuild_predicate_requires_the_exact_canonical_index_and_sbom_binding() {
  let sbom_hash = sha256_value(&sbom_predicate()).expect("SBOM predicate hash");
  validate_rebuild(&rebuild_predicate(), &input(), &sbom_hash).expect("canonical rebuild");

  let mut cases = Vec::new();
  let mut unknown_outer = rebuild_predicate();
  unknown_outer["unexpected"] = json!(true);
  cases.push(unknown_outer);
  let mut unknown_metadata = rebuild_predicate();
  unknown_metadata["output"]["indexMetadata"]["unexpected"] = json!(true);
  cases.push(unknown_metadata);
  let mut wrong_metadata_schema = rebuild_predicate();
  wrong_metadata_schema["output"]["indexMetadata"]["schemaVersion"] = json!(1);
  cases.push(wrong_metadata_schema);
  let mut wrong_metadata_role = rebuild_predicate();
  wrong_metadata_role["output"]["indexMetadata"]["role"] = json!("dataplane");
  cases.push(wrong_metadata_role);
  let mut wrong_metadata_image = rebuild_predicate();
  wrong_metadata_image["output"]["indexMetadata"]["image"] = json!("ghcr.io/example/image");
  cases.push(wrong_metadata_image);
  let mut wrong_metadata_digest = rebuild_predicate();
  wrong_metadata_digest["output"]["indexMetadata"]["digest"] = json!(child_digest('9'));
  cases.push(wrong_metadata_digest);
  let mut wrong_os = rebuild_predicate();
  wrong_os["output"]["indexMetadata"]["children"][0]["os"] = json!("windows");
  cases.push(wrong_os);
  let mut wrong_architecture = rebuild_predicate();
  wrong_architecture["output"]["indexMetadata"]["children"][1]["architecture"] = json!("amd64");
  cases.push(wrong_architecture);
  let mut wrong_variant = rebuild_predicate();
  wrong_variant["output"]["indexMetadata"]["children"][2]["variant"] = json!("v8");
  cases.push(wrong_variant);
  let mut wrong_order = rebuild_predicate();
  wrong_order["output"]["indexMetadata"]["children"]
    .as_array_mut()
    .expect("children")
    .swap(0, 1);
  cases.push(wrong_order);
  let mut child_mismatch = rebuild_predicate();
  child_mismatch["output"]["children"][0]["digest"] = json!(child_digest('9'));
  cases.push(child_mismatch);
  let mut wrong_metadata_hash = rebuild_predicate();
  wrong_metadata_hash["output"]["indexMetadataSha256"] = json!(child_digest('9'));
  cases.push(wrong_metadata_hash);
  let mut wrong_sbom_hash = rebuild_predicate();
  wrong_sbom_hash["output"]["sbomSha256"] = json!(child_digest('9'));
  cases.push(wrong_sbom_hash);

  for predicate in cases {
    assert!(
      validate_rebuild(&predicate, &input(), &sbom_hash).is_err(),
      "non-canonical rebuild predicate was accepted: {predicate}"
    );
  }
}

#[test]
fn immutable_historical_v1_and_pre_attempt_v2_signatures_remain_compatible() {
  let public_key = decode_hex(
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
    32,
    "historical admission public key",
  )
  .expect("fixed public key");
  let revocations = RevocationSet {
    schema_version: 1,
    revocations: Vec::new(),
  };
  let fixtures = [
    (
      include_str!("fixtures/admission-bundle-v1-pre-receipt-hardening.json"),
      1,
      "sha256:dfe2b99d4c2a4b16e4ad9a71c62dc4f9c60cb0b30a3869e45fd2bd639bbeb88a",
    ),
    (
      include_str!("fixtures/admission-bundle-v2-pre-attempt.json"),
      2,
      "sha256:13ecc36f2b66c075dd39264d1481872b488326f1e31c0aa986b2ca0c002db53e",
    ),
  ];

  for (fixture, schema_version, payload_sha256) in fixtures {
    let bundle: AdmissionBundleEnvelope =
      serde_json::from_str(fixture).expect("historical signed bundle fixture");
    assert_eq!(bundle.payload.schema_version, schema_version);
    assert_eq!(bundle.signature.payload_sha256, payload_sha256);
    assert!(
      bundle
        .payload
        .independent_rebuild
        .workflow_run_attempt
        .is_none()
    );
    assert!(
      bundle
        .payload
        .independent_rebuild
        .receipts
        .iter()
        .all(|receipt| receipt.platform_recipe_sha256.is_none())
    );
    verify_bundle(
      &bundle,
      &public_key,
      "deployment-admission-2026",
      &revocations,
      input().verification_time,
    )
    .expect("historical signature remains valid");
  }
}

#[test]
fn mixed_bundle_contracts_and_workload_tampering_fail_closed() {
  let (bundle, public_key, revocations) = valid_bundle();
  let mut mixed = bundle.clone();
  mixed.payload.schema_version = 1;
  assert!(
    verify_bundle(
      &mixed,
      &public_key,
      "deployment-admission-2026",
      &revocations,
      input().verification_time,
    )
    .expect_err("mixed schema and policy")
    .to_string()
    .contains("inconsistent")
  );

  let mut missing = bundle.clone();
  missing.payload.workload_policy = None;
  assert!(
    verify_bundle(
      &missing,
      &public_key,
      "deployment-admission-2026",
      &revocations,
      input().verification_time,
    )
    .is_err()
  );

  let mut tampered = bundle;
  tampered
    .payload
    .workload_policy
    .as_mut()
    .expect("workload policy")
    .auxiliary_containers
    .push(ContainerApproval {
      class: ContainerClass::Regular,
      name: "mesh-proxy".to_string(),
      image_reference: format!("ghcr.io/example/mesh-proxy@sha256:{}", "e".repeat(64)),
    });
  let error = verify_bundle(
    &tampered,
    &public_key,
    "deployment-admission-2026",
    &revocations,
    input().verification_time,
  )
  .expect_err("tampered workload policy");
  assert!(error.to_string().contains("payload digest mismatch"));
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

  let mut invalid_attempt = receipts();
  invalid_attempt.workflow_run_attempt = 0;
  let error = verify_and_sign_bundle(
    input(),
    BundleEvidenceInput {
      provenance: provenance(),
      sbom: sbom(),
      rebuild: rebuild(),
      independent_rebuild: invalid_attempt,
    },
    &revocations,
    &hash,
    &key,
  )
  .expect_err("zero workflow run attempt");
  assert!(error.to_string().contains("run attempt must be positive"));
}

#[test]
fn wrong_top_level_repository_and_role_fail_closed() {
  let mut wrong_repository = input();
  wrong_repository.repository = "ghcr.io/oxibelt/oxibelt-dataplane".to_string();
  assert!(validate_input(&wrong_repository).is_err());

  let mut wrong_role = input();
  wrong_role.role = SupplyChainRole::Dataplane;
  assert!(validate_input(&wrong_role).is_err());
}

#[test]
fn wrong_source_commit_fails_closed() {
  let (revocations, hash) = empty_revocations();
  let mut wrong_commit = input();
  wrong_commit.source_revision = "f".repeat(40);
  let error = verify_and_sign_bundle(
    wrong_commit,
    BundleEvidenceInput {
      provenance: provenance(),
      sbom: sbom(),
      rebuild: rebuild(),
      independent_rebuild: receipts(),
    },
    &revocations,
    &hash,
    &[7_u8; 32],
  )
  .expect_err("evidence from a different source commit");
  assert!(error.to_string().contains("no verified provenance"));
}

#[test]
fn missing_provenance_or_sbom_fails_closed() {
  let (revocations, hash) = empty_revocations();
  for (provenance, sbom, expected) in [
    (json!([]), sbom(), "provenance"),
    (provenance(), json!([]), "sbom"),
  ] {
    let error = verify_and_sign_bundle(
      input(),
      BundleEvidenceInput {
        provenance,
        sbom,
        rebuild: rebuild(),
        independent_rebuild: receipts(),
      },
      &revocations,
      &hash,
      &[7_u8; 32],
    )
    .expect_err("required attestation is missing");
    assert!(error.to_string().contains(expected), "{error:#}");
  }
}

#[test]
fn malformed_rebuild_predicate_fails_closed() {
  let (revocations, hash) = empty_revocations();
  let error = verify_and_sign_bundle(
    input(),
    BundleEvidenceInput {
      provenance: provenance(),
      sbom: sbom(),
      rebuild: attestation(REBUILD_PREDICATE, json!({"schemaVersion": 1})),
      independent_rebuild: receipts(),
    },
    &revocations,
    &hash,
    &[7_u8; 32],
  )
  .expect_err("malformed rebuild predicate");
  assert!(error.to_string().contains("invalid or non-canonical shape"));
}

#[test]
fn duplicated_independent_rebuild_receipt_fails_closed() {
  let (revocations, hash) = empty_revocations();
  let mut duplicated = receipts();
  duplicated.receipts[1].artifact_arch = "amd64".to_string();
  duplicated.receipts[1].receipt["published"]["imageDigest"] = json!(child_digest('c'));
  duplicated.receipts[1].receipt["rebuilt"]["imageDigest"] = json!(child_digest('c'));
  duplicated.receipts[1].receipt["build"]["artifactArch"] = json!("amd64");
  duplicated.receipts[1].receipt["build"]["recipeSha256"] = json!(child_digest('1'));
  let error = verify_and_sign_bundle(
    input(),
    BundleEvidenceInput {
      provenance: provenance(),
      sbom: sbom(),
      rebuild: rebuild(),
      independent_rebuild: duplicated,
    },
    &revocations,
    &hash,
    &[7_u8; 32],
  )
  .expect_err("duplicated independent receipt");
  assert!(error.to_string().contains("missing or duplicated"));
}

#[test]
fn independent_rebuild_receipts_are_strict_consistent_and_recipe_bound() {
  let generate = |independent_rebuild| {
    let (revocations, hash) = empty_revocations();
    verify_and_sign_bundle(
      input(),
      BundleEvidenceInput {
        provenance: provenance(),
        sbom: sbom(),
        rebuild: rebuild(),
        independent_rebuild,
      },
      &revocations,
      &hash,
      &[7_u8; 32],
    )
  };

  let mut normalized = receipts();
  normalized.receipts[0].receipt["rebuilt"]["imageTarSha256"] = json!(child_digest('9'));
  normalized.receipts[0].receipt["outcome"] = json!("normalized_equivalent");
  normalized.receipts[0].receipt["guarantee"] = json!(
    "security-relevant content matches after the documented normalization; this is not byte-for-byte reproducibility"
  );
  let normalized_bundle = generate(normalized).expect("consistent normalized rebuild receipt");
  assert_eq!(
    normalized_bundle.payload.independent_rebuild.receipts[0].outcome,
    "normalized_equivalent"
  );

  let mut cases = Vec::new();
  let mut missing_rebuilt = receipts();
  missing_rebuilt.receipts[0]
    .receipt
    .as_object_mut()
    .expect("receipt object")
    .remove("rebuilt");
  cases.push(missing_rebuilt);
  let mut unknown_field = receipts();
  unknown_field.receipts[0].receipt["unexpected"] = json!(true);
  cases.push(unknown_field);
  let mut wrong_recipe = receipts();
  wrong_recipe.receipts[0].receipt["build"]["recipeSha256"] = json!(child_digest('9'));
  cases.push(wrong_recipe);
  let mut inconsistent_exact = receipts();
  inconsistent_exact.receipts[0].receipt["rebuilt"]["imageDigest"] = json!(child_digest('9'));
  cases.push(inconsistent_exact);
  let mut inconsistent_exact_archive = receipts();
  inconsistent_exact_archive.receipts[0].receipt["rebuilt"]["imageTarSha256"] =
    json!(child_digest('9'));
  cases.push(inconsistent_exact_archive);
  let mut inconsistent_normalized = receipts();
  inconsistent_normalized.receipts[0].receipt["outcome"] = json!("normalized_equivalent");
  inconsistent_normalized.receipts[0].receipt["guarantee"] = json!(
    "security-relevant content matches after the documented normalization; this is not byte-for-byte reproducibility"
  );
  cases.push(inconsistent_normalized);
  let mut differences = receipts();
  differences.receipts[0].receipt["differences"] = json!(["runtime-config"]);
  cases.push(differences);
  let mut broadened_normalization = receipts();
  broadened_normalization.receipts[0].receipt["normalization"]["ignored"] =
    json!(["runtime-config"]);
  cases.push(broadened_normalization);

  for malformed in cases {
    generate(malformed).expect_err("malformed independent rebuild receipt");
  }
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

#[test]
#[ignore = "explicitly emits short-lived inputs for the rootless live Kubernetes harness"]
fn emit_live_kubernetes_admission_fixture() -> anyhow::Result<()> {
  use std::fs::{self, OpenOptions};
  use std::io::Write as _;
  #[cfg(unix)]
  use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
  use std::path::{Path, PathBuf};

  use crate::supply_chain_workload_policy::load_workload_policy;

  let required = |name: &str| {
    std::env::var(name).with_context(|| format!("{name} must be set for the live fixture emitter"))
  };
  let output_dir = PathBuf::from(required("OXIBELT_TEST_ADMISSION_OUTPUT_DIR")?);
  let primary_digest = required("OXIBELT_TEST_ADMISSION_PRIMARY_DIGEST")?;
  let tools_digest = required("OXIBELT_TEST_ADMISSION_TOOLS_DIGEST")?;
  let source_revision = required("OXIBELT_TEST_ADMISSION_SOURCE_REVISION")?;
  let verification_time = required("OXIBELT_TEST_ADMISSION_VERIFICATION_TIME")?
    .parse::<u64>()
    .context("OXIBELT_TEST_ADMISSION_VERIFICATION_TIME must be a Unix timestamp")?;
  let key_id = required("OXIBELT_TEST_ADMISSION_KEY_ID")?;
  let workload_policy_path = PathBuf::from(required("OXIBELT_TEST_ADMISSION_WORKLOAD_POLICY")?);
  ensure!(
    output_dir.is_absolute() && workload_policy_path.is_absolute(),
    "live fixture output and workload policy paths must be absolute"
  );
  let metadata =
    fs::symlink_metadata(&output_dir).context("failed to inspect live fixture output directory")?;
  ensure!(
    metadata.file_type().is_dir(),
    "live fixture output must be an existing directory"
  );
  #[cfg(unix)]
  ensure!(
    metadata.permissions().mode() & 0o777 == 0o700,
    "live fixture output directory must have mode 0700"
  );
  ensure!(
    fs::read_dir(&output_dir)
      .context("failed to read live fixture output directory")?
      .next()
      .is_none(),
    "live fixture output directory must be empty"
  );
  validate_digest(&primary_digest, "live fixture primary digest")?;
  validate_digest(&tools_digest, "live fixture tools digest")?;
  ensure!(
    is_lower_hex(&source_revision, 40),
    "live fixture source revision must be a full lowercase Git commit"
  );
  validate_identifier(&key_id, 128, "live fixture key id")?;
  let workload_policy = load_workload_policy(Some(&workload_policy_path))?;
  let tools_image_reference = format!("{}@{tools_digest}", SupplyChainRole::Tools.repository());
  ensure!(
    workload_policy
      .auxiliary_containers
      .iter()
      .any(|approval| approval.image_reference == tools_image_reference),
    "live fixture workload policy must approve the exact supplied tools image"
  );
  let input = BundleVerificationInput {
    repository: SupplyChainRole::DataplaneStrict.repository().to_string(),
    role: SupplyChainRole::DataplaneStrict,
    digest: primary_digest.clone(),
    source_ref: SOURCE_REF.to_string(),
    source_revision: source_revision.clone(),
    release_channel: SupplyChainReleaseChannel::Stable,
    verification_time,
    max_evidence_age_seconds: 3600,
    expires_after_seconds: 1800,
    key_id: key_id.clone(),
    workload_policy,
  };
  let timestamp = Timestamp::new(
    i64::try_from(verification_time).context("live fixture timestamp exceeds i64")?,
    0,
  )?
  .to_string();
  let signer_workflow = format!(
    "https://github.com/OxiBelt/OxiBelt/.github/workflows/release.yml@{}",
    input.source_ref
  );
  let provenance_predicate = json!({
    "buildDefinition": {
      "buildType": "https://actions.github.io/buildtypes/workflow/v1",
      "externalParameters": {"workflow": {
        "path": ".github/workflows/release.yml",
        "ref": input.source_ref,
        "repository": SOURCE_REPOSITORY_URL
      }},
      "internalParameters": {"github": {"runner_environment": "github-hosted"}},
      "resolvedDependencies": [{
        "uri": format!("git+{SOURCE_REPOSITORY_URL}@{}", input.source_ref),
        "digest": {"gitCommit": input.source_revision}
      }]
    },
    "runDetails": {"builder": {"id": signer_workflow}}
  });
  let sbom_predicate = json!({
    "bomFormat": "CycloneDX",
    "specVersion": "1.7",
    "metadata": {"component": {"properties": [
      {"name": "io.oxibelt.image.role", "value": input.role.as_str()},
      {"name": "io.oxibelt.image.repository", "value": input.repository},
      {"name": "io.oxibelt.image.digest", "value": input.digest},
      {"name": "io.oxibelt.release.revision", "value": input.source_revision},
      {"name": "io.oxibelt.release.ref", "value": input.source_ref}
    ]}}
  });
  let index_metadata = json!({
    "schemaVersion": 2,
    "role": input.role.as_str(),
    "image": input.repository,
    "digest": input.digest,
    "children": [
      {"artifactArch": "amd64", "digest": child_digest('c'), "os": "linux", "architecture": "amd64", "variant": null},
      {"artifactArch": "arm64", "digest": child_digest('d'), "os": "linux", "architecture": "arm64", "variant": null},
      {"artifactArch": "riscv64", "digest": child_digest('e'), "os": "linux", "architecture": "riscv64", "variant": null}
    ]
  });
  let rebuild_predicate = json!({
    "schemaVersion": 1,
    "predicateType": REBUILD_PREDICATE,
    "kind": "index",
    "subject": {"name": input.repository, "digest": input.digest},
    "source": {
      "repository": SOURCE_REPOSITORY_URL,
      "ref": input.source_ref,
      "revision": input.source_revision
    },
    "output": {
      "indexMetadataSha256": sha256_value(&index_metadata)?,
      "indexMetadata": index_metadata,
      "children": [
        {"artifactArch": "amd64", "digest": child_digest('c'), "recipeSha256": child_digest('1')},
        {"artifactArch": "arm64", "digest": child_digest('d'), "recipeSha256": child_digest('2')},
        {"artifactArch": "riscv64", "digest": child_digest('e'), "recipeSha256": child_digest('3')}
      ],
      "sbomSha256": sha256_value(&sbom_predicate)?
    }
  });
  let independent_rebuild = IndependentRebuildVerificationInput {
    workflow_run_id: 1,
    workflow_run_attempt: 1,
    workflow_path: ".github/workflows/verify-release-rebuild.yml".to_string(),
    workflow_sha: source_revision.clone(),
    completed_at: verification_time,
    receipts: [
      ("amd64", 'c', '1'),
      ("arm64", 'd', '2'),
      ("riscv64", 'e', '3'),
    ]
      .into_iter()
      .map(
        |(arch, digest_character, recipe_character)| IndependentRebuildVerificationReceipt {
          artifact_arch: arch.to_string(),
          archive_sha256: child_digest('5'),
          receipt: json!({
            "schemaVersion": 1,
            "published": {"imageDigest": child_digest(digest_character), "imageTarSha256": child_digest('4')},
            "rebuilt": {"imageDigest": child_digest(digest_character), "imageTarSha256": child_digest('4')},
            "normalization": {"schemaVersion": 1, "ignored": [
              "outer-archive-order",
              "layer-compression",
              "filesystem-mtime",
              "oci-created-and-history-timestamps"
            ]},
            "differences": [],
            "outcome": "exact",
            "guarantee": "published and rebuilt OCI manifest and image archive digests match exactly",
            "source": {
              "repository": SOURCE_REPOSITORY,
              "ref": input.source_ref,
              "revision": input.source_revision
            },
            "build": {
              "role": input.role.as_str(),
              "artifactArch": arch,
              "recipeSha256": child_digest(recipe_character)
            },
            "workflow": {
              "repository": SOURCE_REPOSITORY,
              "path": ".github/workflows/verify-release-rebuild.yml",
              "sha": input.source_revision,
              "runId": 1,
              "runAttempt": 1
            }
          }),
        },
      )
      .collect(),
  };
  let revocations = RevocationSet {
    schema_version: 1,
    revocations: Vec::new(),
  };
  let revocations_value = serde_json::to_value(&revocations)?;
  let revocations_sha256 = sha256_value(&revocations_value)?;
  let mut signing_key = Zeroizing::new([0_u8; 32]);
  getrandom::fill(signing_key.as_mut()).context("failed to generate live fixture signing key")?;
  let public_key = derive_public_key(signing_key.as_ref())?;
  let evidence = {
    let attestation = |predicate_type: &str, predicate: Value| {
      json!([{
        "verificationResult": {
          "signature": {"certificate": {
            "subjectAlternativeName": signer_workflow,
            "sourceRepositoryURI": SOURCE_REPOSITORY_URL,
            "sourceRepositoryRef": input.source_ref,
            "sourceRepositoryDigest": input.source_revision,
            "buildSignerDigest": input.source_revision,
            "runnerEnvironment": "github-hosted"
          }},
          "verifiedTimestamps": [{"timestamp": timestamp}],
          "statement": {
            "subject": [{
              "name": input.repository,
              "digest": {"sha256": input.digest.trim_start_matches("sha256:")}
            }],
            "predicateType": predicate_type,
            "predicate": predicate
          }
        }
      }])
    };
    BundleEvidenceInput {
      provenance: attestation(PROVENANCE_PREDICATE, provenance_predicate),
      sbom: attestation(SBOM_PREDICATE, sbom_predicate),
      rebuild: attestation(REBUILD_PREDICATE, rebuild_predicate),
      independent_rebuild,
    }
  };
  let bundle = verify_and_sign_bundle(
    input,
    evidence,
    &revocations,
    &revocations_sha256,
    signing_key.as_ref(),
  )?;
  let primary_image_reference = format!(
    "{}@{primary_digest}",
    SupplyChainRole::DataplaneStrict.repository()
  );
  let fixture_metadata = json!({
    "schemaVersion": 1,
    "syntheticTestFixture": true,
    "payloadDigest": bundle.signature.payload_sha256,
    "keyId": key_id,
    "verifiedAt": bundle.payload.decision.verified_at,
    "expiresAt": bundle.payload.decision.expires_at,
    "primaryImageReference": primary_image_reference,
    "toolsImageReference": tools_image_reference
  });
  let write_new = |path: &Path, bytes: &[u8]| -> anyhow::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
      .open(path)
      .with_context(|| format!("failed to create live fixture output: {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
  };
  let json_bytes = |value: &Value| -> anyhow::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
  };
  write_new(
    &output_dir.join("bundle.json"),
    &json_bytes(&serde_json::to_value(&bundle)?)?,
  )?;
  write_new(
    &output_dir.join("public-key.b64"),
    format!("{}\n", encode_base64(&public_key)).as_bytes(),
  )?;
  write_new(
    &output_dir.join("revocations.json"),
    &json_bytes(&revocations_value)?,
  )?;
  write_new(
    &output_dir.join("metadata.json"),
    &json_bytes(&fixture_metadata)?,
  )?;
  Ok(())
}

#[test]
fn live_fixture_public_key_base64_is_standard_and_padded() {
  assert_eq!(encode_base64(&[0_u8; 32]), format!("{}=", "A".repeat(43)));
}

fn encode_base64(bytes: &[u8]) -> String {
  const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
  for chunk in bytes.chunks(3) {
    let first = chunk[0];
    let second = chunk.get(1).copied().unwrap_or(0);
    let third = chunk.get(2).copied().unwrap_or(0);
    output.push(char::from(ALPHABET[usize::from(first >> 2)]));
    output.push(char::from(
      ALPHABET[usize::from(((first & 0x03) << 4) | (second >> 4))],
    ));
    output.push(if chunk.len() > 1 {
      char::from(ALPHABET[usize::from(((second & 0x0f) << 2) | (third >> 6))])
    } else {
      '='
    });
    output.push(if chunk.len() > 2 {
      char::from(ALPHABET[usize::from(third & 0x3f)])
    } else {
      '='
    });
  }
  output
}

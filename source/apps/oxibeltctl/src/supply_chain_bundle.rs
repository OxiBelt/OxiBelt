//! Exact GitHub attestation verification and deterministic admission bundles.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail, ensure};
use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::cli::{SupplyChainReleaseChannel, SupplyChainRole};
use crate::supply_chain_workload_policy::{AdmissionWorkloadPolicy, validate_workload_policy};

pub(crate) const MAX_ATTESTATION_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const MAX_BUNDLE_BYTES: u64 = 256 * 1024;
pub(crate) const MAX_REVOCATION_BYTES: u64 = 1024 * 1024;
pub(crate) const MAX_REBUILD_RECEIPT_BYTES: u64 = 1024 * 1024;
const MAX_ATTESTATION_RESULTS: usize = 100;
const MAX_REVOCATIONS: usize = 1024;
const CLOCK_SKEW_SECONDS: u64 = 300;
const SOURCE_REPOSITORY: &str = "OxiBelt/OxiBelt";
const SOURCE_REPOSITORY_URL: &str = "https://github.com/OxiBelt/OxiBelt";
const PROVENANCE_PREDICATE: &str = "https://slsa.dev/provenance/v1";
const SBOM_PREDICATE: &str = "https://cyclonedx.org/bom";
const REBUILD_PREDICATE: &str = "https://oxibelt.dev/attestations/rebuild/v1";
const POLICY_VERSION_V1: &str = "oxibelt-admission-v1";
const POLICY_VERSION_V2: &str = "oxibelt-admission-v2";
const SIGNATURE_DOMAIN_V1: &[u8] = b"OXIBELT-SUPPLY-CHAIN-ADMISSION-BUNDLE-V1\0";
const SIGNATURE_DOMAIN_V2: &[u8] = b"OXIBELT-SUPPLY-CHAIN-ADMISSION-BUNDLE-V2\0";
const DECISION_REASONS_V1: [&str; 1] = ["exact_evidence_verified"];
const DECISION_REASONS_V2: [&str; 2] = [
  "exact_primary_evidence_verified",
  "signed_workload_policy_verified",
];

#[derive(Debug)]
pub(crate) struct BundleVerificationInput {
  pub(crate) repository: String,
  pub(crate) role: SupplyChainRole,
  pub(crate) digest: String,
  pub(crate) source_ref: String,
  pub(crate) source_revision: String,
  pub(crate) release_channel: SupplyChainReleaseChannel,
  pub(crate) verification_time: u64,
  pub(crate) max_evidence_age_seconds: u64,
  pub(crate) expires_after_seconds: u64,
  pub(crate) key_id: String,
  pub(crate) workload_policy: AdmissionWorkloadPolicy,
}

#[derive(Debug)]
pub(crate) struct IndependentRebuildVerificationInput {
  pub(crate) workflow_run_id: u64,
  pub(crate) workflow_run_attempt: u64,
  pub(crate) workflow_path: String,
  pub(crate) workflow_sha: String,
  pub(crate) completed_at: u64,
  pub(crate) receipts: Vec<IndependentRebuildVerificationReceipt>,
}

#[derive(Debug)]
pub(crate) struct IndependentRebuildVerificationReceipt {
  pub(crate) artifact_arch: String,
  pub(crate) archive_sha256: String,
  pub(crate) receipt: Value,
}

#[derive(Debug)]
pub(crate) struct BundleEvidenceInput {
  pub(crate) provenance: Value,
  pub(crate) sbom: Value,
  pub(crate) rebuild: Value,
  pub(crate) independent_rebuild: IndependentRebuildVerificationInput,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionBundleEnvelope {
  pub(crate) payload: AdmissionBundlePayload,
  pub(crate) signature: AdmissionBundleSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionBundlePayload {
  pub(crate) schema_version: u32,
  pub(crate) policy: AdmissionPolicyClaim,
  pub(crate) artifact: AdmissionArtifactClaim,
  pub(crate) evidence: Vec<AdmissionEvidenceClaim>,
  pub(crate) independent_rebuild: IndependentRebuildClaim,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub(crate) workload_policy: Option<AdmissionWorkloadPolicy>,
  pub(crate) decision: AdmissionDecision,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionPolicyClaim {
  pub(crate) version: String,
  pub(crate) release_channel: String,
  pub(crate) max_evidence_age_seconds: u64,
  pub(crate) revocations_sha256: String,
  pub(crate) bundle_signing_key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionArtifactClaim {
  pub(crate) repository: String,
  pub(crate) digest: String,
  pub(crate) image_reference: String,
  pub(crate) role: String,
  pub(crate) source_repository: String,
  pub(crate) source_ref: String,
  pub(crate) source_revision: String,
  pub(crate) signer_workflow: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionEvidenceClaim {
  pub(crate) kind: String,
  pub(crate) predicate_type: String,
  pub(crate) object_sha256: String,
  pub(crate) predicate_sha256: String,
  pub(crate) trusted_timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct IndependentRebuildClaim {
  pub(crate) required_architectures: Vec<String>,
  pub(crate) workflow_run_id: u64,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub(crate) workflow_run_attempt: Option<u64>,
  pub(crate) workflow_path: String,
  pub(crate) workflow_sha: String,
  pub(crate) completed_at: u64,
  pub(crate) receipts: Vec<IndependentRebuildReceiptClaim>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct IndependentRebuildReceiptClaim {
  pub(crate) artifact_arch: String,
  pub(crate) published_digest: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub(crate) platform_recipe_sha256: Option<String>,
  pub(crate) outcome: String,
  pub(crate) archive_sha256: String,
  pub(crate) object_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionDecision {
  pub(crate) status: String,
  pub(crate) reasons: Vec<String>,
  pub(crate) verified_at: u64,
  pub(crate) expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionBundleSignature {
  pub(crate) algorithm: String,
  pub(crate) key_id: String,
  pub(crate) payload_sha256: String,
  pub(crate) value_hex: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RevocationSet {
  pub(crate) schema_version: u32,
  #[serde(default)]
  pub(crate) revocations: Vec<RevocationEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RevocationEntry {
  pub(crate) repository: String,
  pub(crate) digest: String,
  pub(crate) effective_at: u64,
  pub(crate) reason: String,
}

#[derive(Debug)]
struct ExactAttestation {
  claim: AdmissionEvidenceClaim,
  predicate: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RebuildChild {
  artifact_arch: String,
  digest: String,
  recipe_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RebuildReceiptEvidence {
  schema_version: u32,
  published: RebuildReceiptImage,
  rebuilt: RebuildReceiptImage,
  normalization: RebuildReceiptNormalization,
  differences: Vec<String>,
  outcome: String,
  guarantee: String,
  source: RebuildReceiptSource,
  build: RebuildReceiptBuild,
  workflow: RebuildReceiptWorkflow,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RebuildReceiptImage {
  image_digest: String,
  image_tar_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RebuildReceiptNormalization {
  schema_version: u32,
  ignored: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RebuildReceiptSource {
  repository: String,
  #[serde(rename = "ref")]
  source_ref: String,
  revision: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RebuildReceiptBuild {
  role: String,
  artifact_arch: String,
  recipe_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RebuildReceiptWorkflow {
  repository: String,
  path: String,
  sha: String,
  run_id: u64,
  run_attempt: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IndexRebuildPredicate {
  schema_version: u32,
  predicate_type: String,
  kind: String,
  subject: IndexRebuildSubject,
  source: IndexRebuildSource,
  output: IndexRebuildOutput,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexRebuildSubject {
  name: String,
  digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexRebuildSource {
  repository: String,
  #[serde(rename = "ref")]
  source_ref: String,
  revision: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IndexRebuildOutput {
  index_metadata: IndexMetadata,
  index_metadata_sha256: String,
  children: Vec<RebuildChild>,
  sbom_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IndexMetadata {
  schema_version: u32,
  role: String,
  image: String,
  digest: String,
  children: Vec<IndexMetadataChild>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IndexMetadataChild {
  artifact_arch: String,
  digest: String,
  os: String,
  architecture: String,
  variant: Value,
}

pub(crate) fn now_unix_seconds() -> anyhow::Result<u64> {
  Ok(
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .context("system clock is before the Unix epoch")?
      .as_secs(),
  )
}

pub(crate) fn load_json_bounded(path: &Path, limit: u64, label: &str) -> anyhow::Result<Value> {
  let bytes = read_file_bounded(path, limit, label)?;
  serde_json::from_slice(&bytes).with_context(|| format!("{label} is not valid JSON"))
}

pub(crate) fn load_revocations(path: Option<&Path>) -> anyhow::Result<(RevocationSet, String)> {
  let set = if let Some(path) = path {
    let value = load_json_bounded(path, MAX_REVOCATION_BYTES, "revocation policy")?;
    serde_json::from_value(value).context("revocation policy has an invalid shape")?
  } else {
    RevocationSet {
      schema_version: 1,
      revocations: Vec::new(),
    }
  };
  validate_revocations(&set)?;
  let hash = sha256_value(&serde_json::to_value(&set)?)?;
  Ok((set, hash))
}

pub(crate) fn verify_and_sign_bundle(
  input: BundleVerificationInput,
  evidence: BundleEvidenceInput,
  revocations: &RevocationSet,
  revocations_sha256: &str,
  signing_key: &[u8],
) -> anyhow::Result<AdmissionBundleEnvelope> {
  validate_input(&input)?;
  ensure!(
    sha256_value(&serde_json::to_value(revocations)?)? == revocations_sha256,
    "revocation policy digest does not match the supplied policy"
  );
  ensure!(
    !is_revoked(
      revocations,
      &input.repository,
      &input.digest,
      input.verification_time
    ),
    "artifact is revoked or withdrawn"
  );
  let signer_workflow = format!(
    "https://github.com/OxiBelt/OxiBelt/.github/workflows/release.yml@{}",
    input.source_ref
  );
  let provenance = exact_attestation(
    evidence.provenance,
    "provenance",
    PROVENANCE_PREDICATE,
    &input,
    &signer_workflow,
  )?;
  validate_provenance(&provenance.predicate, &input, &signer_workflow)?;
  let sbom = exact_attestation(
    evidence.sbom,
    "sbom",
    SBOM_PREDICATE,
    &input,
    &signer_workflow,
  )?;
  validate_sbom(&sbom.predicate, &input)?;
  let rebuild = exact_attestation(
    evidence.rebuild,
    "rebuild",
    REBUILD_PREDICATE,
    &input,
    &signer_workflow,
  )?;
  let children = validate_rebuild(&rebuild.predicate, &input, &sbom.claim.predicate_sha256)?;
  validate_independent_rebuild_run(&evidence.independent_rebuild, &input)?;
  let receipts = validate_rebuild_receipts(
    &evidence.independent_rebuild.receipts,
    &children,
    &evidence.independent_rebuild,
    &input,
  )?;

  let expires_at = input
    .verification_time
    .checked_add(input.expires_after_seconds)
    .context("bundle expiry overflows Unix time")?;
  let evidence_horizon = [
    provenance.claim.trusted_timestamp,
    sbom.claim.trusted_timestamp,
    rebuild.claim.trusted_timestamp,
    evidence.independent_rebuild.completed_at,
  ]
  .into_iter()
  .min()
  .expect("four evidence timestamps")
  .checked_add(input.max_evidence_age_seconds)
  .context("evidence freshness horizon overflows Unix time")?;
  ensure!(
    expires_at <= evidence_horizon,
    "bundle expiry exceeds the verified evidence freshness horizon"
  );
  let payload = AdmissionBundlePayload {
    schema_version: 2,
    policy: AdmissionPolicyClaim {
      version: POLICY_VERSION_V2.to_string(),
      release_channel: input.release_channel.as_str().to_string(),
      max_evidence_age_seconds: input.max_evidence_age_seconds,
      revocations_sha256: revocations_sha256.to_string(),
      bundle_signing_key_id: input.key_id.clone(),
    },
    artifact: AdmissionArtifactClaim {
      repository: input.repository.clone(),
      digest: input.digest.clone(),
      image_reference: format!("{}@{}", input.repository, input.digest),
      role: input.role.as_str().to_string(),
      source_repository: SOURCE_REPOSITORY.to_string(),
      source_ref: input.source_ref.clone(),
      source_revision: input.source_revision.clone(),
      signer_workflow,
    },
    evidence: vec![provenance.claim, sbom.claim, rebuild.claim],
    independent_rebuild: IndependentRebuildClaim {
      required_architectures: vec![
        "amd64".to_string(),
        "arm64".to_string(),
        "riscv64".to_string(),
      ],
      workflow_run_id: evidence.independent_rebuild.workflow_run_id,
      workflow_run_attempt: Some(evidence.independent_rebuild.workflow_run_attempt),
      workflow_path: evidence.independent_rebuild.workflow_path,
      workflow_sha: evidence.independent_rebuild.workflow_sha,
      completed_at: evidence.independent_rebuild.completed_at,
      receipts,
    },
    workload_policy: Some(input.workload_policy.clone()),
    decision: AdmissionDecision {
      status: "pass".to_string(),
      reasons: DECISION_REASONS_V2.map(str::to_string).to_vec(),
      verified_at: input.verification_time,
      expires_at,
    },
  };
  sign_payload(payload, &input.key_id, signing_key)
}

fn validate_input(input: &BundleVerificationInput) -> anyhow::Result<()> {
  ensure!(
    input.repository == input.role.repository(),
    "repository does not match the selected role"
  );
  validate_digest(&input.digest, "artifact digest")?;
  ensure!(
    is_lower_hex(&input.source_revision, 40),
    "source revision must be a full lowercase Git commit"
  );
  validate_release_ref(&input.source_ref, input.release_channel)?;
  validate_identifier(&input.key_id, 128, "bundle key id")?;
  ensure!(
    (1..=31_536_000).contains(&input.max_evidence_age_seconds),
    "max evidence age must be between one second and one year"
  );
  ensure!(
    (1..=2_592_000).contains(&input.expires_after_seconds),
    "bundle lifetime must be between one second and 30 days"
  );
  validate_workload_policy(&input.workload_policy)?;
  Ok(())
}

fn exact_attestation(
  value: Value,
  kind: &str,
  predicate_type: &str,
  input: &BundleVerificationInput,
  signer_workflow: &str,
) -> anyhow::Result<ExactAttestation> {
  let results = value
    .as_array()
    .context("gh attestation verification result must be an array")?;
  ensure!(
    results.len() <= MAX_ATTESTATION_RESULTS,
    "gh attestation verification result exceeds 100 entries"
  );
  let mut matches = Vec::new();
  for result in results {
    if let Some((predicate, timestamp)) =
      matching_attestation(result, predicate_type, input, signer_workflow)?
    {
      ensure!(
        timestamp <= input.verification_time.saturating_add(CLOCK_SKEW_SECONDS),
        "verified attestation timestamp is unacceptably in the future"
      );
      ensure!(
        input.verification_time.saturating_sub(timestamp) <= input.max_evidence_age_seconds,
        "verified attestation evidence is stale"
      );
      matches.push((result, predicate, timestamp, sha256_value(result)?));
    }
  }
  ensure!(
    !matches.is_empty(),
    "no verified {kind} attestation exactly matches the requested artifact identity"
  );
  let predicate_hashes = matches
    .iter()
    .map(|(_, predicate, _, _)| sha256_value(predicate))
    .collect::<anyhow::Result<BTreeSet<_>>>()?;
  ensure!(
    predicate_hashes.len() == 1,
    "verified {kind} attestations contain conflicting predicates"
  );
  matches.sort_by(|left, right| (left.2, left.3.as_str()).cmp(&(right.2, right.3.as_str())));
  let (_, predicate, timestamp, object_sha256) = matches.pop().expect("nonempty exact matches");
  Ok(ExactAttestation {
    claim: AdmissionEvidenceClaim {
      kind: kind.to_string(),
      predicate_type: predicate_type.to_string(),
      object_sha256,
      predicate_sha256: predicate_hashes
        .into_iter()
        .next()
        .expect("one predicate hash"),
      trusted_timestamp: timestamp,
    },
    predicate: predicate.clone(),
  })
}

fn matching_attestation<'a>(
  result: &'a Value,
  predicate_type: &str,
  input: &BundleVerificationInput,
  signer_workflow: &str,
) -> anyhow::Result<Option<(&'a Value, u64)>> {
  let Some(verification) = result.get("verificationResult") else {
    return Ok(None);
  };
  let Some(certificate) = verification.pointer("/signature/certificate") else {
    return Ok(None);
  };
  if certificate_string(
    certificate,
    &["subjectAlternativeName", "SubjectAlternativeName"],
  ) != Some(signer_workflow)
    || !matches!(
      certificate_string(
        certificate,
        &[
          "sourceRepository",
          "SourceRepository",
          "sourceRepositoryURI",
          "SourceRepositoryURI"
        ]
      ),
      Some(SOURCE_REPOSITORY | SOURCE_REPOSITORY_URL)
    )
    || certificate_string(certificate, &["sourceRepositoryRef", "SourceRepositoryRef"])
      != Some(input.source_ref.as_str())
    || certificate_string(
      certificate,
      &["sourceRepositoryDigest", "SourceRepositoryDigest"],
    ) != Some(input.source_revision.as_str())
    || certificate_string(certificate, &["buildSignerDigest", "BuildSignerDigest"])
      != Some(input.source_revision.as_str())
    || certificate_string(certificate, &["runnerEnvironment", "RunnerEnvironment"])
      != Some("github-hosted")
  {
    return Ok(None);
  }
  let Some(statement) = verification.get("statement") else {
    return Ok(None);
  };
  if statement.get("predicateType").and_then(Value::as_str) != Some(predicate_type) {
    return Ok(None);
  }
  let Some(subjects) = statement.get("subject").and_then(Value::as_array) else {
    return Ok(None);
  };
  if subjects.len() != 1
    || subjects[0].get("name").and_then(Value::as_str) != Some(input.repository.as_str())
    || subjects[0]
      .pointer("/digest/sha256")
      .and_then(Value::as_str)
      != Some(input.digest.trim_start_matches("sha256:"))
  {
    return Ok(None);
  }
  let Some(predicate) = statement.get("predicate") else {
    return Ok(None);
  };
  let timestamps = verification
    .get("verifiedTimestamps")
    .and_then(Value::as_array)
    .context("matching attestation is missing verified timestamps")?;
  let timestamp = timestamps
    .iter()
    .filter_map(|item| item.get("timestamp").and_then(Value::as_str))
    .filter_map(|value| value.parse::<Timestamp>().ok())
    .filter_map(|value| u64::try_from(value.as_second()).ok())
    .max()
    .context("matching attestation has no parseable trusted timestamp")?;
  Ok(Some((predicate, timestamp)))
}

fn validate_provenance(
  predicate: &Value,
  input: &BundleVerificationInput,
  signer_workflow: &str,
) -> anyhow::Result<()> {
  ensure!(
    predicate
      .pointer("/buildDefinition/buildType")
      .and_then(Value::as_str)
      == Some("https://actions.github.io/buildtypes/workflow/v1"),
    "provenance build type is not the GitHub workflow build type"
  );
  let workflow = predicate
    .pointer("/buildDefinition/externalParameters/workflow")
    .context("provenance is missing external workflow parameters")?;
  ensure!(
    workflow.get("path").and_then(Value::as_str) == Some(".github/workflows/release.yml")
      && workflow.get("ref").and_then(Value::as_str) == Some(input.source_ref.as_str())
      && workflow.get("repository").and_then(Value::as_str) == Some(SOURCE_REPOSITORY_URL),
    "provenance caller workflow identity does not match the release contract"
  );
  ensure!(
    predicate
      .pointer("/runDetails/builder/id")
      .and_then(Value::as_str)
      == Some(signer_workflow),
    "provenance builder identity does not match the release workflow"
  );
  ensure!(
    predicate
      .pointer("/buildDefinition/internalParameters/github/runner_environment")
      .and_then(Value::as_str)
      == Some("github-hosted"),
    "provenance runner environment is not GitHub-hosted"
  );
  let dependencies = predicate
    .pointer("/buildDefinition/resolvedDependencies")
    .and_then(Value::as_array)
    .context("provenance is missing resolved dependencies")?;
  ensure!(
    dependencies.iter().any(|dependency| {
      dependency.get("uri").and_then(Value::as_str)
        == Some(format!("git+{SOURCE_REPOSITORY_URL}@{}", input.source_ref).as_str())
        && dependency
          .pointer("/digest/gitCommit")
          .and_then(Value::as_str)
          == Some(input.source_revision.as_str())
    }),
    "provenance does not bind the exact source ref and revision"
  );
  Ok(())
}

fn validate_sbom(predicate: &Value, input: &BundleVerificationInput) -> anyhow::Result<()> {
  ensure!(
    predicate.get("bomFormat").and_then(Value::as_str) == Some("CycloneDX")
      && matches!(
        predicate.get("specVersion").and_then(Value::as_str),
        Some("1.6" | "1.7")
      ),
    "SBOM must be CycloneDX 1.6 or 1.7"
  );
  let properties = predicate
    .pointer("/metadata/component/properties")
    .and_then(Value::as_array)
    .context("SBOM is missing root component properties")?;
  let mut expected = BTreeMap::from([
    ("io.oxibelt.image.role", input.role.as_str()),
    ("io.oxibelt.image.repository", input.repository.as_str()),
    ("io.oxibelt.image.digest", input.digest.as_str()),
    (
      "io.oxibelt.release.revision",
      input.source_revision.as_str(),
    ),
    ("io.oxibelt.release.ref", input.source_ref.as_str()),
  ]);
  for property in properties {
    let Some(name) = property.get("name").and_then(Value::as_str) else {
      continue;
    };
    if let Some(expected_value) = expected.remove(name) {
      ensure!(
        property.get("value").and_then(Value::as_str) == Some(expected_value),
        "SBOM property {name} does not match the requested artifact"
      );
      ensure!(
        !properties
          .iter()
          .skip_while(|candidate| !std::ptr::eq(*candidate, property))
          .skip(1)
          .any(|candidate| candidate.get("name").and_then(Value::as_str) == Some(name)),
        "SBOM property {name} is duplicated"
      );
    }
  }
  ensure!(
    expected.is_empty(),
    "SBOM is missing required artifact properties"
  );
  Ok(())
}

fn validate_rebuild(
  predicate: &Value,
  input: &BundleVerificationInput,
  sbom_predicate_sha256: &str,
) -> anyhow::Result<Vec<RebuildChild>> {
  let predicate: IndexRebuildPredicate = serde_json::from_value(predicate.clone())
    .context("rebuild predicate has an invalid or non-canonical shape")?;
  ensure!(
    predicate.schema_version == 1
      && predicate.predicate_type == REBUILD_PREDICATE
      && predicate.kind == "index",
    "rebuild predicate is not an index recipe v1"
  );
  ensure!(
    predicate.subject.name == input.repository
      && predicate.subject.digest == input.digest
      && predicate.source.repository == SOURCE_REPOSITORY_URL
      && predicate.source.source_ref == input.source_ref
      && predicate.source.revision == input.source_revision,
    "rebuild predicate identity does not match the requested artifact"
  );
  ensure!(
    predicate.output.index_metadata.schema_version == 2
      && predicate.output.index_metadata.role == input.role.as_str()
      && predicate.output.index_metadata.image == input.repository
      && predicate.output.index_metadata.digest == input.digest,
    "index rebuild metadata identity does not match the requested artifact"
  );
  ensure!(
    predicate.output.index_metadata.children.len() == 3 && predicate.output.children.len() == 3,
    "index rebuild predicate must contain three platform children"
  );
  validate_digest(
    &predicate.output.index_metadata_sha256,
    "index metadata digest",
  )?;
  ensure!(
    sha256_value(&serde_json::to_value(&predicate.output.index_metadata)?)?
      == predicate.output.index_metadata_sha256,
    "index rebuild metadata digest does not match its canonical contents"
  );
  validate_digest(&predicate.output.sbom_sha256, "index SBOM predicate digest")?;
  ensure!(
    predicate.output.sbom_sha256 == sbom_predicate_sha256,
    "index rebuild SBOM digest does not match the selected SBOM predicate"
  );
  let mut children = Vec::with_capacity(3);
  let mut child_digests = BTreeSet::new();
  for (index, expected_arch) in ["amd64", "arm64", "riscv64"].iter().enumerate() {
    let metadata_child = &predicate.output.index_metadata.children[index];
    let child = &predicate.output.children[index];
    ensure!(
      metadata_child.artifact_arch == *expected_arch
        && metadata_child.os == "linux"
        && metadata_child.architecture == *expected_arch
        && metadata_child.variant.is_null()
        && child.artifact_arch == *expected_arch,
      "index rebuild children are incomplete or out of canonical order"
    );
    validate_digest(&metadata_child.digest, "index metadata child digest")?;
    validate_digest(&child.digest, "index child digest")?;
    ensure!(
      metadata_child.digest == child.digest,
      "index rebuild child digest does not match index metadata"
    );
    ensure!(
      child_digests.insert(child.digest.as_str()),
      "index rebuild predicate contains a duplicate child digest"
    );
    validate_digest(&child.recipe_sha256, "platform recipe digest")?;
    children.push(RebuildChild {
      artifact_arch: (*expected_arch).to_string(),
      digest: child.digest.clone(),
      recipe_sha256: child.recipe_sha256.clone(),
    });
  }
  Ok(children)
}

fn validate_independent_rebuild_run(
  independent_rebuild: &IndependentRebuildVerificationInput,
  input: &BundleVerificationInput,
) -> anyhow::Result<()> {
  ensure!(
    independent_rebuild.workflow_run_id > 0,
    "independent rebuild workflow run id must be positive"
  );
  ensure!(
    independent_rebuild.workflow_run_attempt > 0,
    "independent rebuild workflow run attempt must be positive"
  );
  ensure!(
    independent_rebuild.workflow_path == ".github/workflows/verify-release-rebuild.yml",
    "independent rebuild workflow path is not trusted"
  );
  ensure!(
    is_lower_hex(&independent_rebuild.workflow_sha, 40),
    "independent rebuild workflow revision must be a full lowercase Git commit"
  );
  ensure!(
    independent_rebuild.completed_at <= input.verification_time.saturating_add(CLOCK_SKEW_SECONDS),
    "independent rebuild workflow completion is unacceptably in the future"
  );
  ensure!(
    input
      .verification_time
      .saturating_sub(independent_rebuild.completed_at)
      <= input.max_evidence_age_seconds,
    "independent rebuild workflow evidence is stale"
  );
  Ok(())
}

fn validate_rebuild_receipts(
  values: &[IndependentRebuildVerificationReceipt],
  children: &[RebuildChild],
  independent_rebuild: &IndependentRebuildVerificationInput,
  input: &BundleVerificationInput,
) -> anyhow::Result<Vec<IndependentRebuildReceiptClaim>> {
  ensure!(
    values.len() == children.len(),
    "exactly three independent rebuild receipts are required"
  );
  let parsed = values
    .iter()
    .map(|evidence| {
      let receipt: RebuildReceiptEvidence = serde_json::from_value(evidence.receipt.clone())
        .context("independent rebuild receipt has an invalid or non-canonical shape")?;
      ensure!(
        receipt.schema_version == 1,
        "independent rebuild receipt schema must be 1"
      );
      ensure!(
        evidence.artifact_arch == receipt.build.artifact_arch,
        "independent rebuild artifact and receipt architectures disagree"
      );
      ensure!(
        receipt.source.repository == SOURCE_REPOSITORY
          && receipt.source.source_ref == input.source_ref
          && receipt.source.revision == input.source_revision
          && receipt.build.role == input.role.as_str()
          && receipt.workflow.repository == SOURCE_REPOSITORY
          && receipt.workflow.path == ".github/workflows/verify-release-rebuild.yml"
          && receipt.workflow.sha == independent_rebuild.workflow_sha
          && receipt.workflow.run_id == independent_rebuild.workflow_run_id
          && receipt.workflow.run_attempt == independent_rebuild.workflow_run_attempt,
        "independent rebuild receipt identity does not match the verified release and workflow"
      );
      validate_digest(
        &receipt.published.image_digest,
        "published rebuild receipt image digest",
      )?;
      validate_digest(
        &receipt.published.image_tar_sha256,
        "published rebuild receipt image archive digest",
      )?;
      validate_digest(
        &receipt.rebuilt.image_digest,
        "rebuilt receipt image digest",
      )?;
      validate_digest(
        &receipt.rebuilt.image_tar_sha256,
        "rebuilt receipt image archive digest",
      )?;
      validate_digest(&receipt.build.recipe_sha256, "platform recipe digest")?;
      ensure!(
        receipt.normalization.schema_version == 1
          && receipt.normalization.ignored
            == [
              "outer-archive-order",
              "layer-compression",
              "filesystem-mtime",
              "oci-created-and-history-timestamps",
            ],
        "independent rebuild receipt normalization policy is invalid"
      );
      ensure!(
        receipt.differences.is_empty(),
        "accepted independent rebuild receipt contains security-relevant differences"
      );
      match receipt.outcome.as_str() {
        "exact" => ensure!(
          receipt.rebuilt.image_digest == receipt.published.image_digest
            && receipt.rebuilt.image_tar_sha256 == receipt.published.image_tar_sha256
            && receipt.guarantee
              == "published and rebuilt OCI manifest and image archive digests match exactly",
          "exact independent rebuild receipt is internally inconsistent"
        ),
        "normalized_equivalent" => ensure!(
          (receipt.rebuilt.image_digest != receipt.published.image_digest
            || receipt.rebuilt.image_tar_sha256 != receipt.published.image_tar_sha256)
            && receipt.guarantee
              == "security-relevant content matches after the documented normalization; this is not byte-for-byte reproducibility",
          "normalized-equivalent independent rebuild receipt is internally inconsistent"
        ),
        _ => bail!("independent rebuild receipt does not prove an accepted rebuild"),
      }
      Ok((evidence, receipt))
    })
    .collect::<anyhow::Result<Vec<_>>>()?;
  let mut claims = Vec::with_capacity(3);
  let mut seen = BTreeSet::new();
  for child in children {
    let matching = parsed
      .iter()
      .filter(|(evidence, receipt)| {
        evidence.artifact_arch == child.artifact_arch
          && receipt.published.image_digest == child.digest
          && receipt.build.recipe_sha256 == child.recipe_sha256
      })
      .collect::<Vec<_>>();
    ensure!(
      matching.len() == 1,
      "independent rebuild receipts are missing or duplicated for {}",
      child.artifact_arch
    );
    let (evidence, receipt) = matching[0];
    validate_digest(
      &evidence.archive_sha256,
      "independent rebuild artifact archive digest",
    )?;
    let value = &evidence.receipt;
    let hash = sha256_value(value)?;
    ensure!(
      seen.insert(hash.clone()),
      "independent rebuild receipt is duplicated"
    );
    claims.push(IndependentRebuildReceiptClaim {
      artifact_arch: child.artifact_arch.clone(),
      published_digest: child.digest.clone(),
      platform_recipe_sha256: Some(child.recipe_sha256.clone()),
      outcome: receipt.outcome.clone(),
      archive_sha256: evidence.archive_sha256.clone(),
      object_sha256: hash,
    });
  }
  Ok(claims)
}

fn sign_payload(
  payload: AdmissionBundlePayload,
  key_id: &str,
  signing_key: &[u8],
) -> anyhow::Result<AdmissionBundleEnvelope> {
  ensure!(
    signing_key.len() == 32,
    "bundle signing key must contain exactly 32 raw bytes"
  );
  let key = Ed25519KeyPair::from_seed_unchecked(signing_key)
    .map_err(|_| anyhow::anyhow!("bundle signing key is invalid"))?;
  validate_bundle_payload(&payload)?;
  let payload_bytes = serde_json::to_vec(&payload)?;
  let payload_sha256 = sha256_bytes(&payload_bytes);
  let contract = bundle_contract(&payload)?;
  let mut signed = Vec::with_capacity(contract.signature_domain.len() + payload_bytes.len());
  signed.extend_from_slice(contract.signature_domain);
  signed.extend_from_slice(&payload_bytes);
  let signature = key.sign(&signed);
  Ok(AdmissionBundleEnvelope {
    payload,
    signature: AdmissionBundleSignature {
      algorithm: "ed25519".to_string(),
      key_id: key_id.to_string(),
      payload_sha256,
      value_hex: encode_hex(signature.as_ref()),
    },
  })
}

struct BundleContract {
  signature_domain: &'static [u8],
  decision_reasons: &'static [&'static str],
}

fn bundle_contract(payload: &AdmissionBundlePayload) -> anyhow::Result<BundleContract> {
  match (
    payload.schema_version,
    payload.policy.version.as_str(),
    payload.workload_policy.as_ref(),
  ) {
    (1, POLICY_VERSION_V1, None) => Ok(BundleContract {
      signature_domain: SIGNATURE_DOMAIN_V1,
      decision_reasons: &DECISION_REASONS_V1,
    }),
    (2, POLICY_VERSION_V2, Some(_)) => Ok(BundleContract {
      signature_domain: SIGNATURE_DOMAIN_V2,
      decision_reasons: &DECISION_REASONS_V2,
    }),
    _ => bail!("unsupported or inconsistent admission bundle contract"),
  }
}

pub(crate) fn derive_public_key(signing_key: &[u8]) -> anyhow::Result<Vec<u8>> {
  ensure!(
    signing_key.len() == 32,
    "bundle signing key must contain exactly 32 raw bytes"
  );
  let key = Ed25519KeyPair::from_seed_unchecked(signing_key)
    .map_err(|_| anyhow::anyhow!("bundle signing key is invalid"))?;
  Ok(key.public_key().as_ref().to_vec())
}

pub(crate) fn verify_bundle(
  bundle: &AdmissionBundleEnvelope,
  public_key: &[u8],
  expected_key_id: &str,
  revocations: &RevocationSet,
  now: u64,
) -> anyhow::Result<()> {
  validate_bundle_payload(&bundle.payload)?;
  let contract = bundle_contract(&bundle.payload)?;
  ensure!(
    bundle.payload.policy.bundle_signing_key_id == expected_key_id
      && bundle.signature.key_id == expected_key_id,
    "admission bundle signing key id does not match the trusted key"
  );
  ensure!(
    bundle.signature.algorithm == "ed25519",
    "unsupported admission bundle signature algorithm"
  );
  ensure!(
    public_key.len() == 32,
    "trusted admission public key must contain 32 raw bytes"
  );
  let payload_bytes = serde_json::to_vec(&bundle.payload)?;
  ensure!(
    sha256_bytes(&payload_bytes) == bundle.signature.payload_sha256,
    "admission bundle payload digest mismatch"
  );
  let signature = decode_hex(
    &bundle.signature.value_hex,
    64,
    "admission bundle signature",
  )?;
  let mut signed = Vec::with_capacity(contract.signature_domain.len() + payload_bytes.len());
  signed.extend_from_slice(contract.signature_domain);
  signed.extend_from_slice(&payload_bytes);
  UnparsedPublicKey::new(&ED25519, public_key)
    .verify(&signed, &signature)
    .map_err(|_| anyhow::anyhow!("admission bundle signature is invalid"))?;
  ensure!(
    bundle.payload.decision.status == "pass"
      && bundle
        .payload
        .decision
        .reasons
        .iter()
        .map(String::as_str)
        .eq(contract.decision_reasons.iter().copied()),
    "admission bundle does not contain a passing decision"
  );
  ensure!(
    now <= bundle.payload.decision.expires_at,
    "admission bundle is expired"
  );
  ensure!(
    now <= evidence_freshness_horizon(&bundle.payload)?,
    "admission bundle evidence is stale"
  );
  ensure!(
    bundle.payload.decision.verified_at <= now.saturating_add(CLOCK_SKEW_SECONDS),
    "admission bundle verification time is unacceptably in the future"
  );
  ensure!(
    bundle.payload.artifact.image_reference
      == format!(
        "{}@{}",
        bundle.payload.artifact.repository, bundle.payload.artifact.digest
      ),
    "admission bundle image reference is inconsistent"
  );
  validate_digest(&bundle.payload.artifact.digest, "bundle artifact digest")?;
  ensure!(
    !is_revoked(
      revocations,
      &bundle.payload.artifact.repository,
      &bundle.payload.artifact.digest,
      now
    ),
    "admission bundle artifact is revoked or withdrawn"
  );
  Ok(())
}

fn evidence_freshness_horizon(payload: &AdmissionBundlePayload) -> anyhow::Result<u64> {
  let oldest = payload
    .evidence
    .iter()
    .map(|claim| claim.trusted_timestamp)
    .chain(std::iter::once(payload.independent_rebuild.completed_at))
    .min()
    .context("admission bundle has no evidence timestamps")?;
  oldest
    .checked_add(payload.policy.max_evidence_age_seconds)
    .context("admission bundle evidence freshness horizon overflows Unix time")
}

fn validate_bundle_payload(payload: &AdmissionBundlePayload) -> anyhow::Result<()> {
  let contract = bundle_contract(payload)?;
  match payload.schema_version {
    1 => ensure!(
      payload.independent_rebuild.workflow_run_attempt.is_none()
        && payload
          .independent_rebuild
          .receipts
          .iter()
          .all(|receipt| receipt.platform_recipe_sha256.is_none()),
      "legacy admission bundles cannot contain workflow-attempt or platform-recipe extensions"
    ),
    2 => {
      ensure!(
        payload
          .independent_rebuild
          .workflow_run_attempt
          .is_none_or(|attempt| attempt > 0),
        "admission bundle workflow run attempt must be positive when present"
      );
      let recipe_hash_count = payload
        .independent_rebuild
        .receipts
        .iter()
        .filter(|receipt| receipt.platform_recipe_sha256.is_some())
        .count();
      ensure!(
        matches!(recipe_hash_count, 0 | 3)
          && payload.independent_rebuild.workflow_run_attempt.is_some() == (recipe_hash_count == 3),
        "admission bundle platform recipe linkage is incomplete"
      );
    }
    _ => unreachable!("bundle_contract rejected an unknown schema"),
  }
  if let Some(workload_policy) = &payload.workload_policy {
    validate_workload_policy(workload_policy)?;
  }
  validate_identifier(
    &payload.policy.bundle_signing_key_id,
    128,
    "bundle signing key id",
  )?;
  ensure!(
    (1..=31_536_000).contains(&payload.policy.max_evidence_age_seconds),
    "bundle evidence age policy is invalid"
  );
  validate_digest(
    &payload.policy.revocations_sha256,
    "revocation policy digest",
  )?;
  let channel = match payload.policy.release_channel.as_str() {
    "stable" => SupplyChainReleaseChannel::Stable,
    "beta" => SupplyChainReleaseChannel::Beta,
    _ => bail!("bundle release channel is invalid"),
  };
  validate_release_ref(&payload.artifact.source_ref, channel)?;
  ensure!(
    is_lower_hex(&payload.artifact.source_revision, 40),
    "bundle source revision must be a full lowercase Git commit"
  );
  ensure!(
    payload.artifact.source_repository == SOURCE_REPOSITORY,
    "bundle source repository is invalid"
  );
  let expected_repository = match payload.artifact.role.as_str() {
    "standalone" => SupplyChainRole::Standalone.repository(),
    "dataplane" => SupplyChainRole::Dataplane.repository(),
    "dataplane-strict" => SupplyChainRole::DataplaneStrict.repository(),
    "controller" => SupplyChainRole::Controller.repository(),
    "tools" => SupplyChainRole::Tools.repository(),
    "keysigner" => SupplyChainRole::Keysigner.repository(),
    _ => bail!("bundle image role is invalid"),
  };
  ensure!(
    payload.artifact.repository == expected_repository,
    "bundle repository does not match its image role"
  );
  ensure!(
    payload.artifact.signer_workflow
      == format!(
        "https://github.com/OxiBelt/OxiBelt/.github/workflows/release.yml@{}",
        payload.artifact.source_ref
      ),
    "bundle signer workflow is invalid"
  );
  validate_digest(&payload.artifact.digest, "bundle artifact digest")?;
  ensure!(
    payload.artifact.image_reference
      == format!(
        "{}@{}",
        payload.artifact.repository, payload.artifact.digest
      ),
    "admission bundle image reference is inconsistent"
  );
  let expected_evidence = [
    ("provenance", PROVENANCE_PREDICATE),
    ("sbom", SBOM_PREDICATE),
    ("rebuild", REBUILD_PREDICATE),
  ];
  ensure!(
    payload.evidence.len() == 3,
    "bundle must contain exactly three evidence claims"
  );
  for (claim, (kind, predicate_type)) in payload.evidence.iter().zip(expected_evidence) {
    ensure!(
      claim.kind == kind && claim.predicate_type == predicate_type,
      "bundle evidence claims are incomplete or out of canonical order"
    );
    validate_digest(&claim.object_sha256, "evidence object digest")?;
    validate_digest(&claim.predicate_sha256, "evidence predicate digest")?;
    ensure!(
      claim.trusted_timestamp
        <= payload
          .decision
          .verified_at
          .saturating_add(CLOCK_SKEW_SECONDS)
        && payload
          .decision
          .verified_at
          .saturating_sub(claim.trusted_timestamp)
          <= payload.policy.max_evidence_age_seconds,
      "bundle evidence timestamp is stale or unacceptably in the future"
    );
  }
  ensure!(
    payload.independent_rebuild.required_architectures == ["amd64", "arm64", "riscv64"]
      && payload.independent_rebuild.receipts.len() == 3,
    "bundle independent rebuild coverage is incomplete"
  );
  ensure!(
    payload.independent_rebuild.workflow_run_id > 0
      && payload.independent_rebuild.workflow_path
        == ".github/workflows/verify-release-rebuild.yml"
      && is_lower_hex(&payload.independent_rebuild.workflow_sha, 40),
    "bundle independent rebuild workflow identity is invalid"
  );
  ensure!(
    payload.independent_rebuild.completed_at
      <= payload
        .decision
        .verified_at
        .saturating_add(CLOCK_SKEW_SECONDS)
      && payload
        .decision
        .verified_at
        .saturating_sub(payload.independent_rebuild.completed_at)
        <= payload.policy.max_evidence_age_seconds,
    "bundle independent rebuild workflow evidence is stale or unacceptably in the future"
  );
  for (receipt, expected_arch) in payload
    .independent_rebuild
    .receipts
    .iter()
    .zip(["amd64", "arm64", "riscv64"])
  {
    ensure!(
      receipt.artifact_arch == expected_arch
        && matches!(receipt.outcome.as_str(), "exact" | "normalized_equivalent"),
      "bundle independent rebuild receipt is invalid"
    );
    validate_digest(&receipt.published_digest, "rebuilt platform digest")?;
    if let Some(recipe_sha256) = &receipt.platform_recipe_sha256 {
      validate_digest(recipe_sha256, "platform recipe digest")?;
    }
    validate_digest(
      &receipt.archive_sha256,
      "independent rebuild artifact archive digest",
    )?;
    validate_digest(&receipt.object_sha256, "rebuild receipt digest")?;
  }
  ensure!(
    payload.decision.status == "pass"
      && payload
        .decision
        .reasons
        .iter()
        .map(String::as_str)
        .eq(contract.decision_reasons.iter().copied()),
    "admission bundle does not contain a passing decision"
  );
  ensure!(
    payload.decision.expires_at > payload.decision.verified_at
      && payload
        .decision
        .expires_at
        .saturating_sub(payload.decision.verified_at)
        <= 2_592_000,
    "admission bundle lifetime is invalid"
  );
  Ok(())
}

pub(crate) fn load_bundle(path: &Path) -> anyhow::Result<AdmissionBundleEnvelope> {
  serde_json::from_value(load_json_bounded(
    path,
    MAX_BUNDLE_BYTES,
    "admission bundle",
  )?)
  .context("admission bundle has an invalid shape")
}

pub(crate) fn load_secret_key(path: &Path, label: &str) -> anyhow::Result<Vec<u8>> {
  let metadata = fs::symlink_metadata(path)
    .with_context(|| format!("failed to inspect {label}: {}", path.display()))?;
  ensure!(
    metadata.file_type().is_file(),
    "{label} must be a regular file"
  );
  #[cfg(unix)]
  ensure!(
    metadata.permissions().mode() & 0o077 == 0,
    "{label} must not be accessible by group or other users"
  );
  let bytes = read_file_bounded(path, 32, label)?;
  ensure!(
    bytes.len() == 32,
    "{label} must contain exactly 32 raw bytes"
  );
  Ok(bytes)
}

pub(crate) fn load_public_key(path: &Path) -> anyhow::Result<Vec<u8>> {
  let bytes = read_file_bounded(path, 32, "trusted admission public key")?;
  ensure!(
    bytes.len() == 32,
    "trusted admission public key must contain exactly 32 raw bytes"
  );
  Ok(bytes)
}

pub(crate) fn bundle_payload_digest(bundle: &AdmissionBundleEnvelope) -> &str {
  &bundle.signature.payload_sha256
}

#[cfg(test)]
pub(crate) fn signed_bundle_for_admission_test(
  now: u64,
) -> (AdmissionBundleEnvelope, Vec<u8>, RevocationSet) {
  signed_test_bundle(now, Some(AdmissionWorkloadPolicy::default()))
}

#[cfg(test)]
pub(crate) fn signed_v1_bundle_for_admission_test(
  now: u64,
) -> (AdmissionBundleEnvelope, Vec<u8>, RevocationSet) {
  signed_test_bundle(now, None)
}

#[cfg(test)]
pub(crate) fn signed_bundle_for_admission_test_with_policy(
  now: u64,
  workload_policy: AdmissionWorkloadPolicy,
) -> (AdmissionBundleEnvelope, Vec<u8>, RevocationSet) {
  validate_workload_policy(&workload_policy).expect("canonical test workload policy");
  signed_test_bundle(now, Some(workload_policy))
}

#[cfg(test)]
fn signed_test_bundle(
  now: u64,
  workload_policy: Option<AdmissionWorkloadPolicy>,
) -> (AdmissionBundleEnvelope, Vec<u8>, RevocationSet) {
  let key = [9_u8; 32];
  let pair = Ed25519KeyPair::from_seed_unchecked(&key).expect("test key");
  let digest = format!("sha256:{}", "a".repeat(64));
  let evidence_digest = format!("sha256:{}", "b".repeat(64));
  let receipt_digest = format!("sha256:{}", "c".repeat(64));
  let source_ref = "refs/tags/1.2.3".to_string();
  let (schema_version, policy_version, decision_reasons) = if workload_policy.is_some() {
    (2, POLICY_VERSION_V2, DECISION_REASONS_V2.as_slice())
  } else {
    (1, POLICY_VERSION_V1, DECISION_REASONS_V1.as_slice())
  };
  let payload = AdmissionBundlePayload {
    schema_version,
    policy: AdmissionPolicyClaim {
      version: policy_version.to_string(),
      release_channel: "stable".to_string(),
      max_evidence_age_seconds: 3600,
      revocations_sha256: sha256_value(&serde_json::json!({
        "schemaVersion": 1,
        "revocations": []
      }))
      .expect("revocations hash"),
      bundle_signing_key_id: "test-key".to_string(),
    },
    artifact: AdmissionArtifactClaim {
      repository: SupplyChainRole::DataplaneStrict.repository().to_string(),
      digest: digest.clone(),
      image_reference: format!("{}@{digest}", SupplyChainRole::DataplaneStrict.repository()),
      role: "dataplane-strict".to_string(),
      source_repository: SOURCE_REPOSITORY.to_string(),
      source_ref: source_ref.clone(),
      source_revision: "d".repeat(40),
      signer_workflow: format!(
        "https://github.com/OxiBelt/OxiBelt/.github/workflows/release.yml@{source_ref}"
      ),
    },
    evidence: [
      ("provenance", PROVENANCE_PREDICATE),
      ("sbom", SBOM_PREDICATE),
      ("rebuild", REBUILD_PREDICATE),
    ]
    .into_iter()
    .map(|(kind, predicate_type)| AdmissionEvidenceClaim {
      kind: kind.to_string(),
      predicate_type: predicate_type.to_string(),
      object_sha256: evidence_digest.clone(),
      predicate_sha256: evidence_digest.clone(),
      trusted_timestamp: now,
    })
    .collect(),
    independent_rebuild: IndependentRebuildClaim {
      required_architectures: vec![
        "amd64".to_string(),
        "arm64".to_string(),
        "riscv64".to_string(),
      ],
      workflow_run_id: 42,
      workflow_run_attempt: (schema_version == 2).then_some(1),
      workflow_path: ".github/workflows/verify-release-rebuild.yml".to_string(),
      workflow_sha: "d".repeat(40),
      completed_at: now,
      receipts: ["amd64", "arm64", "riscv64"]
        .into_iter()
        .map(|arch| IndependentRebuildReceiptClaim {
          artifact_arch: arch.to_string(),
          published_digest: receipt_digest.clone(),
          platform_recipe_sha256: (schema_version == 2).then(|| receipt_digest.clone()),
          outcome: "exact".to_string(),
          archive_sha256: receipt_digest.clone(),
          object_sha256: receipt_digest.clone(),
        })
        .collect(),
    },
    workload_policy,
    decision: AdmissionDecision {
      status: "pass".to_string(),
      reasons: decision_reasons.iter().map(ToString::to_string).collect(),
      verified_at: now,
      expires_at: now + 1800,
    },
  };
  (
    sign_payload(payload, "test-key", &key).expect("signed test bundle"),
    pair.public_key().as_ref().to_vec(),
    RevocationSet {
      schema_version: 1,
      revocations: Vec::new(),
    },
  )
}

pub(crate) fn is_revoked(set: &RevocationSet, repository: &str, digest: &str, now: u64) -> bool {
  set.revocations.iter().any(|entry| {
    entry.repository == repository && entry.digest == digest && entry.effective_at <= now
  })
}

fn validate_revocations(set: &RevocationSet) -> anyhow::Result<()> {
  ensure!(
    set.schema_version == 1,
    "revocation policy schema must be 1"
  );
  ensure!(
    set.revocations.len() <= MAX_REVOCATIONS,
    "revocation policy exceeds 1024 entries"
  );
  let mut identities = BTreeSet::new();
  for entry in &set.revocations {
    ensure!(
      matches!(
        entry.repository.as_str(),
        "ghcr.io/oxibelt/oxibelt"
          | "ghcr.io/oxibelt/oxibelt-dataplane"
          | "ghcr.io/oxibelt/oxibelt-dataplane-strict"
          | "ghcr.io/oxibelt/oxibelt-gateway-controller"
          | "ghcr.io/oxibelt/oxibelt-tools"
          | "ghcr.io/oxibelt/oxibelt-keysigner"
      ),
      "revocation repository is not an official OxiBelt repository"
    );
    validate_digest(&entry.digest, "revocation digest")?;
    ensure!(
      matches!(
        entry.reason.as_str(),
        "compromised" | "withdrawn" | "policy_violation"
      ),
      "revocation reason is not in the fixed vocabulary"
    );
    ensure!(
      identities.insert((&entry.repository, &entry.digest)),
      "revocation policy contains a duplicate artifact"
    );
  }
  Ok(())
}

fn validate_release_ref(value: &str, channel: SupplyChainReleaseChannel) -> anyhow::Result<()> {
  let version = value
    .strip_prefix("refs/tags/")
    .context("source ref must be an exact refs/tags release ref")?;
  let valid = match channel {
    SupplyChainReleaseChannel::Stable => valid_core_version(version),
    SupplyChainReleaseChannel::Beta => version
      .rsplit_once("-beta.")
      .is_some_and(|(core, serial)| valid_core_version(core) && valid_decimal(serial)),
  };
  ensure!(
    valid,
    "source ref does not match the selected release channel"
  );
  Ok(())
}

fn valid_core_version(value: &str) -> bool {
  let parts = value.split('.').collect::<Vec<_>>();
  parts.len() == 3 && parts.into_iter().all(valid_decimal)
}

fn valid_decimal(value: &str) -> bool {
  !value.is_empty()
    && value.bytes().all(|byte| byte.is_ascii_digit())
    && (value == "0" || !value.starts_with('0'))
}

fn validate_digest(value: &str, label: &str) -> anyhow::Result<()> {
  ensure!(
    value
      .strip_prefix("sha256:")
      .is_some_and(|digest| is_lower_hex(digest, 64)),
    "{label} must be a lowercase SHA-256 digest"
  );
  Ok(())
}

fn validate_identifier(value: &str, maximum: usize, label: &str) -> anyhow::Result<()> {
  ensure!(
    !value.is_empty()
      && value.len() <= maximum
      && value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
    "{label} is invalid"
  );
  Ok(())
}

fn certificate_string<'a>(value: &'a Value, names: &[&str]) -> Option<&'a str> {
  names
    .iter()
    .find_map(|name| value.get(*name).and_then(Value::as_str))
}

fn read_file_bounded(path: &Path, limit: u64, label: &str) -> anyhow::Result<Vec<u8>> {
  let metadata =
    fs::metadata(path).with_context(|| format!("failed to inspect {label}: {}", path.display()))?;
  ensure!(metadata.is_file(), "{label} must be a regular file");
  ensure!(
    metadata.len() <= limit,
    "{label} exceeds its {limit}-byte limit"
  );
  let file =
    fs::File::open(path).with_context(|| format!("failed to open {label}: {}", path.display()))?;
  let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
  file
    .take(limit + 1)
    .read_to_end(&mut bytes)
    .with_context(|| format!("failed to read {label}: {}", path.display()))?;
  ensure!(
    bytes.len() as u64 <= limit,
    "{label} exceeds its {limit}-byte limit"
  );
  Ok(bytes)
}

fn sha256_value(value: &Value) -> anyhow::Result<String> {
  let canonical = canonical_value(value);
  Ok(sha256_bytes(&serde_json::to_vec(&canonical)?))
}

fn canonical_value(value: &Value) -> Value {
  match value {
    Value::Array(values) => Value::Array(values.iter().map(canonical_value).collect()),
    Value::Object(values) => {
      let sorted = values
        .iter()
        .map(|(key, value)| (key.clone(), canonical_value(value)))
        .collect::<BTreeMap<_, _>>();
      serde_json::to_value(sorted).expect("canonical JSON map serializes")
    }
    _ => value.clone(),
  }
}

fn sha256_bytes(value: &[u8]) -> String {
  format!("sha256:{}", encode_hex(Sha256::digest(value).as_ref()))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
  value.len() == length
    && value
      .bytes()
      .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn encode_hex(value: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut output = String::with_capacity(value.len() * 2);
  for byte in value {
    output.push(char::from(HEX[usize::from(byte >> 4)]));
    output.push(char::from(HEX[usize::from(byte & 0x0f)]));
  }
  output
}

fn decode_hex(value: &str, expected_bytes: usize, label: &str) -> anyhow::Result<Vec<u8>> {
  ensure!(
    value.len() == expected_bytes * 2,
    "{label} has an invalid length"
  );
  let mut output = Vec::with_capacity(expected_bytes);
  for pair in value.as_bytes().chunks_exact(2) {
    let high = hex_nibble(pair[0]).context("signature contains invalid hexadecimal")?;
    let low = hex_nibble(pair[1]).context("signature contains invalid hexadecimal")?;
    output.push((high << 4) | low);
  }
  Ok(output)
}

fn hex_nibble(value: u8) -> Option<u8> {
  match value {
    b'0'..=b'9' => Some(value - b'0'),
    b'a'..=b'f' => Some(value - b'a' + 10),
    _ => None,
  }
}

#[cfg(test)]
#[path = "supply_chain_bundle_tests.rs"]
mod tests;

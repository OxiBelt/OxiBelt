//! Local supply-chain verification and admission dispatch.

use std::io::{Cursor, Read as _};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, bail, ensure};
use flate2::read::DeflateDecoder;
use jiff::Timestamp;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncReadExt as _;

use crate::cli::{Command, SupplyChainAdmissionBundleArgs, SupplyChainSubcommand};
use crate::supply_chain_bundle::{
  BundleEvidenceInput, BundleVerificationInput, IndependentRebuildVerificationInput,
  IndependentRebuildVerificationReceipt, MAX_ATTESTATION_BYTES, MAX_REBUILD_RECEIPT_BYTES,
  derive_public_key, load_revocations, load_secret_key, now_unix_seconds, verify_and_sign_bundle,
};

const GH_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_GH_STDERR_BYTES: u64 = 64 * 1024;
const MAX_GH_RUN_BYTES: u64 = 1024 * 1024;
const MAX_GH_ARTIFACT_LIST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_GH_ARTIFACT_ARCHIVE_BYTES: u64 = 2 * 1024 * 1024;
const REBUILD_WORKFLOW_NAME: &str = "Independently verify release rebuilds";
const REBUILD_WORKFLOW_PATH: &str = ".github/workflows/verify-release-rebuild.yml";
const SOURCE_REPOSITORY: &str = "OxiBelt/OxiBelt";

pub(crate) async fn run_if_requested(command: &Command) -> anyhow::Result<Option<i32>> {
  let Command::SupplyChain(command) = command else {
    return Ok(None);
  };
  match &command.command {
    SupplyChainSubcommand::AdmissionBundle(args) => {
      generate_bundle(args).await?;
    }
    SupplyChainSubcommand::AdmissionServer(args) => {
      crate::supply_chain_admission::serve(args).await?;
    }
  }
  Ok(Some(0))
}

async fn generate_bundle(args: &SupplyChainAdmissionBundleArgs) -> anyhow::Result<()> {
  if args.output.exists() && !args.force {
    bail!(
      "refusing to overwrite existing admission bundle without --force: {}",
      args.output.display()
    );
  }
  if args
    .public_key_output
    .as_ref()
    .is_some_and(|path| path.exists() && !args.force)
  {
    bail!("refusing to overwrite existing admission public key without --force");
  }
  let verification_time = args.verification_time.map_or_else(now_unix_seconds, Ok)?;
  let (provenance, sbom, rebuild) = (
    run_gh_attestation(args, "https://slsa.dev/provenance/v1").await?,
    run_gh_attestation(args, "https://cyclonedx.org/bom").await?,
    run_gh_attestation(args, "https://oxibelt.dev/attestations/rebuild/v1").await?,
  );
  let independent_rebuild = load_independent_rebuild(args, verification_time).await?;
  let (revocations, revocations_sha256) = load_revocations(args.revocations.as_deref())?;
  let signing_key = load_secret_key(&args.signing_key_file, "bundle signing key")?;
  let public_key = derive_public_key(&signing_key)?;
  let bundle = verify_and_sign_bundle(
    BundleVerificationInput {
      repository: args.repository.clone(),
      role: args.role,
      digest: args.digest.clone(),
      source_ref: args.source_ref.clone(),
      source_revision: args.source_revision.clone(),
      release_channel: args.release_channel,
      verification_time,
      max_evidence_age_seconds: args.max_evidence_age_seconds,
      expires_after_seconds: args.expires_after_seconds,
      key_id: args.key_id.clone(),
    },
    BundleEvidenceInput {
      provenance,
      sbom,
      rebuild,
      independent_rebuild,
    },
    &revocations,
    &revocations_sha256,
    &signing_key,
  )?;
  if let Some(path) = &args.public_key_output {
    write_bytes_atomic(path, &public_key, args.force, "admission public key")?;
  }
  write_json_atomic(&args.output, &bundle, args.force)?;
  println!(
    "{}",
    serde_json::to_string_pretty(&serde_json::json!({
      "status": "pass",
      "bundle": args.output,
      "payloadDigest": bundle.signature.payload_sha256,
      "expiresAt": bundle.payload.decision.expires_at,
    }))?
  );
  Ok(())
}

async fn run_gh_attestation(
  args: &SupplyChainAdmissionBundleArgs,
  predicate_type: &str,
) -> anyhow::Result<Value> {
  let subject = format!("oci://{}@{}", args.repository, args.digest);
  let signer = "OxiBelt/OxiBelt/.github/workflows/release.yml";
  let mut child = tokio::process::Command::new("gh")
    .args([
      "attestation",
      "verify",
      &subject,
      "--repo",
      "OxiBelt/OxiBelt",
      "--signer-workflow",
      signer,
      "--signer-digest",
      &args.source_revision,
      "--source-digest",
      &args.source_revision,
      "--source-ref",
      &args.source_ref,
      "--cert-oidc-issuer",
      "https://token.actions.githubusercontent.com",
      "--deny-self-hosted-runners",
      "--predicate-type",
      predicate_type,
      "--limit",
      "100",
      "--format",
      "json",
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true)
    .spawn()
    .context("failed to start gh attestation verification")?;
  let stdout = child.stdout.take().context("failed to capture gh stdout")?;
  let stderr = child.stderr.take().context("failed to capture gh stderr")?;
  let stdout_task = tokio::spawn(read_stream_bounded(stdout, MAX_ATTESTATION_BYTES));
  let stderr_task = tokio::spawn(read_stream_bounded(stderr, MAX_GH_STDERR_BYTES));
  let status = match tokio::time::timeout(GH_TIMEOUT, child.wait()).await {
    Ok(result) => result.context("failed to wait for gh attestation verification")?,
    Err(_) => {
      let _ = child.kill().await;
      let _ = child.wait().await;
      bail!("gh attestation verification exceeded its 60-second deadline");
    }
  };
  let stdout = stdout_task
    .await
    .context("gh stdout reader task failed")??;
  let stderr = stderr_task
    .await
    .context("gh stderr reader task failed")??;
  ensure!(
    stdout.len() as u64 <= MAX_ATTESTATION_BYTES,
    "gh attestation response exceeds the 16 MiB input limit"
  );
  ensure!(
    stderr.len() as u64 <= MAX_GH_STDERR_BYTES,
    "gh attestation diagnostic exceeds the 64 KiB limit"
  );
  if !status.success() {
    let diagnostic = String::from_utf8_lossy(&stderr);
    bail!(
      "gh attestation verification failed for {predicate_type}: {}",
      diagnostic.trim()
    );
  }
  serde_json::from_slice(&stdout).context("gh attestation verification returned invalid JSON")
}

#[derive(Debug, Deserialize)]
struct GitHubRepository {
  full_name: String,
}

#[derive(Debug, Deserialize)]
struct GitHubWorkflowRun {
  id: u64,
  name: String,
  path: String,
  event: String,
  status: String,
  conclusion: Option<String>,
  head_sha: String,
  updated_at: String,
  repository: GitHubRepository,
}

#[derive(Debug, Deserialize)]
struct GitHubArtifactList {
  total_count: usize,
  artifacts: Vec<GitHubArtifact>,
}

#[derive(Debug, Deserialize)]
struct GitHubArtifact {
  id: u64,
  name: String,
  size_in_bytes: u64,
  expired: bool,
  digest: Option<String>,
  workflow_run: Option<GitHubArtifactWorkflowRun>,
}

#[derive(Debug, Deserialize)]
struct GitHubArtifactWorkflowRun {
  id: u64,
}

async fn load_independent_rebuild(
  args: &SupplyChainAdmissionBundleArgs,
  verification_time: u64,
) -> anyhow::Result<IndependentRebuildVerificationInput> {
  ensure!(
    args.independent_rebuild_run_id > 0,
    "independent rebuild workflow run id must be positive"
  );
  let run_endpoint = format!(
    "repos/{SOURCE_REPOSITORY}/actions/runs/{}",
    args.independent_rebuild_run_id
  );
  let run: GitHubWorkflowRun = serde_json::from_slice(
    &run_gh_api(
      &run_endpoint,
      MAX_GH_RUN_BYTES,
      "independent rebuild workflow run",
    )
    .await?,
  )
  .context("GitHub returned an invalid independent rebuild workflow run")?;
  validate_workflow_run(&run, args, verification_time)?;

  let artifacts_endpoint = format!(
    "repos/{SOURCE_REPOSITORY}/actions/runs/{}/artifacts?per_page=100",
    args.independent_rebuild_run_id
  );
  let artifact_list: GitHubArtifactList = serde_json::from_slice(
    &run_gh_api(
      &artifacts_endpoint,
      MAX_GH_ARTIFACT_LIST_BYTES,
      "independent rebuild artifact list",
    )
    .await?,
  )
  .context("GitHub returned an invalid independent rebuild artifact list")?;
  ensure!(
    artifact_list.total_count <= 100 && artifact_list.artifacts.len() <= 100,
    "independent rebuild workflow exposes more than 100 artifacts"
  );

  let mut receipts = Vec::with_capacity(3);
  for arch in ["amd64", "arm64", "riscv64"] {
    let expected_name = format!("rebuild-receipt-{}-{arch}", args.role.as_str());
    let matches = artifact_list
      .artifacts
      .iter()
      .filter(|artifact| artifact.name == expected_name)
      .collect::<Vec<_>>();
    ensure!(
      matches.len() == 1,
      "independent rebuild run must contain exactly one {expected_name} artifact"
    );
    let artifact = matches[0];
    validate_artifact_metadata(artifact, args.independent_rebuild_run_id)?;
    let archive_sha256 = artifact
      .digest
      .as_deref()
      .context("independent rebuild artifact is missing its immutable archive digest")?;
    validate_sha256(
      archive_sha256,
      "independent rebuild artifact archive digest",
    )?;
    let endpoint = format!(
      "repos/{SOURCE_REPOSITORY}/actions/artifacts/{}/zip",
      artifact.id
    );
    let archive = run_gh_api(
      &endpoint,
      MAX_GH_ARTIFACT_ARCHIVE_BYTES,
      "independent rebuild artifact archive",
    )
    .await?;
    ensure!(
      sha256_bytes(&archive) == archive_sha256,
      "downloaded independent rebuild artifact archive digest does not match GitHub metadata"
    );
    let receipt = extract_receipt(&archive, &expected_name)?;
    validate_receipt_identity(&receipt, args, args.independent_rebuild_run_id, arch)?;
    receipts.push(IndependentRebuildVerificationReceipt {
      artifact_arch: arch.to_string(),
      archive_sha256: archive_sha256.to_string(),
      receipt,
    });
  }

  Ok(IndependentRebuildVerificationInput {
    workflow_run_id: run.id,
    workflow_path: run.path,
    workflow_sha: run.head_sha,
    completed_at: parse_timestamp(&run.updated_at, "workflow run completion")?,
    receipts,
  })
}

fn validate_workflow_run(
  run: &GitHubWorkflowRun,
  args: &SupplyChainAdmissionBundleArgs,
  verification_time: u64,
) -> anyhow::Result<()> {
  ensure!(
    run.id == args.independent_rebuild_run_id,
    "GitHub returned the wrong independent rebuild workflow run"
  );
  ensure!(
    run.repository.full_name == SOURCE_REPOSITORY,
    "independent rebuild workflow run belongs to the wrong repository"
  );
  ensure!(
    run.name == REBUILD_WORKFLOW_NAME && run.path == REBUILD_WORKFLOW_PATH,
    "independent rebuild workflow identity is not trusted"
  );
  ensure!(
    run.event == "workflow_run",
    "manual independent rebuild runs cannot satisfy release admission"
  );
  ensure!(
    run.status == "completed" && run.conclusion.as_deref() == Some("success"),
    "independent rebuild workflow run did not complete successfully"
  );
  ensure!(
    is_lower_hex(&args.independent_rebuild_workflow_sha, 40),
    "approved independent rebuild workflow revision must be a full lowercase Git commit"
  );
  ensure!(
    run.head_sha == args.independent_rebuild_workflow_sha,
    "independent rebuild workflow revision does not match the approved revision"
  );
  let completed_at = parse_timestamp(&run.updated_at, "workflow run completion")?;
  ensure!(
    completed_at <= verification_time.saturating_add(300),
    "independent rebuild workflow completion is unacceptably in the future"
  );
  ensure!(
    verification_time.saturating_sub(completed_at) <= args.max_evidence_age_seconds,
    "independent rebuild workflow evidence is stale"
  );
  Ok(())
}

fn validate_artifact_metadata(artifact: &GitHubArtifact, run_id: u64) -> anyhow::Result<()> {
  ensure!(
    artifact.id > 0,
    "independent rebuild artifact id is invalid"
  );
  ensure!(
    !artifact.expired,
    "independent rebuild artifact has expired"
  );
  ensure!(
    (1..=MAX_GH_ARTIFACT_ARCHIVE_BYTES).contains(&artifact.size_in_bytes),
    "independent rebuild artifact archive size is invalid"
  );
  ensure!(
    artifact.workflow_run.as_ref().map(|run| run.id) == Some(run_id),
    "independent rebuild artifact belongs to the wrong workflow run"
  );
  Ok(())
}

fn extract_receipt(archive: &[u8], artifact_name: &str) -> anyhow::Result<Value> {
  let eocd_offset = archive
    .windows(4)
    .rposition(|window| window == b"PK\x05\x06")
    .context("independent rebuild artifact has no ZIP end record")?;
  ensure!(
    eocd_offset.checked_add(22) == Some(archive.len())
      && zip_u16(archive, eocd_offset + 4)? == 0
      && zip_u16(archive, eocd_offset + 6)? == 0
      && zip_u16(archive, eocd_offset + 8)? == 1
      && zip_u16(archive, eocd_offset + 10)? == 1
      && zip_u16(archive, eocd_offset + 20)? == 0,
    "independent rebuild artifact archive must contain exactly one file"
  );
  let central_size = zip_usize_u32(archive, eocd_offset + 12)?;
  let central_offset = zip_usize_u32(archive, eocd_offset + 16)?;
  ensure!(
    central_offset.checked_add(central_size) == Some(eocd_offset)
      && archive.get(central_offset..central_offset + 4) == Some(b"PK\x01\x02"),
    "independent rebuild artifact central directory is invalid"
  );
  let flags = zip_u16(archive, central_offset + 8)?;
  let method = zip_u16(archive, central_offset + 10)?;
  let expected_crc = zip_u32(archive, central_offset + 16)?;
  let compressed_size = zip_usize_u32(archive, central_offset + 20)?;
  let uncompressed_size = zip_usize_u32(archive, central_offset + 24)?;
  let name_length = usize::from(zip_u16(archive, central_offset + 28)?);
  let extra_length = usize::from(zip_u16(archive, central_offset + 30)?);
  let comment_length = usize::from(zip_u16(archive, central_offset + 32)?);
  let local_offset = zip_usize_u32(archive, central_offset + 42)?;
  ensure!(
    flags & !0x0808 == 0 && matches!(method, 0 | 8),
    "independent rebuild artifact uses unsupported ZIP features"
  );
  ensure!(
    uncompressed_size as u64 <= MAX_REBUILD_RECEIPT_BYTES,
    "independent rebuild receipt exceeds the 1 MiB input limit"
  );
  let central_end = central_offset
    .checked_add(46)
    .and_then(|value| value.checked_add(name_length))
    .and_then(|value| value.checked_add(extra_length))
    .and_then(|value| value.checked_add(comment_length))
    .context("independent rebuild artifact central directory overflows")?;
  ensure!(
    central_end == eocd_offset && local_offset == 0,
    "independent rebuild artifact has a non-canonical ZIP layout"
  );
  let expected_name = format!("{artifact_name}.json");
  let central_name = archive
    .get(central_offset + 46..central_offset + 46 + name_length)
    .context("independent rebuild artifact filename is truncated")?;
  ensure!(
    central_name == expected_name.as_bytes(),
    "independent rebuild artifact archive contains an unexpected path"
  );
  ensure!(
    archive.get(local_offset..local_offset + 4) == Some(b"PK\x03\x04")
      && zip_u16(archive, local_offset + 6)? == flags
      && zip_u16(archive, local_offset + 8)? == method,
    "independent rebuild artifact local ZIP header is invalid"
  );
  let local_name_length = usize::from(zip_u16(archive, local_offset + 26)?);
  let local_extra_length = usize::from(zip_u16(archive, local_offset + 28)?);
  let data_offset = local_offset
    .checked_add(30)
    .and_then(|value| value.checked_add(local_name_length))
    .and_then(|value| value.checked_add(local_extra_length))
    .context("independent rebuild artifact local header overflows")?;
  ensure!(
    archive.get(local_offset + 30..local_offset + 30 + local_name_length)
      == Some(expected_name.as_bytes()),
    "independent rebuild artifact local filename is invalid"
  );
  if flags & 0x0008 == 0 {
    ensure!(
      zip_u32(archive, local_offset + 14)? == expected_crc
        && zip_usize_u32(archive, local_offset + 18)? == compressed_size
        && zip_usize_u32(archive, local_offset + 22)? == uncompressed_size,
      "independent rebuild artifact ZIP headers disagree"
    );
  }
  let data_end = data_offset
    .checked_add(compressed_size)
    .context("independent rebuild artifact data range overflows")?;
  let compressed = archive
    .get(data_offset..data_end)
    .context("independent rebuild artifact data is truncated")?;
  validate_zip_descriptor(
    archive
      .get(data_end..central_offset)
      .context("independent rebuild artifact data overlaps its central directory")?,
    flags,
    expected_crc,
    compressed_size,
    uncompressed_size,
  )?;
  let mut bytes = Vec::new();
  match method {
    0 => bytes.extend_from_slice(compressed),
    8 => {
      DeflateDecoder::new(Cursor::new(compressed))
        .take(MAX_REBUILD_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("failed to decompress independent rebuild receipt")?;
    }
    _ => bail!("independent rebuild artifact uses an unsupported ZIP method"),
  }
  ensure!(
    bytes.len() == uncompressed_size && crc32fast::hash(&bytes) == expected_crc,
    "independent rebuild receipt size or checksum is invalid"
  );
  serde_json::from_slice(&bytes).context("independent rebuild receipt is not valid JSON")
}

fn validate_zip_descriptor(
  descriptor: &[u8],
  flags: u16,
  expected_crc: u32,
  compressed_size: usize,
  uncompressed_size: usize,
) -> anyhow::Result<()> {
  if flags & 0x0008 == 0 {
    ensure!(
      descriptor.is_empty(),
      "ZIP archive contains trailing local data"
    );
    return Ok(());
  }
  let offset = usize::from(descriptor.starts_with(b"PK\x07\x08")) * 4;
  ensure!(
    descriptor.len() == offset + 12
      && zip_u32(descriptor, offset)? == expected_crc
      && zip_usize_u32(descriptor, offset + 4)? == compressed_size
      && zip_usize_u32(descriptor, offset + 8)? == uncompressed_size,
    "independent rebuild artifact ZIP data descriptor is invalid"
  );
  Ok(())
}

fn zip_u16(bytes: &[u8], offset: usize) -> anyhow::Result<u16> {
  let value = bytes
    .get(offset..offset + 2)
    .context("independent rebuild artifact ZIP field is truncated")?;
  Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn zip_u32(bytes: &[u8], offset: usize) -> anyhow::Result<u32> {
  let value = bytes
    .get(offset..offset + 4)
    .context("independent rebuild artifact ZIP field is truncated")?;
  Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn zip_usize_u32(bytes: &[u8], offset: usize) -> anyhow::Result<usize> {
  usize::try_from(zip_u32(bytes, offset)?)
    .context("independent rebuild artifact ZIP field exceeds addressable memory")
}

fn validate_receipt_identity(
  receipt: &Value,
  args: &SupplyChainAdmissionBundleArgs,
  run_id: u64,
  arch: &str,
) -> anyhow::Result<()> {
  ensure!(
    receipt.get("schemaVersion").and_then(Value::as_u64) == Some(1),
    "independent rebuild receipt schema must be 1"
  );
  let exact = |pointer: &str, expected: &str| {
    receipt.pointer(pointer).and_then(Value::as_str) == Some(expected)
  };
  ensure!(
    exact("/source/repository", SOURCE_REPOSITORY)
      && exact("/source/ref", &args.source_ref)
      && exact("/source/revision", &args.source_revision)
      && exact("/build/role", args.role.as_str())
      && exact("/build/artifactArch", arch)
      && exact("/workflow/repository", SOURCE_REPOSITORY)
      && exact("/workflow/path", REBUILD_WORKFLOW_PATH)
      && receipt.pointer("/workflow/runId").and_then(Value::as_u64) == Some(run_id),
    "independent rebuild receipt identity does not match the requested release"
  );
  Ok(())
}

async fn run_gh_api(endpoint: &str, limit: u64, label: &str) -> anyhow::Result<Vec<u8>> {
  let mut child = tokio::process::Command::new("gh")
    .args(["api", "--method", "GET", endpoint])
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true)
    .spawn()
    .with_context(|| format!("failed to start gh API request for {label}"))?;
  let stdout = child.stdout.take().context("failed to capture gh stdout")?;
  let stderr = child.stderr.take().context("failed to capture gh stderr")?;
  let stdout_task = tokio::spawn(read_stream_bounded(stdout, limit));
  let stderr_task = tokio::spawn(read_stream_bounded(stderr, MAX_GH_STDERR_BYTES));
  let status = match tokio::time::timeout(GH_TIMEOUT, child.wait()).await {
    Ok(result) => {
      result.with_context(|| format!("failed to wait for gh API request for {label}"))?
    }
    Err(_) => {
      let _ = child.kill().await;
      let _ = child.wait().await;
      bail!("gh API request for {label} exceeded its 60-second deadline");
    }
  };
  let stdout = stdout_task
    .await
    .context("gh stdout reader task failed")??;
  let stderr = stderr_task
    .await
    .context("gh stderr reader task failed")??;
  ensure!(
    stdout.len() as u64 <= limit,
    "gh API response for {label} exceeds its input limit"
  );
  ensure!(
    stderr.len() as u64 <= MAX_GH_STDERR_BYTES,
    "gh API diagnostic exceeds the 64 KiB limit"
  );
  if !status.success() {
    let diagnostic = String::from_utf8_lossy(&stderr);
    bail!("gh API request for {label} failed: {}", diagnostic.trim());
  }
  Ok(stdout)
}

fn parse_timestamp(value: &str, label: &str) -> anyhow::Result<u64> {
  let timestamp = value
    .parse::<Timestamp>()
    .with_context(|| format!("{label} is not RFC 3339"))?
    .as_second();
  u64::try_from(timestamp).with_context(|| format!("{label} predates the Unix epoch"))
}

fn validate_sha256(value: &str, label: &str) -> anyhow::Result<()> {
  let digest = value
    .strip_prefix("sha256:")
    .with_context(|| format!("{label} must use sha256"))?;
  ensure!(
    digest.len() == 64
      && digest
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
    "{label} must be a lowercase SHA-256 digest"
  );
  Ok(())
}

fn is_lower_hex(value: &str, length: usize) -> bool {
  value.len() == length
    && value
      .bytes()
      .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn sha256_bytes(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let digest = Sha256::digest(bytes);
  let mut output = String::with_capacity(71);
  output.push_str("sha256:");
  for byte in digest {
    output.push(char::from(HEX[usize::from(byte >> 4)]));
    output.push(char::from(HEX[usize::from(byte & 0x0f)]));
  }
  output
}

async fn read_stream_bounded(
  stream: impl tokio::io::AsyncRead + Unpin,
  limit: u64,
) -> anyhow::Result<Vec<u8>> {
  let mut bytes = Vec::new();
  stream.take(limit + 1).read_to_end(&mut bytes).await?;
  Ok(bytes)
}

fn write_json_atomic<T: serde::Serialize>(
  path: &Path,
  value: &T,
  overwrite: bool,
) -> anyhow::Result<()> {
  let parent = path
    .parent()
    .filter(|parent| !parent.as_os_str().is_empty())
    .unwrap_or_else(|| Path::new("."));
  ensure!(
    parent.is_dir(),
    "admission bundle output parent must be a directory"
  );
  let mut temporary = tempfile::NamedTempFile::new_in(parent)
    .context("failed to create temporary admission bundle")?;
  serde_json::to_writer_pretty(&mut temporary, value)?;
  use std::io::Write as _;
  temporary.write_all(b"\n")?;
  temporary.as_file().sync_all()?;
  if overwrite {
    temporary
      .persist(path)
      .map_err(|error| error.error)
      .context("failed to persist admission bundle")?;
  } else {
    temporary
      .persist_noclobber(path)
      .map_err(|error| error.error)
      .context("failed to persist admission bundle without overwrite")?;
  }
  Ok(())
}

fn write_bytes_atomic(
  path: &Path,
  value: &[u8],
  overwrite: bool,
  label: &str,
) -> anyhow::Result<()> {
  let parent = path
    .parent()
    .filter(|parent| !parent.as_os_str().is_empty())
    .unwrap_or_else(|| Path::new("."));
  ensure!(parent.is_dir(), "{label} output parent must be a directory");
  let mut temporary = tempfile::NamedTempFile::new_in(parent)
    .with_context(|| format!("failed to create temporary {label}"))?;
  use std::io::Write as _;
  temporary.write_all(value)?;
  temporary.as_file().sync_all()?;
  if overwrite {
    temporary
      .persist(path)
      .map_err(|error| error.error)
      .with_context(|| format!("failed to persist {label}"))?;
  } else {
    temporary
      .persist_noclobber(path)
      .map_err(|error| error.error)
      .with_context(|| format!("failed to persist {label} without overwrite"))?;
  }
  Ok(())
}

#[cfg(test)]
#[path = "supply_chain_tests.rs"]
mod tests;

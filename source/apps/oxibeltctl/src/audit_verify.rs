use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use anyhow::{Context, bail, ensure};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::audit_verify_evidence::verify_evidence;
use crate::audit_verify_postgres::load_verification_evidence;
use crate::cli::{AdminAuditSubcommand, Command, OutputFormat};

pub(crate) const VERIFICATION_SCHEMA_VERSION: &str = "oxibelt.admin.audit.verification/v1";
const EXPECTED_STREAMS_SCHEMA_VERSION: &str = "oxibelt.admin.audit.expected-streams/v1";
const WITNESS_SCHEMA_VERSION: &str = "oxibelt.admin.audit.witness/v1";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExpectedStreamsManifest {
  pub(crate) schema_version: String,
  pub(crate) namespace: String,
  pub(crate) streams: Vec<ExpectedStream>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExpectedStream {
  pub(crate) stream_id: String,
  pub(crate) instance_id: String,
  #[serde(default)]
  pub(crate) cluster_id: Option<String>,
  #[serde(default)]
  pub(crate) accepted_epoch_history: Vec<ExpectedStreamEpoch>,
  pub(crate) membership_epoch: String,
  pub(crate) deployment_epoch: String,
  pub(crate) signing_key_schedule: Vec<ExpectedSigningKeyRange>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExpectedStreamEpoch {
  pub(crate) membership_epoch: String,
  pub(crate) deployment_epoch: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExpectedSigningKeyRange {
  pub(crate) key_id: String,
  pub(crate) first_checkpoint_ordinal: u64,
  #[serde(default)]
  pub(crate) last_checkpoint_ordinal: Option<u64>,
}

impl ExpectedStream {
  pub(crate) fn epoch_position(
    &self,
    membership_epoch: &str,
    deployment_epoch: &str,
  ) -> Option<usize> {
    self
      .accepted_epoch_history
      .iter()
      .position(|epoch| {
        epoch.membership_epoch == membership_epoch && epoch.deployment_epoch == deployment_epoch
      })
      .or_else(|| {
        (self.membership_epoch == membership_epoch && self.deployment_epoch == deployment_epoch)
          .then_some(self.accepted_epoch_history.len())
      })
  }

  pub(crate) fn is_current_epoch(&self, membership_epoch: &str, deployment_epoch: &str) -> bool {
    self.membership_epoch == membership_epoch && self.deployment_epoch == deployment_epoch
  }

  pub(crate) fn signing_key_allowed(&self, key_id: &str, checkpoint_ordinal: u64) -> bool {
    self.signing_key_schedule.iter().any(|range| {
      range.key_id == key_id
        && checkpoint_ordinal >= range.first_checkpoint_ordinal
        && range
          .last_checkpoint_ordinal
          .is_none_or(|last| checkpoint_ordinal <= last)
    })
  }
}

#[derive(Clone, Debug)]
pub(crate) struct TrustedKey {
  pub(crate) key_id: String,
  pub(crate) public_key: Vec<u8>,
}

#[derive(Clone)]
pub(crate) struct TrustedHmacKey {
  pub(crate) key_id: String,
  pub(crate) key: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditWitness {
  pub(crate) schema_version: String,
  pub(crate) namespace: String,
  pub(crate) streams: BTreeMap<String, WitnessHead>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WitnessHead {
  pub(crate) checkpoint_ordinal: u64,
  pub(crate) checkpoint_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VerificationStatus {
  Valid,
  Incomplete,
  Invalid,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct VerificationReport {
  pub(crate) schema_version: &'static str,
  pub(crate) status: VerificationStatus,
  pub(crate) namespace: String,
  pub(crate) streams_expected: usize,
  pub(crate) streams_verified: usize,
  pub(crate) events_verified: usize,
  pub(crate) checkpoints_verified: usize,
  pub(crate) findings: Vec<VerificationFinding>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct VerificationFinding {
  pub(crate) code: &'static str,
  pub(crate) status: VerificationStatus,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(crate) stream_id: Option<String>,
}

impl VerificationReport {
  pub(crate) fn new(namespace: String, streams_expected: usize) -> Self {
    Self {
      schema_version: VERIFICATION_SCHEMA_VERSION,
      status: VerificationStatus::Valid,
      namespace,
      streams_expected,
      streams_verified: 0,
      events_verified: 0,
      checkpoints_verified: 0,
      findings: Vec::new(),
    }
  }

  pub(crate) fn finding(
    &mut self,
    code: &'static str,
    status: VerificationStatus,
    stream_id: Option<&str>,
  ) {
    self.status = self.status.max(status);
    self.findings.push(VerificationFinding {
      code,
      status,
      stream_id: stream_id.map(str::to_string),
    });
  }

  fn exit_code(&self) -> i32 {
    if self.status == VerificationStatus::Valid {
      0
    } else {
      2
    }
  }
}

pub(crate) async fn run_local_if_requested(
  command: &Command,
  output: OutputFormat,
) -> anyhow::Result<Option<i32>> {
  let Command::Audit(args) = command else {
    return Ok(None);
  };
  let Some(AdminAuditSubcommand::Verify(args)) = args.command.as_ref() else {
    return Ok(None);
  };

  let _witness_lock = lock_witness(&args.witness)?;
  let manifest = load_manifest(&args.expected_streams)?;
  let trusted_keys = load_trusted_keys(&args.trusted_keys)?;
  let trusted_hmac_keys = load_trusted_hmac_keys(&args.trusted_hmac_keys)?;
  let prior_witness = load_witness(&args.witness, &manifest, args.initialize_witness)?;
  let evidence = load_verification_evidence(args, &manifest).await?;
  let (mut report, next_witness) = verify_evidence(
    &manifest,
    &trusted_keys,
    &trusted_hmac_keys,
    prior_witness.as_ref(),
    evidence,
  )?;

  if prior_witness.is_none() && !args.initialize_witness {
    report.finding(
      "witness_initialization_required",
      VerificationStatus::Incomplete,
      None,
    );
  } else if report.status == VerificationStatus::Valid {
    write_witness(&args.witness, &next_witness)?;
  }

  match output {
    OutputFormat::PrettyJson => println!("{}", serde_json::to_string_pretty(&report)?),
    OutputFormat::Json => println!("{}", serde_json::to_string(&report)?),
  }
  Ok(Some(report.exit_code()))
}

struct WitnessLock(File);

impl Drop for WitnessLock {
  fn drop(&mut self) {
    let _ = self.0.unlock();
  }
}

fn lock_witness(path: &Path) -> anyhow::Result<WitnessLock> {
  let file_name = path
    .file_name()
    .context("audit witness path must have a file name")?;
  let mut lock_name = file_name.to_os_string();
  lock_name.push(".lock");
  let lock_path = path.with_file_name(lock_name);
  let file = OpenOptions::new()
    .read(true)
    .write(true)
    .create(true)
    .mode(0o600)
    .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
    .open(&lock_path)
    .with_context(|| format!("failed to open audit witness lock {}", lock_path.display()))?;
  file
    .lock()
    .with_context(|| format!("failed to lock audit witness {}", lock_path.display()))?;
  Ok(WitnessLock(file))
}

fn load_manifest(path: &Path) -> anyhow::Result<ExpectedStreamsManifest> {
  let bytes = fs::read(path)
    .with_context(|| format!("failed to read expected-stream manifest {}", path.display()))?;
  let manifest: ExpectedStreamsManifest = serde_json::from_slice(&bytes).with_context(|| {
    format!(
      "failed to parse expected-stream manifest {}",
      path.display()
    )
  })?;
  ensure!(
    manifest.schema_version == EXPECTED_STREAMS_SCHEMA_VERSION,
    "expected-stream manifest schema_version must be {EXPECTED_STREAMS_SCHEMA_VERSION}"
  );
  validate_identifier(&manifest.namespace, "expected-stream namespace")?;
  ensure!(
    !manifest.streams.is_empty(),
    "expected-stream manifest must contain at least one stream"
  );
  ensure!(
    manifest.streams.len() <= 10_000,
    "expected-stream manifest may contain at most 10000 streams"
  );
  let mut stream_ids = HashSet::new();
  let mut instance_ids = HashSet::new();
  for stream in &manifest.streams {
    validate_identifier(&stream.stream_id, "expected stream ID")?;
    validate_identifier(&stream.instance_id, "expected instance ID")?;
    validate_identifier(&stream.membership_epoch, "expected membership epoch")?;
    validate_identifier(&stream.deployment_epoch, "expected deployment epoch")?;
    ensure!(
      stream.accepted_epoch_history.len() <= 1024,
      "expected stream {} may contain at most 1024 historical epochs",
      stream.stream_id
    );
    let mut epoch_pairs = HashSet::new();
    for epoch in &stream.accepted_epoch_history {
      validate_identifier(
        &epoch.membership_epoch,
        "historical expected membership epoch",
      )?;
      validate_identifier(
        &epoch.deployment_epoch,
        "historical expected deployment epoch",
      )?;
      ensure!(
        epoch_pairs.insert((
          epoch.membership_epoch.as_str(),
          epoch.deployment_epoch.as_str()
        )),
        "expected stream {} contains a duplicate historical epoch pair",
        stream.stream_id
      );
    }
    ensure!(
      epoch_pairs.insert((
        stream.membership_epoch.as_str(),
        stream.deployment_epoch.as_str()
      )),
      "expected stream {} current epoch duplicates its historical epoch list",
      stream.stream_id
    );
    ensure!(
      !stream.signing_key_schedule.is_empty(),
      "expected stream {} must contain a signing-key schedule",
      stream.stream_id
    );
    ensure!(
      stream.signing_key_schedule.len() <= 1024,
      "expected stream {} may contain at most 1024 signing-key ranges",
      stream.stream_id
    );
    let mut expected_first_ordinal = 1_u64;
    let mut signing_key_ids = HashSet::new();
    for (index, range) in stream.signing_key_schedule.iter().enumerate() {
      validate_identifier(&range.key_id, "expected checkpoint signing key ID")?;
      ensure!(
        signing_key_ids.insert(range.key_id.as_str()),
        "expected stream {} reuses checkpoint signing key ID {}",
        stream.stream_id,
        range.key_id
      );
      ensure!(
        range.first_checkpoint_ordinal == expected_first_ordinal,
        "expected stream {} signing-key schedule is not contiguous",
        stream.stream_id
      );
      match range.last_checkpoint_ordinal {
        Some(last) => {
          ensure!(
            last >= range.first_checkpoint_ordinal,
            "expected stream {} signing-key range is reversed",
            stream.stream_id
          );
          expected_first_ordinal = last.checked_add(1).with_context(|| {
            format!(
              "expected stream {} signing-key ordinal is exhausted",
              stream.stream_id
            )
          })?;
        }
        None => ensure!(
          index + 1 == stream.signing_key_schedule.len(),
          "expected stream {} has an open signing-key range before its final entry",
          stream.stream_id
        ),
      }
    }
    if let Some(cluster_id) = &stream.cluster_id {
      validate_identifier(cluster_id, "expected cluster ID")?;
    }
    ensure!(
      stream_ids.insert(stream.stream_id.as_str()),
      "expected-stream manifest contains duplicate stream ID {}",
      stream.stream_id
    );
    ensure!(
      instance_ids.insert(stream.instance_id.as_str()),
      "expected-stream manifest contains duplicate instance ID {}",
      stream.instance_id
    );
  }
  Ok(manifest)
}

fn load_trusted_keys(values: &[String]) -> anyhow::Result<BTreeMap<String, TrustedKey>> {
  let mut keys = BTreeMap::new();
  for value in values {
    let (key_id, path) = value
      .split_once('=')
      .context("--trusted-key must use KEY_ID=FILE")?;
    validate_identifier(key_id, "trusted key ID")?;
    ensure!(
      !path.is_empty(),
      "trusted public-key path must not be empty"
    );
    let public_key =
      fs::read(path).with_context(|| format!("failed to read trusted public key {key_id}"))?;
    ensure!(
      public_key.len() == 32,
      "trusted Ed25519 public key {key_id} must contain exactly 32 raw bytes"
    );
    let prior = keys.insert(
      key_id.to_string(),
      TrustedKey {
        key_id: key_id.to_string(),
        public_key,
      },
    );
    ensure!(prior.is_none(), "trusted key ID {key_id} is duplicated");
  }
  Ok(keys)
}

fn load_trusted_hmac_keys(values: &[String]) -> anyhow::Result<BTreeMap<String, TrustedHmacKey>> {
  let mut keys = BTreeMap::new();
  for value in values {
    let (key_id, path) = value
      .split_once('=')
      .context("--trusted-hmac-key must use KEY_ID=FILE")?;
    validate_identifier(key_id, "trusted HMAC key ID")?;
    ensure!(!path.is_empty(), "trusted HMAC key path must not be empty");
    let metadata =
      fs::metadata(path).with_context(|| format!("failed to inspect trusted HMAC key {key_id}"))?;
    ensure!(
      metadata.is_file(),
      "trusted HMAC key {key_id} is not a file"
    );
    #[cfg(unix)]
    {
      use std::os::unix::fs::PermissionsExt as _;
      ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "trusted HMAC key {key_id} must not be accessible by group or other users"
      );
    }
    let key = Zeroizing::new(
      fs::read(path).with_context(|| format!("failed to read trusted HMAC key {key_id}"))?,
    );
    ensure!(
      key.len() == 32,
      "trusted HMAC key {key_id} must contain exactly 32 raw bytes"
    );
    let prior = keys.insert(
      key_id.to_string(),
      TrustedHmacKey {
        key_id: key_id.to_string(),
        key,
      },
    );
    ensure!(
      prior.is_none(),
      "trusted HMAC key ID {key_id} is duplicated"
    );
  }
  Ok(keys)
}

fn load_witness(
  path: &Path,
  manifest: &ExpectedStreamsManifest,
  initialize: bool,
) -> anyhow::Result<Option<AuditWitness>> {
  let bytes = match fs::read(path) {
    Ok(bytes) => bytes,
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      if initialize {
        return Ok(None);
      }
      return Ok(None);
    }
    Err(error) => {
      return Err(error)
        .with_context(|| format!("failed to read audit witness {}", path.display()));
    }
  };
  if initialize {
    bail!(
      "--initialize-witness refuses to replace existing witness {}",
      path.display()
    );
  }
  let witness: AuditWitness = serde_json::from_slice(&bytes)
    .with_context(|| format!("failed to parse audit witness {}", path.display()))?;
  ensure!(
    witness.schema_version == WITNESS_SCHEMA_VERSION,
    "audit witness schema_version must be {WITNESS_SCHEMA_VERSION}"
  );
  ensure!(
    witness.namespace == manifest.namespace,
    "audit witness namespace does not match the expected-stream manifest"
  );
  Ok(Some(witness))
}

fn write_witness(path: &Path, witness: &AuditWitness) -> anyhow::Result<()> {
  let parent = path
    .parent()
    .filter(|parent| !parent.as_os_str().is_empty())
    .unwrap_or_else(|| Path::new("."));
  let mut temporary = tempfile::Builder::new()
    .prefix(".oxibelt-audit-witness-")
    .tempfile_in(parent)
    .with_context(|| format!("failed to create witness beside {}", path.display()))?;
  serde_json::to_writer_pretty(&mut temporary, witness)?;
  temporary.write_all(b"\n")?;
  temporary.as_file_mut().sync_all()?;
  temporary
    .persist(path)
    .map_err(|error| error.error)
    .with_context(|| format!("failed to atomically persist witness {}", path.display()))?;
  File::open(parent)?.sync_all()?;
  Ok(())
}

pub(crate) fn new_witness(
  namespace: String,
  streams: BTreeMap<String, WitnessHead>,
) -> AuditWitness {
  AuditWitness {
    schema_version: WITNESS_SCHEMA_VERSION.to_string(),
    namespace,
    streams,
  }
}

fn validate_identifier(value: &str, label: &str) -> anyhow::Result<()> {
  ensure!(
    !value.is_empty() && value.trim() == value,
    "{label} must not be empty or padded"
  );
  ensure!(value.len() <= 256, "{label} must be at most 256 bytes");
  ensure!(
    !value.bytes().any(|byte| byte.is_ascii_control()),
    "{label} must not contain control characters"
  );
  Ok(())
}

#[cfg(test)]
pub(crate) fn load_manifest_for_test(path: &Path) -> anyhow::Result<ExpectedStreamsManifest> {
  load_manifest(path)
}

#[cfg(test)]
pub(crate) fn load_trusted_keys_for_test(
  values: &[String],
) -> anyhow::Result<BTreeMap<String, TrustedKey>> {
  load_trusted_keys(values)
}

#[cfg(test)]
pub(crate) fn load_trusted_hmac_keys_for_test(
  values: &[String],
) -> anyhow::Result<BTreeMap<String, TrustedHmacKey>> {
  load_trusted_hmac_keys(values)
}

#[cfg(test)]
pub(crate) fn load_witness_for_test(
  path: &Path,
  manifest: &ExpectedStreamsManifest,
  initialize: bool,
) -> anyhow::Result<Option<AuditWitness>> {
  load_witness(path, manifest, initialize)
}

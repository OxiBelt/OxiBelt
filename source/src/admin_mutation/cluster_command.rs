//! Versioned encrypted command carried by a fixed-member Admin rollout.

use std::fmt;

use anyhow::{Context, bail, ensure};
use http::Method;
use http::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::ipm::IpmActor;

use super::artifact::{ArtifactBinding, MutationArtifactPlaintext, sha256_digest};
use super::envelope::{TranscriptContext, parse_mutation_header, parse_timestamp};
use super::{MUTATION_HEADER, SignerRegistry};

const FORMAT: &str = "oxibelt-admin-cluster-command-v1";
const FRAME_DOMAIN: &[u8] = b"OXIBELT-ADMIN-CLUSTER-COMMAND-V1\0";
pub(super) const MAX_COMMAND_METADATA_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ClusterExecutionModel {
  PerMember,
  SharedStaged,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct ClusterCommandAuthorization {
  pub(crate) admin_update_config: bool,
  pub(crate) ipm_update_config: bool,
  pub(crate) checks_digest: String,
  pub(crate) check_count: u16,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub(crate) struct ClusterAuthorizationCheck {
  pub(crate) action: String,
  pub(crate) resource: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct ClusterAuthenticatedActor {
  pub(crate) name: String,
  pub(crate) principal: String,
  pub(crate) subject: String,
  pub(crate) groups: Vec<String>,
  pub(crate) credential_kind: String,
  pub(crate) authenticated_with_break_glass: bool,
}

impl ClusterAuthenticatedActor {
  pub(crate) fn new(
    actor: &IpmActor,
    credential_kind: &str,
    authenticated_with_break_glass: bool,
  ) -> anyhow::Result<Self> {
    let value = Self {
      name: actor.name.clone(),
      principal: actor.principal.clone(),
      subject: actor.subject.clone(),
      groups: actor.groups.clone(),
      credential_kind: credential_kind.to_string(),
      authenticated_with_break_glass,
    };
    value.validate()?;
    Ok(value)
  }

  pub(crate) fn ipm_actor(&self) -> IpmActor {
    IpmActor {
      name: self.name.clone(),
      principal: self.principal.clone(),
      subject: self.subject.clone(),
      groups: self.groups.clone(),
    }
  }

  fn validate(&self) -> anyhow::Result<()> {
    let group_bytes = self.groups.iter().try_fold(0_usize, |total, group| {
      total
        .checked_add(group.len())
        .context("cluster command actor group length overflow")
    })?;
    for (name, value) in [
      ("actor name", self.name.as_str()),
      ("actor principal", self.principal.as_str()),
      ("actor subject", self.subject.as_str()),
      ("credential kind", self.credential_kind.as_str()),
    ] {
      ensure!(
        !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control),
        "cluster command {name} is invalid"
      );
    }
    ensure!(
      self.groups.len() <= 256
        && group_bytes <= 8 * 1024
        && self.groups.iter().all(|group| {
          !group.is_empty() && group.len() <= 256 && !group.chars().any(char::is_control)
        }),
      "cluster command actor groups are invalid"
    );
    ensure!(
      self.authenticated_with_break_glass == (self.credential_kind == "break_glass"),
      "cluster command break-glass evidence conflicts with its credential kind"
    );
    Ok(())
  }
}

impl ClusterCommandAuthorization {
  pub(crate) fn from_checks(
    admin_update_config: bool,
    ipm_update_config: bool,
    checks: &[ClusterAuthorizationCheck],
  ) -> anyhow::Result<Self> {
    let checks = canonical_authorization_checks(checks)?;
    Ok(Self {
      admin_update_config,
      ipm_update_config,
      checks_digest: authorization_checks_digest(&checks),
      check_count: u16::try_from(checks.len()).context("authorization check count is too large")?,
    })
  }

  pub(crate) fn matches_checks(&self, checks: &[ClusterAuthorizationCheck]) -> bool {
    canonical_authorization_checks(checks).is_ok_and(|checks| {
      usize::from(self.check_count) == checks.len()
        && self.checks_digest == authorization_checks_digest(&checks)
    })
  }
}

pub(crate) struct ClusterMutationCommand {
  pub(crate) method: Method,
  pub(crate) path_and_query: String,
  pub(crate) precondition_revision: String,
  pub(crate) principal: String,
  pub(crate) actor: ClusterAuthenticatedActor,
  pub(crate) signer_id: String,
  pub(crate) action: String,
  pub(crate) resource: String,
  pub(crate) expected_previous_revision: String,
  pub(crate) new_revision: String,
  pub(crate) execution_model: ClusterExecutionModel,
  pub(crate) authorization: ClusterCommandAuthorization,
  mutation_header: Zeroizing<String>,
  body: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for ClusterMutationCommand {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ClusterMutationCommand")
      .field("method", &self.method)
      .field("path_and_query", &self.path_and_query)
      .field("resource", &self.resource)
      .field("execution_model", &self.execution_model)
      .field("body_len", &self.body.len())
      .finish_non_exhaustive()
  }
}

impl ClusterMutationCommand {
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn new(
    method: &Method,
    path_and_query: &str,
    precondition_revision: &str,
    principal: &str,
    actor: ClusterAuthenticatedActor,
    signer_id: &str,
    action: &str,
    resource: &str,
    expected_previous_revision: &str,
    new_revision: &str,
    body: &[u8],
    mutation_header: &str,
    authorization: ClusterCommandAuthorization,
  ) -> anyhow::Result<Self> {
    let execution_model = execution_model(method, path_and_query)?;
    let command = Self {
      method: method.clone(),
      path_and_query: path_and_query.to_string(),
      precondition_revision: precondition_revision.to_string(),
      principal: principal.to_string(),
      actor,
      signer_id: signer_id.to_string(),
      action: action.to_string(),
      resource: resource.to_string(),
      expected_previous_revision: expected_previous_revision.to_string(),
      new_revision: new_revision.to_string(),
      execution_model,
      authorization,
      mutation_header: Zeroizing::new(mutation_header.to_string()),
      body: Zeroizing::new(body.to_vec()),
    };
    command.validate()?;
    Ok(command)
  }

  pub(crate) fn body(&self) -> &[u8] {
    &self.body
  }

  pub(crate) fn signed_content_digest(&self) -> String {
    sha256_digest(&self.body)
  }

  pub(crate) fn mutation_identity(&self) -> anyhow::Result<(String, String, String)> {
    let mut headers = HeaderMap::new();
    headers.insert(
      MUTATION_HEADER,
      HeaderValue::from_str(&self.mutation_header)
        .context("encrypted mutation envelope is not a valid header value")?,
    );
    let envelope = parse_mutation_header(&headers)?;
    Ok((
      envelope.unsigned.request_id,
      envelope.unsigned.target.cluster_id,
      envelope.unsigned.target.membership_revision,
    ))
  }

  pub(crate) fn into_plaintext(self) -> anyhow::Result<MutationArtifactPlaintext> {
    let signed_content_digest = self.signed_content_digest();
    let wire = ClusterMutationCommandWire {
      format: FORMAT,
      method: self.method.as_str(),
      path_and_query: &self.path_and_query,
      precondition_revision: &self.precondition_revision,
      principal: &self.principal,
      actor: &self.actor,
      signer_id: &self.signer_id,
      action: &self.action,
      resource: &self.resource,
      expected_previous_revision: &self.expected_previous_revision,
      new_revision: &self.new_revision,
      execution_model: self.execution_model,
      authorization: &self.authorization,
      mutation_header: self.mutation_header.as_str(),
    };
    let metadata = Zeroizing::new(
      serde_json::to_vec(&wire).context("failed to encode cluster mutation command")?,
    );
    ensure!(
      metadata.len() <= MAX_COMMAND_METADATA_BYTES,
      "cluster mutation command metadata exceeds its bound"
    );
    let metadata_len = u32::try_from(metadata.len()).context("command metadata is too large")?;
    let capacity = FRAME_DOMAIN
      .len()
      .checked_add(4)
      .and_then(|value| value.checked_add(metadata.len()))
      .and_then(|value| value.checked_add(self.body.len()))
      .context("cluster command length overflow")?;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(FRAME_DOMAIN);
    encoded.extend_from_slice(&metadata_len.to_be_bytes());
    encoded.extend_from_slice(&metadata);
    encoded.extend_from_slice(&self.body);
    Ok(MutationArtifactPlaintext::with_signed_digest(
      encoded,
      signed_content_digest,
    ))
  }

  pub(super) fn from_plaintext(
    plaintext: &MutationArtifactPlaintext,
    binding: &ArtifactBinding,
  ) -> anyhow::Result<Self> {
    let (wire, body) = decode_frame(plaintext.as_bytes())?;
    ensure!(wire.format == FORMAT, "unsupported cluster command format");
    let method = Method::from_bytes(wire.method.as_bytes()).context("invalid command method")?;
    let command = Self {
      method,
      path_and_query: wire.path_and_query,
      precondition_revision: wire.precondition_revision,
      principal: wire.principal,
      actor: wire.actor,
      signer_id: wire.signer_id,
      action: wire.action,
      resource: wire.resource,
      expected_previous_revision: wire.expected_previous_revision,
      new_revision: wire.new_revision,
      execution_model: wire.execution_model,
      authorization: wire.authorization,
      mutation_header: Zeroizing::new(wire.mutation_header),
      body: Zeroizing::new(body.to_vec()),
    };
    command.validate_against(binding)?;
    Ok(command)
  }

  pub(super) fn validate_against(&self, binding: &ArtifactBinding) -> anyhow::Result<()> {
    self.validate()?;
    ensure!(
      self.principal == binding.principal
        && self.signer_id == binding.signer_id
        && self.action == binding.action
        && self.resource == binding.resource
        && self.expected_previous_revision == binding.expected_previous_revision
        && self.new_revision == binding.new_revision
        && self.signed_content_digest() == binding.content_digest,
      "cluster command conflicts with its signed durable binding"
    );
    let mut headers = HeaderMap::new();
    headers.insert(
      MUTATION_HEADER,
      HeaderValue::from_str(&self.mutation_header)
        .context("encrypted mutation envelope is not a valid header value")?,
    );
    let envelope = parse_mutation_header(&headers)?;
    ensure!(
      envelope.unsigned.request_id == binding.request_id
        && envelope.unsigned.signer_id == binding.signer_id
        && envelope.unsigned.expected_previous_revision == binding.expected_previous_revision
        && envelope.unsigned.new_revision == binding.new_revision
        && envelope.unsigned.content_digest == binding.content_digest
        && envelope.unsigned.target.cluster_id == binding.cluster_id
        && envelope.unsigned.target.membership_revision == binding.membership_revision,
      "encrypted mutation envelope conflicts with its durable binding"
    );
    Ok(())
  }

  pub(super) fn reverify(
    &self,
    registry: &SignerRegistry,
    ipm_namespace: &str,
    binding: &ArtifactBinding,
    maximum_validity_seconds: u64,
    maximum_clock_skew_seconds: u64,
  ) -> anyhow::Result<()> {
    self.validate_against(binding)?;
    let mut headers = HeaderMap::new();
    headers.insert(
      MUTATION_HEADER,
      HeaderValue::from_str(&self.mutation_header)
        .context("encrypted mutation envelope is not a valid header value")?,
    );
    let envelope = parse_mutation_header(&headers)?;
    let verified = registry.verify(
      &headers,
      &TranscriptContext {
        method: &self.method,
        path_and_query: &self.path_and_query,
        ipm_namespace,
        authenticated_principal: &self.principal,
        body: &self.body,
        precondition_revision: &self.precondition_revision,
        now_unix_seconds: parse_timestamp(&envelope.unsigned.issued_at)?,
        maximum_validity_seconds,
        maximum_clock_skew_seconds,
      },
    )?;
    ensure!(
      verified.fingerprint == binding.fingerprint && verified.signer_principal == binding.principal,
      "recovered mutation signature conflicts with its durable fingerprint"
    );
    Ok(())
  }

  fn validate(&self) -> anyhow::Result<()> {
    ensure!(
      self.method != Method::GET && self.method != Method::HEAD,
      "cluster command must mutate"
    );
    ensure!(
      self.path_and_query.starts_with("/admin/v1/")
        && self.path_and_query.len() <= 2_048
        && !self.path_and_query.chars().any(char::is_control),
      "cluster command path is invalid"
    );
    ensure!(
      !self.mutation_header.is_empty()
        && self.mutation_header.len() <= 8 * 1024
        && self
          .mutation_header
          .bytes()
          .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
      "cluster command mutation envelope is invalid"
    );
    for (name, value) in [
      ("precondition_revision", self.precondition_revision.as_str()),
      ("principal", self.principal.as_str()),
      ("signer_id", self.signer_id.as_str()),
      ("action", self.action.as_str()),
      ("resource", self.resource.as_str()),
      (
        "expected_previous_revision",
        self.expected_previous_revision.as_str(),
      ),
      ("new_revision", self.new_revision.as_str()),
    ] {
      ensure!(
        !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control),
        "cluster command {name} is invalid"
      );
    }
    ensure!(
      execution_model(&self.method, &self.path_and_query)? == self.execution_model,
      "cluster command execution model does not match its route"
    );
    self.actor.validate()?;
    ensure!(
      self.actor.principal == self.principal,
      "cluster command actor principal conflicts with its signed principal"
    );
    ensure!(
      (1..=1_024).contains(&self.authorization.check_count)
        && self.authorization.checks_digest.len() == 71
        && self.authorization.checks_digest.starts_with("sha256:"),
      "cluster command authorization evidence is invalid"
    );
    Ok(())
  }
}

fn canonical_authorization_checks(
  checks: &[ClusterAuthorizationCheck],
) -> anyhow::Result<Vec<ClusterAuthorizationCheck>> {
  ensure!(
    !checks.is_empty() && checks.len() <= 1_024,
    "cluster authorization check count is invalid"
  );
  let mut checks = checks.to_vec();
  for check in &checks {
    for (name, value) in [
      ("authorization action", check.action.as_str()),
      ("authorization resource", check.resource.as_str()),
    ] {
      ensure!(
        !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control),
        "cluster command {name} is invalid"
      );
    }
  }
  checks.sort();
  checks.dedup();
  Ok(checks)
}

fn authorization_checks_digest(checks: &[ClusterAuthorizationCheck]) -> String {
  let mut bytes = Zeroizing::new(Vec::new());
  bytes.extend_from_slice(b"OXIBELT-ADMIN-CLUSTER-AUTHORIZATION-V1\0");
  for check in checks {
    bytes.extend_from_slice(&(check.action.len() as u64).to_be_bytes());
    bytes.extend_from_slice(check.action.as_bytes());
    bytes.extend_from_slice(&(check.resource.len() as u64).to_be_bytes());
    bytes.extend_from_slice(check.resource.as_bytes());
  }
  sha256_digest(&bytes)
}

fn execution_model(method: &Method, path_and_query: &str) -> anyhow::Result<ClusterExecutionModel> {
  let path = path_and_query.split('?').next().unwrap_or(path_and_query);
  if method == Method::POST
    && matches!(
      path,
      "/admin/v1/config/load"
        | "/admin/v1/config/rollback"
        | "/admin/v1/files/sync"
        | "/admin/v1/tls/downstream/reload"
        | "/admin/v1/keys/rotate"
        | "/admin/v1/config/secret-references/update"
    )
  {
    return Ok(ClusterExecutionModel::PerMember);
  }
  if (path.starts_with("/admin/v1/ipm/")
    && matches!(*method, Method::POST | Method::PATCH | Method::DELETE)
    && path != "/admin/v1/ipm/simulate")
    || (path.starts_with("/admin/v1/break-glass/") && method == Method::POST)
  {
    return Ok(ClusterExecutionModel::SharedStaged);
  }
  bail!("Admin route is not eligible for fixed-member mutation rollout")
}

#[derive(Serialize)]
struct ClusterMutationCommandWire<'a> {
  format: &'static str,
  method: &'a str,
  path_and_query: &'a str,
  precondition_revision: &'a str,
  principal: &'a str,
  actor: &'a ClusterAuthenticatedActor,
  signer_id: &'a str,
  action: &'a str,
  resource: &'a str,
  expected_previous_revision: &'a str,
  new_revision: &'a str,
  execution_model: ClusterExecutionModel,
  authorization: &'a ClusterCommandAuthorization,
  mutation_header: &'a str,
}

#[derive(Deserialize)]
struct ClusterMutationCommandOwned {
  format: String,
  method: String,
  path_and_query: String,
  precondition_revision: String,
  principal: String,
  actor: ClusterAuthenticatedActor,
  signer_id: String,
  action: String,
  resource: String,
  expected_previous_revision: String,
  new_revision: String,
  execution_model: ClusterExecutionModel,
  authorization: ClusterCommandAuthorization,
  mutation_header: String,
}

pub(super) fn signed_digest_from_encoded(encoded: &[u8]) -> anyhow::Result<String> {
  let (wire, body) = decode_frame(encoded)?;
  ensure!(wire.format == FORMAT, "unsupported cluster command format");
  Ok(sha256_digest(body))
}

fn decode_frame(encoded: &[u8]) -> anyhow::Result<(ClusterMutationCommandOwned, &[u8])> {
  ensure!(
    encoded.starts_with(FRAME_DOMAIN) && encoded.len() >= FRAME_DOMAIN.len() + 4,
    "encrypted artifact is not a valid cluster mutation command frame"
  );
  let offset = FRAME_DOMAIN.len();
  let metadata_len = u32::from_be_bytes(
    encoded[offset..offset + 4]
      .try_into()
      .map_err(|_| anyhow::anyhow!("cluster command metadata length is invalid"))?,
  ) as usize;
  ensure!(
    metadata_len <= MAX_COMMAND_METADATA_BYTES,
    "cluster command metadata exceeds its bound"
  );
  let body_offset = offset
    .checked_add(4)
    .and_then(|value| value.checked_add(metadata_len))
    .context("cluster command metadata length overflow")?;
  ensure!(
    body_offset <= encoded.len(),
    "cluster command frame is truncated"
  );
  let wire = serde_json::from_slice(&encoded[offset + 4..body_offset])
    .context("cluster command metadata is invalid")?;
  Ok((wire, &encoded[body_offset..]))
}

#[cfg(feature = "fuzzing")]
pub(super) fn fuzz_decode_frame(data: &[u8]) {
  let _ = decode_frame(data);
  if data.first() == Some(&b'{') && data.len() <= MAX_COMMAND_METADATA_BYTES {
    let mut framed = Vec::with_capacity(
      FRAME_DOMAIN
        .len()
        .saturating_add(4)
        .saturating_add(data.len()),
    );
    framed.extend_from_slice(FRAME_DOMAIN);
    framed.extend_from_slice(&(data.len() as u32).to_be_bytes());
    framed.extend_from_slice(data);
    let _ = decode_frame(&framed);
  }
}

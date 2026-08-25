//! Bounded certificate-chain admission for CT submissions.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use der::{Decode as _, Encode as _};
use sha2::{Digest as _, Sha256};
use x509_cert::Certificate;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};

use super::AcceptedRoot;

const MAX_CHAIN_CERTIFICATES: usize = 16;
const MAX_CERTIFICATE_BYTES: usize = 1024 * 1024;
const MAX_CHAIN_BYTES: usize = 16 * 1024 * 1024;
const CT_POISON_OID: &str = "1.3.6.1.4.1.11129.2.4.3";
const CT_PRECERT_SIGNING_CA_OID: &str = "1.3.6.1.4.1.11129.2.4.4";
const SERVER_AUTH_OID: &str = "1.3.6.1.5.5.7.3.1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CtSubmissionKind {
  Certificate,
  Precertificate,
}

#[derive(Clone, Debug)]
pub struct CtChainPolicy {
  pub reject_expired: bool,
  pub require_server_auth_eku: bool,
  pub reject_precertificate_signing_ca: bool,
  pub shard_not_after_start_millis: u64,
  pub shard_not_after_end_millis: u64,
}

#[derive(Clone, Debug)]
pub struct ValidatedCtChain {
  pub certificates: Vec<Vec<u8>>,
  pub leaf_sha256: [u8; 32],
  pub leaf_not_before_millis: u64,
  pub leaf_not_after_millis: u64,
  pub accepted_root_sha256: [u8; 32],
}

pub fn validate_chain(
  chain: &[Vec<u8>],
  accepted_roots: &[AcceptedRoot],
  kind: CtSubmissionKind,
  policy: &CtChainPolicy,
) -> anyhow::Result<ValidatedCtChain> {
  if chain.is_empty() || chain.len() > MAX_CHAIN_CERTIFICATES {
    bail!("CT submission chain count is outside 1..={MAX_CHAIN_CERTIFICATES}");
  }
  if accepted_roots.is_empty() {
    bail!("CT submission cannot be validated without accepted roots");
  }
  let total_bytes = chain.iter().try_fold(0_usize, |total, certificate| {
    if certificate.is_empty() || certificate.len() > MAX_CERTIFICATE_BYTES {
      bail!("CT certificate length is outside 1..={MAX_CERTIFICATE_BYTES}");
    }
    total
      .checked_add(certificate.len())
      .ok_or_else(|| anyhow!("CT certificate chain length overflow"))
  })?;
  if total_bytes > MAX_CHAIN_BYTES {
    bail!("CT certificate chain exceeds {MAX_CHAIN_BYTES} bytes");
  }
  if policy.shard_not_after_start_millis >= policy.shard_not_after_end_millis {
    bail!("CT shard expiry interval must be non-empty");
  }

  let certificates = chain
    .iter()
    .map(|der| Certificate::from_der(der).context("failed to parse CT certificate DER"))
    .collect::<anyhow::Result<Vec<_>>>()?;
  if policy.reject_precertificate_signing_ca && chain_uses_precertificate_signing_ca(chain)? {
    bail!("CT submission uses a prohibited Precertificate Signing CA");
  }
  validate_leaf_extensions(&certificates[0], kind, policy)?;
  for issuer_index in 1..certificates.len() {
    validate_ca_certificate(&certificates[issuer_index], issuer_index - 1)?;
    verify_issued_by(
      &certificates[issuer_index - 1],
      &chain[issuer_index],
      &certificates[issuer_index],
    )?;
  }

  let (accepted_root_sha256, _) = find_accepted_root(chain, &certificates, accepted_roots)?;

  let leaf = &certificates[0];
  let leaf_not_before_millis = duration_millis(
    leaf
      .tbs_certificate()
      .validity()
      .not_before
      .to_unix_duration(),
    "notBefore",
  )?;
  let leaf_not_after_millis = duration_millis(
    leaf
      .tbs_certificate()
      .validity()
      .not_after
      .to_unix_duration(),
    "notAfter",
  )?;
  if leaf_not_after_millis <= leaf_not_before_millis {
    bail!("CT leaf certificate validity interval is empty");
  }
  if leaf_not_after_millis < policy.shard_not_after_start_millis
    || leaf_not_after_millis >= policy.shard_not_after_end_millis
  {
    bail!("CT leaf certificate expiry is outside the configured temporal shard");
  }
  if policy.reject_expired {
    let now = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .context("system clock is before the Unix epoch")?;
    let now_millis = duration_millis(now, "current time")?;
    if leaf_not_after_millis <= now_millis {
      bail!("CT leaf certificate is already expired");
    }
  }
  let leaf_sha256: [u8; 32] = Sha256::digest(&chain[0]).into();
  Ok(ValidatedCtChain {
    certificates: chain.to_vec(),
    leaf_sha256,
    leaf_not_before_millis,
    leaf_not_after_millis,
    accepted_root_sha256,
  })
}

fn validate_leaf_extensions(
  leaf: &Certificate,
  kind: CtSubmissionKind,
  policy: &CtChainPolicy,
) -> anyhow::Result<()> {
  let poison_count = leaf
    .tbs_certificate()
    .extensions()
    .map_or(&[][..], Vec::as_slice)
    .iter()
    .filter(|extension| extension.extn_id.to_string() == CT_POISON_OID)
    .count();
  match kind {
    CtSubmissionKind::Certificate if poison_count != 0 => {
      bail!("final CT certificate must not contain the poison extension")
    }
    CtSubmissionKind::Precertificate if poison_count != 1 => {
      bail!("CT precertificate must contain exactly one poison extension")
    }
    _ => {}
  }
  if kind == CtSubmissionKind::Precertificate {
    let poison = leaf
      .tbs_certificate()
      .extensions()
      .map_or(&[][..], Vec::as_slice)
      .iter()
      .find(|extension| extension.extn_id.to_string() == CT_POISON_OID)
      .ok_or_else(|| anyhow!("CT poison extension disappeared during validation"))?;
    if !poison.critical || poison.extn_value.as_bytes() != [5, 0] {
      bail!("CT poison extension must be critical ASN.1 NULL");
    }
  }
  if policy.require_server_auth_eku
    && let Some((_, usages)) = leaf
      .tbs_certificate()
      .get_extension::<ExtendedKeyUsage>()
      .context("failed to parse CT leaf extended key usage")?
    && !usages
      .0
      .iter()
      .any(|usage| usage.to_string() == SERVER_AUTH_OID)
  {
    bail!("CT leaf certificate does not permit serverAuth");
  }
  Ok(())
}

fn validate_ca_certificate(certificate: &Certificate, ca_depth_below: usize) -> anyhow::Result<()> {
  let (_, constraints) = certificate
    .tbs_certificate()
    .get_extension::<BasicConstraints>()
    .context("failed to parse CT CA basic constraints")?
    .ok_or_else(|| anyhow!("CT issuer certificate is missing basic constraints"))?;
  if !constraints.ca {
    bail!("CT issuer certificate is not a CA");
  }
  if constraints
    .path_len_constraint
    .is_some_and(|limit| ca_depth_below > usize::from(limit))
  {
    bail!("CT issuer certificate path length constraint is exceeded");
  }
  if let Some((_, usage)) = certificate
    .tbs_certificate()
    .get_extension::<KeyUsage>()
    .context("failed to parse CT CA key usage")?
    && !usage.key_cert_sign()
  {
    bail!("CT issuer certificate does not permit certificate signing");
  }
  Ok(())
}

fn find_accepted_root(
  chain: &[Vec<u8>],
  certificates: &[Certificate],
  accepted_roots: &[AcceptedRoot],
) -> anyhow::Result<([u8; 32], bool)> {
  let last_der = chain.last().ok_or_else(|| anyhow!("CT chain is empty"))?;
  if let Some(root) = accepted_roots.iter().find(|root| root.der == *last_der) {
    return Ok((root.sha256, true));
  }
  let last = certificates
    .last()
    .ok_or_else(|| anyhow!("CT chain is empty"))?;
  for root in accepted_roots {
    let parsed = Certificate::from_der(&root.der).context("failed to parse accepted CT root")?;
    if last.tbs_certificate().issuer() != parsed.tbs_certificate().subject() {
      continue;
    }
    if verify_issued_by(last, &root.der, &parsed).is_ok() {
      return Ok((root.sha256, false));
    }
  }
  bail!("CT submission chain does not terminate at an accepted root")
}

fn verify_issued_by(
  certificate: &Certificate,
  issuer_der: &[u8],
  issuer: &Certificate,
) -> anyhow::Result<()> {
  if certificate.tbs_certificate().issuer() != issuer.tbs_certificate().subject() {
    bail!("CT certificate issuer and subject names do not form an ordered chain");
  }
  let algorithm = certificate
    .signature_algorithm()
    .to_der()
    .context("failed to encode CT certificate signature algorithm")?;
  let message = certificate
    .tbs_certificate()
    .to_der()
    .context("failed to encode CT TBSCertificate")?;
  let signature = certificate
    .signature()
    .as_bytes()
    .ok_or_else(|| anyhow!("CT certificate signature has unused bits"))?;
  crate::tls::verify_certificate_signature(issuer_der, &algorithm, &message, signature)
    .context("CT certificate signature verification failed")
}

fn duration_millis(duration: std::time::Duration, label: &str) -> anyhow::Result<u64> {
  u64::try_from(duration.as_millis()).with_context(|| format!("CT certificate {label} overflow"))
}

pub fn chain_uses_precertificate_signing_ca(chain: &[Vec<u8>]) -> anyhow::Result<bool> {
  for der in chain.iter().skip(1) {
    let certificate = Certificate::from_der(der).context("failed to parse CT issuer")?;
    if certificate
      .tbs_certificate()
      .extensions()
      .map_or(&[][..], Vec::as_slice)
      .iter()
      .any(|extension| extension.extn_id.to_string() == CT_PRECERT_SIGNING_CA_OID)
    {
      return Ok(true);
    }
  }
  Ok(false)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn empty_chain_is_rejected_before_parsing() {
    let policy = CtChainPolicy {
      reject_expired: true,
      require_server_auth_eku: false,
      reject_precertificate_signing_ca: true,
      shard_not_after_start_millis: 1,
      shard_not_after_end_millis: 2,
    };
    assert!(validate_chain(&[], &[], CtSubmissionKind::Certificate, &policy).is_err());
  }
}

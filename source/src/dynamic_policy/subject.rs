//! Dynamic policy subject parsing and canonicalization.

use std::net::IpAddr;
use std::str::FromStr;

use anyhow::{Context, anyhow, bail};

use crate::identity::Cidr;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum DynamicPolicySubjectType {
  Ip,
  IpCidr,
  IpPrefix,
  IpRoute,
  IpPath,
  IpPrefixRoute,
  TlsFingerprint,
  TlsFingerprintRoute,
  TokenBindingHash,
  PersonProofClearance,
  Asn,
  AsnRoute,
  CompositeClient,
}

impl DynamicPolicySubjectType {
  pub(super) fn as_str(self) -> &'static str {
    match self {
      Self::Ip => "client_ip",
      Self::IpCidr => "client_ip_cidr",
      Self::IpPrefix => "client_ip_prefix",
      Self::IpRoute => "client_ip_route",
      Self::IpPath => "client_ip_path",
      Self::IpPrefixRoute => "client_ip_prefix_route",
      Self::TlsFingerprint => "tls_fingerprint",
      Self::TlsFingerprintRoute => "tls_fingerprint_route",
      Self::TokenBindingHash => "token_binding_hash",
      Self::PersonProofClearance => "person_proof_clearance",
      Self::Asn => "asn",
      Self::AsnRoute => "asn_route",
      Self::CompositeClient => "composite_client",
    }
  }

  fn parse(raw: &str) -> Option<Self> {
    Some(match raw {
      "client_ip" => Self::Ip,
      "client_ip_cidr" => Self::IpCidr,
      "client_ip_prefix" => Self::IpPrefix,
      "client_ip_route" => Self::IpRoute,
      "client_ip_path" => Self::IpPath,
      "client_ip_prefix_route" => Self::IpPrefixRoute,
      "tls_fingerprint" => Self::TlsFingerprint,
      "tls_fingerprint_route" => Self::TlsFingerprintRoute,
      "token_binding_hash" => Self::TokenBindingHash,
      "person_proof_clearance" => Self::PersonProofClearance,
      "asn" => Self::Asn,
      "asn_route" => Self::AsnRoute,
      "composite_client" => Self::CompositeClient,
      _ => return None,
    })
  }
}

pub(super) fn parse_subject_type(raw: &str) -> anyhow::Result<DynamicPolicySubjectType> {
  DynamicPolicySubjectType::parse(raw)
    .ok_or_else(|| anyhow!("dynamic policy has unsupported subject_type {raw}"))
}

pub(super) fn validate_subject(
  id: i64,
  subject_type: DynamicPolicySubjectType,
  subject: &str,
  route_name: Option<&str>,
  path_prefix: Option<&str>,
) -> anyhow::Result<(String, Option<Cidr>)> {
  let subject = match subject_type {
    DynamicPolicySubjectType::Ip => {
      let ip = IpAddr::from_str(subject)
        .with_context(|| format!("dynamic policy {id} subject must be a valid IP address"))?;
      (ip.to_string(), None)
    }
    DynamicPolicySubjectType::IpCidr => {
      let cidr = Cidr::parse(subject)
        .with_context(|| format!("dynamic policy {id} subject must be a valid CIDR"))?;
      (cidr.canonical(), Some(cidr))
    }
    DynamicPolicySubjectType::IpPrefix => {
      let cidr = Cidr::parse(subject).with_context(|| {
        format!("dynamic policy {id} client_ip_prefix subject must be a valid CIDR")
      })?;
      (cidr.canonical(), Some(cidr))
    }
    DynamicPolicySubjectType::IpRoute => {
      let (ip, route) = split_composite_subject(id, subject, "client_ip_route")?;
      let ip = IpAddr::from_str(ip).with_context(|| {
        format!("dynamic policy {id} client_ip_route subject must start with a valid IP address")
      })?;
      let Some(route_name) = route_name else {
        bail!("dynamic policy {id} client_ip_route requires route_name");
      };
      if route != route_name {
        bail!("dynamic policy {id} client_ip_route subject route does not match route_name");
      }
      (format!("{ip}|{route_name}"), None)
    }
    DynamicPolicySubjectType::IpPrefixRoute => {
      let (prefix, route) = split_composite_subject(id, subject, "client_ip_prefix_route")?;
      let cidr = Cidr::parse(prefix).with_context(|| {
        format!("dynamic policy {id} client_ip_prefix_route subject must start with a valid CIDR")
      })?;
      let Some(route_name) = route_name else {
        bail!("dynamic policy {id} client_ip_prefix_route requires route_name");
      };
      if route != route_name {
        bail!("dynamic policy {id} client_ip_prefix_route subject route does not match route_name");
      }
      (format!("{}|{route_name}", cidr.canonical()), Some(cidr))
    }
    DynamicPolicySubjectType::IpPath => {
      let (ip, path) = split_composite_subject(id, subject, "client_ip_path")?;
      let ip = IpAddr::from_str(ip).with_context(|| {
        format!("dynamic policy {id} client_ip_path subject must start with a valid IP address")
      })?;
      let Some(path_prefix) = path_prefix else {
        bail!("dynamic policy {id} client_ip_path requires path_prefix");
      };
      if path != path_prefix {
        bail!("dynamic policy {id} client_ip_path subject path does not match path_prefix");
      }
      (format!("{ip}|{path_prefix}"), None)
    }
    DynamicPolicySubjectType::TlsFingerprint => (
      canonical_hash_subject(id, subject, "tls_fingerprint", "fingerprint")?,
      None,
    ),
    DynamicPolicySubjectType::TlsFingerprintRoute => {
      let (fingerprint, route) = split_composite_subject(id, subject, "tls_fingerprint_route")?;
      let Some(route_name) = route_name else {
        bail!("dynamic policy {id} tls_fingerprint_route requires route_name");
      };
      if route != route_name {
        bail!("dynamic policy {id} tls_fingerprint_route subject route does not match route_name");
      }
      (
        format!(
          "{}|{route_name}",
          canonical_hash_subject(id, fingerprint, "tls_fingerprint_route", "fingerprint")?
        ),
        None,
      )
    }
    DynamicPolicySubjectType::TokenBindingHash => (
      canonical_hash_subject(id, subject, "token_binding_hash", "binding")?,
      None,
    ),
    DynamicPolicySubjectType::PersonProofClearance => (
      canonical_hash_subject(id, subject, "person_proof_clearance", "clearance")?,
      None,
    ),
    DynamicPolicySubjectType::Asn => (canonical_asn_subject(id, subject, "asn")?, None),
    DynamicPolicySubjectType::AsnRoute => {
      let (asn, route) = split_composite_subject(id, subject, "asn_route")?;
      let Some(route_name) = route_name else {
        bail!("dynamic policy {id} asn_route requires route_name");
      };
      if route != route_name {
        bail!("dynamic policy {id} asn_route subject route does not match route_name");
      }
      (
        format!(
          "{}|{route_name}",
          canonical_asn_subject(id, asn, "asn_route")?
        ),
        None,
      )
    }
    DynamicPolicySubjectType::CompositeClient => (
      canonical_hash_subject(id, subject, "composite_client", "hash")?,
      None,
    ),
  };
  Ok(subject)
}

fn split_composite_subject<'a>(
  id: i64,
  subject: &'a str,
  subject_type: &str,
) -> anyhow::Result<(&'a str, &'a str)> {
  let Some((subject, value)) = subject.split_once('|') else {
    bail!("dynamic policy {id} {subject_type} subject must use '<subject>|<value>' format");
  };
  if subject.is_empty() || value.is_empty() {
    bail!("dynamic policy {id} {subject_type} subject must not contain empty parts");
  }
  Ok((subject, value))
}

fn canonical_hash_subject(
  id: i64,
  subject: &str,
  subject_type: &str,
  prefix: &str,
) -> anyhow::Result<String> {
  let subject = subject.trim();
  let hash = subject
    .strip_prefix(prefix)
    .and_then(|value| value.strip_prefix(':'))
    .unwrap_or(subject);
  if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
    bail!("dynamic policy {id} {subject_type} subject must be a 64-hex SHA-256 value");
  }
  Ok(format!("{prefix}:{}", hash.to_ascii_lowercase()))
}

fn canonical_asn_subject(id: i64, subject: &str, subject_type: &str) -> anyhow::Result<String> {
  let subject = subject.trim();
  let value = subject
    .strip_prefix("AS")
    .or_else(|| subject.strip_prefix("as"))
    .unwrap_or(subject);
  let asn: u32 = value
    .parse()
    .with_context(|| format!("dynamic policy {id} {subject_type} subject must be an ASN"))?;
  Ok(format!("AS{asn}"))
}

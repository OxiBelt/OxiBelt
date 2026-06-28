//! Downstream certificate partition metadata for SNI-scoped resumption.

use std::collections::HashSet;

use anyhow::Context;

use crate::config::TlsConfig;

use super::certificate_io::load_certs;
use super::resumption::certificate_identity;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::tls) struct DownstreamCertificatePartition {
  pub(in crate::tls) identity: String,
  pub(in crate::tls) server_names: Vec<String>,
  pub(in crate::tls) is_default: bool,
}

#[derive(Clone, Debug)]
pub(in crate::tls) struct DownstreamCertificatePartitions {
  partitions: Vec<DownstreamCertificatePartition>,
  require_sni: bool,
  reject_unknown_sni: bool,
}

impl DownstreamCertificatePartitions {
  pub(in crate::tls) fn new(
    partitions: Vec<DownstreamCertificatePartition>,
    require_sni: bool,
    reject_unknown_sni: bool,
  ) -> Self {
    Self {
      partitions,
      require_sni,
      reject_unknown_sni,
    }
  }

  pub(in crate::tls) fn default_identity(&self) -> &str {
    &self
      .partitions
      .first()
      .expect("downstream certificate partitions must include default")
      .identity
  }

  pub(in crate::tls) fn identities(&self) -> Vec<String> {
    let mut seen = HashSet::new();
    self
      .partitions
      .iter()
      .filter_map(|partition| {
        if seen.insert(partition.identity.clone()) {
          Some(partition.identity.clone())
        } else {
          None
        }
      })
      .collect()
  }

  pub(in crate::tls) fn identity_for_sni(&self, sni: Option<&str>) -> Option<&str> {
    let Some(server_name) = sni else {
      return (!self.require_sni).then(|| self.default_identity());
    };
    self
      .named_partition(server_name)
      .map(|partition| partition.identity.as_str())
      .or_else(|| (!self.reject_unknown_sni).then(|| self.default_identity()))
  }

  pub(in crate::tls) fn identity_for_sni_or_default(&self, sni: Option<&str>) -> &str {
    self
      .identity_for_sni(sni)
      .unwrap_or_else(|| self.default_identity())
  }

  fn named_partition(&self, server_name: &str) -> Option<&DownstreamCertificatePartition> {
    self
      .matching_partition(server_name, false, true)
      .or_else(|| self.matching_partition(server_name, false, false))
      .or_else(|| self.matching_partition(server_name, true, true))
      .or_else(|| self.matching_partition(server_name, true, false))
  }

  fn matching_partition(
    &self,
    server_name: &str,
    wildcard: bool,
    default: bool,
  ) -> Option<&DownstreamCertificatePartition> {
    self
      .partitions
      .iter()
      .filter(|partition| partition.is_default == default)
      .find(|partition| {
        partition.server_names.iter().any(|pattern| {
          if pattern.starts_with("*.") != wildcard {
            return false;
          }
          if wildcard {
            super::sni_matches(pattern, server_name)
          } else {
            pattern.eq_ignore_ascii_case(server_name)
          }
        })
      })
  }
}

pub(in crate::tls) fn downstream_certificate_partitions(
  tls: &TlsConfig,
) -> anyhow::Result<DownstreamCertificatePartitions> {
  let default_certs =
    load_certs(&tls.cert_chain).context("failed to load default downstream certificate chain")?;
  let mut partitions = vec![DownstreamCertificatePartition {
    identity: certificate_identity(&default_certs),
    server_names: normalize_server_names(&tls.server_names),
    is_default: true,
  }];

  for (index, certificate) in tls.certificates.iter().enumerate() {
    let certs = load_certs(&certificate.cert_chain)
      .with_context(|| format!("failed to load tls.certificates[{index}] certificate chain"))?;
    partitions.push(DownstreamCertificatePartition {
      identity: certificate_identity(&certs),
      server_names: normalize_server_names(&certificate.server_names),
      is_default: false,
    });
  }

  Ok(DownstreamCertificatePartitions::new(
    partitions,
    tls.require_sni,
    tls.reject_unknown_sni,
  ))
}

pub(in crate::tls) fn normalize_server_names(names: &[String]) -> Vec<String> {
  names.iter().map(|name| name.to_ascii_lowercase()).collect()
}

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, bail};
use h3_quinn::quinn::ServerConfig as QuinnServerConfig;
use rustls::{CipherSuite, NamedGroup, ServerConfig};

use crate::config::{
  CryptoConfig, ListenerConfig, QuicConfig, RouteConfig, Tls13NegotiationConfig, TlsConfig,
  TlsKeyExchangeGroup, TlsMultiCertificateResumptionMode, TlsNegotiationPolicy, TlsVersion,
};

use super::certificate_partition::{
  DownstreamCertificatePartitions, downstream_certificate_partitions,
};
use super::{CrliteRuntime, OcspStapleRuntime, TlsResumptionState};

#[derive(Debug, Clone)]
pub struct DownstreamTlsServerConfig {
  configs: Arc<HashMap<TcpServerConfigKey, Arc<TlsServerConfigSet>>>,
  default_key: TcpServerConfigKey,
  default_policy: TlsNegotiationPolicy,
  by_sni_policy: Arc<HashMap<String, TlsNegotiationPolicy>>,
  certificate_partitions: Option<Arc<DownstreamCertificatePartitions>>,
}

impl DownstreamTlsServerConfig {
  pub(crate) fn select(&self, client_hello: &rustls::server::ClientHello<'_>) -> Arc<ServerConfig> {
    let sni = client_hello.server_name();
    let policy = self.selected_negotiation_policy(sni).clone();
    let certificate_identity = self
      .certificate_partitions
      .as_ref()
      .map(|partitions| partitions.identity_for_sni_or_default(sni).to_string());
    let key = TcpServerConfigKey {
      policy,
      certificate_identity,
    };
    let config_set = self
      .configs
      .get(&key)
      .or_else(|| self.configs.get(&self.default_key))
      .expect("downstream TLS config set must include default");
    config_set.select(client_hello)
  }

  pub(crate) fn selected_negotiation_policy(&self, sni: Option<&str>) -> &TlsNegotiationPolicy {
    sni
      .and_then(|name| self.by_sni_policy.get(&name.to_ascii_lowercase()))
      .unwrap_or(&self.default_policy)
  }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct TcpServerConfigKey {
  policy: TlsNegotiationPolicy,
  certificate_identity: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TurnTlsServerConfig {
  config_set: Arc<TlsServerConfigSet>,
}

impl TurnTlsServerConfig {
  pub(crate) fn select(&self, client_hello: &rustls::server::ClientHello<'_>) -> Arc<ServerConfig> {
    self.config_set.select(client_hello)
  }
}

#[derive(Debug, Clone)]
pub struct DownstreamQuicServerConfig {
  configs: Arc<Vec<QuinnServerConfig>>,
  indices: Arc<HashMap<QuicServerConfigKey, usize>>,
  default_policy: Tls13NegotiationConfig,
  by_sni_policy: Arc<HashMap<String, Tls13NegotiationConfig>>,
  reject_sni: Arc<HashSet<String>>,
  certificate_partitions: Option<Arc<DownstreamCertificatePartitions>>,
}

impl DownstreamQuicServerConfig {
  pub(crate) fn default_config(&self) -> QuinnServerConfig {
    self
      .configs
      .first()
      .expect("downstream QUIC config set must not be empty")
      .clone()
  }

  pub(crate) fn configs(&self) -> &[QuinnServerConfig] {
    &self.configs
  }

  pub(crate) fn requires_sni_policy_demux(&self) -> bool {
    self.configs.len() > 1 || !self.reject_sni.is_empty()
  }

  pub(crate) fn policy_index_for_sni(&self, sni: Option<&str>) -> Option<usize> {
    let normalized = sni.map(str::to_ascii_lowercase);
    if normalized
      .as_ref()
      .is_some_and(|name| self.reject_sni.contains(name))
    {
      return None;
    }
    let policy = normalized
      .as_ref()
      .and_then(|name| self.by_sni_policy.get(name))
      .cloned()
      .unwrap_or_else(|| self.default_policy.clone());
    let certificate_identity = match &self.certificate_partitions {
      Some(partitions) => Some(partitions.identity_for_sni(sni)?.to_string()),
      None => None,
    };
    self
      .indices
      .get(&QuicServerConfigKey {
        policy,
        certificate_identity,
      })
      .copied()
  }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct QuicServerConfigKey {
  policy: Tls13NegotiationConfig,
  certificate_identity: Option<String>,
}

#[derive(Debug)]
struct TlsServerConfigSet {
  tls13: Option<TlsServerVersionConfig>,
  tls12: Option<TlsServerVersionConfig>,
}

impl TlsServerConfigSet {
  fn select(&self, client_hello: &rustls::server::ClientHello<'_>) -> Arc<ServerConfig> {
    if let Some(tls13) = &self.tls13
      && client_offers_any_cipher(client_hello, &tls13.cipher_suites)
      && client_offers_any_group(client_hello, &tls13.key_exchange_groups)
    {
      return tls13.config.clone();
    }
    if let Some(tls12) = &self.tls12
      && client_offers_any_cipher(client_hello, &tls12.cipher_suites)
      && client_offers_any_group(client_hello, &tls12.key_exchange_groups)
    {
      return tls12.config.clone();
    }
    self
      .tls13
      .as_ref()
      .or(self.tls12.as_ref())
      .expect("TLS config set must include at least one version")
      .config
      .clone()
  }
}

#[derive(Debug)]
struct TlsServerVersionConfig {
  config: Arc<ServerConfig>,
  key_exchange_groups: Vec<TlsKeyExchangeGroup>,
  cipher_suites: Vec<CipherSuite>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_downstream_tls_server_config_with_resumption_and_ocsp(
  crypto: &CryptoConfig,
  tls: &TlsConfig,
  listeners: &ListenerConfig,
  routes: &[RouteConfig],
  max_early_data_size: u32,
  resumption_state: Option<&TlsResumptionState>,
  ocsp_runtime: Option<&OcspStapleRuntime>,
  crlite_runtime: Option<&CrliteRuntime>,
) -> anyhow::Result<DownstreamTlsServerConfig> {
  let default_policy = tls.negotiation_policy();
  let certificate_partitions = downstream_resumption_partitions(tls)?;
  let default_certificate_identity = certificate_partitions
    .as_ref()
    .map(|partitions| partitions.default_identity().to_string());
  let mut policies = HashMap::<TcpServerConfigKey, Arc<TlsServerConfigSet>>::new();
  let tcp_build = super::DownstreamTcpTlsBuild::new(
    crypto,
    tls,
    listeners,
    max_early_data_size,
    resumption_state,
    ocsp_runtime,
    crlite_runtime,
  );
  let default_key = TcpServerConfigKey {
    policy: default_policy.clone(),
    certificate_identity: default_certificate_identity.clone(),
  };
  build_or_get_tcp_policy(&mut policies, &tcp_build, default_key.clone())?;
  if let Some(partitions) = &certificate_partitions {
    for identity in partitions.identities() {
      build_or_get_tcp_policy(
        &mut policies,
        &tcp_build,
        TcpServerConfigKey {
          policy: default_policy.clone(),
          certificate_identity: Some(identity),
        },
      )?;
    }
  }
  let mut by_sni_policy = HashMap::new();
  for route in routes {
    if !route.tls.has_negotiation_overrides() {
      continue;
    }
    let policy = tls.effective_route_negotiation_policy(&route.tls);
    for host in &route.hosts {
      let normalized_host = host.to_ascii_lowercase();
      let certificate_identity = certificate_partitions.as_ref().map(|partitions| {
        partitions
          .identity_for_sni_or_default(Some(&normalized_host))
          .to_string()
      });
      build_or_get_tcp_policy(
        &mut policies,
        &tcp_build,
        TcpServerConfigKey {
          policy: policy.clone(),
          certificate_identity,
        },
      )
      .with_context(|| format!("failed to build route {} downstream TLS policy", route.name))?;
      by_sni_policy.insert(normalized_host, policy.clone());
    }
  }
  Ok(DownstreamTlsServerConfig {
    configs: Arc::new(policies),
    default_key,
    default_policy,
    by_sni_policy: Arc::new(by_sni_policy),
    certificate_partitions: certificate_partitions.map(Arc::new),
  })
}

pub(crate) fn build_turn_tls_server_config_with_resumption(
  crypto: &CryptoConfig,
  listener_tls: &crate::config::TurnListenerTlsConfig,
  default_tls: &TlsConfig,
  resumption_state: Option<&TlsResumptionState>,
) -> anyhow::Result<TurnTlsServerConfig> {
  let policy = default_tls.negotiation_policy();
  let tls13 = if default_tls.max_version >= TlsVersion::Tls13 {
    Some(TlsServerVersionConfig {
      config: super::build_turn_server_config_for_tls13(
        listener_tls,
        default_tls,
        crypto,
        &policy.tls13.key_exchange_groups,
        &policy.tls13.ciphers,
        &[&rustls::version::TLS13],
        resumption_state,
      )?,
      key_exchange_groups: policy.tls13.key_exchange_groups.clone(),
      cipher_suites: tls13_cipher_suites(crypto, &policy.tls13.ciphers)?,
    })
  } else {
    None
  };
  let tls12 = if default_tls.min_version <= TlsVersion::Tls12 {
    Some(TlsServerVersionConfig {
      config: super::build_turn_server_config_for_tls12(
        listener_tls,
        default_tls,
        crypto,
        &policy.tls12.key_exchange_groups,
        &policy.tls12.groups,
        &[&rustls::version::TLS12],
        resumption_state,
      )?,
      key_exchange_groups: policy.tls12.key_exchange_groups.clone(),
      cipher_suites: tls12_cipher_suites(crypto, &policy.tls12.groups)?,
    })
  } else {
    None
  };
  if tls13.is_none() && tls12.is_none() {
    bail!("TURN TLS policy must allow at least one protocol version");
  }
  Ok(TurnTlsServerConfig {
    config_set: Arc::new(TlsServerConfigSet { tls13, tls12 }),
  })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_downstream_quic_server_config_with_resumption_and_ocsp(
  crypto: &CryptoConfig,
  tls: &TlsConfig,
  quic: &QuicConfig,
  quic_host_key_base_dir: Option<&Path>,
  routes: &[RouteConfig],
  resumption_state: Option<&TlsResumptionState>,
  ocsp_runtime: Option<&OcspStapleRuntime>,
  crlite_runtime: Option<&CrliteRuntime>,
) -> anyhow::Result<DownstreamQuicServerConfig> {
  let certificate_partitions = downstream_resumption_partitions(tls)?;
  let default_certificate_identity = certificate_partitions
    .as_ref()
    .map(|partitions| partitions.default_identity().to_string());
  let mut policy_indices = HashMap::<QuicServerConfigKey, usize>::new();
  let mut configs = Vec::new();
  let default_key = QuicServerConfigKey {
    policy: tls.tls13.clone(),
    certificate_identity: default_certificate_identity,
  };
  let default_index = build_or_get_quic_policy(
    &mut policy_indices,
    &mut configs,
    tls,
    crypto,
    quic,
    quic_host_key_base_dir,
    default_key,
    resumption_state,
    ocsp_runtime,
    crlite_runtime,
  )?;
  debug_assert_eq!(default_index, 0);
  if let Some(partitions) = &certificate_partitions {
    for identity in partitions.identities() {
      build_or_get_quic_policy(
        &mut policy_indices,
        &mut configs,
        tls,
        crypto,
        quic,
        quic_host_key_base_dir,
        QuicServerConfigKey {
          policy: tls.tls13.clone(),
          certificate_identity: Some(identity),
        },
        resumption_state,
        ocsp_runtime,
        crlite_runtime,
      )?;
    }
  }

  let mut by_sni_policy = HashMap::new();
  let mut reject_sni = HashSet::new();
  for route in routes {
    if !route.tls.has_negotiation_overrides() {
      continue;
    }
    let policy = tls.effective_route_negotiation_policy(&route.tls);
    if !policy.allows_tls13() {
      for host in &route.hosts {
        reject_sni.insert(host.to_ascii_lowercase());
      }
      continue;
    }
    for host in &route.hosts {
      let normalized_host = host.to_ascii_lowercase();
      let certificate_identity = certificate_partitions.as_ref().map(|partitions| {
        partitions
          .identity_for_sni_or_default(Some(&normalized_host))
          .to_string()
      });
      build_or_get_quic_policy(
        &mut policy_indices,
        &mut configs,
        tls,
        crypto,
        quic,
        quic_host_key_base_dir,
        QuicServerConfigKey {
          policy: policy.tls13.clone(),
          certificate_identity,
        },
        resumption_state,
        ocsp_runtime,
        crlite_runtime,
      )
      .with_context(|| {
        format!(
          "failed to build route {} downstream QUIC policy for host {}",
          route.name, host
        )
      })?;
      by_sni_policy.insert(normalized_host, policy.tls13.clone());
    }
  }

  Ok(DownstreamQuicServerConfig {
    configs: Arc::new(configs),
    indices: Arc::new(policy_indices),
    default_policy: tls.tls13.clone(),
    by_sni_policy: Arc::new(by_sni_policy),
    reject_sni: Arc::new(reject_sni),
    certificate_partitions: certificate_partitions.map(Arc::new),
  })
}

#[allow(clippy::too_many_arguments)]
fn build_or_get_quic_policy(
  policy_indices: &mut HashMap<QuicServerConfigKey, usize>,
  configs: &mut Vec<QuinnServerConfig>,
  tls: &TlsConfig,
  crypto: &CryptoConfig,
  quic: &QuicConfig,
  quic_host_key_base_dir: Option<&Path>,
  key: QuicServerConfigKey,
  resumption_state: Option<&TlsResumptionState>,
  ocsp_runtime: Option<&OcspStapleRuntime>,
  crlite_runtime: Option<&CrliteRuntime>,
) -> anyhow::Result<usize> {
  if let Some(index) = policy_indices.get(&key) {
    return Ok(*index);
  }
  let config = super::build_downstream_quic_server_config_for_tls13(
    tls,
    quic,
    quic_host_key_base_dir,
    crypto,
    &key.policy.key_exchange_groups,
    &key.policy.ciphers,
    key.certificate_identity.as_deref(),
    resumption_state,
    ocsp_runtime,
    crlite_runtime,
  )?;
  let index = configs.len();
  configs.push(config);
  policy_indices.insert(key, index);
  Ok(index)
}

fn downstream_resumption_partitions(
  tls: &TlsConfig,
) -> anyhow::Result<Option<DownstreamCertificatePartitions>> {
  if tls.resumption.multi_certificate != TlsMultiCertificateResumptionMode::PartitionBySni {
    return Ok(None);
  }
  downstream_certificate_partitions(tls).map(Some)
}

fn build_or_get_tcp_policy(
  policies: &mut HashMap<TcpServerConfigKey, Arc<TlsServerConfigSet>>,
  build: &super::DownstreamTcpTlsBuild<'_>,
  key: TcpServerConfigKey,
) -> anyhow::Result<Arc<TlsServerConfigSet>> {
  if let Some(config) = policies.get(&key) {
    return Ok(config.clone());
  }
  let config = Arc::new(build_tcp_policy(build, &key)?);
  policies.insert(key, config.clone());
  Ok(config)
}

fn build_tcp_policy(
  build: &super::DownstreamTcpTlsBuild<'_>,
  key: &TcpServerConfigKey,
) -> anyhow::Result<TlsServerConfigSet> {
  let policy = &key.policy;
  let build = build
    .clone()
    .with_certificate_partition_identity(key.certificate_identity.clone());
  let tls13 = if policy.allows_tls13() {
    let cipher_suites = tls13_cipher_suites(build.crypto, &policy.tls13.ciphers)?;
    Some(TlsServerVersionConfig {
      config: super::build_downstream_tcp_server_config_for_tls13(
        build.clone(),
        &policy.tls13.key_exchange_groups,
        &policy.tls13.ciphers,
        &[&rustls::version::TLS13],
      )?,
      key_exchange_groups: policy.tls13.key_exchange_groups.clone(),
      cipher_suites,
    })
  } else {
    None
  };
  let tls12 = if policy.allows_tls12() {
    let cipher_suites = tls12_cipher_suites(build.crypto, &policy.tls12.groups)?;
    Some(TlsServerVersionConfig {
      config: super::build_downstream_tcp_server_config_for_tls12(
        build.with_max_early_data_size(0),
        &policy.tls12.key_exchange_groups,
        &policy.tls12.groups,
        &[&rustls::version::TLS12],
      )?,
      key_exchange_groups: policy.tls12.key_exchange_groups.clone(),
      cipher_suites,
    })
  } else {
    None
  };
  if tls13.is_none() && tls12.is_none() {
    bail!("TLS policy must allow at least one protocol version");
  }
  Ok(TlsServerConfigSet { tls13, tls12 })
}

fn tls13_cipher_suites(
  crypto: &CryptoConfig,
  ciphers: &[crate::config::Tls13CipherSuite],
) -> anyhow::Result<Vec<CipherSuite>> {
  ciphers
    .iter()
    .copied()
    .map(|cipher| super::negotiation::supported_tls13_cipher_suite(crypto.tls_provider, cipher))
    .map(|suite| suite.map(|suite| suite.suite()))
    .collect()
}

fn tls12_cipher_suites(
  crypto: &CryptoConfig,
  ciphers: &[crate::config::Tls12CipherSuite],
) -> anyhow::Result<Vec<CipherSuite>> {
  ciphers
    .iter()
    .copied()
    .map(|cipher| super::negotiation::supported_tls12_cipher_suite(crypto.tls_provider, cipher))
    .map(|suite| suite.map(|suite| suite.suite()))
    .collect()
}

fn client_offers_any_cipher(
  client_hello: &rustls::server::ClientHello<'_>,
  ciphers: &[CipherSuite],
) -> bool {
  client_hello
    .cipher_suites()
    .iter()
    .any(|suite| ciphers.contains(suite))
}

fn client_offers_any_group(
  client_hello: &rustls::server::ClientHello<'_>,
  groups: &[TlsKeyExchangeGroup],
) -> bool {
  let Some(offered) = client_hello.named_groups() else {
    return false;
  };
  groups
    .iter()
    .map(|group| named_group(*group))
    .any(|group| offered.contains(&group))
}

fn named_group(group: TlsKeyExchangeGroup) -> NamedGroup {
  match group {
    TlsKeyExchangeGroup::X25519MlKem768 => NamedGroup::X25519MLKEM768,
    TlsKeyExchangeGroup::X25519 => NamedGroup::X25519,
    TlsKeyExchangeGroup::Secp256r1 => NamedGroup::secp256r1,
    TlsKeyExchangeGroup::Secp384r1 => NamedGroup::secp384r1,
  }
}

#[cfg(test)]
#[path = "server_policy_tests.rs"]
mod tests;

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, bail};
use h3_quinn::quinn::ServerConfig as QuinnServerConfig;
use rustls::{CipherSuite, NamedGroup, ServerConfig};

use crate::config::{
  ListenerConfig, QuicConfig, RouteConfig, Tls13NegotiationConfig, TlsConfig, TlsKeyExchangeGroup,
  TlsNegotiationPolicy, TlsVersion,
};

use super::{CrliteRuntime, OcspStapleRuntime, TlsResumptionState};

#[derive(Debug, Clone)]
pub struct DownstreamTlsServerConfig {
  default: Arc<TlsServerConfigSet>,
  by_sni: Arc<HashMap<String, Arc<TlsServerConfigSet>>>,
  default_policy: TlsNegotiationPolicy,
  by_sni_policy: Arc<HashMap<String, TlsNegotiationPolicy>>,
}

impl DownstreamTlsServerConfig {
  pub(crate) fn select(&self, client_hello: &rustls::server::ClientHello<'_>) -> Arc<ServerConfig> {
    let config_set = client_hello
      .server_name()
      .and_then(|name| self.by_sni.get(&name.to_ascii_lowercase()))
      .unwrap_or(&self.default);
    config_set.select(client_hello)
  }

  pub(crate) fn selected_negotiation_policy(&self, sni: Option<&str>) -> &TlsNegotiationPolicy {
    sni
      .and_then(|name| self.by_sni_policy.get(&name.to_ascii_lowercase()))
      .unwrap_or(&self.default_policy)
  }
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
  by_sni: Arc<HashMap<String, usize>>,
  reject_sni: Arc<HashSet<String>>,
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
    let Some(name) = sni else {
      return Some(0);
    };
    let name = name.to_ascii_lowercase();
    if self.reject_sni.contains(&name) {
      return None;
    }
    Some(self.by_sni.get(&name).copied().unwrap_or(0))
  }
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

pub(crate) fn build_downstream_tls_server_config_with_resumption_and_ocsp(
  tls: &TlsConfig,
  listeners: &ListenerConfig,
  routes: &[RouteConfig],
  max_early_data_size: u32,
  resumption_state: Option<&TlsResumptionState>,
  ocsp_runtime: Option<&OcspStapleRuntime>,
  crlite_runtime: Option<&CrliteRuntime>,
) -> anyhow::Result<DownstreamTlsServerConfig> {
  let default_policy = tls.negotiation_policy();
  let mut policies = HashMap::<TlsNegotiationPolicy, Arc<TlsServerConfigSet>>::new();
  let tcp_build = super::DownstreamTcpTlsBuild::new(
    tls,
    listeners,
    max_early_data_size,
    resumption_state,
    ocsp_runtime,
    crlite_runtime,
  );
  let default = build_or_get_tcp_policy(&mut policies, tcp_build, &default_policy)?;
  let mut by_sni = HashMap::new();
  let mut by_sni_policy = HashMap::new();
  for route in routes {
    if !route.tls.has_negotiation_overrides() {
      continue;
    }
    let policy = tls.effective_route_negotiation_policy(&route.tls);
    let config_set = build_or_get_tcp_policy(&mut policies, tcp_build, &policy)
      .with_context(|| format!("failed to build route {} downstream TLS policy", route.name))?;
    for host in &route.hosts {
      let normalized_host = host.to_ascii_lowercase();
      by_sni.insert(normalized_host.clone(), config_set.clone());
      by_sni_policy.insert(normalized_host, policy.clone());
    }
  }
  Ok(DownstreamTlsServerConfig {
    default,
    by_sni: Arc::new(by_sni),
    default_policy,
    by_sni_policy: Arc::new(by_sni_policy),
  })
}

pub(crate) fn build_turn_tls_server_config_with_resumption(
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
        &policy.tls13.key_exchange_groups,
        &policy.tls13.ciphers,
        &[&rustls::version::TLS13],
        resumption_state,
      )?,
      key_exchange_groups: policy.tls13.key_exchange_groups.clone(),
      cipher_suites: tls13_cipher_suites(&policy.tls13.ciphers),
    })
  } else {
    None
  };
  let tls12 = if default_tls.min_version <= TlsVersion::Tls12 {
    Some(TlsServerVersionConfig {
      config: super::build_turn_server_config_for_tls12(
        listener_tls,
        default_tls,
        &policy.tls12.key_exchange_groups,
        &policy.tls12.groups,
        &[&rustls::version::TLS12],
        resumption_state,
      )?,
      key_exchange_groups: policy.tls12.key_exchange_groups.clone(),
      cipher_suites: tls12_cipher_suites(&policy.tls12.groups),
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

pub(crate) fn build_downstream_quic_server_config_with_resumption_and_ocsp(
  tls: &TlsConfig,
  quic: &QuicConfig,
  quic_host_key_base_dir: Option<&Path>,
  routes: &[RouteConfig],
  resumption_state: Option<&TlsResumptionState>,
  ocsp_runtime: Option<&OcspStapleRuntime>,
  crlite_runtime: Option<&CrliteRuntime>,
) -> anyhow::Result<DownstreamQuicServerConfig> {
  let mut policy_indices = HashMap::<Tls13NegotiationConfig, usize>::new();
  let mut configs = Vec::new();
  let default_index = build_or_get_quic_policy(
    &mut policy_indices,
    &mut configs,
    tls,
    quic,
    quic_host_key_base_dir,
    &tls.tls13,
    resumption_state,
    ocsp_runtime,
    crlite_runtime,
  )?;
  debug_assert_eq!(default_index, 0);

  let mut by_sni = HashMap::new();
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
    let index = build_or_get_quic_policy(
      &mut policy_indices,
      &mut configs,
      tls,
      quic,
      quic_host_key_base_dir,
      &policy.tls13,
      resumption_state,
      ocsp_runtime,
      crlite_runtime,
    )
    .with_context(|| {
      format!(
        "failed to build route {} downstream QUIC policy",
        route.name
      )
    })?;
    for host in &route.hosts {
      by_sni.insert(host.to_ascii_lowercase(), index);
    }
  }

  Ok(DownstreamQuicServerConfig {
    configs: Arc::new(configs),
    by_sni: Arc::new(by_sni),
    reject_sni: Arc::new(reject_sni),
  })
}

#[allow(clippy::too_many_arguments)]
fn build_or_get_quic_policy(
  policy_indices: &mut HashMap<Tls13NegotiationConfig, usize>,
  configs: &mut Vec<QuinnServerConfig>,
  tls: &TlsConfig,
  quic: &QuicConfig,
  quic_host_key_base_dir: Option<&Path>,
  policy: &Tls13NegotiationConfig,
  resumption_state: Option<&TlsResumptionState>,
  ocsp_runtime: Option<&OcspStapleRuntime>,
  crlite_runtime: Option<&CrliteRuntime>,
) -> anyhow::Result<usize> {
  if let Some(index) = policy_indices.get(policy) {
    return Ok(*index);
  }
  let config = super::build_downstream_quic_server_config_for_tls13(
    tls,
    quic,
    quic_host_key_base_dir,
    &policy.key_exchange_groups,
    &policy.ciphers,
    resumption_state,
    ocsp_runtime,
    crlite_runtime,
  )?;
  let index = configs.len();
  configs.push(config);
  policy_indices.insert(policy.clone(), index);
  Ok(index)
}

fn build_or_get_tcp_policy(
  policies: &mut HashMap<TlsNegotiationPolicy, Arc<TlsServerConfigSet>>,
  build: super::DownstreamTcpTlsBuild<'_>,
  policy: &TlsNegotiationPolicy,
) -> anyhow::Result<Arc<TlsServerConfigSet>> {
  if let Some(config) = policies.get(policy) {
    return Ok(config.clone());
  }
  let config = Arc::new(build_tcp_policy(build, policy)?);
  policies.insert(policy.clone(), config.clone());
  Ok(config)
}

fn build_tcp_policy(
  build: super::DownstreamTcpTlsBuild<'_>,
  policy: &TlsNegotiationPolicy,
) -> anyhow::Result<TlsServerConfigSet> {
  let tls13 = if policy.allows_tls13() {
    Some(TlsServerVersionConfig {
      config: super::build_downstream_tcp_server_config_for_tls13(
        build,
        &policy.tls13.key_exchange_groups,
        &policy.tls13.ciphers,
        &[&rustls::version::TLS13],
      )?,
      key_exchange_groups: policy.tls13.key_exchange_groups.clone(),
      cipher_suites: tls13_cipher_suites(&policy.tls13.ciphers),
    })
  } else {
    None
  };
  let tls12 = if policy.allows_tls12() {
    Some(TlsServerVersionConfig {
      config: super::build_downstream_tcp_server_config_for_tls12(
        build.with_max_early_data_size(0),
        &policy.tls12.key_exchange_groups,
        &policy.tls12.groups,
        &[&rustls::version::TLS12],
      )?,
      key_exchange_groups: policy.tls12.key_exchange_groups.clone(),
      cipher_suites: tls12_cipher_suites(&policy.tls12.groups),
    })
  } else {
    None
  };
  if tls13.is_none() && tls12.is_none() {
    bail!("TLS policy must allow at least one protocol version");
  }
  Ok(TlsServerConfigSet { tls13, tls12 })
}

fn tls13_cipher_suites(ciphers: &[crate::config::Tls13CipherSuite]) -> Vec<CipherSuite> {
  ciphers
    .iter()
    .copied()
    .map(super::negotiation::supported_tls13_cipher_suite)
    .map(|suite| suite.suite())
    .collect()
}

fn tls12_cipher_suites(ciphers: &[crate::config::Tls12CipherSuite]) -> Vec<CipherSuite> {
  ciphers
    .iter()
    .copied()
    .map(super::negotiation::supported_tls12_cipher_suite)
    .map(|suite| suite.suite())
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
mod tests {
  use std::path::{Path, PathBuf};
  use std::sync::Arc;

  use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
  use rustls::{ClientConfig, ProtocolVersion, RootCertStore};
  use tokio::net::{TcpListener, TcpStream};
  use tokio_rustls::{LazyConfigAcceptor, TlsConnector};

  use super::*;

  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  #[test]
  fn sni_version_policy_lookup_tracks_route_policy() {
    let temp_dir = common::TempDir::new("sni-version-policy-lookup");
    let (config, _) = sni_version_policy_config(&temp_dir);
    let server_config = downstream_tls_server_config(&config);
    assert_sni_policy_lookup(&server_config);
  }

  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn sni_version_policy_selects_tcp_tls_versions() {
    let temp_dir = common::TempDir::new("sni-version-policy");
    let (config, ca_cert_path) = sni_version_policy_config(&temp_dir);
    let server_config = downstream_tls_server_config(&config);

    let legacy_version = selected_tcp_tls_version(
      server_config.clone(),
      &ca_cert_path,
      "legacy.example.com",
      &[&rustls::version::TLS12],
    )
    .await;
    let default_version = selected_tcp_tls_version(
      server_config,
      &ca_cert_path,
      "example.com",
      &[&rustls::version::TLS13],
    )
    .await;

    assert_eq!(legacy_version, ProtocolVersion::TLSv1_2);
    assert_eq!(default_version, ProtocolVersion::TLSv1_3);
  }

  fn sni_version_policy_config(temp_dir: &common::TempDir) -> (crate::config::Config, PathBuf) {
    let (ca_cert_path, ca_key_path) =
      common::create_self_signed_cert(temp_dir.path(), "sni-version-policy-ca");
    let (default_cert, default_key) = common::create_ca_signed_server_cert(
      temp_dir.path(),
      "example.com",
      &ca_cert_path,
      &ca_key_path,
    );
    let (legacy_cert, legacy_key) = common::create_ca_signed_server_cert(
      temp_dir.path(),
      "legacy.example.com",
      &ca_cert_path,
      &ca_key_path,
    );
    let raw = common::minimal_config_toml(&default_cert, &default_key).replace(
      "[tls.ocsp]",
      &format!(
        r#"server_names = ["example.com"]

[tls.resumption]
mode = "off"

[[tls.certificates]]
server_names = ["legacy.example.com"]
cert_chain = "{}"
private_key = "{}"

[tls.ocsp]"#,
        legacy_cert.display(),
        legacy_key.display()
      ),
    ) + r#"

[[routes]]
name = "legacy-root"
hosts = ["legacy.example.com"]
path_prefix = "/"
upstream = "app"

[routes.tls]
min_version = "tls1.2"
max_version = "tls1.2"
"#;
    let config: crate::config::Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    (config, ca_cert_path)
  }

  fn downstream_tls_server_config(config: &crate::config::Config) -> DownstreamTlsServerConfig {
    build_downstream_tls_server_config_with_resumption_and_ocsp(
      &config.tls,
      &config.listeners,
      &config.routes,
      0,
      None,
      None,
      None,
    )
    .expect("server config should build")
  }

  fn assert_sni_policy_lookup(server_config: &DownstreamTlsServerConfig) {
    let legacy_policy = server_config.selected_negotiation_policy(Some("legacy.example.com"));
    assert_eq!(legacy_policy.min_version, TlsVersion::Tls12);
    assert_eq!(legacy_policy.max_version, TlsVersion::Tls12);
    let default_policy = server_config.selected_negotiation_policy(Some("example.com"));
    assert_eq!(default_policy.min_version, TlsVersion::Tls13);
    assert_eq!(default_policy.max_version, TlsVersion::Tls13);
    assert_eq!(
      server_config.selected_negotiation_policy(Some("unknown.example.com")),
      default_policy
    );
    assert_eq!(
      server_config.selected_negotiation_policy(None),
      default_policy
    );
  }

  async fn selected_tcp_tls_version(
    server_config: DownstreamTlsServerConfig,
    ca_cert_path: &Path,
    server_name: &str,
    versions: &[&'static rustls::SupportedProtocolVersion],
  ) -> ProtocolVersion {
    let listener = TcpListener::bind("127.0.0.1:0")
      .await
      .expect("server listener should bind");
    let addr = listener.local_addr().expect("listener addr should resolve");
    let server = tokio::spawn(async move {
      let (stream, _) = listener.accept().await.expect("server should accept");
      let start = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)
        .await
        .expect("server should read ClientHello");
      let selected_config = server_config.select(&start.client_hello());
      let tls_stream = start
        .into_stream(selected_config)
        .await
        .expect("server TLS handshake should complete");
      tls_stream
        .get_ref()
        .1
        .protocol_version()
        .expect("TLS version should be selected")
    });

    let client_config = tcp_client_config(ca_cert_path, versions);
    let stream = TcpStream::connect(addr)
      .await
      .expect("client should connect to server");
    TlsConnector::from(Arc::new(client_config))
      .connect(
        ServerName::try_from(server_name.to_string()).expect("server name should be valid"),
        stream,
      )
      .await
      .expect("client TLS handshake should complete");

    server.await.expect("server task should finish")
  }

  fn tcp_client_config(
    ca_cert_path: &Path,
    versions: &[&'static rustls::SupportedProtocolVersion],
  ) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    let certs = CertificateDer::pem_file_iter(ca_cert_path)
      .expect("CA cert file should open")
      .collect::<Result<Vec<_>, _>>()
      .expect("CA cert should parse");
    let (added, _) = roots.add_parsable_certificates(certs);
    assert!(added > 0, "CA root should be added");
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
      .with_protocol_versions(versions)
      .expect("client TLS versions should configure")
      .with_root_certificates(roots)
      .with_no_client_auth()
  }
}

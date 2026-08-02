//! Runtime upstream discovery registry and reconciliation.
//! Discovery providers update candidate upstreams without bypassing route validation.

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, anyhow};

use crate::config::{
  DiscoveryUpstreamScheme, DnsDiscoveryRecordType, UpstreamDiscoveryProvider,
  UpstreamPoolDiscoveryConfig, UpstreamPoolServerConfig, UpstreamPoolServerSource,
  UpstreamPoolServerState,
};
use crate::control_http::ControlHttpClient;
use crate::state::AppHandle;
use crate::upstream_control;
use crate::upstream_resolution::{DnsAnswer, DnsQueryType, lookup_dns};

mod enterprise;
mod file;
mod kubernetes;
mod nomad;
mod supervisor;
pub(crate) use supervisor::run_dynamic_upstream_discovery;

#[cfg(test)]
mod runtime_tests;

async fn apply_discovered_servers(
  state: &AppHandle,
  pool_name: &str,
  discovery: &UpstreamPoolDiscoveryConfig,
  servers: Vec<UpstreamPoolServerConfig>,
) -> anyhow::Result<()> {
  let source = discovery_source(discovery.provider);
  if discovered_servers_unchanged(state, pool_name, discovery, &servers)? {
    return Ok(());
  }
  let discovery_instance_id = discovery.effective_id().to_string();
  upstream_control::apply_runtime_pool_update(state, |config| {
    upstream_control::replace_discovered_servers(
      config,
      pool_name,
      source,
      &discovery_instance_id,
      servers.clone(),
    )
  })
  .await
}

fn discovery_source(provider: UpstreamDiscoveryProvider) -> UpstreamPoolServerSource {
  match provider {
    UpstreamDiscoveryProvider::Dns => UpstreamPoolServerSource::Dns,
    UpstreamDiscoveryProvider::File => UpstreamPoolServerSource::File,
    UpstreamDiscoveryProvider::Kubernetes => UpstreamPoolServerSource::Kubernetes,
    UpstreamDiscoveryProvider::Consul => UpstreamPoolServerSource::Consul,
    UpstreamDiscoveryProvider::Etcd => UpstreamPoolServerSource::Etcd,
    UpstreamDiscoveryProvider::Nomad => UpstreamPoolServerSource::Nomad,
  }
}

fn discovered_servers_unchanged(
  state: &AppHandle,
  pool_name: &str,
  discovery: &UpstreamPoolDiscoveryConfig,
  servers: &[UpstreamPoolServerConfig],
) -> anyhow::Result<bool> {
  let snapshot = state.snapshot();
  let existing = snapshot
    .config
    .upstream_pools
    .iter()
    .find(|pool| pool.name == pool_name)
    .ok_or_else(|| anyhow!("unknown upstream pool {pool_name}"))?;
  let mut candidate = snapshot.config.clone();
  upstream_control::replace_discovered_servers(
    &mut candidate,
    pool_name,
    discovery_source(discovery.provider),
    discovery.effective_id(),
    servers.to_vec(),
  )?;
  let candidate = candidate
    .upstream_pools
    .iter()
    .find(|pool| pool.name == pool_name)
    .ok_or_else(|| anyhow!("unknown upstream pool {pool_name}"))?;
  Ok(existing.servers == candidate.servers)
}

pub(crate) async fn discover_servers(
  client: &ControlHttpClient,
  discovery: &UpstreamPoolDiscoveryConfig,
) -> anyhow::Result<(Vec<UpstreamPoolServerConfig>, Duration)> {
  match discovery.provider {
    UpstreamDiscoveryProvider::File => file::discover_file_servers(discovery).await,
    UpstreamDiscoveryProvider::Dns => discover_dns_servers(discovery).await,
    UpstreamDiscoveryProvider::Kubernetes => {
      kubernetes::discover_kubernetes_servers(client, discovery).await
    }
    UpstreamDiscoveryProvider::Consul => {
      enterprise::discover_consul_servers(client, discovery).await
    }
    UpstreamDiscoveryProvider::Etcd => enterprise::discover_etcd_servers(client, discovery).await,
    UpstreamDiscoveryProvider::Nomad => {
      let result = nomad::discover_nomad_servers(client, discovery, None).await?;
      Ok((result.servers, result.delay))
    }
  }
}

async fn discover_dns_servers(
  discovery: &UpstreamPoolDiscoveryConfig,
) -> anyhow::Result<(Vec<UpstreamPoolServerConfig>, Duration)> {
  let name = discovery
    .name
    .as_deref()
    .ok_or_else(|| anyhow!("DNS discovery requires name"))?;
  let mut ttl_ms = discovery.refresh_interval_ms;
  let mut servers = Vec::new();

  match discovery.record_type {
    DnsDiscoveryRecordType::A => {
      let (answers, ttl) = lookup_dns(name, DnsQueryType::A).await?;
      ttl_ms = ttl_ms.min(ttl);
      servers.extend(ip_answers_to_servers(discovery, answers)?);
    }
    DnsDiscoveryRecordType::Aaaa => {
      let (answers, ttl) = lookup_dns(name, DnsQueryType::Aaaa).await?;
      ttl_ms = ttl_ms.min(ttl);
      servers.extend(ip_answers_to_servers(discovery, answers)?);
    }
    DnsDiscoveryRecordType::AAndAaaa => {
      for query_type in [DnsQueryType::A, DnsQueryType::Aaaa] {
        let (answers, ttl) = lookup_dns(name, query_type).await?;
        ttl_ms = ttl_ms.min(ttl);
        servers.extend(ip_answers_to_servers(discovery, answers)?);
      }
    }
    DnsDiscoveryRecordType::Srv => {
      let (answers, ttl) = lookup_dns(name, DnsQueryType::Srv).await?;
      ttl_ms = ttl_ms.min(ttl);
      let mut srv_records = answers
        .into_iter()
        .filter_map(|answer| match answer {
          DnsAnswer::Srv(record) => Some(record),
          _ => None,
        })
        .collect::<Vec<_>>();
      srv_records.sort_by_key(|record| (record.priority, record.target.clone(), record.port));
      for record in srv_records {
        for query_type in [DnsQueryType::A, DnsQueryType::Aaaa] {
          let (answers, target_ttl) = lookup_dns(&record.target, query_type).await?;
          ttl_ms = ttl_ms.min(target_ttl);
          for answer in answers {
            let DnsAnswer::Ip(ip) = answer else {
              continue;
            };
            servers.push(dns_ip_server(
              discovery.scheme,
              ip,
              record.port,
              &record.target,
            )?);
          }
        }
      }
    }
  }

  servers.sort_by(|left, right| {
    left
      .id
      .as_deref()
      .unwrap_or_default()
      .cmp(right.id.as_deref().unwrap_or_default())
  });
  servers.dedup_by(|left, right| left.id == right.id);
  let delay = ttl_ms.max(discovery.min_ttl_ms);
  Ok((servers, Duration::from_millis(delay)))
}

fn ip_answers_to_servers(
  discovery: &UpstreamPoolDiscoveryConfig,
  answers: Vec<DnsAnswer>,
) -> anyhow::Result<Vec<UpstreamPoolServerConfig>> {
  let port = discovery
    .port
    .ok_or_else(|| anyhow!("DNS A/AAAA discovery requires port"))?;
  answers
    .into_iter()
    .filter_map(|answer| match answer {
      DnsAnswer::Ip(ip) => Some(dns_ip_server(discovery.scheme, ip, port, &ip.to_string())),
      _ => None,
    })
    .collect()
}

fn dns_ip_server(
  scheme: DiscoveryUpstreamScheme,
  ip: IpAddr,
  port: u16,
  id_host: &str,
) -> anyhow::Result<UpstreamPoolServerConfig> {
  let host = match ip {
    IpAddr::V4(ip) => ip.to_string(),
    IpAddr::V6(ip) => format!("[{ip}]"),
  };
  let origin = format!("{}://{}:{}/", scheme.as_str(), host, port)
    .parse()
    .context("failed to build discovered DNS upstream origin")?;
  Ok(UpstreamPoolServerConfig {
    id: Some(upstream_control::stable_generated_server_id(&[
      "dns",
      id_host.trim_end_matches('.'),
      &port.to_string(),
    ])),
    origin,
    weight: 1,
    max_conns: 0,
    backup: false,
    state: UpstreamPoolServerState::Ready,
    tls: Default::default(),
    source: UpstreamPoolServerSource::Dns,
    discovery_instance_id: None,
    discovered_weight: None,
  })
}

fn default_discovered_weight() -> u32 {
  1
}

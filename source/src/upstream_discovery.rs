use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use serde::Deserialize;
use tokio::net::UdpSocket;
use tokio::sync::watch;

use crate::config::{
  DiscoveryUpstreamScheme, DnsDiscoveryRecordType, UpstreamDiscoveryProvider,
  UpstreamPoolDiscoveryConfig, UpstreamPoolServerConfig, UpstreamPoolServerSource,
  UpstreamPoolServerState,
};
use crate::state::AppHandle;
use crate::upstream_control;

pub(crate) async fn run_dynamic_upstream_discovery(
  state: AppHandle,
  mut shutdown: watch::Receiver<bool>,
) {
  let mut next_checks: HashMap<(String, usize), Instant> = HashMap::new();

  loop {
    if *shutdown.borrow() {
      break;
    }

    let snapshot = state.snapshot();
    let now = Instant::now();
    let mut next_sleep = Duration::from_secs(5);

    for pool in &snapshot.config.upstream_pools {
      for (index, discovery) in pool.discovery.iter().cloned().enumerate() {
        let key = (pool.name.clone(), index);
        let due = next_checks.entry(key).or_insert(now);
        if *due > now {
          next_sleep = next_sleep.min(*due - now);
          continue;
        }

        let fallback_delay = Duration::from_millis(discovery.refresh_interval_ms);
        let result = discover_servers(&discovery).await;
        let delay = match result {
          Ok((servers, delay)) => {
            if let Err(error) =
              apply_discovered_servers(&state, &pool.name, discovery.provider, servers).await
            {
              tracing::warn!(
                error = %error,
                pool = %pool.name,
                provider = ?discovery.provider,
                "dynamic upstream discovery update rejected; keeping previous pool state"
              );
            }
            delay
          }
          Err(error) => {
            tracing::warn!(
              error = %error,
              pool = %pool.name,
              provider = ?discovery.provider,
              "dynamic upstream discovery failed; keeping previous pool state"
            );
            fallback_delay
          }
        };
        next_checks.insert((pool.name.clone(), index), Instant::now() + delay);
        next_sleep = next_sleep.min(delay);
      }
    }

    tokio::select! {
      _ = shutdown.changed() => {}
      _ = tokio::time::sleep(next_sleep) => {}
    }
  }
}

async fn apply_discovered_servers(
  state: &AppHandle,
  pool_name: &str,
  provider: UpstreamDiscoveryProvider,
  servers: Vec<UpstreamPoolServerConfig>,
) -> anyhow::Result<()> {
  let source = match provider {
    UpstreamDiscoveryProvider::Dns => UpstreamPoolServerSource::Dns,
    UpstreamDiscoveryProvider::File => UpstreamPoolServerSource::File,
    UpstreamDiscoveryProvider::Kubernetes
    | UpstreamDiscoveryProvider::Consul
    | UpstreamDiscoveryProvider::Etcd => {
      bail!("unsupported discovery provider {provider:?}");
    }
  };
  upstream_control::apply_runtime_pool_update(state, |config| {
    upstream_control::replace_discovered_servers(config, pool_name, source, servers)
  })
  .await
}

async fn discover_servers(
  discovery: &UpstreamPoolDiscoveryConfig,
) -> anyhow::Result<(Vec<UpstreamPoolServerConfig>, Duration)> {
  match discovery.provider {
    UpstreamDiscoveryProvider::File => discover_file_servers(discovery).await,
    UpstreamDiscoveryProvider::Dns => discover_dns_servers(discovery).await,
    UpstreamDiscoveryProvider::Kubernetes
    | UpstreamDiscoveryProvider::Consul
    | UpstreamDiscoveryProvider::Etcd => {
      bail!("discovery provider {:?} is reserved", discovery.provider);
    }
  }
}

#[derive(Debug, Deserialize)]
struct FileDiscoveryDocument {
  servers: Vec<FileDiscoveryServer>,
}

#[derive(Debug, Deserialize)]
struct FileDiscoveryServer {
  id: String,
  origin: url::Url,
  #[serde(default = "default_discovered_weight")]
  weight: u32,
  #[serde(default)]
  max_conns: usize,
  #[serde(default)]
  backup: bool,
  #[serde(default)]
  state: UpstreamPoolServerState,
}

async fn discover_file_servers(
  discovery: &UpstreamPoolDiscoveryConfig,
) -> anyhow::Result<(Vec<UpstreamPoolServerConfig>, Duration)> {
  let path = discovery
    .file
    .as_ref()
    .ok_or_else(|| anyhow!("file discovery requires file"))?;
  let raw = tokio::fs::read_to_string(path)
    .await
    .with_context(|| format!("failed to read file discovery {}", path.display()))?;
  let document: FileDiscoveryDocument = serde_json::from_str(&raw)
    .with_context(|| format!("failed to parse file discovery {}", path.display()))?;
  let servers = document
    .servers
    .into_iter()
    .map(|server| {
      if server.weight == 0 {
        bail!(
          "file discovery server {} weight must be greater than 0",
          server.id
        );
      }
      Ok(UpstreamPoolServerConfig {
        id: Some(server.id),
        origin: server.origin,
        weight: server.weight,
        max_conns: server.max_conns,
        backup: server.backup,
        state: server.state,
        source: UpstreamPoolServerSource::File,
      })
    })
    .collect::<anyhow::Result<Vec<_>>>()?;
  Ok((
    servers,
    Duration::from_millis(discovery.refresh_interval_ms),
  ))
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
    source: UpstreamPoolServerSource::Dns,
  })
}

fn default_discovered_weight() -> u32 {
  1
}

#[derive(Debug, Clone, Copy)]
enum DnsQueryType {
  A = 1,
  Aaaa = 28,
  Srv = 33,
}

enum DnsAnswer {
  Ip(IpAddr),
  Srv(SrvRecord),
}

struct SrvRecord {
  priority: u16,
  port: u16,
  target: String,
}

async fn lookup_dns(name: &str, query_type: DnsQueryType) -> anyhow::Result<(Vec<DnsAnswer>, u64)> {
  let query = build_dns_query(name, query_type)?;
  let mut last_error = None;
  for server in dns_nameservers() {
    match query_nameserver(server, &query).await {
      Ok(response) => return parse_dns_response(&response, query_type),
      Err(error) => last_error = Some(error),
    }
  }
  Err(last_error.unwrap_or_else(|| anyhow!("no DNS nameservers configured")))
}

async fn query_nameserver(server: SocketAddr, query: &[u8]) -> anyhow::Result<Vec<u8>> {
  let bind_addr: SocketAddr = if server.is_ipv4() {
    "0.0.0.0:0".parse().expect("valid IPv4 bind")
  } else {
    "[::]:0".parse().expect("valid IPv6 bind")
  };
  let socket = UdpSocket::bind(bind_addr).await?;
  socket.connect(server).await?;
  socket.send(query).await?;
  let mut response = vec![0_u8; 4096];
  let len = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut response))
    .await
    .context("DNS query timed out")??;
  response.truncate(len);
  Ok(response)
}

fn dns_nameservers() -> Vec<SocketAddr> {
  let Some(content) = std::fs::read_to_string("/etc/resolv.conf").ok() else {
    return Vec::new();
  };
  content
    .lines()
    .filter_map(|line| {
      let line = line.split('#').next().unwrap_or_default().trim();
      let raw = line.strip_prefix("nameserver")?.trim();
      let ip = raw.parse::<IpAddr>().ok()?;
      Some(SocketAddr::new(ip, 53))
    })
    .collect()
}

fn build_dns_query(name: &str, query_type: DnsQueryType) -> anyhow::Result<Vec<u8>> {
  let id = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .subsec_nanos() as u16;
  let mut query = Vec::new();
  query.extend_from_slice(&id.to_be_bytes());
  query.extend_from_slice(&0x0100_u16.to_be_bytes());
  query.extend_from_slice(&1_u16.to_be_bytes());
  query.extend_from_slice(&0_u16.to_be_bytes());
  query.extend_from_slice(&0_u16.to_be_bytes());
  query.extend_from_slice(&0_u16.to_be_bytes());
  encode_dns_name(name, &mut query)?;
  query.extend_from_slice(&(query_type as u16).to_be_bytes());
  query.extend_from_slice(&1_u16.to_be_bytes());
  Ok(query)
}

fn encode_dns_name(name: &str, out: &mut Vec<u8>) -> anyhow::Result<()> {
  let trimmed = name.trim_end_matches('.');
  if trimmed.is_empty() {
    bail!("DNS name must not be empty");
  }
  for label in trimmed.split('.') {
    if label.is_empty() || label.len() > 63 {
      bail!("DNS name contains an invalid label");
    }
    out.push(label.len() as u8);
    out.extend_from_slice(label.as_bytes());
  }
  out.push(0);
  Ok(())
}

fn parse_dns_response(
  response: &[u8],
  query_type: DnsQueryType,
) -> anyhow::Result<(Vec<DnsAnswer>, u64)> {
  if response.len() < 12 {
    bail!("DNS response is too short");
  }
  let qdcount = read_u16(response, 4)? as usize;
  let ancount = read_u16(response, 6)? as usize;
  let mut offset = 12;
  for _ in 0..qdcount {
    read_dns_name(response, &mut offset)?;
    offset += 4;
  }

  let mut answers = Vec::new();
  let mut min_ttl_ms = 30_000_u64;
  for _ in 0..ancount {
    read_dns_name(response, &mut offset)?;
    let record_type = read_u16(response, offset)?;
    offset += 2;
    let class = read_u16(response, offset)?;
    offset += 2;
    let ttl = read_u32(response, offset)?;
    offset += 4;
    let rdlen = read_u16(response, offset)? as usize;
    offset += 2;
    let rdata = offset;
    offset = offset
      .checked_add(rdlen)
      .ok_or_else(|| anyhow!("DNS response offset overflow"))?;
    if offset > response.len() || class != 1 {
      continue;
    }
    min_ttl_ms = min_ttl_ms.min(u64::from(ttl).saturating_mul(1_000));
    match (query_type, record_type, rdlen) {
      (DnsQueryType::A, 1, 4) => {
        answers.push(DnsAnswer::Ip(IpAddr::V4(Ipv4Addr::new(
          response[rdata],
          response[rdata + 1],
          response[rdata + 2],
          response[rdata + 3],
        ))));
      }
      (DnsQueryType::Aaaa, 28, 16) => {
        let octets: [u8; 16] = response[rdata..rdata + 16]
          .try_into()
          .expect("slice length checked");
        answers.push(DnsAnswer::Ip(IpAddr::V6(Ipv6Addr::from(octets))));
      }
      (DnsQueryType::Srv, 33, len) if len >= 6 => {
        let priority = read_u16(response, rdata)?;
        let _weight = read_u16(response, rdata + 2)?;
        let port = read_u16(response, rdata + 4)?;
        let mut target_offset = rdata + 6;
        let target = read_dns_name(response, &mut target_offset)?;
        answers.push(DnsAnswer::Srv(SrvRecord {
          priority,
          port,
          target,
        }));
      }
      _ => {}
    }
  }
  Ok((answers, min_ttl_ms))
}

fn read_dns_name(response: &[u8], offset: &mut usize) -> anyhow::Result<String> {
  let mut labels = Vec::new();
  let mut cursor = *offset;
  let mut jumped = false;
  for _ in 0..32 {
    let len = *response
      .get(cursor)
      .ok_or_else(|| anyhow!("DNS name offset out of bounds"))?;
    if len & 0xc0 == 0xc0 {
      let next = *response
        .get(cursor + 1)
        .ok_or_else(|| anyhow!("DNS compression pointer out of bounds"))?;
      let pointer = (((len & 0x3f) as usize) << 8) | next as usize;
      if !jumped {
        *offset = cursor + 2;
      }
      cursor = pointer;
      jumped = true;
      continue;
    }
    cursor += 1;
    if len == 0 {
      if !jumped {
        *offset = cursor;
      }
      return Ok(if labels.is_empty() {
        ".".to_string()
      } else {
        labels.join(".")
      });
    }
    let end = cursor
      .checked_add(len as usize)
      .ok_or_else(|| anyhow!("DNS label offset overflow"))?;
    let label = response
      .get(cursor..end)
      .ok_or_else(|| anyhow!("DNS label out of bounds"))?;
    labels.push(String::from_utf8_lossy(label).to_string());
    cursor = end;
  }
  bail!("DNS name compression chain is too deep")
}

fn read_u16(input: &[u8], offset: usize) -> anyhow::Result<u16> {
  let bytes = input
    .get(offset..offset + 2)
    .ok_or_else(|| anyhow!("DNS response is truncated"))?;
  Ok(u16::from_be_bytes(
    bytes.try_into().expect("slice length checked"),
  ))
}

fn read_u32(input: &[u8], offset: usize) -> anyhow::Result<u32> {
  let bytes = input
    .get(offset..offset + 4)
    .ok_or_else(|| anyhow!("DNS response is truncated"))?;
  Ok(u32::from_be_bytes(
    bytes.try_into().expect("slice length checked"),
  ))
}

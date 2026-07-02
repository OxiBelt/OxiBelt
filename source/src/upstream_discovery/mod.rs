//! Runtime upstream discovery registry and reconciliation.
//! Discovery providers update candidate upstreams without bypassing route validation.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use tokio::net::UdpSocket;

use crate::config::{
  DiscoveryUpstreamScheme, DnsDiscoveryRecordType, UpstreamDiscoveryProvider,
  UpstreamPoolDiscoveryConfig, UpstreamPoolServerConfig, UpstreamPoolServerSource,
  UpstreamPoolServerState, upstream_pool_server_id,
};
use crate::control_http::ControlHttpClient;
use crate::state::AppHandle;
use crate::upstream_control;

mod dns;
#[cfg(test)]
mod dns_tests;
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
  provider: UpstreamDiscoveryProvider,
  mut servers: Vec<UpstreamPoolServerConfig>,
) -> anyhow::Result<()> {
  let source = discovery_source(provider);
  if discovered_servers_unchanged(state, pool_name, source, &mut servers)? {
    return Ok(());
  }
  upstream_control::apply_runtime_pool_update(state, |config| {
    upstream_control::replace_discovered_servers(config, pool_name, source, servers.clone())
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
  source: UpstreamPoolServerSource,
  servers: &mut Vec<UpstreamPoolServerConfig>,
) -> anyhow::Result<bool> {
  let snapshot = state.snapshot();
  let pool = snapshot
    .config
    .upstream_pools
    .iter()
    .find(|pool| pool.name == pool_name)
    .ok_or_else(|| anyhow!("unknown upstream pool {pool_name}"))?;
  let previous_states = pool
    .servers
    .iter()
    .enumerate()
    .filter(|(_, server)| server.source == source)
    .map(|(index, server)| (upstream_pool_server_id(index, server), server.state))
    .collect::<HashMap<_, _>>();

  for (index, server) in servers.iter_mut().enumerate() {
    let server_id = upstream_pool_server_id(index, server);
    server.id = Some(server_id.clone());
    server.source = source;
    if let Some(state) = previous_states.get(&server_id) {
      server.state = *state;
    } else if server.state != UpstreamPoolServerState::Ready {
      server.state = UpstreamPoolServerState::Ready;
    }
  }

  let existing = pool
    .servers
    .iter()
    .filter(|server| server.source == source)
    .cloned()
    .collect::<Vec<_>>();
  Ok(existing == *servers)
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
    source: UpstreamPoolServerSource::Dns,
  })
}

fn default_discovered_weight() -> u32 {
  1
}

const DNS_CLASS_IN: u16 = 1;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_CNAME: u16 = 5;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_SRV: u16 = 33;
const DNS_DEFAULT_TTL_MS: u64 = 30_000;

#[derive(Debug)]
struct DnsQuery {
  id: u16,
  name: String,
  query_type: DnsQueryType,
  packet: Vec<u8>,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum DnsQueryType {
  A = DNS_TYPE_A,
  Aaaa = DNS_TYPE_AAAA,
  Srv = DNS_TYPE_SRV,
}

#[derive(Debug, PartialEq)]
enum DnsAnswer {
  Ip(IpAddr),
  Srv(SrvRecord),
}

#[derive(Debug, Clone, PartialEq)]
struct SrvRecord {
  priority: u16,
  port: u16,
  target: String,
}

#[derive(Debug)]
struct ParsedDnsRecord {
  owner: String,
  record_type: u16,
  ttl: u32,
  data: ParsedDnsRecordData,
}

#[derive(Debug)]
enum ParsedDnsRecordData {
  Ip(IpAddr),
  Srv(SrvRecord),
  Cname(String),
  Other,
}

async fn lookup_dns(name: &str, query_type: DnsQueryType) -> anyhow::Result<(Vec<DnsAnswer>, u64)> {
  let query = build_dns_query(name, query_type)?;
  let mut last_error = None;
  for server in dns_nameservers() {
    match query_nameserver(server, &query.packet).await {
      Ok(response) => return parse_dns_response(&response, &query),
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

fn build_dns_query(name: &str, query_type: DnsQueryType) -> anyhow::Result<DnsQuery> {
  let name = dns::canonical_dns_name(name)?;
  let id = random_dns_transaction_id()?;
  let mut packet = Vec::new();
  packet.extend_from_slice(&id.to_be_bytes());
  packet.extend_from_slice(&0x0100_u16.to_be_bytes());
  packet.extend_from_slice(&1_u16.to_be_bytes());
  packet.extend_from_slice(&0_u16.to_be_bytes());
  packet.extend_from_slice(&0_u16.to_be_bytes());
  packet.extend_from_slice(&0_u16.to_be_bytes());
  encode_dns_name(&name, &mut packet)?;
  packet.extend_from_slice(&(query_type as u16).to_be_bytes());
  packet.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
  Ok(DnsQuery {
    id,
    name,
    query_type,
    packet,
  })
}

fn encode_dns_name(name: &str, out: &mut Vec<u8>) -> anyhow::Result<()> {
  let name = dns::canonical_dns_name(name)?;
  for label in name.split('.') {
    if label.is_empty() || label.len() > 63 {
      bail!("DNS name contains an invalid label");
    }
    out.push(label.len() as u8);
    out.extend_from_slice(label.as_bytes());
  }
  out.push(0);
  Ok(())
}

fn random_dns_transaction_id() -> anyhow::Result<u16> {
  let mut bytes = [0_u8; 2];
  crate::crypto::random_fill(&mut bytes)
    .map_err(|_| anyhow!("failed to generate DNS transaction ID"))?;
  Ok(u16::from_be_bytes(bytes))
}

fn parse_dns_response(response: &[u8], query: &DnsQuery) -> anyhow::Result<(Vec<DnsAnswer>, u64)> {
  if response.len() < 12 {
    bail!("DNS response is too short");
  }
  let id = read_u16(response, 0)?;
  if id != query.id {
    bail!("DNS response transaction ID does not match query");
  }
  let flags = read_u16(response, 2)?;
  if flags & 0x8000 == 0 {
    bail!("DNS packet is not a response");
  }
  if flags & 0x7800 != 0 {
    bail!("DNS response opcode is not a standard query");
  }
  if flags & 0x0200 != 0 {
    bail!("DNS response is truncated");
  }
  if flags & 0x000f != 0 {
    bail!("DNS response returned error code {}", flags & 0x000f);
  }
  let qdcount = read_u16(response, 4)? as usize;
  let ancount = read_u16(response, 6)? as usize;
  let nscount = read_u16(response, 8)? as usize;
  let arcount = read_u16(response, 10)? as usize;
  if qdcount != 1 {
    bail!("DNS response question count does not match query");
  }
  let mut offset = 12;
  let question_name = dns::canonical_dns_name(&read_dns_name(response, &mut offset)?)?;
  let question_type = read_u16(response, offset)?;
  offset += 2;
  let question_class = read_u16(response, offset)?;
  offset += 2;
  if question_name != query.name
    || question_type != query.query_type as u16
    || question_class != DNS_CLASS_IN
  {
    bail!("DNS response question does not match query");
  }

  let mut records = Vec::new();
  for _ in 0..ancount {
    let owner = dns::canonical_dns_name(&read_dns_name(response, &mut offset)?)?;
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
    if offset > response.len() {
      bail!("DNS response is truncated");
    }
    if class != DNS_CLASS_IN {
      continue;
    }
    let data = match (record_type, rdlen) {
      (DNS_TYPE_A, 4) => ParsedDnsRecordData::Ip(IpAddr::V4(Ipv4Addr::new(
        response[rdata],
        response[rdata + 1],
        response[rdata + 2],
        response[rdata + 3],
      ))),
      (DNS_TYPE_AAAA, 16) => {
        let octets: [u8; 16] = response[rdata..rdata + 16]
          .try_into()
          .expect("slice length checked");
        ParsedDnsRecordData::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
      }
      (DNS_TYPE_CNAME, len) if len > 0 => {
        let mut target_offset = rdata;
        let target = read_dns_name(response, &mut target_offset)?;
        if target_offset > offset {
          bail!("DNS CNAME record is truncated");
        }
        ParsedDnsRecordData::Cname(dns::canonical_dns_name(&target)?)
      }
      (DNS_TYPE_SRV, len) if len >= 6 => {
        let priority = read_u16(response, rdata)?;
        let _weight = read_u16(response, rdata + 2)?;
        let port = read_u16(response, rdata + 4)?;
        let mut target_offset = rdata + 6;
        let target = read_dns_name(response, &mut target_offset)?;
        if target_offset > offset {
          bail!("DNS SRV record is truncated");
        }
        ParsedDnsRecordData::Srv(SrvRecord {
          priority,
          port,
          target: dns::canonical_dns_name(&target)?,
        })
      }
      _ => ParsedDnsRecordData::Other,
    };
    records.push(ParsedDnsRecord {
      owner,
      record_type,
      ttl,
      data,
    });
  }
  skip_dns_records(response, &mut offset, nscount + arcount)?;

  let (accepted_names, mut min_ttl_ms) = verified_answer_names(&query.name, &records);
  let mut answers = Vec::new();
  for record in records {
    if !accepted_names.contains(&record.owner) {
      continue;
    }
    match (query.query_type, record.record_type, record.data) {
      (DnsQueryType::A, DNS_TYPE_A, ParsedDnsRecordData::Ip(IpAddr::V4(ip))) => {
        min_ttl_ms = min_ttl_ms.min(u64::from(record.ttl).saturating_mul(1_000));
        answers.push(DnsAnswer::Ip(IpAddr::V4(ip)));
      }
      (DnsQueryType::Aaaa, DNS_TYPE_AAAA, ParsedDnsRecordData::Ip(IpAddr::V6(ip))) => {
        min_ttl_ms = min_ttl_ms.min(u64::from(record.ttl).saturating_mul(1_000));
        answers.push(DnsAnswer::Ip(IpAddr::V6(ip)));
      }
      (DnsQueryType::Srv, DNS_TYPE_SRV, ParsedDnsRecordData::Srv(srv_record)) => {
        min_ttl_ms = min_ttl_ms.min(u64::from(record.ttl).saturating_mul(1_000));
        answers.push(DnsAnswer::Srv(srv_record));
      }
      _ => {}
    }
  }
  Ok((answers, min_ttl_ms))
}

fn verified_answer_names(query_name: &str, records: &[ParsedDnsRecord]) -> (HashSet<String>, u64) {
  let mut accepted_names = HashSet::from([query_name.to_string()]);
  let mut min_ttl_ms = DNS_DEFAULT_TTL_MS;
  let mut changed = true;
  while changed {
    changed = false;
    for record in records {
      let ParsedDnsRecordData::Cname(target) = &record.data else {
        continue;
      };
      if !accepted_names.contains(&record.owner) {
        continue;
      }
      min_ttl_ms = min_ttl_ms.min(u64::from(record.ttl).saturating_mul(1_000));
      if accepted_names.insert(target.clone()) {
        changed = true;
      }
    }
  }
  (accepted_names, min_ttl_ms)
}

fn skip_dns_records(response: &[u8], offset: &mut usize, count: usize) -> anyhow::Result<()> {
  for _ in 0..count {
    read_dns_name(response, offset)?;
    *offset = offset
      .checked_add(8)
      .ok_or_else(|| anyhow!("DNS response offset overflow"))?;
    read_u16(response, *offset)?;
    let rdlen = read_u16(response, *offset)? as usize;
    *offset = offset
      .checked_add(2)
      .and_then(|value| value.checked_add(rdlen))
      .ok_or_else(|| anyhow!("DNS response offset overflow"))?;
    if *offset > response.len() {
      bail!("DNS response is truncated");
    }
  }
  Ok(())
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
    if len & 0xc0 != 0 {
      bail!("DNS label has invalid length bits");
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

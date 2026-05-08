use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};
use ring::rand::{SecureRandom, SystemRandom};
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
  let name = canonical_dns_name(name)?;
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
  let name = canonical_dns_name(name)?;
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
  SystemRandom::new()
    .fill(&mut bytes)
    .map_err(|_| anyhow!("failed to generate DNS transaction ID"))?;
  Ok(u16::from_be_bytes(bytes))
}

fn canonical_dns_name(name: &str) -> anyhow::Result<String> {
  let trimmed = name.trim_end_matches('.');
  if trimmed.is_empty() {
    bail!("DNS name must not be empty");
  }
  for label in trimmed.split('.') {
    if label.is_empty() || label.len() > 63 {
      bail!("DNS name contains an invalid label");
    }
  }
  Ok(trimmed.to_ascii_lowercase())
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
  let question_name = canonical_dns_name(&read_dns_name(response, &mut offset)?)?;
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
    let owner = canonical_dns_name(&read_dns_name(response, &mut offset)?)?;
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
        ParsedDnsRecordData::Cname(canonical_dns_name(&target)?)
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
          target: canonical_dns_name(&target)?,
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

#[cfg(test)]
mod tests {
  use super::*;

  fn test_query(name: &str, query_type: DnsQueryType) -> DnsQuery {
    DnsQuery {
      id: 0x1234,
      name: canonical_dns_name(name).expect("valid test DNS name"),
      query_type,
      packet: Vec::new(),
    }
  }

  fn response_start(
    id: u16,
    flags: u16,
    question_name: &str,
    question_type: DnsQueryType,
    question_class: u16,
    answer_count: u16,
  ) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&id.to_be_bytes());
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&answer_count.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    encode_dns_name(question_name, &mut response).expect("valid question name");
    response.extend_from_slice(&(question_type as u16).to_be_bytes());
    response.extend_from_slice(&question_class.to_be_bytes());
    response
  }

  fn add_record(response: &mut Vec<u8>, owner: &str, record_type: u16, ttl: u32, rdata: &[u8]) {
    encode_dns_name(owner, response).expect("valid owner name");
    response.extend_from_slice(&record_type.to_be_bytes());
    response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    response.extend_from_slice(&ttl.to_be_bytes());
    response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    response.extend_from_slice(rdata);
  }

  fn add_a(response: &mut Vec<u8>, owner: &str, ttl: u32, ip: Ipv4Addr) {
    add_record(response, owner, DNS_TYPE_A, ttl, &ip.octets());
  }

  fn add_cname(response: &mut Vec<u8>, owner: &str, ttl: u32, target: &str) {
    let mut rdata = Vec::new();
    encode_dns_name(target, &mut rdata).expect("valid CNAME target");
    add_record(response, owner, DNS_TYPE_CNAME, ttl, &rdata);
  }

  fn add_srv(response: &mut Vec<u8>, owner: &str, ttl: u32, port: u16, target: &str) {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&10_u16.to_be_bytes());
    rdata.extend_from_slice(&5_u16.to_be_bytes());
    rdata.extend_from_slice(&port.to_be_bytes());
    encode_dns_name(target, &mut rdata).expect("valid SRV target");
    add_record(response, owner, DNS_TYPE_SRV, ttl, &rdata);
  }

  #[test]
  fn upstream_discovery_dns_response_accepts_matching_a_and_ttl() {
    let query = test_query("App.Example.", DnsQueryType::A);
    let mut response = response_start(
      query.id,
      0x8180,
      "app.example",
      DnsQueryType::A,
      DNS_CLASS_IN,
      1,
    );
    add_a(
      &mut response,
      "app.example",
      12,
      Ipv4Addr::new(192, 0, 2, 10),
    );

    let (answers, ttl_ms) = parse_dns_response(&response, &query).expect("valid DNS response");

    assert_eq!(ttl_ms, 12_000);
    assert_eq!(
      answers,
      vec![DnsAnswer::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))]
    );
  }

  #[test]
  fn upstream_discovery_dns_response_rejects_mismatched_transaction_id() {
    let query = test_query("app.example", DnsQueryType::A);
    let response = response_start(
      0x9999,
      0x8180,
      "app.example",
      DnsQueryType::A,
      DNS_CLASS_IN,
      0,
    );

    let error = parse_dns_response(&response, &query).expect_err("mismatched ID must fail");

    assert!(error.to_string().contains("transaction ID"));
  }

  #[test]
  fn upstream_discovery_dns_response_rejects_mismatched_question() {
    let query = test_query("app.example", DnsQueryType::A);
    let wrong_name = response_start(
      query.id,
      0x8180,
      "other.example",
      DnsQueryType::A,
      DNS_CLASS_IN,
      0,
    );
    let wrong_type = response_start(
      query.id,
      0x8180,
      "app.example",
      DnsQueryType::Aaaa,
      DNS_CLASS_IN,
      0,
    );
    let wrong_class = response_start(query.id, 0x8180, "app.example", DnsQueryType::A, 3, 0);

    for response in [wrong_name, wrong_type, wrong_class] {
      let error = parse_dns_response(&response, &query).expect_err("question mismatch must fail");
      assert!(error.to_string().contains("question"));
    }
  }

  #[test]
  fn upstream_discovery_dns_response_rejects_unsuccessful_or_truncated_response() {
    let query = test_query("app.example", DnsQueryType::A);
    let nxdomain = response_start(
      query.id,
      0x8183,
      "app.example",
      DnsQueryType::A,
      DNS_CLASS_IN,
      0,
    );
    let truncated = response_start(
      query.id,
      0x8380,
      "app.example",
      DnsQueryType::A,
      DNS_CLASS_IN,
      0,
    );

    assert!(parse_dns_response(&nxdomain, &query).is_err());
    assert!(parse_dns_response(&truncated, &query).is_err());
  }

  #[test]
  fn upstream_discovery_dns_response_ignores_wrong_owner_ip_and_srv_answers() {
    let query = test_query("app.example", DnsQueryType::A);
    let mut response = response_start(
      query.id,
      0x8180,
      "app.example",
      DnsQueryType::A,
      DNS_CLASS_IN,
      1,
    );
    add_a(
      &mut response,
      "attacker.example",
      1,
      Ipv4Addr::new(203, 0, 113, 66),
    );

    let (answers, ttl_ms) =
      parse_dns_response(&response, &query).expect("wrong-owner A should be ignored");

    assert!(answers.is_empty());
    assert_eq!(ttl_ms, DNS_DEFAULT_TTL_MS);

    let srv_query = test_query("_app._tcp.example", DnsQueryType::Srv);
    let mut srv_response = response_start(
      srv_query.id,
      0x8180,
      "_app._tcp.example",
      DnsQueryType::Srv,
      DNS_CLASS_IN,
      1,
    );
    add_srv(
      &mut srv_response,
      "_attacker._tcp.example",
      1,
      18080,
      "attacker.example",
    );

    let (answers, ttl_ms) =
      parse_dns_response(&srv_response, &srv_query).expect("wrong-owner SRV should be ignored");

    assert!(answers.is_empty());
    assert_eq!(ttl_ms, DNS_DEFAULT_TTL_MS);
  }

  #[test]
  fn upstream_discovery_dns_response_accepts_verified_cname_chain() {
    let query = test_query("app.example", DnsQueryType::A);
    let mut response = response_start(
      query.id,
      0x8180,
      "app.example",
      DnsQueryType::A,
      DNS_CLASS_IN,
      2,
    );
    add_cname(&mut response, "app.example", 30, "alias.example");
    add_a(
      &mut response,
      "alias.example",
      5,
      Ipv4Addr::new(198, 51, 100, 10),
    );

    let (answers, ttl_ms) =
      parse_dns_response(&response, &query).expect("valid CNAME chain should resolve");

    assert_eq!(ttl_ms, 5_000);
    assert_eq!(
      answers,
      vec![DnsAnswer::Ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)))]
    );
  }

  #[test]
  fn upstream_discovery_dns_response_rejects_unverified_cname_chain() {
    let query = test_query("app.example", DnsQueryType::A);
    let mut response = response_start(
      query.id,
      0x8180,
      "app.example",
      DnsQueryType::A,
      DNS_CLASS_IN,
      2,
    );
    add_cname(&mut response, "attacker.example", 1, "alias.example");
    add_a(
      &mut response,
      "alias.example",
      1,
      Ipv4Addr::new(203, 0, 113, 66),
    );

    let (answers, ttl_ms) =
      parse_dns_response(&response, &query).expect("unverified CNAME chain should be ignored");

    assert!(answers.is_empty());
    assert_eq!(ttl_ms, DNS_DEFAULT_TTL_MS);
  }
}

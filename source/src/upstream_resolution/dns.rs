//! DNS wire types, query construction, and response parsing.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use super::{ResolutionError, ResolutionErrorClass, ResolutionSource};

mod system;
pub(crate) use system::{DnsResolverBackend, lookup_dns};

pub(super) const DNS_CLASS_IN: u16 = 1;
pub(super) const DNS_TYPE_A: u16 = 1;
pub(super) const DNS_TYPE_CNAME: u16 = 5;
pub(super) const DNS_TYPE_AAAA: u16 = 28;
pub(super) const DNS_TYPE_SRV: u16 = 33;
pub(super) const DNS_DEFAULT_TTL_MS: u64 = 30_000;
const DNS_MAX_COMPRESSION_HOPS: usize = 32;

#[derive(Debug)]
pub(super) struct DnsQuery {
  pub(super) id: u16,
  pub(super) name: String,
  pub(super) query_type: DnsQueryType,
  pub(super) packet: Vec<u8>,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum DnsQueryType {
  A = DNS_TYPE_A,
  Aaaa = DNS_TYPE_AAAA,
  Srv = DNS_TYPE_SRV,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum DnsAnswer {
  Ip(IpAddr),
  Srv(SrvRecord),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SrvRecord {
  pub(crate) priority: u16,
  pub(crate) weight: u16,
  pub(crate) port: u16,
  pub(crate) target: String,
}

#[derive(Clone, Debug)]
pub(crate) struct DnsLookup {
  pub(super) answers: Vec<DnsAnswer>,
  pub(super) ttl_ms: u64,
  pub(super) source: ResolutionSource,
}

impl DnsLookup {
  #[cfg(test)]
  pub(super) fn new(answers: Vec<DnsAnswer>, ttl_ms: u64) -> Self {
    Self {
      answers,
      ttl_ms,
      source: ResolutionSource::Dns,
    }
  }
}

pub(super) fn build_dns_query(
  name: &str,
  query_type: DnsQueryType,
) -> Result<DnsQuery, ResolutionError> {
  let name = canonical_dns_name(name).map_err(malformed_dns)?;
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

pub(super) fn encode_dns_name(name: &str, out: &mut Vec<u8>) -> Result<(), ResolutionError> {
  let name = canonical_dns_name(name).map_err(malformed_dns)?;
  for label in name.split('.') {
    out.push(label.len() as u8);
    out.extend_from_slice(label.as_bytes());
  }
  out.push(0);
  Ok(())
}

fn random_dns_transaction_id() -> Result<u16, ResolutionError> {
  let mut bytes = [0_u8; 2];
  crate::crypto::random_fill(&mut bytes).map_err(|_| {
    ResolutionError::new(
      ResolutionErrorClass::Io,
      "failed to generate DNS transaction ID",
    )
  })?;
  Ok(u16::from_be_bytes(bytes))
}

pub(super) fn parse_dns_response(
  response: &[u8],
  query: &DnsQuery,
) -> Result<DnsLookup, ResolutionError> {
  if response.len() < 12 {
    return Err(malformed_dns("DNS response is too short"));
  }
  let id = read_u16(response, 0)?;
  if id != query.id {
    return Err(malformed_dns(
      "DNS response transaction ID does not match query",
    ));
  }
  let flags = read_u16(response, 2)?;
  if flags & 0x8000 == 0 {
    return Err(malformed_dns("DNS packet is not a response"));
  }
  if flags & 0x7800 != 0 {
    return Err(malformed_dns("DNS response opcode is not a standard query"));
  }
  if flags & 0x0200 != 0 {
    return Err(ResolutionError::new(
      ResolutionErrorClass::Truncated,
      "DNS response is truncated",
    ));
  }
  let qdcount = read_u16(response, 4)? as usize;
  let ancount = read_u16(response, 6)? as usize;
  let nscount = read_u16(response, 8)? as usize;
  let arcount = read_u16(response, 10)? as usize;
  if qdcount != 1 {
    return Err(malformed_dns(
      "DNS response question count does not match query",
    ));
  }
  let mut offset = 12;
  let question_name =
    canonical_dns_name(&read_dns_name(response, &mut offset)?).map_err(malformed_dns)?;
  let question_type = read_u16(response, offset)?;
  offset += 2;
  let question_class = read_u16(response, offset)?;
  offset += 2;
  if question_name != query.name
    || question_type != query.query_type as u16
    || question_class != DNS_CLASS_IN
  {
    return Err(malformed_dns("DNS response question does not match query"));
  }
  match flags & 0x000f {
    0 => {}
    2 => {
      return Err(ResolutionError::new(
        ResolutionErrorClass::ServerFailure,
        "DNS response returned server failure",
      ));
    }
    3 => {
      return Err(ResolutionError::new(
        ResolutionErrorClass::NxDomain,
        "DNS response returned NXDOMAIN",
      ));
    }
    5 => {
      return Err(ResolutionError::new(
        ResolutionErrorClass::Refused,
        "DNS response was refused",
      ));
    }
    code => {
      return Err(malformed_dns(format!(
        "DNS response returned error code {code}"
      )));
    }
  }

  let mut records = Vec::new();
  for _ in 0..ancount {
    let owner =
      canonical_dns_name(&read_dns_name(response, &mut offset)?).map_err(malformed_dns)?;
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
      .ok_or_else(|| malformed_dns("DNS response offset overflow"))?;
    if offset > response.len() {
      return Err(malformed_dns("DNS response is truncated"));
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
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&response[rdata..rdata + 16]);
        ParsedDnsRecordData::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
      }
      (DNS_TYPE_CNAME, len) if len > 0 => {
        let mut target_offset = rdata;
        let target = read_dns_name(response, &mut target_offset)?;
        if target_offset != offset {
          return Err(malformed_dns("DNS CNAME record length is invalid"));
        }
        ParsedDnsRecordData::Cname(canonical_dns_name(&target).map_err(malformed_dns)?)
      }
      (DNS_TYPE_SRV, len) if len >= 6 => {
        let priority = read_u16(response, rdata)?;
        let weight = read_u16(response, rdata + 2)?;
        let port = read_u16(response, rdata + 4)?;
        let mut target_offset = rdata + 6;
        let target = read_dns_name(response, &mut target_offset)?;
        if target_offset != offset {
          return Err(malformed_dns("DNS SRV record length is invalid"));
        }
        ParsedDnsRecordData::Srv(SrvRecord {
          priority,
          weight,
          port,
          target: canonical_dns_name(&target).map_err(malformed_dns)?,
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
  Ok(DnsLookup {
    answers,
    ttl_ms: min_ttl_ms,
    source: ResolutionSource::Dns,
  })
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

fn verified_answer_names(query_name: &str, records: &[ParsedDnsRecord]) -> (HashSet<String>, u64) {
  let mut accepted_names = HashSet::from([query_name.to_string()]);
  let mut min_ttl_ms = u64::MAX;
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

fn skip_dns_records(
  response: &[u8],
  offset: &mut usize,
  count: usize,
) -> Result<(), ResolutionError> {
  for _ in 0..count {
    read_dns_name(response, offset)?;
    *offset = offset
      .checked_add(8)
      .ok_or_else(|| malformed_dns("DNS response offset overflow"))?;
    let rdlen = read_u16(response, *offset)? as usize;
    *offset = offset
      .checked_add(2)
      .and_then(|value| value.checked_add(rdlen))
      .ok_or_else(|| malformed_dns("DNS response offset overflow"))?;
    if *offset > response.len() {
      return Err(malformed_dns("DNS response is truncated"));
    }
  }
  Ok(())
}

fn read_dns_name(response: &[u8], offset: &mut usize) -> Result<String, ResolutionError> {
  let mut labels = Vec::new();
  let mut cursor = *offset;
  let mut jumped = false;
  for _ in 0..DNS_MAX_COMPRESSION_HOPS {
    let len = *response
      .get(cursor)
      .ok_or_else(|| malformed_dns("DNS name offset out of bounds"))?;
    if len & 0xc0 == 0xc0 {
      let next = *response
        .get(cursor + 1)
        .ok_or_else(|| malformed_dns("DNS compression pointer out of bounds"))?;
      let pointer = (((len & 0x3f) as usize) << 8) | next as usize;
      if !jumped {
        *offset = cursor + 2;
      }
      cursor = pointer;
      jumped = true;
      continue;
    }
    if len & 0xc0 != 0 {
      return Err(malformed_dns("DNS label has invalid length bits"));
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
      .ok_or_else(|| malformed_dns("DNS label offset overflow"))?;
    let label = response
      .get(cursor..end)
      .ok_or_else(|| malformed_dns("DNS label out of bounds"))?;
    if !label.is_ascii() {
      return Err(malformed_dns("DNS label contains non-ASCII bytes"));
    }
    let label =
      std::str::from_utf8(label).map_err(|_| malformed_dns("DNS label is not valid UTF-8"))?;
    labels.push(label.to_string());
    cursor = end;
  }
  Err(malformed_dns("DNS name compression chain is too deep"))
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, ResolutionError> {
  let bytes = input
    .get(offset..offset + 2)
    .ok_or_else(|| malformed_dns("DNS response is truncated"))?;
  Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, ResolutionError> {
  let bytes = input
    .get(offset..offset + 4)
    .ok_or_else(|| malformed_dns("DNS response is truncated"))?;
  Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(super) fn canonical_dns_name(name: &str) -> Result<String, String> {
  let trimmed = name.trim_end_matches('.');
  if trimmed.is_empty() {
    return Err("DNS name must not be empty".to_string());
  }
  if trimmed.len() > 253 {
    return Err("DNS name exceeds 253 bytes".to_string());
  }
  for label in trimmed.split('.') {
    if label.is_empty() || label.len() > 63 {
      return Err("DNS name contains an invalid label".to_string());
    }
  }
  Ok(trimmed.to_ascii_lowercase())
}

fn malformed_dns(detail: impl Into<Arc<str>>) -> ResolutionError {
  ResolutionError::new(ResolutionErrorClass::Malformed, detail)
}

#[cfg(feature = "fuzzing")]
pub(super) fn fuzz_parse_dns_response(data: &[u8]) {
  for query_type in [DnsQueryType::A, DnsQueryType::Aaaa, DnsQueryType::Srv] {
    let query = DnsQuery {
      id: 0x1234,
      name: "example.test".to_string(),
      query_type,
      packet: Vec::new(),
    };
    let _ = parse_dns_response(data, &query);
  }
}

#[cfg(test)]
mod tests;

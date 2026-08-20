//! DNS wire types, query construction, and response parsing.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;
use std::sync::Arc;

use super::{ResolutionError, ResolutionErrorClass, ResolutionSource};

mod system;
pub(crate) use system::{DnsResolverBackend, lookup_dns, lookup_dns_absolute_until};

pub(super) const DNS_CLASS_IN: u16 = 1;
pub(super) const DNS_TYPE_A: u16 = 1;
pub(super) const DNS_TYPE_CNAME: u16 = 5;
pub(super) const DNS_TYPE_AAAA: u16 = 28;
pub(super) const DNS_TYPE_SRV: u16 = 33;
pub(super) const DNS_TYPE_HTTPS: u16 = 65;
pub(super) const DNS_DEFAULT_TTL_MS: u64 = 30_000;
const DNS_MAX_COMPRESSION_HOPS: usize = 32;
const DNS_HTTPS_MAX_RECORDS: usize = 16;
const DNS_HTTPS_MAX_PARAMS: usize = 8;
const DNS_HTTPS_MAX_ALPNS: usize = 8;
const DNS_HTTPS_MAX_HINTS_PER_FAMILY: usize = 16;
const DNS_HTTPS_MAX_ALIAS_HOPS: usize = 8;

const HTTPS_PARAM_MANDATORY: u16 = 0;
const HTTPS_PARAM_ALPN: u16 = 1;
const HTTPS_PARAM_NO_DEFAULT_ALPN: u16 = 2;
const HTTPS_PARAM_PORT: u16 = 3;
const HTTPS_PARAM_IPV4_HINT: u16 = 4;
const HTTPS_PARAM_ECH: u16 = 5;
const HTTPS_PARAM_IPV6_HINT: u16 = 6;

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
  Https = DNS_TYPE_HTTPS,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum DnsAnswer {
  Ip(IpAddr),
  Srv(SrvRecord),
  Https(HttpsRecord),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SrvRecord {
  pub(crate) priority: u16,
  pub(crate) weight: u16,
  pub(crate) port: u16,
  pub(crate) target: String,
}

/// Bounded HTTPS/SVCB metadata retained from an untrusted DNS response.
///
/// The parser deliberately retains only transport-selection fields. In particular it never
/// retains ECH bytes, arbitrary SvcParams, or a DNS-provided TLS identity/trust setting.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct HttpsRecord {
  pub(crate) priority: u16,
  pub(crate) target: HttpsTarget,
  pub(crate) alpn_present: bool,
  pub(crate) alpn: Box<[HttpsAlpn]>,
  pub(crate) port: Option<NonZeroU16>,
  pub(crate) ipv4_hints: Box<[Ipv4Addr]>,
  pub(crate) ipv6_hints: Box<[Ipv6Addr]>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum HttpsTarget {
  /// A service-mode target of `.`; use the owner name when a future caller resolves it.
  Owner,
  /// A canonical absolute DNS target. Search suffixes must never be applied to this value.
  Absolute(String),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum HttpsAlpn {
  H1,
  H2,
  H3,
}

#[derive(Clone, Debug)]
pub(crate) struct DnsLookup {
  pub(super) answers: Vec<DnsAnswer>,
  pub(super) ttl_ms: u64,
  pub(super) source: ResolutionSource,
  query_name: Option<Arc<str>>,
  accepted_cname: bool,
}

impl DnsLookup {
  #[cfg(test)]
  pub(super) fn new(answers: Vec<DnsAnswer>, ttl_ms: u64) -> Self {
    Self {
      answers,
      ttl_ms,
      source: ResolutionSource::Dns,
      query_name: None,
      accepted_cname: false,
    }
  }

  #[cfg(test)]
  pub(super) fn with_query_name(mut self, name: impl Into<Arc<str>>) -> Self {
    self.query_name = Some(name.into());
    self
  }

  pub(crate) fn query_name(&self) -> Option<&str> {
    self.query_name.as_deref()
  }

  /// Whether the accepted answer chain contained a CNAME.
  ///
  /// Callers that require a DNS name with no indirection (such as the RFC7050
  /// `ipv4only.arpa` probe) must reject this rather than inheriting the target.
  pub(crate) fn accepted_cname(&self) -> bool {
    self.accepted_cname
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
      (DNS_TYPE_HTTPS, len) if query.query_type == DnsQueryType::Https && len >= 3 => {
        ParsedDnsRecordData::Https(parse_https_record(response, rdata, offset)?)
      }
      (DNS_TYPE_HTTPS, _) if query.query_type == DnsQueryType::Https => {
        return Err(malformed_dns("DNS HTTPS record is too short"));
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
  let accepted_cname = records.iter().any(|record| {
    accepted_names.contains(&record.owner) && matches!(&record.data, ParsedDnsRecordData::Cname(_))
  });
  if query.query_type == DnsQueryType::Https {
    validate_https_aliases(&accepted_names, &records)?;
  }
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
      (DnsQueryType::Https, DNS_TYPE_HTTPS, ParsedDnsRecordData::Https(https_record)) => {
        if answers.len() >= DNS_HTTPS_MAX_RECORDS {
          return Err(malformed_dns(format!(
            "DNS HTTPS response exceeds {DNS_HTTPS_MAX_RECORDS} eligible records"
          )));
        }
        min_ttl_ms = min_ttl_ms.min(u64::from(record.ttl).saturating_mul(1_000));
        answers.push(DnsAnswer::Https(https_record));
      }
      _ => {}
    }
  }
  Ok(DnsLookup {
    answers,
    ttl_ms: min_ttl_ms,
    source: ResolutionSource::Dns,
    query_name: Some(Arc::from(query.name.clone())),
    accepted_cname,
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
  Https(HttpsRecord),
  Cname(String),
  Other,
}

fn parse_https_record(
  response: &[u8],
  rdata_start: usize,
  rdata_end: usize,
) -> Result<HttpsRecord, ResolutionError> {
  let priority = read_u16(response, rdata_start)?;
  let mut offset = rdata_start + 2;
  let target = read_dns_name(response, &mut offset)?;
  let target = if target == "." {
    HttpsTarget::Owner
  } else {
    HttpsTarget::Absolute(canonical_dns_name(&target).map_err(malformed_dns)?)
  };
  if offset > rdata_end {
    return Err(malformed_dns("DNS HTTPS target exceeds record length"));
  }
  if priority == 0 && matches!(&target, HttpsTarget::Owner) {
    return Err(malformed_dns(
      "DNS HTTPS alias record must not use the root target",
    ));
  }

  let mut seen = HashSet::new();
  let mut mandatory = None;
  let mut alpn = Vec::new();
  let mut port = None;
  let mut ipv4_hints = Vec::new();
  let mut ipv6_hints = Vec::new();
  let mut no_default_alpn = false;
  let mut param_count = 0usize;
  while offset < rdata_end {
    param_count = param_count.saturating_add(1);
    if param_count > DNS_HTTPS_MAX_PARAMS {
      return Err(malformed_dns(format!(
        "DNS HTTPS record exceeds {DNS_HTTPS_MAX_PARAMS} parameters"
      )));
    }
    if rdata_end.saturating_sub(offset) < 4 {
      return Err(malformed_dns(
        "DNS HTTPS parameter header exceeds record length",
      ));
    }
    let key = read_u16(response, offset)?;
    offset += 2;
    let length = read_u16(response, offset)? as usize;
    offset += 2;
    let value_end = offset
      .checked_add(length)
      .ok_or_else(|| malformed_dns("DNS HTTPS parameter length overflows"))?;
    if value_end > rdata_end {
      return Err(malformed_dns("DNS HTTPS parameter exceeds record length"));
    }
    if !seen.insert(key) {
      return Err(malformed_dns(
        "DNS HTTPS record has duplicate parameter keys",
      ));
    }
    let value = &response[offset..value_end];
    match key {
      HTTPS_PARAM_MANDATORY => {
        mandatory = Some(parse_https_mandatory(value)?);
      }
      HTTPS_PARAM_ALPN => parse_https_alpn(value, &mut alpn)?,
      HTTPS_PARAM_NO_DEFAULT_ALPN => {
        if !value.is_empty() {
          return Err(malformed_dns(
            "DNS HTTPS no-default-alpn parameter must be empty",
          ));
        }
        no_default_alpn = true;
      }
      HTTPS_PARAM_PORT => {
        if value.len() != 2 {
          return Err(malformed_dns(
            "DNS HTTPS port parameter must contain one u16",
          ));
        }
        port = Some(
          NonZeroU16::new(u16::from_be_bytes([value[0], value[1]]))
            .ok_or_else(|| malformed_dns("DNS HTTPS port parameter must not be zero"))?,
        );
      }
      HTTPS_PARAM_IPV4_HINT => parse_https_ipv4_hints(value, &mut ipv4_hints)?,
      // Dynamic ECH is intentionally neither interpreted nor retained. Its declared length is
      // still checked by the enclosing parameter parser above.
      HTTPS_PARAM_ECH => {}
      HTTPS_PARAM_IPV6_HINT => parse_https_ipv6_hints(value, &mut ipv6_hints)?,
      // Unknown optional parameters are deliberately ignored.
      _ => {}
    }
    offset = value_end;
  }
  if offset != rdata_end {
    return Err(malformed_dns("DNS HTTPS record length is invalid"));
  }
  if priority == 0 && param_count != 0 {
    return Err(malformed_dns(
      "DNS HTTPS alias record must not contain parameters",
    ));
  }
  if no_default_alpn && !seen.contains(&HTTPS_PARAM_ALPN) {
    return Err(malformed_dns(
      "DNS HTTPS no-default-alpn parameter requires an ALPN parameter",
    ));
  }
  if no_default_alpn && alpn.is_empty() {
    return Err(malformed_dns(
      "DNS HTTPS no-default-alpn parameter requires a supported ALPN identifier",
    ));
  }
  if let Some(mandatory) = mandatory {
    for key in mandatory {
      if !seen.contains(&key) || !https_mandatory_key_is_supported(key) {
        return Err(malformed_dns(
          "DNS HTTPS mandatory parameter is unsupported or missing",
        ));
      }
    }
  }
  Ok(HttpsRecord {
    priority,
    target,
    alpn_present: seen.contains(&HTTPS_PARAM_ALPN),
    alpn: alpn.into_boxed_slice(),
    port,
    ipv4_hints: ipv4_hints.into_boxed_slice(),
    ipv6_hints: ipv6_hints.into_boxed_slice(),
  })
}

fn parse_https_mandatory(value: &[u8]) -> Result<Vec<u16>, ResolutionError> {
  if value.is_empty() || !value.len().is_multiple_of(2) {
    return Err(malformed_dns(
      "DNS HTTPS mandatory parameter must contain ordered u16 keys",
    ));
  }
  let mut keys = Vec::with_capacity(value.len() / 2);
  let mut previous = None;
  for chunk in value.chunks_exact(2) {
    let key = u16::from_be_bytes([chunk[0], chunk[1]]);
    if key == HTTPS_PARAM_MANDATORY || previous.is_some_and(|previous| key <= previous) {
      return Err(malformed_dns(
        "DNS HTTPS mandatory parameter keys must be nonzero and strictly ordered",
      ));
    }
    previous = Some(key);
    keys.push(key);
    if keys.len() > DNS_HTTPS_MAX_PARAMS {
      return Err(malformed_dns(format!(
        "DNS HTTPS mandatory parameter exceeds {DNS_HTTPS_MAX_PARAMS} keys"
      )));
    }
  }
  Ok(keys)
}

fn parse_https_alpn(value: &[u8], output: &mut Vec<HttpsAlpn>) -> Result<(), ResolutionError> {
  if value.is_empty() {
    return Err(malformed_dns("DNS HTTPS ALPN parameter must not be empty"));
  }
  let mut offset = 0;
  while offset < value.len() {
    let length = usize::from(value[offset]);
    offset += 1;
    if length == 0 {
      return Err(malformed_dns("DNS HTTPS ALPN identifier must not be empty"));
    }
    let end = offset
      .checked_add(length)
      .ok_or_else(|| malformed_dns("DNS HTTPS ALPN length overflows"))?;
    let identifier = value
      .get(offset..end)
      .ok_or_else(|| malformed_dns("DNS HTTPS ALPN identifier is truncated"))?;
    let alpn = match identifier {
      b"http/1.1" => Some(HttpsAlpn::H1),
      b"h2" => Some(HttpsAlpn::H2),
      b"h3" => Some(HttpsAlpn::H3),
      _ => None,
    };
    if let Some(alpn) = alpn {
      if output.contains(&alpn) {
        return Err(malformed_dns(
          "DNS HTTPS ALPN identifiers must not be duplicated",
        ));
      }
      if output.len() >= DNS_HTTPS_MAX_ALPNS {
        return Err(malformed_dns(format!(
          "DNS HTTPS record exceeds {DNS_HTTPS_MAX_ALPNS} supported ALPN identifiers"
        )));
      }
      output.push(alpn);
    }
    offset = end;
  }
  if offset != value.len() {
    return Err(malformed_dns("DNS HTTPS ALPN parameter length is invalid"));
  }
  Ok(())
}

fn parse_https_ipv4_hints(value: &[u8], output: &mut Vec<Ipv4Addr>) -> Result<(), ResolutionError> {
  if value.is_empty() || !value.len().is_multiple_of(4) {
    return Err(malformed_dns(
      "DNS HTTPS IPv4 hint parameter must contain whole addresses",
    ));
  }
  for octets in value.chunks_exact(4) {
    let address = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
    if output.contains(&address) {
      return Err(malformed_dns("DNS HTTPS IPv4 hints must not be duplicated"));
    }
    if output.len() >= DNS_HTTPS_MAX_HINTS_PER_FAMILY {
      return Err(malformed_dns(format!(
        "DNS HTTPS record exceeds {DNS_HTTPS_MAX_HINTS_PER_FAMILY} IPv4 hints"
      )));
    }
    output.push(address);
  }
  Ok(())
}

fn parse_https_ipv6_hints(value: &[u8], output: &mut Vec<Ipv6Addr>) -> Result<(), ResolutionError> {
  if value.is_empty() || !value.len().is_multiple_of(16) {
    return Err(malformed_dns(
      "DNS HTTPS IPv6 hint parameter must contain whole addresses",
    ));
  }
  for octets in value.chunks_exact(16) {
    let mut address = [0_u8; 16];
    address.copy_from_slice(octets);
    let address = Ipv6Addr::from(address);
    if output.contains(&address) {
      return Err(malformed_dns("DNS HTTPS IPv6 hints must not be duplicated"));
    }
    if output.len() >= DNS_HTTPS_MAX_HINTS_PER_FAMILY {
      return Err(malformed_dns(format!(
        "DNS HTTPS record exceeds {DNS_HTTPS_MAX_HINTS_PER_FAMILY} IPv6 hints"
      )));
    }
    output.push(address);
  }
  Ok(())
}

fn https_mandatory_key_is_supported(key: u16) -> bool {
  matches!(
    key,
    HTTPS_PARAM_ALPN
      | HTTPS_PARAM_NO_DEFAULT_ALPN
      | HTTPS_PARAM_PORT
      | HTTPS_PARAM_IPV4_HINT
      | HTTPS_PARAM_IPV6_HINT
  )
}

fn validate_https_aliases(
  accepted_names: &HashSet<String>,
  records: &[ParsedDnsRecord],
) -> Result<(), ResolutionError> {
  let mut aliases = HashMap::new();
  let mut service_owners = HashSet::new();
  for record in records {
    let ParsedDnsRecordData::Https(https) = &record.data else {
      continue;
    };
    if !accepted_names.contains(&record.owner) {
      continue;
    }
    if https.priority != 0 {
      if aliases.contains_key(record.owner.as_str()) {
        return Err(malformed_dns(
          "DNS HTTPS owner mixes alias and service records",
        ));
      }
      service_owners.insert(record.owner.as_str());
      continue;
    }
    if service_owners.contains(record.owner.as_str()) {
      return Err(malformed_dns(
        "DNS HTTPS owner mixes alias and service records",
      ));
    }
    let HttpsTarget::Absolute(target) = &https.target else {
      return Err(malformed_dns(
        "DNS HTTPS alias record must have an absolute target",
      ));
    };
    if aliases
      .insert(record.owner.as_str(), target.as_str())
      .is_some()
    {
      return Err(malformed_dns("DNS HTTPS owner has multiple alias records"));
    }
  }
  for start in aliases.keys().copied() {
    let mut current = start;
    let mut seen = HashSet::new();
    for _ in 0..DNS_HTTPS_MAX_ALIAS_HOPS {
      if !seen.insert(current) {
        return Err(malformed_dns("DNS HTTPS alias records form a loop"));
      }
      let Some(target) = aliases.get(current).copied() else {
        break;
      };
      current = target;
    }
    if aliases.contains_key(current) {
      return Err(malformed_dns(format!(
        "DNS HTTPS alias records exceed {DNS_HTTPS_MAX_ALIAS_HOPS} hops"
      )));
    }
  }
  Ok(())
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
  for query_type in [
    DnsQueryType::A,
    DnsQueryType::Aaaa,
    DnsQueryType::Srv,
    DnsQueryType::Https,
  ] {
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

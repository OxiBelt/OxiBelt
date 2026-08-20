//! Bounded system DNS transport, hosts lookup, and resolver configuration.

use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::Instant;

use super::{
  DNS_DEFAULT_TTL_MS, DnsAnswer, DnsLookup, DnsQueryType, build_dns_query, canonical_dns_name,
  malformed_dns, parse_dns_response,
};
use crate::upstream_resolution::{
  ResolutionError, ResolutionErrorClass, ResolutionSource, ResolverBackend,
};

const DNS_MAX_NAMESERVERS: usize = 3;
const DNS_MAX_SEARCH_SUFFIXES: usize = 6;
const DNS_MAX_SEARCH_CANDIDATES: usize = 8;
const DNS_MAX_PACKET_BYTES: usize = 4096;
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const HOSTS_MAX_BYTES: u64 = 1024 * 1024;
const RESOLV_CONF_MAX_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DnsResolverBackend;

impl ResolverBackend for DnsResolverBackend {
  #[allow(
    clippy::manual_async_fn,
    reason = "the resolver trait requires an explicitly Send future for spawned cancellation-aware producers"
  )]
  fn lookup(
    &self,
    name: &str,
    query_type: DnsQueryType,
    deadline: Instant,
  ) -> impl std::future::Future<Output = Result<DnsLookup, ResolutionError>> + Send {
    async move {
      if query_type == DnsQueryType::Https {
        return lookup_dns_absolute_until(name, query_type, deadline).await;
      }
      if let Some(lookup) = lookup_hosts(name, query_type)? {
        return Ok(lookup);
      }
      lookup_dns_until(name, query_type, deadline).await
    }
  }
}

/// Compatibility adapter for the existing dynamic-discovery caller.
pub(crate) async fn lookup_dns(
  name: &str,
  query_type: DnsQueryType,
) -> Result<(Vec<DnsAnswer>, u64), ResolutionError> {
  if query_type != DnsQueryType::Https
    && let Some(lookup) = lookup_hosts(name, query_type)?
  {
    return Ok((lookup.answers, lookup.ttl_ms));
  }
  let timeout = DNS_QUERY_TIMEOUT
    .checked_mul(DNS_MAX_NAMESERVERS as u32)
    .unwrap_or(DNS_QUERY_TIMEOUT);
  let deadline = Instant::now()
    .checked_add(timeout)
    .ok_or_else(ResolutionError::deadline)?;
  let lookup = if query_type == DnsQueryType::Https {
    lookup_dns_absolute_until(name, query_type, deadline).await?
  } else {
    lookup_dns_until(name, query_type, deadline).await?
  };
  Ok((lookup.answers, lookup.ttl_ms))
}

pub(crate) async fn lookup_dns_absolute_until(
  name: &str,
  query_type: DnsQueryType,
  deadline: Instant,
) -> Result<DnsLookup, ResolutionError> {
  let resolver_config = resolver_config();
  if resolver_config.nameservers.is_empty() {
    return Err(ResolutionError::new(
      ResolutionErrorClass::NoNameservers,
      "no DNS nameservers configured",
    ));
  }
  let canonical = canonical_dns_name(name).map_err(malformed_dns)?;
  lookup_dns_candidate(
    &canonical,
    query_type,
    &resolver_config.nameservers,
    deadline,
  )
  .await
}

async fn lookup_dns_until(
  name: &str,
  query_type: DnsQueryType,
  deadline: Instant,
) -> Result<DnsLookup, ResolutionError> {
  let resolver_config = resolver_config();
  if resolver_config.nameservers.is_empty() {
    return Err(ResolutionError::new(
      ResolutionErrorClass::NoNameservers,
      "no DNS nameservers configured",
    ));
  }
  let mut last_error = None;
  let mut last_empty = None;
  for candidate in dns_search_candidates(name, &resolver_config)? {
    if deadline <= Instant::now() {
      return Err(ResolutionError::deadline());
    }
    match lookup_dns_candidate(
      &candidate,
      query_type,
      &resolver_config.nameservers,
      deadline,
    )
    .await
    {
      Ok(lookup) if !lookup.answers.is_empty() => return Ok(lookup),
      Ok(lookup) => {
        last_error = Some(ResolutionError::new(
          ResolutionErrorClass::NoData,
          format!("DNS name {candidate} returned no eligible records"),
        ));
        last_empty = Some(lookup);
      }
      Err(error) if error.class() == ResolutionErrorClass::NxDomain => {
        last_error = Some(error);
      }
      Err(error) => return Err(error),
    }
  }
  if let Some(lookup) = last_empty {
    return Ok(lookup);
  }
  Err(last_error.unwrap_or_else(|| {
    ResolutionError::new(
      ResolutionErrorClass::NoNameservers,
      "no DNS nameservers configured",
    )
  }))
}

async fn lookup_dns_candidate(
  name: &str,
  query_type: DnsQueryType,
  nameservers: &[SocketAddr],
  deadline: Instant,
) -> Result<DnsLookup, ResolutionError> {
  let query = build_dns_query(name, query_type)?;
  let mut last_error = None;
  for &server in nameservers {
    if deadline <= Instant::now() {
      return Err(ResolutionError::deadline());
    }
    let response = match query_nameserver_udp(server, &query.packet, deadline).await {
      Ok(response) => response,
      Err(error) => {
        last_error = Some(error);
        continue;
      }
    };
    match parse_dns_response(&response, &query) {
      Ok(lookup) => return Ok(lookup),
      Err(error) if error.class() == ResolutionErrorClass::Truncated => {
        match query_nameserver_tcp(server, &query.packet, deadline).await {
          Ok(response) => match parse_dns_response(&response, &query) {
            Ok(lookup) => return Ok(lookup),
            Err(error) => last_error = Some(error),
          },
          Err(error) => last_error = Some(error),
        }
      }
      Err(error) if error.class() == ResolutionErrorClass::NxDomain => return Err(error),
      Err(error) => last_error = Some(error),
    }
  }
  Err(last_error.unwrap_or_else(|| {
    ResolutionError::new(
      ResolutionErrorClass::NoNameservers,
      "no DNS nameservers configured",
    )
  }))
}

async fn query_nameserver_udp(
  server: SocketAddr,
  query: &[u8],
  deadline: Instant,
) -> Result<Vec<u8>, ResolutionError> {
  let bind_addr: SocketAddr = if server.is_ipv4() {
    SocketAddr::from(([0, 0, 0, 0], 0))
  } else {
    SocketAddr::from(([0u16; 8], 0))
  };
  let attempt_deadline = deadline.min(
    Instant::now()
      .checked_add(DNS_QUERY_TIMEOUT)
      .unwrap_or(deadline),
  );
  let exchange = async {
    let socket = UdpSocket::bind(bind_addr).await.map_err(dns_io_error)?;
    socket.connect(server).await.map_err(dns_io_error)?;
    socket.send(query).await.map_err(dns_io_error)?;
    let mut response = vec![0_u8; DNS_MAX_PACKET_BYTES];
    let len = socket.recv(&mut response).await.map_err(dns_io_error)?;
    response.truncate(len);
    Ok(response)
  };
  tokio::time::timeout_at(attempt_deadline, exchange)
    .await
    .map_err(|_| ResolutionError::deadline())?
}

async fn query_nameserver_tcp(
  server: SocketAddr,
  query: &[u8],
  deadline: Instant,
) -> Result<Vec<u8>, ResolutionError> {
  let query_len = u16::try_from(query.len()).map_err(|_| {
    ResolutionError::new(
      ResolutionErrorClass::InvalidInput,
      "DNS query exceeds the TCP framing limit",
    )
  })?;
  let exchange = async {
    let mut stream = TcpStream::connect(server).await.map_err(dns_io_error)?;
    stream
      .write_all(&query_len.to_be_bytes())
      .await
      .map_err(dns_io_error)?;
    stream.write_all(query).await.map_err(dns_io_error)?;
    let response_len = stream.read_u16().await.map_err(dns_io_error)? as usize;
    if response_len == 0 || response_len > DNS_MAX_PACKET_BYTES {
      return Err(malformed_dns("DNS TCP response length is invalid"));
    }
    let mut response = vec![0_u8; response_len];
    stream
      .read_exact(&mut response)
      .await
      .map_err(dns_io_error)?;
    Ok(response)
  };
  tokio::time::timeout_at(deadline, exchange)
    .await
    .map_err(|_| ResolutionError::deadline())?
}

fn dns_io_error(error: std::io::Error) -> ResolutionError {
  ResolutionError::new(
    ResolutionErrorClass::Io,
    Arc::<str>::from(format!("DNS I/O failed: {error}")),
  )
}

#[derive(Debug)]
struct ResolverConfig {
  nameservers: Vec<SocketAddr>,
  search: Vec<String>,
  ndots: usize,
}

fn resolver_config() -> ResolverConfig {
  let Ok(file) = std::fs::File::open("/etc/resolv.conf") else {
    return ResolverConfig {
      nameservers: Vec::new(),
      search: Vec::new(),
      ndots: 1,
    };
  };
  let Ok(content) = read_bounded_text(file, RESOLV_CONF_MAX_BYTES, "resolver configuration") else {
    return ResolverConfig {
      nameservers: Vec::new(),
      search: Vec::new(),
      ndots: 1,
    };
  };
  parse_resolver_config(&content)
}

fn parse_resolver_config(content: &str) -> ResolverConfig {
  let mut nameservers = Vec::new();
  let mut search = Vec::new();
  let mut ndots = 1;
  for line in content.lines() {
    let line = line.split('#').next().unwrap_or_default().trim();
    let mut fields = line.split_whitespace();
    match fields.next() {
      Some("nameserver") if nameservers.len() < DNS_MAX_NAMESERVERS => {
        if let Some(ip) = fields.next().and_then(|raw| raw.parse::<IpAddr>().ok()) {
          nameservers.push(SocketAddr::new(ip, 53));
        }
      }
      Some("search") => {
        search.clear();
        search.extend(
          fields
            .filter_map(|value| canonical_dns_name(value).ok())
            .take(DNS_MAX_SEARCH_SUFFIXES),
        );
      }
      Some("domain") if search.is_empty() => {
        if let Some(value) = fields
          .next()
          .and_then(|value| canonical_dns_name(value).ok())
        {
          search.push(value);
        }
      }
      Some("options") => {
        for option in fields {
          if let Some(value) = option
            .strip_prefix("ndots:")
            .and_then(|value| value.parse::<usize>().ok())
          {
            ndots = value.min(15);
          }
        }
      }
      _ => {}
    }
  }
  ResolverConfig {
    nameservers,
    search,
    ndots,
  }
}

fn dns_search_candidates(
  name: &str,
  config: &ResolverConfig,
) -> Result<Vec<String>, ResolutionError> {
  let absolute = name.ends_with('.');
  let canonical = canonical_dns_name(name).map_err(malformed_dns)?;
  if absolute {
    return Ok(vec![canonical]);
  }
  let mut candidates = Vec::new();
  let absolute_first = canonical.matches('.').count() >= config.ndots;
  if absolute_first {
    candidates.push(canonical.clone());
  }
  for suffix in &config.search {
    if candidates.len() >= DNS_MAX_SEARCH_CANDIDATES {
      break;
    }
    let candidate = format!("{canonical}.{suffix}");
    if let Ok(candidate) = canonical_dns_name(&candidate)
      && !candidates.contains(&candidate)
    {
      candidates.push(candidate);
    }
  }
  if candidates.len() < DNS_MAX_SEARCH_CANDIDATES && !candidates.contains(&canonical) {
    candidates.push(canonical);
  }
  Ok(candidates)
}

fn lookup_hosts(
  name: &str,
  query_type: DnsQueryType,
) -> Result<Option<DnsLookup>, ResolutionError> {
  if matches!(query_type, DnsQueryType::Srv | DnsQueryType::Https) {
    return Ok(None);
  }
  let canonical = canonical_dns_name(name).map_err(malformed_dns)?;
  let file = match std::fs::File::open("/etc/hosts") {
    Ok(file) => file,
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
    Err(error) => return Err(dns_io_error(error)),
  };
  let content = read_bounded_text(file, HOSTS_MAX_BYTES, "hosts file")?;
  Ok(parse_hosts_lookup(&content, &canonical, query_type))
}

fn read_bounded_text(
  file: std::fs::File,
  max_bytes: u64,
  description: &str,
) -> Result<String, ResolutionError> {
  let mut content = String::new();
  file
    .take(max_bytes.saturating_add(1))
    .read_to_string(&mut content)
    .map_err(dns_io_error)?;
  if content.len() as u64 > max_bytes {
    return Err(ResolutionError::new(
      ResolutionErrorClass::InvalidInput,
      format!("DNS {description} exceeds {max_bytes} bytes"),
    ));
  }
  Ok(content)
}

fn parse_hosts_lookup(
  content: &str,
  canonical: &str,
  query_type: DnsQueryType,
) -> Option<DnsLookup> {
  let mut matched = false;
  let mut answers = Vec::new();
  for line in content.lines() {
    let line = line.split('#').next().unwrap_or_default();
    let mut fields = line.split_whitespace();
    let Some(ip) = fields.next().and_then(|value| value.parse::<IpAddr>().ok()) else {
      continue;
    };
    if !fields.any(|alias| {
      canonical_dns_name(alias)
        .ok()
        .is_some_and(|alias| alias == canonical)
    }) {
      continue;
    }
    matched = true;
    if matches!(
      (query_type, ip),
      (DnsQueryType::A, IpAddr::V4(_)) | (DnsQueryType::Aaaa, IpAddr::V6(_))
    ) {
      answers.push(DnsAnswer::Ip(ip));
    }
  }
  matched.then_some(DnsLookup {
    answers,
    ttl_ms: DNS_DEFAULT_TTL_MS,
    source: ResolutionSource::Hosts,
    query_name: None,
    accepted_cname: false,
  })
}

#[cfg(test)]
mod tests;

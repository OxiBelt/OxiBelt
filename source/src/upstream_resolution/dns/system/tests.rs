use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use super::*;
use crate::upstream_resolution::dns::{DNS_CLASS_IN, DNS_TYPE_A};

#[test]
fn resolver_config_bounds_nameservers_search_and_ndots() {
  let config = parse_resolver_config(
    r#"
nameserver 192.0.2.1
nameserver 192.0.2.2
nameserver 192.0.2.3
nameserver 192.0.2.4
search one.test two.test three.test four.test five.test six.test seven.test
options rotate ndots:99
"#,
  );
  assert_eq!(config.nameservers.len(), DNS_MAX_NAMESERVERS);
  assert_eq!(config.search.len(), DNS_MAX_SEARCH_SUFFIXES);
  assert_eq!(config.ndots, 15);
}

#[test]
fn search_candidates_follow_ndots_and_are_bounded() {
  let config = ResolverConfig {
    nameservers: Vec::new(),
    search: (0..DNS_MAX_SEARCH_SUFFIXES)
      .map(|index| format!("s{index}.test"))
      .collect(),
    ndots: 2,
  };
  let candidates = dns_search_candidates("api", &config).expect("valid search candidates");
  assert_eq!(candidates.first().map(String::as_str), Some("api.s0.test"));
  assert_eq!(candidates.last().map(String::as_str), Some("api"));
  assert!(candidates.len() <= DNS_MAX_SEARCH_CANDIDATES);

  let absolute = dns_search_candidates("api.example.", &config).expect("absolute name");
  assert_eq!(absolute, vec!["api.example"]);
}

#[test]
fn hosts_lookup_is_case_insensitive_and_family_specific() {
  let content = r#"
192.0.2.10 API.Example api
2001:db8::10 api.example
203.0.113.66 unrelated.example
"#;
  let a = parse_hosts_lookup(content, "api.example", DnsQueryType::A).expect("matching hosts name");
  assert_eq!(
    a.answers,
    vec![DnsAnswer::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))]
  );
  assert_eq!(a.source, ResolutionSource::Hosts);

  let aaaa = parse_hosts_lookup(content, "api", DnsQueryType::Aaaa).expect("matching hosts alias");
  assert!(aaaa.answers.is_empty());
  assert_eq!(aaaa.source, ResolutionSource::Hosts);
}

#[tokio::test]
async fn truncated_udp_response_retries_over_tcp_under_the_same_deadline() {
  let tcp = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
    .await
    .expect("bind TCP DNS fixture");
  let address = tcp.local_addr().expect("TCP fixture address");
  let udp = UdpSocket::bind(address)
    .await
    .expect("bind UDP DNS fixture");

  let udp_task = tokio::spawn(async move {
    let mut query = [0_u8; DNS_MAX_PACKET_BYTES];
    let (len, peer) = udp.recv_from(&mut query).await.expect("receive UDP query");
    let response = dns_response(&query[..len], 0x8380, None);
    udp
      .send_to(&response, peer)
      .await
      .expect("send truncated UDP");
  });
  let tcp_task = tokio::spawn(async move {
    let (mut stream, _) = tcp.accept().await.expect("accept TCP query");
    let len = stream.read_u16().await.expect("read TCP query length") as usize;
    let mut query = vec![0_u8; len];
    stream.read_exact(&mut query).await.expect("read TCP query");
    let response = dns_response(&query, 0x8180, Some(Ipv4Addr::new(192, 0, 2, 44)));
    stream
      .write_all(&(response.len() as u16).to_be_bytes())
      .await
      .expect("write TCP response length");
    stream
      .write_all(&response)
      .await
      .expect("write TCP response");
  });

  let deadline = Instant::now()
    .checked_add(Duration::from_secs(2))
    .expect("test deadline");
  let lookup = lookup_dns_candidate("example.test", DnsQueryType::A, &[address], deadline)
    .await
    .expect("TCP fallback lookup");
  assert_eq!(
    lookup.answers,
    vec![DnsAnswer::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)))]
  );
  udp_task.await.expect("UDP fixture task");
  tcp_task.await.expect("TCP fixture task");
}

fn dns_response(query: &[u8], flags: u16, answer: Option<Ipv4Addr>) -> Vec<u8> {
  let mut response = Vec::new();
  response.extend_from_slice(&query[..2]);
  response.extend_from_slice(&flags.to_be_bytes());
  response.extend_from_slice(&1_u16.to_be_bytes());
  response.extend_from_slice(&(answer.is_some() as u16).to_be_bytes());
  response.extend_from_slice(&0_u16.to_be_bytes());
  response.extend_from_slice(&0_u16.to_be_bytes());
  response.extend_from_slice(&query[12..]);
  if let Some(ip) = answer {
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    response.extend_from_slice(&5_u32.to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&ip.octets());
  }
  response
}

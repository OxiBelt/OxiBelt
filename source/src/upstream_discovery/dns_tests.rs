use super::*;

fn test_query(name: &str, query_type: DnsQueryType) -> DnsQuery {
  DnsQuery {
    id: 0x1234,
    name: dns::canonical_dns_name(name).expect("valid test DNS name"),
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

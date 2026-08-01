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

fn add_aaaa(response: &mut Vec<u8>, owner: &str, ttl: u32, ip: Ipv6Addr) {
  add_record(response, owner, DNS_TYPE_AAAA, ttl, &ip.octets());
}

fn add_cname(response: &mut Vec<u8>, owner: &str, ttl: u32, target: &str) {
  let mut rdata = Vec::new();
  encode_dns_name(target, &mut rdata).expect("valid CNAME target");
  add_record(response, owner, DNS_TYPE_CNAME, ttl, &rdata);
}

fn add_srv(
  response: &mut Vec<u8>,
  owner: &str,
  ttl: u32,
  priority: u16,
  weight: u16,
  port: u16,
  target: &str,
) {
  let mut rdata = Vec::new();
  rdata.extend_from_slice(&priority.to_be_bytes());
  rdata.extend_from_slice(&weight.to_be_bytes());
  rdata.extend_from_slice(&port.to_be_bytes());
  encode_dns_name(target, &mut rdata).expect("valid SRV target");
  add_record(response, owner, DNS_TYPE_SRV, ttl, &rdata);
}

#[test]
fn response_accepts_matching_a_aaaa_and_ttl() {
  let a_query = test_query("App.Example.", DnsQueryType::A);
  let mut a_response = response_start(
    a_query.id,
    0x8180,
    "app.example",
    DnsQueryType::A,
    DNS_CLASS_IN,
    1,
  );
  add_a(
    &mut a_response,
    "app.example",
    12,
    Ipv4Addr::new(192, 0, 2, 10),
  );
  let a = parse_dns_response(&a_response, &a_query).expect("valid A response");
  assert_eq!(a.ttl_ms, 12_000);
  assert_eq!(
    a.answers,
    vec![DnsAnswer::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))]
  );

  let aaaa_query = test_query("app.example", DnsQueryType::Aaaa);
  let mut aaaa_response = response_start(
    aaaa_query.id,
    0x8180,
    "app.example",
    DnsQueryType::Aaaa,
    DNS_CLASS_IN,
    1,
  );
  let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
  add_aaaa(&mut aaaa_response, "app.example", 7, ipv6);
  let aaaa = parse_dns_response(&aaaa_response, &aaaa_query).expect("valid AAAA response");
  assert_eq!(aaaa.ttl_ms, 7_000);
  assert_eq!(aaaa.answers, vec![DnsAnswer::Ip(IpAddr::V6(ipv6))]);

  let long_ttl_query = test_query("long.example", DnsQueryType::A);
  let mut long_ttl_response = response_start(
    long_ttl_query.id,
    0x8180,
    "long.example",
    DnsQueryType::A,
    DNS_CLASS_IN,
    1,
  );
  add_a(
    &mut long_ttl_response,
    "long.example",
    300,
    Ipv4Addr::new(198, 51, 100, 20),
  );
  assert_eq!(
    parse_dns_response(&long_ttl_response, &long_ttl_query)
      .expect("valid long-TTL response")
      .ttl_ms,
    300_000
  );
}

#[test]
fn response_rejects_mismatched_transaction_question_and_non_ascii_labels() {
  let query = test_query("app.example", DnsQueryType::A);
  let wrong_id = response_start(
    0x9999,
    0x8180,
    "app.example",
    DnsQueryType::A,
    DNS_CLASS_IN,
    0,
  );
  assert_eq!(
    parse_dns_response(&wrong_id, &query)
      .expect_err("mismatched ID must fail")
      .class(),
    ResolutionErrorClass::Malformed
  );

  let wrong_question = response_start(
    query.id,
    0x8180,
    "other.example",
    DnsQueryType::A,
    DNS_CLASS_IN,
    0,
  );
  assert!(
    parse_dns_response(&wrong_question, &query)
      .expect_err("mismatched question must fail")
      .to_string()
      .contains("question")
  );

  let mut non_ascii = response_start(
    query.id,
    0x8180,
    "app.example",
    DnsQueryType::A,
    DNS_CLASS_IN,
    0,
  );
  non_ascii[13] = 0xff;
  assert!(
    parse_dns_response(&non_ascii, &query)
      .expect_err("non-ASCII labels must fail")
      .to_string()
      .contains("non-ASCII")
  );
}

#[test]
fn response_classifies_negative_server_and_truncated_results() {
  let query = test_query("app.example", DnsQueryType::A);
  for (flags, expected) in [
    (0x8183, ResolutionErrorClass::NxDomain),
    (0x8182, ResolutionErrorClass::ServerFailure),
    (0x8185, ResolutionErrorClass::Refused),
    (0x8380, ResolutionErrorClass::Truncated),
  ] {
    let response = response_start(
      query.id,
      flags,
      "app.example",
      DnsQueryType::A,
      DNS_CLASS_IN,
      0,
    );
    assert_eq!(
      parse_dns_response(&response, &query)
        .expect_err("response must be classified")
        .class(),
      expected
    );
  }
}

#[test]
fn response_accepts_only_verified_owner_and_cname_chain() {
  let query = test_query("app.example", DnsQueryType::A);
  let mut response = response_start(
    query.id,
    0x8180,
    "app.example",
    DnsQueryType::A,
    DNS_CLASS_IN,
    3,
  );
  add_cname(&mut response, "app.example", 30, "alias.example");
  add_a(
    &mut response,
    "alias.example",
    5,
    Ipv4Addr::new(198, 51, 100, 10),
  );
  add_a(
    &mut response,
    "attacker.example",
    1,
    Ipv4Addr::new(203, 0, 113, 66),
  );
  let lookup = parse_dns_response(&response, &query).expect("valid CNAME response");
  assert_eq!(lookup.ttl_ms, 5_000);
  assert_eq!(
    lookup.answers,
    vec![DnsAnswer::Ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)))]
  );
}

#[test]
fn response_preserves_srv_priority_weight_and_port() {
  let query = test_query("_app._udp.example", DnsQueryType::Srv);
  let mut response = response_start(
    query.id,
    0x8180,
    "_app._udp.example",
    DnsQueryType::Srv,
    DNS_CLASS_IN,
    1,
  );
  add_srv(
    &mut response,
    "_app._udp.example",
    9,
    10,
    25,
    443,
    "target.example",
  );
  let lookup = parse_dns_response(&response, &query).expect("valid SRV response");
  assert_eq!(lookup.ttl_ms, 9_000);
  assert_eq!(
    lookup.answers,
    vec![DnsAnswer::Srv(SrvRecord {
      priority: 10,
      weight: 25,
      port: 443,
      target: "target.example".to_string(),
    })]
  );
}

#[test]
fn canonical_names_are_bounded() {
  assert_eq!(
    canonical_dns_name("ExAmPlE.test.").expect("valid name"),
    "example.test"
  );
  assert!(canonical_dns_name(&format!("{}.test", "a".repeat(64))).is_err());
  assert!(canonical_dns_name(&"a".repeat(254)).is_err());
}

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

fn add_https(
  response: &mut Vec<u8>,
  owner: &str,
  ttl: u32,
  priority: u16,
  target: Option<&str>,
  params: &[(u16, Vec<u8>)],
) {
  let mut rdata = Vec::new();
  rdata.extend_from_slice(&priority.to_be_bytes());
  if let Some(target) = target {
    encode_dns_name(target, &mut rdata).expect("valid HTTPS target");
  } else {
    rdata.push(0);
  }
  for (key, value) in params {
    rdata.extend_from_slice(&key.to_be_bytes());
    rdata.extend_from_slice(&(value.len() as u16).to_be_bytes());
    rdata.extend_from_slice(value);
  }
  add_record(response, owner, DNS_TYPE_HTTPS, ttl, &rdata);
}

fn https_response(answer_count: u16) -> (DnsQuery, Vec<u8>) {
  let query = test_query("svc.example", DnsQueryType::Https);
  let response = response_start(
    query.id,
    0x8180,
    "svc.example",
    DnsQueryType::Https,
    DNS_CLASS_IN,
    answer_count,
  );
  (query, response)
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
  assert_eq!(a.query_name(), Some("app.example"));
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
  assert!(lookup.accepted_cname());
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
fn response_retains_only_bounded_https_transport_metadata() {
  let (query, mut response) = https_response(2);
  add_https(
    &mut response,
    "svc.example",
    9,
    1,
    Some("Target.Example."),
    &[
      (HTTPS_PARAM_MANDATORY, vec![0, 1, 0, 3, 0, 4, 0, 6]),
      (
        HTTPS_PARAM_ALPN,
        [
          vec![2, b'h', b'2'],
          vec![2, b'h', b'3'],
          vec![8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'],
          vec![6, b'f', b'u', b't', b'u', b'r', b'e'],
        ]
        .concat(),
      ),
      (HTTPS_PARAM_PORT, 443_u16.to_be_bytes().to_vec()),
      (HTTPS_PARAM_IPV4_HINT, vec![192, 0, 2, 1, 198, 51, 100, 2]),
      (HTTPS_PARAM_ECH, vec![0xff, 0, 1, 2]),
      (
        HTTPS_PARAM_IPV6_HINT,
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
          .octets()
          .to_vec(),
      ),
      (65_000, vec![1, 2, 3]),
    ],
  );
  add_https(&mut response, "svc.example", 7, 2, None, &[]);

  let lookup = parse_dns_response(&response, &query).expect("valid HTTPS response");
  assert_eq!(lookup.ttl_ms, 7_000);
  assert_eq!(
    lookup.answers,
    vec![
      DnsAnswer::Https(HttpsRecord {
        priority: 1,
        target: HttpsTarget::Absolute("target.example".to_string()),
        alpn_present: true,
        alpn: vec![HttpsAlpn::H2, HttpsAlpn::H3, HttpsAlpn::H1].into_boxed_slice(),
        port: NonZeroU16::new(443),
        ipv4_hints: vec![Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(198, 51, 100, 2)]
          .into_boxed_slice(),
        ipv6_hints: vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)].into_boxed_slice(),
      }),
      DnsAnswer::Https(HttpsRecord {
        priority: 2,
        target: HttpsTarget::Owner,
        alpn_present: false,
        alpn: Box::default(),
        port: None,
        ipv4_hints: Box::default(),
        ipv6_hints: Box::default(),
      }),
    ]
  );
}

#[test]
fn response_rejects_malformed_or_unsafe_https_parameters() {
  let cases = [
    (
      "duplicate parameter",
      1,
      Some("target.example"),
      vec![
        (HTTPS_PARAM_PORT, 443_u16.to_be_bytes().to_vec()),
        (HTTPS_PARAM_PORT, 8443_u16.to_be_bytes().to_vec()),
      ],
    ),
    (
      "unknown mandatory parameter",
      1,
      Some("target.example"),
      vec![(HTTPS_PARAM_MANDATORY, vec![0, 9])],
    ),
    (
      "unordered mandatory parameter",
      1,
      Some("target.example"),
      vec![(HTTPS_PARAM_MANDATORY, vec![0, 3, 0, 1])],
    ),
    (
      "mandatory ECH is rejected",
      1,
      Some("target.example"),
      vec![
        (HTTPS_PARAM_MANDATORY, vec![0, HTTPS_PARAM_ECH as u8]),
        (HTTPS_PARAM_ECH, vec![1, 2]),
      ],
    ),
    (
      "zero port",
      1,
      Some("target.example"),
      vec![(HTTPS_PARAM_PORT, vec![0, 0])],
    ),
    (
      "bad IPv4 hint length",
      1,
      Some("target.example"),
      vec![(HTTPS_PARAM_IPV4_HINT, vec![192, 0, 2])],
    ),
    (
      "no-default ALPN without a supported identifier",
      1,
      Some("target.example"),
      vec![
        (HTTPS_PARAM_ALPN, vec![3, b'f', b'o', b'o']),
        (HTTPS_PARAM_NO_DEFAULT_ALPN, Vec::new()),
      ],
    ),
    (
      "alias parameters",
      0,
      Some("target.example"),
      vec![(HTTPS_PARAM_PORT, 443_u16.to_be_bytes().to_vec())],
    ),
    ("alias root target", 0, None, vec![]),
  ];
  for (name, priority, target, params) in cases {
    let (query, mut response) = https_response(1);
    add_https(&mut response, "svc.example", 10, priority, target, &params);
    assert_eq!(
      parse_dns_response(&response, &query)
        .expect_err(name)
        .class(),
      ResolutionErrorClass::Malformed,
      "{name} must fail closed"
    );
  }
}

#[test]
fn response_rejects_https_alias_loops_and_record_overflow() {
  let (query, mut loop_response) = https_response(1);
  add_https(
    &mut loop_response,
    "svc.example",
    10,
    0,
    Some("svc.example"),
    &[],
  );
  assert_eq!(
    parse_dns_response(&loop_response, &query)
      .expect_err("self-referential HTTPS alias must fail")
      .class(),
    ResolutionErrorClass::Malformed
  );

  let (query, mut indirect_loop_response) = https_response(3);
  add_cname(
    &mut indirect_loop_response,
    "svc.example",
    10,
    "alias.example",
  );
  add_https(
    &mut indirect_loop_response,
    "svc.example",
    10,
    0,
    Some("alias.example"),
    &[],
  );
  add_https(
    &mut indirect_loop_response,
    "alias.example",
    10,
    0,
    Some("svc.example"),
    &[],
  );
  assert_eq!(
    parse_dns_response(&indirect_loop_response, &query)
      .expect_err("indirect HTTPS alias loop must fail")
      .class(),
    ResolutionErrorClass::Malformed
  );

  let (query, mut overflow_response) = https_response((DNS_HTTPS_MAX_RECORDS + 1) as u16);
  for _ in 0..=DNS_HTTPS_MAX_RECORDS {
    add_https(
      &mut overflow_response,
      "svc.example",
      10,
      1,
      Some("target.example"),
      &[],
    );
  }
  assert_eq!(
    parse_dns_response(&overflow_response, &query)
      .expect_err("HTTPS record overflow must fail")
      .class(),
    ResolutionErrorClass::Malformed
  );
}

#[test]
fn response_rejects_mixed_or_duplicate_https_alias_mode() {
  let (query, mut mixed) = https_response(2);
  add_https(&mut mixed, "svc.example", 10, 0, Some("alias.example"), &[]);
  add_https(
    &mut mixed,
    "svc.example",
    10,
    1,
    Some("target.example"),
    &[],
  );
  assert_eq!(
    parse_dns_response(&mixed, &query)
      .expect_err("mixed AliasMode and ServiceMode must fail")
      .class(),
    ResolutionErrorClass::Malformed
  );

  let (query, mut duplicate) = https_response(2);
  for _ in 0..2 {
    add_https(
      &mut duplicate,
      "svc.example",
      10,
      0,
      Some("alias.example"),
      &[],
    );
  }
  assert_eq!(
    parse_dns_response(&duplicate, &query)
      .expect_err("duplicate AliasMode records must fail")
      .class(),
    ResolutionErrorClass::Malformed
  );
}

#[test]
fn response_rejects_https_parameter_header_crossing_rdata() {
  let (query, mut response) = https_response(2);
  let truncated_parameter_header = [0, 1, 0, 0, HTTPS_PARAM_PORT as u8];
  add_record(
    &mut response,
    "svc.example",
    DNS_TYPE_HTTPS,
    10,
    &truncated_parameter_header,
  );
  add_a(
    &mut response,
    "svc.example",
    10,
    Ipv4Addr::new(192, 0, 2, 1),
  );
  assert_eq!(
    parse_dns_response(&response, &query)
      .expect_err("SvcParam header must stay inside its RDATA")
      .class(),
    ResolutionErrorClass::Malformed
  );
}

#[test]
fn response_rejects_https_hint_and_parameter_caps() {
  let (query, mut hint_response) = https_response(1);
  let mut hints = Vec::new();
  for last in 0..=DNS_HTTPS_MAX_HINTS_PER_FAMILY {
    hints.extend_from_slice(&[192, 0, 2, last as u8]);
  }
  add_https(
    &mut hint_response,
    "svc.example",
    10,
    1,
    Some("target.example"),
    &[(HTTPS_PARAM_IPV4_HINT, hints)],
  );
  assert!(parse_dns_response(&hint_response, &query).is_err());

  let (query, mut params_response) = https_response(1);
  let params = (10..=(10 + DNS_HTTPS_MAX_PARAMS as u16))
    .map(|key| (key, Vec::new()))
    .collect::<Vec<_>>();
  add_https(
    &mut params_response,
    "svc.example",
    10,
    1,
    Some("target.example"),
    &params,
  );
  assert!(parse_dns_response(&params_response, &query).is_err());
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

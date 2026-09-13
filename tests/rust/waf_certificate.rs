//! Certificate expressions exercise the public devtools and runtime evaluation paths.
use super::*;
use oxibelt::waf::metadata::{WafCertificateMetadata, WafCertificateNames};
use serde_json::{Value as JsonValue, json};
use std::sync::Arc;

fn certificate(identity: &str) -> JsonValue {
  json!({
    "fingerprint_sha256": identity.repeat(64),
    "subject_common_names": ["client.example", "second.example"],
    "san_dns_names": ["client.example", "*.example"],
    "san_ip_addresses": ["192.0.2.1", "2001:db8::1"],
    "san_uri_names": ["spiffe://example.test/workload"],
    "san_email_addresses": ["User@Example.test"]
  })
}

fn evaluate(
  config: &Config,
  phase: WafPhase,
  expression: &str,
  fixture: JsonValue,
) -> oxibelt::waf::OxiRuleDevtoolsReport {
  let action = match phase {
    WafPhase::Request => "type = 'reject'\nstatus = 403",
    WafPhase::Response => "type = 'reject_response'\nstatus = 502",
    WafPhase::Stream => "type = 'close_stream'\nreason = 'certificate policy'",
  };
  test_oxirule(
    config,
    OxiRuleDevtoolsEvalRequest {
      rule: devtools_rule(
        "certificate-policy",
        phase,
        &format!("when = {expression:?}\n\n[[actions]]\n{action}\n"),
      ),
      groups: Vec::new(),
      include_active_rules: false,
      fixture: serde_json::from_value(fixture).expect("valid fixture"),
      expected: None,
    },
  )
}

fn assert_matched(report: oxibelt::waf::OxiRuleDevtoolsReport) {
  assert!(report.ok, "{:?}", report.diagnostics);
  assert!(
    report
      .matched_rules
      .iter()
      .any(|rule| rule.name == "certificate-policy"),
    "{report:?}"
  );
}

#[test]
fn certificate_names_use_existing_bounded_list_operators() {
  let config = minimal_devtools_config("certificate-fields");
  let expression = format!(
    "Request.Tls.ClientCertificate != null && Request.Tls.ClientCertificatePresent && Request.Tls.Fingerprint == 'hello-fingerprint' && Request.Tls.ClientCertificate.FingerprintSha256 == '{}' && Request.Tls.ClientCertificate.ParseStatus == 'complete' && Request.Tls.ClientCertificate.SubjectCommonNames.Count == 2 && Request.Tls.ClientCertificate.SubjectCommonNames.First == 'client.example' && Request.Tls.ClientCertificate.SubjectCommonNames.contains('second.example') && Request.Tls.ClientCertificate.SanDnsNames.contains('*.example') && !Request.Tls.ClientCertificate.SanDnsNames.contains('host.example') && Request.Tls.ClientCertificate.SanIpAddresses.contains('2001:db8::1') && Request.Tls.ClientCertificate.SanUriNames.contains('spiffe://example.test/workload') && Request.Tls.ClientCertificate.SanEmailAddresses.contains('User@Example.test') && !Request.Tls.ClientCertificate.SanEmailAddresses.contains('user@example.test') && !Request.Tls.ClientCertificate.SanDnsNames.IsTruncated",
    "a".repeat(64)
  );
  assert_matched(evaluate(
    &config,
    WafPhase::Request,
    &expression,
    json!({"request":{"tls":{"enabled":true,"fingerprint":"hello-fingerprint","client_certificate":certificate("a")}}}),
  ));
}

#[test]
fn certificate_response_keeps_downstream_and_upstream_identities_separate() {
  let config = minimal_devtools_config("certificate-response");
  let expression = format!(
    "Request.Tls.ClientCertificate.FingerprintSha256 == '{}' && Response.Upstream.ServerCertificate.FingerprintSha256 == '{}' && Response.Upstream.ServerCertificate.SanEmailAddresses.contains('User@Example.test') && Response.Tls.Enabled == false",
    "a".repeat(64),
    "b".repeat(64)
  );
  assert_matched(evaluate(
    &config,
    WafPhase::Response,
    &expression,
    json!({"request":{"tls":{"enabled":true,"client_certificate":certificate("a")}},"response":{"server_certificate":certificate("b")}}),
  ));
}

#[test]
fn certificate_stream_fields_cover_both_protocols_and_directions() {
  let config = minimal_devtools_config("certificate-stream");
  for direction in ["downstream_to_upstream", "upstream_to_downstream"] {
    for (protocol, unit) in [
      ("websocket", "websocket_frame"),
      ("webtransport", "webtransport_datagram"),
    ] {
      assert_matched(evaluate(
        &config,
        WafPhase::Stream,
        "Request.Tls.ClientCertificate != null && Stream.Upstream.ServerCertificate != null && Stream.Upstream.ServerCertificate.SanUriNames.contains('spiffe://example.test/workload')",
        json!({"request":{"tls":{"enabled":true,"client_certificate":certificate("a")}},"stream":{"protocol":protocol,"unit":unit,"direction":direction,"server_certificate":certificate("b")}}),
      ));
    }
  }
}

#[test]
fn certificate_absence_and_incomplete_extraction_are_distinct() {
  let config = minimal_devtools_config("certificate-absence");
  for (phase, expression, fixture) in [
    (
      WafPhase::Request,
      "Request.Tls.ClientCertificate == null",
      json!({}),
    ),
    (
      WafPhase::Response,
      "Response.Upstream.ServerCertificate == null",
      json!({"response":{}}),
    ),
    (
      WafPhase::Stream,
      "Stream.Upstream.ServerCertificate == null",
      json!({"stream":{}}),
    ),
  ] {
    assert_matched(evaluate(&config, phase, expression, fixture));
  }
  let mut incomplete = certificate("a");
  incomplete["parse_complete"] = json!(false);
  assert_matched(evaluate(
    &config,
    WafPhase::Request,
    "Request.Tls.ClientCertificate != null && Request.Tls.ClientCertificate.ParseStatus == 'incomplete' && Request.Tls.ClientCertificate.SubjectCommonNames.contains('client.example')",
    json!({"request":{"tls":{"enabled":true,"client_certificate":incomplete}}}),
  ));
}

#[test]
fn certificate_helpers_apply_item_and_result_byte_limits_without_cutting_names() {
  let mut config = minimal_devtools_config("certificate-limits");
  config.waf.limits.max_helper_items = 1;
  assert_matched(evaluate(
    &config,
    WafPhase::Request,
    "Request.Tls.ClientCertificate.ParseStatus == 'complete' && Request.Tls.ClientCertificate.SubjectCommonNames.Count == 1 && Request.Tls.ClientCertificate.SubjectCommonNames.IsTruncated && !Request.Tls.ClientCertificate.SubjectCommonNames.contains('second.example')",
    json!({"request":{"tls":{"client_certificate":certificate("a")}}}),
  ));
  config.waf.limits.max_helper_result_bytes = 1;
  assert_matched(evaluate(
    &config,
    WafPhase::Request,
    "Request.Tls.ClientCertificate.SubjectCommonNames.Count == 0 && Request.Tls.ClientCertificate.SubjectCommonNames.First == null && Request.Tls.ClientCertificate.SubjectCommonNames.IsTruncated",
    json!({"request":{"tls":{"client_certificate":certificate("a")}}}),
  ));
}

#[test]
fn certificate_unknown_members_keep_runtime_failure_behavior() {
  let config = minimal_devtools_config("certificate-unknown");
  let report = evaluate(
    &config,
    WafPhase::Request,
    "Request.Tls.ClientCertificate.Unknown == 'x'",
    json!({"request":{"tls":{"client_certificate":certificate("a")}}}),
  );
  assert!(
    !report.ok || report.terminal.is_some(),
    "unknown members must not silently allow: {report:?}"
  );
  assert!(report.matched_rules.is_empty());
}

#[test]
fn certificate_upstream_and_stream_roots_retain_phase_restrictions() {
  let config = minimal_devtools_config("certificate-phase");
  for expression in [
    "Response.Upstream.ServerCertificate == null",
    "Stream.Upstream.ServerCertificate == null",
  ] {
    let report = evaluate(&config, WafPhase::Request, expression, json!({}));
    assert!(!report.ok, "phase restrictions must reject: {report:?}");
  }
}

fn runtime_certificate(identity: char, dns_names_truncated: bool) -> WafCertificateMetadata {
  let names = |values: &[&str], is_truncated| WafCertificateNames {
    values: values.iter().map(|value| (*value).to_string()).collect(),
    is_truncated,
  };
  WafCertificateMetadata {
    fingerprint_sha256: identity.to_string().repeat(64),
    parse_complete: true,
    subject_common_names: names(&["client.example", "second.example"], false),
    san_dns_names: names(&["client.example", "*.example"], dns_names_truncated),
    san_ip_addresses: names(&["192.0.2.1", "2001:db8::1"], false),
    san_uri_names: names(&["spiffe://example.test/workload"], false),
    san_email_addresses: names(&["client@example.test"], false),
  }
}

#[test]
fn h3_client_certificate_details_without_legacy_projection_are_present_and_incomplete() {
  let engine = compile_waf_fragment(
    "waf-h3-certificate-details-only",
    r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "certificate-details-only"
phase = "request"
priority = 10
when = "Request.Tls.ClientCertificatePresent && Request.Tls.ClientCertificate != null && Request.Tls.ClientCertificate.ParseStatus == 'incomplete'"

[[waf.rules.actions]]
type = "reject"
status = 403
"#,
  );
  let mut incomplete = runtime_certificate('d', false);
  incomplete.parse_complete = false;
  let tls = WafTlsMetadata {
    enabled: true,
    client_certificate: None,
    client_certificate_details: Some(Arc::new(incomplete)),
    ..WafTlsMetadata::default()
  };
  let method = Method::GET;
  let uri: Uri = "/h3-certificate".parse().expect("valid request URI");
  let headers = HeaderMap::new();
  let tags = HashMap::new();
  let request = request_input_with_protocol_and_network(
    &method,
    &uri,
    &headers,
    &tags,
    "203.0.113.10:49152".parse().unwrap(),
    &tls,
    WafProtocol::Http,
    WafTransportNetwork::Udp,
  );

  assert!(tls.client_certificate.is_none());
  assert!(tls.client_certificate_details.is_some());
  let decision = engine.evaluate_request(request);
  assert!(
    decision.terminal.is_some(),
    "details-only H3 certificate metadata must be present and retain its incomplete parse status: {decision:?}"
  );
}

#[test]
fn certificate_access_logs_project_metadata_explicitly_and_keep_capture_truncation() {
  let fragment = format!(
    r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[waf.limits]
max_helper_items = 256
max_helper_result_bytes = 65536

[[waf.rules]]
name = "certificate-access-log"
phase = "response"
priority = 10
when = "true"

[[waf.rules.actions]]
type = "emit_access_log"

[[waf.rules.actions.fields]]
name = "request_tls"
value = "Request.Tls"

[[waf.rules.actions.fields]]
name = "request_certificate"
value = "Request.Tls.ClientCertificate"

[[waf.rules.actions.fields]]
name = "request_fingerprint"
value = "Request.Tls.ClientCertificate.FingerprintSha256"

[[waf.rules.actions.fields]]
name = "request_dns_names"
value = "Request.Tls.ClientCertificate.SanDnsNames"

[[waf.rules.actions.fields]]
name = "request_dns_truncated"
value = "Request.Tls.ClientCertificate.SanDnsNames.IsTruncated"

[[waf.rules.actions.fields]]
name = "response_upstream"
value = "Response.Upstream"

[[waf.rules.actions.fields]]
name = "response_certificate"
value = "Response.Upstream.ServerCertificate"

[[waf.rules.actions.fields]]
name = "response_fingerprint"
value = "Response.Upstream.ServerCertificate.FingerprintSha256"

[[waf.rules.actions.fields]]
name = "response_dns_names"
value = "Response.Upstream.ServerCertificate.SanDnsNames"

[[waf.rules.actions.fields]]
name = "response_dns_truncated"
value = "Response.Upstream.ServerCertificate.SanDnsNames.IsTruncated"

[[waf.rules]]
name = "stream-certificate-capture-truncation"
phase = "stream"
priority = 10
when = "Stream.Upstream.ServerCertificate.FingerprintSha256 == '{stream_fingerprint}' && Stream.Upstream.ServerCertificate.ParseStatus == 'complete' && Stream.Upstream.ServerCertificate.SanDnsNames.IsTruncated"

[[waf.rules.actions]]
type = "close_stream"
reason = "truncated certificate names"
"#,
    stream_fingerprint = "c".repeat(64),
  );
  let engine = compile_waf_fragment("waf-certificate-access-log", &fragment);
  let request_certificate = runtime_certificate('a', true);
  let response_certificate = runtime_certificate('b', true);
  let stream_certificate = runtime_certificate('c', true);
  let tls = WafTlsMetadata {
    enabled: true,
    version: Some("TLSv1.3".to_string()),
    cipher_suite: Some("TLS_AES_128_GCM_SHA256".to_string()),
    sni: Some("api.example.com".to_string()),
    alpn: Some("h2".to_string()),
    fingerprint: Some("tls-client-fingerprint".to_string()),
    fingerprint_scheme: Some("sha256".to_string()),
    client_certificate: Some(WafClientCertificateMetadata {
      fingerprint_sha256: request_certificate.fingerprint_sha256.clone(),
      subject_common_names: request_certificate.subject_common_names.values.clone(),
      san_dns_names: request_certificate.san_dns_names.values.clone(),
      san_ip_addresses: request_certificate.san_ip_addresses.values.clone(),
    }),
    client_certificate_details: Some(Arc::new(request_certificate.clone())),
  };
  let method = Method::GET;
  let uri: Uri = "/certificate".parse().expect("valid request URI");
  let request_headers = HeaderMap::new();
  let response_headers = HeaderMap::new();
  let tags = HashMap::new();
  let request = request_input_with_tls(
    &method,
    &uri,
    &request_headers,
    &tags,
    "203.0.113.10:49152".parse().unwrap(),
    &tls,
  );

  let decision = engine.evaluate_response(WafResponseInput {
    request,
    response_id: "certificate-response",
    received_at_unix_ms: 1_700_000_000_123,
    version: http::Version::HTTP_2,
    status: StatusCode::OK,
    headers: &response_headers,
    body: None,
    upstream_name: "origin",
    upstream_pool: Some("primary"),
    upstream_scheme: "https",
    upstream_connect_time_ms: Some(11),
    upstream_first_byte_time_ms: Some(13),
    upstream_error: None,
    upstream_certificate: Some(&response_certificate),
  });

  assert!(
    decision.terminal.is_none(),
    "unexpected terminal decision: {decision:?}"
  );
  assert_eq!(decision.access_logs.len(), 1);
  let logged = decision.access_logs[0].to_json_value();
  assert_eq!(
    logged["request_tls"],
    json!({
      "enabled": true,
      "version": "TLSv1.3",
      "ciphersuite": "TLS_AES_128_GCM_SHA256",
      "sni": "api.example.com",
      "alpn": "h2",
      "fingerprint": "tls-client-fingerprint",
      "fingerprintscheme": "sha256",
      "clientcertificatepresent": true
    })
  );
  assert_eq!(
    logged["request_certificate"],
    json!({
      "fingerprintsha256": "a".repeat(64),
      "parsestatus": "complete",
      "subjectcommonnames": {"values": ["client.example", "second.example"], "is_truncated": false},
      "sandnsnames": {"values": ["client.example", "*.example"], "is_truncated": true},
      "sanipaddresses": {"values": ["192.0.2.1", "2001:db8::1"], "is_truncated": false},
      "sanurinames": {"values": ["spiffe://example.test/workload"], "is_truncated": false},
      "sanemailaddresses": {"values": ["client@example.test"], "is_truncated": false}
    })
  );
  assert_eq!(logged["request_fingerprint"], json!("a".repeat(64)));
  assert_eq!(
    logged["request_dns_names"],
    json!({"values": ["client.example", "*.example"], "is_truncated": true})
  );
  assert_eq!(logged["request_dns_truncated"], json!(true));
  assert_eq!(
    logged["response_upstream"],
    json!({
      "name": "origin",
      "pool": "primary",
      "scheme": "https",
      "connecttimems": 11,
      "firstbytetimems": 13,
      "error": null
    })
  );
  assert_eq!(
    logged["response_certificate"],
    json!({
      "fingerprintsha256": "b".repeat(64),
      "parsestatus": "complete",
      "subjectcommonnames": {"values": ["client.example", "second.example"], "is_truncated": false},
      "sandnsnames": {"values": ["client.example", "*.example"], "is_truncated": true},
      "sanipaddresses": {"values": ["192.0.2.1", "2001:db8::1"], "is_truncated": false},
      "sanurinames": {"values": ["spiffe://example.test/workload"], "is_truncated": false},
      "sanemailaddresses": {"values": ["client@example.test"], "is_truncated": false}
    })
  );
  assert_eq!(logged["response_fingerprint"], json!("b".repeat(64)));
  assert_eq!(
    logged["response_dns_names"],
    json!({"values": ["client.example", "*.example"], "is_truncated": true})
  );
  assert_eq!(logged["response_dns_truncated"], json!(true));

  let stream_decision = engine.evaluate_stream(WafStreamInput {
    request,
    protocol: WafStreamProtocol::Webtransport,
    direction: WafStreamDirection::UpstreamToDownstream,
    unit: WafStreamUnit::WebtransportDatagram,
    payload: WafBodyInput {
      bytes: b"datagram",
      is_truncated: false,
    },
    websocket: None,
    webtransport: Some(WafWebTransportStreamMetadata {
      stream_kind: None,
      stream_id: None,
      datagram_size: Some(8),
    }),
    upstream_certificate: Some(&stream_certificate),
  });
  assert!(
    stream_decision.close.is_some(),
    "stream certificate capture truncation must remain visible with high WAF limits: {stream_decision:?}"
  );
}

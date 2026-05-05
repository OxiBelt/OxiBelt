#[path = "common/mod.rs"]
mod common;

use std::collections::HashMap;
use std::net::SocketAddr;

use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use oxibelt::config::Config;
use oxibelt::waf::{
    HeaderMutation, WafBodyInput, WafEngine, WafProtocol, WafRequestInput, WafResponseInput,
    WafTlsMetadata, WafTransportNetwork,
};
use ring::digest;

#[test]
fn request_rule_can_reject_by_path_and_client_cidr() {
    let temp_dir = common::TempDir::new("waf-reject");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "waf-reject");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "block-public-admin"
phase = "request"
priority = 100
when = "Request.Http.Path.startsWith('/admin') && !Request.Client.Ip.inCidr('10.0.0.0/8')"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "Forbidden"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = "/admin".parse().expect("URI should parse");
    let decision = engine.evaluate_request(request_input(
        &method,
        &uri,
        &headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ));

    assert_eq!(
        decision.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );
}

#[test]
fn request_body_format_helper_can_reject_non_png_payload() {
    let temp_dir = common::TempDir::new("waf-request-body-png");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-request-body-png");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "post-must-be-png"
phase = "request"
priority = 10
when = "Request.Http.Method == 'POST' && !Request.Body.isFormat('png')"

[[waf.rules.actions]]
type = "reject"
status = 415
body = "Unsupported Media Type"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");
    assert!(engine.requires_request_body_inspection("app-root"));

    let method = Method::POST;
    let uri: Uri = "/upload".parse().expect("URI should parse");
    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let peer_addr: SocketAddr = "203.0.113.10:49152".parse().unwrap();

    let png = b"\x89PNG\r\n\x1a\npayload";
    let allowed = engine.evaluate_request(request_input_with_body(
        &method, &uri, &headers, &tags, peer_addr, png, false,
    ));
    assert!(allowed.terminal.is_none());

    let zip = b"PK\x03\x04payload";
    let rejected = engine.evaluate_request(request_input_with_body(
        &method, &uri, &headers, &tags, peer_addr, zip, false,
    ));
    assert_eq!(
        rejected.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::UNSUPPORTED_MEDIA_TYPE)
    );
}

#[test]
fn request_body_bytes_format_helper_matches_supported_binary_formats() {
    let temp_dir = common::TempDir::new("waf-request-body-binary-formats");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-request-body-binary-formats");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "block-archive-and-webm"
phase = "request"
priority = 10
when = "Request.Http.Body.Bytes.isFormat('zip') || Request.Http.Body.Bytes.isFormat('webm') || Request.Http.Body.Bytes.isFormat('7z') || Request.Http.Body.Bytes.isFormat('elf') || Request.Http.Body.Bytes.isFormat('windows-exe')"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "blocked binary format"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");
    assert!(engine.requires_request_body_inspection("app-root"));

    let method = Method::PUT;
    let uri: Uri = "/upload".parse().expect("URI should parse");
    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let peer_addr: SocketAddr = "203.0.113.10:49152".parse().unwrap();
    let pe = {
        let mut bytes = vec![0u8; 0x84];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes
    };

    for body in [
        b"PK\x03\x04payload".as_slice(),
        b"\x37\x7a\xbc\xaf\x27\x1c\x00\x04payload".as_slice(),
        b"\x1a\x45\xdf\xa3\x9f\x42\x86\x81\x01\x42\xf7\x81\x01\x42\xf2\x81\x04\x42\xf3\x81\x08\x42\x82\x84webmpayload".as_slice(),
        b"\x7fELF\x02\x01\x01payload".as_slice(),
        pe.as_slice(),
    ] {
        let decision = engine.evaluate_request(request_input_with_body(
            &method, &uri, &headers, &tags, peer_addr, body, false,
        ));
        assert_eq!(
            decision.terminal.as_ref().map(|terminal| terminal.status),
            Some(StatusCode::FORBIDDEN)
        );
    }
}

#[test]
fn request_rule_can_match_tcp_max_hop_metadata() {
    let temp_dir = common::TempDir::new("waf-tcp-hop-metadata");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "waf-tcp-hop");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "reject-short-hop"
phase = "request"
priority = 10
when = "Request.Transport.Tcp.MaxHop == 16"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "short hop"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");
    let method = Method::GET;
    let uri: Uri = "/protected".parse().expect("URI should parse");
    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let peer_addr: SocketAddr = "203.0.113.10:49152".parse().unwrap();

    let rejected = engine.evaluate_request(request_input_with_tcp_max_hop(
        &method, &uri, &headers, &tags, peer_addr, 16,
    ));
    assert_eq!(
        rejected.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );

    let allowed = engine.evaluate_request(request_input_with_tcp_max_hop(
        &method, &uri, &headers, &tags, peer_addr, 32,
    ));
    assert!(allowed.terminal.is_none());
}

#[test]
fn request_rule_can_match_tcp_sni_and_alpn_metadata() {
    let temp_dir = common::TempDir::new("waf-tcp-tls-metadata");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "waf-tcp-tls");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "reject-transport-tls-metadata"
phase = "request"
priority = 10
when = "Request.Transport.Tcp.Sni == 'example.com' && Request.Transport.Tcp.Alpn == 'h2' && Request.Tls.FingerprintScheme == 'rustls-tcp-negotiated-v2'"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "blocked transport TLS metadata"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");
    let method = Method::GET;
    let uri: Uri = "/protected".parse().expect("URI should parse");
    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let peer_addr: SocketAddr = "203.0.113.10:49152".parse().unwrap();

    let rejected = engine.evaluate_request(request_input_with_tls(
        &method,
        &uri,
        &headers,
        &tags,
        peer_addr,
        &test_tls("browser-fingerprint"),
    ));
    assert_eq!(
        rejected.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );
}

#[test]
fn request_rule_can_match_webtransport_udp_metadata() {
    let temp_dir = common::TempDir::new("waf-webtransport-udp");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-webtransport-udp");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "reject-webtransport-udp"
phase = "request"
priority = 10
when = "Request.Protocol == 'webtransport' && Request.Transport.Network == 'udp' && Request.Transport.Udp != null && Request.Transport.Tcp == null"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "webtransport blocked"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");
    let method = Method::CONNECT;
    let uri: Uri = "https://example.com/session"
        .parse()
        .expect("URI should parse");
    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let peer_addr: SocketAddr = "203.0.113.10:49152".parse().unwrap();
    let tls = WafTlsMetadata {
        enabled: true,
        version: Some("TLSv1_3".to_string()),
        cipher_suite: None,
        sni: Some("example.com".to_string()),
        alpn: Some("h3".to_string()),
        fingerprint: Some("quic-fingerprint".to_string()),
        fingerprint_scheme: Some("quinn-rustls-quic-v2".to_string()),
    };

    let rejected = engine.evaluate_request(request_input_with_protocol_and_network(
        &method,
        &uri,
        &headers,
        &tags,
        peer_addr,
        &tls,
        WafProtocol::Webtransport,
        WafTransportNetwork::Udp,
    ));
    assert_eq!(
        rejected.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );
}

#[test]
fn http3_request_rules_can_match_quic_tls_fingerprint() {
    let temp_dir = common::TempDir::new("waf-quic-fingerprint");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-quic-fingerprint");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "block-quic-fingerprint"
phase = "request"
priority = 1
when = "Request.Protocol == 'http' && Request.Transport.Network == 'udp' && Request.Transport.Udp.QuicDetected == true && Request.Tls.FingerprintScheme == 'quinn-rustls-quic-v2' && Request.Tls.Fingerprint == 'quic-fingerprint'"

[[waf.rules.actions]]
type = "reject"
status = 451
body = "quic fingerprint blocked"
"#,
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");
    let method = Method::GET;
    let uri: Uri = "https://example.com/h3".parse().expect("URI should parse");
    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let peer_addr: SocketAddr = "203.0.113.10:49152".parse().unwrap();
    let tls = WafTlsMetadata {
        enabled: true,
        version: Some("TLSv1_3".to_string()),
        cipher_suite: None,
        sni: Some("example.com".to_string()),
        alpn: Some("h3".to_string()),
        fingerprint: Some("quic-fingerprint".to_string()),
        fingerprint_scheme: Some("quinn-rustls-quic-v2".to_string()),
    };

    let rejected = engine.evaluate_request(request_input_with_protocol_and_network(
        &method,
        &uri,
        &headers,
        &tags,
        peer_addr,
        &tls,
        WafProtocol::Http,
        WafTransportNetwork::Udp,
    ));
    assert_eq!(
        rejected.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS)
    );
}

#[test]
fn request_rule_can_match_person_proof_token_binding_inputs() {
    let temp_dir = common::TempDir::new("waf-token-binding-inputs");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-token-binding-inputs");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "reject-token-binding-inputs"
phase = "request"
priority = 10
when = """
Request.TokenBindings.UserAgent == 'Mozilla/5.0 TokenBindingTest' &&
Request.TokenBindings.TlsFingerprint == 'browser-fingerprint' &&
Request.TokenBindings.Route == 'app-root' &&
Request.TokenBindings.DirectPeerIpNetworkPrefix == 'ipv4:203.0.113.0/24' &&
Request.TokenBindings.TcpMaxHop == 'configured=unconfigured;applied=16' &&
Request.TokenBindings.directPeerIpNetworkPrefix(32, 128) == 'ipv4:203.0.113.10/32' &&
Request.TokenBindings.tcpMaxHop(16) == 'configured=16;applied=16'
"""

[[waf.rules.actions]]
type = "reject"
status = 403
body = "blocked token binding inputs"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");
    let method = Method::GET;
    let uri: Uri = "/protected".parse().expect("URI should parse");
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::USER_AGENT,
        HeaderValue::from_static("Mozilla/5.0 TokenBindingTest"),
    );
    let tags = HashMap::new();
    let peer_addr: SocketAddr = "203.0.113.10:49152".parse().unwrap();

    let rejected = engine.evaluate_request(request_input_with_transport(
        &method,
        &uri,
        &headers,
        &tags,
        peer_addr,
        Some(16),
        &test_tls("browser-fingerprint"),
    ));

    assert_eq!(
        rejected.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );
}

#[test]
fn request_tags_are_visible_to_response_rules() {
    let temp_dir = common::TempDir::new("waf-tags");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "waf-tags");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "tag-login"
phase = "request"
priority = 10
when = "Request.Http.Path.startsWith('/login')"

[[waf.rules.actions]]
type = "set_tag"
key = "LoginRequest"
value = "true"

[[waf.rules]]
name = "no-store-login-errors"
phase = "response"
priority = 20
when = "Request.Tags.get('LoginRequest') == 'true' && Response.Http.Status >= 500"

[[waf.rules.actions]]
type = "set_response_header"
name = "Cache-Control"
value = "no-store"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let headers = HeaderMap::new();
    let mut tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = "/login".parse().expect("URI should parse");
    let request_decision = engine.evaluate_request(request_input(
        &method,
        &uri,
        &headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ));
    for (key, value) in request_decision.tags {
        tags.insert(key, value);
    }

    let response_headers = HeaderMap::new();
    let response_decision = engine.evaluate_response(WafResponseInput {
        request: request_input(
            &method,
            &uri,
            &headers,
            &tags,
            "203.0.113.10:49152".parse().unwrap(),
        ),
        status: StatusCode::INTERNAL_SERVER_ERROR,
        headers: &response_headers,
        upstream_name: "app",
        upstream_error: None,
    });

    assert_eq!(response_decision.response_header_mutations.len(), 1);
}

#[test]
fn request_tags_are_visible_to_later_request_rules() {
    let temp_dir = common::TempDir::new("waf-request-tag-chain");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-request-tag-chain");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "tag-login"
phase = "request"
priority = 10
when = "Request.Http.Path.startsWith('/login')"

[[waf.rules.actions]]
type = "set_tag"
key = "LoginRequest"
value = "true"

[[waf.rules]]
name = "block-tagged-login"
phase = "request"
priority = 20
when = "Request.Tags.get('LoginRequest') == 'true'"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "tagged"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = "/login".parse().expect("URI should parse");
    let decision = engine.evaluate_request(request_input(
        &method,
        &uri,
        &headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ));

    assert_eq!(
        decision.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );
}

#[test]
fn person_proof_challenge_allows_solved_pow() {
    let temp_dir = common::TempDir::new("waf-person-proof");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-person-proof");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "require-person-proof"
phase = "request"
priority = 10
when = "Request.Client.PersonProof.State != 'valid' && Request.Client.Agent.Verified != true && Request.Client.Bot.Disposition != 'normal'"

[[waf.rules.actions]]
type = "require_person_proof"
difficulty = 4
token_validity_seconds = 60
cookie = "__test_person_proof"
success_tag = "PersonProof"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = "/protected".parse().expect("URI should parse");
    let challenge_decision = engine.evaluate_request(request_input(
        &method,
        &uri,
        &headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ));

    let challenge = challenge_decision
        .terminal
        .as_ref()
        .expect("missing person proof challenge");
    assert_eq!(challenge.status, StatusCode::FORBIDDEN);
    assert!(challenge.body.contains("Person proof required"));
    assert!(challenge.body.contains("cdn.jsdelivr.net"));
    assert!(challenge.body.contains("Pretendard"));
    assert!(challenge.body.contains("nonce=\""));

    let csp = extract_response_header(
        &challenge.headers,
        http::header::HeaderName::from_static("content-security-policy"),
    );
    assert!(csp.contains("default-src 'none'"));
    assert!(csp.contains("script-src 'nonce-"));
    assert!(csp.contains("style-src 'nonce-"));
    assert!(csp.contains("https://cdn.jsdelivr.net"));
    assert!(csp.contains("font-src https://cdn.jsdelivr.net"));

    assert_eq!(
        extract_response_header(
            &challenge.headers,
            http::header::HeaderName::from_static("cross-origin-resource-policy"),
        ),
        "same-origin"
    );
    assert_eq!(
        extract_response_header(
            &challenge.headers,
            http::header::HeaderName::from_static("access-control-allow-origin"),
        ),
        "https://example.com"
    );

    let token = extract_person_proof_token(&challenge.body);
    let nonce = solve_pow_nonce(&token, 4);
    let mut solved_headers = HeaderMap::new();
    solved_headers.insert(
        http::header::COOKIE,
        HeaderValue::from_str(&format!("__test_person_proof={token}.{nonce}")).unwrap(),
    );

    let solved_decision = engine.evaluate_request(request_input(
        &method,
        &uri,
        &solved_headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ));

    assert!(solved_decision.terminal.is_none());
    assert_eq!(
        solved_decision.tags,
        vec![("PersonProof".to_string(), "valid".to_string())]
    );
    let clearance_cookie = extract_set_cookie(&solved_decision.response_header_mutations);
    assert!(clearance_cookie.contains("__test_person_proof=clearance.v1."));
    assert!(clearance_cookie.contains("HttpOnly"));

    let clearance_value = clearance_cookie
        .split_once('=')
        .and_then(|(_, value)| value.split_once(';'))
        .map(|(value, _)| value)
        .expect("clearance cookie should contain a value");
    let mut clearance_headers = HeaderMap::new();
    clearance_headers.insert(
        http::header::COOKIE,
        HeaderValue::from_str(&format!("__test_person_proof={clearance_value}")).unwrap(),
    );
    let clearance_decision = engine.evaluate_request(request_input(
        &method,
        &uri,
        &clearance_headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ));

    assert!(clearance_decision.terminal.is_none());
    assert!(clearance_decision.response_header_mutations.is_empty());
}

#[test]
fn person_proof_success_tag_can_chain_to_later_request_rule() {
    let temp_dir = common::TempDir::new("waf-person-proof-chain");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-person-proof-chain");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "require-person-proof"
phase = "request"
priority = 10
when = "Request.Client.PersonProof.State != 'valid'"

[[waf.rules.actions]]
type = "require_person_proof"
difficulty = 4
token_validity_seconds = 60
cookie = "__test_person_proof"
success_tag = "PersonProof"

[[waf.rules]]
name = "mark-person-proof"
phase = "request"
priority = 20
when = "Request.Tags.get('PersonProof') == 'valid'"

[[waf.rules.actions]]
type = "set_request_header"
name = "X-Person-Proof"
value = "valid"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = "/protected".parse().expect("URI should parse");
    let challenge_decision = engine.evaluate_request(request_input(
        &method,
        &uri,
        &headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ));
    let token = extract_person_proof_token(&challenge_decision.terminal.unwrap().body);
    let nonce = solve_pow_nonce(&token, 4);

    let mut solved_headers = HeaderMap::new();
    solved_headers.insert(
        http::header::COOKIE,
        HeaderValue::from_str(&format!("__test_person_proof={token}.{nonce}")).unwrap(),
    );
    let solved_decision = engine.evaluate_request(request_input(
        &method,
        &uri,
        &solved_headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ));

    assert!(solved_decision.terminal.is_none());
    assert_eq!(
        solved_decision.tags,
        vec![("PersonProof".to_string(), "valid".to_string())]
    );
    assert!(
        solved_decision
            .request_header_mutations
            .iter()
            .any(|mutation| matches!(
                mutation,
                HeaderMutation::Set { name, value }
                    if name.as_str() == "x-person-proof" && value.as_bytes() == b"valid"
            ))
    );
}

#[test]
fn person_proof_challenge_rejects_invalid_pow() {
    let temp_dir = common::TempDir::new("waf-person-proof-invalid");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-person-proof-invalid");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "require-person-proof"
phase = "request"
priority = 10
when = "Request.Client.PersonProof.State != 'valid'"

[[waf.rules.actions]]
type = "require_person_proof"
difficulty = 4
token_validity_seconds = 60
cookie = "__test_person_proof"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = "/protected".parse().expect("URI should parse");
    let challenge_decision = engine.evaluate_request(request_input(
        &method,
        &uri,
        &headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ));
    let token = extract_person_proof_token(&challenge_decision.terminal.unwrap().body);

    let mut invalid_headers = HeaderMap::new();
    invalid_headers.insert(
        http::header::COOKIE,
        HeaderValue::from_str(&format!(
            "__test_person_proof={token}.{}",
            unsolved_pow_nonce(&token, 4)
        ))
        .unwrap(),
    );

    let invalid_decision = engine.evaluate_request(request_input(
        &method,
        &uri,
        &invalid_headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ));

    assert_eq!(
        invalid_decision
            .terminal
            .as_ref()
            .map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );
}

#[test]
fn person_proof_token_bindings_can_use_client_network() {
    let temp_dir = common::TempDir::new("waf-person-proof-network-binding");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-person-proof-network-binding");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "require-person-proof"
phase = "request"
priority = 10
when = "Request.Client.PersonProof.State != 'valid'"

[[waf.rules.actions]]
type = "require_person_proof"
difficulty = 4
token_validity_seconds = 60
cookie = "__test_person_proof"
token_bindings = ["user_agent", "route", "direct_peer_ip_network_prefix"]
direct_peer_ipv4_prefix_bits = 24
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = "/protected".parse().expect("URI should parse");
    let challenge_decision = engine.evaluate_request(request_input(
        &method,
        &uri,
        &headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ));
    let token = extract_person_proof_token(&challenge_decision.terminal.unwrap().body);
    let nonce = solve_pow_nonce(&token, 4);
    let mut solved_headers = HeaderMap::new();
    solved_headers.insert(
        http::header::COOKIE,
        HeaderValue::from_str(&format!("__test_person_proof={token}.{nonce}")).unwrap(),
    );

    let different_network_decision = engine.evaluate_request(request_input(
        &method,
        &uri,
        &solved_headers,
        &tags,
        "198.51.100.10:49152".parse().unwrap(),
    ));

    assert_eq!(
        different_network_decision
            .terminal
            .as_ref()
            .map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );

    let same_network_decision = engine.evaluate_request(request_input(
        &method,
        &uri,
        &solved_headers,
        &tags,
        "203.0.113.42:49152".parse().unwrap(),
    ));

    assert!(same_network_decision.terminal.is_none());
}

#[test]
fn person_proof_token_bindings_can_use_tls_fingerprint() {
    let temp_dir = common::TempDir::new("waf-person-proof-tls-binding");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-person-proof-tls-binding");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "require-person-proof"
phase = "request"
priority = 10
when = "Request.Client.PersonProof.State != 'valid'"

[[waf.rules.actions]]
type = "require_person_proof"
difficulty = 4
token_validity_seconds = 60
cookie = "__test_person_proof"
token_bindings = ["tls_fingerprint"]
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let browser_tls = test_tls("browser-fingerprint");
    let automation_tls = test_tls("automation-fingerprint");
    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = "/protected".parse().expect("URI should parse");
    let client_addr: SocketAddr = "203.0.113.10:49152".parse().unwrap();
    let challenge_decision = engine.evaluate_request(request_input_with_tls(
        &method,
        &uri,
        &headers,
        &tags,
        client_addr,
        &browser_tls,
    ));
    let token = extract_person_proof_token(&challenge_decision.terminal.unwrap().body);
    let nonce = solve_pow_nonce(&token, 4);
    let mut solved_headers = HeaderMap::new();
    solved_headers.insert(
        http::header::COOKIE,
        HeaderValue::from_str(&format!("__test_person_proof={token}.{nonce}")).unwrap(),
    );

    let automation_decision = engine.evaluate_request(request_input_with_tls(
        &method,
        &uri,
        &solved_headers,
        &tags,
        client_addr,
        &automation_tls,
    ));
    assert_eq!(
        automation_decision
            .terminal
            .as_ref()
            .map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );

    let browser_decision = engine.evaluate_request(request_input_with_tls(
        &method,
        &uri,
        &solved_headers,
        &tags,
        client_addr,
        &browser_tls,
    ));
    assert!(browser_decision.terminal.is_none());
}

#[test]
fn person_proof_token_bindings_can_use_tcp_max_hop() {
    let temp_dir = common::TempDir::new("waf-person-proof-tcp-hop-binding");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-person-proof-tcp-hop-binding");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "require-person-proof"
phase = "request"
priority = 10
when = "Request.Client.PersonProof.State != 'valid'"

[[waf.rules.actions]]
type = "require_person_proof"
difficulty = 4
token_validity_seconds = 60
cookie = "__test_person_proof"
token_bindings = ["tcp_max_hop"]
tcp_max_hop = 16
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");
    assert_eq!(engine.person_proof_tcp_max_hop(), Some(16));

    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = "/protected".parse().expect("URI should parse");
    let client_addr: SocketAddr = "203.0.113.10:49152".parse().unwrap();
    let challenge_decision = engine.evaluate_request(request_input_with_tcp_max_hop(
        &method,
        &uri,
        &headers,
        &tags,
        client_addr,
        16,
    ));
    let token = extract_person_proof_token(&challenge_decision.terminal.unwrap().body);
    let nonce = solve_pow_nonce(&token, 4);
    let mut solved_headers = HeaderMap::new();
    solved_headers.insert(
        http::header::COOKIE,
        HeaderValue::from_str(&format!("__test_person_proof={token}.{nonce}")).unwrap(),
    );

    let different_hop_decision = engine.evaluate_request(request_input_with_tcp_max_hop(
        &method,
        &uri,
        &solved_headers,
        &tags,
        client_addr,
        32,
    ));
    assert_eq!(
        different_hop_decision
            .terminal
            .as_ref()
            .map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );

    let same_hop_decision = engine.evaluate_request(request_input_with_tcp_max_hop(
        &method,
        &uri,
        &solved_headers,
        &tags,
        client_addr,
        16,
    ));
    assert!(same_hop_decision.terminal.is_none());
}

#[test]
fn disabled_waf_does_not_apply_person_proof_tcp_max_hop() {
    let temp_dir = common::TempDir::new("waf-disabled-tcp-hop");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-disabled-tcp-hop");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = false

[[waf.rules]]
name = "disabled-person-proof"
phase = "request"
priority = 10
when = "Request.Client.PersonProof.State != 'valid'"

[[waf.rules.actions]]
type = "require_person_proof"
token_bindings = ["tcp_max_hop"]
tcp_max_hop = 16
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    assert_eq!(engine.person_proof_tcp_max_hop(), None);
}

#[test]
fn person_proof_single_use_bindings_rotate_clearance() {
    let temp_dir = common::TempDir::new("waf-person-proof-single-use");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-person-proof-single-use");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "require-person-proof"
phase = "request"
priority = 10
when = "Request.Client.PersonProof.State != 'valid'"

[[waf.rules.actions]]
type = "require_person_proof"
difficulty = 4
token_validity_seconds = 60
cookie = "__test_person_proof"
token_bindings = ["user_agent", "route", "direct_peer_ip_network_prefix"]
direct_peer_ipv4_prefix_bits = 32
single_use = true
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = "/protected".parse().expect("URI should parse");
    let client_addr: SocketAddr = "203.0.113.10:49152".parse().unwrap();
    let challenge_decision =
        engine.evaluate_request(request_input(&method, &uri, &headers, &tags, client_addr));
    let token = extract_person_proof_token(&challenge_decision.terminal.unwrap().body);
    let nonce = solve_pow_nonce(&token, 4);
    let mut solved_headers = HeaderMap::new();
    solved_headers.insert(
        http::header::COOKIE,
        HeaderValue::from_str(&format!("__test_person_proof={token}.{nonce}")).unwrap(),
    );

    let different_client_decision = engine.evaluate_request(request_input(
        &method,
        &uri,
        &solved_headers,
        &tags,
        "203.0.113.11:49152".parse().unwrap(),
    ));
    assert_eq!(
        different_client_decision
            .terminal
            .as_ref()
            .map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );

    let solved_decision = engine.evaluate_request(request_input(
        &method,
        &uri,
        &solved_headers,
        &tags,
        client_addr,
    ));
    assert!(solved_decision.terminal.is_none());
    let initial_clearance = extract_cookie_value(&extract_set_cookie(
        &solved_decision.response_header_mutations,
    ));
    let mut clearance_headers = HeaderMap::new();
    clearance_headers.insert(
        http::header::COOKIE,
        HeaderValue::from_str(&format!("__test_person_proof={initial_clearance}")).unwrap(),
    );

    let clearance_decision = engine.evaluate_request(request_input(
        &method,
        &uri,
        &clearance_headers,
        &tags,
        client_addr,
    ));
    assert!(clearance_decision.terminal.is_none());
    let rotated_clearance = extract_cookie_value(&extract_set_cookie(
        &clearance_decision.response_header_mutations,
    ));
    assert_ne!(initial_clearance, rotated_clearance);

    let replay_decision = engine.evaluate_request(request_input(
        &method,
        &uri,
        &clearance_headers,
        &tags,
        client_addr,
    ));
    assert_eq!(
        replay_decision
            .terminal
            .as_ref()
            .map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );

    let mut rotated_headers = HeaderMap::new();
    rotated_headers.insert(
        http::header::COOKIE,
        HeaderValue::from_str(&format!("__test_person_proof={rotated_clearance}")).unwrap(),
    );
    let rotated_from_different_client = engine.evaluate_request(request_input(
        &method,
        &uri,
        &rotated_headers,
        &tags,
        "203.0.113.11:49152".parse().unwrap(),
    ));
    assert_eq!(
        rotated_from_different_client
            .terminal
            .as_ref()
            .map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );
}

#[test]
fn external_rule_files_are_loaded_from_oxirule_directory() {
    let temp_dir = common::TempDir::new("waf-external");
    let config_dir = temp_dir.path().join("config");
    let cert_dir = temp_dir.path().join("cert");
    let rules_dir = temp_dir.path().join("oxirule").join("rules");
    std::fs::create_dir_all(&config_dir).expect("failed to create config directory");
    std::fs::create_dir_all(&cert_dir).expect("failed to create cert directory");
    std::fs::create_dir_all(&rules_dir).expect("failed to create rules directory");
    let (cert_path, key_path) = common::create_self_signed_cert(&cert_dir, "waf-external");
    std::fs::write(
        rules_dir.join("global-request.oxirule.toml"),
        r#"
when = "Request.Headers.anyValueContains('sqlmap')"

[[actions]]
type = "reject"
status = 403
body = "Blocked by WAF"
"#,
    )
    .expect("failed to write global WAF rule");

    let config_path = config_dir.join("oxibelt.toml");
    std::fs::write(
        &config_path,
        format!(
            "{}\n{}",
            common::minimal_config_toml_with_paths(
                &cert_path.file_name().unwrap().to_string_lossy(),
                &key_path.file_name().unwrap().to_string_lossy(),
            ),
            r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "global-request-policy"
phase = "request"
priority = 10
path = "rules/global-request.oxirule.toml"
"#
        ),
    )
    .expect("failed to write config");

    let config = Config::load(&config_path).expect("config should load external rule");
    config.validate().expect("config should validate");

    let engine = WafEngine::new(&config).expect("WAF should compile");
    let mut headers = HeaderMap::new();
    headers.insert("user-agent", HeaderValue::from_static("sqlmap"));
    let tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = "/".parse().expect("URI should parse");

    let decision = engine.evaluate_request(request_input(
        &method,
        &uri,
        &headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ));

    assert_eq!(
        decision.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );
}

#[test]
fn external_rule_paths_must_stay_in_oxirule_directory() {
    let temp_dir = common::TempDir::new("waf-path-escape");
    let config_dir = temp_dir.path().join("config");
    let cert_dir = temp_dir.path().join("cert");
    std::fs::create_dir_all(&config_dir).expect("failed to create config directory");
    std::fs::create_dir_all(&cert_dir).expect("failed to create cert directory");
    let (cert_path, key_path) = common::create_self_signed_cert(&cert_dir, "waf-path-escape");
    std::fs::write(
        temp_dir.path().join("outside.oxirule.toml"),
        r#"
when = "Request.Http.Path == '/'"

[[actions]]
type = "reject"
status = 403
"#,
    )
    .expect("failed to write outside WAF rule");

    let config_path = config_dir.join("oxibelt.toml");
    std::fs::write(
        &config_path,
        format!(
            "{}\n{}",
            common::minimal_config_toml_with_paths(
                &cert_path.file_name().unwrap().to_string_lossy(),
                &key_path.file_name().unwrap().to_string_lossy(),
            ),
            r#"
[waf]
enabled = true

[[waf.rules]]
name = "escaped-rule"
phase = "request"
priority = 10
path = "../outside.oxirule.toml"
"#
        ),
    )
    .expect("failed to write config");

    let error = Config::load(&config_path).expect_err("path escape should be rejected");

    assert!(
        error.to_string().contains("WAF rule path must not contain"),
        "unexpected error: {error}"
    );
}

#[test]
fn rule_id_and_tags_are_available_in_context() {
    let temp_dir = common::TempDir::new("waf-rule-metadata");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-rule-metadata");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true

[[waf.rules]]
name = "metadata-rule"
id = "proof-chain"
tags = ["person-proof", "chain"]
phase = "request"
priority = 1
when = "Context.RuleId == 'proof-chain' && Context.RuleTags.has('person-proof')"

[[waf.rules.actions]]
type = "reject"
status = 403
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = "/".parse().expect("URI should parse");
    let decision = engine.evaluate_request(request_input(
        &method,
        &uri,
        &headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ));

    assert_eq!(
        decision.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );
}

#[test]
fn validation_rejects_invalid_rule_metadata_label() {
    let temp_dir = common::TempDir::new("waf-invalid-rule-metadata");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-invalid-rule-metadata");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true

[[waf.rules]]
name = "bad-metadata-rule"
id = "bad_rule"
phase = "request"
priority = 1
when = "true"

[[waf.rules.actions]]
type = "reject"
status = 403
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config.validate().expect_err("validation should fail");
    assert!(
        error
            .to_string()
            .contains("id must match [A-Za-z0-9-]{0,32}"),
        "unexpected error: {error}"
    );
}

#[test]
fn validation_rejects_response_access_in_request_phase() {
    let temp_dir = common::TempDir::new("waf-invalid");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "waf-invalid");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true

[[waf.rules]]
name = "bad-request-rule"
phase = "request"
priority = 1
when = "Response.Http.Status >= 500"

[[waf.rules.actions]]
type = "reject"
status = 403
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config.validate().expect_err("validation should fail");
    let error_chain = format!("{error:#}");
    assert!(
        error_chain.contains("Response is unavailable"),
        "unexpected error: {error}"
    );
}

#[test]
fn validation_rejects_unsafe_person_proof_difficulty() {
    let temp_dir = common::TempDir::new("waf-person-proof-invalid-config");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-person-proof-invalid-config");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true

[[waf.rules]]
name = "bad-person-proof"
phase = "request"
priority = 1
when = "Request.Client.PersonProof.State != 'valid'"

[[waf.rules.actions]]
type = "require_person_proof"
difficulty = 31
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config.validate().expect_err("validation should fail");
    assert!(
        error
            .to_string()
            .contains("require_person_proof difficulty"),
        "unexpected error: {error}"
    );
}

#[test]
fn validation_requires_tcp_max_hop_value_for_tcp_max_hop_person_proof_binding() {
    let temp_dir = common::TempDir::new("waf-person-proof-tcp-hop-config");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-person-proof-tcp-hop-config");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true

[[waf.rules]]
name = "bad-person-proof-binding"
phase = "request"
priority = 1
when = "Request.Client.PersonProof.State != 'valid'"

[[waf.rules.actions]]
type = "require_person_proof"
token_bindings = ["tcp_max_hop"]
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config.validate().expect_err("validation should fail");
    assert!(
        error.to_string().contains("requires tcp_max_hop"),
        "unexpected error: {error}"
    );
}

fn request_input<'a>(
    method: &'a Method,
    uri: &'a Uri,
    headers: &'a HeaderMap,
    tags: &'a HashMap<String, String>,
    peer_addr: SocketAddr,
) -> WafRequestInput<'a> {
    static TEST_TLS: WafTlsMetadata = WafTlsMetadata {
        enabled: true,
        version: None,
        cipher_suite: None,
        sni: None,
        alpn: None,
        fingerprint: None,
        fingerprint_scheme: None,
    };

    request_input_with_transport(method, uri, headers, tags, peer_addr, None, &TEST_TLS)
}

fn request_input_with_body<'a>(
    method: &'a Method,
    uri: &'a Uri,
    headers: &'a HeaderMap,
    tags: &'a HashMap<String, String>,
    peer_addr: SocketAddr,
    body: &'a [u8],
    is_truncated: bool,
) -> WafRequestInput<'a> {
    let mut input = request_input(method, uri, headers, tags, peer_addr);
    input.body = Some(WafBodyInput {
        bytes: body,
        is_truncated,
    });
    input
}

fn request_input_with_tls<'a>(
    method: &'a Method,
    uri: &'a Uri,
    headers: &'a HeaderMap,
    tags: &'a HashMap<String, String>,
    peer_addr: SocketAddr,
    tls: &'a WafTlsMetadata,
) -> WafRequestInput<'a> {
    request_input_with_transport(method, uri, headers, tags, peer_addr, None, tls)
}

fn request_input_with_tcp_max_hop<'a>(
    method: &'a Method,
    uri: &'a Uri,
    headers: &'a HeaderMap,
    tags: &'a HashMap<String, String>,
    peer_addr: SocketAddr,
    tcp_max_hop: u8,
) -> WafRequestInput<'a> {
    static TEST_TLS: WafTlsMetadata = WafTlsMetadata {
        enabled: true,
        version: None,
        cipher_suite: None,
        sni: None,
        alpn: None,
        fingerprint: None,
        fingerprint_scheme: None,
    };

    request_input_with_transport(
        method,
        uri,
        headers,
        tags,
        peer_addr,
        Some(tcp_max_hop),
        &TEST_TLS,
    )
}

fn request_input_with_transport<'a>(
    method: &'a Method,
    uri: &'a Uri,
    headers: &'a HeaderMap,
    tags: &'a HashMap<String, String>,
    peer_addr: SocketAddr,
    tcp_max_hop: Option<u8>,
    tls: &'a WafTlsMetadata,
) -> WafRequestInput<'a> {
    WafRequestInput {
        method,
        uri,
        version: http::Version::HTTP_11,
        headers,
        body: None,
        peer_addr,
        downstream_host: "example.com",
        route_name: "app-root",
        tcp_max_hop,
        tls,
        protocol: WafProtocol::Http,
        transport_network: WafTransportNetwork::Tcp,
        tags,
    }
}

#[allow(clippy::too_many_arguments)]
fn request_input_with_protocol_and_network<'a>(
    method: &'a Method,
    uri: &'a Uri,
    headers: &'a HeaderMap,
    tags: &'a HashMap<String, String>,
    peer_addr: SocketAddr,
    tls: &'a WafTlsMetadata,
    protocol: WafProtocol,
    transport_network: WafTransportNetwork,
) -> WafRequestInput<'a> {
    WafRequestInput {
        method,
        uri,
        version: http::Version::HTTP_3,
        headers,
        body: None,
        peer_addr,
        downstream_host: "example.com",
        route_name: "app-root",
        tcp_max_hop: None,
        tls,
        protocol,
        transport_network,
        tags,
    }
}

fn test_tls(fingerprint: &str) -> WafTlsMetadata {
    WafTlsMetadata {
        enabled: true,
        version: Some("TLSv1_3".to_string()),
        cipher_suite: Some("TLS13_AES_128_GCM_SHA256".to_string()),
        sni: Some("example.com".to_string()),
        alpn: Some("h2".to_string()),
        fingerprint: Some(fingerprint.to_string()),
        fingerprint_scheme: Some("rustls-tcp-negotiated-v2".to_string()),
    }
}

fn extract_person_proof_token(body: &str) -> String {
    let marker = "name=\"oxibelt-person-proof-token\" content=\"";
    let start = body
        .find(marker)
        .map(|index| index + marker.len())
        .expect("challenge token marker should exist");
    let end = body[start..]
        .find('"')
        .map(|index| start + index)
        .expect("challenge token should be quoted");
    body[start..end].to_string()
}

fn solve_pow_nonce(token: &str, difficulty: u8) -> u64 {
    for nonce in 0u64.. {
        let input = format!("{token}.{nonce}");
        let hash = digest::digest(&digest::SHA256, input.as_bytes());
        if leading_zero_bits(hash.as_ref()) >= u32::from(difficulty) {
            return nonce;
        }
    }
    unreachable!("u64 nonce space should be sufficient for test difficulty")
}

fn unsolved_pow_nonce(token: &str, difficulty: u8) -> u64 {
    for nonce in 0u64.. {
        let input = format!("{token}.{nonce}");
        let hash = digest::digest(&digest::SHA256, input.as_bytes());
        if leading_zero_bits(hash.as_ref()) < u32::from(difficulty) {
            return nonce;
        }
    }
    unreachable!("u64 nonce space should contain an unsolved test nonce")
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut total = 0u32;
    for byte in bytes {
        if *byte == 0 {
            total += 8;
        } else {
            total += byte.leading_zeros();
            break;
        }
    }
    total
}

fn extract_set_cookie(mutations: &[HeaderMutation]) -> String {
    mutations
        .iter()
        .find_map(|mutation| match mutation {
            HeaderMutation::Append { name, value } | HeaderMutation::Set { name, value }
                if name == http::header::SET_COOKIE =>
            {
                value.to_str().ok().map(str::to_string)
            }
            _ => None,
        })
        .expect("Set-Cookie mutation should exist")
}

fn extract_cookie_value(set_cookie: &str) -> String {
    set_cookie
        .split_once('=')
        .and_then(|(_, value)| value.split_once(';'))
        .map(|(value, _)| value.to_string())
        .expect("Set-Cookie header should contain a cookie value")
}

fn extract_response_header(
    mutations: &[HeaderMutation],
    expected_name: http::HeaderName,
) -> String {
    mutations
        .iter()
        .find_map(|mutation| match mutation {
            HeaderMutation::Append { name, value } | HeaderMutation::Set { name, value }
                if name == expected_name =>
            {
                value.to_str().ok().map(str::to_string)
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("{} header should exist", expected_name))
}

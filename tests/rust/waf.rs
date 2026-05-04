#[path = "common/mod.rs"]
mod common;

use std::collections::HashMap;
use std::net::SocketAddr;

use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use oxibelt::config::Config;
use oxibelt::waf::{WafEngine, WafProtocol, WafRequestInput, WafResponseInput};

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

fn request_input<'a>(
    method: &'a Method,
    uri: &'a Uri,
    headers: &'a HeaderMap,
    tags: &'a HashMap<String, String>,
    peer_addr: SocketAddr,
) -> WafRequestInput<'a> {
    WafRequestInput {
        method,
        uri,
        version: http::Version::HTTP_11,
        headers,
        peer_addr,
        downstream_host: "example.com",
        route_name: "app-root",
        protocol: WafProtocol::Http,
        tags,
    }
}

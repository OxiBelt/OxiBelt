#[path = "common/mod.rs"]
mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::OnceLock;

use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use oxibelt::config::Config;
use oxibelt::dynamic_policy::DynamicPolicyContext;
use oxibelt::waf::{
    BodyNeed, HeaderMutation, WafBodyInput, WafEngine, WafProtocol, WafRequestInput,
    WafResponseInput, WafStreamDirection, WafStreamInput, WafStreamProtocol, WafStreamUnit,
    WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork, WafWebSocketStreamMetadata,
    WafWebTransportStreamKind, WafWebTransportStreamMetadata, compile_access_log_fields,
    crs_compatibility_matrix,
};
use ring::digest;

static TEST_DYNAMIC_POLICY: OnceLock<DynamicPolicyContext> = OnceLock::new();

fn test_dynamic_policy() -> &'static DynamicPolicyContext {
    TEST_DYNAMIC_POLICY.get_or_init(DynamicPolicyContext::default)
}

#[test]
fn rule_monitor_mode_overrides_global_enforcing_and_counts_hit() {
    let temp_dir = common::TempDir::new("waf-rule-monitor-mode");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-rule-monitor-mode");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"

[[waf.rules]]
name = "shadow-block"
id = "shadow-block"
mode = "monitor"
phase = "request"
priority = 10
when = "Context.Mode == 'monitor'"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "would block"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let decision = evaluate_simple_request(&engine, "/shadow");

    assert!(decision.terminal.is_none());
    let hit = only_rule_hit(&engine);
    assert_eq!(hit.name, "shadow-block");
    assert_eq!(hit.id.as_deref(), Some("shadow-block"));
    assert_eq!(hit.effective_mode, "monitor");
    assert_eq!(hit.hits, 1);
}

#[test]
fn rule_enforcing_mode_overrides_global_monitor_and_counts_hit() {
    let temp_dir = common::TempDir::new("waf-rule-enforcing-mode");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-rule-enforcing-mode");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "monitor"

[[waf.rules]]
name = "enforced-block"
id = "enforced-block"
mode = "enforcing"
phase = "request"
priority = 10
when = "Context.Mode == 'enforcing'"

[[waf.rules.actions]]
type = "reject"
status = 451
body = "blocked"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let decision = evaluate_simple_request(&engine, "/enforced");

    assert_eq!(
        decision.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS)
    );
    let hit = only_rule_hit(&engine);
    assert_eq!(hit.effective_mode, "enforcing");
    assert_eq!(hit.hits, 1);
}

#[test]
fn route_level_rate_limit_action_blocks_second_matching_request() {
    let temp_dir = common::TempDir::new("waf-rate-limit-action");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-rate-limit-action");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"

[[routes.waf.rules]]
name = "route-rate-limit"
phase = "request"
priority = 10
when = "Request.Http.Path.startsWith('/login')"

[[routes.waf.rules.actions]]
type = "rate_limit"
name = "login-token-limit"
key = "access_token_route"
token_header = "X-Api-Token"
rate = "1r/h"
burst = 1
status = 429
body = "slow down"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");
    let mut headers = HeaderMap::new();
    headers.insert("authorization", HeaderValue::from_static("Bearer token-a"));
    let tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = "/login".parse().expect("URI should parse");

    let first = engine.evaluate_request(request_input(
        &method,
        &uri,
        &headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ));
    let second = engine.evaluate_request(request_input(
        &method,
        &uri,
        &headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ));

    assert!(first.terminal.is_none());
    assert_eq!(
        second.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::TOO_MANY_REQUESTS)
    );
    assert_eq!(
        second
            .terminal
            .as_ref()
            .map(|terminal| terminal.body.as_str()),
        Some("slow down")
    );
}

#[test]
fn user_defined_functions_can_reuse_bounded_request_predicates() {
    let temp_dir = common::TempDir::new("waf-udf-request");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "waf-udf");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"

[[waf.functions]]
name = "lower_contains"
params = ["value", "needle"]
expression = "value.lowerAscii().contains(needle)"

[[waf.functions]]
name = "blocked_path"
params = ["path"]
expression = "lower_contains(path, '/admin')"

[[waf.rules]]
name = "block-admin"
phase = "request"
priority = 10
when = "blocked_path(Request.Http.Path)"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "blocked"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let decision = evaluate_simple_request(&engine, "/ADMIN/panel");

    assert_eq!(
        decision.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );
}

#[test]
fn route_udf_overrides_global_for_route_rules_only() {
    let temp_dir = common::TempDir::new("waf-udf-route-override");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-udf-route-override");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"

[[waf.functions]]
name = "is_bad_path"
params = ["path"]
expression = "path.startsWith('/global')"

[[waf.rules]]
name = "global-block"
phase = "request"
priority = 10
when = "is_bad_path(Request.Http.Path)"

[[waf.rules.actions]]
type = "reject"
status = 451
body = "global"

[[routes.waf.functions]]
name = "is_bad_path"
params = ["path"]
expression = "path.startsWith('/route')"

[[routes.waf.rules]]
name = "route-block"
phase = "request"
priority = 20
when = "is_bad_path(Request.Http.Path)"

[[routes.waf.rules.actions]]
type = "reject"
status = 409
body = "route"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let route_decision = evaluate_simple_request(&engine, "/route-only");
    let global_decision = evaluate_simple_request(&engine, "/global-only");

    assert_eq!(
        route_decision
            .terminal
            .as_ref()
            .map(|terminal| terminal.status),
        Some(StatusCode::CONFLICT)
    );
    assert_eq!(
        route_decision
            .terminal
            .as_ref()
            .map(|terminal| terminal.body.as_str()),
        Some("route")
    );
    assert_eq!(
        global_decision
            .terminal
            .as_ref()
            .map(|terminal| terminal.status),
        Some(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS)
    );
    assert_eq!(
        global_decision
            .terminal
            .as_ref()
            .map(|terminal| terminal.body.as_str()),
        Some("global")
    );
}

#[test]
fn global_udf_body_keeps_global_resolution_inside_route_rules() {
    let temp_dir = common::TempDir::new("waf-udf-lexical-global");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-udf-lexical-global");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"

[[waf.functions]]
name = "is_bad_path"
params = ["path"]
expression = "path.startsWith('/global')"

[[waf.functions]]
name = "is_global_bad_path"
params = ["path"]
expression = "is_bad_path(path)"

[[routes.waf.functions]]
name = "is_bad_path"
params = ["path"]
expression = "path.startsWith('/route')"

[[routes.waf.rules]]
name = "route-calls-global"
phase = "request"
priority = 10
when = "is_global_bad_path(Request.Http.Path)"

[[routes.waf.rules.actions]]
type = "reject"
status = 403
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let route_decision = evaluate_simple_request(&engine, "/route-only");
    let global_decision = evaluate_simple_request(&engine, "/global-only");

    assert!(route_decision.terminal.is_none());
    assert_eq!(
        global_decision
            .terminal
            .as_ref()
            .map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );
}

#[test]
fn waf_access_log_fields_can_call_udfs() {
    let temp_dir = common::TempDir::new("waf-udf-access-log");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-udf-access-log");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"

[[waf.functions]]
name = "is_created"
params = ["status"]
expression = "status == 201"

[[waf.rules]]
name = "log-created"
phase = "response"
priority = 10
when = "is_created(Response.Http.Status)"

[[waf.rules.actions]]
type = "emit_access_log"

[[waf.rules.actions.fields]]
name = "created"
value = "is_created(Response.Http.Status)"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");
    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = "/created".parse().expect("URI should parse");

    let response_decision = engine.evaluate_response(WafResponseInput {
        request: request_input(
            &method,
            &uri,
            &headers,
            &tags,
            "203.0.113.10:49152".parse().unwrap(),
        ),
        response_id: "test-response-id",
        received_at_unix_ms: 1_700_000_000_123,
        version: http::Version::HTTP_11,
        status: StatusCode::CREATED,
        headers: &headers,
        body: None,
        upstream_name: "app",
        upstream_pool: None,
        upstream_scheme: "http",
        upstream_connect_time_ms: None,
        upstream_first_byte_time_ms: None,
        upstream_error: None,
    });

    assert_eq!(response_decision.access_logs.len(), 1);
    assert!(
        response_decision.access_logs[0]
            .to_json_line()
            .contains("\"created\":true")
    );
}

#[test]
fn system_access_log_fields_reject_udf_calls() {
    let temp_dir = common::TempDir::new("system-access-log-udf-reject");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "system-access-log-udf-reject");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true

[[waf.functions]]
name = "is_created"
params = ["status"]
expression = "status == 201"

[logging.access_log]
enabled = true
fields = [
  { name = "created", value = "is_created(Response.Http.Status)" },
]
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config.validate().expect_err("validation should fail");
    assert!(
        format!("{error:#}").contains("unknown OxiRule function is_created"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn external_rule_files_cannot_define_udfs() {
    let temp_dir = common::TempDir::new("external-rule-udf-reject");
    let config_dir = temp_dir.path().join("config");
    let cert_dir = temp_dir.path().join("cert");
    let rules_dir = temp_dir.path().join("oxirule").join("rules");
    std::fs::create_dir_all(&config_dir).expect("config dir should be created");
    std::fs::create_dir_all(&cert_dir).expect("cert dir should be created");
    std::fs::create_dir_all(&rules_dir).expect("rules dir should be created");
    let (cert_path, key_path) = common::create_self_signed_cert(&cert_dir, "external-rule-udf");
    let raw = format!(
        r#"{}

[waf]
enabled = true

[[waf.rules]]
name = "external"
phase = "request"
priority = 10
path = "rules/external.oxirule.toml"
"#,
        common::minimal_config_toml_with_paths(
            cert_path.file_name().unwrap().to_str().unwrap(),
            key_path.file_name().unwrap().to_str().unwrap(),
        )
    );
    std::fs::write(
        rules_dir.join("external.oxirule.toml"),
        r#"
when = "true"

[[functions]]
name = "bad"
expression = "true"

[[actions]]
type = "reject"
status = 403
"#,
    )
    .expect("external rule should be written");
    let config_path = config_dir.join("oxibelt.toml");
    std::fs::write(&config_path, raw).expect("config should be written");

    let error = Config::load(&config_path).expect_err("config load should reject functions");
    assert!(
        format!("{error:#}").contains("unknown field `functions`"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn udf_phase_validation_happens_at_call_site() {
    for (name, phase, expression, expected) in [
        (
            "request-calls-response",
            "request",
            "response_is_error()",
            "Response is unavailable",
        ),
        (
            "response-calls-stream",
            "response",
            "stream_has_payload()",
            "Stream is available only in stream-phase rules",
        ),
        (
            "stream-calls-request-body",
            "stream",
            "request_body_has_secret()",
            "Request.Body is unavailable",
        ),
    ] {
        let temp_dir = common::TempDir::new(name);
        let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), name);
        let action = if phase == "stream" {
            r#"type = "close_stream""#
        } else if phase == "response" {
            r#"type = "continue_response""#
        } else {
            r#"type = "reject"
status = 403"#
        };
        let base_config = common::minimal_config_toml(&cert_path, &key_path);
        let raw = format!(
            r#"{base_config}

[waf]
enabled = true

[[waf.functions]]
name = "response_is_error"
expression = "Response.Http.Status >= 500"

[[waf.functions]]
name = "stream_has_payload"
expression = "Stream.Payload.contains('secret')"

[[waf.functions]]
name = "request_body_has_secret"
expression = "Request.Body.contains('secret')"

[[waf.rules]]
name = "{name}"
phase = "{phase}"
priority = 10
when = "{expression}"

[[waf.rules.actions]]
{action}
"#
        );

        let config: Config = toml::from_str(&raw).expect("config should parse");
        let error = config.validate().expect_err("validation should fail");
        let error_chain = format!("{error:#}");
        assert!(
            error_chain.contains(expected),
            "unexpected error for {name}: {error_chain}"
        );
    }
}

#[test]
fn response_phase_can_call_response_udf() {
    let temp_dir = common::TempDir::new("waf-udf-response-phase");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-udf-response-phase");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"

[[waf.functions]]
name = "response_is_error"
expression = "Response.Http.Status >= 500"

[[waf.rules]]
name = "reject-error"
phase = "response"
priority = 10
when = "response_is_error()"

[[waf.rules.actions]]
type = "reject_response"
status = 502
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
}

#[test]
fn udf_body_object_params_trigger_request_and_response_body_inspection() {
    let temp_dir = common::TempDir::new("waf-udf-body-object-params");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-udf-body-object-params");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.pattern_sets]]
name = "blocked-bodies"
kind = "contains"
patterns = ["blocked"]

[[waf.pattern_sets]]
name = "leak-bodies"
kind = "contains"
patterns = ["leak"]

[[waf.functions]]
name = "body_has_blocked"
params = ["body"]
expression = "body.containsAny('blocked-bodies')"

[[waf.functions]]
name = "nested_body_has_blocked"
params = ["payload"]
expression = "body_has_blocked(payload)"

[[waf.functions]]
name = "body_has_leak"
params = ["body"]
expression = "body.containsAny('leak-bodies')"

[[waf.rules]]
name = "block-request-body"
phase = "request"
priority = 10
when = "nested_body_has_blocked(Request.Body)"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "blocked request body"

[[waf.rules]]
name = "block-response-body"
phase = "response"
priority = 10
when = "body_has_leak(Response.Body)"

[[waf.rules.actions]]
type = "reject_response"
status = 451
body = "blocked response body"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");
    assert!(engine.requires_request_body_inspection("app-root"));
    assert!(engine.requires_response_body_inspection("app-root"));

    let method = Method::POST;
    let uri: Uri = "/upload".parse().expect("URI should parse");
    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let peer_addr: SocketAddr = "203.0.113.10:49152".parse().unwrap();

    let request_decision = engine.evaluate_request(request_input_with_body(
        &method,
        &uri,
        &headers,
        &tags,
        peer_addr,
        b"prefix blocked suffix",
        false,
    ));
    assert_eq!(
        request_decision
            .terminal
            .as_ref()
            .map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );

    let response_headers = HeaderMap::new();
    let response_decision = engine.evaluate_response(WafResponseInput {
        request: request_input(&method, &uri, &headers, &tags, peer_addr),
        response_id: "test-response-id",
        received_at_unix_ms: 1_700_000_000_123,
        version: http::Version::HTTP_11,
        status: StatusCode::OK,
        headers: &response_headers,
        body: Some(WafBodyInput {
            bytes: b"prefix leak suffix",
            is_truncated: false,
        }),
        upstream_name: "app",
        upstream_pool: None,
        upstream_scheme: "http",
        upstream_connect_time_ms: None,
        upstream_first_byte_time_ms: Some(7),
        upstream_error: None,
    });
    assert_eq!(
        response_decision
            .terminal
            .as_ref()
            .map(|terminal| terminal.status),
        Some(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS)
    );
}

#[test]
fn request_body_size_only_rules_are_planned_as_size_only() {
    let engine = compile_waf_fragment(
        "waf-request-body-size-only-plan",
        r#"
[waf]
enabled = true
mode = "enforcing"

[[waf.functions]]
name = "large_body"
params = ["body"]
expression = "body.Size > 8"

[[waf.rules]]
name = "global-size-only"
phase = "request"
priority = 10
when = "large_body(Request.Body)"

[[waf.rules.actions]]
type = "reject"
status = 403

[[routes.waf.functions]]
name = "route_large_body"
params = ["body"]
expression = "body.Size > 16"

[[routes.waf.rules]]
name = "route-size-only"
phase = "request"
priority = 20
when = "route_large_body(Request.Body)"

[[routes.waf.rules.actions]]
type = "reject"
status = 403
"#,
    );

    assert_eq!(engine.request_body_need("app-root"), BodyNeed::SizeOnly);
    assert!(!engine.requires_request_body_inspection("app-root"));
}

#[test]
fn request_body_size_uses_captured_unknown_length_body() {
    let engine = compile_waf_fragment(
        "waf-request-body-size-captured-unknown",
        r#"
[waf]
enabled = true
mode = "enforcing"

[[waf.rules]]
name = "large-body"
phase = "request"
priority = 10
when = "Request.Body.Size > 8"

[[waf.rules.actions]]
type = "reject"
status = 413
"#,
    );
    let method = Method::POST;
    let uri: Uri = "/upload".parse().expect("URI should parse");
    let headers = HeaderMap::new();
    let tags = HashMap::new();

    let decision = engine.evaluate_request(request_input_with_body(
        &method,
        &uri,
        &headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
        b"123456789",
        false,
    ));

    assert_eq!(
        decision.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::PAYLOAD_TOO_LARGE)
    );
}

#[test]
fn request_body_size_uses_truncated_capture_lower_bound() {
    let engine = compile_waf_fragment(
        "waf-request-body-size-truncated-lower-bound",
        r#"
[waf]
enabled = true
mode = "enforcing"

[[waf.rules]]
name = "large-body"
phase = "request"
priority = 10
when = "Request.Body.Size > 8"

[[waf.rules.actions]]
type = "reject"
status = 413
"#,
    );
    let method = Method::POST;
    let uri: Uri = "/upload".parse().expect("URI should parse");
    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let peer_addr: SocketAddr = "203.0.113.10:49152".parse().unwrap();

    let complete = engine.evaluate_request(request_input_with_body(
        &method,
        &uri,
        &headers,
        &tags,
        peer_addr,
        b"12345678",
        false,
    ));
    assert!(complete.terminal.is_none());

    let truncated = engine.evaluate_request(request_input_with_body(
        &method,
        &uri,
        &headers,
        &tags,
        peer_addr,
        b"12345678",
        true,
    ));
    assert_eq!(
        truncated.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::PAYLOAD_TOO_LARGE)
    );
}

#[test]
fn request_body_size_prefers_positive_content_length() {
    let engine = compile_waf_fragment(
        "waf-request-body-size-content-length",
        r#"
[waf]
enabled = true
mode = "enforcing"

[[waf.rules]]
name = "large-body"
phase = "request"
priority = 10
when = "Request.Body.Size > 8"

[[waf.rules.actions]]
type = "reject"
status = 413
"#,
    );
    let method = Method::POST;
    let uri: Uri = "/upload".parse().expect("URI should parse");
    let tags = HashMap::new();
    let peer_addr: SocketAddr = "203.0.113.10:49152".parse().unwrap();
    let mut small_length_headers = HeaderMap::new();
    small_length_headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("4"));

    let allowed = engine.evaluate_request(request_input_with_body(
        &method,
        &uri,
        &small_length_headers,
        &tags,
        peer_addr,
        b"123456789",
        false,
    ));
    assert!(allowed.terminal.is_none());

    let mut large_length_headers = HeaderMap::new();
    large_length_headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("9"));
    let rejected = engine.evaluate_request(request_input(
        &method,
        &uri,
        &large_length_headers,
        &tags,
        peer_addr,
    ));
    assert_eq!(
        rejected.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::PAYLOAD_TOO_LARGE)
    );
}

#[test]
fn request_body_content_rules_are_planned_with_prefix_capture() {
    for (index, expression) in [
        "Request.Body.Text.contains('secret')",
        "Request.Body.Bytes.size() > 0",
        "Request.Body.contains('secret')",
        "Request.Body.matches('sec.*')",
        "Request.Body.scan('body-patterns').Matched",
        "Request.Body.isFormat('png')",
    ]
    .iter()
    .enumerate()
    {
        let engine = compile_waf_fragment(
            &format!("waf-request-body-prefix-plan-{index}"),
            &format!(
                r#"
[waf]
enabled = true
mode = "enforcing"

[[waf.pattern_sets]]
name = "body-patterns"
kind = "contains"
patterns = ["secret"]

[[waf.rules]]
name = "prefix-rule"
phase = "request"
priority = 10
when = "{expression}"

[[waf.rules.actions]]
type = "reject"
status = 403
"#
            ),
        );

        assert_eq!(
            engine.request_body_need("app-root"),
            BodyNeed::PrefixBytes,
            "{expression}"
        );
        assert!(engine.requires_request_body_inspection("app-root"));
    }
}

#[test]
fn response_body_size_only_rules_are_planned_as_size_only() {
    let engine = compile_waf_fragment(
        "waf-response-body-size-only-plan",
        r#"
[waf]
enabled = true
mode = "enforcing"

[[waf.functions]]
name = "large_response"
params = ["body"]
expression = "body.Size > 8"

[[waf.rules]]
name = "response-size-only"
phase = "response"
priority = 10
when = "large_response(Response.Body)"

[[waf.rules.actions]]
type = "continue_response"
"#,
    );

    assert_eq!(engine.response_body_need("app-root"), BodyNeed::SizeOnly);
    assert!(!engine.requires_response_body_inspection("app-root"));
}

#[test]
fn response_body_size_uses_captured_unknown_length_body() {
    let engine = compile_waf_fragment(
        "waf-response-body-size-captured-unknown",
        r#"
[waf]
enabled = true
mode = "enforcing"

[[waf.rules]]
name = "large-response"
phase = "response"
priority = 10
when = "Response.Body.Size > 8"

[[waf.rules.actions]]
type = "reject_response"
status = 451
"#,
    );
    let method = Method::GET;
    let uri: Uri = "/download".parse().expect("URI should parse");
    let request_headers = HeaderMap::new();
    let response_headers = HeaderMap::new();
    let tags = HashMap::new();
    let peer_addr: SocketAddr = "203.0.113.10:49152".parse().unwrap();

    let decision = engine.evaluate_response(WafResponseInput {
        request: request_input(&method, &uri, &request_headers, &tags, peer_addr),
        response_id: "test-response-id",
        received_at_unix_ms: 1_700_000_000_123,
        version: http::Version::HTTP_11,
        status: StatusCode::OK,
        headers: &response_headers,
        body: Some(WafBodyInput {
            bytes: b"123456789",
            is_truncated: false,
        }),
        upstream_name: "app",
        upstream_pool: None,
        upstream_scheme: "http",
        upstream_connect_time_ms: None,
        upstream_first_byte_time_ms: Some(7),
        upstream_error: None,
    });

    assert_eq!(
        decision.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS)
    );
}

#[test]
fn response_body_size_uses_truncated_capture_lower_bound() {
    let engine = compile_waf_fragment(
        "waf-response-body-size-truncated-lower-bound",
        r#"
[waf]
enabled = true
mode = "enforcing"

[[waf.rules]]
name = "large-response"
phase = "response"
priority = 10
when = "Response.Body.Size > 8"

[[waf.rules.actions]]
type = "reject_response"
status = 451
"#,
    );
    let method = Method::GET;
    let uri: Uri = "/download".parse().expect("URI should parse");
    let request_headers = HeaderMap::new();
    let response_headers = HeaderMap::new();
    let tags = HashMap::new();
    let peer_addr: SocketAddr = "203.0.113.10:49152".parse().unwrap();

    let complete = engine.evaluate_response(WafResponseInput {
        request: request_input(&method, &uri, &request_headers, &tags, peer_addr),
        response_id: "test-response-id",
        received_at_unix_ms: 1_700_000_000_123,
        version: http::Version::HTTP_11,
        status: StatusCode::OK,
        headers: &response_headers,
        body: Some(WafBodyInput {
            bytes: b"12345678",
            is_truncated: false,
        }),
        upstream_name: "app",
        upstream_pool: None,
        upstream_scheme: "http",
        upstream_connect_time_ms: None,
        upstream_first_byte_time_ms: Some(7),
        upstream_error: None,
    });
    assert!(complete.terminal.is_none());

    let truncated = engine.evaluate_response(WafResponseInput {
        request: request_input(&method, &uri, &request_headers, &tags, peer_addr),
        response_id: "test-response-id",
        received_at_unix_ms: 1_700_000_000_123,
        version: http::Version::HTTP_11,
        status: StatusCode::OK,
        headers: &response_headers,
        body: Some(WafBodyInput {
            bytes: b"12345678",
            is_truncated: true,
        }),
        upstream_name: "app",
        upstream_pool: None,
        upstream_scheme: "http",
        upstream_connect_time_ms: None,
        upstream_first_byte_time_ms: Some(7),
        upstream_error: None,
    });
    assert_eq!(
        truncated.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS)
    );
}

#[test]
fn response_body_size_prefers_positive_content_length() {
    let engine = compile_waf_fragment(
        "waf-response-body-size-content-length",
        r#"
[waf]
enabled = true
mode = "enforcing"

[[waf.rules]]
name = "large-response"
phase = "response"
priority = 10
when = "Response.Body.Size > 8"

[[waf.rules.actions]]
type = "reject_response"
status = 451
"#,
    );
    let method = Method::GET;
    let uri: Uri = "/download".parse().expect("URI should parse");
    let request_headers = HeaderMap::new();
    let tags = HashMap::new();
    let peer_addr: SocketAddr = "203.0.113.10:49152".parse().unwrap();
    let mut small_length_headers = HeaderMap::new();
    small_length_headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("4"));

    let allowed = engine.evaluate_response(WafResponseInput {
        request: request_input(&method, &uri, &request_headers, &tags, peer_addr),
        response_id: "test-response-id",
        received_at_unix_ms: 1_700_000_000_123,
        version: http::Version::HTTP_11,
        status: StatusCode::OK,
        headers: &small_length_headers,
        body: Some(WafBodyInput {
            bytes: b"123456789",
            is_truncated: false,
        }),
        upstream_name: "app",
        upstream_pool: None,
        upstream_scheme: "http",
        upstream_connect_time_ms: None,
        upstream_first_byte_time_ms: Some(7),
        upstream_error: None,
    });
    assert!(allowed.terminal.is_none());

    let mut large_length_headers = HeaderMap::new();
    large_length_headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("9"));
    let rejected = engine.evaluate_response(WafResponseInput {
        request: request_input(&method, &uri, &request_headers, &tags, peer_addr),
        response_id: "test-response-id",
        received_at_unix_ms: 1_700_000_000_123,
        version: http::Version::HTTP_11,
        status: StatusCode::OK,
        headers: &large_length_headers,
        body: None,
        upstream_name: "app",
        upstream_pool: None,
        upstream_scheme: "http",
        upstream_connect_time_ms: None,
        upstream_first_byte_time_ms: Some(7),
        upstream_error: None,
    });
    assert_eq!(
        rejected.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS)
    );
}

#[test]
fn response_body_content_rules_are_planned_with_prefix_capture() {
    for (index, expression) in [
        "Response.Body.Text.contains('secret')",
        "Response.Body.Bytes.size() > 0",
        "Response.Body.contains('secret')",
        "Response.Body.matches('sec.*')",
        "Response.Body.scan('body-patterns').Matched",
        "Response.Body.isFormat('png')",
    ]
    .iter()
    .enumerate()
    {
        let engine = compile_waf_fragment(
            &format!("waf-response-body-prefix-plan-{index}"),
            &format!(
                r#"
[waf]
enabled = true
mode = "enforcing"

[[waf.pattern_sets]]
name = "body-patterns"
kind = "contains"
patterns = ["secret"]

[[waf.rules]]
name = "prefix-rule"
phase = "response"
priority = 10
when = "{expression}"

[[waf.rules.actions]]
type = "continue_response"
"#
            ),
        );

        assert_eq!(
            engine.response_body_need("app-root"),
            BodyNeed::PrefixBytes,
            "{expression}"
        );
        assert!(engine.requires_response_body_inspection("app-root"));
    }
}

#[test]
fn empty_captured_request_body_text_evaluates_as_empty_string() {
    let engine = compile_waf_fragment(
        "waf-empty-request-body-text",
        r#"
[waf]
enabled = true
mode = "enforcing"

[[waf.rules]]
name = "empty-body"
phase = "request"
priority = 10
when = "Request.Body.Text == ''"

[[waf.rules.actions]]
type = "reject"
status = 418
"#,
    );
    let method = Method::POST;
    let uri: Uri = "/upload".parse().expect("URI should parse");
    let headers = HeaderMap::new();
    let tags = HashMap::new();

    let decision = engine.evaluate_request(request_input_with_body(
        &method,
        &uri,
        &headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
        b"",
        false,
    ));

    assert_eq!(
        decision.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::IM_A_TEAPOT)
    );
}

#[test]
fn empty_captured_response_body_text_evaluates_as_empty_string() {
    let engine = compile_waf_fragment(
        "waf-empty-response-body-text",
        r#"
[waf]
enabled = true
mode = "enforcing"

[[waf.rules]]
name = "empty-body"
phase = "response"
priority = 10
when = "Response.Body.Text == ''"

[[waf.rules.actions]]
type = "reject_response"
status = 451
"#,
    );
    let method = Method::GET;
    let uri: Uri = "/".parse().expect("URI should parse");
    let headers = HeaderMap::new();
    let tags = HashMap::new();

    let decision = engine.evaluate_response(WafResponseInput {
        request: request_input(
            &method,
            &uri,
            &headers,
            &tags,
            "203.0.113.10:49152".parse().unwrap(),
        ),
        response_id: "test-response-id",
        received_at_unix_ms: 1_700_000_000_123,
        version: http::Version::HTTP_11,
        status: StatusCode::OK,
        headers: &headers,
        body: Some(WafBodyInput {
            bytes: b"",
            is_truncated: false,
        }),
        upstream_name: "app",
        upstream_pool: None,
        upstream_scheme: "http",
        upstream_connect_time_ms: None,
        upstream_first_byte_time_ms: Some(7),
        upstream_error: None,
    });

    assert_eq!(
        decision.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS)
    );
}

#[test]
fn validation_rejects_invalid_udf_definitions_and_calls() {
    for (name, snippet, expected) in [
        (
            "duplicate-function",
            r#"
[[waf.functions]]
name = "same"
expression = "true"

[[waf.functions]]
name = "same"
expression = "false"
"#,
            "duplicate OxiRule function same",
        ),
        (
            "invalid-function-name",
            r#"
[[waf.functions]]
name = "Request"
expression = "true"
"#,
            "function name Request must be a valid OxiRule identifier",
        ),
        (
            "reserved-function-name",
            r#"
[[waf.functions]]
name = "return"
expression = "true"
"#,
            "function name return must be a valid OxiRule identifier",
        ),
        (
            "duplicate-param",
            r#"
[[waf.functions]]
name = "has_value"
params = ["value", "value"]
expression = "value != null"
"#,
            "duplicate parameter value",
        ),
        (
            "top-level-param-name",
            r#"
[[waf.functions]]
name = "has_value"
params = ["Stream"]
expression = "Stream != null"
"#,
            "parameter Stream must be a valid OxiRule identifier",
        ),
        (
            "unknown-function",
            "",
            "unknown OxiRule function missing_fn",
        ),
        ("bad-call-token", "", "unexpected token RParen"),
        ("reserved-call-token", "", "forbidden OxiRule construct if"),
        (
            "arity-mismatch",
            r#"
[[waf.functions]]
name = "one_arg"
params = ["value"]
expression = "value != null"
"#,
            "expects 1 arguments but got 0",
        ),
        (
            "recursive-function",
            r#"
[[waf.functions]]
name = "first"
expression = "second()"

[[waf.functions]]
name = "second"
expression = "first()"
"#,
            "recursive OxiRule function",
        ),
        (
            "global-cannot-see-route-function",
            r#"
[[routes.waf.functions]]
name = "route_only"
params = ["path"]
expression = "path.startsWith('/route')"
"#,
            "unknown OxiRule function route_only",
        ),
    ] {
        let temp_dir = common::TempDir::new(name);
        let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), name);
        let base_config = common::minimal_config_toml(&cert_path, &key_path);
        let when = if name == "arity-mismatch" {
            "one_arg()"
        } else if name == "bad-call-token" {
            "missing_fn(Request.Http.Path,)"
        } else if name == "reserved-call-token" {
            "if(Request.Http.Path)"
        } else if name == "global-cannot-see-route-function" {
            "route_only(Request.Http.Path)"
        } else {
            "missing_fn(Request.Http.Path)"
        };
        let raw = format!(
            r#"{base_config}

[waf]
enabled = true
{snippet}

[[waf.rules]]
name = "{name}"
phase = "request"
priority = 10
when = "{when}"

[[waf.rules.actions]]
type = "reject"
status = 403
"#
        );

        let config: Config = toml::from_str(&raw).expect("config should parse");
        let error = config.validate().expect_err("validation should fail");
        let error_chain = format!("{error:#}");
        assert!(
            error_chain.contains(expected),
            "unexpected error for {name}: {error_chain}"
        );
    }
}

#[test]
fn rate_limit_action_monitor_mode_does_not_consume_tokens() {
    let temp_dir = common::TempDir::new("waf-rate-limit-monitor");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-rate-limit-monitor");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"

[[waf.rules]]
name = "monitor-rate-limit"
mode = "monitor"
phase = "request"
priority = 10
when = "Request.Http.Path == '/monitored'"

[[waf.rules.actions]]
type = "rate_limit"
name = "monitor-limit"
key = "client_ip_route"
rate = "1r/h"
burst = 1
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    assert!(
        evaluate_simple_request(&engine, "/monitored")
            .terminal
            .is_none()
    );
    assert!(
        evaluate_simple_request(&engine, "/monitored")
            .terminal
            .is_none()
    );
}

#[test]
fn rule_without_mode_inherits_global_mode() {
    let temp_dir = common::TempDir::new("waf-rule-inherit-mode");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-rule-inherit-mode");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "monitor"

[[waf.rules]]
name = "inherited-shadow"
phase = "request"
priority = 10
when = "Context.Mode == 'monitor'"

[[waf.rules.actions]]
type = "reject"
status = 403
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let decision = evaluate_simple_request(&engine, "/inherited");

    assert!(decision.terminal.is_none());
    let hit = only_rule_hit(&engine);
    assert_eq!(hit.effective_mode, "monitor");
    assert_eq!(hit.hits, 1);
}

#[test]
fn rule_hit_snapshots_include_zero_hit_rules_deterministically() {
    let temp_dir = common::TempDir::new("waf-rule-hit-snapshot");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-rule-hit-snapshot");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"

[[waf.rules]]
name = "matched-rule"
id = "matched-rule"
phase = "request"
priority = 10
when = "Request.Http.Path == '/matched'"

[[waf.rules.actions]]
type = "reject"
status = 403

[[waf.rules]]
name = "zero-rule"
id = "zero-rule"
mode = "monitor"
phase = "request"
priority = 20
when = "Request.Http.Path == '/zero'"

[[waf.rules.actions]]
type = "reject"
status = 403
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let _ = evaluate_simple_request(&engine, "/matched");
    let snapshots = engine.rule_hit_snapshots();

    assert_eq!(snapshots.len(), 2);
    assert_eq!(snapshots[0].name, "matched-rule");
    assert_eq!(snapshots[0].scope, "global");
    assert_eq!(snapshots[0].route, None);
    assert_eq!(snapshots[0].phase, "request");
    assert_eq!(snapshots[0].effective_mode, "enforcing");
    assert_eq!(snapshots[0].hits, 1);
    assert_eq!(snapshots[1].name, "zero-rule");
    assert_eq!(snapshots[1].effective_mode, "monitor");
    assert_eq!(snapshots[1].hits, 0);
}

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
fn request_rule_can_read_dynamic_policy_snapshot_context() {
    let temp_dir = common::TempDir::new("waf-dynamic-policy-context");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-dynamic-policy-context");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "dynamic-rate-tag"
phase = "request"
priority = 100
when = "DynamicPolicy.Matched && DynamicPolicy.Action == 'rate_limit' && DynamicPolicy.Name == 'login-rate'"

[[waf.rules.actions]]
type = "set_tag"
key = "dp"
value = "hit"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = "/app/login".parse().expect("URI should parse");
    let dynamic_policy = DynamicPolicyContext {
        matched: true,
        action: Some("rate_limit".to_string()),
        name: Some("login-rate".to_string()),
        reason: Some("failed login".to_string()),
        ..DynamicPolicyContext::default()
    };
    let input = WafRequestInput {
        dynamic_policy: &dynamic_policy,
        ..request_input(
            &method,
            &uri,
            &headers,
            &tags,
            "203.0.113.10:49152".parse().unwrap(),
        )
    };
    let decision = engine.evaluate_request(input);

    assert!(decision.terminal.is_none());
    assert_eq!(decision.tags, vec![("dp".to_string(), "hit".to_string())]);
}

#[test]
fn request_helper_maps_match_case_insensitive_header_names() {
    let temp_dir = common::TempDir::new("waf-helper-maps");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "waf-helper-maps");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[waf.limits]
max_rule_runtime_ms = 50
max_total_waf_runtime_ms = 100

[[waf.rules]]
name = "helper-block"
phase = "request"
priority = 10
when = "Request.Headers.anyNameMatches('^X-Matrix-') && Request.Headers.anyEntryMatches('^X-Matrix-', '^yes$') && Request.QueryParams.get('block') == 'yes' && Request.Cookies.get('matrix') == 'cookie'"

[[waf.rules.actions]]
type = "reject"
status = 418
body = "helper matched"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::HeaderName::from_static("x-matrix-case"),
        HeaderValue::from_static("yes"),
    );
    headers.insert(
        http::header::COOKIE,
        HeaderValue::from_static("matrix=cookie"),
    );
    let tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = "/helpers?block=yes".parse().expect("URI should parse");
    let decision = engine.evaluate_request(request_input(
        &method,
        &uri,
        &headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ));

    assert_eq!(
        decision.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::from_u16(418).unwrap())
    );
}

#[test]
fn duplicate_metadata_get_fails_closed_by_default() {
    let temp_dir = common::TempDir::new("waf-duplicate-get-fail-closed");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-duplicate-get-fail-closed");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "single-role"
phase = "request"
priority = 10
when = "Request.QueryParams.get('role') == 'user'"

[[waf.rules.actions]]
type = "reject"
status = 418
body = "role matched"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let method = Method::GET;
    let uri: Uri = "/helpers?role=user&role=admin"
        .parse()
        .expect("URI should parse");
    let headers = HeaderMap::new();
    let tags = HashMap::new();
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
fn duplicate_metadata_policy_can_return_null_or_reject_request() {
    let temp_dir = common::TempDir::new("waf-duplicate-policy");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-duplicate-policy");
    let null_raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
duplicate_metadata_policy = "null_on_duplicate"

[[waf.rules]]
name = "duplicate-role-is-null"
phase = "request"
priority = 10
when = "Request.QueryParams.get('role') == null"

[[waf.rules.actions]]
type = "reject"
status = 409
body = "duplicate role"
"#
    );
    let null_config: Config = toml::from_str(&null_raw).expect("config should parse");
    null_config.validate().expect("config should validate");
    let null_engine = WafEngine::new(&null_config).expect("WAF should compile");

    let method = Method::GET;
    let uri: Uri = "/helpers?role=user&role=admin"
        .parse()
        .expect("URI should parse");
    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let null_decision = null_engine.evaluate_request(request_input(
        &method,
        &uri,
        &headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ));
    assert_eq!(
        null_decision
            .terminal
            .as_ref()
            .map(|terminal| terminal.status),
        Some(StatusCode::CONFLICT)
    );

    let reject_raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
duplicate_metadata_policy = "reject_request"
"#
    );
    let reject_config: Config = toml::from_str(&reject_raw).expect("config should parse");
    reject_config.validate().expect("config should validate");
    let reject_engine = WafEngine::new(&reject_config).expect("WAF should compile");
    let reject_decision = reject_engine.evaluate_request(request_input(
        &method,
        &uri,
        &headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ));
    assert_eq!(
        reject_decision
            .terminal
            .as_ref()
            .map(|terminal| terminal.status),
        Some(StatusCode::BAD_REQUEST)
    );
}

#[test]
fn duplicate_metadata_get_all_exposes_bounded_values() {
    let temp_dir = common::TempDir::new("waf-duplicate-get-all");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-duplicate-get-all");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"

[[waf.rules]]
name = "duplicate-get-all"
phase = "request"
priority = 10
when = "Request.Headers.getAll('X-User').Count == 2 && Request.Headers.getAll('X-User').First == 'allowed' && Request.QueryParams.getAll('role').contains('admin') && Request.Cookies.getAll('session').Count == 2"

[[waf.rules.actions]]
type = "reject"
status = 409
body = "duplicates visible"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let mut headers = HeaderMap::new();
    headers.append(
        http::header::HeaderName::from_static("x-user"),
        HeaderValue::from_static("allowed"),
    );
    headers.append(
        http::header::HeaderName::from_static("x-user"),
        HeaderValue::from_static("admin"),
    );
    headers.append(
        http::header::COOKIE,
        HeaderValue::from_static("session=one"),
    );
    headers.append(
        http::header::COOKIE,
        HeaderValue::from_static("session=two"),
    );
    let method = Method::GET;
    let uri: Uri = "/helpers?role=user&role=admin"
        .parse()
        .expect("URI should parse");
    let tags = HashMap::new();
    let decision = engine.evaluate_request(request_input(
        &method,
        &uri,
        &headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ));

    assert_eq!(
        decision.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::CONFLICT)
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
fn normalized_request_view_decodes_path_query_headers_and_cookies() {
    let temp_dir = common::TempDir::new("waf-normalized-view");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-normalized-view");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "normalized-view"
phase = "request"
priority = 10
when = "Request.Http.Path != Request.Normalized.Http.Path && Request.Normalized.Http.Path == '/admin/secret' && Request.Normalized.Http.Query.contains('role=admin') && Request.Normalized.Headers.get('x-user') == 'alice root' && Request.Normalized.QueryParams.get('role') == 'admin' && Request.Normalized.Cookies.get('theme') == 'dark mode'"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "normalized"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");
    let mut headers = HeaderMap::new();
    headers.insert("x-user", HeaderValue::from_static("  ALICE%20ROOT  "));
    headers.insert(
        http::header::COOKIE,
        HeaderValue::from_static("session=One; theme=Dark%20Mode"),
    );
    let tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = "/safe/%2e%2e/Admin/%53ecret?role=%41DMIN&bad=%ZZ"
        .parse()
        .expect("URI should parse");

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
fn request_and_response_body_text_scan_helpers_match_bounded_bodies() {
    let temp_dir = common::TempDir::new("waf-body-scan-helpers");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-body-scan-helpers");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.pattern_sets]]
name = "request-secrets"
kind = "regex"
patterns = ["boundary.secret"]

[[waf.pattern_sets]]
name = "response-secrets"
kind = "contains"
patterns = ["token"]

[[waf.rules]]
name = "request-body-text"
mode = "monitor"
phase = "request"
priority = 10
when = "Request.Body.Text.contains('hello')"

[[waf.rules.actions]]
type = "reject"
status = 422
body = "request body"

[[waf.rules]]
name = "request-body-contains"
mode = "monitor"
phase = "request"
priority = 11
when = "Request.Body.contains('boundary secret')"

[[waf.rules.actions]]
type = "reject"
status = 422
body = "request body"

[[waf.rules]]
name = "request-body-matches"
mode = "monitor"
phase = "request"
priority = 12
when = "Request.Body.matches('boundary.secret')"

[[waf.rules.actions]]
type = "reject"
status = 422
body = "request body"

[[waf.rules]]
name = "request-body-pattern-set"
mode = "monitor"
phase = "request"
priority = 13
when = "Request.Body.matchesAny('request-secrets')"

[[waf.rules.actions]]
type = "reject"
status = 422
body = "request body"

[[waf.rules]]
name = "request-body-scan-result"
mode = "monitor"
phase = "request"
priority = 14
when = "Request.Body.scan('request-secrets').Matched && Request.Body.scan('request-secrets').Match == 'boundary secret' && Request.Body.scan('request-secrets').IsTruncated"

[[waf.rules.actions]]
type = "reject"
status = 422
body = "request body"

[[waf.rules]]
name = "response-body-text"
mode = "monitor"
phase = "response"
priority = 10
when = "Response.Body.Text.contains('leak')"

[[waf.rules.actions]]
type = "continue_response"

[[waf.rules]]
name = "response-body-pattern-set"
mode = "monitor"
phase = "response"
priority = 11
when = "Response.Body.containsAny('response-secrets')"

[[waf.rules.actions]]
type = "continue_response"

[[waf.rules]]
name = "response-body-scan-result"
phase = "response"
priority = 12
when = "Response.Body.scan('response-secrets').Matched && Response.Body.scan('response-secrets').Offset == 5 && !Response.Body.scan('response-secrets').IsTruncated"

[[waf.rules.actions]]
type = "reject_response"
status = 451
body = "response body"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");
    assert!(engine.requires_request_body_inspection("app-root"));
    assert!(engine.requires_response_body_inspection("app-root"));

    let method = Method::POST;
    let uri: Uri = "/upload".parse().expect("URI should parse");
    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let peer_addr: SocketAddr = "203.0.113.10:49152".parse().unwrap();

    let rejected = engine.evaluate_request(request_input_with_body(
        &method,
        &uri,
        &headers,
        &tags,
        peer_addr,
        b"hello boundary secret trailer",
        true,
    ));
    assert!(rejected.terminal.is_none());
    for name in [
        "request-body-text",
        "request-body-contains",
        "request-body-matches",
        "request-body-pattern-set",
        "request-body-scan-result",
    ] {
        let hit = engine
            .rule_hit_snapshots()
            .into_iter()
            .find(|hit| hit.name == name)
            .unwrap_or_else(|| panic!("missing hit snapshot for {name}"));
        assert_eq!(hit.hits, 1, "expected {name} to match once");
    }

    let response_headers = HeaderMap::new();
    let response = engine.evaluate_response(WafResponseInput {
        request: request_input(&method, &uri, &headers, &tags, peer_addr),
        response_id: "test-response-id",
        received_at_unix_ms: 1_700_000_000_123,
        version: http::Version::HTTP_11,
        status: StatusCode::OK,
        headers: &response_headers,
        body: Some(WafBodyInput {
            bytes: b"leak token here",
            is_truncated: false,
        }),
        upstream_name: "app",
        upstream_pool: None,
        upstream_scheme: "http",
        upstream_connect_time_ms: None,
        upstream_first_byte_time_ms: Some(7),
        upstream_error: None,
    });
    assert_eq!(
        response.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS)
    );
    for name in [
        "response-body-text",
        "response-body-pattern-set",
        "response-body-scan-result",
    ] {
        let hit = engine
            .rule_hit_snapshots()
            .into_iter()
            .find(|hit| hit.name == name)
            .unwrap_or_else(|| panic!("missing hit snapshot for {name}"));
        assert_eq!(hit.hits, 1, "expected {name} to match once");
    }
}

#[test]
fn stream_phase_close_stream_enforces_in_priority_order() {
    let temp_dir = common::TempDir::new("waf-stream-priority");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-stream-priority");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "later-stream-close"
phase = "stream"
priority = 20
when = "Stream.Payload.contains('block-me')"

[[waf.rules.actions]]
type = "close_stream"
websocket_code = 4002
reason = "later"

[[waf.rules]]
name = "first-stream-close"
phase = "stream"
priority = 10
when = "Stream.Payload.contains('block-me')"

[[waf.rules.actions]]
type = "close_stream"
websocket_code = 4001
reason = "first"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");
    assert!(engine.requires_stream_inspection("app-root"));

    let method = Method::GET;
    let uri: Uri = "/ws".parse().expect("URI should parse");
    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let decision = engine.evaluate_stream(websocket_stream_input(
        request_input(
            &method,
            &uri,
            &headers,
            &tags,
            "203.0.113.10:49152".parse().unwrap(),
        ),
        WafStreamDirection::DownstreamToUpstream,
        WafStreamUnit::WebsocketMessage,
        b"please block-me",
        false,
        WafWebSocketStreamMetadata {
            opcode: "message",
            fin: true,
            is_control: false,
            message_opcode: Some("text"),
            frame_payload_size: 15,
        },
    ));

    let close = decision.close.expect("stream should be closed");
    assert_eq!(close.websocket_code, 4001);
    assert_eq!(close.webtransport_code, 1);
    assert_eq!(close.reason, "first");
    let first_hit = engine
        .rule_hit_snapshots()
        .into_iter()
        .find(|hit| hit.name == "first-stream-close")
        .expect("first stream rule snapshot should exist");
    assert_eq!(first_hit.hits, 1);
    let later_hit = engine
        .rule_hit_snapshots()
        .into_iter()
        .find(|hit| hit.name == "later-stream-close")
        .expect("later stream rule snapshot should exist");
    assert_eq!(later_hit.hits, 0);
}

#[test]
fn stream_phase_websocket_payload_metadata_and_monitor_mode_match() {
    let temp_dir = common::TempDir::new("waf-stream-websocket-metadata");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-stream-websocket-metadata");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.pattern_sets]]
name = "stream-secrets"
kind = "contains"
patterns = ["needle"]

[[waf.rules]]
name = "websocket-stream-metadata"
mode = "monitor"
phase = "stream"
priority = 10
when = "Stream.Protocol == 'websocket' && Stream.Direction == 'downstream_to_upstream' && Stream.Unit == 'websocket_frame' && Stream.Payload.contains('needle') && Stream.Payload.matches('n.edle') && Stream.Payload.containsAny('stream-secrets') && Stream.Payload.Bytes.size() == 11 && Stream.Payload.Text.contains('needle') && Stream.Payload.IsTruncated && Stream.WebSocket.Opcode == 'text' && Stream.WebSocket.Fin && !Stream.WebSocket.IsControl && Stream.WebSocket.MessageOpcode == 'text' && Stream.WebSocket.FramePayloadSize == 99"

[[waf.rules.actions]]
type = "close_stream"
websocket_code = 4000
reason = "monitor"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");
    let method = Method::GET;
    let uri: Uri = "/ws".parse().expect("URI should parse");
    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let decision = engine.evaluate_stream(websocket_stream_input(
        request_input(
            &method,
            &uri,
            &headers,
            &tags,
            "203.0.113.10:49152".parse().unwrap(),
        ),
        WafStreamDirection::DownstreamToUpstream,
        WafStreamUnit::WebsocketFrame,
        b"needle-text",
        true,
        WafWebSocketStreamMetadata {
            opcode: "text",
            fin: true,
            is_control: false,
            message_opcode: Some("text"),
            frame_payload_size: 99,
        },
    ));

    assert!(decision.close.is_none());
    let hit = only_rule_hit(&engine);
    assert_eq!(hit.name, "websocket-stream-metadata");
    assert_eq!(hit.effective_mode, "monitor");
}

#[test]
fn stream_phase_webtransport_payload_and_metadata_match() {
    let temp_dir = common::TempDir::new("waf-stream-webtransport-metadata");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-stream-webtransport-metadata");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "monitor"
fail_policy = "closed"

[[waf.rules]]
name = "webtransport-datagram"
phase = "stream"
priority = 10
when = "Stream.Protocol == 'webtransport' && Stream.Direction == 'upstream_to_downstream' && Stream.Unit == 'webtransport_datagram' && Stream.Payload.contains('token') && Stream.WebTransport.DatagramSize == 42 && Stream.WebTransport.StreamKind == null && Stream.WebTransport.StreamId == null"

[[waf.rules.actions]]
type = "close_stream"
webtransport_code = 44
reason = "datagram"

[[waf.rules]]
name = "webtransport-stream-chunk"
phase = "stream"
priority = 20
when = "Stream.Protocol == 'webtransport' && Stream.Direction == 'downstream_to_upstream' && Stream.Unit == 'webtransport_stream_chunk' && Stream.Payload.Text.contains('chunk') && Stream.WebTransport.StreamKind == 'bidi'"

[[waf.rules.actions]]
type = "close_stream"
webtransport_code = 45
reason = "chunk"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");
    let method = Method::CONNECT;
    let uri: Uri = "/wt".parse().expect("URI should parse");
    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let tls = WafTlsMetadata::default();
    let request = request_input_with_protocol_and_network(
        &method,
        &uri,
        &headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
        &tls,
        WafProtocol::Webtransport,
        WafTransportNetwork::Udp,
    );

    let datagram = engine.evaluate_stream(WafStreamInput {
        request,
        protocol: WafStreamProtocol::Webtransport,
        direction: WafStreamDirection::UpstreamToDownstream,
        unit: WafStreamUnit::WebtransportDatagram,
        payload: WafBodyInput {
            bytes: b"token",
            is_truncated: false,
        },
        websocket: None,
        webtransport: Some(WafWebTransportStreamMetadata {
            stream_kind: None,
            stream_id: None,
            datagram_size: Some(42),
        }),
    });
    assert!(datagram.close.is_none());

    let request = request_input_with_protocol_and_network(
        &method,
        &uri,
        &headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
        &tls,
        WafProtocol::Webtransport,
        WafTransportNetwork::Udp,
    );
    let chunk = engine.evaluate_stream(WafStreamInput {
        request,
        protocol: WafStreamProtocol::Webtransport,
        direction: WafStreamDirection::DownstreamToUpstream,
        unit: WafStreamUnit::WebtransportStreamChunk,
        payload: WafBodyInput {
            bytes: b"chunk payload",
            is_truncated: false,
        },
        websocket: None,
        webtransport: Some(WafWebTransportStreamMetadata {
            stream_kind: Some(WafWebTransportStreamKind::Bidi),
            stream_id: None,
            datagram_size: None,
        }),
    });
    assert!(chunk.close.is_none());

    for name in ["webtransport-datagram", "webtransport-stream-chunk"] {
        let hit = engine
            .rule_hit_snapshots()
            .into_iter()
            .find(|hit| hit.name == name)
            .unwrap_or_else(|| panic!("missing hit snapshot for {name}"));
        assert_eq!(hit.hits, 1, "expected {name} to match once");
        assert_eq!(hit.effective_mode, "monitor");
    }
}

#[test]
fn crs_monitor_mode_scores_and_counts_without_blocking() {
    let (_temp_dir, config) = load_crs_fixture_config("waf-crs-monitor", "monitor");
    let engine = WafEngine::new(&config).expect("WAF should compile");
    assert!(engine.requires_request_body_inspection("app-root"));
    assert!(engine.requires_response_body_inspection("app-root"));

    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let method = Method::POST;
    let uri: Uri = "/search?q=UNION%20SELECT"
        .parse()
        .expect("URI should parse");
    let peer_addr: SocketAddr = "203.0.113.10:49152".parse().unwrap();

    let request_decision = engine.evaluate_request(request_input_with_body(
        &method,
        &uri,
        &headers,
        &tags,
        peer_addr,
        b"normal request body",
        false,
    ));
    assert!(request_decision.terminal.is_none());

    let inbound_hit = engine
        .rule_hit_snapshots()
        .into_iter()
        .find(|hit| hit.id.as_deref() == Some("942100"))
        .expect("CRS inbound rule should have a snapshot");
    assert_eq!(inbound_hit.scope, "crs");
    assert_eq!(inbound_hit.effective_mode, "monitor");
    assert_eq!(inbound_hit.hits, 1);
    assert_eq!(inbound_hit.latest_inbound_anomaly_score, Some(5));

    let response_headers = HeaderMap::new();
    let response_decision = engine.evaluate_response(WafResponseInput {
        request: request_input(&method, &uri, &headers, &tags, peer_addr),
        response_id: "test-response-id",
        received_at_unix_ms: 1_700_000_000_123,
        version: http::Version::HTTP_11,
        status: StatusCode::OK,
        headers: &response_headers,
        body: Some(WafBodyInput {
            bytes: b"public body with secret-leak marker",
            is_truncated: false,
        }),
        upstream_name: "app",
        upstream_pool: None,
        upstream_scheme: "http",
        upstream_connect_time_ms: None,
        upstream_first_byte_time_ms: Some(7),
        upstream_error: None,
    });
    assert!(response_decision.terminal.is_none());

    let outbound_hit = engine
        .rule_hit_snapshots()
        .into_iter()
        .find(|hit| hit.id.as_deref() == Some("951100"))
        .expect("CRS outbound rule should have a snapshot");
    assert_eq!(outbound_hit.hits, 1);
    assert_eq!(outbound_hit.latest_outbound_anomaly_score, Some(4));
}

#[test]
fn crs_enforcing_blocks_request_and_response_body_by_anomaly_threshold() {
    let (_temp_dir, config) = load_crs_fixture_config("waf-crs-enforcing", "enforcing");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let method = Method::POST;
    let uri: Uri = "/search?q=union%20select"
        .parse()
        .expect("URI should parse");
    let peer_addr: SocketAddr = "203.0.113.10:49152".parse().unwrap();

    let request_decision = engine.evaluate_request(request_input_with_body(
        &method,
        &uri,
        &headers,
        &tags,
        peer_addr,
        b"normal request body",
        false,
    ));
    assert_eq!(
        request_decision
            .terminal
            .as_ref()
            .map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );

    let ok_uri: Uri = "/ok".parse().expect("URI should parse");
    let response_headers = HeaderMap::new();
    let response_decision = engine.evaluate_response(WafResponseInput {
        request: request_input(&method, &ok_uri, &headers, &tags, peer_addr),
        response_id: "test-response-id",
        received_at_unix_ms: 1_700_000_000_123,
        version: http::Version::HTTP_11,
        status: StatusCode::OK,
        headers: &response_headers,
        body: Some(WafBodyInput {
            bytes: b"public body with secret-leak marker",
            is_truncated: false,
        }),
        upstream_name: "app",
        upstream_pool: None,
        upstream_scheme: "http",
        upstream_connect_time_ms: None,
        upstream_first_byte_time_ms: Some(7),
        upstream_error: None,
    });
    assert_eq!(
        response_decision
            .terminal
            .as_ref()
            .map(|terminal| terminal.status),
        Some(StatusCode::BAD_GATEWAY)
    );
}

#[test]
fn crs_compatibility_matrix_lists_supported_and_ignored_syntax() {
    let matrix = crs_compatibility_matrix();

    assert_eq!(matrix.compatibility_as_of, "2026-05-10");
    assert!(
        matrix
            .release_lines
            .iter()
            .any(|line| line.name == "current" && line.version == "v4.25.0")
    );
    assert!(matrix.supported.directives.contains(&"SecRule"));
    assert!(matrix.supported.operators.contains(&"validateUtf8Encoding"));
    assert!(matrix.supported.transforms.contains(&"urlDecodeUni"));
    assert!(matrix.supported.variables.contains(&"REQUEST_HEADERS"));
    assert!(
        matrix
            .accepted_but_ignored
            .directives
            .contains(&"SecRuleRemoveById")
    );
    assert!(
        matrix
            .known_unsupported
            .iter()
            .any(|entry| entry.contains("WebTransport"))
    );
}

#[test]
fn crs_paranoia_levels_only_activate_configured_level_and_below() {
    for paranoia_level in 1..=4 {
        let (_temp_dir, config) = load_crs_fixture_config_with_rule_and_crs_extra(
            &format!("waf-crs-pl-{paranoia_level}"),
            "monitor",
            r#"
SecRule REQUEST_URI "@contains paranoia-probe" "id:910001,phase:2,msg:'PL1',tag:'paranoia-level/1',setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
SecRule REQUEST_URI "@contains paranoia-probe" "id:910002,phase:2,msg:'PL2',tag:'paranoia-level/2',setvar:'tx.anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
SecRule REQUEST_URI "@contains paranoia-probe" "id:910003,phase:2,msg:'PL3',tag:'paranoia-level/3',setvar:'tx.anomaly_score_pl3=+%{tx.critical_anomaly_score}'"
SecRule REQUEST_URI "@contains paranoia-probe" "id:910004,phase:2,msg:'PL4',tag:'paranoia-level/4',setvar:'tx.anomaly_score_pl4=+%{tx.critical_anomaly_score}'"
"#,
            &format!("paranoia_level = {paranoia_level}"),
        );
        let engine = WafEngine::new(&config).expect("WAF should compile");

        let decision = evaluate_simple_request(&engine, "/app/paranoia-probe");

        assert!(decision.terminal.is_none());
        let snapshots = engine.rule_hit_snapshots();
        for level in 1..=4 {
            let id = format!("91000{level}");
            let hit = snapshots
                .iter()
                .find(|hit| hit.id.as_deref() == Some(id.as_str()))
                .unwrap_or_else(|| panic!("missing CRS snapshot for {id}"));
            let expected_hits = if level <= paranoia_level { 1 } else { 0 };
            assert_eq!(
                hit.hits, expected_hits,
                "unexpected hit count for PL{level} when configured PL is {paranoia_level}"
            );
        }
    }
}

#[test]
fn crs_rule_override_monitor_records_without_blocking_global_enforcing() {
    let (_temp_dir, config) = load_crs_fixture_config_with_rule_and_crs_extra(
        "waf-crs-override-monitor",
        "enforcing",
        r#"
SecRule REQUEST_URI "@contains union select" "id:942100,phase:2,t:urlDecodeUni,t:lowercase,msg:'SQLi',tag:'paranoia-level/1',tag:'attack-sqli',setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
"#,
        r#"
[[waf.crs.rule_overrides]]
name = "monitor-sqli-rule"
rule_ids = ["942100"]
mode = "monitor"
reason = "known application false positive"
"#,
    );
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let decision = evaluate_simple_request(&engine, "/search?q=union%20select");

    assert!(decision.terminal.is_none());
    let hit = engine
        .rule_hit_snapshots()
        .into_iter()
        .find(|hit| hit.id.as_deref() == Some("942100"))
        .expect("CRS override hit should be present");
    assert_eq!(hit.effective_mode, "monitor");
    assert_eq!(hit.hits, 1);
    assert_eq!(hit.tuned_hits, Some(1));
    assert_eq!(hit.latest_inbound_anomaly_score, Some(5));
    assert_eq!(hit.latest_inbound_blocking_score, Some(0));
    assert!(hit.tags.contains(&"attack-sqli".to_string()));
}

#[test]
fn crs_rule_override_enforcing_blocks_global_monitor() {
    let (_temp_dir, config) = load_crs_fixture_config_with_rule_and_crs_extra(
        "waf-crs-override-enforcing",
        "monitor",
        r#"
SecRule REQUEST_URI "@contains union select" "id:942100,phase:2,t:urlDecodeUni,t:lowercase,msg:'SQLi',tag:'paranoia-level/1',tag:'attack-sqli',setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
"#,
        r#"
[[waf.crs.rule_overrides]]
name = "enforce-sqli-rule"
tags = ["attack-sqli"]
mode = "enforcing"
"#,
    );
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let decision = evaluate_simple_request(&engine, "/search?q=union%20select");

    assert_eq!(
        decision.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );
    let hit = engine
        .rule_hit_snapshots()
        .into_iter()
        .find(|hit| hit.id.as_deref() == Some("942100"))
        .expect("CRS override hit should be present");
    assert_eq!(hit.effective_mode, "enforcing");
    assert_eq!(hit.tuned_hits, Some(1));
    assert_eq!(hit.latest_inbound_blocking_score, Some(5));
}

#[test]
fn crs_allowlist_suppresses_scoped_false_positive_only() {
    let (_temp_dir, config) = load_crs_fixture_config_with_rule_and_crs_extra(
        "waf-crs-allowlist",
        "enforcing",
        r#"
SecRule REQUEST_URI "@contains safe-html" "id:941320,phase:2,msg:'Possible XSS',tag:'paranoia-level/1',tag:'attack-xss',setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
"#,
        r#"
[[waf.crs.allowlists]]
name = "allow-editor-html"
rule_ids = ["941320"]
methods = ["GET"]
routes = ["app-root"]
path_prefixes = ["/editor/"]
reason = "editor intentionally submits HTML"
"#,
    );
    let engine = WafEngine::new(&config).expect("WAF should compile");
    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let method = Method::GET;
    let peer_addr: SocketAddr = "203.0.113.10:49152".parse().unwrap();

    let editor_uri: Uri = "/editor/post?content=safe-html"
        .parse()
        .expect("URI should parse");
    let editor_decision = engine.evaluate_request(request_input(
        &method,
        &editor_uri,
        &headers,
        &tags,
        peer_addr,
    ));
    assert!(editor_decision.terminal.is_none());

    let public_uri: Uri = "/public/post?content=safe-html"
        .parse()
        .expect("URI should parse");
    let public_decision = engine.evaluate_request(request_input(
        &method,
        &public_uri,
        &headers,
        &tags,
        peer_addr,
    ));
    assert_eq!(
        public_decision
            .terminal
            .as_ref()
            .map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );

    let hit = engine
        .rule_hit_snapshots()
        .into_iter()
        .find(|hit| hit.id.as_deref() == Some("941320"))
        .expect("CRS allowlist hit should be present");
    assert_eq!(hit.hits, 2);
    assert_eq!(hit.tuned_hits, Some(1));
    assert_eq!(hit.latest_inbound_blocking_score, Some(5));
}

#[test]
fn crs_tuning_config_rejects_invalid_selectors_and_traffic_scopes() {
    for (name, extra, expected) in [
        (
            "missing-rule-selector",
            r#"
[[waf.crs.rule_overrides]]
name = "missing-selector"
mode = "monitor"
"#,
            "must include at least one of rule_ids, tags, or msg_contains",
        ),
        (
            "missing-traffic-selector",
            r#"
[[waf.crs.allowlists]]
name = "missing-traffic"
rule_ids = ["942100"]
"#,
            "must include at least one traffic selector",
        ),
        (
            "spoofable-header-selector",
            r#"
[[waf.crs.allowlists]]
name = "spoofable-header-selector"
rule_ids = ["942100"]
header_equals = { "x-app-context" = "trusted-editor" }
"#,
            "header_equals is not supported because request headers are client-controlled",
        ),
        (
            "spoofable-header-plus-path",
            r#"
[[waf.crs.allowlists]]
name = "spoofable-header-plus-path"
rule_ids = ["942100"]
path_prefixes = ["/editor/"]
header_equals = { "x-app-context" = "trusted-editor" }
"#,
            "header_equals is not supported because request headers are client-controlled",
        ),
        (
            "invalid-method",
            r#"
[[waf.crs.allowlists]]
name = "invalid-method"
rule_ids = ["942100"]
methods = ["GET BAD"]
"#,
            "invalid HTTP method",
        ),
        (
            "invalid-path-prefix",
            r#"
[[waf.crs.allowlists]]
name = "invalid-prefix"
rule_ids = ["942100"]
path_prefixes = ["editor/"]
"#,
            "path_prefixes entries must start with /",
        ),
        (
            "invalid-header",
            r#"
[[waf.crs.allowlists]]
name = "invalid-header"
rule_ids = ["942100"]
header_equals = { "bad header" = "value" }
"#,
            "invalid header name",
        ),
    ] {
        let temp_dir = common::TempDir::new(&format!("waf-crs-tuning-{name}"));
        let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), name);
        let raw = format!(
            "{}\n{}\n{}",
            common::minimal_config_toml(&cert_path, &key_path),
            r#"
[waf]
enabled = true

[waf.crs]
enabled = true
"#,
            extra
        );
        let config: Config = toml::from_str(&raw).expect("config should parse");
        let error = config
            .validate()
            .expect_err("invalid CRS tuning should fail validation");
        assert!(
            error.to_string().contains(expected),
            "expected error containing {expected:?}, got {error:#}"
        );
    }
}

#[test]
fn crs_validate_url_encoding_matches_malformed_percent_sequences_only() {
    let (_temp_dir, config) = load_crs_fixture_config_with_rule(
        "waf-crs-url-encoding",
        "enforcing",
        r#"
SecRule REQUEST_URI_RAW "@validateUrlEncoding" "id:920100,phase:1,msg:'Malformed URL encoding',tag:'paranoia-level/1',severity:'CRITICAL',setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
"#,
    );
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let safe = evaluate_simple_request(&engine, "/app/search?q=safe%20value");
    assert!(safe.terminal.is_none());

    let rejected = evaluate_simple_request(&engine, "/app/search?q=%ZZ");
    assert_eq!(
        rejected.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );

    let hit = engine
        .rule_hit_snapshots()
        .into_iter()
        .find(|hit| hit.id.as_deref() == Some("920100"))
        .expect("CRS URL encoding rule should have a snapshot");
    assert_eq!(hit.hits, 1);
}

#[test]
fn crs_validate_utf8_encoding_matches_invalid_decoded_args_only() {
    let (_temp_dir, config) = load_crs_fixture_config_with_rule(
        "waf-crs-utf8-encoding",
        "enforcing",
        r#"
SecRule ARGS "@validateUtf8Encoding" "id:920200,phase:2,msg:'Invalid UTF-8 encoding',tag:'paranoia-level/1',severity:'CRITICAL',setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
"#,
    );
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let safe = evaluate_simple_request(&engine, "/app/search?q=%E2%9C%93");
    assert!(safe.terminal.is_none());

    let rejected = evaluate_simple_request(&engine, "/app/search?q=%C0%AF");
    assert_eq!(
        rejected.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );

    let hit = engine
        .rule_hit_snapshots()
        .into_iter()
        .find(|hit| hit.id.as_deref() == Some("920200"))
        .expect("CRS UTF-8 encoding rule should have a snapshot");
    assert_eq!(hit.hits, 1);
}

#[test]
fn config_rejects_crs_path_escaping() {
    let temp_dir = common::TempDir::new("waf-crs-path-escape");
    let layout = temp_dir.path();
    std::fs::create_dir_all(layout.join("config")).expect("config dir should be created");
    std::fs::create_dir_all(layout.join("cert")).expect("cert dir should be created");
    std::fs::create_dir_all(layout.join("oxirule/crs/rules"))
        .expect("oxirule dir should be created");
    let (cert_path, key_path) =
        common::create_self_signed_cert(&layout.join("cert"), "waf-crs-path-escape");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml_with_paths(
            cert_path.file_name().unwrap().to_str().unwrap(),
            key_path.file_name().unwrap().to_str().unwrap(),
        ),
        r#"
[waf]
enabled = true

[waf.crs]
enabled = true
setup_file = "crs/crs-setup.conf"
rule_files = ["../escape.conf"]
"#
    );
    let config_path = layout.join("config/oxibelt.toml");
    std::fs::write(&config_path, raw).expect("config should be written");
    std::fs::write(layout.join("oxirule/crs/crs-setup.conf"), "")
        .expect("setup file should be written");

    let error = Config::load(&config_path).expect_err("path escaping should fail");
    assert!(
        error.to_string().contains("waf.crs.rule_files"),
        "unexpected error: {error}"
    );
}

#[test]
fn crs_unsupported_syntax_fails_closed_during_compile() {
    let (_temp_dir, config) = load_crs_fixture_config_with_rule(
        "waf-crs-unsupported",
        "monitor",
        r#"
SecRule REQUEST_URI "@unknownOperator test" "id:999001,phase:1,msg:'unsupported'"
"#,
    );

    let error = match WafEngine::new(&config) {
        Ok(_) => panic!("unsupported CRS syntax should fail closed"),
        Err(error) => error,
    };
    let error_chain = format!("{error:#}");
    assert!(
        error_chain.contains("unsupported CRS operator"),
        "unexpected error: {error_chain}"
    );
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
fn request_rule_can_match_tcp_mss_and_rtt_metadata() {
    let temp_dir = common::TempDir::new("waf-tcp-socket-metadata");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-tcp-socket-metadata");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "reject-tcp-socket-metadata"
phase = "request"
priority = 10
when = "Request.Transport.Tcp.Mss == 1460 && Request.Transport.Tcp.RttMs == 12"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "blocked TCP socket metadata"
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
    let mut input = request_input(&method, &uri, &headers, &tags, peer_addr);
    input.transport_metadata = WafTransportMetadataInput {
        tcp_mss: Some(1460),
        tcp_rtt_ms: Some(12),
        ..WafTransportMetadataInput::default()
    };

    let rejected = engine.evaluate_request(input);
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
fn request_rule_can_match_udp_connection_id_and_null_datagram_size() {
    let temp_dir = common::TempDir::new("waf-udp-connection-id");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-udp-connection-id");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "reject-udp-connection-id"
phase = "request"
priority = 10
when = "Request.Transport.Udp.ConnectionId == 'quinn-stable:7' && Request.Transport.Udp.DatagramSize == null"

[[waf.rules.actions]]
type = "reject"
status = 451
body = "blocked UDP connection id"
"#
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
    let mut input = request_input_with_protocol_and_network(
        &method,
        &uri,
        &headers,
        &tags,
        peer_addr,
        &tls,
        WafProtocol::Http,
        WafTransportNetwork::Udp,
    );
    input.transport_metadata = WafTransportMetadataInput {
        udp_connection_id: Some("quinn-stable:7"),
        ..WafTransportMetadataInput::default()
    };

    let rejected = engine.evaluate_request(input);
    assert_eq!(
        rejected.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS)
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
        response_id: "test-response-id",
        received_at_unix_ms: 1_700_000_000_123,
        version: http::Version::HTTP_11,
        status: StatusCode::INTERNAL_SERVER_ERROR,
        headers: &response_headers,
        body: None,
        upstream_name: "app",
        upstream_pool: None,
        upstream_scheme: "http",
        upstream_connect_time_ms: None,
        upstream_first_byte_time_ms: Some(7),
        upstream_error: None,
    });

    assert_eq!(response_decision.response_header_mutations.len(), 1);
}

#[test]
fn response_rule_can_emit_structured_access_log() {
    let temp_dir = common::TempDir::new("waf-access-log");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "waf-access-log");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "stdout-access"
id = "access-log"
tags = ["audit", "access"]
phase = "response"
priority = 10
when = "true"

[[waf.rules.actions]]
type = "emit_access_log"

[[waf.rules.actions.fields]]
name = "request_method"
value = "Request.Http.Method"

[[waf.rules.actions.fields]]
name = "request_uri"
value = "Request.Http.Uri"

[[waf.rules.actions.fields]]
name = "agent"
value = "Request.Headers.get('User-Agent')"

[[waf.rules.actions.fields]]
name = "status_code"
value = "Response.Http.Status"

[[waf.rules.actions.fields]]
name = "body_bytes"
value = "Response.Body.Size"

[[waf.rules.actions.fields]]
name = "transport"
value = "Request.Transport"

[[waf.rules.actions.fields]]
name = "upstream_name"
value = "Response.Upstream.Name"

[[waf.rules.actions.fields]]
name = "matched_rule"
value = "Context.RuleName"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let mut request_headers = HeaderMap::new();
    request_headers.insert(
        http::header::USER_AGENT,
        HeaderValue::from_static("curl/8.0 \"quoted\""),
    );
    let tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = "/search?q=one%20two".parse().expect("URI should parse");
    let mut response_headers = HeaderMap::new();
    response_headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("12"));
    let mut request = request_input(
        &method,
        &uri,
        &request_headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    );
    request.transport_metadata = WafTransportMetadataInput {
        tcp_mss: Some(1460),
        tcp_rtt_ms: Some(12),
        ..WafTransportMetadataInput::default()
    };

    let response_decision = engine.evaluate_response(WafResponseInput {
        request,
        response_id: "test-response-id",
        received_at_unix_ms: 1_700_000_000_123,
        version: http::Version::HTTP_11,
        status: StatusCode::CREATED,
        headers: &response_headers,
        body: None,
        upstream_name: "app",
        upstream_pool: None,
        upstream_scheme: "http",
        upstream_connect_time_ms: None,
        upstream_first_byte_time_ms: Some(7),
        upstream_error: None,
    });

    assert_eq!(response_decision.access_logs.len(), 1);
    let line = response_decision.access_logs[0].to_json_line();
    assert!(line.contains("\"event\":\"oxibelt.access\""));
    assert!(line.contains("\"timestamp_unix_ms\":"));
    assert!(line.contains("\"request_method\":\"GET\""));
    assert!(line.contains("\"request_uri\":\"/search?q=one%20two\""));
    assert!(line.contains("\"agent\":\"curl/8.0 \\\"quoted\\\"\""));
    assert!(line.contains("\"status_code\":201"));
    assert!(line.contains("\"body_bytes\":12"));
    assert!(line.contains("\"transport\":{\"network\":\"tcp\",\"remoteip\":\"203.0.113.10\",\"remoteport\":49152,\"isencrypted\":true,\"tcp\":{\"sni\":null,\"alpn\":null,\"maxhop\":null,\"mss\":1460,\"rttms\":12},\"udp\":null}"));
    assert!(line.contains("\"upstream_name\":\"app\""));
    assert!(line.contains("\"matched_rule\":\"stdout-access\""));
    assert!(!line.contains("\"client_ip\":"));
    assert!(!line.contains("\"waf_rule_tags\":"));
}

#[test]
fn system_access_log_default_fields_preserve_duplicate_user_agents() {
    let temp_dir = common::TempDir::new("system-access-log-duplicate-ua");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "system-access-log-duplicate-ua");
    let raw = common::minimal_config_toml(&cert_path, &key_path);

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");
    let fields = compile_access_log_fields("logging.access_log", &config.logging.access_log.fields)
        .expect("system access-log fields should compile");

    let mut request_headers = HeaderMap::new();
    request_headers.append(
        http::header::USER_AGENT,
        HeaderValue::from_static("first-agent"),
    );
    request_headers.append(
        http::header::USER_AGENT,
        HeaderValue::from_static("second-agent"),
    );
    let tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = "/search?q=one%20two".parse().expect("URI should parse");
    let mut response_headers = HeaderMap::new();
    response_headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("12"));

    let record = engine
        .build_system_access_log(
            &fields,
            WafResponseInput {
                request: request_input(
                    &method,
                    &uri,
                    &request_headers,
                    &tags,
                    "203.0.113.10:49152".parse().unwrap(),
                ),
                response_id: "test-response-id",
                received_at_unix_ms: 1_700_000_000_123,
                version: http::Version::HTTP_11,
                status: StatusCode::CREATED,
                headers: &response_headers,
                body: None,
                upstream_name: "app",
                upstream_pool: None,
                upstream_scheme: "http",
                upstream_connect_time_ms: None,
                upstream_first_byte_time_ms: Some(7),
                upstream_error: None,
            },
        )
        .expect("duplicate User-Agent should not suppress the system access log");

    let line = record.to_json_line();
    assert!(line.contains("\"scope\":\"system\""));
    assert!(line.contains(
        "\"user_agent\":{\"values\":[\"first-agent\",\"second-agent\"],\"is_truncated\":false}"
    ));
}

#[test]
fn default_emit_access_log_fields_preserve_duplicate_user_agents() {
    let temp_dir = common::TempDir::new("waf-access-log-duplicate-ua");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-access-log-duplicate-ua");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "default-access"
phase = "response"
priority = 10
when = "true"

[[waf.rules.actions]]
type = "emit_access_log"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let mut request_headers = HeaderMap::new();
    request_headers.append(
        http::header::USER_AGENT,
        HeaderValue::from_static("first-agent"),
    );
    request_headers.append(
        http::header::USER_AGENT,
        HeaderValue::from_static("second-agent"),
    );
    let tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = "/search?q=one%20two".parse().expect("URI should parse");
    let mut response_headers = HeaderMap::new();
    response_headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("12"));

    let response_decision = engine.evaluate_response(WafResponseInput {
        request: request_input(
            &method,
            &uri,
            &request_headers,
            &tags,
            "203.0.113.10:49152".parse().unwrap(),
        ),
        response_id: "test-response-id",
        received_at_unix_ms: 1_700_000_000_123,
        version: http::Version::HTTP_11,
        status: StatusCode::CREATED,
        headers: &response_headers,
        body: None,
        upstream_name: "app",
        upstream_pool: None,
        upstream_scheme: "http",
        upstream_connect_time_ms: None,
        upstream_first_byte_time_ms: Some(7),
        upstream_error: None,
    });

    assert_eq!(response_decision.access_logs.len(), 1);
    let line = response_decision.access_logs[0].to_json_line();
    assert!(line.contains("\"scope\":\"waf\""));
    assert!(line.contains(
        "\"user_agent\":{\"values\":[\"first-agent\",\"second-agent\"],\"is_truncated\":false}"
    ));
}

#[test]
fn access_log_can_emit_runtime_metadata_and_json_collections() {
    let temp_dir = common::TempDir::new("waf-access-log-json");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-access-log-json");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "json-access"
phase = "response"
priority = 10
when = "true"

[[waf.rules.actions]]
type = "emit_access_log"

[[waf.rules.actions.fields]]
name = "request_id"
value = "Request.Id"

[[waf.rules.actions.fields]]
name = "response_id"
value = "Response.Id"

[[waf.rules.actions.fields]]
name = "transaction_id"
value = "Context.TransactionId"

[[waf.rules.actions.fields]]
name = "request_received"
value = "Request.ReceivedAtUnixMs"

[[waf.rules.actions.fields]]
name = "response_received"
value = "Response.ReceivedAtUnixMs"

[[waf.rules.actions.fields]]
name = "multi_header"
value = "Request.Headers.getAll('X-Multi')"

[[waf.rules.actions.fields]]
name = "request_headers"
value = "Request.Headers"

[[waf.rules.actions.fields]]
name = "query"
value = "Request.QueryParams"

[[waf.rules.actions.fields]]
name = "request_http"
value = "Request.Http"

[[waf.rules.actions.fields]]
name = "first_byte_ms"
value = "Response.Upstream.FirstByteTimeMs"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let mut request_headers = HeaderMap::new();
    request_headers.append("x-multi", HeaderValue::from_static("one"));
    request_headers.append("x-multi", HeaderValue::from_static("two"));
    let tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = "/search?q=one&q=two".parse().expect("URI should parse");
    let response_headers = HeaderMap::new();

    let response_decision = engine.evaluate_response(WafResponseInput {
        request: request_input(
            &method,
            &uri,
            &request_headers,
            &tags,
            "203.0.113.10:49152".parse().unwrap(),
        ),
        response_id: "test-response-json-id",
        received_at_unix_ms: 1_700_000_000_321,
        version: http::Version::HTTP_11,
        status: StatusCode::OK,
        headers: &response_headers,
        body: None,
        upstream_name: "app",
        upstream_pool: Some("main-pool"),
        upstream_scheme: "http",
        upstream_connect_time_ms: None,
        upstream_first_byte_time_ms: Some(42),
        upstream_error: None,
    });

    assert_eq!(response_decision.access_logs.len(), 1);
    let line = response_decision.access_logs[0].to_json_line();
    assert!(line.contains("\"scope\":\"waf\""));
    assert!(line.contains("\"request_id\":\"test-request-id\""));
    assert!(line.contains("\"response_id\":\"test-response-json-id\""));
    assert!(line.contains("\"transaction_id\":\"test-transaction-id\""));
    assert!(line.contains("\"request_received\":1700000000000"));
    assert!(line.contains("\"response_received\":1700000000321"));
    assert!(
        line.contains("\"multi_header\":{\"values\":[\"one\",\"two\"],\"is_truncated\":false}")
    );
    assert!(line.contains("\"x-multi\":[\"one\",\"two\"]"));
    assert!(line.contains("\"query\":{\"q\":[\"one\",\"two\"]}"));
    assert!(line.contains("\"request_http\":{"));
    assert!(line.contains("\"first_byte_ms\":42"));
}

#[test]
fn access_log_rejects_request_body_bytes_fields() {
    let temp_dir = common::TempDir::new("waf-access-log-body-bytes");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-access-log-body-bytes");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "bad-access"
phase = "response"
priority = 10
when = "true"

[[waf.rules.actions]]
type = "emit_access_log"

[[waf.rules.actions.fields]]
name = "body_bytes"
value = "Request.Body.Bytes.size()"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
        .validate()
        .expect_err("request body bytes should fail");
    assert!(
        error.to_string().contains("cannot read request body bytes"),
        "unexpected error: {error}"
    );
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
fn person_proof_success_tag_uses_verified_policy() {
    let temp_dir = common::TempDir::new("waf-person-proof-tag-policy");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-person-proof-tag-policy");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "weak-public-proof"
phase = "request"
priority = 10
when = "Request.Http.Path.startsWith('/public') && Request.Client.PersonProof.State != 'valid'"

[[waf.rules.actions]]
type = "require_person_proof"
difficulty = 4
token_validity_seconds = 60
cookie = "__test_person_proof"
success_tag = "WeakProof"

[[waf.rules]]
name = "admin-proof"
phase = "request"
priority = 20
when = "Request.Http.Path.startsWith('/admin') && Request.Client.PersonProof.State != 'valid'"

[[waf.rules.actions]]
type = "require_person_proof"
difficulty = 4
token_validity_seconds = 60
cookie = "__test_person_proof"
success_tag = "AdminProof"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = "/admin".parse().expect("URI should parse");
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
        vec![("AdminProof".to_string(), "valid".to_string())]
    );
}

#[test]
fn weaker_person_proof_does_not_satisfy_stricter_rule() {
    let temp_dir = common::TempDir::new("waf-person-proof-policy-scope");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-person-proof-policy-scope");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "low-proof"
phase = "request"
priority = 10
when = "Request.Http.Path.startsWith('/low') && Request.Client.PersonProof.State != 'valid'"

[[waf.rules.actions]]
type = "require_person_proof"
difficulty = 4
token_validity_seconds = 60
cookie = "__test_person_proof"
success_tag = "LowProof"

[[waf.rules]]
name = "admin-proof"
phase = "request"
priority = 20
when = "Request.Http.Path.startsWith('/admin') && Request.Client.PersonProof.State != 'valid'"

[[waf.rules.actions]]
type = "require_person_proof"
difficulty = 6
token_validity_seconds = 60
cookie = "__test_person_proof"
success_tag = "AdminProof"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    let engine = WafEngine::new(&config).expect("WAF should compile");

    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let method = Method::GET;
    let low_uri: Uri = "/low".parse().expect("URI should parse");
    let challenge_decision = engine.evaluate_request(request_input(
        &method,
        &low_uri,
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
    let admin_uri: Uri = "/admin".parse().expect("URI should parse");
    let admin_decision = engine.evaluate_request(request_input(
        &method,
        &admin_uri,
        &solved_headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ));

    assert_eq!(
        admin_decision
            .terminal
            .as_ref()
            .map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );
    assert!(
        admin_decision
            .terminal
            .as_ref()
            .unwrap()
            .body
            .contains("oxibelt-person-proof-token")
    );
}

#[test]
fn person_proof_single_use_challenge_state_is_capped() {
    let temp_dir = common::TempDir::new("waf-person-proof-reuse-cap");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-person-proof-reuse-cap");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[waf.limits]
max_person_proof_reuse_tokens = 1

[[waf.rules]]
name = "single-use-proof"
phase = "request"
priority = 10
when = "Request.Client.PersonProof.State != 'valid'"

[[waf.rules.actions]]
type = "require_person_proof"
difficulty = 4
token_validity_seconds = 60
cookie = "__test_person_proof"
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
    let first = engine.evaluate_request(request_input(
        &method,
        &uri,
        &headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ));
    assert_eq!(
        first.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::FORBIDDEN)
    );

    let second = engine.evaluate_request(request_input(
        &method,
        &uri,
        &headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ));
    assert_eq!(
        second.terminal.as_ref().map(|terminal| terminal.status),
        Some(StatusCode::TOO_MANY_REQUESTS)
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
fn person_proof_single_use_clearance_survives_waf_reload() {
    let temp_dir = common::TempDir::new("waf-person-proof-reload");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-person-proof-reload");
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

    let reloaded_raw = format!(
        "{raw}\n{}",
        r#"
[[waf.rules]]
name = "reload-marker"
phase = "request"
priority = 20
when = "false"

[[waf.rules.actions]]
type = "reject"
status = 409
body = "reloaded"
"#
    );
    let reloaded_config: Config = toml::from_str(&reloaded_raw).expect("config should parse");
    reloaded_config
        .validate()
        .expect("reloaded config should validate");
    let reloaded_engine = WafEngine::new_with_previous(&reloaded_config, Some(&engine), None)
        .expect("reloaded WAF should compile");

    let mut clearance_headers = HeaderMap::new();
    clearance_headers.insert(
        http::header::COOKIE,
        HeaderValue::from_str(&format!("__test_person_proof={initial_clearance}")).unwrap(),
    );
    let clearance_decision = reloaded_engine.evaluate_request(request_input(
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

    let replay_decision = reloaded_engine.evaluate_request(request_input(
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
fn validation_rejects_request_body_and_response_access_in_stream_phase() {
    for (name, expression, expected) in [
        (
            "stream-response-access",
            "Response.Http.Status >= 500",
            "Response is unavailable",
        ),
        (
            "stream-request-body-access",
            "Request.Body.contains('secret')",
            "Request.Body is unavailable",
        ),
    ] {
        let temp_dir = common::TempDir::new(name);
        let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), name);
        let base_config = common::minimal_config_toml(&cert_path, &key_path);
        let raw = format!(
            r#"{base_config}

[waf]
enabled = true

[[waf.rules]]
name = "{name}"
phase = "stream"
priority = 1
when = "{expression}"

[[waf.rules.actions]]
type = "close_stream"
"#
        );

        let config: Config = toml::from_str(&raw).expect("config should parse");
        let error = config.validate().expect_err("validation should fail");
        let error_chain = format!("{error:#}");
        assert!(
            error_chain.contains(expected),
            "unexpected error for {name}: {error}"
        );
    }
}

#[test]
fn validation_rejects_stream_actions_in_wrong_phases() {
    for (name, phase, action, expected) in [
        (
            "request-close-stream",
            "request",
            r#"type = "close_stream""#,
            "action close_stream is not valid in Request phase",
        ),
        (
            "stream-reject",
            "stream",
            r#"type = "reject"
status = 403"#,
            "action reject is not valid in Stream phase",
        ),
        (
            "stream-reject-response",
            "stream",
            r#"type = "reject_response"
status = 403"#,
            "response terminal action is not valid in Stream phase",
        ),
    ] {
        let temp_dir = common::TempDir::new(name);
        let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), name);
        let when = if phase == "response" {
            "Response.Http.Status == 200"
        } else if phase == "stream" {
            "Stream.Payload.contains('x')"
        } else {
            "true"
        };
        let base_config = common::minimal_config_toml(&cert_path, &key_path);
        let raw = format!(
            r#"{base_config}

[waf]
enabled = true

[[waf.rules]]
name = "{name}"
phase = "{phase}"
priority = 1
when = "{when}"

[[waf.rules.actions]]
{action}
"#
        );

        let config: Config = toml::from_str(&raw).expect("config should parse");
        let error = config.validate().expect_err("validation should fail");
        assert!(
            error.to_string().contains(expected),
            "unexpected error for {name}: {error}"
        );
    }
}

#[test]
fn validation_rejects_access_log_action_in_request_phase() {
    let temp_dir = common::TempDir::new("waf-access-log-phase");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-access-log-phase");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true

[[waf.rules]]
name = "bad-access-log-phase"
phase = "request"
priority = 1
when = "true"

[[waf.rules.actions]]
type = "emit_access_log"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config.validate().expect_err("validation should fail");
    assert!(
        error
            .to_string()
            .contains("action emit_access_log is not valid in Request phase"),
        "unexpected error: {error}"
    );
}

#[test]
fn validation_rejects_rate_limit_action_in_response_phase() {
    let temp_dir = common::TempDir::new("waf-rate-limit-response-phase");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-rate-limit-response-phase");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true

[[waf.rules]]
name = "response-rate-limit"
phase = "response"
priority = 10
when = "Response.Http.Status == 200"

[[waf.rules.actions]]
type = "rate_limit"
name = "bad-response-limit"
rate = "1r/s"
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
        .validate()
        .expect_err("WAF should reject invalid action phase");
    assert!(
        error
            .to_string()
            .contains("action rate_limit is not valid in Response phase"),
        "unexpected error: {error}"
    );
}

#[test]
fn validation_rejects_rate_limit_action_zero_max_buckets() {
    let temp_dir = common::TempDir::new("waf-rate-limit-zero-buckets");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "waf-rate-limit-zero-buckets");
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        r#"
[waf]
enabled = true

[[waf.rules]]
name = "zero-rate-buckets"
phase = "request"
priority = 10
when = "true"

[[waf.rules.actions]]
type = "rate_limit"
name = "bad-bucket-cap"
rate = "1r/s"
max_buckets = 0
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
        .validate()
        .expect_err("WAF should reject zero rate-limit max_buckets");
    assert!(
        error
            .to_string()
            .contains("WAF rule zero-rate-buckets rate_limit max_buckets must be greater than 0"),
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

fn load_crs_fixture_config(prefix: &str, mode: &str) -> (common::TempDir, Config) {
    load_crs_fixture_config_with_rule(
        prefix,
        mode,
        r#"
SecRule REQUEST_URI "@contains union select" "id:942100,phase:2,t:urlDecodeUni,t:lowercase,msg:'SQLi',tag:'paranoia-level/1',severity:'CRITICAL',setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
SecRule REQUEST_BODY "@contains body-threat" "id:942101,phase:2,t:lowercase,msg:'Request body threat',tag:'paranoia-level/1',severity:'CRITICAL',setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
SecRule RESPONSE_BODY "@contains secret-leak" "id:951100,phase:4,t:lowercase,msg:'Leak',tag:'paranoia-level/1',severity:'ERROR',setvar:'tx.outbound_anomaly_score=+%{tx.error_anomaly_score}'"
"#,
    )
}

fn load_crs_fixture_config_with_rule(
    prefix: &str,
    mode: &str,
    rule_file: &str,
) -> (common::TempDir, Config) {
    load_crs_fixture_config_with_rule_and_crs_extra(prefix, mode, rule_file, "")
}

fn load_crs_fixture_config_with_rule_and_crs_extra(
    prefix: &str,
    mode: &str,
    rule_file: &str,
    crs_extra: &str,
) -> (common::TempDir, Config) {
    let temp_dir = common::TempDir::new(prefix);
    let layout = temp_dir.path();
    let config_dir = layout.join("config");
    let cert_dir = layout.join("cert");
    let oxirule_rules_dir = layout.join("oxirule/crs/rules");
    std::fs::create_dir_all(&config_dir).expect("config dir should be created");
    std::fs::create_dir_all(&cert_dir).expect("cert dir should be created");
    std::fs::create_dir_all(&oxirule_rules_dir).expect("CRS rules dir should be created");
    let (cert_path, key_path) = common::create_self_signed_cert(&cert_dir, prefix);
    std::fs::write(layout.join("oxirule/crs/crs-setup.conf"), "")
        .expect("CRS setup file should be written");
    std::fs::write(oxirule_rules_dir.join("REQUEST-942.conf"), rule_file)
        .expect("CRS rule file should be written");
    let base = common::minimal_config_toml_with_paths(
        cert_path.file_name().unwrap().to_str().unwrap(),
        key_path.file_name().unwrap().to_str().unwrap(),
    );
    let paranoia_level = if crs_extra.contains("paranoia_level") {
        ""
    } else {
        "paranoia_level = 1"
    };
    let raw = format!(
        r#"{base}

[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[waf.limits]
max_body_inspection_bytes = 128

[waf.crs]
enabled = true
mode = "{mode}"
setup_file = "crs/crs-setup.conf"
rule_files = ["crs/rules/*.conf"]
{paranoia_level}
inbound_anomaly_score_threshold = 5
outbound_anomaly_score_threshold = 4
unsupported_directive_policy = "fail_closed"
{crs_extra}
"#
    );
    let config_path = config_dir.join("oxibelt.toml");
    std::fs::write(&config_path, raw).expect("config should be written");
    let config = Config::load(&config_path).expect("config should load");
    config.validate().expect("config should validate");
    (temp_dir, config)
}

fn evaluate_simple_request(engine: &WafEngine, path: &str) -> oxibelt::waf::RequestWafDecision {
    let headers = HeaderMap::new();
    let tags = HashMap::new();
    let method = Method::GET;
    let uri: Uri = path.parse().expect("URI should parse");
    engine.evaluate_request(request_input(
        &method,
        &uri,
        &headers,
        &tags,
        "203.0.113.10:49152".parse().unwrap(),
    ))
}

fn only_rule_hit(engine: &WafEngine) -> oxibelt::waf::WafRuleHitSnapshot {
    let snapshots = engine.rule_hit_snapshots();
    assert_eq!(snapshots.len(), 1);
    snapshots.into_iter().next().expect("rule hit should exist")
}

fn compile_waf_fragment(test_name: &str, fragment: &str) -> WafEngine {
    let temp_dir = common::TempDir::new(test_name);
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), test_name);
    let raw = format!(
        "{}\n{}",
        common::minimal_config_toml(&cert_path, &key_path),
        fragment
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    WafEngine::new(&config).expect("WAF should compile")
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
        request_id: "test-request-id",
        transaction_id: "test-transaction-id",
        received_at_unix_ms: 1_700_000_000_000,
        method,
        uri,
        version: http::Version::HTTP_11,
        headers,
        body: None,
        peer_addr,
        downstream_host: "example.com",
        downstream_scheme: "https",
        route_name: "app-root",
        tcp_max_hop,
        tls,
        protocol: WafProtocol::Http,
        transport_network: WafTransportNetwork::Tcp,
        transport_metadata: WafTransportMetadataInput::default(),
        tags,
        dynamic_policy: test_dynamic_policy(),
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
        request_id: "test-request-id",
        transaction_id: "test-transaction-id",
        received_at_unix_ms: 1_700_000_000_000,
        method,
        uri,
        version: http::Version::HTTP_3,
        headers,
        body: None,
        peer_addr,
        downstream_host: "example.com",
        downstream_scheme: "https",
        route_name: "app-root",
        tcp_max_hop: None,
        tls,
        protocol,
        transport_network,
        transport_metadata: WafTransportMetadataInput::default(),
        tags,
        dynamic_policy: test_dynamic_policy(),
    }
}

fn websocket_stream_input<'a>(
    request: WafRequestInput<'a>,
    direction: WafStreamDirection,
    unit: WafStreamUnit,
    payload: &'a [u8],
    is_truncated: bool,
    websocket: WafWebSocketStreamMetadata<'a>,
) -> WafStreamInput<'a> {
    WafStreamInput {
        request,
        protocol: WafStreamProtocol::Websocket,
        direction,
        unit,
        payload: WafBodyInput {
            bytes: payload,
            is_truncated,
        },
        websocket: Some(websocket),
        webtransport: None,
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

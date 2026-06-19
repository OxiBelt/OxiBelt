use crate::{DockerCase, ExpectStart, Needs, docker_case};

pub(super) fn docker_cases() -> Vec<DockerCase> {
  vec![
    docker_case(
      "waf-request",
      "reject-path",
      "request-phase reject blocks a matching path",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-request",
      "body-size-chunked",
      "request Body.Size rules reject chunked bodies without Content-Length",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-request",
      "monitor-mode-allows",
      "monitor mode evaluates but does not enforce request rejection",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-request",
      "rule-mode-hit-counters",
      "rule-level WAF modes expose per-rule hit telemetry only through admin",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf",
      "waf-http-body-compression",
      "opt-in WAF body compression transform inspects decoded bodies and rejects bombs",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-crs",
      "request-response-full",
      "CRS-compatible rules enforce request and response phases 1 through 4",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-crs",
      "monitor-first",
      "default CRS monitor mode allows traffic while recording hits and anomaly scores",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-request",
      "normalized-crs-request",
      "CRS transforms detect encoded traversal and SQLi request payloads",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-request",
      "route-to-upstream",
      "request rule can override the selected upstream",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        alt_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-request",
      "route-to-pool",
      "request rule can override the selected upstream pool",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        alt_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-request",
      "set-tag-chain",
      "request tags created by one rule are visible to later rules",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-request",
      "external-rule-file",
      "external OxiRule files are loaded from the oxirule directory",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-request",
      "route-level-rule",
      "route-scoped OxiRules apply only after route selection",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-response",
      "set-remove-response-headers",
      "response rules set and remove headers",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-response",
      "response-object-model",
      "response rules can match response cookies, request tags, and transport metadata",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-response",
      "replace-5xx",
      "response rules can replace upstream 5xx responses",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-response",
      "reject-response",
      "response rules can reject otherwise successful upstream responses",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-response",
      "body-size-chunked",
      "response Body.Size rules reject chunked upstream bodies without Content-Length",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-response",
      "upstream-error-replaced",
      "synthetic upstream errors are visible to response rules",
      ExpectStart::Success,
      Needs::default(),
      None,
    ),
    docker_case(
      "waf-validation",
      "route-to-pool-reserved",
      "route_to_pool rejects unknown upstream pool names",
      ExpectStart::Failure,
      Needs::default(),
      Some("route_to_pool"),
    ),
    docker_case(
      "waf-validation",
      "set-load-balancing-reserved",
      "set_load_balancing_policy rejects unsupported policies",
      ExpectStart::Failure,
      Needs::default(),
      Some("set_load_balancing_policy"),
    ),
    docker_case(
      "waf-validation",
      "response-access-in-request",
      "request phase rejects Response object access",
      ExpectStart::Failure,
      Needs::default(),
      Some("Response is unavailable in request-phase rules"),
    ),
    docker_case(
      "waf-helpers",
      "response-body-scan",
      "bounded response body scan can reject matching upstream bodies",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-helpers",
      "header-query-cookie",
      "header, query, and cookie helpers work together",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-helpers",
      "pattern-set-contains",
      "contains pattern sets can drive request decisions",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-helpers",
      "body-format-helper",
      "request body byte format helper can reject non-PNG uploads",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-helpers",
      "body-streaming-scan",
      "bounded request body scan detects a pattern split across body frames",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-helpers",
      "udf-body-object",
      "body object arguments passed into UDFs trigger request and response body inspection",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-person-proof",
      "challenge-issued",
      "request-phase person proof challenge is issued",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-person-proof",
      "challenge-spam-does-not-reserve-single-use-state",
      "default single-use challenge spam does not reserve replay state",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-person-proof",
      "provider-mock-verify",
      "Person proof session API verifies through a local custom HTTP provider",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "waf-person-proof",
      "provider-replay-consumes-session",
      "single-use provider verification replay is rejected before a second provider call",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
  ]
}

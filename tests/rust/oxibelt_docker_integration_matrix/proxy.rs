use crate::{DockerCase, ExpectStart, Needs, docker_case};

pub(super) fn docker_cases() -> Vec<DockerCase> {
    vec![
        docker_case(
            "proxy-compression",
            "downstream-gzip-response",
            "downstream response compression negotiates and serves gzip",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-compression",
            "secret-bearing-response-skip",
            "downstream response compression skips authenticated and private responses",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-compression",
            "route-compression-off-overrides-default",
            "route compression off skips global downstream compression",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "http-semantics",
            "early-hints-pass",
            "HTTP semantics accepts early hints pass mode and forwards final responses",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "http-semantics",
            "expect-priority",
            "HTTP semantics validates Expect and can strip Priority headers",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "http-semantics",
            "sse-grpc-errors",
            "HTTP semantics keeps SSE streaming and maps proxy errors for gRPC and JSON clients",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-identity",
            "real-ip-waf",
            "trusted X-Forwarded-For real IP is used by request WAF rules",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-identity",
            "connection-limit-first-request-real-ip",
            "first-request Real-IP connection limits use trusted forwarded client IPs",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-identity",
            "connection-limit-per-request-real-ip",
            "per-request Real-IP connection limits release after response body completion",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-identity",
            "connection-limit-per-request-real-ip-http1-tunnels",
            "per-request Real-IP connection limits stay held for HTTP/1 tunnel lifetimes",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-protocol",
            "trusted-v1",
            "trusted PROXY protocol v1 source address reaches request WAF rules",
            ExpectStart::Success,
            Needs::default(),
            None,
        ),
        docker_case(
            "proxy-protocol",
            "connection-limit-source-ip",
            "PROXY protocol source IP is used for downstream connection limits",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "upstream-pools",
            "power-of-two-choices",
            "routes can select upstream pools with power-of-two-choices balancing",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "upstream-pools",
            "active-health-options",
            "active HTTP health checks honor method, Host, headers, body, ranges, regex, and jitter",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "upstream-pools",
            "retry-failover",
            "pool retry reselects a healthy backend and reports passive health",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "upstream-pools",
            "retry-connect-error-on-policy",
            "retry.on excludes connect errors from pool retry",
            ExpectStart::Success,
            Needs {
                alt_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "upstream-pools",
            "route-retry-enable",
            "route retry override can enable failover when global retry is disabled",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "upstream-pools",
            "slow-start-outlier-metrics",
            "slow start, outlier ejection, Admin snapshots, and pool metrics work together",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "upstream-pools",
            "route-retry-disable",
            "route retry override can disable failover when global retry is enabled",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "upstream-pools",
            "retry-non-idempotent",
            "retry_non_idempotent enables POST retry only when configured",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "upstream-discovery",
            "file-provider",
            "file discovery adds and removes upstream pool servers without full reload",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "upstream-discovery",
            "dns-spoofed-answers",
            "DNS discovery rejects spoofed answers while accepting matching responses",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                dns_server: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "upstream-discovery",
            "kubernetes-endpointslice-watch",
            "Kubernetes EndpointSlice watch updates discovered pool servers",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                kubernetes_server: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "upstream-discovery",
            "nomad-service-watch",
            "Nomad service discovery watches indexes and exposes safe pool health details",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                nomad_server: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "upstream-discovery",
            "admin-runtime-control",
            "admin API can drain/down pool servers and update runtime weights",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "upstream-discovery",
            "admin-rbac",
            "admin RBAC allows pool reads while protecting mutations",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-routing",
            "exact-host-beats-wildcard",
            "exact host routes beat wildcard routes",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-routing",
            "leading-dot-host-falls-back",
            "empty host labels do not match wildcard routes",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-routing",
            "longer-path-prefix-wins",
            "longer path prefixes beat shorter matches",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-routing",
            "replace-prefix",
            "route prefix replacement rewrites upstream paths",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-routing",
            "rewrite-action",
            "route rewrite action rewrites upstream path and query",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-routing",
            "redirect-action",
            "route redirect action returns terminal Location",
            ExpectStart::Success,
            Needs::default(),
            None,
        ),
        docker_case(
            "proxy-routing",
            "host-port-and-case-normalization",
            "host matching normalizes case and strips ordinary ports",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-routing",
            "wildcard-suffix-specificity",
            "more specific wildcard host suffixes win over broader wildcards",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-routing",
            "prefix-boundary-no-partial-match",
            "route prefixes match only full path segment boundaries",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-routing",
            "equal-specificity-keeps-route-order",
            "equal host and path specificity keeps the first configured route",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-routing",
            "host-header-not-tls-sni-selects-route",
            "HTTPS routing uses the Host header rather than TLS SNI",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-routing",
            "replace-prefix-exact-root-and-query",
            "prefix replacement preserves query strings on exact prefix matches",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-routing",
            "no-matching-route-fails-closed",
            "unmatched hosts and paths return no matching route",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-routing",
            "pool-only-route-forwards",
            "routes can forward through an upstream pool without direct upstream entries",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-routing",
            "route-upstream-http-version-h2-override",
            "route-level upstream HTTP version override can force HTTP/2",
            ExpectStart::Success,
            Needs {
                h2_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-headers",
            "forwarded-and-host-defaults",
            "default upstream Host and forwarded headers are stable",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-headers",
            "waf-request-header-mutations",
            "WAF request header set/remove actions reach upstream",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-headers",
            "security-response-headers",
            "configured response security headers are added to downstream responses",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-upstream-tls",
            "trusted-https-upstream",
            "trusted upstream CA allows HTTPS forwarding",
            ExpectStart::Success,
            Needs {
                https_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-upstream-tls",
            "untrusted-https-upstream-fails",
            "untrusted HTTPS upstream certificates fail closed at proxy boundary",
            ExpectStart::Success,
            Needs {
                https_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "proxy-upstream-tls",
            "health-check-tls-policy",
            "health-check-only CA roots do not weaken forwarding TLS verification",
            ExpectStart::Success,
            Needs {
                https_upstream: true,
                ..Needs::default()
            },
            None,
        ),
    ]
}

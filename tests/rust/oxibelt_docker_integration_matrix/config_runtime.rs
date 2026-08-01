use crate::{DockerCase, ExpectStart, Needs, docker_case, root_netport_switcher_case};

pub(super) fn docker_cases() -> Vec<DockerCase> {
  vec![
    docker_case(
      "config-valid",
      "minimal-http1",
      "minimal HTTP/1 startup and forwarding",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "config-valid",
      "edge-secure-medium-v1",
      "edge-secure-medium v1 expands, starts, and forwards",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "config-invalid",
      "edge-secure-medium-v2-missing-manifest",
      "edge-secure-medium v2 fails closed without a filesystem expectation",
      ExpectStart::Failure,
      Needs::default(),
      Some(
        "edge-secure-medium v2 requires runtime.hardening.filesystem_manifest.expected_digest and expected_writable_paths",
      ),
    ),
    docker_case(
      "config-valid",
      "modular-include-glob",
      "configuration split through sorted include globs",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "config-valid",
      "multi-listener-binds",
      "plural HTTPS and plain HTTP listener binds serve on every configured port",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    root_netport_switcher_case(docker_case(
      "config-valid",
      "root-netport-switcher-https-443",
      "root netport switcher starts unprivileged OxiBelt and serves HTTPS on port 443",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    )),
    docker_case(
      "config-valid",
      "static-ocsp-compression-off",
      "static OCSP file with compression disabled",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "config-valid",
      "static-only-route-startup",
      "static-only route starts without direct upstream configuration",
      ExpectStart::Success,
      Needs::default(),
      None,
    ),
    docker_case(
      "config-valid",
      "https-grease-trusted-ca",
      "HTTPS upstream with trusted CA and ECH GREASE",
      ExpectStart::Success,
      Needs {
        https_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "config-invalid",
      "strict-unknown-field",
      "strict configuration rejects unknown merged fields by default",
      ExpectStart::Failure,
      Needs::default(),
      Some("configuration contains unknown field"),
    ),
    docker_case(
      "config-invalid",
      "emit-mitigation-udf-payload-exclusion",
      "mitigation field validation rejects UDF payload indirection",
      ExpectStart::Failure,
      Needs::default(),
      Some("cannot read request, response, or stream body bytes"),
    ),
    docker_case(
      "listener-http",
      "redirect-to-https",
      "plain HTTP listener redirects to HTTPS",
      ExpectStart::Success,
      Needs::default(),
      None,
    ),
    docker_case(
      "listener-http",
      "plain-proxy-mode",
      "plain HTTP listener can proxy requests without TLS",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "limits",
      "request-body-limit",
      "configured request body limit rejects oversized requests before upstream forwarding",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "limits",
      "route-request-body-limit",
      "route request body limit overrides the global request body limit",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "limits",
      "http3-content-length-zero-body-limit",
      "HTTP/3 Content-Length zero requests still apply body limits to DATA frames",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "limits",
      "rate-limit-bucket-cap",
      "local rate-limit bucket caps reject attacker-controlled token/path churn",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "buffering",
      "request-spool",
      "request body spooling preserves uploads and cleans temp files after success and rejection",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "buffering",
      "response-spool",
      "response body spooling protects upstream and cleans temp files after success and rejection",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "timeouts",
      "route-first-byte-timeout",
      "route-level upstream first-byte timeout can fail one route while another succeeds",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "timeouts",
      "route-client-body-timeout",
      "route-level client body timeout rejects a slow upload",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "timeouts",
      "zero-length-body-timeout",
      "HTTP/2 zero-length bodies that delay END_STREAM still hit client body timeout",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "timeouts",
      "route-upstream-read-timeout",
      "route-level upstream read timeout fails a stalled buffered response",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "timeouts",
      "route-upstream-send-timeout",
      "route-level upstream send timeout aborts a backpressured request body",
      ExpectStart::Success,
      Needs {
        h1_stall_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "hot-reload",
      "oxirule-config",
      "OxiRule-only hot reload updates inline WAF policy without restarting",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "hot-reload",
      "downstream-tls-only",
      "downstream TLS-only hot reload imports renewed certificate material",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "hot-reload",
      "full-config-tls-listener-rebind",
      "full hot reload updates configuration, TLS material, and listener bind port",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        alt_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "hot-reload",
      "telemetry-tracing-disable",
      "full hot reload rebuilds telemetry tracing and stops traceparent propagation when disabled",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "hot-reload",
      "admin-listener-rebind",
      "full hot reload rebinds the admin listener and closes the old admin port",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "hot-reload",
      "graceful-http-drain",
      "full hot reload drains old HTTP/1 and HTTP/2 listener generations",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        alt_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "hot-reload",
      "graceful-upgrade-drain",
      "full hot reload protects upgraded connections during old listener drain",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        alt_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "hot-reload",
      "webtransport-stale-snapshot-drain",
      "full hot reload rejects new WebTransport-connection requests on a stale snapshot",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        alt_upstream: true,
        protocol_probe: true,
        webtransport_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "lifecycle",
      "admin-drain-readiness",
      "admin lifecycle drain flips readiness, rejects new requests, and preserves in-flight work",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "lifecycle",
      "process-signal-h2-h3-drain",
      "process pre-drain and termination preserve active HTTP/2 and HTTP/3 requests",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "config-invalid",
      "no-http-versions",
      "listener validation rejects all downstream HTTP versions and SNI forwarding protocols disabled",
      ExpectStart::Failure,
      Needs::default(),
      Some("at least one downstream HTTP version or SNI forwarding protocol must be enabled"),
    ),
    docker_case(
      "config-invalid",
      "privileged-port-unprivileged",
      "unprivileged mode rejects privileged listener ports",
      ExpectStart::Failure,
      Needs::default(),
      Some("requires a privileged port"),
    ),
    docker_case(
      "config-invalid",
      "accept-workers-without-reuseport",
      "multi-worker TCP accept requires SO_REUSEPORT",
      ExpectStart::Failure,
      Needs::default(),
      Some("runtime.accept.reuse_port must be true"),
    ),
    docker_case(
      "config-invalid",
      "static-ocsp-missing-response",
      "static OCSP mode requires a response file",
      ExpectStart::Failure,
      Needs::default(),
      Some("tls.ocsp.response_file is required"),
    ),
    docker_case(
      "config-invalid",
      "http3-upstream-requires-https",
      "HTTP/3 upstream mode rejects cleartext origins",
      ExpectStart::Failure,
      Needs::default(),
      Some("must use https:// origin when max_http_version = \"h3\""),
    ),
    docker_case(
      "config-invalid",
      "quic-receive-window-above-dynamic-cap",
      "QUIC receive window rejects values above the stream concurrency cap",
      ExpectStart::Failure,
      Needs::default(),
      Some(
        "quic.transport.receive_window_bytes must be at most 3072 based on quic.transport.stream_receive_window_bytes",
      ),
    ),
    docker_case(
      "config-invalid",
      "ech-config-list-missing-file",
      "ECH config-list mode requires a file",
      ExpectStart::Failure,
      Needs::default(),
      Some("tls.ech.config_list_file is required"),
    ),
    docker_case(
      "config-invalid",
      "unsafe-route-path",
      "route path validation rejects dot segments",
      ExpectStart::Failure,
      Needs::default(),
      Some("must not contain dot segments"),
    ),
    docker_case(
      "config-invalid",
      "crs-allowlist-header-selector",
      "CRS allowlists reject client-spoofable request header selectors",
      ExpectStart::Failure,
      Needs::default(),
      Some("header_equals is not supported because request headers are client-controlled"),
    ),
    docker_case(
      "config-invalid",
      "legacy-load-balancing-algorithm",
      "legacy upstream pool load-balancing algorithms are rejected",
      ExpectStart::Failure,
      Needs::default(),
      Some("round_robin"),
    ),
    docker_case(
      "config-invalid",
      "route-multiple-targets",
      "routes must configure exactly one target kind",
      ExpectStart::Failure,
      Needs::default(),
      Some("must set exactly one of upstream, upstream_pool, static_root, or actions.redirect"),
    ),
    docker_case(
      "config-invalid",
      "route-action-invalid",
      "route rewrite and redirect actions reject invalid combinations",
      ExpectStart::Failure,
      Needs::default(),
      Some("cannot set replace_prefix_with when actions.rewrite is configured"),
    ),
    docker_case(
      "config-invalid",
      "route-unknown-references",
      "routes reject unknown target references",
      ExpectStart::Failure,
      Needs::default(),
      Some("references unknown upstream missing-upstream"),
    ),
  ]
}

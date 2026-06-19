use crate::{DockerCase, ExpectStart, Needs, docker_case};

pub(super) fn docker_cases() -> Vec<DockerCase> {
  vec![
    docker_case(
      "protocol-operations",
      "generic-upgrade",
      "generic HTTP/1.1 upgrade tunnels bytes to the selected upstream",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-operations",
      "websocket-upgrade-echo",
      "WebSocket upgrade echoes binary payloads and rejects upstreams with WebSocket disabled",
      ExpectStart::Success,
      Needs {
        websocket_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-operations",
      "connect-tunnel",
      "HTTP/1.1 CONNECT tunnels only to the route-selected upstream origin",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-operations",
      "stream-listener",
      "TCP stream listener proxies raw HTTP to a fixed target",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-operations",
      "proxy-protocol-egress-v1",
      "TCP upstream PROXY protocol egress writes the client address before HTTP",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-operations",
      "grpc-web-h2c",
      "gRPC-Web requests are translated to HTTP/2 cleartext upstreams",
      ExpectStart::Success,
      Needs {
        h2c_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-operations",
      "grpc-active-health",
      "active gRPC health checks can probe an HTTP/2 upstream pool",
      ExpectStart::Success,
      Needs {
        h2c_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-startup",
      "http1-only",
      "HTTP/1-only downstream listener starts and forwards",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-startup",
      "http1-http2",
      "HTTP/1 and HTTP/2 downstream listener starts",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-startup",
      "http3-enabled-startup",
      "HTTP/3-enabled listener starts alongside TCP listeners",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "sni-forwarding",
      "tcp-and-quic-passthrough",
      "SNI forwarding preserves local routes and forwards TCP TLS plus same-port QUIC",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        https_upstream: true,
        h3_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "sni-forwarding",
      "resource-limits",
      "SNI forwarding bounds partial TLS and QUIC pre-classification resources",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        https_upstream: true,
        h3_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-startup",
      "listener-reuseport-workers",
      "in-process SO_REUSEPORT accept workers start and forward",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-proxying",
      "downstream-h2-upstream-h1",
      "downstream HTTP/2 over HTTPS forwards to an HTTP/1.1 upstream",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-proxying",
      "downstream-tls-http-suite",
      "one downstream TLS config proxies HTTP/1.1, HTTP/2, and HTTP/3 with stable forwarded metadata",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-proxying",
      "remote-signer-downstream-tls-http-suite",
      "remote signer downstream TLS proxies HTTP/1.1, HTTP/2, and HTTP/3 with stable forwarded metadata",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        protocol_probe: true,
        remote_signer: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-proxying",
      "downstream-h2-adaptive-window-default",
      "downstream HTTP/2 uses the default adaptive flow-control window",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-proxying",
      "downstream-h2-upstream-h2",
      "downstream HTTP/2 over HTTPS forwards to an HTTP/2 upstream",
      ExpectStart::Success,
      Needs {
        h2_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-proxying",
      "downstream-h2-upstream-h2c",
      "downstream HTTP/2 over HTTPS forwards to a cleartext HTTP/2 upstream",
      ExpectStart::Success,
      Needs {
        h2c_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-proxying",
      "downstream-h2-upstream-h3-pooled",
      "downstream HTTP/2 forwards sequential requests over one pooled HTTP/3 upstream connection",
      ExpectStart::Success,
      Needs {
        h3_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-proxying",
      "downstream-h2-upstream-h3-one-shot",
      "downstream HTTP/2 forwards ordinary HTTP/3 upstream requests without the H3 pool",
      ExpectStart::Success,
      Needs {
        h3_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-proxying",
      "downstream-h2-upstream-h3-pooled-reconnect",
      "pooled upstream HTTP/3 entries are discarded and reconnected after the upstream closes",
      ExpectStart::Success,
      Needs {
        h3_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-proxying",
      "alt-svc-https-response",
      "HTTPS HTTP/1.1 and HTTP/2 responses advertise HTTP/3 with Alt-Svc",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-proxying",
      "alt-svc-skip-rules",
      "Alt-Svc is not advertised on plain HTTP, downstream HTTP/3, or 101 responses",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-proxying",
      "downstream-h3-retry",
      "downstream HTTP/3 requests succeed when QUIC Retry is enabled",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-proxying",
      "downstream-h3-zero-rtt-policy",
      "HTTP/3 early-data policy ignores spoofed Early-Data headers",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-proxying",
      "downstream-h3-upstream-h1",
      "downstream HTTP/3 over HTTPS forwards to an HTTP/1.1 upstream",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-proxying",
      "downstream-h3-bounded-receive-window",
      "downstream HTTP/3 forwards a request body with a bounded QUIC receive window",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-proxying",
      "downstream-h3-upstream-h2",
      "downstream HTTP/3 over HTTPS forwards to an HTTP/2 upstream",
      ExpectStart::Success,
      Needs {
        h2_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-proxying",
      "downstream-h3-upstream-h2c",
      "downstream HTTP/3 over HTTPS forwards to a cleartext HTTP/2 upstream",
      ExpectStart::Success,
      Needs {
        h2c_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "protocol-startup",
      "pq-tls-groups",
      "downstream TLS negotiates both X25519 and X25519MLKEM768 groups",
      ExpectStart::Success,
      Needs {
        pq_probe: true,
        ..Needs::default()
      },
      None,
    ),
  ]
}

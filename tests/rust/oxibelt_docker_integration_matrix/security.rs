use crate::{DockerCase, ExpectStart, Needs, docker_case};

pub(super) fn docker_cases() -> Vec<DockerCase> {
  vec![
    docker_case(
      "security",
      "external-auth-response-body-timeout",
      "external auth timeout covers response body collection",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "security",
      "grpc-timeout-pool-health",
      "client gRPC deadlines do not poison passive upstream pool health",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        alt_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "security",
      "fast-general-proxy-equivalence",
      "plain proxy fast path and forced general path preserve security semantics",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "security",
      "static-openat2-blocking-isolated",
      "blocking Linux static-file opens do not occupy async runtime workers",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "security",
      "static-file-symlink-race",
      "static file serving does not leak out-of-root files during symlink swaps",
      ExpectStart::Success,
      Needs::default(),
      None,
    ),
    docker_case(
      "security",
      "static-hot-cache-security",
      "static hot-object cache revalidates through secure static root resolution",
      ExpectStart::Success,
      Needs::default(),
      None,
    ),
    docker_case(
      "security",
      "static-sendfile-general-equivalence",
      "plaintext static sendfile fast path matches HTTPS static general path",
      ExpectStart::Success,
      Needs::default(),
      None,
    ),
    docker_case(
      "security",
      "static-sendfile-real-ip-waf",
      "plaintext static sendfile WAF uses resolved Real-IP client identity",
      ExpectStart::Success,
      Needs::default(),
      None,
    ),
    docker_case(
      "security",
      "static-sendfile-response-timeout",
      "plaintext static sendfile responses release connection permits after downstream send timeout",
      ExpectStart::Success,
      Needs::default(),
      None,
    ),
    docker_case(
      "security",
      "connection-task-registry-reaping",
      "completed downstream connection tasks are reaped during long-lived listener generations",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "security",
      "tls-stateful-resumption-cache-bounded",
      "stateful downstream TLS resumption cache stays bounded under repeated resumes",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "security",
      "dpi-bypass-clienthello-fragmentation",
      "DPI-bypass ClientHello fragmentation still terminates TLS and classifies SNI forwarding",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        https_upstream: true,
        protocol_probe: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "security",
      "webtransport-session-limit",
      "multiplexed WebTransport sessions are limited per client on one HTTP/3 connection",
      ExpectStart::Success,
      Needs {
        protocol_probe: true,
        webtransport_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "security",
      "webtransport-real-ip-connection-limit",
      "WebTransport sessions honor normal Real-IP connection limits",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        protocol_probe: true,
        webtransport_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "security",
      "websocket-stream-waf-frame-limit",
      "WebSocket stream WAF rejects frames above the inspection limit",
      ExpectStart::Success,
      Needs::default(),
      None,
    ),
    docker_case(
      "security",
      "turn-udp-session-cleanup",
      "TURN UDP proxy sessions close upstream sockets after idle expiration",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "security",
      "webrtc-turn-auth-transports",
      "WebRTC TURN proxy validates long-term auth over UDP, TCP, and TLS transports",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        protocol_probe: true,
        turn_udp_upstream: true,
        turn_tcp_upstream: true,
        turn_tls_upstream: true,
        ..Needs::default()
      },
      None,
    ),
  ]
}

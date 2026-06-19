use crate::{DockerCase, ExpectStart, Needs, docker_case};

pub(super) fn docker_cases() -> Vec<DockerCase> {
    vec![
        docker_case(
            "ops",
            "metrics-and-health",
            "local metrics and health listeners expose operational endpoints",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "ops",
            "observability-detail",
            "detailed Prometheus metrics, tracecontext propagation, and admin-only WAF cost telemetry work in Docker",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "ops",
            "admin-config-file-sync",
            "Admin API config load/rollback, file sync, fine-grained RBAC, and downstream TLS reload work in Docker",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "ops",
            "admin-operation-webtransport",
            "Admin HTTP/3 WebTransport operation events and data-plane WebTransport drain rules work in Docker",
            ExpectStart::Success,
            Needs {
                protocol_probe: true,
                webtransport_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "ops",
            "kernel-extension-installer",
            "kernel extension installer stages and verifies Linux 7.0.x host tuning files",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "ops",
            "system-access-log-stdout",
            "system-wide access log emits structured stdout records without WAF rules",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                ..Needs::default()
            },
            None,
        ),
    ]
}

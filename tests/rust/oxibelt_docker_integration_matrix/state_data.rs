use crate::{DockerCase, ExpectStart, Needs, docker_case};

pub(super) fn docker_cases() -> Vec<DockerCase> {
    vec![
        docker_case(
            "database-access-log",
            "postgres-mtls",
            "OxiRule access logs are written to PostgreSQL over verified mTLS",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                postgres: true,
                postgres_mtls: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "database-access-log",
            "system-postgres",
            "system-wide access logs use a separate PostgreSQL sink",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                postgres: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "database-mitigation",
            "managed-postgres",
            "OxiRule mitigation events aggregate into a managed PostgreSQL table",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                postgres: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "database-mitigation",
            "existing-postgres",
            "OxiRule mitigation events write to an existing minimal PostgreSQL table",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                postgres: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "shared-state",
            "redis-valkey-cluster-state",
            "Redis/Valkey shared state coordinates two proxy instances",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                redis: true,
                second_proxy: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "shared-state",
            "postgres-cluster-state",
            "PostgreSQL shared state coordinates representative cluster paths",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                alt_upstream: true,
                postgres: true,
                second_proxy: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "dynamic-policy",
            "postgres-snapshot",
            "PostgreSQL dynamic policy snapshot rejects and rate-limits without hot-path DB reads",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                postgres: true,
                ..Needs::default()
            },
            None,
        ),
        docker_case(
            "dynamic-policy",
            "automation-api",
            "signed Admin dynamic policy automation API creates, imports, disables, and verifies rows",
            ExpectStart::Success,
            Needs {
                http_upstream: true,
                postgres: true,
                ..Needs::default()
            },
            None,
        ),
    ]
}

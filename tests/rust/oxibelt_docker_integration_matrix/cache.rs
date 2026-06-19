use crate::{DockerCase, ExpectStart, Needs, docker_case};

pub(super) fn docker_cases() -> Vec<DockerCase> {
  vec![
    docker_case(
      "cache",
      "tmpfs-route-cache",
      "tmpfs cache serves a route response after the upstream disappears",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "route-named-cache-policy-isolated",
      "route named cache policy hits independently from default cache",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "http-semantics-revalidate",
      "cache revalidates stale entries with ETag validators",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "vary-header-isolation",
      "cache keeps Vary header variants isolated",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "rfc9111-semantics",
      "cache follows RFC 9111 freshness, validators, and no-cache request semantics",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "range-hit",
      "cache serves byte ranges from a stored full response",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "multi-range-hit",
      "cache serves multipart byte ranges from a stored full response",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "memory-then-disk-fallback",
      "memory_then_disk cache falls back to disk when memory budget is exhausted",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "disk-policy-by-mime",
      "cache policy stores selected response MIME types on disk",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "admin-purge-tls-sni",
      "admin API purges cache over TLS with SNI certificate selection",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "admin-purge-docker-plaintext-allowlist",
      "admin API can allow plaintext purge from Docker bridge CIDRs",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "purge-audit",
      "cache purge emits audit logs without raw URI query leakage",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        postgres: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "tag-purge",
      "admin API purges cache entries by Surrogate-Key tag",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "signed-purge",
      "HMAC signed cache purge works without bearer credentials and rejects replay",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "tenant-partition-isolation",
      "cache partition keys isolate tenants sharing one URI",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "surrogate-control",
      "Surrogate-Control overrides origin no-store and is stripped downstream",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "vary-explosion-rejection",
      "Vary variant caps reject extra variants without poisoning cached variants",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "json-warming",
      "admin JSON cache warming stores a GET response before client traffic",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "large-object-cache",
      "large cacheable objects survive upstream removal",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "large-object-over-memory-not-cached",
      "cache streams responses larger than the proxy memory body limit without storing them",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "huge-object-streaming-disk",
      "disk cache streams huge cacheable responses and serves them after upstream removal",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "streaming-disk-reservation",
      "disk cache accounts concurrent streaming temp files against disk limits",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "disk-index-churn",
      "disk cache index remains coherent after eviction churn",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "lock-starvation",
      "streaming cache fills keep collapsed forwarding waiters from timing out",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "shared-streaming-disk-l2",
      "streaming disk cache fills publish chunked shared L2 entries",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        redis: true,
        second_proxy: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "background-refresh",
      "stale-while-revalidate serves stale while refreshing in the background",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "shared-background-refresh-disabled",
      "shared cache stale hits honor disabled background refresh policy",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        redis: true,
        second_proxy: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "admission-stale-errors",
      "cache admission policy and stale-if-error status handling work together",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
    docker_case(
      "cache",
      "collapsed-forwarding-metrics",
      "collapsed forwarding exposes waiter metrics for concurrent cache fills",
      ExpectStart::Success,
      Needs {
        http_upstream: true,
        ..Needs::default()
      },
      None,
    ),
  ]
}

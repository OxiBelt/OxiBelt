use super::*;
use crate::config::Config;

fn retry_config(raw_retry: &str, route_retry: &str) -> Config {
  let raw = format!(
    r#"
[logging]
level = "info"

[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true
worker_threads = "auto"

[runtime.accept]
workers = "auto"
reuse_port = true

[listeners]
https_bind = "127.0.0.1:8443"
http1 = true
http2 = true
http3 = false

[tls]
cert_chain = "/tmp/cert.pem"
private_key = "/tmp/key.pem"

[tls.ocsp]
mode = "disabled"

[proxy]
trusted_ca_certs = []

{raw_retry}

[[upstreams]]
name = "app"
origin = "http://app.example"

[[routes]]
name = "app"
hosts = ["example.com"]
path_prefix = "/"
upstream = "app"
{route_retry}
"#
  );
  toml::from_str(&raw).expect("config should parse")
}

fn retry_policy(raw_retry: &str, route_retry: &str, method: Method) -> EffectiveRetryPolicy {
  let config = retry_config(raw_retry, route_retry);
  EffectiveRetryPolicy::for_http_request(&config, &config.routes[0], &method)
}

fn direct_retry_policy(raw_retry: &str, route_retry: &str, method: Method) -> EffectiveRetryPolicy {
  let config = retry_config(raw_retry, route_retry);
  EffectiveRetryPolicy::for_direct_http_request(&config, &config.routes[0], &method)
}

#[test]
fn retry_on_applies_to_status_connect_and_timeout() {
  let policy = retry_policy(
    r#"
[proxy.retry]
enabled = true
on = ["503"]
"#,
    "",
    Method::GET,
  );

  assert!(policy.matches_failure(AttemptFailure::Status(StatusCode::SERVICE_UNAVAILABLE)));
  assert!(!policy.matches_failure(AttemptFailure::ConnectError));
  assert!(!policy.matches_failure(AttemptFailure::ReadTimeout));
}

#[test]
fn retry_non_idempotent_gates_http_methods() {
  let disabled = retry_policy(
    r#"
	[proxy.retry]
enabled = true
"#,
    "",
    Method::POST,
  );
  assert!(!disabled.enabled);

  let enabled = retry_policy(
    r#"
[proxy.retry]
enabled = true
retry_non_idempotent = true
"#,
    "",
    Method::POST,
  );
  assert!(enabled.enabled);
}

#[test]
fn direct_retry_policy_skips_disabled_retry_metadata() {
  let policy = direct_retry_policy(
    r#"
[proxy.retry]
enabled = false
on = ["503"]
"#,
    "",
    Method::GET,
  );

  assert!(!policy.enabled);
  assert!(!policy.matches_failure(AttemptFailure::Status(StatusCode::SERVICE_UNAVAILABLE)));
}

#[test]
fn direct_retry_policy_keeps_enabled_retry_conditions() {
  let policy = direct_retry_policy(
    r#"
[proxy.retry]
enabled = true
on = ["503"]
"#,
    "",
    Method::GET,
  );

  assert!(policy.enabled);
  assert!(policy.matches_failure(AttemptFailure::Status(StatusCode::SERVICE_UNAVAILABLE)));
}

#[test]
fn direct_retry_policy_honors_route_enable_override() {
  let policy = direct_retry_policy(
    r#"
[proxy.retry]
enabled = false
on = ["502"]
"#,
    r#"

[routes.retry]
enabled = true
on = ["503"]
"#,
    Method::GET,
  );

  assert!(policy.enabled);
  assert!(policy.matches_failure(AttemptFailure::Status(StatusCode::SERVICE_UNAVAILABLE)));
  assert!(!policy.matches_failure(AttemptFailure::Status(StatusCode::BAD_GATEWAY)));
}

#[test]
fn direct_retry_policy_keeps_non_idempotent_gate() {
  let policy = direct_retry_policy(
    r#"
[proxy.retry]
enabled = false
"#,
    r#"

[routes.retry]
enabled = true
on = ["503"]
"#,
    Method::POST,
  );

  assert!(!policy.enabled);
  assert!(!policy.matches_failure(AttemptFailure::Status(StatusCode::SERVICE_UNAVAILABLE)));
}

#[test]
fn route_retry_overrides_global_policy() {
  let policy = retry_policy(
    r#"
[proxy.retry]
enabled = false
tries = 2
total_budget_ms = 5000
"#,
    r#"

[routes.retry]
enabled = true
tries = 4
total_budget_ms = 250
per_attempt_timeout_ms = 100
"#,
    Method::GET,
  );

  assert!(policy.enabled);
  assert_eq!(policy.tries, 4);
  assert_eq!(policy.total_budget, Duration::from_millis(250));
  assert_eq!(policy.per_attempt_timeout, Some(Duration::from_millis(100)));
}

#[test]
fn enabled_breakers_supply_bounded_jittered_retry_defaults() {
  let policy = retry_policy(
    r#"
[proxy.retry]
enabled = true
"#,
    "",
    Method::GET,
  );
  assert_eq!(policy.backoff_base, Duration::from_millis(25));
  assert_eq!(policy.backoff_max, Duration::from_millis(250));
  assert!(policy.jitter);
}

#[test]
fn pool_passive_health_reporting_requires_retry_enabled_policy() {
  let route_disabled = retry_policy(
    r#"
[proxy.retry]
enabled = true
on = ["503"]
"#,
    r#"

[routes.retry]
enabled = false
"#,
    Method::GET,
  );
  assert!(!route_disabled.enabled);
  assert!(!should_report_pool_passive_failure(&route_disabled));
  assert!(!should_report_pool_response_success(
    &route_disabled,
    StatusCode::SERVICE_UNAVAILABLE
  ));
  assert!(should_report_pool_response_success(
    &route_disabled,
    StatusCode::OK
  ));

  let method_disabled = retry_policy(
    r#"
[proxy.retry]
enabled = true
on = ["503"]
"#,
    "",
    Method::POST,
  );
  assert!(!method_disabled.enabled);
  assert!(!should_report_pool_passive_failure(&method_disabled));
}

#[test]
fn pool_passive_health_reporting_honors_report_flag() {
  let policy = retry_policy(
    r#"
[proxy.retry]
enabled = true
on = ["503"]
report_passive_health = false
"#,
    "",
    Method::GET,
  );

  assert!(policy.enabled);
  assert!(!should_report_pool_passive_failure(&policy));
  assert!(!should_report_pool_response_success(
    &policy,
    StatusCode::SERVICE_UNAVAILABLE
  ));
}

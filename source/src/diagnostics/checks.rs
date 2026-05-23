use std::net::IpAddr;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;

use crate::config::{AdminTransportMode, Config, TlsClientAuthMode};
use crate::waf::{WafActionConfig, WafMode};

use super::{DiagnosticReport, DiagnosticSeverity};

pub(super) fn diagnose_admin(config: &Config, report: &mut DiagnosticReport) {
  if !config.admin.enabled {
    return;
  }
  let public_bind = is_public_ip(config.admin.bind.ip());
  if matches!(config.admin.transport, AdminTransportMode::Plaintext) && public_bind {
    report.push(
      DiagnosticSeverity::Critical,
      "admin.plaintext_public",
      "admin",
      "admin.bind",
      "admin plaintext transport is bound to a public address",
      "Use TLS, bind admin to loopback, or restrict access with a private control-plane network.",
    );
  }
  if matches!(
    config.admin.transport,
    AdminTransportMode::PlaintextAllowlist
  ) && config
    .admin
    .plaintext_allowed_source_cidrs
    .iter()
    .any(|cidr| cidr_is_any(cidr))
  {
    report.push(
      DiagnosticSeverity::Critical,
      "admin.plaintext_broad_allowlist",
      "admin",
      "admin.plaintext_allowed_source_cidrs",
      "admin plaintext allowlist includes an all-address CIDR",
      "Restrict plaintext admin access to loopback or a narrow private management CIDR.",
    );
  }
  if public_bind
    && config.admin.tls.enabled
    && config.admin.tls.client_auth.mode != TlsClientAuthMode::Require
  {
    report.push(
      DiagnosticSeverity::Warning,
      "admin.public_without_mtls",
      "admin",
      "admin.tls.client_auth",
      "admin is reachable on a non-loopback address without required client certificates",
      "Set admin.tls.client_auth.mode = \"require\" with CA roots or keep admin on loopback.",
    );
  }
  if !config.ipm.enabled {
    report.push(
      DiagnosticSeverity::Warning,
      "admin.bootstrap_token_only",
      "admin",
      "ipm.enabled",
      "admin uses the legacy bootstrap bearer token authorization path",
      "Enable IPM and grant separate least-privilege policies for diagnostics, config, WAF, and cache operations.",
    );
  }
}

pub(super) fn diagnose_ipm(config: &Config, report: &mut DiagnosticReport) {
  if !config.ipm.enabled {
    return;
  }
  let has_wildcard_allow = config.ipm.policies.iter().any(|policy| {
    policy.statements.iter().any(|statement| {
      statement.effect == crate::config::IpmPolicyEffect::Allow
        && statement.actions.iter().any(|action| action == "*")
    })
  });
  let has_diagnostics_policy = config.ipm.policies.iter().any(|policy| {
    policy.statements.iter().any(|statement| {
      statement.actions.iter().any(|action| {
        action == "diagnostics:*"
          || action == "diagnostics:ReadPreflight"
          || action == "diagnostics:RunPreflight"
      })
    })
  });
  if has_wildcard_allow && !has_diagnostics_policy {
    report.push(
      DiagnosticSeverity::Warning,
      "ipm.diagnostics_not_separated",
      "ipm",
      "ipm.policies",
      "IPM has wildcard allow policies but no explicit diagnostics policy",
      "Add a diagnostics-only policy so preflight access can be delegated without full admin privileges.",
    );
  }
}

pub(super) fn diagnose_ops_listeners(config: &Config, report: &mut DiagnosticReport) {
  if !config.metrics.enabled {
    report.push(
      DiagnosticSeverity::Warning,
      "metrics.disabled",
      "ops",
      "metrics.enabled",
      "Prometheus metrics are disabled",
      "Enable metrics on loopback or a protected management network before production deployment.",
    );
  } else if is_public_ip(config.metrics.bind.ip()) {
    report.push(
      DiagnosticSeverity::Error,
      "metrics.public_bind",
      "ops",
      "metrics.bind",
      "metrics listener is bound to a non-loopback address",
      "Bind metrics to 127.0.0.1 or protect it behind a strict network allowlist.",
    );
  }

  if !config.health.enabled {
    report.push(
      DiagnosticSeverity::Warning,
      "health.disabled",
      "ops",
      "health.enabled",
      "health endpoints are disabled",
      "Enable readiness and liveness endpoints for deployment orchestration.",
    );
  } else if is_public_ip(config.health.bind.ip()) {
    report.push(
      DiagnosticSeverity::Warning,
      "health.public_bind",
      "ops",
      "health.bind",
      "health listener is bound to a non-loopback address",
      "Bind health to loopback or ensure it is reachable only by trusted load balancers.",
    );
  }
}

pub(super) fn diagnose_real_ip(config: &Config, report: &mut DiagnosticReport) {
  if !config.proxy.real_ip.enabled {
    return;
  }
  if config.proxy.real_ip.trusted_proxies.is_empty() {
    report.push(
      DiagnosticSeverity::Warning,
      "real_ip.no_trusted_proxies",
      "identity",
      "proxy.real_ip.trusted_proxies",
      "real IP processing is enabled without trusted proxy CIDRs",
      "Set explicit trusted proxy CIDRs for the load balancers allowed to provide forwarded client IP metadata.",
    );
  }
  if !config.proxy.real_ip.fail_on_untrusted_forwarded_headers {
    report.push(
      DiagnosticSeverity::Warning,
      "real_ip.untrusted_forwarded_headers_allowed",
      "identity",
      "proxy.real_ip.fail_on_untrusted_forwarded_headers",
      "untrusted forwarded client IP headers are ignored instead of rejected",
      "Set fail_on_untrusted_forwarded_headers = true to make spoofing attempts visible and fail closed.",
    );
  }
  for cidr in &config.proxy.real_ip.trusted_proxies {
    if cidr_is_any(cidr) {
      report.push(
        DiagnosticSeverity::Error,
        "real_ip.trusts_everywhere",
        "identity",
        format!("proxy.real_ip.trusted_proxies[{cidr}]"),
        "real IP trusts all source addresses",
        "Replace all-address CIDRs with the exact load balancer or CDN proxy ranges.",
      );
    } else if broad_cidr(cidr) {
      report.push(
        DiagnosticSeverity::Warning,
        "real_ip.broad_trusted_proxy",
        "identity",
        format!("proxy.real_ip.trusted_proxies[{cidr}]"),
        "real IP trusted proxy CIDR is broad",
        "Prefer the narrowest CIDR ranges that cover only your trusted proxy infrastructure.",
      );
    }
  }
}

pub(super) fn diagnose_waf(config: &Config, report: &mut DiagnosticReport) {
  if !config.waf.enabled {
    report.push(
      DiagnosticSeverity::Warning,
      "waf.disabled",
      "waf",
      "waf.enabled",
      "WAF is disabled",
      "Enable WAF and deploy request rules or CRS before exposing public traffic.",
    );
    return;
  }
  if config.waf.mode == WafMode::Monitor {
    report.push(
      DiagnosticSeverity::Warning,
      "waf.monitor_mode",
      "waf",
      "waf.mode",
      "global WAF mode is monitor",
      "Switch to enforcing after reviewing false positives.",
    );
  }
  if config.waf.crs.enabled && config.waf.crs.mode == WafMode::Monitor {
    report.push(
      DiagnosticSeverity::Warning,
      "waf.crs_monitor_mode",
      "waf",
      "waf.crs.mode",
      "CRS is enabled in monitor mode",
      "Move CRS to enforcing after tuning allowlists and rule overrides.",
    );
  }
  for rule in &config.waf.rules {
    if rule.mode == Some(WafMode::Monitor) {
      report.push(
        DiagnosticSeverity::Info,
        "waf.rule_monitor_mode",
        "waf",
        format!("waf.rules.{}", rule.name),
        "a global WAF rule is pinned to monitor mode",
        "Confirm this is intentional before production rollout.",
      );
    }
  }
  for route in &config.routes {
    for rule in &route.waf.rules {
      if rule.mode == Some(WafMode::Monitor) {
        report.push(
          DiagnosticSeverity::Info,
          "waf.route_rule_monitor_mode",
          "waf",
          format!("routes.{}.waf.rules.{}", route.name, rule.name),
          "a route WAF rule is pinned to monitor mode",
          "Confirm this is intentional before production rollout.",
        );
      }
    }
  }
}

pub(super) fn diagnose_shared_state(config: &Config, report: &mut DiagnosticReport) {
  if config.shared_state.enabled {
    return;
  }
  if !config.rate_limits.is_empty() {
    report.push(
      DiagnosticSeverity::Warning,
      "shared_state.rate_limits_local",
      "shared_state",
      "rate_limits",
      "rate limits use local process state only",
      "Enable shared_state and map rate_limits_backend for multi-instance deployments.",
    );
  }
  if !config.connection_limits.is_empty() {
    report.push(
      DiagnosticSeverity::Warning,
      "shared_state.connection_limits_local",
      "shared_state",
      "connection_limits",
      "connection limits use local process state only",
      "Enable shared_state and map connection_limits_backend for multi-instance deployments.",
    );
  }
  if config.cache.enabled {
    report.push(
      DiagnosticSeverity::Info,
      "shared_state.cache_local",
      "shared_state",
      "cache",
      "cache is local to each process",
      "Configure shared_state.cache_backend when cache purge/fill coordination must span instances.",
    );
  }
  if uses_person_proof(config) {
    report.push(
      DiagnosticSeverity::Warning,
      "shared_state.person_proof_local",
      "shared_state",
      "waf.person_proof",
      "Person proof state is local to the instance",
      "Enable shared_state.person_proof_backend before running multiple public instances.",
    );
  }
}

pub(super) fn diagnose_cache(config: &Config, report: &mut DiagnosticReport) {
  if !config.cache.enabled {
    return;
  }
  check_cache_key(report, "cache.cache_key", &config.cache.cache_key);
  for policy in &config.cache.policies {
    let key = policy
      .cache_key
      .as_deref()
      .unwrap_or(&config.cache.cache_key);
    check_cache_key(
      report,
      &format!("cache.policies.{}.cache_key", policy.name),
      key,
    );
  }
  if !header_list_contains(&config.cache.bypass_request_headers, "authorization")
    || !header_list_contains(&config.cache.bypass_request_headers, "cookie")
  {
    report.push(
      DiagnosticSeverity::Error,
      "cache.secret_headers_not_bypassed",
      "cache",
      "cache.bypass_request_headers",
      "cache does not bypass both Authorization and Cookie requests",
      "Keep Authorization and Cookie in bypass_request_headers unless the cache key varies by a safe credential-derived value.",
    );
  }
}

fn check_cache_key(report: &mut DiagnosticReport, target: &str, key: &str) {
  if !key.contains("{host}") {
    report.push(
      DiagnosticSeverity::Error,
      "cache.key_missing_host",
      "cache",
      target,
      "cache key does not include the effective host",
      "Include {host} in cache_key to avoid cross-host cache poisoning and tenant leaks.",
    );
  }
  if !key.contains("{scheme}") {
    report.push(
      DiagnosticSeverity::Warning,
      "cache.key_missing_scheme",
      "cache",
      target,
      "cache key does not include the request scheme",
      "Include {scheme} when HTTP and HTTPS variants can differ.",
    );
  }
  if key.contains("{query}") {
    report.push(
      DiagnosticSeverity::Warning,
      "cache.key_broad_query",
      "cache",
      target,
      "cache key includes the full query string",
      "Prefer {query:name} allowlist entries for parameters that actually affect the response.",
    );
  }
}

pub(super) fn diagnose_upgrades(config: &Config, report: &mut DiagnosticReport) {
  if config.proxy.upgrades.generic_http_upgrade {
    report.push(
      DiagnosticSeverity::Warning,
      "upgrades.generic_enabled",
      "proxy",
      "proxy.upgrades.generic_http_upgrade",
      "generic HTTP upgrade support is globally enabled",
      "Keep generic upgrades disabled unless a known upstream protocol requires them.",
    );
  }
  if config.proxy.upgrades.connect_tunneling {
    report.push(
      DiagnosticSeverity::Warning,
      "upgrades.connect_enabled",
      "proxy",
      "proxy.upgrades.connect_tunneling",
      "CONNECT tunneling support is globally enabled",
      "Enable CONNECT only for explicit routes that require tunneling.",
    );
  }
  for route in &config.routes {
    if (route.connect_tunneling || route.generic_http_upgrade)
      && route.hosts.iter().any(|host| host == "*")
    {
      report.push(
        DiagnosticSeverity::Error,
        "upgrades.wildcard_route",
        "proxy",
        format!("routes.{}", route.name),
        "upgrade or CONNECT behavior is enabled on a wildcard-host route",
        "Scope upgrade and CONNECT routes to explicit hostnames and path prefixes.",
      );
    }
  }
}

pub(super) fn diagnose_remote_signer_local(config: &Config, report: &mut DiagnosticReport) {
  if !config.tls.remote_signer.enabled {
    return;
  }
  if config.tls.remote_signer.allow_tls12_unstructured_signing {
    report.push(
      DiagnosticSeverity::Warning,
      "remote_signer.tls12_unstructured",
      "tls",
      "tls.remote_signer.allow_tls12_unstructured_signing",
      "remote signer accepts TLS 1.2 unstructured signing inputs",
      "Keep TLS 1.2 unstructured signing disabled unless legacy TLS 1.2 support is required.",
    );
  }
  check_socket_permissions(
    report,
    &config.tls.remote_signer.socket_path,
    "tls.remote_signer.socket_path",
  );
}

pub(super) fn diagnose_deploy_hygiene(config: &Config, report: &mut DiagnosticReport) {
  if !config.runtime.unprivileged_mode {
    report.push(
      DiagnosticSeverity::Warning,
      "runtime.privileged_mode",
      "runtime",
      "runtime.unprivileged_mode",
      "runtime is not configured for unprivileged deployment",
      "Use an unprivileged runtime user when binding only high ports or delegated sockets.",
    );
  }
  if !config.runtime.read_only_rootfs_compatible {
    report.push(
      DiagnosticSeverity::Warning,
      "runtime.read_only_rootfs_disabled",
      "runtime",
      "runtime.read_only_rootfs_compatible",
      "read-only root filesystem compatibility is disabled",
      "Keep runtime writes under explicit cache/temp paths for container hardening.",
    );
  }
}

fn check_socket_permissions(report: &mut DiagnosticReport, path: &Path, target: &str) {
  match std::fs::symlink_metadata(path) {
    Ok(metadata) => {
      if !metadata.file_type().is_socket() {
        report.push(
          DiagnosticSeverity::Error,
          "remote_signer.socket_not_socket",
          "tls",
          target,
          "remote signer socket path exists but is not a Unix socket",
          "Point tls.remote_signer.socket_path to the signer Unix domain socket.",
        );
      }
      let mode = metadata.permissions().mode();
      if mode & 0o002 != 0 {
        report.push(
          DiagnosticSeverity::Error,
          "remote_signer.socket_world_writable",
          "tls",
          target,
          "remote signer socket is world-writable",
          "Use a restrictive socket mode such as 0660 and isolate signer group membership.",
        );
      }
    }
    Err(error) => report.push(
      DiagnosticSeverity::Error,
      "remote_signer.socket_missing",
      "tls",
      target,
      format!("remote signer socket is not available: {error}"),
      "Start the signer sidecar before production preflight or mount the socket at the configured path.",
    ),
  }

  if let Some(parent) = path.parent()
    && let Ok(metadata) = std::fs::symlink_metadata(parent)
    && metadata.permissions().mode() & 0o002 != 0
  {
    report.push(
      DiagnosticSeverity::Error,
      "remote_signer.socket_parent_world_writable",
      "tls",
      parent.display().to_string(),
      "remote signer socket parent directory is world-writable",
      "Move the socket into a directory writable only by the signer or a trusted admin group.",
    );
  }
}

fn uses_person_proof(config: &Config) -> bool {
  config.waf.rules.iter().any(rule_uses_person_proof)
    || config
      .routes
      .iter()
      .any(|route| route.waf.rules.iter().any(rule_uses_person_proof))
}

fn rule_uses_person_proof(rule: &crate::waf::WafRuleConfig) -> bool {
  rule
    .actions
    .iter()
    .any(|action| matches!(action, WafActionConfig::RequirePersonProof { .. }))
    || rule.local_rule_groups.iter().any(|group| {
      group
        .actions
        .iter()
        .any(|action| matches!(action, WafActionConfig::RequirePersonProof { .. }))
    })
}

fn is_public_ip(ip: IpAddr) -> bool {
  ip.is_unspecified() || !ip.is_loopback()
}

fn cidr_is_any(raw: &str) -> bool {
  crate::identity::Cidr::parse(raw)
    .map(|cidr| cidr.prefix() == 0)
    .unwrap_or(false)
}

fn broad_cidr(raw: &str) -> bool {
  crate::identity::Cidr::parse(raw)
    .map(|cidr| cidr.prefix() <= 8)
    .unwrap_or(false)
}

fn header_list_contains(values: &[String], name: &str) -> bool {
  values.iter().any(|value| value.eq_ignore_ascii_case(name))
}

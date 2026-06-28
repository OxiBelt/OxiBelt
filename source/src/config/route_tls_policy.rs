use std::collections::HashMap;

use anyhow::bail;

use super::{Config, TlsVersion};

pub(super) fn validate_key_exchange_policies(config: &Config) -> anyhow::Result<()> {
  let global_policy = config.tls.key_exchange_policy();
  let mut host_policies = HashMap::new();

  for route in &config.routes {
    if let Some(key_exchange_groups) = &route.tls.tls13.key_exchange_groups {
      super::validate_tls_key_exchange_groups(
        &format!("route {} tls.1_3.key_exchange_groups", route.name),
        key_exchange_groups,
        TlsVersion::Tls13,
      )?;
    }
    if let Some(key_exchange_groups) = &route.tls.tls12.key_exchange_groups {
      super::validate_tls_key_exchange_groups(
        &format!("route {} tls.1_2.key_exchange_groups", route.name),
        key_exchange_groups,
        TlsVersion::Tls12,
      )?;
    }
    if !route.tls.has_key_exchange_overrides() {
      continue;
    }
    if route.effective_path_prefix() != "/" || route.r#match.has_additional_conditions() {
      bail!(
        "route {} tls key_exchange_groups can only be set on SNI-only routes with path_prefix = \"/\" and no additional match conditions",
        route.name
      );
    }
    if route
      .hosts
      .iter()
      .any(|host| host == "*" || host.contains('*'))
    {
      bail!(
        "route {} tls key_exchange_groups can only be set on exact non-wildcard hosts",
        route.name
      );
    }
    let policy = config.tls.effective_route_key_exchange_policy(&route.tls);
    for host in &route.hosts {
      super::validate_tls_server_name(&format!("route {} hosts", route.name), host)?;
      match host_policies.entry(host.to_ascii_lowercase()) {
        std::collections::hash_map::Entry::Vacant(entry) => {
          entry.insert((route.name.as_str(), policy.clone()));
        }
        std::collections::hash_map::Entry::Occupied(entry) if entry.get().1 == policy => {}
        std::collections::hash_map::Entry::Occupied(entry) => {
          bail!(
            "route {} tls key_exchange_groups conflict with route {} for host {}",
            route.name,
            entry.get().0,
            host
          );
        }
      }
    }
  }

  for route in &config.routes {
    let policy = if route.tls.has_key_exchange_overrides() {
      config.tls.effective_route_key_exchange_policy(&route.tls)
    } else {
      global_policy.clone()
    };
    for override_host in host_policies.keys() {
      if !route
        .hosts
        .iter()
        .any(|host| route_host_matches(host, override_host))
      {
        continue;
      }
      if policy != host_policies[override_host].1 {
        bail!(
          "route {} tls key_exchange_groups conflict with SNI policy for host {}",
          route.name,
          override_host
        );
      }
    }
  }

  Ok(())
}

fn route_host_matches(pattern: &str, exact_host: &str) -> bool {
  if pattern == "*" {
    return true;
  }
  if let Some(suffix) = pattern.strip_prefix("*.") {
    let Some(prefix_len) = exact_host.len().checked_sub(suffix.len() + 1) else {
      return false;
    };
    if exact_host.as_bytes().get(prefix_len) != Some(&b'.') {
      return false;
    }
    let prefix = &exact_host[..prefix_len];
    let server_suffix = &exact_host[prefix_len + 1..];
    return !prefix.is_empty()
      && !prefix.contains('.')
      && server_suffix.eq_ignore_ascii_case(suffix);
  }
  pattern.eq_ignore_ascii_case(exact_host)
}

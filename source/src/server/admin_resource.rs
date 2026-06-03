//! Admin resource-name helpers for IPM authorization.
//! Centralized names keep handler checks aligned with policy statements.

pub(super) fn cache_policy(policy: &str) -> String {
  format!("policy/{}", component(policy))
}

pub(super) fn cache_host(host: &str) -> String {
  format!("host/{}", component(&crate::routes::normalize_host(host)))
}

pub(super) fn dynamic_policy_source_name(source: &str, name: &str) -> String {
  format!("source/{}/name/{}", component(source), component(name))
}

pub(super) fn dynamic_policy_route(route: &str) -> String {
  format!("route/{}", component(route))
}

pub(super) fn dynamic_policy_status() -> &'static str {
  "status/current"
}

pub(super) fn upstream_pool_server(pool: &str, server_id: &str) -> String {
  format!("{}/server/{}", component(pool), component(server_id))
}

pub(super) fn upstream_pool_status() -> &'static str {
  "status/current"
}

pub(super) fn ipm_status() -> &'static str {
  "status/current"
}

pub(super) fn ipm_principal(id: &str) -> String {
  format!("principal/{}", component(id))
}

pub(super) fn ipm_principal_wildcard() -> &'static str {
  "principal/*"
}

pub(super) fn ipm_credential(id: &str) -> String {
  format!("credential/{}", component(id))
}

pub(super) fn ipm_policy(name: &str) -> String {
  format!("policy/{}", component(name))
}

pub(super) fn ipm_binding(id: &str) -> String {
  format!("binding/{}", component(id))
}

pub(super) fn ipm_group(group: &str) -> String {
  format!("group/{}", component(group))
}

pub(super) fn ipm_audit() -> &'static str {
  "audit/current"
}

pub(super) fn ipm_simulation() -> &'static str {
  "simulation/current"
}

pub(super) fn component(value: &str) -> String {
  let mut encoded = String::with_capacity(value.len());
  for byte in value.bytes() {
    if is_component_byte(byte) {
      encoded.push(char::from(byte));
    } else {
      encoded.push('%');
      encoded.push(hex(byte >> 4));
      encoded.push(hex(byte & 0x0f));
    }
  }
  encoded
}

fn is_component_byte(byte: u8) -> bool {
  byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
}

fn hex(value: u8) -> char {
  match value {
    0..=9 => char::from(b'0' + value),
    10..=15 => char::from(b'A' + value - 10),
    _ => unreachable!("hex nibble should be within 0..=15"),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::{IpmPolicyConfig, IpmPolicyEffect, IpmPolicyStatementConfig};
  use crate::ipm::{IpmActor, IpmDecision, IpmRequestContext, IpmRuntime, resource};

  #[test]
  fn component_encodes_resource_separators() {
    assert_eq!(
      component("source/name:with space*"),
      "source%2Fname%3Awith%20space%2A"
    );
    assert_eq!(component("safe-name_1.~"), "safe-name_1.~");
  }

  #[test]
  fn cache_host_normalizes_before_encoding() {
    assert_eq!(cache_host("Example.COM:443"), "host/example.com");
    assert_eq!(cache_host("[2001:db8::1]:443"), "host/2001%3Adb8%3A%3A1");
  }

  #[test]
  fn resource_builders_use_typed_prefixes() {
    assert_eq!(
      dynamic_policy_source_name("crowd/sec", "block all"),
      "source/crowd%2Fsec/name/block%20all"
    );
    assert_eq!(
      upstream_pool_server("app-pool", "primary/blue"),
      "app-pool/server/primary%2Fblue"
    );
    assert_eq!(ipm_principal("deployer"), "principal/deployer");
  }

  #[test]
  fn authorization_matches_resource_specific_families() {
    let (runtime, actor) = runtime_with_resources(&[
      resource("oxibelt", "cache", &cache_policy("default")),
      resource("oxibelt", "cache", &cache_host("Example.COM:443")),
      resource(
        "oxibelt",
        "dynamic-policy",
        &dynamic_policy_source_name("vault/sec", "block all"),
      ),
      resource(
        "oxibelt",
        "dynamic-policy",
        &dynamic_policy_route("app-root"),
      ),
      resource(
        "oxibelt",
        "upstream-pool",
        &upstream_pool_server("app-pool", "primary/blue"),
      ),
      resource("oxibelt", "ipm", ipm_status()),
      resource("oxibelt", "ipm", &ipm_principal("deployer")),
      resource("oxibelt", "ipm", &ipm_credential("deploy token")),
      resource("oxibelt", "ipm", &ipm_policy("admin-full-access")),
      resource("oxibelt", "ipm", &ipm_binding("principal.deployer.admin")),
      resource("oxibelt", "ipm", &ipm_group("platform/admins")),
      resource("oxibelt", "ipm", ipm_audit()),
      resource("oxibelt", "ipm", ipm_simulation()),
    ]);

    assert_allowed(
      &runtime,
      &actor,
      "cache:PurgeObject",
      &cache_policy("default"),
    );
    assert_allowed(
      &runtime,
      &actor,
      "cache:PurgeObject",
      &cache_host("example.com"),
    );
    assert_allowed(
      &runtime,
      &actor,
      "dynamic-policy:Create",
      &dynamic_policy_source_name("vault/sec", "block all"),
    );
    assert_allowed(
      &runtime,
      &actor,
      "dynamic-policy:Create",
      &dynamic_policy_route("app-root"),
    );
    assert_allowed(
      &runtime,
      &actor,
      "upstream-pool:UpdateServer",
      &upstream_pool_server("app-pool", "primary/blue"),
    );
    assert_allowed(&runtime, &actor, "ipm:GetStatus", ipm_status());
    assert_allowed(
      &runtime,
      &actor,
      "ipm:GetPrincipal",
      &ipm_principal("deployer"),
    );
    assert_allowed(
      &runtime,
      &actor,
      "ipm:GetCredential",
      &ipm_credential("deploy token"),
    );
    assert_allowed(
      &runtime,
      &actor,
      "ipm:GetPolicy",
      &ipm_policy("admin-full-access"),
    );
    assert_allowed(
      &runtime,
      &actor,
      "ipm:DeleteBinding",
      &ipm_binding("principal.deployer.admin"),
    );
    assert_allowed(
      &runtime,
      &actor,
      "ipm:CreateBinding",
      &ipm_group("platform/admins"),
    );
    assert_allowed(&runtime, &actor, "ipm:ReadAudit", ipm_audit());
    assert_allowed(&runtime, &actor, "ipm:SimulateSelf", ipm_simulation());
    assert_allowed(&runtime, &actor, "ipm:SimulatePrincipal", ipm_simulation());
    assert_allowed(&runtime, &actor, "ipm:SimulatePolicy", ipm_simulation());
  }

  #[test]
  fn authorization_wildcards_match_new_resource_shapes() {
    let (runtime, actor) = runtime_with_resources(&[
      resource("oxibelt", "cache", "host/*"),
      resource("oxibelt", "dynamic-policy", "source/oxibeltctl/name/*"),
      resource("oxibelt", "upstream-pool", "app-pool/server/*"),
      resource("oxibelt", "ipm", "credential/*"),
    ]);

    assert_allowed(
      &runtime,
      &actor,
      "cache:Warm",
      &cache_host("Assets.EXAMPLE.com"),
    );
    assert_allowed(
      &runtime,
      &actor,
      "dynamic-policy:Apply",
      &dynamic_policy_source_name("oxibeltctl", "block-login"),
    );
    assert_allowed(
      &runtime,
      &actor,
      "upstream-pool:RemoveServer",
      &upstream_pool_server("app-pool", "blue-1"),
    );
    assert_allowed(
      &runtime,
      &actor,
      "ipm:RotateCredential",
      &ipm_credential("deploy-token"),
    );
    assert_denied(&runtime, &actor, "cache:Warm", &cache_policy("default"));
    assert_denied(&runtime, &actor, "upstream-pool:RemoveServer", "app-pool");
  }

  fn runtime_with_resources(resources: &[String]) -> (IpmRuntime, IpmActor) {
    let actor = IpmActor {
      name: "operator-token".to_string(),
      principal: "operator".to_string(),
      subject: "operator@example.com".to_string(),
      groups: vec!["platform".to_string()],
    };
    let runtime = IpmRuntime::test_with_actor_policy(
      "oxibelt",
      actor.clone(),
      IpmPolicyConfig {
        name: "resource-scoped".to_string(),
        version: "test".to_string(),
        statements: vec![IpmPolicyStatementConfig {
          effect: IpmPolicyEffect::Allow,
          actions: vec![
            "cache:*".to_string(),
            "dynamic-policy:*".to_string(),
            "upstream-pool:*".to_string(),
            "ipm:*".to_string(),
          ],
          resources: resources.to_vec(),
          conditions: Vec::new(),
        }],
      },
    );
    (runtime, actor)
  }

  fn assert_allowed(runtime: &IpmRuntime, actor: &IpmActor, action: &str, resource_name: &str) {
    assert_eq!(
      decision(runtime, actor, action, resource_name),
      IpmDecision::Allow
    );
  }

  fn assert_denied(runtime: &IpmRuntime, actor: &IpmActor, action: &str, resource_name: &str) {
    assert_eq!(
      decision(runtime, actor, action, resource_name),
      IpmDecision::Deny
    );
  }

  fn decision(
    runtime: &IpmRuntime,
    actor: &IpmActor,
    action: &str,
    resource_name: &str,
  ) -> IpmDecision {
    let service = action.split_once(':').map_or("*", |(service, _)| service);
    runtime.authorize(
      actor,
      action,
      &resource(runtime.namespace(), service, resource_name),
      &IpmRequestContext::default(),
    )
  }
}

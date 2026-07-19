use std::collections::BTreeMap;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::super::model::{Diagnostic, KubernetesObject, ObjectKey, object_ref};
use super::{BackendTlsDecision, GeneratedBackendTls, RenderedAsset, TranslationState, string_at};

const MAX_CA_PEM_BYTES: usize = 256 * 1024;

struct ParsedPolicy {
  object: KubernetesObject,
  target: ObjectKey,
  tls: Option<GeneratedBackendTls>,
}

impl TranslationState {
  pub(super) fn index_backend_tls(&mut self, objects: &[KubernetesObject]) {
    let config_maps = objects
      .iter()
      .filter(|object| object.kind == "ConfigMap")
      .map(|object| (object.key(), object))
      .collect::<BTreeMap<_, _>>();
    let mut by_target = BTreeMap::<ObjectKey, Vec<ParsedPolicy>>::new();
    for policy in objects
      .iter()
      .filter(|object| object.kind == "BackendTLSPolicy")
    {
      let Some(parsed) = self.parse_backend_tls_policy(policy, &config_maps) else {
        continue;
      };
      by_target
        .entry(parsed.target.clone())
        .or_default()
        .push(parsed);
    }

    for (target, mut policies) in by_target {
      policies.sort_by(|left, right| {
        policy_precedence(&left.object).cmp(&policy_precedence(&right.object))
      });
      if policies.len() > 1 {
        for policy in policies {
          self.diagnostics.push(Diagnostic::error(
            object_ref(&policy.object),
            format!(
              "BackendTLSPolicy is Conflicted because multiple policies target Service {}/{}",
              target.namespace, target.name
            ),
          ));
        }
        self.backend_tls.insert(target, BackendTlsDecision::Invalid);
        continue;
      }
      if let Some(policy) = policies.pop() {
        self.backend_tls.insert(
          target,
          policy
            .tls
            .map(BackendTlsDecision::Valid)
            .unwrap_or(BackendTlsDecision::Invalid),
        );
      }
    }
    let referenced_assets = self
      .backend_tls
      .values()
      .filter_map(|decision| match decision {
        BackendTlsDecision::Valid(tls) => Some(tls.trusted_ca_certs.iter()),
        BackendTlsDecision::Invalid => None,
      })
      .flatten()
      .cloned()
      .collect::<std::collections::HashSet<_>>();
    self
      .assets
      .retain(|managed_path, _| referenced_assets.contains(managed_path));
  }

  pub(super) fn backend_tls_for_service(
    &mut self,
    route: &KubernetesObject,
    service: &ObjectKey,
  ) -> Result<Option<GeneratedBackendTls>, ()> {
    match self.backend_tls.get(service).cloned() {
      None => Ok(None),
      Some(BackendTlsDecision::Valid(tls)) => Ok(Some(tls)),
      Some(BackendTlsDecision::Invalid) => {
        self.diagnostics.push(Diagnostic::error(
          object_ref(route),
          format!(
            "backend Service {}/{} has an invalid or conflicted BackendTLSPolicy",
            service.namespace, service.name
          ),
        ));
        Err(())
      }
    }
  }

  fn parse_backend_tls_policy(
    &mut self,
    policy: &KubernetesObject,
    config_maps: &BTreeMap<ObjectKey, &KubernetesObject>,
  ) -> Option<ParsedPolicy> {
    let mut valid = true;
    if let Some(field) = unsupported_field(&policy.spec, &["targetRefs", "validation"]) {
      self.policy_error(
        policy,
        &format!("spec.{field} is outside the supported stable core"),
      );
      valid = false;
    }
    let target_refs = policy.spec.get("targetRefs").and_then(Value::as_array);
    let Some(target_refs) = target_refs else {
      self.policy_error(policy, "spec.targetRefs is required");
      return None;
    };
    if target_refs.len() != 1 {
      self.policy_error(policy, "stable core requires exactly one targetRef");
      return None;
    }
    let target_ref = &target_refs[0];
    let group = string_at(target_ref, &["group"]).unwrap_or("");
    let kind = string_at(target_ref, &["kind"]).unwrap_or("Service");
    let Some(name) = string_at(target_ref, &["name"]) else {
      self.policy_error(policy, "targetRef.name is required");
      return None;
    };
    let target = ObjectKey {
      namespace: policy.namespace().to_string(),
      name: name.to_string(),
    };
    if unsupported_field(target_ref, &["group", "kind", "name", "sectionName"]).is_some() {
      self.policy_error(
        policy,
        "targetRef contains fields outside the supported stable core",
      );
      valid = false;
    }
    if !group.is_empty() || kind != "Service" {
      self.policy_error(policy, "targetRef must select a core Kubernetes Service");
      valid = false;
    }
    if target_ref
      .get("sectionName")
      .is_some_and(|value| !value.is_null())
    {
      self.policy_error(
        policy,
        "targetRef.sectionName is outside the supported stable core",
      );
      valid = false;
    }
    if !self.services.contains_key(&target) {
      self.policy_error(
        policy,
        &format!(
          "target Service {}/{} was not found",
          target.namespace, target.name
        ),
      );
      valid = false;
    }
    let Some(validation) = policy.spec.get("validation") else {
      self.policy_error(policy, "spec.validation is required");
      return Some(ParsedPolicy {
        object: policy.clone(),
        target,
        tls: None,
      });
    };
    if unsupported_field(
      validation,
      &[
        "hostname",
        "caCertificateRefs",
        "wellKnownCACertificates",
        "subjectAltNames",
        "options",
      ],
    )
    .is_some()
    {
      self.policy_error(
        policy,
        "validation contains fields outside the supported stable core",
      );
      valid = false;
    }
    if validation.get("subjectAltNames").is_some() {
      self.policy_error(
        policy,
        "validation.subjectAltNames is outside the supported stable core",
      );
      valid = false;
    }
    if validation.get("options").is_some() {
      self.policy_error(
        policy,
        "validation.options is outside the supported stable core",
      );
      valid = false;
    }
    let Some(hostname) = string_at(validation, &["hostname"]) else {
      self.policy_error(policy, "validation.hostname is required");
      return Some(ParsedPolicy {
        object: policy.clone(),
        target,
        tls: None,
      });
    };
    if !valid_precise_hostname(hostname) {
      self.policy_error(
        policy,
        "validation.hostname must be a valid precise DNS hostname",
      );
      valid = false;
    }

    let ca_refs = validation
      .get("caCertificateRefs")
      .and_then(Value::as_array)
      .cloned()
      .unwrap_or_default();
    let system = string_at(validation, &["wellKnownCACertificates"]);
    let tls = match (system, ca_refs.as_slice()) {
      (Some("System"), []) => Some(GeneratedBackendTls {
        server_name: hostname.to_ascii_lowercase(),
        trust: "system".to_string(),
        trusted_ca_certs: Vec::new(),
        trusted_ca_sha256: Vec::new(),
      }),
      (Some(_), _) => {
        self.policy_error(
          policy,
          "wellKnownCACertificates must be System and cannot be combined with caCertificateRefs",
        );
        None
      }
      (None, [ca_ref]) => self.policy_config_map_tls(policy, hostname, ca_ref, config_maps),
      (None, _) => {
        self.policy_error(
          policy,
          "validation requires System roots or exactly one ConfigMap caCertificateRef",
        );
        None
      }
    };
    if tls.is_none() {
      valid = false;
    }
    Some(ParsedPolicy {
      object: policy.clone(),
      target,
      tls: valid.then_some(tls).flatten(),
    })
  }

  fn policy_config_map_tls(
    &mut self,
    policy: &KubernetesObject,
    hostname: &str,
    ca_ref: &Value,
    config_maps: &BTreeMap<ObjectKey, &KubernetesObject>,
  ) -> Option<GeneratedBackendTls> {
    if unsupported_field(ca_ref, &["group", "kind", "name"]).is_some() {
      self.policy_error(
        policy,
        "caCertificateRef contains fields outside the supported stable core",
      );
      return None;
    }
    let group = string_at(ca_ref, &["group"]).unwrap_or("");
    let kind = string_at(ca_ref, &["kind"]).unwrap_or("ConfigMap");
    let Some(name) = string_at(ca_ref, &["name"]) else {
      self.policy_error(policy, "caCertificateRef.name is required");
      return None;
    };
    if !group.is_empty() || kind != "ConfigMap" {
      self.policy_error(
        policy,
        "stable core only supports a core ConfigMap caCertificateRef",
      );
      return None;
    }
    let key = ObjectKey {
      namespace: policy.namespace().to_string(),
      name: name.to_string(),
    };
    let Some(config_map) = config_maps.get(&key) else {
      self.policy_error(
        policy,
        &format!(
          "referenced ConfigMap {}/{} was not found",
          key.namespace, key.name
        ),
      );
      return None;
    };
    let Some(pem) = config_map.data.get("ca.crt") else {
      self.policy_error(policy, "referenced ConfigMap must contain data[\"ca.crt\"]");
      return None;
    };
    if pem.is_empty() || pem.len() > MAX_CA_PEM_BYTES {
      self.policy_error(
        policy,
        &format!("ConfigMap ca.crt must be 1..={MAX_CA_PEM_BYTES} bytes"),
      );
      return None;
    }
    if pem.contains('\0')
      || !pem.contains("-----BEGIN CERTIFICATE-----")
      || !pem.contains("-----END CERTIFICATE-----")
    {
      self.policy_error(policy, "ConfigMap ca.crt is not a PEM certificate bundle");
      return None;
    }
    let digest = hex_digest(&Sha256::digest(pem.as_bytes()));
    let managed_path = format!("gateway-api-ca/{digest}.pem");
    let data_key = format!("gateway-api-ca-{digest}.pem");
    self
      .assets
      .entry(managed_path.clone())
      .or_insert_with(|| RenderedAsset {
        data_key,
        managed_path: managed_path.clone(),
        content: pem.clone(),
      });
    Some(GeneratedBackendTls {
      server_name: hostname.to_ascii_lowercase(),
      trust: "exclusive".to_string(),
      trusted_ca_certs: vec![managed_path],
      trusted_ca_sha256: vec![digest],
    })
  }

  fn policy_error(&mut self, policy: &KubernetesObject, message: &str) {
    self
      .diagnostics
      .push(Diagnostic::error(object_ref(policy), message));
  }
}

fn policy_precedence(policy: &KubernetesObject) -> (&str, &str, &str) {
  (
    policy.metadata.creation_timestamp.as_deref().unwrap_or("~"),
    policy.namespace(),
    policy.name(),
  )
}

fn valid_precise_hostname(hostname: &str) -> bool {
  !hostname.is_empty()
    && hostname.len() <= 253
    && !hostname.ends_with('.')
    && hostname.split('.').all(|label| {
      !label.is_empty()
        && label.len() <= 63
        && label
          .bytes()
          .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && label
          .as_bytes()
          .first()
          .is_some_and(u8::is_ascii_alphanumeric)
        && label
          .as_bytes()
          .last()
          .is_some_and(u8::is_ascii_alphanumeric)
    })
}

fn hex_digest(digest: &[u8]) -> String {
  digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unsupported_field<'a>(value: &'a Value, allowed: &[&str]) -> Option<&'a str> {
  value
    .as_object()?
    .keys()
    .find(|key| !allowed.contains(&key.as_str()))
    .map(String::as_str)
}

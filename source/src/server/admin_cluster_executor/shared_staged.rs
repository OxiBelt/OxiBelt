//! Typed authorization and publication contract for shared Admin mutations.
//!
//! Member workers validate these commands but never invoke their effects.
//! Exactly one coordinator publishes the staged PostgreSQL delta through a
//! `SharedStagedPublisher` that validates its durable fencing token in the same
//! transaction as the shared-state change.

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use anyhow::{Context, bail, ensure};
use http::Method;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::admin_mutation::{
  ClusterAuthorizationCheck, ClusterMutationCommand, CoordinatorFence, MembershipActivationRequest,
  MembershipCancelRequest, MembershipTransitionRequest,
};
use crate::ipm::{
  IpmActor, IpmAdminMutation, IpmBindingCreate, IpmCredentialCreate, IpmCredentialPatch,
  IpmCredentialRevoke, IpmCredentialRotate, IpmPolicyCreate, IpmPolicyPatch, IpmPrincipalCreate,
  IpmPrincipalPatch,
};

use crate::server::admin_resource;

const MAX_SHARED_BODY_BYTES: usize = 1024 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SharedStagedOperation {
  pub(crate) method: Method,
  pub(crate) path: String,
  pub(crate) principal: String,
  pub(crate) previous_revision: String,
  pub(crate) operational_precondition_revision: String,
  pub(crate) candidate_revision: String,
  pub(crate) candidate_digest: String,
  pub(crate) body: Zeroizing<Vec<u8>>,
  pub(crate) kind: SharedMutationKind,
}

impl fmt::Debug for SharedStagedOperation {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("SharedStagedOperation")
      .field("method", &self.method)
      .field("path", &self.path)
      .field("principal", &self.principal)
      .field("previous_revision", &self.previous_revision)
      .field(
        "operational_precondition_revision",
        &self.operational_precondition_revision,
      )
      .field("candidate_revision", &self.candidate_revision)
      .field("candidate_digest", &self.candidate_digest)
      .field("body_len", &self.body.len())
      .finish_non_exhaustive()
  }
}

impl SharedStagedOperation {
  /// Reconstructs the typed IPM delta after the signed command has been
  /// authorized. Break-glass mutations use the control-plane store directly
  /// and therefore return `None` here.
  pub(crate) fn ipm_mutation(&self) -> anyhow::Result<Option<IpmAdminMutation>> {
    let mutation = match &self.kind {
      SharedMutationKind::PrincipalCreate => IpmAdminMutation::PrincipalCreate(decode(&self.body)?),
      SharedMutationKind::PrincipalPatch(id) => {
        IpmAdminMutation::PrincipalPatch(id.clone(), decode(&self.body)?)
      }
      SharedMutationKind::PrincipalDelete(id) => IpmAdminMutation::PrincipalDelete(id.clone()),
      SharedMutationKind::CredentialCreate => {
        IpmAdminMutation::CredentialCreate(decode(&self.body)?)
      }
      SharedMutationKind::CredentialPatch(id) => {
        IpmAdminMutation::CredentialPatch(id.clone(), decode(&self.body)?)
      }
      SharedMutationKind::CredentialDelete(id) => IpmAdminMutation::CredentialDelete(id.clone()),
      SharedMutationKind::CredentialRotate(id) => {
        IpmAdminMutation::CredentialRotate(id.clone(), decode(&self.body)?)
      }
      SharedMutationKind::CredentialRevoke(id) => {
        IpmAdminMutation::CredentialRevoke(id.clone(), decode(&self.body)?)
      }
      SharedMutationKind::PolicyCreate => IpmAdminMutation::PolicyCreate(decode(&self.body)?),
      SharedMutationKind::PolicyPatch(id) => {
        IpmAdminMutation::PolicyPatch(id.clone(), decode(&self.body)?)
      }
      SharedMutationKind::PolicyDelete(id) => IpmAdminMutation::PolicyDelete(id.clone()),
      SharedMutationKind::BindingCreate => IpmAdminMutation::BindingCreate(decode(&self.body)?),
      SharedMutationKind::BindingDelete(id) => IpmAdminMutation::BindingDelete(id.clone()),
      SharedMutationKind::BreakGlassActivate | SharedMutationKind::BreakGlassRevoke(_) => {
        return Ok(None);
      }
      SharedMutationKind::MembershipPropose(_)
      | SharedMutationKind::MembershipActivate(_, _)
      | SharedMutationKind::MembershipCancel(_, _) => return Ok(None),
    };
    Ok(Some(mutation))
  }

  pub(crate) fn break_glass_mutation(&self) -> anyhow::Result<Option<BreakGlassStagedMutation>> {
    Ok(match &self.kind {
      SharedMutationKind::BreakGlassActivate => {
        let request: BreakGlassActivation = decode(&self.body)?;
        Some(BreakGlassStagedMutation::Activate {
          ttl_seconds: request.ttl_seconds,
        })
      }
      SharedMutationKind::BreakGlassRevoke(id) => {
        Some(BreakGlassStagedMutation::Revoke { id: id.clone() })
      }
      _ => None,
    })
  }

  pub(crate) fn membership_proposal(&self) -> Option<&MembershipTransitionRequest> {
    match &self.kind {
      SharedMutationKind::MembershipPropose(request) => Some(request),
      _ => None,
    }
  }

  pub(crate) fn membership_activation(&self) -> Option<(&str, &MembershipActivationRequest)> {
    match &self.kind {
      SharedMutationKind::MembershipActivate(id, request) => Some((id, request)),
      _ => None,
    }
  }

  pub(crate) fn membership_cancellation(&self) -> Option<(&str, &MembershipCancelRequest)> {
    match &self.kind {
      SharedMutationKind::MembershipCancel(id, request) => Some((id, request)),
      _ => None,
    }
  }

  pub(crate) fn token_producing(&self) -> bool {
    matches!(
      &self.kind,
      SharedMutationKind::CredentialCreate | SharedMutationKind::CredentialRotate(_)
    )
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum BreakGlassStagedMutation {
  Activate { ttl_seconds: u64 },
  Revoke { id: String },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum SharedMutationKind {
  PrincipalCreate,
  PrincipalPatch(String),
  PrincipalDelete(String),
  CredentialCreate,
  CredentialPatch(String),
  CredentialDelete(String),
  CredentialRotate(String),
  CredentialRevoke(String),
  PolicyCreate,
  PolicyPatch(String),
  PolicyDelete(String),
  BindingCreate,
  BindingDelete(String),
  BreakGlassActivate,
  BreakGlassRevoke(String),
  MembershipPropose(MembershipTransitionRequest),
  MembershipActivate(String, MembershipActivationRequest),
  MembershipCancel(String, MembershipCancelRequest),
}

pub(crate) struct SharedPublishResult {
  pub(crate) revision: String,
  pub(crate) digest: String,
}

impl fmt::Debug for SharedPublishResult {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("SharedPublishResult")
      .field("revision", &self.revision)
      .field("digest", &self.digest)
      .finish()
  }
}

pub(crate) trait SharedStagedPublisher: Send + Sync {
  fn publish_once<'a>(
    &'a self,
    fence: &'a CoordinatorFence,
    actor: &'a IpmActor,
    operation: &'a SharedStagedOperation,
  ) -> Pin<Box<dyn Future<Output = anyhow::Result<SharedPublishResult>> + Send + 'a>>;

  fn observe<'a>(
    &'a self,
    request_id: &'a str,
    operation: &'a SharedStagedOperation,
  ) -> Pin<Box<dyn Future<Output = anyhow::Result<bool>> + Send + 'a>>;

  fn restore_once<'a>(
    &'a self,
    fence: &'a CoordinatorFence,
    actor: &'a IpmActor,
    operation: &'a SharedStagedOperation,
  ) -> Pin<Box<dyn Future<Output = anyhow::Result<SharedPublishResult>> + Send + 'a>>;

  fn observe_restored<'a>(
    &'a self,
    request_id: &'a str,
    operation: &'a SharedStagedOperation,
  ) -> Pin<Box<dyn Future<Output = anyhow::Result<bool>> + Send + 'a>>;
}

pub(crate) fn decode_shared_operation(
  method: &Method,
  path: &str,
  body: &[u8],
  principal: &str,
) -> anyhow::Result<(SharedMutationKindEvidence, Vec<ClusterAuthorizationCheck>)> {
  ensure!(
    body.len() <= MAX_SHARED_BODY_BYTES,
    "shared mutation body is too large"
  );
  let (kind, mut checks) = match (method, path) {
    (&Method::POST, "/admin/v1/ipm/principals") => {
      let value: IpmPrincipalCreate = decode(body)?;
      (
        SharedMutationKind::PrincipalCreate,
        vec![check(
          "ipm:CreatePrincipal",
          admin_resource::ipm_principal(&value.id),
        )],
      )
    }
    (&Method::POST, "/admin/v1/ipm/credentials") => {
      let value: IpmCredentialCreate = decode(body)?;
      (
        SharedMutationKind::CredentialCreate,
        vec![
          check(
            "ipm:CreateCredential",
            admin_resource::ipm_credential(&value.id),
          ),
          check(
            "ipm:CreateCredential",
            admin_resource::ipm_principal(&value.principal),
          ),
        ],
      )
    }
    (&Method::POST, "/admin/v1/ipm/policies") => {
      let value: IpmPolicyCreate = decode(body)?;
      (
        SharedMutationKind::PolicyCreate,
        vec![check(
          "ipm:CreatePolicy",
          admin_resource::ipm_policy(&value.name),
        )],
      )
    }
    (&Method::POST, "/admin/v1/ipm/bindings") => {
      let value: IpmBindingCreate = decode(body)?;
      let id = value
        .id
        .clone()
        .unwrap_or_else(|| generated_binding_id(&value));
      let mut checks = vec![
        check("ipm:CreateBinding", admin_resource::ipm_binding(&id)),
        check(
          "ipm:CreateBinding",
          admin_resource::ipm_policy(&value.policy),
        ),
      ];
      if let Some(value) = value.principal {
        checks.push(check(
          "ipm:CreateBinding",
          admin_resource::ipm_principal(&value),
        ));
      }
      if let Some(value) = value.group {
        checks.push(check(
          "ipm:CreateBinding",
          admin_resource::ipm_group(&value),
        ));
      }
      (SharedMutationKind::BindingCreate, checks)
    }
    (&Method::POST, "/admin/v1/break-glass/activations") => {
      let value: BreakGlassActivation = decode(body)?;
      ensure!(value.ttl_seconds > 0, "ttl_seconds must be positive");
      if let Some(reason) = value.reason {
        ensure!(
          !reason.is_empty() && reason.len() <= 512 && !reason.chars().any(char::is_control),
          "break-glass reason is invalid"
        );
      }
      (
        SharedMutationKind::BreakGlassActivate,
        vec![check(
          "ipm:ActivateBreakGlass",
          format!(
            "break-glass/principal/{}",
            admin_resource::component(principal)
          ),
        )],
      )
    }
    (&Method::POST, "/admin/v1/membership/transitions") => {
      let value: MembershipTransitionRequest = decode(body)?;
      value.validate()?;
      (
        SharedMutationKind::MembershipPropose(value),
        vec![check(
          "membership:Propose",
          "membership/current".to_string(),
        )],
      )
    }
    _ => decode_item_operation(method, path, body)?,
  };
  checks.sort();
  checks.dedup();
  Ok((SharedMutationKindEvidence(kind), checks))
}

fn decode_item_operation(
  method: &Method,
  path: &str,
  body: &[u8],
) -> anyhow::Result<(SharedMutationKind, Vec<ClusterAuthorizationCheck>)> {
  if let Some(rest) = path.strip_prefix("/admin/v1/membership/transitions/") {
    let (id, suffix) = rest.split_once('/').unwrap_or((rest, ""));
    ensure!(
      !id.is_empty() && !id.contains('/'),
      "invalid membership transition path"
    );
    return match (method.as_str(), suffix) {
      ("POST", "activate") => {
        let request: MembershipActivationRequest = decode(body)?;
        request.validate()?;
        ensure!(
          request.transition_id == id,
          "membership activation path does not match body"
        );
        Ok((
          SharedMutationKind::MembershipActivate(id.to_string(), request),
          vec![check(
            "membership:Activate",
            format!("membership/transition/{}", admin_resource::component(id)),
          )],
        ))
      }
      ("POST", "cancel") => {
        let request: MembershipCancelRequest = decode(body)?;
        request.validate()?;
        ensure!(
          request.transition_id == id,
          "membership cancellation path does not match body"
        );
        Ok((
          SharedMutationKind::MembershipCancel(id.to_string(), request),
          vec![check(
            "membership:Cancel",
            format!("membership/transition/{}", admin_resource::component(id)),
          )],
        ))
      }
      _ => bail!("unsupported membership transition mutation"),
    };
  }
  if let Some(id) = one_segment(path, "/admin/v1/ipm/principals/") {
    return match method.as_str() {
      "PATCH" => {
        let _: IpmPrincipalPatch = decode(body)?;
        Ok((
          SharedMutationKind::PrincipalPatch(id.into()),
          vec![check(
            "ipm:UpdatePrincipal",
            admin_resource::ipm_principal(id),
          )],
        ))
      }
      "DELETE" => {
        require_empty(body)?;
        Ok((
          SharedMutationKind::PrincipalDelete(id.into()),
          vec![check(
            "ipm:DeletePrincipal",
            admin_resource::ipm_principal(id),
          )],
        ))
      }
      _ => bail!("unsupported principal mutation"),
    };
  }
  if let Some(rest) = path.strip_prefix("/admin/v1/ipm/credentials/") {
    let (id, suffix) = rest.split_once('/').unwrap_or((rest, ""));
    ensure!(
      !id.is_empty() && !id.contains('/'),
      "invalid credential path"
    );
    return match (method.as_str(), suffix) {
      ("PATCH", "") => {
        let value: IpmCredentialPatch = decode(body)?;
        let mut checks = vec![check(
          "ipm:UpdateCredential",
          admin_resource::ipm_credential(id),
        )];
        if let Some(value) = value.principal {
          checks.push(check(
            "ipm:UpdateCredential",
            admin_resource::ipm_principal(&value),
          ));
        }
        Ok((SharedMutationKind::CredentialPatch(id.into()), checks))
      }
      ("DELETE", "") => {
        require_empty(body)?;
        Ok((
          SharedMutationKind::CredentialDelete(id.into()),
          vec![check(
            "ipm:DeleteCredential",
            admin_resource::ipm_credential(id),
          )],
        ))
      }
      ("POST", "rotate") => {
        let _: IpmCredentialRotate = decode(body)?;
        Ok((
          SharedMutationKind::CredentialRotate(id.into()),
          vec![check(
            "ipm:RotateCredential",
            admin_resource::ipm_credential(id),
          )],
        ))
      }
      ("POST", "revoke") => {
        let _: IpmCredentialRevoke = decode(body)?;
        Ok((
          SharedMutationKind::CredentialRevoke(id.into()),
          vec![check(
            "ipm:RevokeCredential",
            admin_resource::ipm_credential(id),
          )],
        ))
      }
      _ => bail!("unsupported credential mutation"),
    };
  }
  if let Some(id) = one_segment(path, "/admin/v1/ipm/policies/") {
    return match method.as_str() {
      "PATCH" => {
        let _: IpmPolicyPatch = decode(body)?;
        Ok((
          SharedMutationKind::PolicyPatch(id.into()),
          vec![check("ipm:UpdatePolicy", admin_resource::ipm_policy(id))],
        ))
      }
      "DELETE" => {
        require_empty(body)?;
        Ok((
          SharedMutationKind::PolicyDelete(id.into()),
          vec![check("ipm:DeletePolicy", admin_resource::ipm_policy(id))],
        ))
      }
      _ => bail!("unsupported policy mutation"),
    };
  }
  if let Some(id) = one_segment(path, "/admin/v1/ipm/bindings/") {
    ensure!(*method == Method::DELETE, "unsupported binding mutation");
    require_empty(body)?;
    return Ok((
      SharedMutationKind::BindingDelete(id.into()),
      vec![check("ipm:DeleteBinding", admin_resource::ipm_binding(id))],
    ));
  }
  if let Some(id) = path
    .strip_prefix("/admin/v1/break-glass/activations/")
    .and_then(|value| value.strip_suffix("/revoke"))
  {
    ensure!(
      !id.is_empty() && !id.contains('/') && *method == Method::POST,
      "invalid break-glass revoke path"
    );
    require_empty_json(body)?;
    return Ok((
      SharedMutationKind::BreakGlassRevoke(id.into()),
      vec![check(
        "ipm:RevokeBreakGlass",
        format!("break-glass/activation/{}", admin_resource::component(id)),
      )],
    ));
  }
  bail!("unsupported shared Admin mutation")
}

#[derive(Debug, Clone)]
pub(crate) struct SharedMutationKindEvidence(SharedMutationKind);

impl SharedMutationKindEvidence {
  pub(crate) fn attach(
    self,
    command: &ClusterMutationCommand,
    path: &str,
    candidate_digest: &str,
  ) -> SharedStagedOperation {
    SharedStagedOperation {
      method: command.method.clone(),
      path: path.to_string(),
      principal: command.principal.clone(),
      previous_revision: command.expected_previous_revision.clone(),
      operational_precondition_revision: command.precondition_revision.clone(),
      candidate_revision: command.new_revision.clone(),
      candidate_digest: candidate_digest.to_string(),
      body: Zeroizing::new(command.body().to_vec()),
      kind: self.0,
    }
  }
}

fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> anyhow::Result<T> {
  ensure!(!body.is_empty(), "shared mutation JSON body is required");
  serde_json::from_slice(body).context("shared mutation JSON body is invalid")
}

fn require_empty(body: &[u8]) -> anyhow::Result<()> {
  ensure!(body.is_empty(), "mutation body must be empty");
  Ok(())
}

fn require_empty_json(body: &[u8]) -> anyhow::Result<()> {
  if body.is_empty() {
    return Ok(());
  }
  let _: EmptyRequest = decode(body)?;
  Ok(())
}

fn one_segment<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
  path
    .strip_prefix(prefix)
    .filter(|value| !value.is_empty() && !value.contains('/'))
}

fn check(action: &str, resource: String) -> ClusterAuthorizationCheck {
  ClusterAuthorizationCheck {
    action: action.into(),
    resource,
  }
}

fn generated_binding_id(body: &IpmBindingCreate) -> String {
  body
    .id
    .clone()
    .unwrap_or_else(|| match (&body.principal, &body.group) {
      (Some(principal), None) => format!("principal.{principal}.{}", body.policy),
      (None, Some(group)) => format!("group.{group}.{}", body.policy),
      _ => format!("binding.{}", body.policy),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BreakGlassActivation {
  ttl_seconds: u64,
  #[serde(default)]
  reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyRequest {}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn credential_create_binds_credential_and_principal_permissions() {
    let (_, checks) = decode_shared_operation(
      &Method::POST,
      "/admin/v1/ipm/credentials",
      br#"{"id":"deploy","principal":"controller","no_expiry":true}"#,
      "controller",
    )
    .expect("credential command");
    assert_eq!(checks.len(), 2);
    assert!(
      checks
        .iter()
        .any(|check| check.resource == "credential/deploy")
    );
    assert!(
      checks
        .iter()
        .any(|check| check.resource == "principal/controller")
    );
  }

  #[test]
  fn item_paths_reject_nested_identifiers() {
    assert!(
      decode_shared_operation(
        &Method::DELETE,
        "/admin/v1/ipm/principals/a/b",
        b"",
        "controller"
      )
      .is_err()
    );
  }

  #[test]
  fn break_glass_permission_is_principal_bound() {
    let (_, checks) = decode_shared_operation(
      &Method::POST,
      "/admin/v1/break-glass/activations",
      br#"{"ttl_seconds":30}"#,
      "spiffe://example/admin",
    )
    .expect("activation");
    assert_eq!(checks[0].action, "ipm:ActivateBreakGlass");
    assert!(
      checks[0]
        .resource
        .contains("spiffe%3A%2F%2Fexample%2Fadmin")
    );
  }
}

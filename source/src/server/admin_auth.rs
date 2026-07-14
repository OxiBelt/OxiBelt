//! Admin authentication and authorization glue around IPM decisions.
//! Denied checks can run silently when returning audit detail would disclose a protected target.

use std::net::SocketAddr;

use crate::admin_audit::AdminAuditHandle;
use crate::config::{AdminWorkloadIdentityBearerMode, Config};
use crate::ipm::{
  IpmActor, IpmAdminBearerAuthentication, IpmAdminCredentialKind, IpmDecision,
  IpmPresentedWorkloadIdentity, IpmRequestContext, IpmRuntime, IpmWorkloadIdentity,
  IpmWorkloadIdentityError, resource,
};
use crate::proxy::http::headers::extract_host;
use crate::tls::VerifiedClientCertificate;

pub(super) type AdminActor = IpmActor;

pub(super) struct AdminAuthorization<'a> {
  pub(super) actor: &'a AdminActor,
  pub(super) ipm: &'a IpmRuntime,
  context: &'a IpmRequestContext,
  audit: Option<AdminAuditHandle>,
}

impl<'a> AdminAuthorization<'a> {
  pub(super) fn new(
    actor: &'a AdminActor,
    ipm: &'a IpmRuntime,
    context: &'a IpmRequestContext,
  ) -> Self {
    Self {
      actor,
      ipm,
      context,
      audit: None,
    }
  }

  pub(super) fn new_with_audit(
    actor: &'a AdminActor,
    ipm: &'a IpmRuntime,
    context: &'a IpmRequestContext,
    audit: AdminAuditHandle,
  ) -> Self {
    Self {
      actor,
      ipm,
      context,
      audit: Some(audit),
    }
  }

  pub(super) fn is_allowed(&self, action: &str, resource_name: &str) -> bool {
    self.is_allowed_with_audit(action, resource_name, true)
  }

  pub(super) fn is_allowed_silently(&self, action: &str, resource_name: &str) -> bool {
    self.is_allowed_with_audit(action, resource_name, false)
  }

  fn is_allowed_with_audit(&self, action: &str, resource_name: &str, audit_check: bool) -> bool {
    let resource = resource(
      self.ipm.namespace(),
      service_for_action(action),
      resource_name,
    );
    let allowed = matches!(
      self
        .ipm
        .authorize(self.actor, action, &resource, self.context),
      IpmDecision::Allow
    );
    if audit_check && let Some(audit) = &self.audit {
      audit.record_authorization(action, &resource, allowed);
    }
    allowed
  }

  pub(super) fn context(&self) -> &IpmRequestContext {
    self.context
  }
}

#[derive(Debug, Clone)]
pub(super) struct AdminAuthentication {
  pub(super) actor: AdminActor,
  details: AdminAuthenticationDetails,
}

#[derive(Debug, Clone)]
pub(super) struct AdminAuthenticationFailure {
  details: AdminAuthenticationDetails,
}

#[derive(Debug, Clone)]
struct AdminAuthenticationDetails {
  workload_identity: Option<AdminWorkloadIdentityEvidence>,
  credential: Option<AdminCredentialEvidence>,
  reason: &'static str,
}

#[derive(Debug, Clone)]
struct AdminWorkloadIdentityEvidence {
  actor: Option<AdminActor>,
  kind: Option<String>,
  identity: Option<String>,
  principal: Option<String>,
  fingerprint_sha256: Option<String>,
}

#[derive(Debug, Clone)]
struct AdminCredentialEvidence {
  kind: &'static str,
  identity: String,
  principal: String,
}

impl AdminAuthentication {
  pub(super) const fn reason(&self) -> &'static str {
    self.details.reason
  }

  pub(super) fn authenticated_with_break_glass(&self) -> bool {
    self
      .details
      .credential
      .as_ref()
      .is_some_and(|credential| credential.kind == "break_glass")
  }

  pub(super) fn record_audit(&self, audit: &AdminAuditHandle) {
    audit.set_actor(
      &self.actor.name,
      &self.actor.principal,
      &self.actor.subject,
      &self.actor.groups,
    );
    audit.set_authentication(
      self.details.reason,
      self
        .details
        .workload_identity
        .as_ref()
        .and_then(|identity| identity.kind.as_deref()),
      self
        .details
        .workload_identity
        .as_ref()
        .and_then(|identity| identity.identity.as_deref()),
      self
        .details
        .workload_identity
        .as_ref()
        .and_then(|identity| identity.principal.as_deref()),
      self
        .details
        .workload_identity
        .as_ref()
        .and_then(|identity| identity.fingerprint_sha256.as_deref()),
      self
        .details
        .credential
        .as_ref()
        .map(|credential| credential.kind),
      self
        .details
        .credential
        .as_ref()
        .map(|credential| credential.identity.as_str()),
      self
        .details
        .credential
        .as_ref()
        .map(|credential| credential.principal.as_str()),
    );
  }

  pub(super) fn legacy_signed_cache_purge(actor: AdminActor) -> Self {
    Self {
      details: AdminAuthenticationDetails {
        workload_identity: None,
        credential: Some(AdminCredentialEvidence {
          kind: "signed_cache_purge",
          identity: actor.name.clone(),
          principal: actor.principal.clone(),
        }),
        reason: "signed_cache_purge",
      },
      actor,
    }
  }
}

impl AdminAuthenticationFailure {
  pub(super) const fn reason(&self) -> &'static str {
    self.details.reason
  }

  pub(super) fn record_audit(&self, audit: &AdminAuditHandle) {
    audit.set_authentication(
      self.details.reason,
      self
        .details
        .workload_identity
        .as_ref()
        .and_then(|identity| identity.kind.as_deref()),
      self
        .details
        .workload_identity
        .as_ref()
        .and_then(|identity| identity.identity.as_deref()),
      self
        .details
        .workload_identity
        .as_ref()
        .and_then(|identity| identity.principal.as_deref()),
      self
        .details
        .workload_identity
        .as_ref()
        .and_then(|identity| identity.fingerprint_sha256.as_deref()),
      self
        .details
        .credential
        .as_ref()
        .map(|credential| credential.kind),
      self
        .details
        .credential
        .as_ref()
        .map(|credential| credential.identity.as_str()),
      self
        .details
        .credential
        .as_ref()
        .map(|credential| credential.principal.as_str()),
    );
  }

  pub(super) fn into_signed_cache_purge_authentication(self) -> Option<AdminAuthentication> {
    if self.details.reason != "missing_bearer" {
      return None;
    }
    let actor = self.details.workload_identity.as_ref()?.actor.clone()?;
    let mut details = self.details;
    details.credential = Some(AdminCredentialEvidence {
      kind: "signed_cache_purge",
      identity: "signed-cache-purge".to_string(),
      principal: actor.principal.clone(),
    });
    details.reason = "bound_signed_cache_purge";
    Some(AdminAuthentication { actor, details })
  }

  pub(super) fn supports_signed_cache_purge(&self) -> bool {
    self.details.reason == "missing_bearer"
      && self
        .details
        .workload_identity
        .as_ref()
        .and_then(|identity| identity.actor.as_ref())
        .is_some()
  }
}

pub(super) async fn admin_authentication<B>(
  request: &::http::Request<B>,
  config: &Config,
  ipm: &IpmRuntime,
) -> Result<AdminAuthentication, AdminAuthenticationFailure> {
  if !config.admin.workload_identity.enabled {
    return legacy_admin_authentication(request, config, ipm).await;
  }

  let workload_identity =
    authenticated_workload_identity(request, config, ipm).map_err(|error| *error)?;
  match ipm.admin_bearer_authentication(request.headers()).await {
    IpmAdminBearerAuthentication::Authenticated(credential) => {
      let credential_evidence = credential_evidence(
        credential.kind,
        credential.credential_name.clone(),
        credential.actor.principal.clone(),
      );
      let Some(workload_actor) = workload_identity.actor.clone() else {
        return Err(workload_failure(
          "unmapped_workload_identity",
          Some(workload_identity),
        ));
      };
      let workload_principal = workload_actor.principal;
      if credential.actor.principal != workload_principal {
        return Err(AdminAuthenticationFailure {
          details: AdminAuthenticationDetails {
            workload_identity: Some(workload_identity),
            credential: Some(credential_evidence),
            reason: "principal_mismatch",
          },
        });
      }
      Ok(AdminAuthentication {
        actor: credential.actor,
        details: AdminAuthenticationDetails {
          workload_identity: Some(workload_identity),
          credential: Some(credential_evidence),
          reason: "bound_bearer",
        },
      })
    }
    IpmAdminBearerAuthentication::Missing
      if config.admin.workload_identity.bearer_mode
        == AdminWorkloadIdentityBearerMode::Optional =>
    {
      let Some(actor) = workload_identity.actor.clone() else {
        return Err(workload_failure(
          "unmapped_workload_identity",
          Some(workload_identity),
        ));
      };
      Ok(AdminAuthentication {
        actor,
        details: AdminAuthenticationDetails {
          workload_identity: Some(workload_identity),
          credential: None,
          reason: "certificate_only",
        },
      })
    }
    IpmAdminBearerAuthentication::Missing => Err(AdminAuthenticationFailure {
      details: AdminAuthenticationDetails {
        workload_identity: Some(workload_identity),
        credential: None,
        reason: "missing_bearer",
      },
    }),
    IpmAdminBearerAuthentication::Invalid => Err(AdminAuthenticationFailure {
      details: AdminAuthenticationDetails {
        workload_identity: Some(workload_identity),
        credential: None,
        reason: "invalid_bearer",
      },
    }),
  }
}

async fn legacy_admin_authentication<B>(
  request: &::http::Request<B>,
  config: &Config,
  ipm: &IpmRuntime,
) -> Result<AdminAuthentication, AdminAuthenticationFailure> {
  match ipm.admin_bearer_authentication(request.headers()).await {
    IpmAdminBearerAuthentication::Authenticated(credential)
      if config.ipm.enabled || credential.actor.principal == "bootstrap-admin" =>
    {
      let credential_evidence = credential_evidence(
        credential.kind,
        credential.credential_name.clone(),
        credential.actor.principal.clone(),
      );
      Ok(AdminAuthentication {
        actor: credential.actor,
        details: AdminAuthenticationDetails {
          workload_identity: None,
          credential: Some(credential_evidence),
          reason: "bearer",
        },
      })
    }
    IpmAdminBearerAuthentication::Authenticated(_) | IpmAdminBearerAuthentication::Invalid => {
      Err(AdminAuthenticationFailure {
        details: AdminAuthenticationDetails {
          workload_identity: None,
          credential: None,
          reason: "invalid_bearer",
        },
      })
    }
    IpmAdminBearerAuthentication::Missing => Err(AdminAuthenticationFailure {
      details: AdminAuthenticationDetails {
        workload_identity: None,
        credential: None,
        reason: "missing_bearer",
      },
    }),
  }
}

fn authenticated_workload_identity<B>(
  request: &::http::Request<B>,
  config: &Config,
  ipm: &IpmRuntime,
) -> Result<AdminWorkloadIdentityEvidence, Box<AdminAuthenticationFailure>> {
  let Some(certificate) = request.extensions().get::<VerifiedClientCertificate>() else {
    return Err(Box::new(workload_failure("missing_certificate", None)));
  };
  let certificate = match certificate {
    VerifiedClientCertificate::Parsed(certificate) => certificate,
    VerifiedClientCertificate::Unparseable { fingerprint_sha256 } => {
      return Err(Box::new(workload_failure(
        "unparseable_certificate",
        Some(AdminWorkloadIdentityEvidence {
          actor: None,
          kind: None,
          identity: None,
          principal: None,
          fingerprint_sha256: Some(fingerprint_sha256.clone()),
        }),
      )));
    }
  };
  let base_evidence =
    |kind: Option<String>, identity: Option<String>, principal: Option<String>| {
      AdminWorkloadIdentityEvidence {
        actor: None,
        kind,
        identity,
        principal,
        fingerprint_sha256: Some(certificate.fingerprint_sha256.clone()),
      }
    };
  if config
    .admin
    .workload_identity
    .revoked_certificate_fingerprints_sha256
    .iter()
    .any(|fingerprint| fingerprint == &certificate.fingerprint_sha256)
  {
    return Err(Box::new(workload_failure(
      "revoked_certificate",
      Some(base_evidence(None, None, None)),
    )));
  }
  match ipm.workload_identity_from_certificate(certificate, &config.ipm.trust) {
    Ok(identity) => Ok(workload_evidence(identity, &certificate.fingerprint_sha256)),
    Err(IpmWorkloadIdentityError::Unmapped { presented }) => Err(Box::new(workload_failure(
      "unmapped_workload_identity",
      Some(presented_evidence(
        presented,
        &certificate.fingerprint_sha256,
      )),
    ))),
    Err(IpmWorkloadIdentityError::Ambiguous { presented, .. }) => Err(Box::new(workload_failure(
      "ambiguous_workload_identity",
      Some(presented_evidence(
        Some(presented),
        &certificate.fingerprint_sha256,
      )),
    ))),
  }
}

fn workload_failure(
  reason: &'static str,
  workload_identity: Option<AdminWorkloadIdentityEvidence>,
) -> AdminAuthenticationFailure {
  AdminAuthenticationFailure {
    details: AdminAuthenticationDetails {
      workload_identity,
      credential: None,
      reason,
    },
  }
}

fn workload_evidence(
  identity: IpmWorkloadIdentity,
  fingerprint_sha256: &str,
) -> AdminWorkloadIdentityEvidence {
  AdminWorkloadIdentityEvidence {
    principal: Some(identity.actor.principal.clone()),
    actor: Some(identity.actor),
    kind: Some(identity.kind.as_str().to_string()),
    identity: Some(identity.identity),
    fingerprint_sha256: Some(fingerprint_sha256.to_string()),
  }
}

fn presented_evidence(
  presented: Option<IpmPresentedWorkloadIdentity>,
  fingerprint_sha256: &str,
) -> AdminWorkloadIdentityEvidence {
  AdminWorkloadIdentityEvidence {
    actor: None,
    kind: presented
      .as_ref()
      .map(|identity| identity.kind.as_str().to_string()),
    identity: presented.map(|identity| identity.identity),
    principal: None,
    fingerprint_sha256: Some(fingerprint_sha256.to_string()),
  }
}

fn credential_evidence(
  kind: IpmAdminCredentialKind,
  identity: String,
  principal: String,
) -> AdminCredentialEvidence {
  AdminCredentialEvidence {
    kind: kind.as_str(),
    identity,
    principal,
  }
}

pub(super) fn admin_request_context<B>(
  request: &hyper::Request<B>,
  peer_addr: SocketAddr,
) -> IpmRequestContext {
  IpmRequestContext {
    source_ip: Some(peer_addr.ip()),
    method: Some(request.method().as_str().to_string()),
    host: extract_host(request).map(|host| host.into_owned()),
    path: Some(request.uri().path().to_string()),
    protocol: Some(format!("{:?}", request.version())),
    ..IpmRequestContext::default()
  }
}

fn service_for_action(action: &str) -> &str {
  action.split_once(':').map_or("*", |(service, _)| service)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn admin_ipm_request_context_populates_request_metadata() {
    let request = hyper::Request::builder()
      .method("POST")
      .uri("/admin/v1/config/status?verbose=true")
      .version(::http::Version::HTTP_11)
      .header(::http::header::HOST, "Admin.Example.COM:9443")
      .body(())
      .expect("request should build");
    let context = admin_request_context(
      &request,
      "203.0.113.9:45123"
        .parse()
        .expect("peer address should parse"),
    );

    assert_eq!(
      context.source_ip,
      Some("203.0.113.9".parse().expect("test IP should parse"))
    );
    assert_eq!(context.method.as_deref(), Some("POST"));
    assert_eq!(context.host.as_deref(), Some("admin.example.com"));
    assert_eq!(context.path.as_deref(), Some("/admin/v1/config/status"));
    assert_eq!(context.protocol.as_deref(), Some("HTTP/1.1"));
    assert!(context.route.is_none());
    assert!(context.claims.is_empty());
  }
}

#[cfg(test)]
#[path = "admin_auth_tests.rs"]
mod workload_identity_tests;

//! Admin credential classification and mTLS workload-to-principal resolution.
//!
//! The resolver only accepts certificate facts captured after a successful TLS handshake.
//! It never reads identity headers, and it maps exact SAN values to one enabled IPM principal.

use std::collections::BTreeSet;
#[cfg(test)]
use std::sync::{Arc, RwLock};

use http::HeaderMap;

use crate::config::{IpmTrustMappingConfig, IpmTrustSource};
use crate::tls::VerifiedClientCertificateIdentity;

use super::{IpmActor, IpmRuntime};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum IpmAdminCredentialKind {
  Bearer,
  BreakGlass,
  LegacyBootstrap,
}

impl IpmAdminCredentialKind {
  pub(crate) const fn as_str(self) -> &'static str {
    match self {
      Self::Bearer => "bearer",
      Self::BreakGlass => "break_glass",
      Self::LegacyBootstrap => "legacy_bootstrap",
    }
  }
}

#[derive(Debug, Clone)]
pub(crate) struct IpmAdminBearerCredential {
  pub(crate) actor: IpmActor,
  pub(crate) kind: IpmAdminCredentialKind,
  pub(crate) credential_name: String,
}

#[derive(Debug, Clone)]
pub(crate) enum IpmAdminBearerAuthentication {
  Missing,
  Invalid,
  Authenticated(IpmAdminBearerCredential),
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum IpmWorkloadIdentityKind {
  SpiffeId,
  SanUri,
  SanDns,
}

impl IpmWorkloadIdentityKind {
  pub(crate) const fn as_str(self) -> &'static str {
    match self {
      Self::SpiffeId => "spiffe_id",
      Self::SanUri => "san_uri",
      Self::SanDns => "san_dns",
    }
  }
}

#[derive(Debug, Clone)]
pub(crate) struct IpmWorkloadIdentity {
  pub(crate) actor: IpmActor,
  pub(crate) kind: IpmWorkloadIdentityKind,
  pub(crate) identity: String,
}

#[derive(Debug, Clone)]
pub(crate) struct IpmPresentedWorkloadIdentity {
  pub(crate) kind: IpmWorkloadIdentityKind,
  pub(crate) identity: String,
}

#[derive(Debug, Clone)]
pub(crate) enum IpmWorkloadIdentityError {
  Unmapped {
    presented: Option<IpmPresentedWorkloadIdentity>,
  },
  Ambiguous {
    presented: IpmPresentedWorkloadIdentity,
  },
}

impl IpmRuntime {
  pub async fn admin_actor_from_headers(&self, headers: &HeaderMap) -> Option<IpmActor> {
    match self.admin_bearer_authentication(headers).await {
      IpmAdminBearerAuthentication::Authenticated(credential) => Some(credential.actor),
      IpmAdminBearerAuthentication::Missing | IpmAdminBearerAuthentication::Invalid => None,
    }
  }

  pub async fn admin_actor_from_bearer(&self, bearer: &str) -> Option<IpmActor> {
    match self.admin_bearer_authentication_from_bearer(bearer).await {
      IpmAdminBearerAuthentication::Authenticated(credential) => Some(credential.actor),
      IpmAdminBearerAuthentication::Missing | IpmAdminBearerAuthentication::Invalid => None,
    }
  }

  pub(crate) async fn admin_bearer_authentication(
    &self,
    headers: &HeaderMap,
  ) -> IpmAdminBearerAuthentication {
    let Some(value) = headers.get(http::header::AUTHORIZATION) else {
      return IpmAdminBearerAuthentication::Missing;
    };
    let Ok(value) = value.to_str() else {
      return IpmAdminBearerAuthentication::Invalid;
    };
    let Some(bearer) = value.strip_prefix("Bearer ") else {
      return IpmAdminBearerAuthentication::Invalid;
    };
    if bearer.is_empty() {
      return IpmAdminBearerAuthentication::Invalid;
    }
    self.admin_bearer_authentication_from_bearer(bearer).await
  }

  pub(crate) fn workload_identity_from_certificate(
    &self,
    certificate: &VerifiedClientCertificateIdentity,
    trust: &[IpmTrustMappingConfig],
  ) -> Result<IpmWorkloadIdentity, IpmWorkloadIdentityError> {
    let mut matches = trust
      .iter()
      .filter(|mapping| mapping.source == IpmTrustSource::Mtls)
      .filter_map(|mapping| {
        let principal = mapping.principal.as_deref()?;
        let kind = workload_identity_kind(&mapping.claim)?;
        workload_mapping_matches(certificate, kind, &mapping.value)
          .then(|| (kind, mapping.value.clone(), principal.to_string()))
      })
      .collect::<Vec<_>>();
    matches.sort();

    let Some((kind, identity, _)) = matches.first().cloned() else {
      return Err(IpmWorkloadIdentityError::Unmapped {
        presented: presented_identity(certificate),
      });
    };
    let principals = matches
      .iter()
      .map(|(_, _, principal)| principal.clone())
      .collect::<BTreeSet<_>>();
    if principals.len() != 1 {
      return Err(IpmWorkloadIdentityError::Ambiguous {
        presented: IpmPresentedWorkloadIdentity { kind, identity },
      });
    }
    let Some(principal) = principals.into_iter().next() else {
      return Err(IpmWorkloadIdentityError::Unmapped {
        presented: Some(IpmPresentedWorkloadIdentity { kind, identity }),
      });
    };
    let snapshot = self.snapshot();
    let Some(runtime_principal) = snapshot.principals.get(&principal) else {
      return Err(IpmWorkloadIdentityError::Unmapped {
        presented: Some(IpmPresentedWorkloadIdentity { kind, identity }),
      });
    };
    if !runtime_principal.enabled {
      return Err(IpmWorkloadIdentityError::Unmapped {
        presented: Some(IpmPresentedWorkloadIdentity { kind, identity }),
      });
    }
    let mut actor = runtime_principal.actor.clone();
    actor.name = principal;
    Ok(IpmWorkloadIdentity {
      actor,
      kind,
      identity,
    })
  }

  pub(super) async fn admin_bearer_authentication_from_bearer(
    &self,
    bearer: &str,
  ) -> IpmAdminBearerAuthentication {
    if let Some(actor) = self.actor_from_regular_bearer(bearer) {
      let kind = if actor.principal == "bootstrap-admin" {
        IpmAdminCredentialKind::LegacyBootstrap
      } else {
        IpmAdminCredentialKind::Bearer
      };
      return IpmAdminBearerAuthentication::Authenticated(IpmAdminBearerCredential {
        credential_name: actor.name.clone(),
        actor,
        kind,
      });
    }
    if let Some(actor) = self.break_glass_actor_from_bearer(bearer).await {
      return IpmAdminBearerAuthentication::Authenticated(IpmAdminBearerCredential {
        credential_name: actor.name.clone(),
        actor,
        kind: IpmAdminCredentialKind::BreakGlass,
      });
    }
    IpmAdminBearerAuthentication::Invalid
  }
}

#[cfg(test)]
impl IpmRuntime {
  pub(crate) fn test_with_snapshot(snapshot: super::IpmSnapshot) -> Self {
    Self {
      inner: Arc::new(super::IpmRuntimeInner {
        namespace: "oxibelt".to_string(),
        static_snapshot: Arc::new(snapshot.clone()),
        snapshot: RwLock::new(Arc::new(snapshot)),
        store: None,
        last_refresh: RwLock::new(super::IpmRefreshState::ok(0)),
        legacy_admin_env: "OXIBELT_ADMIN_TOKEN".to_string(),
        allow_legacy_bootstrap: false,
        break_glass_verifier: super::break_glass_verifier(),
      }),
    }
  }
}

fn workload_identity_kind(value: &str) -> Option<IpmWorkloadIdentityKind> {
  match value {
    "spiffe_id" => Some(IpmWorkloadIdentityKind::SpiffeId),
    "san_uri" => Some(IpmWorkloadIdentityKind::SanUri),
    "san_dns" => Some(IpmWorkloadIdentityKind::SanDns),
    _ => None,
  }
}

fn workload_mapping_matches(
  certificate: &VerifiedClientCertificateIdentity,
  kind: IpmWorkloadIdentityKind,
  value: &str,
) -> bool {
  match kind {
    IpmWorkloadIdentityKind::SpiffeId => certificate.spiffe_ids.iter().any(|id| id == value),
    IpmWorkloadIdentityKind::SanUri => certificate.san_uri_names.iter().any(|uri| uri == value),
    IpmWorkloadIdentityKind::SanDns => certificate.san_dns_names.iter().any(|dns| dns == value),
  }
}

fn presented_identity(
  certificate: &VerifiedClientCertificateIdentity,
) -> Option<IpmPresentedWorkloadIdentity> {
  certificate
    .spiffe_ids
    .first()
    .map(|identity| IpmPresentedWorkloadIdentity {
      kind: IpmWorkloadIdentityKind::SpiffeId,
      identity: identity.clone(),
    })
    .or_else(|| {
      certificate
        .san_uri_names
        .first()
        .map(|identity| IpmPresentedWorkloadIdentity {
          kind: IpmWorkloadIdentityKind::SanUri,
          identity: identity.clone(),
        })
    })
    .or_else(|| {
      certificate
        .san_dns_names
        .first()
        .map(|identity| IpmPresentedWorkloadIdentity {
          kind: IpmWorkloadIdentityKind::SanDns,
          identity: identity.clone(),
        })
    })
}

#[cfg(test)]
mod tests {
  use std::collections::HashMap;

  use super::*;
  use crate::ipm::{IpmEntrySource, IpmPrincipalRuntime, IpmSnapshot, IpmSnapshotCounts};

  fn runtime() -> IpmRuntime {
    let mut principals = HashMap::new();
    for id in ["controller", "deployer"] {
      principals.insert(
        id.to_string(),
        IpmPrincipalRuntime {
          actor: IpmActor {
            name: id.to_string(),
            principal: id.to_string(),
            subject: format!("{id}@example.test"),
            groups: Vec::new(),
          },
          enabled: true,
          source: IpmEntrySource::Config,
        },
      );
    }
    let snapshot = IpmSnapshot {
      generation: 0,
      fingerprint: 0,
      credentials: Vec::new(),
      principals,
      policies: HashMap::new(),
      principal_bindings: HashMap::new(),
      group_bindings: HashMap::new(),
      bindings: Vec::new(),
      counts: IpmSnapshotCounts::default(),
    };
    IpmRuntime::test_with_snapshot(snapshot)
  }

  fn certificate() -> VerifiedClientCertificateIdentity {
    VerifiedClientCertificateIdentity {
      fingerprint_sha256: "a".repeat(64),
      san_dns_names: vec!["controller.example.test".to_string()],
      san_uri_names: vec!["spiffe://example.test/ns/edge/sa/controller".to_string()],
      spiffe_ids: vec!["spiffe://example.test/ns/edge/sa/controller".to_string()],
    }
  }

  fn mapping(claim: &str, value: &str, principal: &str) -> IpmTrustMappingConfig {
    IpmTrustMappingConfig {
      source: IpmTrustSource::Mtls,
      claim: claim.to_string(),
      value: value.to_string(),
      principal: Some(principal.to_string()),
      group: None,
    }
  }

  #[test]
  fn workload_identity_maps_each_supported_certificate_identity_to_one_principal() {
    let cases = [
      (
        "spiffe_id",
        "spiffe://example.test/ns/edge/sa/controller",
        IpmWorkloadIdentityKind::SpiffeId,
      ),
      (
        "san_uri",
        "spiffe://example.test/ns/edge/sa/controller",
        IpmWorkloadIdentityKind::SanUri,
      ),
      (
        "san_dns",
        "controller.example.test",
        IpmWorkloadIdentityKind::SanDns,
      ),
    ];
    for (claim, value, expected_kind) in cases {
      let identity = runtime()
        .workload_identity_from_certificate(&certificate(), &[mapping(claim, value, "controller")])
        .expect("mapping should resolve");

      assert_eq!(identity.actor.principal, "controller");
      assert_eq!(identity.actor.name, "controller");
      assert_eq!(identity.kind, expected_kind);
      assert_eq!(identity.identity, value);
    }
  }

  #[test]
  fn workload_identity_rejects_ambiguous_principals() {
    let error = runtime()
      .workload_identity_from_certificate(
        &certificate(),
        &[
          mapping(
            "spiffe_id",
            "spiffe://example.test/ns/edge/sa/controller",
            "controller",
          ),
          mapping("san_dns", "controller.example.test", "deployer"),
        ],
      )
      .expect_err("multiple principal mappings must fail closed");

    assert!(matches!(error, IpmWorkloadIdentityError::Ambiguous { .. }));
  }

  #[test]
  fn workload_identity_allows_certificate_rotation_overlap_for_one_principal() {
    let mut rotated_certificate = certificate();
    let rotated_id = "spiffe://example.test/ns/edge/sa/controller-v2".to_string();
    rotated_certificate.san_uri_names = vec![rotated_id.clone()];
    rotated_certificate.spiffe_ids = vec![rotated_id.clone()];

    let identity = runtime()
      .workload_identity_from_certificate(
        &rotated_certificate,
        &[
          mapping(
            "spiffe_id",
            "spiffe://example.test/ns/edge/sa/controller",
            "controller",
          ),
          mapping("spiffe_id", &rotated_id, "controller"),
        ],
      )
      .expect("rotated certificate should map to the same principal");

    assert_eq!(identity.actor.principal, "controller");
    assert_eq!(identity.identity, rotated_id);
  }
}

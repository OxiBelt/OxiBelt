//! Admin authentication and authorization glue around IPM decisions.
//! Denied checks can run silently when returning audit detail would disclose a protected target.

use std::net::SocketAddr;

use crate::admin_audit::AdminAuditHandle;
use crate::config::Config;
use crate::ipm::{IpmActor, IpmDecision, IpmRequestContext, IpmRuntime, resource};
use crate::proxy::http::headers::extract_host;

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

pub(super) async fn admin_actor<B>(
  request: &::http::Request<B>,
  config: &Config,
  ipm: &IpmRuntime,
) -> Option<AdminActor> {
  let actor = ipm.admin_actor_from_headers(request.headers()).await?;
  if !config.ipm.enabled && actor.principal != "bootstrap-admin" {
    return None;
  }
  Some(actor)
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

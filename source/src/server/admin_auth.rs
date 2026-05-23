use std::net::SocketAddr;

use hyper::body::Incoming;

use crate::config::Config;
use crate::ipm::{IpmActor, IpmDecision, IpmRequestContext, IpmRuntime, resource};
use crate::proxy::http::headers::extract_host;

pub(super) type AdminActor = IpmActor;

pub(super) struct AdminAuthorization<'a> {
  pub(super) actor: &'a AdminActor,
  pub(super) ipm: &'a IpmRuntime,
  context: &'a IpmRequestContext,
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
    }
  }

  pub(super) fn is_allowed(&self, action: &str, resource_name: &str) -> bool {
    admin_actor_is_allowed(self, action, resource_name)
  }
}

pub(super) fn admin_actor(
  request: &hyper::Request<Incoming>,
  config: &Config,
  ipm: &IpmRuntime,
) -> Option<AdminActor> {
  let actor = ipm.actor_from_headers(request.headers())?;
  if !config.ipm.enabled && actor.principal != "bootstrap-admin" {
    return None;
  }
  Some(actor)
}

pub(super) fn admin_actor_is_allowed(
  authorization: &AdminAuthorization<'_>,
  action: &str,
  resource_name: &str,
) -> bool {
  let resource = resource(
    authorization.ipm.namespace(),
    service_for_action(action),
    resource_name,
  );
  matches!(
    authorization.ipm.authorize(
      authorization.actor,
      action,
      &resource,
      authorization.context
    ),
    IpmDecision::Allow
  )
}

pub(super) fn admin_request_context<B>(
  request: &hyper::Request<B>,
  peer_addr: SocketAddr,
) -> IpmRequestContext {
  IpmRequestContext {
    source_ip: Some(peer_addr.ip()),
    method: Some(request.method().as_str().to_string()),
    host: extract_host(request),
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

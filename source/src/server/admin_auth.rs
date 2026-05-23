use hyper::body::Incoming;

use crate::config::Config;
use crate::ipm::{IpmActor, IpmDecision, IpmRequestContext, IpmRuntime, resource};

pub(super) type AdminActor = IpmActor;

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
  actor: &AdminActor,
  ipm: &IpmRuntime,
  action: &str,
  resource_name: &str,
) -> bool {
  let resource = resource(ipm.namespace(), service_for_action(action), resource_name);
  matches!(
    ipm.authorize(actor, action, &resource, &IpmRequestContext::default()),
    IpmDecision::Allow
  )
}

fn service_for_action(action: &str) -> &str {
  action.split_once(':').map_or("*", |(service, _)| service)
}

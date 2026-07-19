//! Admin audit enforcement gate.
//! Authorization checks are recorded without changing the decision returned by IPM.

use ::http::Response;
use std::net::SocketAddr;

use crate::admin_audit::{AdminAuditHandle, AdminAuditReservation};
use crate::proxy::http::body::ProxyBody;
use crate::state::{AppHandle, AppSnapshot};

use super::admin_error;

pub(super) fn listener_current(snapshot: &AppSnapshot, listener_bind: SocketAddr) -> bool {
  snapshot.config.admin.enabled && snapshot.config.admin.bind == listener_bind
}

pub(super) fn reserve_or_reject<B>(
  request: &mut hyper::Request<B>,
  state: &AppHandle,
  peer_addr: SocketAddr,
  scheme: &'static str,
) -> Result<(AdminAuditHandle, AdminAuditReservation), Box<Response<ProxyBody>>> {
  let method = request.method().clone();
  let path = request.uri().path().to_string();
  let query = request.uri().query().map(str::to_string);
  let audit = AdminAuditHandle::new(peer_addr, scheme, &method, &path, query.as_deref());
  let audit_runtime = state.snapshot().admin_audit.clone();
  let reservation = audit_runtime.reserve().map_err(|error| {
    let event = audit.finish_with_error(
      ::http::StatusCode::SERVICE_UNAVAILABLE,
      "admin audit unavailable",
    );
    audit_runtime.emit_unstored(event, &error);
    Box::new(admin_error::error_envelope_response(
      ::http::StatusCode::SERVICE_UNAVAILABLE,
      "admin audit unavailable",
      &audit.request_id(),
      None,
    ))
  })?;
  request.extensions_mut().insert(audit.clone());
  Ok((audit, reservation))
}

pub(super) async fn begin_authenticated_mutation(
  audit: Option<&AdminAuditHandle>,
  state: &AppHandle,
  method: &::http::Method,
  path: &str,
  skip: bool,
) -> Result<(), Box<Response<ProxyBody>>> {
  if skip {
    return Ok(());
  }
  let Some(audit) = audit else {
    return Ok(());
  };
  let Some((durability_action, resource)) = mutation_durability_scope(method, path) else {
    return Ok(());
  };
  let runtime = state.snapshot().admin_audit.clone();
  runtime
    .begin_required_mutation(audit, durability_action, resource)
    .await
    .map(|_| ())
    .map_err(|error| {
      let event = audit.finish_with_error(
        ::http::StatusCode::SERVICE_UNAVAILABLE,
        "required Admin audit persistence failed",
      );
      runtime.emit_unstored(event, &error);
      Box::new(admin_error::error_envelope_response(
        ::http::StatusCode::SERVICE_UNAVAILABLE,
        "required Admin audit persistence failed",
        &audit.request_id(),
        None,
      ))
    })
}

pub(super) async fn commit_response(
  audit: AdminAuditHandle,
  reservation: AdminAuditReservation,
  response: Response<ProxyBody>,
  state: &AppHandle,
) -> Response<ProxyBody> {
  let event = audit.finish(response.status());
  if let Err(error) = reservation.commit(&audit, event).await {
    let runtime = state.snapshot().admin_audit.clone();
    let event = audit.finish_with_error(
      ::http::StatusCode::SERVICE_UNAVAILABLE,
      "required Admin audit persistence failed",
    );
    runtime.emit_unstored(event, &error);
    return admin_error::error_envelope_response(
      ::http::StatusCode::SERVICE_UNAVAILABLE,
      "required Admin audit persistence failed",
      &audit.request_id(),
      None,
    );
  }
  response
}

pub(super) fn mutation_durability_scope(
  method: &::http::Method,
  path: &str,
) -> Option<(&'static str, &'static str)> {
  use ::http::Method;

  if matches!(
    path,
    "/cache/purge" | "/cache/purge-prefix" | "/cache/purge-tag"
  ) && *method == Method::POST
  {
    return Some(("cache.purge", "cache"));
  }
  if path == "/admin/v1/operations" && *method == Method::POST {
    return Some(("operations.write", "operations"));
  }
  if path.starts_with("/admin/v1/operations/") && *method == Method::DELETE {
    return Some(("operations.lifecycle", "operations"));
  }
  let exact = match (method, path) {
    (&Method::POST, "/admin/v1/config/load") => Some(("config.load", "config")),
    (&Method::POST, "/admin/v1/config/rollback") => Some(("config.rollback", "config")),
    (&Method::POST, "/admin/v1/config/secret-references/update") => {
      Some(("config.secret_reference_update", "config"))
    }
    (&Method::POST, "/admin/v1/tls/downstream/reload") => {
      Some(("config.downstream_tls_reload", "config"))
    }
    (&Method::POST, "/admin/v1/tls/upstream/refresh") => {
      Some(("config.upstream_tls_refresh", "config"))
    }
    (&Method::POST, "/admin/v1/keys/rotate") => Some(("config.key_rotate", "config")),
    (&Method::POST, "/admin/v1/files/sync") => Some(("config.files_sync", "config")),
    (&Method::POST, "/admin/v1/cache/warm") => Some(("cache.warm", "cache")),
    (&Method::POST, "/admin/v1/cache/purge") => Some(("cache.purge", "cache")),
    (&Method::POST, "/admin/v1/waf/person-proof/clearances/revoke") => {
      Some(("person_proof.revoke", "waf/person-proof"))
    }
    (&Method::POST, "/admin/v1/lifecycle/drain") => Some(("lifecycle.drain", "lifecycle")),
    (&Method::POST, "/admin/v1/lifecycle/undrain") => Some(("lifecycle.undrain", "lifecycle")),
    (_, path)
      if matches!(*method, Method::POST | Method::PATCH | Method::DELETE)
        && path.starts_with("/admin/v1/dynamic-policies") =>
    {
      Some(("dynamic_policy.write", "dynamic-policy"))
    }
    (_, path)
      if matches!(*method, Method::POST | Method::PATCH | Method::DELETE)
        && path.starts_with("/admin/v1/upstream-pools/")
        && path.contains("/servers") =>
    {
      Some(("upstream_pool.write", "upstream-pool"))
    }
    (_, path)
      if matches!(*method, Method::POST | Method::PATCH | Method::DELETE)
        && path.starts_with("/admin/v1/stream-pools/")
        && path.contains("/servers") =>
    {
      Some(("stream_pool.write", "stream-pool"))
    }
    _ => None,
  };
  if exact.is_some() {
    return exact;
  }
  if path.starts_with("/admin/v1/break-glass/activations") && *method == Method::POST {
    return Some(if path.ends_with("/revoke") {
      ("break_glass.revoke", "break-glass")
    } else {
      ("break_glass.activate", "break-glass")
    });
  }
  if path.starts_with("/admin/v1/ipm/")
    && matches!(*method, Method::POST | Method::PATCH | Method::DELETE)
    && path != "/admin/v1/ipm/simulate"
  {
    return Some(("ipm.write", "ipm"));
  }
  None
}

#[cfg(test)]
mod tests {
  use std::collections::HashSet;

  use super::*;
  use crate::config::ADMIN_AUDIT_DURABILITY_ACTIONS;

  #[test]
  fn mutation_classifier_covers_state_changes_without_computational_posts() {
    use ::http::Method;

    let cases = [
      (Method::POST, "/admin/v1/config/load", "config.load"),
      (Method::POST, "/admin/v1/config/rollback", "config.rollback"),
      (Method::POST, "/admin/v1/files/sync", "config.files_sync"),
      (
        Method::POST,
        "/admin/v1/tls/downstream/reload",
        "config.downstream_tls_reload",
      ),
      (
        Method::POST,
        "/admin/v1/tls/upstream/refresh",
        "config.upstream_tls_refresh",
      ),
      (Method::POST, "/admin/v1/keys/rotate", "config.key_rotate"),
      (
        Method::POST,
        "/admin/v1/config/secret-references/update",
        "config.secret_reference_update",
      ),
      (
        Method::PATCH,
        "/admin/v1/ipm/principals/controller",
        "ipm.write",
      ),
      (
        Method::POST,
        "/admin/v1/break-glass/activations",
        "break_glass.activate",
      ),
      (
        Method::POST,
        "/admin/v1/break-glass/activations/id/revoke",
        "break_glass.revoke",
      ),
      (Method::POST, "/admin/v1/operations", "operations.write"),
      (
        Method::DELETE,
        "/admin/v1/operations/id",
        "operations.lifecycle",
      ),
      (Method::POST, "/admin/v1/cache/warm", "cache.warm"),
      (Method::POST, "/admin/v1/cache/purge", "cache.purge"),
      (
        Method::POST,
        "/admin/v1/waf/person-proof/clearances/revoke",
        "person_proof.revoke",
      ),
      (Method::POST, "/admin/v1/lifecycle/drain", "lifecycle.drain"),
      (
        Method::POST,
        "/admin/v1/lifecycle/undrain",
        "lifecycle.undrain",
      ),
      (
        Method::DELETE,
        "/admin/v1/dynamic-policies/id",
        "dynamic_policy.write",
      ),
      (
        Method::PATCH,
        "/admin/v1/upstream-pools/main/servers/id",
        "upstream_pool.write",
      ),
      (
        Method::DELETE,
        "/admin/v1/stream-pools/main/servers/id",
        "stream_pool.write",
      ),
    ];
    let mut reachable = HashSet::new();
    for (method, path, expected_action) in cases {
      let (action, _) = mutation_durability_scope(&method, path)
        .unwrap_or_else(|| panic!("missing durability scope for {method} {path}"));
      assert_eq!(action, expected_action, "{method} {path}");
      reachable.insert(action);
    }
    assert_eq!(
      reachable,
      ADMIN_AUDIT_DURABILITY_ACTIONS.into_iter().collect(),
      "every configured durability action must be reachable"
    );
    for path in ["/cache/purge", "/cache/purge-prefix", "/cache/purge-tag"] {
      assert_eq!(
        mutation_durability_scope(&Method::POST, path),
        Some(("cache.purge", "cache"))
      );
    }
    for path in [
      "/admin/v1/config/validate",
      "/admin/v1/config/diff",
      "/admin/v1/ipm/simulate",
      "/admin/v1/diagnostics/preflight",
      "/admin/v1/waf/oxirule/check",
    ] {
      assert_eq!(
        mutation_durability_scope(&Method::POST, path),
        None,
        "{path}"
      );
    }
  }
}

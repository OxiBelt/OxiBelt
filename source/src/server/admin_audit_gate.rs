use ::http::Response;
use hyper::body::Incoming;
use std::net::SocketAddr;

use crate::admin_audit::{AdminAuditHandle, AdminAuditReservation};
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::AppHandle;

pub(super) fn reserve_or_reject(
  request: &mut hyper::Request<Incoming>,
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
    Box::new(text_response(
      ::http::StatusCode::SERVICE_UNAVAILABLE,
      "admin audit unavailable",
    ))
  })?;
  request.extensions_mut().insert(audit.clone());
  Ok((audit, reservation))
}

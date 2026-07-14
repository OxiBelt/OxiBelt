//! Admin audit read endpoint.
//! Audit output is authorization-gated because it can describe denied sensitive operations.

use ::http::{Response, StatusCode};
use serde_json::json;

use crate::admin_audit::AdminAuditQuery;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::AppSnapshot;

use super::admin::json_response;
use super::admin_auth::AdminAuthorization;

pub(super) async fn admin_audit_response(
  snapshot: &AppSnapshot,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  query: Option<&str>,
) -> Response<ProxyBody> {
  if *method != ::http::Method::GET {
    return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
  }
  if !authorization.is_allowed("admin:ReadAudit", "audit/admin") {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  let query = match AdminAuditQuery::from_query(query) {
    Ok(query) => query,
    Err(error) => return text_response(StatusCode::BAD_REQUEST, &error.to_string()),
  };
  match snapshot.admin_audit.query(query).await {
    Ok(audit) => json_response(StatusCode::OK, &json!({ "audit": audit })),
    Err(error) if error.to_string().contains("not configured") => {
      text_response(StatusCode::CONFLICT, &error.to_string())
    }
    Err(_) => text_response(
      StatusCode::SERVICE_UNAVAILABLE,
      "admin audit store unavailable",
    ),
  }
}

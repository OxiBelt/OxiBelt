//! WebTransport-specific limit context helpers.
//! Session limits reuse connection identity without pretending streams are HTTP requests.

use std::net::IpAddr;
use std::sync::Arc;

use http::StatusCode;

use crate::config::{ConnectionLimitConfig, LimitsConfig};

use super::{ConnectionAcquireKind, ConnectionAcquireSpec, ConnectionPermit, LimitState};

impl LimitState {
  pub fn acquire_webtransport_session(
    self: &Arc<Self>,
    ip: IpAddr,
    limits: &LimitsConfig,
    connection_limits: &[ConnectionLimitConfig],
  ) -> Result<ConnectionPermit, StatusCode> {
    let mut specs = vec![
      ConnectionAcquireSpec {
        key: "webtransport:total".to_string(),
        kind: ConnectionAcquireKind::Scoped("webtransport:total".to_string()),
        limit: limits.effective_max_webtransport_sessions(),
        status: StatusCode::SERVICE_UNAVAILABLE,
      },
      ConnectionAcquireSpec {
        key: format!("webtransport:ip:{ip}"),
        kind: ConnectionAcquireKind::Scoped(format!("webtransport:ip:{ip}")),
        limit: limits.effective_max_webtransport_sessions_per_ip(),
        status: StatusCode::TOO_MANY_REQUESTS,
      },
    ];
    specs.extend(connection_limits.iter().map(|limit| {
      let key = format!("webtransport:named:{}:{ip}", limit.name);
      ConnectionAcquireSpec {
        key: key.clone(),
        kind: ConnectionAcquireKind::Scoped(key),
        limit: limit.limit,
        status: StatusCode::from_u16(limit.status).unwrap_or(StatusCode::TOO_MANY_REQUESTS),
      }
    }));
    self.acquire_scopes(specs)
  }
}

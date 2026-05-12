use http::StatusCode;

use crate::config::ConnectionLimitIdentityMode;
use crate::limits::{ConnectionLimitContext, ConnectionPermit};
use crate::state::AppSnapshot;

pub(super) struct WebTransportSessionPermits {
  _request_connection_permit: Option<ConnectionPermit>,
  _webtransport_session_permit: ConnectionPermit,
}

pub(super) fn acquire_webtransport_session_permits(
  client_ip: std::net::IpAddr,
  connection_limit_context: Option<&ConnectionLimitContext>,
  state: &AppSnapshot,
) -> Result<WebTransportSessionPermits, StatusCode> {
  let acquire_request_connection = |ip| {
    state
      .limits
      .acquire_ip_connection(ip, &state.config.limits, &state.config.connection_limits)
  };
  let mut request_connection_permit = None;
  let limit_ip = match state.config.limits.connection_limit_identity {
    ConnectionLimitIdentityMode::ProxyProtocol => client_ip,
    ConnectionLimitIdentityMode::PerRequestRealIp => {
      request_connection_permit = Some(acquire_request_connection(client_ip)?);
      client_ip
    }
    ConnectionLimitIdentityMode::FirstRequestRealIp => {
      if let Some(context) = connection_limit_context {
        context.bind_first_request(client_ip, acquire_request_connection)?;
        context.bind_or_get_first_request_ip(client_ip)
      } else {
        request_connection_permit = Some(acquire_request_connection(client_ip)?);
        client_ip
      }
    }
  };
  let webtransport_session_permit = state.limits.acquire_webtransport_session(
    limit_ip,
    &state.config.limits,
    &state.config.connection_limits,
  )?;
  Ok(WebTransportSessionPermits {
    _request_connection_permit: request_connection_permit,
    _webtransport_session_permit: webtransport_session_permit,
  })
}

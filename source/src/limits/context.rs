use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use http::StatusCode;

use super::ConnectionPermit;

#[derive(Clone, Default)]
pub struct ConnectionLimitContext {
  first_request: Arc<Mutex<FirstRequestConnectionLimit>>,
}

#[derive(Default)]
struct FirstRequestConnectionLimit {
  ip: Option<IpAddr>,
  permit: Option<ConnectionPermit>,
}

impl ConnectionLimitContext {
  pub fn bind_first_request<F>(&self, ip: IpAddr, acquire: F) -> Result<(), StatusCode>
  where
    F: FnOnce(IpAddr) -> Result<ConnectionPermit, StatusCode>,
  {
    let mut first_request = self
      .first_request
      .lock()
      .expect("first request connection limit lock poisoned");
    let bound_ip = *first_request.ip.get_or_insert(ip);
    if first_request.permit.is_some() {
      return Ok(());
    }
    first_request.permit = Some(acquire(bound_ip)?);
    Ok(())
  }

  pub fn bind_or_get_first_request_ip(&self, ip: IpAddr) -> IpAddr {
    let mut first_request = self
      .first_request
      .lock()
      .expect("first request connection limit lock poisoned");
    *first_request.ip.get_or_insert(ip)
  }
}

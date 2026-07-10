//! Request context used by rate and connection limit keys.
//! Context values are derived once so limit decisions are consistent across modules.

use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;

use http::StatusCode;

use super::ConnectionPermit;

#[derive(Clone, Default)]
pub struct ConnectionLimitContext {
  first_request: Arc<tokio::sync::Mutex<FirstRequestConnectionLimit>>,
}

#[derive(Default)]
struct FirstRequestConnectionLimit {
  ip: Option<IpAddr>,
  permit: Option<ConnectionPermit>,
}

impl ConnectionLimitContext {
  pub async fn bind_first_request<F, Fut>(&self, ip: IpAddr, acquire: F) -> Result<(), StatusCode>
  where
    F: FnOnce(IpAddr) -> Fut,
    Fut: Future<Output = Result<ConnectionPermit, StatusCode>>,
  {
    let mut first_request = self.first_request.lock().await;
    let bound_ip = *first_request.ip.get_or_insert(ip);
    if first_request.permit.is_some() {
      return Ok(());
    }
    first_request.permit = Some(acquire(bound_ip).await?);
    Ok(())
  }

  pub async fn bind_or_get_first_request_ip(&self, ip: IpAddr) -> IpAddr {
    let mut first_request = self.first_request.lock().await;
    *first_request.ip.get_or_insert(ip)
  }
}

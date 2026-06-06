//! Runtime client identity helpers.
//! These helpers never trust client-supplied identity claims.

pub mod asn;

use crate::config::Config;
use crate::control_http::ControlHttpClient;

#[derive(Clone)]
pub struct ClientIdentityRuntime {
  pub asn: asn::AsnRuntime,
}

impl ClientIdentityRuntime {
  pub async fn new(config: &Config, control_http: &ControlHttpClient) -> anyhow::Result<Self> {
    Ok(Self {
      asn: asn::AsnRuntime::new(&config.client_identity.asn, control_http).await?,
    })
  }
}

use anyhow::Context;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::config::{Config, HttpVersion, UpstreamConfig};
use crate::routes::RouteTable;
use crate::tls;
use crate::waf::WafEngine;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type UpstreamBody = BoxBody<Bytes, BoxError>;
type HyperClient = Client<
  hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
  UpstreamBody,
>;

#[derive(Clone)]
pub struct ClientPool {
  h1_only: HyperClient,
  negotiated: HyperClient,
}

impl ClientPool {
  pub fn for_version(&self, version: HttpVersion) -> &HyperClient {
    match version {
      HttpVersion::H1 => &self.h1_only,
      HttpVersion::H2 | HttpVersion::H3 => &self.negotiated,
    }
  }
}

pub struct AppState {
  pub config: Config,
  pub route_table: RouteTable,
  pub upstreams: Vec<UpstreamConfig>,
  pub clients: ClientPool,
  pub tls_server_config: std::sync::Arc<rustls::ServerConfig>,
  pub waf: WafEngine,
}

impl AppState {
  pub fn new(config: Config) -> anyhow::Result<Self> {
    let route_table = RouteTable::new(config.routes.clone());
    let upstreams = config.upstreams.clone();
    let clients = build_clients(&config.proxy.trusted_ca_certs)
      .context("failed to build upstream HTTP clients")?;
    let tls_server_config = tls::build_server_config(&config.tls, &config.listeners)
      .context("failed to build downstream TLS config")?;
    let waf = WafEngine::new(&config).context("failed to build WAF engine")?;

    Ok(Self {
      config,
      route_table,
      upstreams,
      clients,
      tls_server_config,
      waf,
    })
  }
}

fn build_clients(extra_root_certs: &[std::path::PathBuf]) -> anyhow::Result<ClientPool> {
  let h1_tls_config = tls::build_upstream_client_config(extra_root_certs)
    .context("failed to build HTTP/1.1 upstream TLS client")?;
  let negotiated_tls_config = tls::build_upstream_client_config(extra_root_certs)
    .context("failed to build negotiated upstream TLS client")?;

  let h1_connector = HttpsConnectorBuilder::new()
    .with_tls_config(h1_tls_config)
    .https_or_http()
    .enable_http1()
    .build();
  let h1_only = Client::builder(TokioExecutor::new()).build(h1_connector);

  let negotiated_connector = HttpsConnectorBuilder::new()
    .with_tls_config(negotiated_tls_config)
    .https_or_http()
    .enable_http1()
    .enable_http2()
    .build();
  let negotiated = Client::builder(TokioExecutor::new()).build(negotiated_connector);

  Ok(ClientPool {
    h1_only,
    negotiated,
  })
}

use std::convert::Infallible;
use std::time::Duration;

use anyhow::{Context, anyhow};
use bytes::Bytes;
use http::{Request, Response, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full, Limited};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};

use crate::config::UpstreamEchConfig;
use crate::tls;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ControlBody = BoxBody<Bytes, BoxError>;

#[derive(Clone)]
pub struct ControlHttpClient {
  client: Client<hyper_rustls::HttpsConnector<HttpConnector>, ControlBody>,
}

pub struct ControlHttpResponse {
  pub status: http::StatusCode,
  pub headers: http::HeaderMap,
  pub body: Bytes,
}

impl ControlHttpClient {
  pub fn new(extra_root_certs: &[std::path::PathBuf]) -> anyhow::Result<Self> {
    let tls_config =
      tls::build_upstream_client_config(extra_root_certs, &UpstreamEchConfig::default())
        .context("failed to build control-plane TLS client config")?;
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_connect_timeout(Some(Duration::from_secs(5)));
    http.set_nodelay(true);
    let connector = HttpsConnectorBuilder::new()
      .with_tls_config(tls_config)
      .https_or_http()
      .enable_http1()
      .enable_http2()
      .wrap_connector(http);
    let mut builder = Client::builder(TokioExecutor::new());
    builder.pool_timer(TokioTimer::new());
    builder.pool_idle_timeout(Duration::from_secs(30));
    builder.pool_max_idle_per_host(16);
    Ok(Self {
      client: builder.build(connector),
    })
  }

  pub async fn request(
    &self,
    request: Request<ControlBody>,
    timeout: Duration,
    max_body_bytes: usize,
  ) -> anyhow::Result<ControlHttpResponse> {
    let response = tokio::time::timeout(timeout, self.client.request(request))
      .await
      .context("control-plane HTTP request timed out")?
      .context("control-plane HTTP request failed")?;
    collect_response(response, max_body_bytes).await
  }
}

async fn collect_response(
  response: Response<Incoming>,
  max_body_bytes: usize,
) -> anyhow::Result<ControlHttpResponse> {
  let (parts, body) = response.into_parts();
  let collected = Limited::new(body, max_body_bytes)
    .collect()
    .await
    .map_err(|error| anyhow!("control-plane HTTP response body failed: {error}"))?;
  Ok(ControlHttpResponse {
    status: parts.status,
    headers: parts.headers,
    body: collected.to_bytes(),
  })
}

pub fn empty_body() -> ControlBody {
  Empty::<Bytes>::new()
    .map_err(|never: Infallible| -> BoxError { match never {} })
    .boxed()
}

pub fn full_body(bytes: Bytes) -> ControlBody {
  Full::new(bytes)
    .map_err(|never: Infallible| -> BoxError { match never {} })
    .boxed()
}

pub fn uri_from_url(url: &url::Url) -> anyhow::Result<Uri> {
  url
    .as_str()
    .parse::<Uri>()
    .with_context(|| format!("invalid control-plane URL {url}"))
}

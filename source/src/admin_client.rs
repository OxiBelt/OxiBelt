//! Minimal admin HTTP client used by local tooling and tests.
//! Request construction stays narrow so admin authentication material is handled consistently.

use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use bytes::Bytes;
use http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full, Limited};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::{ClientConfig, RootCertStore};
use url::Url;

pub const DEFAULT_ADMIN_URL: &str = "http://127.0.0.1:9092";
pub const DEFAULT_ADMIN_TOKEN_ENV: &str = "OXIBELT_ADMIN_TOKEN";
pub const BREAK_GLASS_TOKEN_ENV: &str = "OXIBELT_BREAK_GLASS_TOKEN";

const DEFAULT_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type AdminBody = BoxBody<Bytes, BoxError>;

#[derive(Debug, Clone)]
pub struct AdminClientOptions {
  pub admin_url: Url,
  pub token: String,
  pub timeout: Duration,
  pub ca_certs: Vec<PathBuf>,
  pub client_cert: Option<PathBuf>,
  pub client_key: Option<PathBuf>,
  pub max_body_bytes: usize,
  /// Enable RFC 10024 SecP256r1MLKEM768 for this Admin TLS client.
  pub admin_tls_secp256r1mlkem768: bool,
  /// Enable RFC 10024 SecP256r1MLKEM768 for owned auxiliary HTTPS clients.
  pub auxiliary_tls_secp256r1mlkem768: bool,
}

impl AdminClientOptions {
  pub fn new(admin_url: Url, token: String, timeout: Duration) -> Self {
    Self {
      admin_url,
      token,
      timeout,
      ca_certs: Vec::new(),
      client_cert: None,
      client_key: None,
      max_body_bytes: DEFAULT_MAX_BODY_BYTES,
      admin_tls_secp256r1mlkem768: false,
      auxiliary_tls_secp256r1mlkem768: false,
    }
  }
}

#[derive(Clone)]
pub struct AdminClient {
  client: Client<hyper_rustls::HttpsConnector<HttpConnector>, AdminBody>,
  options: AdminClientOptions,
}

#[derive(Debug)]
pub struct AdminResponse {
  pub status: StatusCode,
  pub headers: HeaderMap,
  pub body: Bytes,
}

impl AdminClient {
  pub fn new(options: AdminClientOptions) -> anyhow::Result<Self> {
    let enabled = options.admin_tls_secp256r1mlkem768;
    Self::new_with_secp256r1mlkem768(options, enabled)
  }

  pub fn new_with_secp256r1mlkem768(
    mut options: AdminClientOptions,
    enable_secp256r1mlkem768: bool,
  ) -> anyhow::Result<Self> {
    options.admin_tls_secp256r1mlkem768 = enable_secp256r1mlkem768;
    let tls_config = build_tls_config(
      &options.ca_certs,
      options.client_cert.as_deref(),
      options.client_key.as_deref(),
      options.admin_tls_secp256r1mlkem768,
    )?;
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
    builder.pool_max_idle_per_host(8);
    Ok(Self {
      client: builder.build(connector),
      options,
    })
  }

  pub fn timeout(&self) -> Duration {
    self.options.timeout
  }

  pub fn auxiliary_tls_secp256r1mlkem768(&self) -> bool {
    self.options.auxiliary_tls_secp256r1mlkem768
  }

  pub async fn request_json(
    &self,
    method: Method,
    endpoint: &str,
    body: Option<serde_json::Value>,
    if_match: Option<&str>,
  ) -> anyhow::Result<AdminResponse> {
    self
      .request_json_with_extra_headers(method, endpoint, body, if_match, &HeaderMap::new())
      .await
  }

  pub async fn request_json_with_extra_headers(
    &self,
    method: Method,
    endpoint: &str,
    body: Option<serde_json::Value>,
    if_match: Option<&str>,
    extra_headers: &HeaderMap,
  ) -> anyhow::Result<AdminResponse> {
    let bytes = match body {
      Some(value) => Some(serde_json::to_vec(&value).context("failed to encode Admin JSON body")?),
      None => None,
    };
    self
      .request_with_extra_headers(method, endpoint, bytes, if_match, extra_headers)
      .await
  }

  pub async fn request(
    &self,
    method: Method,
    endpoint: &str,
    body: Option<Vec<u8>>,
    if_match: Option<&str>,
  ) -> anyhow::Result<AdminResponse> {
    self
      .request_with_extra_headers(method, endpoint, body, if_match, &HeaderMap::new())
      .await
  }

  pub async fn request_with_extra_headers(
    &self,
    method: Method,
    endpoint: &str,
    body: Option<Vec<u8>>,
    if_match: Option<&str>,
    extra_headers: &HeaderMap,
  ) -> anyhow::Result<AdminResponse> {
    validate_extra_headers(extra_headers)?;
    let url = admin_endpoint_url(&self.options.admin_url, endpoint)?;
    let mut builder = Request::builder()
      .method(method)
      .uri(url.as_str())
      .header(
        http::header::AUTHORIZATION,
        bearer_header(&self.options.token)?,
      )
      .header(http::header::ACCEPT, "application/json");
    if let Some(if_match) = if_match {
      builder = builder.header(http::header::IF_MATCH, if_match);
    }
    for (name, value) in extra_headers {
      builder = builder.header(name, value);
    }
    let body = match body {
      Some(body) => {
        builder = builder
          .header(http::header::CONTENT_TYPE, "application/json")
          .header(http::header::CONTENT_LENGTH, body.len().to_string());
        full_body(Bytes::from(body))
      }
      None => empty_body(),
    };
    let request = builder
      .body(body)
      .context("failed to build Admin request")?;
    tokio::time::timeout(self.options.timeout, async {
      let response = self
        .client
        .request(request)
        .await
        .context("Admin HTTP request failed")?;
      collect_response(response, self.options.max_body_bytes).await
    })
    .await
    .context("Admin HTTP request timed out")?
  }
}

pub fn read_token(token_env: &str, token_file: Option<&Path>) -> anyhow::Result<String> {
  let token = match token_file {
    Some(path) => std::fs::read_to_string(path)
      .with_context(|| format!("failed to read Admin token file {}", path.display()))?,
    None => std::env::var(token_env)
      .with_context(|| format!("Admin token environment variable {token_env} is not set"))?,
  };
  let token = token.trim().to_string();
  if token.is_empty() {
    bail!("Admin token is empty");
  }
  Ok(token)
}

pub fn admin_endpoint_url(base: &Url, endpoint: &str) -> anyhow::Result<Url> {
  if !endpoint.starts_with('/') {
    bail!("Admin endpoint must start with /");
  }
  let mut root = base.clone();
  root.set_path("");
  root.set_query(None);
  root.set_fragment(None);
  root
    .join(endpoint.trim_start_matches('/'))
    .with_context(|| format!("failed to join Admin endpoint {endpoint}"))
}

async fn collect_response(
  response: http::Response<Incoming>,
  max_body_bytes: usize,
) -> anyhow::Result<AdminResponse> {
  let (parts, body) = response.into_parts();
  let collected = Limited::new(body, max_body_bytes)
    .collect()
    .await
    .map_err(|error| anyhow::anyhow!("Admin response body failed: {error}"))?;
  Ok(AdminResponse {
    status: parts.status,
    headers: parts.headers,
    body: collected.to_bytes(),
  })
}

fn build_tls_config(
  extra_roots: &[PathBuf],
  client_cert: Option<&Path>,
  client_key: Option<&Path>,
  enable_secp256r1mlkem768: bool,
) -> anyhow::Result<ClientConfig> {
  let provider = if enable_secp256r1mlkem768 {
    crate::tls::aws_lc_provider_with_secp256r1mlkem768(true)
  } else {
    crate::tls::default_crypto_provider()
  };
  let roots = load_root_store(extra_roots)?;
  let builder = ClientConfig::builder_with_provider(provider.into())
    .with_safe_default_protocol_versions()
    .context("failed to configure Admin TLS protocol versions")?
    .with_root_certificates(roots);
  match (client_cert, client_key) {
    (Some(cert), Some(key)) => builder
      .with_client_auth_cert(load_certs(cert)?, load_private_key(key)?)
      .context("failed to configure Admin client certificate"),
    (None, None) => Ok(builder.with_no_client_auth()),
    _ => bail!("--client-cert and --client-key must be supplied together"),
  }
}

fn load_root_store(extra_roots: &[PathBuf]) -> anyhow::Result<RootCertStore> {
  let mut roots = RootCertStore::empty();
  roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
  for path in extra_roots {
    let certs = load_certs(path)?;
    let (added, _ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
      bail!(
        "no parsable Admin CA certificates found in {}",
        path.display()
      );
    }
  }
  Ok(roots)
}

fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
  let bytes = std::fs::read(path)
    .with_context(|| format!("failed to read certificate PEM {}", path.display()))?;
  let certs = CertificateDer::pem_slice_iter(&bytes)
    .collect::<Result<Vec<_>, _>>()
    .with_context(|| format!("failed to parse certificate PEM {}", path.display()))?;
  if certs.is_empty() {
    bail!(
      "certificate PEM {} did not contain certificates",
      path.display()
    );
  }
  Ok(certs)
}

fn load_private_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
  let bytes = std::fs::read(path)
    .with_context(|| format!("failed to read private key PEM {}", path.display()))?;
  PrivateKeyDer::from_pem_slice(&bytes).map_err(|error| match error {
    rustls::pki_types::pem::Error::NoItemsFound => {
      anyhow::anyhow!("private key PEM {} did not contain a key", path.display())
    }
    error => anyhow::anyhow!(
      "failed to parse private key PEM {}: {error}",
      path.display()
    ),
  })
}

fn bearer_header(token: &str) -> anyhow::Result<http::HeaderValue> {
  http::HeaderValue::from_str(&format!("Bearer {token}")).context("Admin token is not header-safe")
}

fn validate_extra_headers(headers: &HeaderMap) -> anyhow::Result<()> {
  const RESERVED: [&str; 14] = [
    "authorization",
    "accept",
    "connection",
    "content-type",
    "content-length",
    "cookie",
    "if-match",
    "host",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
  ];
  if let Some(name) = headers
    .keys()
    .find(|name| RESERVED.contains(&name.as_str()))
  {
    bail!("Admin extra header {name} is managed by AdminClient");
  }
  Ok(())
}

fn empty_body() -> AdminBody {
  Empty::<Bytes>::new()
    .map_err(|never: Infallible| -> BoxError { match never {} })
    .boxed()
}

fn full_body(bytes: Bytes) -> AdminBody {
  Full::new(bytes)
    .map_err(|never: Infallible| -> BoxError { match never {} })
    .boxed()
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::Arc;

  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  use tokio::net::TcpListener;
  use tokio_rustls::TlsAcceptor;

  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  #[test]
  fn joins_admin_endpoint_from_root_url() {
    let base = Url::parse("http://127.0.0.1:9092").expect("url");
    let joined = admin_endpoint_url(&base, "/admin/v1/config/status").expect("join");
    assert_eq!(
      joined.as_str(),
      "http://127.0.0.1:9092/admin/v1/config/status"
    );
  }

  #[test]
  fn joins_admin_endpoint_from_base_path_by_resetting_path() {
    let base = Url::parse("https://ops.example.test/base/path?old=1").expect("url");
    let joined = admin_endpoint_url(&base, "/admin/v1/ipm/simulate").expect("join");
    assert_eq!(
      joined.as_str(),
      "https://ops.example.test/admin/v1/ipm/simulate"
    );
  }

  #[test]
  fn rejects_relative_admin_endpoint() {
    let base = Url::parse(DEFAULT_ADMIN_URL).expect("url");
    assert!(admin_endpoint_url(&base, "admin/v1/config/status").is_err());
  }

  #[test]
  fn rejects_extra_headers_managed_by_the_client() {
    let mut headers = HeaderMap::new();
    headers.insert(
      http::header::AUTHORIZATION,
      "Bearer replacement".parse().expect("header"),
    );
    assert!(validate_extra_headers(&headers).is_err());

    headers.clear();
    headers.insert("x-oxibelt-mutation", "signed".parse().expect("header"));
    assert!(validate_extra_headers(&headers).is_ok());
  }

  #[test]
  fn admin_tls_secp256r1mlkem768_is_opt_in() {
    let options = AdminClientOptions::new(
      Url::parse(DEFAULT_ADMIN_URL).expect("url"),
      "token".to_string(),
      Duration::from_secs(1),
    );
    assert!(!options.admin_tls_secp256r1mlkem768);
    assert!(!options.auxiliary_tls_secp256r1mlkem768);
    AdminClient::new(options.clone()).expect("default Admin client should build");
    AdminClient::new_with_secp256r1mlkem768(options, true)
      .expect("opt-in Admin client should build");

    let mut options = AdminClientOptions::new(
      Url::parse(DEFAULT_ADMIN_URL).expect("url"),
      "token".to_string(),
      Duration::from_secs(1),
    );
    options.admin_tls_secp256r1mlkem768 = true;
    AdminClient::new(options).expect("field-enabled Admin client should build");
  }

  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn admin_tls_secp256r1mlkem768_handshakes_only_when_enabled() {
    const TEST_TIMEOUT: Duration = Duration::from_secs(3);
    let temp_dir = common::TempDir::new("admin-pq-target-handshake");
    let (ca_path, ca_key) = common::create_self_signed_cert(temp_dir.path(), "admin-pq-ca");
    let (cert_path, key_path) =
      common::create_ca_signed_server_cert(temp_dir.path(), "localhost", &ca_path, &ca_key);
    let listener = TcpListener::bind("127.0.0.1:0")
      .await
      .expect("Admin TLS test listener should bind");
    let address = listener
      .local_addr()
      .expect("Admin TLS test listener should have an address");

    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::SECP256R1MLKEM768];
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
      .with_safe_default_protocol_versions()
      .expect("target-only server TLS versions should configure")
      .with_no_client_auth()
      .with_single_cert(
        load_certs(&cert_path).expect("test certificate should load"),
        load_private_key(&key_path).expect("test key should load"),
      )
      .expect("target-only server TLS config should build");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let server = tokio::spawn(async move {
      let mut outcomes = Vec::with_capacity(2);
      for _ in 0..2 {
        let (stream, _) = tokio::time::timeout(TEST_TIMEOUT, listener.accept())
          .await
          .expect("Admin TLS test server accept should not time out")
          .expect("Admin TLS test server should accept");
        let handshake = tokio::time::timeout(TEST_TIMEOUT, acceptor.accept(stream)).await;
        match handshake {
          Ok(Ok(mut stream)) => {
            outcomes.push(true);
            let mut request = [0_u8; 1024];
            tokio::time::timeout(TEST_TIMEOUT, stream.read(&mut request))
              .await
              .expect("Admin TLS test server read should not time out")
              .expect("Admin TLS test server should read the request");
            tokio::time::timeout(
              TEST_TIMEOUT,
              stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
            )
            .await
            .expect("Admin TLS test server write should not time out")
            .expect("Admin TLS test server should write the response");
          }
          _ => outcomes.push(false),
        }
      }
      outcomes
    });

    let admin_url = |enabled| {
      Url::parse(&format!("https://localhost:{}", address.port()))
        .map(|admin_url| {
          let mut options = AdminClientOptions::new(admin_url, "token".to_string(), TEST_TIMEOUT);
          options.ca_certs = vec![ca_path.clone()];
          options.admin_tls_secp256r1mlkem768 = enabled;
          options
        })
        .expect("Admin TLS test URL should parse")
    };
    let default_client =
      AdminClient::new(admin_url(false)).expect("default Admin client should build");
    let default_result = tokio::time::timeout(
      TEST_TIMEOUT,
      default_client.request(Method::GET, "/admin/v1/config/status", None, None),
    )
    .await
    .expect("default Admin request should not time out");
    assert!(
      default_result.is_err(),
      "default Admin TLS client must reject a target-only peer"
    );

    let enabled_client =
      AdminClient::new(admin_url(true)).expect("opt-in Admin client should build");
    let response = tokio::time::timeout(
      TEST_TIMEOUT,
      enabled_client.request(Method::GET, "/admin/v1/config/status", None, None),
    )
    .await
    .expect("opt-in Admin request should not time out")
    .expect("opt-in Admin client should handshake with target-only peer");
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body.as_ref(), b"ok");

    assert_eq!(
      server.await.expect("Admin TLS test server should finish"),
      vec![false, true]
    );
  }
}

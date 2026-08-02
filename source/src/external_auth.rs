//! External authorization runtime and request projection.
//! The proxy treats external auth failures as policy decisions instead of transport shortcuts.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use base64::Engine;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use tracing::warn;
use url::form_urlencoded;
use zeroize::Zeroizing;

use crate::config::{
  Config, ExternalAuthClaimHeader, ExternalAuthConfig, ExternalAuthFailPolicy, ExternalAuthProvider,
};
use crate::control_http::{ControlHttpClient, empty_body, full_body, uri_from_url};
use crate::metrics::Metrics;
use crate::proxy::http::body::{ProxyBody, materialized_known_small_body};

#[derive(Clone)]
pub struct ExternalAuthRuntime {
  inner: Option<Arc<ExternalAuthInner>>,
}

struct ExternalAuthInner {
  providers: HashMap<String, ExternalAuthProviderRuntime>,
  client: ControlHttpClient,
  metrics: Arc<Metrics>,
}

#[derive(Clone)]
struct ExternalAuthProviderRuntime {
  config: ExternalAuthConfig,
  forward_headers: Vec<HeaderName>,
  identity_headers: Vec<HeaderName>,
  terminal_response_headers: HashSet<HeaderName>,
  claim_headers: Vec<(String, HeaderName)>,
  client_credentials: Option<ClientCredentials>,
}

#[derive(Clone)]
struct ClientCredentials {
  id: Zeroizing<String>,
  secret: Zeroizing<String>,
}

pub enum ExternalAuthOutcome {
  Allowed,
  Denied(ExternalAuthTerminal),
}

pub struct ExternalAuthTerminal {
  pub status: StatusCode,
  pub headers: HeaderMap,
  pub body: Bytes,
}

struct ExternalAuthRequestContext<'a> {
  method: &'a Method,
  uri: &'a http::Uri,
  headers: &'a HeaderMap,
  client_ip: std::net::IpAddr,
  host: &'a str,
  downstream_scheme: &'a str,
  route_name: &'a str,
}

#[derive(Debug, Deserialize)]
struct OAuth2IntrospectionResponse {
  #[serde(default)]
  active: bool,
  #[serde(default)]
  scope: Option<String>,
  #[serde(default)]
  sub: Option<String>,
  #[serde(default)]
  username: Option<String>,
  #[serde(default)]
  email: Option<String>,
  #[serde(default)]
  groups: Option<JsonValue>,
}

impl ExternalAuthRuntime {
  pub fn new(
    config: &Config,
    client: ControlHttpClient,
    metrics: Arc<Metrics>,
  ) -> anyhow::Result<Self> {
    if config.external_auth.is_empty() {
      return Ok(Self::disabled());
    }
    let providers = config
      .external_auth
      .iter()
      .map(build_provider_runtime)
      .collect::<anyhow::Result<HashMap<_, _>>>()?;
    Ok(Self {
      inner: Some(Arc::new(ExternalAuthInner {
        providers,
        client,
        metrics,
      })),
    })
  }

  pub fn disabled() -> Self {
    Self { inner: None }
  }

  #[allow(clippy::too_many_arguments)]
  pub async fn authorize<B>(
    &self,
    provider_name: &str,
    request: &mut Request<B>,
    client_ip: std::net::IpAddr,
    host: &str,
    downstream_scheme: &str,
    route_name: &str,
  ) -> ExternalAuthOutcome {
    let Some(inner) = &self.inner else {
      return ExternalAuthOutcome::Allowed;
    };
    let Some(provider) = inner.providers.get(provider_name) else {
      warn!(
        provider = provider_name,
        "route references missing external auth provider"
      );
      inner.metrics.record_external_auth_error();
      return fail_closed(
        StatusCode::INTERNAL_SERVER_ERROR,
        "external auth provider is not configured",
      );
    };

    strip_identity_headers(request.headers_mut(), &provider.identity_headers);
    let context = ExternalAuthRequestContext {
      method: request.method(),
      uri: request.uri(),
      headers: request.headers(),
      client_ip,
      host,
      downstream_scheme,
      route_name,
    };
    let result = match provider.config.provider {
      ExternalAuthProvider::Authelia => inner.check_forward_auth(provider, context, None).await,
      ExternalAuthProvider::GatewayExtAuthHttp => {
        inner.check_forward_auth(provider, context, None).await
      }
      ExternalAuthProvider::OAuth2 => inner.check_oauth2(provider, context).await,
      ExternalAuthProvider::Oidc => inner.check_oidc(provider, context).await,
    };
    finish_auth_check(request, provider, inner.metrics.as_ref(), result)
  }

  /// Authorize an HTTP request, forwarding a bounded, replayable body only for
  /// the Gateway API HTTP external-auth provider.
  #[allow(clippy::too_many_arguments)]
  pub async fn authorize_http(
    &self,
    provider_name: &str,
    request: &mut Request<ProxyBody>,
    client_ip: std::net::IpAddr,
    host: &str,
    downstream_scheme: &str,
    route_name: &str,
    request_body_limit: usize,
    request_body_timeout: Duration,
  ) -> ExternalAuthOutcome {
    let Some(inner) = &self.inner else {
      return ExternalAuthOutcome::Allowed;
    };
    let Some(provider) = inner.providers.get(provider_name) else {
      warn!(
        provider = provider_name,
        "route references missing external auth provider"
      );
      inner.metrics.record_external_auth_error();
      return fail_closed(
        StatusCode::INTERNAL_SERVER_ERROR,
        "external auth provider is not configured",
      );
    };

    strip_identity_headers(request.headers_mut(), &provider.identity_headers);
    let forwarded_body = if provider.config.provider == ExternalAuthProvider::GatewayExtAuthHttp
      && provider.config.max_request_body_bytes > 0
    {
      match capture_gateway_request_body(
        request,
        provider,
        request_body_limit,
        request_body_timeout,
      )
      .await
      {
        Ok(body) => Some(body),
        Err(terminal) => {
          inner.metrics.record_external_auth_denied();
          return ExternalAuthOutcome::Denied(terminal);
        }
      }
    } else {
      None
    };
    let context = ExternalAuthRequestContext {
      method: request.method(),
      uri: request.uri(),
      headers: request.headers(),
      client_ip,
      host,
      downstream_scheme,
      route_name,
    };
    let result = match provider.config.provider {
      ExternalAuthProvider::Authelia => inner.check_forward_auth(provider, context, None).await,
      ExternalAuthProvider::GatewayExtAuthHttp => {
        inner
          .check_forward_auth(provider, context, forwarded_body)
          .await
      }
      ExternalAuthProvider::OAuth2 => inner.check_oauth2(provider, context).await,
      ExternalAuthProvider::Oidc => inner.check_oidc(provider, context).await,
    };
    finish_auth_check(request, provider, inner.metrics.as_ref(), result)
  }
}

async fn capture_gateway_request_body(
  request: &mut Request<ProxyBody>,
  provider: &ExternalAuthProviderRuntime,
  request_body_limit: usize,
  request_body_timeout: Duration,
) -> Result<Bytes, ExternalAuthTerminal> {
  let limit = provider
    .config
    .max_request_body_bytes
    .min(request_body_limit);
  if request
    .headers()
    .get(http::header::CONTENT_LENGTH)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.parse::<usize>().ok())
    .is_some_and(|length| length > limit)
  {
    return Err(external_auth_request_rejection(
      StatusCode::PAYLOAD_TOO_LARGE,
      "external auth request body exceeds configured limit",
    ));
  }

  let original_body = std::mem::replace(
    request.body_mut(),
    materialized_known_small_body(Bytes::new(), None),
  );
  let collected = tokio::time::timeout(
    request_body_timeout,
    collect_bounded_request_body(original_body, limit),
  )
  .await
  .map_err(|_| {
    external_auth_request_rejection(
      StatusCode::REQUEST_TIMEOUT,
      "external auth request body timed out",
    )
  })?
  .map_err(|error| match error {
    ExternalAuthRequestBodyError::TooLarge => external_auth_request_rejection(
      StatusCode::PAYLOAD_TOO_LARGE,
      "external auth request body exceeds configured limit",
    ),
    ExternalAuthRequestBodyError::Body(error) => {
      warn!(error = %error, "failed to read external auth request body");
      external_auth_request_rejection(
        StatusCode::BAD_REQUEST,
        "failed to read external auth request body",
      )
    }
  })?;
  let (body, trailers) = collected;
  *request.body_mut() = materialized_known_small_body(body.clone(), trailers);

  if !body.is_empty() && !gateway_content_type_allowed(request.headers(), provider) {
    return Err(external_auth_request_rejection(
      StatusCode::UNSUPPORTED_MEDIA_TYPE,
      "external auth request body content type is not allowed",
    ));
  }
  Ok(body)
}

enum ExternalAuthRequestBodyError {
  TooLarge,
  Body(crate::proxy::http::body::BoxError),
}

async fn collect_bounded_request_body(
  mut body: ProxyBody,
  limit: usize,
) -> Result<(Bytes, Option<HeaderMap>), ExternalAuthRequestBodyError> {
  let mut bytes = bytes::BytesMut::new();
  let mut trailers = None;
  while let Some(frame) = body.frame().await {
    let frame = frame.map_err(ExternalAuthRequestBodyError::Body)?;
    match frame.into_data() {
      Ok(data) => {
        let Some(total) = bytes.len().checked_add(data.len()) else {
          return Err(ExternalAuthRequestBodyError::TooLarge);
        };
        if total > limit {
          return Err(ExternalAuthRequestBodyError::TooLarge);
        }
        bytes.extend_from_slice(&data);
      }
      Err(frame) => {
        if let Ok(frame_trailers) = frame.into_trailers() {
          trailers = Some(frame_trailers);
        }
      }
    }
  }
  Ok((bytes.freeze(), trailers))
}

fn gateway_content_type_allowed(
  headers: &HeaderMap,
  provider: &ExternalAuthProviderRuntime,
) -> bool {
  let Some(content_type) = headers
    .get(http::header::CONTENT_TYPE)
    .and_then(|value| value.to_str().ok())
    .map(|value| {
      value
        .split(';')
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase()
    })
  else {
    return false;
  };
  provider
    .config
    .allowed_content_types
    .iter()
    .any(|allowed| allowed.eq_ignore_ascii_case(&content_type))
}

fn gateway_auth_uri(endpoint: &url::Url, request_uri: &http::Uri) -> anyhow::Result<http::Uri> {
  let mut target = endpoint.clone();
  let prefix = endpoint.path().trim_end_matches('/');
  let original_path = request_uri.path();
  let path = if prefix.is_empty() {
    original_path.to_string()
  } else if original_path == "/" {
    format!("{prefix}/")
  } else {
    format!("{prefix}/{}", original_path.trim_start_matches('/'))
  };
  target.set_path(&path);
  target.set_query(request_uri.query());
  target.set_fragment(None);
  uri_from_url(&target)
}

fn external_auth_request_rejection(status: StatusCode, message: &str) -> ExternalAuthTerminal {
  ExternalAuthTerminal {
    status,
    headers: HeaderMap::new(),
    body: Bytes::copy_from_slice(message.as_bytes()),
  }
}

impl ExternalAuthInner {
  async fn check_forward_auth(
    &self,
    provider: &ExternalAuthProviderRuntime,
    context: ExternalAuthRequestContext<'_>,
    forwarded_body: Option<Bytes>,
  ) -> anyhow::Result<AuthCheck> {
    let is_gateway = provider.config.provider == ExternalAuthProvider::GatewayExtAuthHttp;
    let request_uri = if is_gateway {
      gateway_auth_uri(&provider.config.endpoint, context.uri)?
    } else {
      uri_from_url(&provider.config.endpoint)?
    };
    let mut builder = Request::builder()
      .method(if is_gateway {
        context.method.clone()
      } else {
        Method::GET
      })
      .uri(request_uri);
    let headers = builder
      .headers_mut()
      .ok_or_else(|| anyhow::anyhow!("external auth request builder rejected headers"))?;
    add_forward_auth_headers(headers, provider, &context);
    if is_gateway {
      headers.remove(http::header::CONTENT_LENGTH);
      headers.remove(http::header::TRANSFER_ENCODING);
      if let Some(body) = forwarded_body.as_ref() {
        if let Some(content_type) = context.headers.get(http::header::CONTENT_TYPE) {
          headers.insert(http::header::CONTENT_TYPE, content_type.clone());
        }
        headers.insert(
          http::header::CONTENT_LENGTH,
          HeaderValue::from_str(&body.len().to_string())
            .context("failed to encode external auth request body length")?,
        );
      }
    }
    let request = builder
      .body(forwarded_body.map_or_else(empty_body, full_body))
      .context("failed to build external auth request")?;
    let response = self
      .client
      .request(
        request,
        Duration::from_millis(provider.config.timeout_ms),
        provider.config.max_response_body_bytes,
      )
      .await?;
    if response.status.is_success() {
      return Ok(AuthCheck::Allowed(identity_from_headers(
        &response.headers,
        &provider.identity_headers,
      )));
    }
    Ok(AuthCheck::Denied(filter_terminal_response(
      response.status,
      response.headers,
      response.body,
      provider,
    )))
  }

  async fn check_oauth2(
    &self,
    provider: &ExternalAuthProviderRuntime,
    context: ExternalAuthRequestContext<'_>,
  ) -> anyhow::Result<AuthCheck> {
    let Some(token) = bearer_token(context.headers) else {
      return Ok(unauthorized("missing bearer token"));
    };
    let body = {
      let mut form = form_urlencoded::Serializer::new(String::new());
      form.append_pair("token", token);
      Bytes::from(form.finish())
    };
    let mut builder = Request::builder()
      .method(Method::POST)
      .uri(uri_from_url(&provider.config.endpoint)?)
      .header(
        http::header::CONTENT_TYPE,
        "application/x-www-form-urlencoded",
      )
      .header(http::header::ACCEPT, "application/json");
    if let Some(credentials) = &provider.client_credentials {
      builder = builder.header(http::header::AUTHORIZATION, basic_auth(credentials));
    }
    let request = builder
      .body(full_body(body))
      .context("failed to build OAuth2 introspection request")?;
    let response = self
      .client
      .request(
        request,
        Duration::from_millis(provider.config.timeout_ms),
        provider.config.max_response_body_bytes,
      )
      .await?;
    if !response.status.is_success() {
      return Ok(unauthorized("token introspection failed"));
    }
    let document: OAuth2IntrospectionResponse = serde_json::from_slice(&response.body)
      .context("OAuth2 introspection response is not JSON")?;
    if !document.active {
      return Ok(unauthorized("inactive bearer token"));
    }
    if !required_scopes_match(document.scope.as_deref(), &provider.config.required_scopes) {
      return Ok(forbidden("required token scope is missing"));
    }
    let mut identity = HashMap::new();
    if let Some(user) = document.sub.or(document.username) {
      identity.insert("remote-user".to_string(), user);
    }
    if let Some(email) = document.email {
      identity.insert("remote-email".to_string(), email);
    }
    if let Some(groups) = groups_to_header(document.groups.as_ref()) {
      identity.insert("remote-groups".to_string(), groups);
    }
    Ok(AuthCheck::Allowed(identity))
  }

  async fn check_oidc(
    &self,
    provider: &ExternalAuthProviderRuntime,
    context: ExternalAuthRequestContext<'_>,
  ) -> anyhow::Result<AuthCheck> {
    let Some(token) = bearer_token(context.headers) else {
      return Ok(unauthorized("missing bearer token"));
    };
    let request = Request::builder()
      .method(Method::GET)
      .uri(uri_from_url(&provider.config.endpoint)?)
      .header(http::header::ACCEPT, "application/json")
      .header(http::header::AUTHORIZATION, format!("Bearer {token}"))
      .body(empty_body())
      .context("failed to build OIDC UserInfo request")?;
    let response = self
      .client
      .request(
        request,
        Duration::from_millis(provider.config.timeout_ms),
        provider.config.max_response_body_bytes,
      )
      .await?;
    if !response.status.is_success() {
      return Ok(unauthorized("userinfo request failed"));
    }
    let document: JsonValue =
      serde_json::from_slice(&response.body).context("OIDC UserInfo response is not JSON")?;
    for requirement in &provider.config.required_claims {
      if claim_to_string(document.get(&requirement.name)).as_deref() != Some(&requirement.value) {
        return Ok(forbidden("required OIDC claim is missing"));
      }
    }
    let mut identity = HashMap::new();
    for (claim, header) in &provider.claim_headers {
      if let Some(value) = claim_to_string(document.get(claim)) {
        identity.insert(header.as_str().to_string(), value);
      }
    }
    Ok(AuthCheck::Allowed(identity))
  }
}

enum AuthCheck {
  Allowed(HashMap<String, String>),
  Denied(ExternalAuthTerminal),
}

fn build_provider_runtime(
  config: &ExternalAuthConfig,
) -> anyhow::Result<(String, ExternalAuthProviderRuntime)> {
  let forward_headers = parse_headers(&config.forward_headers)?;
  let identity_headers = parse_headers(&config.identity_headers)?;
  let terminal_response_headers = parse_headers(&config.terminal_response_headers)?
    .into_iter()
    .collect::<HashSet<_>>();
  let claim_headers = config
    .claim_headers
    .iter()
    .map(parse_claim_header)
    .collect::<anyhow::Result<Vec<_>>>()?;
  let client_credentials = match (&config.client_id_env, &config.client_secret_env) {
    (Some(id_env), Some(secret_env)) => Some(ClientCredentials {
      id: Zeroizing::new(
        std::env::var(id_env)
          .with_context(|| format!("failed to read external_auth {} client_id_env", config.name))?,
      ),
      secret: Zeroizing::new(std::env::var(secret_env).with_context(|| {
        format!(
          "failed to read external_auth {} client_secret_env",
          config.name
        )
      })?),
    }),
    _ => None,
  };
  Ok((
    config.name.clone(),
    ExternalAuthProviderRuntime {
      config: config.clone(),
      forward_headers,
      identity_headers,
      terminal_response_headers,
      claim_headers,
      client_credentials,
    },
  ))
}

fn parse_headers(headers: &[String]) -> anyhow::Result<Vec<HeaderName>> {
  headers
    .iter()
    .map(|header| {
      HeaderName::from_bytes(header.as_bytes())
        .with_context(|| format!("invalid external auth header {header}"))
    })
    .collect()
}

fn parse_claim_header(mapping: &ExternalAuthClaimHeader) -> anyhow::Result<(String, HeaderName)> {
  Ok((
    mapping.claim.clone(),
    HeaderName::from_bytes(mapping.header.as_bytes())
      .with_context(|| format!("invalid external auth claim header {}", mapping.header))?,
  ))
}

fn add_forward_auth_headers(
  headers: &mut HeaderMap,
  provider: &ExternalAuthProviderRuntime,
  context: &ExternalAuthRequestContext<'_>,
) {
  for name in &provider.forward_headers {
    if oxibelt_control_protocol::is_reserved_route_request_header(name.as_str()) {
      continue;
    }
    if let Some(value) = context.headers.get(name) {
      headers.insert(name.clone(), value.clone());
    }
  }
  if provider.config.provider == ExternalAuthProvider::Authelia {
    for name in [
      http::header::ACCEPT,
      HeaderName::from_static("x-requested-with"),
    ] {
      if let Some(value) = context.headers.get(&name) {
        headers.insert(name, value.clone());
      }
    }
  }
  let forwarded_uri = context
    .uri
    .path_and_query()
    .map(|value| value.as_str())
    .unwrap_or("/");
  insert_header(headers, "x-forwarded-method", context.method.as_str());
  insert_header(headers, "x-forwarded-uri", forwarded_uri);
  insert_header(headers, "x-forwarded-host", context.host);
  insert_header(headers, "x-forwarded-proto", context.downstream_scheme);
  insert_header(headers, "x-forwarded-for", &context.client_ip.to_string());
  insert_header(headers, "x-forwarded-route", context.route_name);
  insert_header(
    headers,
    "x-original-url",
    &format!(
      "{}://{}{}",
      context.downstream_scheme, context.host, forwarded_uri
    ),
  );
}

fn insert_header(headers: &mut HeaderMap, name: &'static str, value: &str) {
  if let Ok(value) = HeaderValue::from_str(value) {
    headers.insert(HeaderName::from_static(name), value);
  }
}

fn strip_identity_headers(headers: &mut HeaderMap, names: &[HeaderName]) {
  for name in names {
    if oxibelt_control_protocol::is_reserved_route_request_header(name.as_str()) {
      continue;
    }
    headers.remove(name);
  }
}

fn apply_identity_headers(
  headers: &mut HeaderMap,
  provider: &ExternalAuthProviderRuntime,
  identity: HashMap<String, String>,
) {
  for name in &provider.identity_headers {
    if oxibelt_control_protocol::is_reserved_route_request_header(name.as_str()) {
      continue;
    }
    if let Some(value) = identity.get(name.as_str())
      && let Ok(value) = HeaderValue::from_str(value)
    {
      headers.insert(name.clone(), value);
    }
  }
}

fn identity_from_headers(
  headers: &HeaderMap,
  identity_headers: &[HeaderName],
) -> HashMap<String, String> {
  let mut identity = HashMap::new();
  for name in identity_headers {
    if let Some(value) = headers.get(name)
      && let Ok(value) = value.to_str()
    {
      identity.insert(name.as_str().to_string(), value.to_string());
    }
  }
  identity
}

fn filter_terminal_response(
  status: StatusCode,
  headers: HeaderMap,
  body: Bytes,
  provider: &ExternalAuthProviderRuntime,
) -> ExternalAuthTerminal {
  let mut filtered = HeaderMap::new();
  for (name, value) in headers {
    if let Some(name) = name
      && provider.terminal_response_headers.contains(&name)
      && !oxibelt_control_protocol::is_forbidden_route_action_header(name.as_str())
    {
      filtered.append(name, value);
    }
  }
  ExternalAuthTerminal {
    status,
    headers: filtered,
    body,
  }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
  let raw = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
  let mut parts = raw.split_whitespace();
  let scheme = parts.next()?;
  let token = parts.next()?;
  if parts.next().is_some() || !scheme.eq_ignore_ascii_case("Bearer") {
    return None;
  }
  Some(token)
}

fn required_scopes_match(scope: Option<&str>, required: &[String]) -> bool {
  if required.is_empty() {
    return true;
  }
  let Some(scope) = scope else {
    return false;
  };
  let scopes = scope.split_whitespace().collect::<HashSet<_>>();
  required.iter().all(|scope| scopes.contains(scope.as_str()))
}

fn groups_to_header(groups: Option<&JsonValue>) -> Option<String> {
  match groups? {
    JsonValue::Array(values) => {
      let groups = values
        .iter()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>();
      (!groups.is_empty()).then(|| groups.join(","))
    }
    JsonValue::String(value) if !value.is_empty() => Some(value.clone()),
    _ => None,
  }
}

fn claim_to_string(value: Option<&JsonValue>) -> Option<String> {
  match value? {
    JsonValue::String(value) => Some(value.clone()),
    JsonValue::Bool(value) => Some(value.to_string()),
    JsonValue::Number(value) => Some(value.to_string()),
    JsonValue::Array(values) => {
      let values = values
        .iter()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>();
      (!values.is_empty()).then(|| values.join(","))
    }
    _ => None,
  }
}

fn basic_auth(credentials: &ClientCredentials) -> String {
  let raw = Zeroizing::new(format!(
    "{}:{}",
    credentials.id.as_str(),
    credentials.secret.as_str()
  ));
  format!(
    "Basic {}",
    base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())
  )
}

fn unauthorized(message: &str) -> AuthCheck {
  AuthCheck::Denied(ExternalAuthTerminal {
    status: StatusCode::UNAUTHORIZED,
    headers: www_authenticate_header(),
    body: Bytes::from(message.to_string()),
  })
}

fn forbidden(message: &str) -> AuthCheck {
  AuthCheck::Denied(ExternalAuthTerminal {
    status: StatusCode::FORBIDDEN,
    headers: HeaderMap::new(),
    body: Bytes::from(message.to_string()),
  })
}

fn fail_closed(status: StatusCode, message: &str) -> ExternalAuthOutcome {
  ExternalAuthOutcome::Denied(ExternalAuthTerminal {
    status,
    headers: HeaderMap::new(),
    body: Bytes::from(message.to_string()),
  })
}

fn finish_auth_check<B>(
  request: &mut Request<B>,
  provider: &ExternalAuthProviderRuntime,
  metrics: &Metrics,
  result: anyhow::Result<AuthCheck>,
) -> ExternalAuthOutcome {
  match result {
    Ok(AuthCheck::Allowed(identity)) => {
      apply_identity_headers(request.headers_mut(), provider, identity);
      metrics.record_external_auth_allowed();
      ExternalAuthOutcome::Allowed
    }
    Ok(AuthCheck::Denied(terminal)) => {
      metrics.record_external_auth_denied();
      ExternalAuthOutcome::Denied(terminal)
    }
    Err(error) if provider.config.fail_policy == ExternalAuthFailPolicy::Open => {
      warn!(provider = %provider.config.name, error = %error, "external auth failed open");
      metrics.record_external_auth_error();
      ExternalAuthOutcome::Allowed
    }
    Err(error) => {
      warn!(provider = %provider.config.name, error = %error, "external auth failed closed");
      metrics.record_external_auth_error();
      fail_closed(
        StatusCode::SERVICE_UNAVAILABLE,
        "external authorization failed",
      )
    }
  }
}

fn www_authenticate_header() -> HeaderMap {
  let mut headers = HeaderMap::new();
  headers.insert(
    http::header::WWW_AUTHENTICATE,
    HeaderValue::from_static("Bearer"),
  );
  headers
}

#[cfg(test)]
mod tests;

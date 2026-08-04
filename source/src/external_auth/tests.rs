use super::*;

fn provider_with_headers(
  identity_headers: &[&str],
  terminal_headers: &[&str],
) -> ExternalAuthProviderRuntime {
  provider_with_kind_and_fail_policy(
    ExternalAuthProvider::Authelia,
    ExternalAuthFailPolicy::Closed,
    identity_headers,
    terminal_headers,
  )
}

fn provider_with_kind_and_fail_policy(
  provider: ExternalAuthProvider,
  fail_policy: ExternalAuthFailPolicy,
  identity_headers: &[&str],
  terminal_headers: &[&str],
) -> ExternalAuthProviderRuntime {
  ExternalAuthProviderRuntime {
    config: ExternalAuthConfig {
      name: "edge-auth".to_string(),
      provider,
      endpoint: "http://127.0.0.1:9000/api/authz/forward-auth"
        .parse()
        .expect("valid auth endpoint"),
      timeout_ms: 1_000,
      fail_policy,
      forward_headers: Vec::new(),
      identity_headers: identity_headers
        .iter()
        .map(|header| header.to_string())
        .collect(),
      terminal_response_headers: terminal_headers
        .iter()
        .map(|header| header.to_string())
        .collect(),
      max_response_body_bytes: 4_096,
      max_request_body_bytes: 0,
      allowed_content_types: Vec::new(),
      client_id_env: None,
      client_secret_env: None,
      required_scopes: Vec::new(),
      required_claims: Vec::new(),
      claim_headers: Vec::new(),
    },
    forward_headers: Vec::new(),
    identity_headers: identity_headers
      .iter()
      .map(|header| HeaderName::from_bytes(header.as_bytes()).expect("valid header"))
      .collect(),
    terminal_response_headers: terminal_headers
      .iter()
      .map(|header| HeaderName::from_bytes(header.as_bytes()).expect("valid header"))
      .collect(),
    claim_headers: Vec::new(),
    client_credentials: None,
  }
}

fn prometheus_for(metrics: &Metrics) -> String {
  metrics.prometheus(
    &crate::config::MetricsConfig::default(),
    crate::cache::CacheStats::default(),
    crate::tls::TlsServerSessionStorageStats::default(),
  )
}

fn assert_metric(output: &str, metric: &str, value: u64) {
  assert!(
    output.contains(&format!("{metric} {value}\n")),
    "missing {metric} {value} in:\n{output}"
  );
}

fn projected_forward_auth_headers(
  provider: &ExternalAuthProviderRuntime,
  request_headers: &HeaderMap,
  uri: &'static str,
) -> HeaderMap {
  let method = Method::GET;
  let uri = http::Uri::from_static(uri);
  let context = ExternalAuthRequestContext {
    method: &method,
    uri: &uri,
    headers: request_headers,
    client_ip: "192.0.2.10".parse().expect("valid client IP"),
    host: "vault.example.test",
    downstream_scheme: "https",
    route_name: "vault-admin",
  };
  let mut headers = HeaderMap::new();
  add_forward_auth_headers(&mut headers, provider, &context);
  headers
}

#[test]
fn forward_auth_headers_project_origin_absolute_and_authority_targets() {
  let provider = provider_with_headers(&[], &[]);
  let request_headers = HeaderMap::new();
  for (uri, expected_uri) in [
    ("/admin?view=summary", "/admin?view=summary"),
    (
      "https://vault.example.test/admin?view=summary",
      "/admin?view=summary",
    ),
    ("vault.example.test:443", "/"),
  ] {
    let headers = projected_forward_auth_headers(&provider, &request_headers, uri);

    assert_eq!(headers["x-forwarded-uri"], expected_uri);
    assert_eq!(
      headers["x-original-url"],
      format!("https://vault.example.test{expected_uri}")
    );
    assert_eq!(headers["x-forwarded-method"], "GET");
    assert_eq!(headers["x-forwarded-host"], "vault.example.test");
    assert_eq!(headers["x-forwarded-proto"], "https");
    assert_eq!(headers["x-forwarded-for"], "192.0.2.10");
    assert_eq!(headers["x-forwarded-route"], "vault-admin");
  }
}

#[test]
fn gateway_forward_auth_projects_only_explicit_request_headers() {
  let mut provider = provider_with_kind_and_fail_policy(
    ExternalAuthProvider::GatewayExtAuthHttp,
    ExternalAuthFailPolicy::Closed,
    &[],
    &[],
  );
  let mut request_headers = HeaderMap::new();
  request_headers.insert(
    http::header::AUTHORIZATION,
    HeaderValue::from_static("Bearer downstream-token"),
  );
  request_headers.insert("x-explicit", HeaderValue::from_static("tenant-a"));

  let omitted = projected_forward_auth_headers(&provider, &request_headers, "/admin");
  assert!(omitted.get(http::header::AUTHORIZATION).is_none());
  assert!(omitted.get("x-explicit").is_none());

  provider.forward_headers = vec![HeaderName::from_static("x-explicit")];
  let unrelated = projected_forward_auth_headers(&provider, &request_headers, "/admin");
  assert!(unrelated.get(http::header::AUTHORIZATION).is_none());
  assert_eq!(unrelated.get("x-explicit").unwrap(), "tenant-a");

  provider.forward_headers = vec![http::header::AUTHORIZATION];
  let authorized = projected_forward_auth_headers(&provider, &request_headers, "/admin");
  assert_eq!(
    authorized.get(http::header::AUTHORIZATION).unwrap(),
    "Bearer downstream-token"
  );
  assert!(authorized.get("x-explicit").is_none());
}

#[test]
fn gateway_auth_endpoint_path_prefixes_original_path_and_query() {
  let endpoint = "https://auth.example.test/ext-auth/"
    .parse()
    .expect("valid auth endpoint");
  let original = "/orders/42?expand=items"
    .parse()
    .expect("valid original URI");

  let target = gateway_auth_uri(&endpoint, &original).expect("gateway auth URI should build");

  assert_eq!(
    target,
    "https://auth.example.test/ext-auth/orders/42?expand=items"
  );
}

#[tokio::test]
async fn gateway_request_body_capture_replays_body_and_enforces_policy() {
  let mut provider = provider_with_kind_and_fail_policy(
    ExternalAuthProvider::GatewayExtAuthHttp,
    ExternalAuthFailPolicy::Closed,
    &[],
    &[],
  );
  provider.config.max_request_body_bytes = 4;
  provider.config.allowed_content_types = vec!["application/json".to_string()];
  let mut request = Request::builder()
    .header(
      http::header::CONTENT_TYPE,
      "application/json; charset=utf-8",
    )
    .header(http::header::CONTENT_LENGTH, "4")
    .body(materialized_known_small_body(
      Bytes::from_static(b"body"),
      None,
    ))
    .expect("request should build");

  let captured = match capture_gateway_request_body(
    &mut request,
    &provider,
    16,
    std::time::Duration::from_secs(1),
  )
  .await
  {
    Ok(captured) => captured,
    Err(terminal) => panic!(
      "allowed request body should be captured, got status {}",
      terminal.status
    ),
  };

  assert_eq!(captured, Bytes::from_static(b"body"));
  let replayed = request
    .into_body()
    .collect()
    .await
    .expect("primary body should replay")
    .to_bytes();
  assert_eq!(replayed, Bytes::from_static(b"body"));

  let mut oversized = Request::builder()
    .header(http::header::CONTENT_TYPE, "application/json")
    .header(http::header::CONTENT_LENGTH, "5")
    .body(materialized_known_small_body(
      Bytes::from_static(b"12345"),
      None,
    ))
    .expect("request should build");
  let terminal = capture_gateway_request_body(
    &mut oversized,
    &provider,
    16,
    std::time::Duration::from_secs(1),
  )
  .await
  .expect_err("oversized request body must fail closed");
  assert_eq!(terminal.status, StatusCode::PAYLOAD_TOO_LARGE);

  let mut disallowed = Request::builder()
    .header(http::header::CONTENT_TYPE, "text/plain")
    .body(materialized_known_small_body(
      Bytes::from_static(b"body"),
      None,
    ))
    .expect("request should build");
  let terminal = capture_gateway_request_body(
    &mut disallowed,
    &provider,
    16,
    std::time::Duration::from_secs(1),
  )
  .await
  .expect_err("disallowed request body content type must fail closed");
  assert_eq!(terminal.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn gateway_forward_auth_dispatches_original_method_prefixed_path_and_body() {
  use tokio::io::{AsyncReadExt, AsyncWriteExt};

  let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
    .await
    .expect("capture listener should bind");
  let address = listener.local_addr().expect("listener address");
  let (capture_sender, capture_receiver) = tokio::sync::oneshot::channel();
  tokio::spawn(async move {
    let (mut stream, _) = listener.accept().await.expect("auth request should arrive");
    let mut request = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
      let read = stream.read(&mut buffer).await.expect("request should read");
      if read == 0 {
        break;
      }
      request.extend_from_slice(&buffer[..read]);
      let Some(headers_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
        continue;
      };
      let headers_end = headers_end + 4;
      let headers = String::from_utf8_lossy(&request[..headers_end]);
      let content_length = headers
        .lines()
        .find_map(|line| {
          let (name, value) = line.split_once(':')?;
          name
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
        })
        .unwrap_or(0);
      if request.len() >= headers_end + content_length {
        break;
      }
    }
    let _ = capture_sender.send(request);
    stream
      .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
      .await
      .expect("auth response should write");
  });

  let mut provider = provider_with_kind_and_fail_policy(
    ExternalAuthProvider::GatewayExtAuthHttp,
    ExternalAuthFailPolicy::Closed,
    &[],
    &[],
  );
  provider.config.endpoint = format!("http://{address}/authz/")
    .parse()
    .expect("valid local endpoint");
  let method = Method::POST;
  let uri = http::Uri::from_static("/orders/42?expand=items");
  let mut headers = HeaderMap::new();
  headers.insert(
    http::header::CONTENT_TYPE,
    HeaderValue::from_static("application/json"),
  );
  let context = ExternalAuthRequestContext {
    method: &method,
    uri: &uri,
    headers: &headers,
    client_ip: "192.0.2.10".parse().expect("valid client IP"),
    host: "shop.example.test",
    downstream_scheme: "https",
    route_name: "orders",
  };
  let inner = ExternalAuthInner {
    providers: HashMap::new(),
    client: ControlHttpClient::new(&[]).expect("control client should build"),
    metrics: Arc::new(Metrics::default()),
  };

  let result = inner
    .check_forward_auth(&provider, context, Some(Bytes::from_static(b"{}")))
    .await
    .expect("gateway auth request should succeed");
  assert!(matches!(result, AuthCheck::Allowed(_)));
  let captured = capture_receiver
    .await
    .expect("captured auth request should be delivered");
  let captured = String::from_utf8(captured).expect("captured request should be UTF-8");
  assert!(captured.starts_with("POST /authz/orders/42?expand=items HTTP/1.1\r\n"));
  assert!(
    captured
      .to_ascii_lowercase()
      .contains("content-type: application/json\r\n")
  );
  assert!(
    captured
      .to_ascii_lowercase()
      .contains("content-length: 2\r\n")
  );
  assert!(captured.ends_with("\r\n\r\n{}"));
}

#[test]
fn authelia_forward_auth_projects_browser_classification_headers() {
  let provider = provider_with_headers(&[], &[]);
  let mut request_headers = HeaderMap::new();
  request_headers.insert(
    http::header::ACCEPT,
    HeaderValue::from_static("text/html,application/xhtml+xml"),
  );
  request_headers.insert(
    "x-requested-with",
    HeaderValue::from_static("XMLHttpRequest"),
  );
  request_headers.insert("x-unconfigured", HeaderValue::from_static("dropped"));

  let headers = projected_forward_auth_headers(&provider, &request_headers, "/admin");

  assert_eq!(
    headers.get(http::header::ACCEPT).unwrap(),
    "text/html,application/xhtml+xml"
  );
  assert_eq!(headers.get("x-requested-with").unwrap(), "XMLHttpRequest");
  assert!(headers.get("x-unconfigured").is_none());
}

#[test]
fn authelia_forward_auth_does_not_synthesize_or_share_classification_headers() {
  let authelia = provider_with_headers(&[], &[]);
  let empty_request_headers = HeaderMap::new();
  let authelia_headers =
    projected_forward_auth_headers(&authelia, &empty_request_headers, "/admin");
  assert!(authelia_headers.get(http::header::ACCEPT).is_none());
  assert!(authelia_headers.get("x-requested-with").is_none());

  let gateway = provider_with_kind_and_fail_policy(
    ExternalAuthProvider::GatewayExtAuthHttp,
    ExternalAuthFailPolicy::Closed,
    &[],
    &[],
  );
  let mut gateway_request_headers = HeaderMap::new();
  gateway_request_headers.insert(http::header::ACCEPT, HeaderValue::from_static("text/html"));
  gateway_request_headers.insert(
    "x-requested-with",
    HeaderValue::from_static("XMLHttpRequest"),
  );
  let gateway_headers = projected_forward_auth_headers(&gateway, &gateway_request_headers, "/");
  assert!(gateway_headers.get(http::header::ACCEPT).is_none());
  assert!(gateway_headers.get("x-requested-with").is_none());
}

#[test]
fn bearer_token_accepts_case_insensitive_scheme_and_rejects_ambiguous_values() {
  let mut headers = HeaderMap::new();
  headers.insert(
    http::header::AUTHORIZATION,
    HeaderValue::from_static("bearer token-123"),
  );
  assert_eq!(bearer_token(&headers), Some("token-123"));

  headers.insert(
    http::header::AUTHORIZATION,
    HeaderValue::from_static("Bearer token extra"),
  );
  assert_eq!(bearer_token(&headers), None);

  headers.insert(
    http::header::AUTHORIZATION,
    HeaderValue::from_static("Basic token-123"),
  );
  assert_eq!(bearer_token(&headers), None);
}

#[test]
fn required_scopes_must_all_be_present() {
  let required = vec!["read".to_string(), "admin".to_string()];
  assert!(required_scopes_match(Some("openid read admin"), &required));
  assert!(!required_scopes_match(Some("openid read"), &required));
  assert!(!required_scopes_match(None, &required));
  assert!(required_scopes_match(None, &[]));
}

#[test]
fn identity_headers_are_stripped_then_reapplied_from_trusted_values() {
  let provider = provider_with_headers(&["remote-user", "remote-email"], &[]);
  let mut request = Request::builder()
    .header("remote-user", "spoofed")
    .header("remote-email", "spoofed@example.com")
    .body(())
    .expect("request builds");

  strip_identity_headers(request.headers_mut(), &provider.identity_headers);
  assert!(request.headers().get("remote-user").is_none());
  assert!(request.headers().get("remote-email").is_none());

  apply_identity_headers(
    request.headers_mut(),
    &provider,
    HashMap::from([("remote-user".to_string(), "alice".to_string())]),
  );
  assert_eq!(request.headers().get("remote-user").unwrap(), "alice");
  assert!(request.headers().get("remote-email").is_none());
}

#[test]
fn denied_forward_auth_response_preserves_unauthorized_status_and_allowlisted_headers() {
  let provider = provider_with_headers(&[], &["location", "set-cookie"]);
  let mut headers = HeaderMap::new();
  headers.insert(http::header::LOCATION, HeaderValue::from_static("/login"));
  headers.append(http::header::SET_COOKIE, HeaderValue::from_static("sid=1"));
  headers.insert("x-internal-error", HeaderValue::from_static("secret"));

  let terminal = filter_terminal_response(
    StatusCode::UNAUTHORIZED,
    headers,
    Bytes::from_static(b"unauthorized"),
    &provider,
  );

  assert_eq!(terminal.status, StatusCode::UNAUTHORIZED);
  assert_eq!(terminal.body, Bytes::from_static(b"unauthorized"));
  assert_eq!(
    terminal.headers.get(http::header::LOCATION).unwrap(),
    "/login"
  );
  assert_eq!(
    terminal.headers.get(http::header::SET_COOKIE).unwrap(),
    "sid=1"
  );
  assert!(terminal.headers.get("x-internal-error").is_none());
}

#[test]
fn invalid_runtime_header_lists_cannot_mutate_message_framing() {
  let provider = provider_with_headers(&["content-length"], &["content-length"]);
  let mut request = Request::builder()
    .header(http::header::CONTENT_LENGTH, "4")
    .body(())
    .expect("request builds");

  strip_identity_headers(request.headers_mut(), &provider.identity_headers);
  apply_identity_headers(
    request.headers_mut(),
    &provider,
    HashMap::from([("content-length".to_string(), "999".to_string())]),
  );
  assert_eq!(request.headers()[http::header::CONTENT_LENGTH], "4");

  let mut headers = HeaderMap::new();
  headers.insert(
    http::header::CONTENT_LENGTH,
    HeaderValue::from_static("999"),
  );
  let terminal = filter_terminal_response(
    StatusCode::UNAUTHORIZED,
    headers,
    Bytes::from_static(b"denied"),
    &provider,
  );
  assert!(terminal.headers.get(http::header::CONTENT_LENGTH).is_none());
}

#[test]
fn gateway_http_auth_outcomes_record_allow_deny_and_error_paths() {
  let metrics = Metrics::default();
  let provider = provider_with_kind_and_fail_policy(
    ExternalAuthProvider::GatewayExtAuthHttp,
    ExternalAuthFailPolicy::Closed,
    &["x-auth-user"],
    &[],
  );
  let mut request = Request::builder().body(()).expect("request should build");

  let allowed = finish_auth_check(
    &mut request,
    &provider,
    &metrics,
    Ok(AuthCheck::Allowed(HashMap::from([(
      "x-auth-user".to_string(),
      "alice".to_string(),
    )]))),
  );
  assert!(matches!(allowed, ExternalAuthOutcome::Allowed));
  assert_eq!(request.headers().get("x-auth-user").unwrap(), "alice");

  let denied = finish_auth_check(
    &mut request,
    &provider,
    &metrics,
    Ok(AuthCheck::Denied(ExternalAuthTerminal {
      status: StatusCode::FORBIDDEN,
      headers: HeaderMap::new(),
      body: Bytes::from_static(b"denied"),
    })),
  );
  assert!(matches!(
    denied,
    ExternalAuthOutcome::Denied(ExternalAuthTerminal {
      status: StatusCode::FORBIDDEN,
      ..
    })
  ));

  let failed_closed = finish_auth_check(
    &mut request,
    &provider,
    &metrics,
    Err(anyhow::anyhow!("auth backend unavailable")),
  );
  assert!(matches!(
    failed_closed,
    ExternalAuthOutcome::Denied(ExternalAuthTerminal {
      status: StatusCode::SERVICE_UNAVAILABLE,
      ..
    })
  ));

  let fail_open_provider = provider_with_kind_and_fail_policy(
    ExternalAuthProvider::GatewayExtAuthHttp,
    ExternalAuthFailPolicy::Open,
    &[],
    &[],
  );
  let fail_open = finish_auth_check(
    &mut request,
    &fail_open_provider,
    &metrics,
    Err(anyhow::anyhow!("temporary auth backend error")),
  );
  assert!(matches!(fail_open, ExternalAuthOutcome::Allowed));

  let output = prometheus_for(&metrics);
  assert_metric(&output, "oxibelt_external_auth_allowed_total", 1);
  assert_metric(&output, "oxibelt_external_auth_denied_total", 1);
  assert_metric(&output, "oxibelt_external_auth_errors_total", 2);
}

#[test]
fn claim_values_are_rendered_only_for_header_safe_scalars_and_string_arrays() {
  assert_eq!(
    claim_to_string(Some(&serde_json::json!(["dev", "ops"]))),
    Some("dev,ops".to_string())
  );
  assert_eq!(
    claim_to_string(Some(&serde_json::json!(true))),
    Some("true".to_string())
  );
  assert_eq!(
    claim_to_string(Some(&serde_json::json!({ "sub": "a" }))),
    None
  );
}

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::Engine;
use http::{HeaderMap, Method, StatusCode, Uri};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::model::{AUTHORITY_VERSION, Authority, LEGACY_AUTHORITY_VERSION};
use super::{CacheGroupOrigin, CacheGroupRequest};
use crate::cache::external_handler::{
  ExternalCacheEntryMetadata, ExternalCacheHeader, ExternalCacheLookupRequest, PROTOCOL_VERSION,
};
use crate::cache::{
  CacheGroupStamp, CacheLookupContext, ExternalCacheRuntime, ResponseCache, system_time_ms,
};
use crate::config::Config;
use crate::runtime_health::RuntimeHealth;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

struct HandlerState {
  value: Vec<u8>,
  exchanges: usize,
  legacy_stamp: CacheGroupStamp,
}

async fn read_request(stream: &mut TcpStream, buffered: &mut Vec<u8>) -> Option<(String, Vec<u8>)> {
  loop {
    if let Some(headers_end) = buffered.windows(4).position(|window| window == b"\r\n\r\n") {
      let headers = std::str::from_utf8(&buffered[..headers_end]).ok()?;
      let content_length = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
      let total = headers_end.checked_add(4)?.checked_add(content_length)?;
      if buffered.len() >= total {
        let first = headers.lines().next()?.to_string();
        let request = buffered.drain(..total).collect::<Vec<_>>();
        return Some((first, request[headers_end + 4..].to_vec()));
      }
    }
    let mut next = [0u8; 4096];
    let read = stream.read(&mut next).await.ok()?;
    if read == 0 {
      return None;
    }
    buffered.extend_from_slice(&next[..read]);
  }
}

async fn serve_connection(mut stream: TcpStream, state: Arc<Mutex<HandlerState>>) {
  let mut buffered = Vec::new();
  while let Some((first, body)) = read_request(&mut stream, &mut buffered).await {
    let path = first.split_whitespace().nth(1).unwrap_or_default();
    let response = if path.ends_with("/cache-group-state") {
      let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
      let mut state = state.lock().unwrap();
      let value = match request["mode"].as_str() {
        Some("read") => serde_json::json!({
          "value_base64": base64::engine::general_purpose::STANDARD.encode(&state.value),
          "capabilities": ["cache-groups-v1"],
        }),
        Some("compare_exchange") => {
          let expected = request["expected_base64"]
            .as_str()
            .and_then(|value| base64::engine::general_purpose::STANDARD.decode(value).ok());
          let replacement = request["replacement_base64"]
            .as_str()
            .and_then(|value| base64::engine::general_purpose::STANDARD.decode(value).ok())
            .unwrap();
          let exchanged = expected.as_deref() == Some(state.value.as_slice());
          if exchanged {
            state.value = replacement;
            state.exchanges += 1;
          }
          serde_json::json!({
            "exchanged": exchanged,
            "capabilities": ["cache-groups-v1"],
          })
        }
        _ => unreachable!(),
      };
      serde_json::to_vec(&value).unwrap()
    } else if path.ends_with("/lookup") {
      let request: ExternalCacheLookupRequest = serde_json::from_slice(&body).unwrap();
      let stamp = state.lock().unwrap().legacy_stamp.clone();
      let mut variant_key = crate::cache::variant_key(&request.partition, &request.base_key, &[]);
      variant_key.push_str(&format!(
        "\ngroup-generation={}:{}",
        stamp.incarnation, stamp.sequence
      ));
      let body = b"legacy external";
      let metadata = ExternalCacheEntryMetadata {
        protocol_version: PROTOCOL_VERSION.to_string(),
        cache_key_version: request.cache_key_version,
        policy: request.policy,
        partition: request.partition,
        base_key: request.base_key,
        variant_key,
        scheme: request.scheme,
        host: request.host,
        uri: request.uri,
        status: StatusCode::OK.as_u16(),
        headers: vec![ExternalCacheHeader::new(
          "cache-control".to_string(),
          b"public, max-age=60",
        )],
        security_headers_neutral: true,
        body_len: body.len(),
        stored_at_ms: system_time_ms(SystemTime::now()),
        expires_at_ms: system_time_ms(SystemTime::now() + Duration::from_secs(60)),
        stale_if_error_until_ms: None,
        stale_while_revalidate_until_ms: None,
        must_revalidate: false,
        vary: Vec::new(),
        tags: Vec::new(),
        query_target_epoch: None,
        dictionary_identity: None,
        no_vary_search: None,
        group_stamp: Some(stamp),
        capabilities: vec!["cache-groups-v1".to_string()],
      };
      let metadata = serde_json::to_vec(&metadata).unwrap();
      let mut frame = Vec::with_capacity(8 + metadata.len() + body.len());
      frame.extend_from_slice(&(metadata.len() as u64).to_be_bytes());
      frame.extend_from_slice(&metadata);
      frame.extend_from_slice(body);
      frame
    } else {
      Vec::new()
    };
    let header = format!(
      "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: keep-alive\r\n\r\n",
      response.len()
    );
    if stream.write_all(header.as_bytes()).await.is_err()
      || stream.write_all(&response).await.is_err()
    {
      return;
    }
  }
}

async fn handler(
  value: Vec<u8>,
  legacy_stamp: CacheGroupStamp,
) -> (String, Arc<Mutex<HandlerState>>) {
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let endpoint = format!(
    "http://{}/internal/v1/cache/",
    listener.local_addr().unwrap()
  );
  let state = Arc::new(Mutex::new(HandlerState {
    value,
    exchanges: 0,
    legacy_stamp,
  }));
  let accept_state = state.clone();
  tokio::spawn(async move {
    while let Ok((stream, _)) = listener.accept().await {
      tokio::spawn(serve_connection(stream, accept_state.clone()));
    }
  });
  (endpoint, state)
}

fn cache(endpoint: &str) -> Arc<ResponseCache> {
  let directory = common::TempDir::new("cache-group-external-migration");
  let (certificate, key) =
    common::create_self_signed_cert(directory.path(), "cache-group-external-migration");
  let raw = format!(
    "{}\n[cache]\nenabled = true\nstore = \"memory\"\nexternal_handler = \"groups\"\n\n[cache.groups]\nenabled = true\n\n[[cache.external_handlers]]\nname = \"groups\"\nkind = \"http\"\nendpoint = \"{endpoint}\"\nconnect_timeout_ms = 250\nrequest_timeout_ms = 1000\nmax_metadata_bytes = 65536\nmax_body_bytes = 65536\nmax_inflight_requests = 8\nfail_policy = \"local_only\"\n",
    common::minimal_config_toml(&certificate, &key)
  );
  let config: Config = toml::from_str(&raw).unwrap();
  let metrics = crate::metrics::Metrics::new();
  let external = ExternalCacheRuntime::new(&config, metrics.clone()).unwrap();
  ResponseCache::new_with_external_and_health(
    &config.cache,
    None,
    external,
    Arc::new(RuntimeHealth::default()),
    metrics,
  )
  .unwrap()
}

#[tokio::test]
async fn activation_rotates_a_legacy_external_authority_and_old_reads_fail_closed() {
  let mut legacy = Authority::new("a".repeat(64));
  let origin = CacheGroupOrigin::new("https", "example.test").unwrap();
  let mut legacy_stamp = legacy.snapshot("default", &origin, "").unwrap();
  legacy_stamp.target = "/legacy-l3".to_string();
  legacy.version = LEGACY_AUTHORITY_VERSION;
  let (endpoint, state) = handler(serde_json::to_vec(&legacy).unwrap(), legacy_stamp).await;
  let cache = cache(&endpoint);
  assert!(cache.groups_external_capable("default").await);
  assert!(cache.group_authority_read("default").await.is_err());

  cache.initialize_group_activation(None).await.unwrap();
  let migrated = cache.group_authority_read("default").await.unwrap();
  assert_eq!(migrated.version, AUTHORITY_VERSION);
  assert_ne!(migrated.incarnation, legacy.incarnation);
  assert_eq!(state.lock().unwrap().exchanges, 1);

  cache.initialize_group_activation(None).await.unwrap();
  assert_eq!(
    cache
      .group_authority_read("default")
      .await
      .unwrap()
      .incarnation,
    migrated.incarnation
  );
  assert_eq!(
    Authority::decode(&state.lock().unwrap().value)
      .unwrap()
      .incarnation,
    migrated.incarnation
  );

  let uri = Uri::from_static("/legacy-l3");
  let headers = HeaderMap::new();
  let request = CacheGroupRequest::new(origin);
  let context = CacheLookupContext {
    group_request: Some(&request),
    no_vary_search: None,
    proxy_protocol_identity: None,
    policy_name: None,
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &headers,
    query_identity: None,
    certificate_identity: None,
    dictionary_identity: None,
    origin_vary_headers: None,
  };
  assert!(cache.bind_group_request(context.clone()).await);
  assert!(
    cache.lookup_external(context, None).await.is_none(),
    "an external entry stamped by the legacy incarnation must cold-miss"
  );

  let mut current = migrated;
  let origin = CacheGroupOrigin::new("https", "example.test").unwrap();
  let mut current_stamp = current.snapshot("default", &origin, "").unwrap();
  current_stamp.target = "/legacy-l3".to_string();
  state.lock().unwrap().legacy_stamp = current_stamp;
  let current_request = CacheGroupRequest::new(origin);
  let current_context = CacheLookupContext {
    group_request: Some(&current_request),
    no_vary_search: None,
    proxy_protocol_identity: None,
    policy_name: None,
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &headers,
    query_identity: None,
    certificate_identity: None,
    dictionary_identity: None,
    origin_vary_headers: None,
  };
  assert!(cache.bind_group_request(current_context.clone()).await);
  assert!(cache.lookup_external(current_context, None).await.is_some());
}

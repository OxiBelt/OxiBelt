//! L3 No-Vary-Search alias regressions using an in-process handler.

use super::*;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::cache::external_handler::{
  ExternalCacheEntryMetadata, ExternalCacheHeader, ExternalCacheLookupRequest, ExternalCacheVary,
  PROTOCOL_VERSION,
};
use crate::config::Config;
use crate::runtime_health::RuntimeHealth;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

const NVS_FIELD: &str = "params=(\"ignored\")";
const OWNER_URI: &str = "/page?ignored=owner&required=1";
const OWNER_EFFECTIVE_URI: &str = "https://origin.test/page?ignored=owner&required=1";

#[derive(Clone, Copy)]
enum HandlerMode {
  Capable,
  GroupedAbsoluteOwner,
  MismatchedOwner,
  LegacyAfterBootstrap,
}

struct HandlerState {
  mode: HandlerMode,
  candidate: CacheNvsCandidate,
  nvs_epoch_requests: usize,
  lookup_requests: usize,
  group_authority: Option<Vec<u8>>,
  group_stamp: Option<CacheGroupStamp>,
}

fn no_vary_headers() -> HeaderMap {
  let mut headers = HeaderMap::new();
  headers.insert(
    CACHE_CONTROL,
    HeaderValue::from_static("public, max-age=60"),
  );
  headers.insert("no-vary-search", HeaderValue::from_static(NVS_FIELD));
  headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
  headers
}

fn external_cache(endpoint: &str, groups_enabled: bool) -> Arc<ResponseCache> {
  let temp_dir = common::TempDir::new("cache-nvs-external");
  let (certificate, key) = common::create_self_signed_cert(temp_dir.path(), "cache-nvs-external");
  let raw = format!(
    "{}\n[cache]\nenabled = true\nstore = \"memory\"\nno_vary_search = true\nexternal_handler = \"nvs\"\n\n[[cache.external_handlers]]\nname = \"nvs\"\nkind = \"http\"\nendpoint = \"{endpoint}\"\nconnect_timeout_ms = 250\nrequest_timeout_ms = 1000\nmax_metadata_bytes = 65536\nmax_body_bytes = 65536\nmax_inflight_requests = 8\nfail_policy = \"local_only\"\n",
    common::minimal_config_toml(&certificate, &key)
  );
  let mut config: Config =
    toml::from_str(&raw).expect("external cache fixture config should parse");
  config.cache.groups.enabled = groups_enabled;
  let metrics = crate::metrics::Metrics::new();
  let runtime = ExternalCacheRuntime::new(&config, metrics.clone())
    .expect("external cache runtime should build");
  ResponseCache::new_with_external_and_health(
    &config.cache,
    None,
    runtime,
    Arc::new(RuntimeHealth::default()),
    metrics,
  )
  .expect("cache should build")
}

async fn owner_candidate(cache: &ResponseCache) -> CacheNvsCandidate {
  let uri = OWNER_URI.parse::<Uri>().expect("owner URI should parse");
  let request = CacheNvsRequest::new(
    OWNER_EFFECTIVE_URI
      .parse()
      .expect("owner effective URI should parse"),
    b"nvs-external-route-v1",
  )
  .expect("owner request should be bounded");
  let headers = no_vary_headers();
  cache
    .bind_nvs_epoch(context(&uri, &request, &headers))
    .await;
  request.capture_origin(&headers);
  let metadata = cache
    .prepare_nvs(
      &CacheInsertContext {
        group_request: None,
        no_vary_search: Some(&request),
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
        proxy_protocol_identity: None,
      },
      &headers,
    )
    .expect("capable handler should bind NVS metadata");
  CacheNvsCandidate::from_parts(metadata, &headers, 1).expect("candidate should be bounded")
}

async fn grouped_owner_candidate(cache: &ResponseCache) -> CacheNvsCandidate {
  let uri = Uri::from_static("https://example.test/page?ignored=owner&required=1");
  let request = CacheNvsRequest::new(
    OWNER_EFFECTIVE_URI.parse().unwrap(),
    b"nvs-external-route-v1",
  )
  .unwrap();
  let group = CacheGroupRequest::new(CacheGroupOrigin::new("https", "example.test").unwrap());
  let headers = no_vary_headers();
  let lookup = CacheLookupContext {
    group_request: Some(&group),
    ..context(&uri, &request, &headers)
  };
  assert!(cache.bind_group_request(lookup.clone()).await);
  cache.bind_nvs_epoch(lookup).await;
  request.capture_origin(&headers);
  let metadata = cache
    .prepare_nvs(
      &CacheInsertContext {
        group_request: Some(&group),
        no_vary_search: Some(&request),
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
        proxy_protocol_identity: None,
      },
      &headers,
    )
    .unwrap();
  CacheNvsCandidate::from_parts(metadata, &headers, 1).unwrap()
}

fn framed_owner_response(
  request: ExternalCacheLookupRequest,
  candidate: &CacheNvsCandidate,
  mode: HandlerMode,
  group_stamp: Option<CacheGroupStamp>,
) -> Vec<u8> {
  let mut no_vary_search = candidate.metadata.clone();
  if matches!(mode, HandlerMode::MismatchedOwner) {
    no_vary_search.owner_uri = "/other?ignored=owner&required=1".to_string();
  }
  let body = b"external owner";
  let mut variant = variant_key(&request.partition, &request.base_key, &[]);
  if let Some(stamp) = &group_stamp {
    variant.push_str(&format!(
      "\ngroup-generation={}:{}",
      stamp.incarnation, stamp.sequence
    ));
  }
  let metadata = ExternalCacheEntryMetadata {
    protocol_version: PROTOCOL_VERSION.to_string(),
    cache_key_version: request.cache_key_version,
    policy: request.policy,
    partition: request.partition.clone(),
    base_key: request.base_key.clone(),
    variant_key: variant,
    scheme: request.scheme,
    host: request.host,
    uri: request.uri,
    status: StatusCode::OK.as_u16(),
    headers: vec![
      ExternalCacheHeader::new("cache-control".to_string(), b"public, max-age=60"),
      ExternalCacheHeader::new("content-type".to_string(), b"text/plain"),
      ExternalCacheHeader::new("no-vary-search".to_string(), NVS_FIELD.as_bytes()),
    ],
    security_headers_neutral: true,
    body_len: body.len(),
    stored_at_ms: system_time_ms(SystemTime::now()),
    expires_at_ms: system_time_ms(SystemTime::now() + Duration::from_secs(60)),
    stale_if_error_until_ms: None,
    stale_while_revalidate_until_ms: None,
    must_revalidate: false,
    vary: Vec::<ExternalCacheVary>::new(),
    tags: Vec::new(),
    query_target_epoch: None,
    dictionary_identity: None,
    no_vary_search: Some(no_vary_search),
    group_stamp,
    capabilities: if matches!(mode, HandlerMode::GroupedAbsoluteOwner) {
      vec!["cache-groups-v1".to_string()]
    } else {
      Vec::new()
    },
  };
  let metadata = serde_json::to_vec(&metadata).expect("external metadata should serialize");
  let mut response = Vec::with_capacity(8 + metadata.len() + body.len());
  response.extend_from_slice(&(metadata.len() as u64).to_be_bytes());
  response.extend_from_slice(&metadata);
  response.extend_from_slice(body);
  response
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

async fn write_response(stream: &mut TcpStream, status: &str, body: &[u8]) -> std::io::Result<()> {
  stream
    .write_all(
      format!(
        "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: keep-alive\r\n\r\n",
        body.len()
      )
      .as_bytes(),
    )
    .await?;
  stream.write_all(body).await
}

async fn serve_connection(mut stream: TcpStream, state: Arc<Mutex<HandlerState>>) {
  let mut buffered = Vec::new();
  while let Some((first, body)) = read_request(&mut stream, &mut buffered).await {
    let path = first.split_whitespace().nth(1).unwrap_or_default();
    let (status, response) = {
      let mut state = state.lock().expect("handler state should not be poisoned");
      match path.rsplit('/').next().unwrap_or_default() {
        "nvs-epoch" => {
          state.nvs_epoch_requests += 1;
          let legacy =
            matches!(state.mode, HandlerMode::LegacyAfterBootstrap) && state.nvs_epoch_requests > 2;
          let capabilities = if legacy {
            Vec::new()
          } else {
            vec!["no-vary-search-v1".to_string()]
          };
          (
            "200 OK",
            serde_json::to_vec(&serde_json::json!({
              "target_epoch": 0,
              "capabilities": capabilities,
            }))
            .expect("epoch response should serialize"),
          )
        }
        "nvs-candidates" => {
          let legacy = matches!(state.mode, HandlerMode::LegacyAfterBootstrap);
          let capabilities = if legacy {
            Vec::new()
          } else {
            vec!["no-vary-search-v1".to_string()]
          };
          (
            "200 OK",
            serde_json::to_vec(&serde_json::json!({
              "candidates": [state.candidate.clone()],
              "capabilities": capabilities,
            }))
            .expect("candidate response should serialize"),
          )
        }
        "lookup" => {
          state.lookup_requests += 1;
          let request: ExternalCacheLookupRequest =
            serde_json::from_slice(&body).expect("lookup request should decode");
          (
            "200 OK",
            framed_owner_response(
              request,
              &state.candidate,
              state.mode,
              state.group_stamp.clone(),
            ),
          )
        }
        "cache-group-state" => {
          let request: serde_json::Value =
            serde_json::from_slice(&body).expect("group request should decode");
          let Some(current) = state.group_authority.clone() else {
            return;
          };
          match request["mode"].as_str() {
            Some("read") => (
              "200 OK",
              serde_json::to_vec(&serde_json::json!({
                "value_base64": base64::engine::general_purpose::STANDARD.encode(current),
                "capabilities": ["cache-groups-v1"],
              }))
              .unwrap(),
            ),
            Some("compare_exchange") => {
              let expected = request["expected_base64"]
                .as_str()
                .and_then(|value| base64::engine::general_purpose::STANDARD.decode(value).ok());
              let replacement = request["replacement_base64"]
                .as_str()
                .and_then(|value| base64::engine::general_purpose::STANDARD.decode(value).ok())
                .unwrap();
              let exchanged = expected.as_deref() == Some(current.as_slice());
              if exchanged {
                state.group_authority = Some(replacement);
              }
              (
                "200 OK",
                serde_json::to_vec(&serde_json::json!({
                  "exchanged": exchanged,
                  "capabilities": ["cache-groups-v1"],
                }))
                .unwrap(),
              )
            }
            _ => ("400 Bad Request", Vec::new()),
          }
        }
        _ => ("404 Not Found", Vec::new()),
      }
    };
    if write_response(&mut stream, status, &response)
      .await
      .is_err()
    {
      return;
    }
  }
}

async fn handler(state: HandlerState) -> (String, Arc<Mutex<HandlerState>>) {
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("handler fixture should bind loopback");
  let endpoint = format!(
    "http://{}/internal/v1/cache/",
    listener
      .local_addr()
      .expect("handler address should resolve")
  );
  let state = Arc::new(Mutex::new(state));
  let accept_state = state.clone();
  tokio::spawn(async move {
    while let Ok((stream, _)) = listener.accept().await {
      tokio::spawn(serve_connection(stream, accept_state.clone()));
    }
  });
  (endpoint, state)
}

async fn external_fixture(mode: HandlerMode) -> (Arc<ResponseCache>, Arc<Mutex<HandlerState>>) {
  // Bootstrap uses a capable handler to bind the owner record's durable fences.
  let placeholder = CacheNvsCandidate {
    metadata: CacheNvsMetadata {
      version: 1,
      scope: "0".repeat(64),
      owner_uri: OWNER_URI.to_string(),
      effective_uri: OWNER_EFFECTIVE_URI.to_string(),
      epoch: 0,
      policy_epoch: 0,
      candidate_limit: 1,
    },
    fields: vec![NVS_FIELD.as_bytes().to_vec()],
    date_ms: 1,
  };
  let (endpoint, state) = handler(HandlerState {
    mode,
    candidate: placeholder,
    nvs_epoch_requests: 0,
    lookup_requests: 0,
    group_authority: None,
    group_stamp: None,
  })
  .await;
  let cache = external_cache(&endpoint, false);
  let candidate = owner_candidate(&cache).await;
  state
    .lock()
    .expect("handler state should not be poisoned")
    .candidate = candidate;
  (cache, state)
}

async fn grouped_external_fixture() -> (Arc<ResponseCache>, Arc<Mutex<HandlerState>>) {
  let absolute_owner = format!("https://example.test{OWNER_URI}");
  let placeholder = CacheNvsCandidate {
    metadata: CacheNvsMetadata {
      version: 1,
      scope: "0".repeat(64),
      owner_uri: absolute_owner.clone(),
      effective_uri: OWNER_EFFECTIVE_URI.to_string(),
      epoch: 0,
      policy_epoch: 0,
      candidate_limit: 1,
    },
    fields: vec![NVS_FIELD.as_bytes().to_vec()],
    date_ms: 1,
  };
  let mut authority = crate::cache::groups::model::Authority::new("a".repeat(64));
  let origin = CacheGroupOrigin::new("https", "example.test").unwrap();
  let mut stamp = authority.snapshot("default", &origin, "").unwrap();
  stamp.target = OWNER_URI.to_string();
  stamp.equivalent_path = Some("/page".to_string());
  let (endpoint, state) = handler(HandlerState {
    mode: HandlerMode::GroupedAbsoluteOwner,
    candidate: placeholder,
    nvs_epoch_requests: 0,
    lookup_requests: 0,
    group_authority: Some(authority.encode().unwrap()),
    group_stamp: Some(stamp),
  })
  .await;
  let cache = external_cache(&endpoint, true);
  let candidate = grouped_owner_candidate(&cache).await;
  assert_eq!(candidate.metadata.owner_uri, absolute_owner);
  state
    .lock()
    .expect("handler state should not be poisoned")
    .candidate = candidate;
  (cache, state)
}

async fn external_alias(cache: &ResponseCache) -> Option<CacheLookup> {
  let uri = "/page?ignored=alias&required=1"
    .parse::<Uri>()
    .expect("alias URI should parse");
  let request = CacheNvsRequest::new(
    "https://origin.test/page?ignored=alias&required=1"
      .parse()
      .expect("alias effective URI should parse"),
    b"nvs-external-route-v1",
  )
  .expect("alias request should be bounded");
  let headers = HeaderMap::new();
  cache
    .lookup_nvs_async(context(&uri, &request, &headers), None)
    .await
}

#[tokio::test]
async fn capable_external_handler_supplies_a_verified_nvs_alias_owner() {
  let (cache, state) = external_fixture(HandlerMode::Capable).await;
  let alias_uri = "/page?ignored=alias&required=1"
    .parse::<Uri>()
    .expect("alias URI should parse");
  let request = CacheNvsRequest::new(
    "https://origin.test/page?ignored=alias&required=1"
      .parse()
      .expect("alias effective URI should parse"),
    b"nvs-external-route-v1",
  )
  .expect("alias request should be bounded");
  let headers = HeaderMap::new();
  assert!(
    cache
      .lookup(context(&alias_uri, &request, &headers))
      .is_none()
  );

  let hit = external_alias(&cache)
    .await
    .expect("capable L3 handler should supply an alias owner");
  let entry = match hit {
    CacheLookup::Fresh(entry) => entry,
    other => panic!("expected fresh alias entry, got {other:?}"),
  };
  assert!(entry.nvs_alias);
  assert_eq!(entry.body, Bytes::from_static(b"external owner"));
  assert_eq!(
    state
      .lock()
      .expect("handler state should not be poisoned")
      .lookup_requests,
    1,
    "the alias must reload its exact owner from L3"
  );
}

#[tokio::test]
async fn grouped_l3_nvs_alias_accepts_an_absolute_owner_with_a_canonical_stamp() {
  let (cache, state) = grouped_external_fixture().await;
  let alias_uri = Uri::from_static("https://example.test/page?ignored=alias&required=1");
  let request = CacheNvsRequest::new(
    Uri::from_static("https://origin.test/page?ignored=alias&required=1"),
    b"nvs-external-route-v1",
  )
  .unwrap();
  let group = CacheGroupRequest::new(CacheGroupOrigin::new("https", "example.test").unwrap());
  let headers = HeaderMap::new();
  let initial_context = CacheLookupContext {
    group_request: Some(&group),
    ..context(&alias_uri, &request, &headers)
  };
  assert!(cache.bind_group_request(initial_context.clone()).await);
  let CacheLookup::Fresh(entry) = cache
    .lookup_nvs_async(initial_context, None)
    .await
    .expect("the grouped L3 alias should be reusable")
  else {
    panic!("fresh grouped L3 alias expected")
  };
  assert!(entry.nvs_alias);
  assert_eq!(entry.group_stamp.unwrap().target, OWNER_URI);
  assert_eq!(state.lock().unwrap().lookup_requests, 1);

  let mutation_uri = Uri::from_static("/page?ignored=alias&required=1");
  let mutation_group =
    CacheGroupRequest::new(CacheGroupOrigin::new("https", "example.test").unwrap());
  let mutation_context = CacheLookupContext {
    group_request: Some(&mutation_group),
    no_vary_search: None,
    proxy_protocol_identity: None,
    policy_name: None,
    scheme: "https",
    host: "example.test",
    method: &Method::POST,
    uri: &mutation_uri,
    request_headers: &headers,
    query_identity: None,
    certificate_identity: None,
    dictionary_identity: None,
    origin_vary_headers: None,
  };
  assert!(cache.bind_group_request(mutation_context.clone()).await);
  cache
    .groups_after_origin_response(mutation_context, StatusCode::OK, &HeaderMap::new())
    .await;

  let after_group = CacheGroupRequest::new(CacheGroupOrigin::new("https", "example.test").unwrap());
  let after = CacheLookupContext {
    group_request: Some(&after_group),
    ..context(&alias_uri, &request, &headers)
  };
  assert!(cache.bind_group_request(after.clone()).await);
  assert!(cache.lookup_nvs_async(after, None).await.is_none());
}

#[tokio::test]
async fn external_owner_metadata_mismatch_is_a_safe_alias_miss() {
  let (cache, state) = external_fixture(HandlerMode::MismatchedOwner).await;
  assert!(external_alias(&cache).await.is_none());
  assert_eq!(
    state
      .lock()
      .expect("handler state should not be poisoned")
      .lookup_requests,
    1,
    "the candidate may cause an owner lookup, but cannot authorize a mismatch"
  );
}

#[tokio::test]
async fn legacy_external_nvs_capability_never_authorizes_aliases() {
  let (cache, state) = external_fixture(HandlerMode::LegacyAfterBootstrap).await;
  assert!(external_alias(&cache).await.is_none());
  assert_eq!(
    state
      .lock()
      .expect("handler state should not be poisoned")
      .lookup_requests,
    0,
    "a legacy candidate response must fail before owner retrieval"
  );
}

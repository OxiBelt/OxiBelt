//! Kubernetes watch loop and backoff handling.
//! Watch failures are surfaced without deleting the last known good snapshot.

use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use http::Request;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use serde::Deserialize;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use crate::config::{UpstreamDiscoveryProvider, UpstreamPoolDiscoveryConfig};
use crate::control_http::{ControlHttpClient, empty_body, uri_from_url};
use crate::state::AppHandle;

const KUBERNETES_WATCH_MAX_EVENT_BYTES: usize = super::KUBERNETES_MAX_BODY_BYTES;

pub(in crate::upstream_discovery) async fn run_kubernetes_endpoint_slice_watch(
  state: AppHandle,
  pool_name: String,
  discovery: UpstreamPoolDiscoveryConfig,
  mut shutdown: watch::Receiver<bool>,
) {
  loop {
    if *shutdown.borrow() {
      break;
    }

    let snapshot = state.snapshot();
    match run_endpoint_slice_watch_session(
      &snapshot.control_http,
      &state,
      &pool_name,
      &discovery,
      &mut shutdown,
    )
    .await
    {
      Ok(WatchSessionEnd::Shutdown) => break,
      Ok(WatchSessionEnd::Reconnect) | Ok(WatchSessionEnd::ResourceExpired) => {}
      Err(error) => {
        tracing::warn!(
          error = %error,
          pool = %pool_name,
          "Kubernetes EndpointSlice watch failed; keeping previous pool state"
        );
        let delay = Duration::from_millis(discovery.refresh_interval_ms);
        tokio::select! {
          _ = shutdown.changed() => {}
          _ = tokio::time::sleep(delay) => {}
        }
      }
    }
  }
}

async fn run_endpoint_slice_watch_session(
  client: &ControlHttpClient,
  state: &AppHandle,
  pool_name: &str,
  discovery: &UpstreamPoolDiscoveryConfig,
  shutdown: &mut watch::Receiver<bool>,
) -> anyhow::Result<WatchSessionEnd> {
  let list = super::list_endpoint_slices(client, discovery).await?;
  let mut resource_version = list.metadata.resource_version.clone().unwrap_or_default();
  let mut cache = super::EndpointSliceCache::from_list(discovery, list)?;
  apply_endpoint_slice_cache(state, pool_name, discovery, &cache).await?;

  loop {
    if *shutdown.borrow() {
      return Ok(WatchSessionEnd::Shutdown);
    }
    match watch_endpoint_slices_once(
      client,
      state,
      pool_name,
      discovery,
      &mut cache,
      &mut resource_version,
      shutdown,
    )
    .await?
    {
      WatchSessionEnd::Shutdown => return Ok(WatchSessionEnd::Shutdown),
      WatchSessionEnd::ResourceExpired => return Ok(WatchSessionEnd::ResourceExpired),
      WatchSessionEnd::Reconnect => {}
    }
  }
}

async fn watch_endpoint_slices_once(
  client: &ControlHttpClient,
  state: &AppHandle,
  pool_name: &str,
  discovery: &UpstreamPoolDiscoveryConfig,
  cache: &mut super::EndpointSliceCache,
  resource_version: &mut String,
  shutdown: &mut watch::Receiver<bool>,
) -> anyhow::Result<WatchSessionEnd> {
  let namespace = discovery
    .namespace
    .as_deref()
    .ok_or_else(|| anyhow!("Kubernetes discovery requires namespace"))?;
  let service = discovery
    .service
    .as_deref()
    .ok_or_else(|| anyhow!("Kubernetes discovery requires service"))?;
  let mut url = super::endpoint_slice_url(discovery, namespace)?;
  {
    let mut query = url.query_pairs_mut();
    query.append_pair(
      "labelSelector",
      &format!("kubernetes.io/service-name={service}"),
    );
    query.append_pair("watch", "true");
    query.append_pair("allowWatchBookmarks", "true");
    query.append_pair(
      "timeoutSeconds",
      &discovery.watch_timeout_seconds.to_string(),
    );
    if !resource_version.is_empty() {
      query.append_pair("resourceVersion", resource_version);
    }
  }
  let mut builder = Request::builder()
    .method(http::Method::GET)
    .uri(uri_from_url(&url)?)
    .header(http::header::ACCEPT, "application/json");
  super::add_bearer_token_header(
    &mut builder,
    discovery.token_env.as_deref(),
    discovery.token_file.as_deref(),
    http::header::AUTHORIZATION,
  )?;
  let response = client
    .request_stream(
      builder.body(empty_body())?,
      Duration::from_millis(discovery.refresh_interval_ms),
    )
    .await?;
  if response.status == http::StatusCode::GONE {
    return Ok(WatchSessionEnd::ResourceExpired);
  }
  if !response.status.is_success() {
    bail!(
      "Kubernetes EndpointSlice watch returned HTTP status {}",
      response.status
    );
  }

  let (sender, receiver) = mpsc::channel(64);
  let reader = tokio::spawn(stream_watch_events(response.body, sender));
  let result = process_watch_events(
    receiver,
    state,
    pool_name,
    discovery,
    cache,
    resource_version,
    shutdown,
  )
  .await;
  reader.abort();
  result
}

async fn process_watch_events(
  mut receiver: mpsc::Receiver<anyhow::Result<KubernetesWatchEvent>>,
  state: &AppHandle,
  pool_name: &str,
  discovery: &UpstreamPoolDiscoveryConfig,
  cache: &mut super::EndpointSliceCache,
  resource_version: &mut String,
  shutdown: &mut watch::Receiver<bool>,
) -> anyhow::Result<WatchSessionEnd> {
  let debounce = Duration::from_millis(discovery.update_debounce_ms);
  let stream_timeout = tokio::time::sleep(endpoint_slice_watch_stream_timeout(discovery));
  tokio::pin!(stream_timeout);
  let mut pending_flush_at: Option<Instant> = None;

  loop {
    let flush_sleep = tokio::time::sleep_until(
      pending_flush_at.unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400)),
    );
    tokio::pin!(flush_sleep);

    tokio::select! {
      _ = shutdown.changed() => {
        return Ok(WatchSessionEnd::Shutdown);
      }
      _ = &mut stream_timeout => {
        if pending_flush_at.is_some() {
          apply_endpoint_slice_cache(state, pool_name, discovery, cache).await?;
        }
        return Ok(WatchSessionEnd::Reconnect);
      }
      _ = &mut flush_sleep, if pending_flush_at.is_some() => {
        apply_endpoint_slice_cache(state, pool_name, discovery, cache).await?;
        pending_flush_at = None;
      }
      event = receiver.recv() => {
        let Some(event) = event else {
          if pending_flush_at.is_some() {
            apply_endpoint_slice_cache(state, pool_name, discovery, cache).await?;
          }
          return Ok(WatchSessionEnd::Reconnect);
        };
        match apply_watch_event(cache, discovery, event?, resource_version)? {
          WatchEventAction::Noop => {}
          WatchEventAction::Changed => {
            pending_flush_at = Some(Instant::now() + debounce);
          }
          WatchEventAction::ResourceExpired => {
            return Ok(WatchSessionEnd::ResourceExpired);
          }
        }
      }
    }
  }
}

async fn stream_watch_events(
  mut body: Incoming,
  sender: mpsc::Sender<anyhow::Result<KubernetesWatchEvent>>,
) {
  let mut buffer = Vec::new();
  while let Some(frame) = body.frame().await {
    let frame = match frame {
      Ok(frame) => frame,
      Err(error) => {
        let _ = sender
          .send(Err(anyhow!(
            "Kubernetes EndpointSlice watch body failed: {error}"
          )))
          .await;
        return;
      }
    };
    let Some(data) = frame.data_ref() else {
      continue;
    };
    if !buffer_watch_data(&sender, &mut buffer, data).await {
      return;
    }
  }
  if !buffer
    .iter()
    .all(|byte| matches!(*byte, b'\r' | b'\n' | b' ' | b'\t'))
  {
    let _ = send_watch_line(&sender, &buffer).await;
  }
}

async fn buffer_watch_data(
  sender: &mpsc::Sender<anyhow::Result<KubernetesWatchEvent>>,
  buffer: &mut Vec<u8>,
  mut data: &[u8],
) -> bool {
  while !data.is_empty() {
    let (segment, rest) = match memchr::memchr(b'\n', data) {
      Some(index) => data.split_at(index + 1),
      None => (data, &[][..]),
    };
    if !extend_watch_line(sender, buffer, segment).await {
      return false;
    }
    if segment.last() == Some(&b'\n') {
      if send_watch_line(sender, buffer).await.is_err() {
        return false;
      }
      buffer.clear();
    }
    data = rest;
  }
  true
}

async fn extend_watch_line(
  sender: &mpsc::Sender<anyhow::Result<KubernetesWatchEvent>>,
  buffer: &mut Vec<u8>,
  segment: &[u8],
) -> bool {
  let Some(next_len) = buffer.len().checked_add(segment.len()) else {
    send_watch_line_limit_error(sender).await;
    return false;
  };
  if next_len > KUBERNETES_WATCH_MAX_EVENT_BYTES {
    send_watch_line_limit_error(sender).await;
    return false;
  }
  buffer.extend_from_slice(segment);
  true
}

async fn send_watch_line_limit_error(sender: &mpsc::Sender<anyhow::Result<KubernetesWatchEvent>>) {
  let _ = sender
    .send(Err(anyhow!(
      "Kubernetes EndpointSlice watch event exceeded {KUBERNETES_WATCH_MAX_EVENT_BYTES} bytes"
    )))
    .await;
}

async fn send_watch_line(
  sender: &mpsc::Sender<anyhow::Result<KubernetesWatchEvent>>,
  line: &[u8],
) -> Result<(), mpsc::error::SendError<anyhow::Result<KubernetesWatchEvent>>> {
  let line = trim_json_line(line);
  if line.is_empty() {
    return Ok(());
  }
  let event = serde_json::from_slice(line).context("failed to parse Kubernetes watch event");
  sender.send(event).await
}

fn trim_json_line(mut line: &[u8]) -> &[u8] {
  while matches!(line.first(), Some(b'\r' | b'\n' | b' ' | b'\t')) {
    line = &line[1..];
  }
  while matches!(line.last(), Some(b'\r' | b'\n' | b' ' | b'\t')) {
    line = &line[..line.len() - 1];
  }
  line
}

fn endpoint_slice_watch_stream_timeout(discovery: &UpstreamPoolDiscoveryConfig) -> Duration {
  Duration::from_secs(discovery.watch_timeout_seconds)
    .saturating_add(Duration::from_millis(discovery.refresh_interval_ms))
}

fn apply_watch_event(
  cache: &mut super::EndpointSliceCache,
  discovery: &UpstreamPoolDiscoveryConfig,
  event: KubernetesWatchEvent,
  resource_version: &mut String,
) -> anyhow::Result<WatchEventAction> {
  match event.event_type.as_str() {
    "ADDED" | "MODIFIED" => {
      let slice: super::KubernetesEndpointSlice =
        serde_json::from_value(event.object).context("failed to parse EndpointSlice watch item")?;
      if let Some(version) = &slice.metadata.resource_version {
        *resource_version = version.clone();
      }
      if super::endpoint_slice_matches_service(&slice, discovery) {
        cache.slices.insert(slice.metadata.name.clone(), slice);
      } else {
        cache.slices.remove(&slice.metadata.name);
      }
      Ok(WatchEventAction::Changed)
    }
    "DELETED" => {
      let slice: super::KubernetesEndpointSlice =
        serde_json::from_value(event.object).context("failed to parse deleted EndpointSlice")?;
      if let Some(version) = &slice.metadata.resource_version {
        *resource_version = version.clone();
      }
      cache.slices.remove(&slice.metadata.name);
      Ok(WatchEventAction::Changed)
    }
    "BOOKMARK" => {
      let bookmark: KubernetesBookmark =
        serde_json::from_value(event.object).context("failed to parse EndpointSlice bookmark")?;
      if let Some(version) = bookmark.metadata.resource_version {
        *resource_version = version;
      }
      Ok(WatchEventAction::Noop)
    }
    "ERROR" => {
      let status: KubernetesStatus =
        serde_json::from_value(event.object).context("failed to parse Kubernetes watch error")?;
      if status.code == Some(410) || status.reason.as_deref() == Some("Expired") {
        return Ok(WatchEventAction::ResourceExpired);
      }
      bail!(
        "Kubernetes EndpointSlice watch returned error: {}",
        status
          .message
          .or(status.reason)
          .unwrap_or_else(|| "unknown Kubernetes watch error".to_string())
      );
    }
    event_type => bail!("unknown Kubernetes watch event type {event_type}"),
  }
}

async fn apply_endpoint_slice_cache(
  state: &AppHandle,
  pool_name: &str,
  discovery: &UpstreamPoolDiscoveryConfig,
  cache: &super::EndpointSliceCache,
) -> anyhow::Result<()> {
  super::super::apply_discovered_servers(
    state,
    pool_name,
    UpstreamDiscoveryProvider::Kubernetes,
    cache.servers(discovery)?,
  )
  .await
}

#[derive(Debug, Deserialize)]
struct KubernetesWatchEvent {
  #[serde(rename = "type")]
  event_type: String,
  object: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct KubernetesBookmark {
  metadata: super::KubernetesObjectMeta,
}

#[derive(Debug, Deserialize)]
struct KubernetesStatus {
  #[serde(default)]
  code: Option<u16>,
  #[serde(default)]
  reason: Option<String>,
  #[serde(default)]
  message: Option<String>,
}

enum WatchSessionEnd {
  Shutdown,
  Reconnect,
  ResourceExpired,
}

enum WatchEventAction {
  Noop,
  Changed,
  ResourceExpired,
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::time::Duration;

  use crate::config::{
    DiscoveryUpstreamScheme, KubernetesDiscoveryResource, UpstreamDiscoveryProvider,
  };

  fn endpoint_slice_discovery() -> UpstreamPoolDiscoveryConfig {
    UpstreamPoolDiscoveryConfig {
      provider: UpstreamDiscoveryProvider::Kubernetes,
      name: None,
      endpoint: Some("https://kubernetes.default.svc".parse().expect("valid URL")),
      namespace: Some("default".to_string()),
      service: Some("app".to_string()),
      port_name: Some("http".to_string()),
      key_prefix: None,
      token_env: None,
      token_file: None,
      filter: None,
      datacenter: None,
      file: None,
      record_type: Default::default(),
      scheme: DiscoveryUpstreamScheme::Http,
      port: None,
      kubernetes_resource: KubernetesDiscoveryResource::EndpointSlice,
      watch: true,
      watch_timeout_seconds: 300,
      update_debounce_ms: 250,
      refresh_interval_ms: 30_000,
      min_ttl_ms: 1_000,
      tls: Default::default(),
    }
  }

  #[test]
  fn watch_error_410_requests_relist() {
    let mut cache = super::super::EndpointSliceCache::default();
    let mut resource_version = "42".to_string();
    let action = apply_watch_event(
      &mut cache,
      &endpoint_slice_discovery(),
      serde_json::from_str(
        r#"{"type":"ERROR","object":{"kind":"Status","code":410,"reason":"Expired"}}"#,
      )
      .expect("watch event should parse"),
      &mut resource_version,
    )
    .expect("expired watch event should be handled");

    assert!(matches!(action, WatchEventAction::ResourceExpired));
  }

  #[tokio::test]
  async fn watch_line_buffer_rejects_newline_free_payload_over_limit() {
    let (sender, mut receiver) = mpsc::channel(1);
    let mut buffer = Vec::new();
    let chunk = vec![b'a'; KUBERNETES_WATCH_MAX_EVENT_BYTES];

    assert!(buffer_watch_data(&sender, &mut buffer, &chunk).await);
    assert_eq!(buffer.len(), KUBERNETES_WATCH_MAX_EVENT_BYTES);
    assert!(receiver.try_recv().is_err());

    assert!(!buffer_watch_data(&sender, &mut buffer, b"a").await);
    let error = receiver
      .recv()
      .await
      .expect("limit error should be sent")
      .expect_err("over-limit watch line should fail");

    assert!(
      format!("{error:#}").contains("Kubernetes EndpointSlice watch event exceeded 8388608 bytes"),
      "unexpected error: {error:#}"
    );
  }

  #[tokio::test]
  async fn watch_line_buffer_accepts_multiple_large_events_by_line() {
    let event = bookmark_event_with_name_len(KUBERNETES_WATCH_MAX_EVENT_BYTES / 2);
    assert!(event.len() < KUBERNETES_WATCH_MAX_EVENT_BYTES);
    let mut stream = Vec::with_capacity(event.len() * 2);
    stream.extend_from_slice(&event);
    stream.extend_from_slice(&event);
    assert!(stream.len() > KUBERNETES_WATCH_MAX_EVENT_BYTES);

    let (sender, mut receiver) = mpsc::channel(4);
    let mut buffer = Vec::new();
    assert!(buffer_watch_data(&sender, &mut buffer, &stream).await);
    assert!(buffer.is_empty());

    for _ in 0..2 {
      let event = receiver
        .recv()
        .await
        .expect("watch event should be sent")
        .expect("watch event should parse");
      assert_eq!(event.event_type, "BOOKMARK");
    }
    assert!(receiver.try_recv().is_err());
  }

  #[test]
  fn endpoint_slice_watch_stream_timeout_includes_watch_timeout_and_refresh_grace() {
    let discovery = endpoint_slice_discovery();

    assert_eq!(
      endpoint_slice_watch_stream_timeout(&discovery),
      Duration::from_secs(330)
    );
  }

  fn bookmark_event_with_name_len(name_len: usize) -> Vec<u8> {
    let mut event =
      br#"{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"1","name":""#.to_vec();
    event.extend(std::iter::repeat_n(b'a', name_len));
    event.extend_from_slice(br#""}}}"#);
    event.push(b'\n');
    event
  }
}

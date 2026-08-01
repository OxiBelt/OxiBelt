//! Telemetry exporters and trace context propagation.
//! Export paths are best-effort observability and must not become request authorization gates.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use http::{HeaderMap, HeaderValue};
use url::Url;

use crate::config::TelemetryTracingConfig;

const TRACEPARENT: &str = "traceparent";
const EXPORT_BATCH_SIZE: usize = 64;
const EXPORT_QUEUE_SIZE: usize = 1024;
static TRACE_ENTROPY_FALLBACK_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
pub struct TelemetryRuntime {
  inner: Option<Arc<TelemetryInner>>,
}

struct TelemetryInner {
  sender: Mutex<Option<SyncSender<TraceSpan>>>,
  exporter: Mutex<Option<JoinHandle<()>>>,
  sample_ratio: f64,
  propagate_trace_context: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct TraceContext {
  trace_id: [u8; 16],
  span_id: [u8; 8],
  parent_span_id: Option<[u8; 8]>,
  sampled: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct TelemetryStart {
  unix_nanos: u64,
  instant: Instant,
}

#[derive(Debug, Clone, Copy)]
pub enum SpanKind {
  Internal = 1,
  Server = 2,
  Client = 3,
}

#[derive(Debug, Clone)]
pub struct TraceAttribute {
  key: String,
  value: String,
}

#[derive(Debug)]
struct TraceSpan {
  trace_id: [u8; 16],
  span_id: [u8; 8],
  parent_span_id: Option<[u8; 8]>,
  name: String,
  kind: SpanKind,
  start_time_unix_nano: u64,
  end_time_unix_nano: u64,
  attributes: Vec<TraceAttribute>,
}

#[derive(Clone)]
struct OtlpHttpEndpoint {
  host: String,
  port: u16,
  path_and_query: String,
}

impl TelemetryRuntime {
  pub fn disabled() -> Self {
    Self { inner: None }
  }

  pub fn new(config: &TelemetryTracingConfig) -> anyhow::Result<Self> {
    if !config.enabled {
      return Ok(Self::disabled());
    }
    let endpoint = OtlpHttpEndpoint::parse(&config.endpoint)?;
    let timeout = Duration::from_millis(config.export_timeout_ms);
    let (sender, receiver) = mpsc::sync_channel(EXPORT_QUEUE_SIZE);
    let exporter_service_name = config.service_name.clone();
    let exporter = thread::Builder::new()
      .name("oxibelt-otlp-trace-exporter".to_string())
      .spawn(move || run_exporter(receiver, endpoint, timeout, exporter_service_name))
      .context("failed to start OTLP trace exporter thread")?;
    Ok(Self {
      inner: Some(Arc::new(TelemetryInner {
        sender: Mutex::new(Some(sender)),
        exporter: Mutex::new(Some(exporter)),
        sample_ratio: config.sample_ratio,
        propagate_trace_context: config.propagate_trace_context,
      })),
    })
  }

  pub fn enabled(&self) -> bool {
    self.inner.is_some()
  }

  pub fn start() -> TelemetryStart {
    TelemetryStart {
      unix_nanos: unix_nanos_now(),
      instant: Instant::now(),
    }
  }

  pub fn context_from_headers(&self, headers: &HeaderMap) -> Option<TraceContext> {
    let inner = self.inner.as_ref()?;
    if inner.propagate_trace_context
      && let Some(parent) = extract_traceparent(headers)
    {
      return Some(TraceContext {
        trace_id: parent.trace_id,
        span_id: random_span_id(),
        parent_span_id: Some(parent.span_id),
        sampled: parent.sampled,
      });
    }
    if !sample_trace(inner.sample_ratio) {
      return None;
    }
    Some(TraceContext {
      trace_id: random_trace_id(),
      span_id: random_span_id(),
      parent_span_id: None,
      sampled: true,
    })
  }

  pub fn inject_trace_context(&self, headers: &mut HeaderMap, context: Option<TraceContext>) {
    let Some(inner) = &self.inner else {
      return;
    };
    if !inner.propagate_trace_context {
      return;
    }
    let Some(context) = context else {
      return;
    };
    if let Ok(value) = HeaderValue::from_str(&format_traceparent(context)) {
      headers.insert(TRACEPARENT, value);
    }
  }

  pub fn record_span(
    &self,
    context: Option<TraceContext>,
    name: &str,
    kind: SpanKind,
    start: TelemetryStart,
    attributes: Vec<TraceAttribute>,
  ) {
    let Some(inner) = &self.inner else {
      return;
    };
    let Some(context) = context else {
      return;
    };
    if !context.sampled {
      return;
    }
    let span = TraceSpan {
      trace_id: context.trace_id,
      span_id: context.span_id,
      parent_span_id: context.parent_span_id,
      name: name.to_string(),
      kind,
      start_time_unix_nano: start.unix_nanos,
      end_time_unix_nano: start.end_unix_nanos(),
      attributes,
    };
    let sender = inner
      .sender
      .lock()
      .ok()
      .and_then(|sender| sender.as_ref().cloned());
    let Some(sender) = sender else {
      return;
    };
    if let Err(error) = sender.try_send(span)
      && matches!(error, TrySendError::Disconnected(_))
    {
      tracing::warn!("OTLP trace exporter is closed; dropping trace span");
    }
  }

  pub fn record_child_span(
    &self,
    context: Option<TraceContext>,
    name: &str,
    kind: SpanKind,
    start: TelemetryStart,
    attributes: Vec<TraceAttribute>,
  ) {
    let Some(inner) = &self.inner else {
      return;
    };
    let Some(context) = context else {
      return;
    };
    if !context.sampled {
      return;
    }
    let span = TraceSpan {
      trace_id: context.trace_id,
      span_id: random_span_id(),
      parent_span_id: Some(context.span_id),
      name: name.to_string(),
      kind,
      start_time_unix_nano: start.unix_nanos,
      end_time_unix_nano: start.end_unix_nanos(),
      attributes,
    };
    let sender = inner
      .sender
      .lock()
      .ok()
      .and_then(|sender| sender.as_ref().cloned());
    let Some(sender) = sender else {
      return;
    };
    if let Err(error) = sender.try_send(span)
      && matches!(error, TrySendError::Disconnected(_))
    {
      tracing::warn!("OTLP trace exporter is closed; dropping trace span");
    }
  }
}

impl Drop for TelemetryRuntime {
  fn drop(&mut self) {
    let Some(inner) = &self.inner else {
      return;
    };
    if Arc::strong_count(inner) != 1 {
      return;
    }
    if let Ok(mut sender) = inner.sender.lock() {
      sender.take();
    }
    if let Ok(mut exporter) = inner.exporter.lock()
      && let Some(handle) = exporter.take()
      && handle.join().is_err()
    {
      tracing::warn!("OTLP trace exporter thread panicked during shutdown");
    }
  }
}

impl Default for TelemetryRuntime {
  fn default() -> Self {
    Self::disabled()
  }
}

impl TelemetryStart {
  pub fn elapsed_ago(duration_ms: u64) -> Self {
    let duration = Duration::from_millis(duration_ms);
    Self {
      unix_nanos: unix_nanos_now()
        .saturating_sub(duration.as_nanos().min(u128::from(u64::MAX)) as u64),
      instant: Instant::now()
        .checked_sub(duration)
        .unwrap_or_else(Instant::now),
    }
  }

  pub fn elapsed_ms(self) -> u64 {
    self.instant.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
  }

  fn end_unix_nanos(self) -> u64 {
    self
      .unix_nanos
      .saturating_add(self.instant.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64)
  }
}

impl TraceAttribute {
  pub fn string(key: impl Into<String>, value: impl Into<String>) -> Self {
    Self {
      key: key.into(),
      value: value.into(),
    }
  }
}

impl OtlpHttpEndpoint {
  fn parse(value: &str) -> anyhow::Result<Self> {
    let url = Url::parse(value).context("invalid OTLP HTTP endpoint")?;
    if url.scheme() != "http" {
      bail!("OTLP HTTP endpoint currently supports only http://");
    }
    let host = url
      .host_str()
      .ok_or_else(|| anyhow::anyhow!("OTLP HTTP endpoint must include a host"))?
      .to_string();
    let port = url.port_or_known_default().unwrap_or(80);
    let path = if url.path().is_empty() {
      "/"
    } else {
      url.path()
    };
    let path_and_query = match url.query() {
      Some(query) => format!("{path}?{query}"),
      None => path.to_string(),
    };
    Ok(Self {
      host,
      port,
      path_and_query,
    })
  }
}

fn run_exporter(
  receiver: mpsc::Receiver<TraceSpan>,
  endpoint: OtlpHttpEndpoint,
  timeout: Duration,
  service_name: String,
) {
  let mut batch = Vec::with_capacity(EXPORT_BATCH_SIZE);
  loop {
    match receiver.recv_timeout(Duration::from_secs(1)) {
      Ok(span) => batch.push(span),
      Err(mpsc::RecvTimeoutError::Timeout) => {}
      Err(mpsc::RecvTimeoutError::Disconnected) => {
        flush_batch(&mut batch, &endpoint, timeout, &service_name);
        return;
      }
    }
    while batch.len() < EXPORT_BATCH_SIZE {
      match receiver.try_recv() {
        Ok(span) => batch.push(span),
        Err(mpsc::TryRecvError::Empty) => break,
        Err(mpsc::TryRecvError::Disconnected) => {
          flush_batch(&mut batch, &endpoint, timeout, &service_name);
          return;
        }
      }
    }
    flush_batch(&mut batch, &endpoint, timeout, &service_name);
  }
}

fn flush_batch(
  batch: &mut Vec<TraceSpan>,
  endpoint: &OtlpHttpEndpoint,
  timeout: Duration,
  service_name: &str,
) {
  if batch.is_empty() {
    return;
  }
  let payload = encode_export_request(service_name, batch);
  batch.clear();
  if let Err(error) = post_otlp_http(endpoint, timeout, &payload) {
    tracing::warn!(error = %error, "failed to export OTLP trace batch");
  }
}

fn post_otlp_http(
  endpoint: &OtlpHttpEndpoint,
  timeout: Duration,
  payload: &[u8],
) -> anyhow::Result<()> {
  let address = crate::upstream_resolution::resolve_socket_addrs_blocking(
    &endpoint.host,
    endpoint.port,
    timeout,
  )
  .context("failed to resolve OTLP endpoint")?
  .into_iter()
  .next()
  .ok_or_else(|| anyhow::anyhow!("OTLP endpoint resolved no addresses"))?;
  let mut stream =
    TcpStream::connect_timeout(&address, timeout).context("failed to connect OTLP endpoint")?;
  stream.set_read_timeout(Some(timeout)).ok();
  stream.set_write_timeout(Some(timeout)).ok();
  let request = format!(
    "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-protobuf\r\nContent-Length: {}\r\nUser-Agent: oxibelt\r\nConnection: close\r\n\r\n",
    endpoint.path_and_query,
    endpoint.host,
    payload.len()
  );
  stream
    .write_all(request.as_bytes())
    .context("failed to write OTLP request headers")?;
  stream
    .write_all(payload)
    .context("failed to write OTLP request body")?;
  let mut response = [0u8; 128];
  let read = stream
    .read(&mut response)
    .context("failed to read OTLP response")?;
  let status_line = std::str::from_utf8(&response[..read]).unwrap_or_default();
  if !status_line.starts_with("HTTP/1.1 2") && !status_line.starts_with("HTTP/1.0 2") {
    bail!("OTLP endpoint returned non-success status");
  }
  Ok(())
}

fn encode_export_request(service_name: &str, spans: &[TraceSpan]) -> Vec<u8> {
  let resource = encode_resource(service_name);
  let scope_spans = encode_scope_spans(spans);
  let mut resource_spans = Vec::new();
  write_message_field(&mut resource_spans, 1, &resource);
  write_message_field(&mut resource_spans, 2, &scope_spans);
  let mut request = Vec::new();
  write_message_field(&mut request, 1, &resource_spans);
  request
}

fn encode_resource(service_name: &str) -> Vec<u8> {
  let attr = encode_key_value("service.name", service_name);
  let mut resource = Vec::new();
  write_message_field(&mut resource, 1, &attr);
  resource
}

fn encode_scope_spans(spans: &[TraceSpan]) -> Vec<u8> {
  let mut scope = Vec::new();
  write_string_field(&mut scope, 1, "oxibelt");
  let mut scope_spans = Vec::new();
  write_message_field(&mut scope_spans, 1, &scope);
  for span in spans {
    write_message_field(&mut scope_spans, 2, &encode_span(span));
  }
  scope_spans
}

fn encode_span(span: &TraceSpan) -> Vec<u8> {
  let mut out = Vec::new();
  write_bytes_field(&mut out, 1, &span.trace_id);
  write_bytes_field(&mut out, 2, &span.span_id);
  if let Some(parent) = span.parent_span_id {
    write_bytes_field(&mut out, 4, &parent);
  }
  write_string_field(&mut out, 5, &span.name);
  write_varint_field(&mut out, 6, span.kind as u64);
  write_fixed64_field(&mut out, 7, span.start_time_unix_nano);
  write_fixed64_field(&mut out, 8, span.end_time_unix_nano);
  for attribute in &span.attributes {
    write_message_field(
      &mut out,
      9,
      &encode_key_value(&attribute.key, &attribute.value),
    );
  }
  out
}

fn encode_key_value(key: &str, value: &str) -> Vec<u8> {
  let mut any = Vec::new();
  write_string_field(&mut any, 1, value);
  let mut kv = Vec::new();
  write_string_field(&mut kv, 1, key);
  write_message_field(&mut kv, 2, &any);
  kv
}

fn write_varint_field(out: &mut Vec<u8>, field: u32, value: u64) {
  write_key(out, field, 0);
  write_varint(out, value);
}

fn write_fixed64_field(out: &mut Vec<u8>, field: u32, value: u64) {
  write_key(out, field, 1);
  out.extend_from_slice(&value.to_le_bytes());
}

fn write_string_field(out: &mut Vec<u8>, field: u32, value: &str) {
  write_bytes_field(out, field, value.as_bytes());
}

fn write_bytes_field(out: &mut Vec<u8>, field: u32, value: &[u8]) {
  write_key(out, field, 2);
  write_varint(out, value.len() as u64);
  out.extend_from_slice(value);
}

fn write_message_field(out: &mut Vec<u8>, field: u32, value: &[u8]) {
  write_bytes_field(out, field, value);
}

fn write_key(out: &mut Vec<u8>, field: u32, wire_type: u8) {
  write_varint(out, ((field as u64) << 3) | u64::from(wire_type));
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
  while value >= 0x80 {
    out.push((value as u8) | 0x80);
    value >>= 7;
  }
  out.push(value as u8);
}

fn extract_traceparent(headers: &HeaderMap) -> Option<TraceContext> {
  let value = headers.get(TRACEPARENT)?.to_str().ok()?;
  parse_traceparent(value)
}

fn parse_traceparent(value: &str) -> Option<TraceContext> {
  let mut parts = value.split('-');
  let version = parts.next()?;
  let trace = parts.next()?;
  let span = parts.next()?;
  let flags = parts.next()?;
  if parts.next().is_some()
    || version.len() != 2
    || trace.len() != 32
    || span.len() != 16
    || flags.len() != 2
  {
    return None;
  }
  let trace_id = parse_hex_16(trace)?;
  let span_id = parse_hex_8(span)?;
  if trace_id.iter().all(|byte| *byte == 0) || span_id.iter().all(|byte| *byte == 0) {
    return None;
  }
  let flags = u8::from_str_radix(flags, 16).ok()?;
  Some(TraceContext {
    trace_id,
    span_id,
    parent_span_id: None,
    sampled: flags & 1 == 1,
  })
}

fn format_traceparent(context: TraceContext) -> String {
  format!(
    "00-{}-{}-{:02x}",
    hex_bytes(&context.trace_id),
    hex_bytes(&context.span_id),
    u8::from(context.sampled)
  )
}

fn parse_hex_16(value: &str) -> Option<[u8; 16]> {
  let mut bytes = [0u8; 16];
  parse_hex_into(value, &mut bytes)?;
  Some(bytes)
}

fn parse_hex_8(value: &str) -> Option<[u8; 8]> {
  let mut bytes = [0u8; 8];
  parse_hex_into(value, &mut bytes)?;
  Some(bytes)
}

fn parse_hex_into(value: &str, out: &mut [u8]) -> Option<()> {
  for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
    let hi = hex_value(chunk[0])?;
    let lo = hex_value(chunk[1])?;
    out[index] = (hi << 4) | lo;
  }
  Some(())
}

fn hex_value(byte: u8) -> Option<u8> {
  match byte {
    b'0'..=b'9' => Some(byte - b'0'),
    b'a'..=b'f' => Some(byte - b'a' + 10),
    b'A'..=b'F' => Some(byte - b'A' + 10),
    _ => None,
  }
}

fn hex_bytes(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut output = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    output.push(HEX[(byte >> 4) as usize] as char);
    output.push(HEX[(byte & 0x0f) as usize] as char);
  }
  output
}

fn sample_trace(sample_ratio: f64) -> bool {
  if sample_ratio >= 1.0 {
    return true;
  }
  if sample_ratio <= 0.0 {
    return false;
  }
  let mut bytes = [0u8; 8];
  fill_trace_entropy(&mut bytes);
  let value = u64::from_be_bytes(bytes) as f64 / u64::MAX as f64;
  value < sample_ratio
}

fn random_trace_id() -> [u8; 16] {
  let mut bytes = [0u8; 16];
  fill_trace_entropy(&mut bytes);
  bytes
}

fn random_span_id() -> [u8; 8] {
  let mut bytes = [0u8; 8];
  fill_trace_entropy(&mut bytes);
  bytes
}

fn fill_trace_entropy(bytes: &mut [u8]) {
  if crate::crypto::random_fill(bytes).is_ok() && bytes.iter().any(|byte| *byte != 0) {
    return;
  }
  let counter = TRACE_ENTROPY_FALLBACK_COUNTER.fetch_add(1, Ordering::Relaxed);
  let mut seed = [0u8; 16];
  seed[..8].copy_from_slice(&unix_nanos_now().to_be_bytes());
  seed[8..].copy_from_slice(&counter.to_be_bytes());
  let digest = crate::crypto::sha256(&seed);
  bytes.copy_from_slice(&digest[..bytes.len()]);
  tracing::warn!("system entropy unavailable; generated a best-effort telemetry identifier");
}

fn unix_nanos_now() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_nanos()
    .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_and_formats_traceparent() {
    let context = parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
      .expect("traceparent should parse");

    assert!(context.sampled);
    assert_eq!(
      format_traceparent(context),
      "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    );
  }

  #[test]
  fn rejects_zero_traceparent_ids() {
    assert!(
      parse_traceparent("00-00000000000000000000000000000000-00f067aa0ba902b7-01",).is_none()
    );
    assert!(
      parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",).is_none()
    );
  }

  #[test]
  fn injects_trace_context_header() {
    let runtime = TelemetryRuntime::new(&TelemetryTracingConfig {
      enabled: true,
      endpoint: "http://127.0.0.1:4318/v1/traces".to_string(),
      service_name: "test".to_string(),
      sample_ratio: 1.0,
      export_timeout_ms: 1,
      propagate_trace_context: true,
    })
    .expect("telemetry runtime should start");
    let context = parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
    let mut headers = HeaderMap::new();

    runtime.inject_trace_context(&mut headers, context);

    assert_eq!(
      headers
        .get(TRACEPARENT)
        .and_then(|value| value.to_str().ok()),
      Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
    );
  }

  #[test]
  fn encodes_nonempty_otlp_export_request() {
    let context =
      parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").unwrap();
    let span = TraceSpan {
      trace_id: context.trace_id,
      span_id: context.span_id,
      parent_span_id: None,
      name: "http.server".to_string(),
      kind: SpanKind::Server,
      start_time_unix_nano: 1,
      end_time_unix_nano: 2,
      attributes: vec![TraceAttribute::string("http.method", "GET")],
    };

    let bytes = encode_export_request("oxibelt", &[span]);

    assert!(!bytes.is_empty());
    assert!(
      bytes
        .windows("service.name".len())
        .any(|item| item == b"service.name")
    );
    assert!(
      bytes
        .windows("http.server".len())
        .any(|item| item == b"http.server")
    );
  }
}

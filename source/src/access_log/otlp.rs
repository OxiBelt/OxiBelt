use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, bail};
use serde_json::Value;
use tracing::warn;
use url::Url;

use crate::config::{AccessLogOtlpConfig, AccessLogSchema};

use super::AccessLogSource;

#[derive(Clone)]
pub(super) struct OtlpAccessLogSink {
  inner: Arc<OtlpAccessLogSinkInner>,
}

struct OtlpAccessLogSinkInner {
  sender: Mutex<Option<SyncSender<OtlpLogRecord>>>,
  exporter: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Debug, Clone)]
pub(super) struct OtlpLogRecord {
  time_unix_nano: u64,
  severity_number: u64,
  severity_text: &'static str,
  event_name: &'static str,
  body: String,
  attributes: Vec<AccessLogAttribute>,
}

#[derive(Debug, Clone)]
struct AccessLogAttribute {
  key: String,
  value: String,
}

#[derive(Clone)]
struct OtlpHttpEndpoint {
  host: String,
  port: u16,
  path_and_query: String,
}

impl OtlpAccessLogSink {
  pub(super) fn start(config: &AccessLogOtlpConfig) -> anyhow::Result<Self> {
    let endpoint = OtlpHttpEndpoint::parse(&config.endpoint)?;
    let timeout = Duration::from_millis(config.export_timeout_ms);
    let batch_size = config.batch_size;
    let service_name = config.service_name.clone();
    let (sender, receiver) = mpsc::sync_channel(config.queue_capacity);
    let exporter = thread::Builder::new()
      .name("oxibelt-otlp-access-log-exporter".to_string())
      .spawn(move || run_otlp_log_exporter(receiver, endpoint, timeout, service_name, batch_size))
      .context("failed to start OTLP access-log exporter thread")?;
    Ok(Self {
      inner: Arc::new(OtlpAccessLogSinkInner {
        sender: Mutex::new(Some(sender)),
        exporter: Mutex::new(Some(exporter)),
      }),
    })
  }

  pub(super) fn enqueue(&self, record: OtlpLogRecord) {
    let sender = self
      .inner
      .sender
      .lock()
      .ok()
      .and_then(|sender| sender.as_ref().cloned());
    let Some(sender) = sender else {
      return;
    };
    if let Err(error) = sender.try_send(record) {
      match error {
        TrySendError::Full(_) => warn!("OTLP access-log queue is full; dropping access log record"),
        TrySendError::Disconnected(_) => {
          warn!("OTLP access-log exporter is closed; dropping access log record");
        }
      }
    }
  }
}

impl Drop for OtlpAccessLogSink {
  fn drop(&mut self) {
    if Arc::strong_count(&self.inner) != 1 {
      return;
    }
    if let Ok(mut sender) = self.inner.sender.lock() {
      sender.take();
    }
    if let Ok(mut exporter) = self.inner.exporter.lock()
      && let Some(handle) = exporter.take()
      && handle.join().is_err()
    {
      warn!("OTLP access-log exporter thread panicked during shutdown");
    }
  }
}

impl OtlpLogRecord {
  pub(super) fn from_projected(
    source: AccessLogSource,
    timestamp_unix_ms: u64,
    schema: AccessLogSchema,
    original: &Value,
    projected: Value,
  ) -> Self {
    let body = serde_json::to_string(&projected).unwrap_or_else(|_| "{}".to_string());
    let mut attributes = vec![
      AccessLogAttribute::string("event.name", event_name(source)),
      AccessLogAttribute::string("event.dataset", event_dataset(source)),
      AccessLogAttribute::string("oxibelt.scope", source_scope(source)),
      AccessLogAttribute::string("oxibelt.access_log.schema", schema_name(schema)),
    ];
    match schema {
      AccessLogSchema::Ocsf => {
        if let Some(version) = value_string(&projected, &["metadata", "version"]) {
          attributes.push(AccessLogAttribute::string("ocsf.version", version));
        }
      }
      AccessLogSchema::Ecs => {
        if let Some(version) = value_string(&projected, &["ecs", "version"]) {
          attributes.push(AccessLogAttribute::string("ecs.version", version));
        }
      }
    }
    let failure = event_failed(original);
    Self {
      time_unix_nano: timestamp_unix_ms.saturating_mul(1_000_000),
      severity_number: if failure { 17 } else { 9 },
      severity_text: if failure { "ERROR" } else { "INFO" },
      event_name: event_name(source),
      body,
      attributes,
    }
  }
}

impl AccessLogAttribute {
  fn string(key: impl Into<String>, value: impl Into<String>) -> Self {
    Self {
      key: key.into(),
      value: value.into(),
    }
  }
}

impl OtlpHttpEndpoint {
  fn parse(value: &str) -> anyhow::Result<Self> {
    let url = Url::parse(value).context("invalid access_log.otlp.endpoint")?;
    if url.scheme() != "http" {
      bail!("access_log.otlp.endpoint currently supports only http://");
    }
    let host = url
      .host_str()
      .ok_or_else(|| anyhow::anyhow!("access_log.otlp.endpoint must include a host"))?
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

fn run_otlp_log_exporter(
  receiver: mpsc::Receiver<OtlpLogRecord>,
  endpoint: OtlpHttpEndpoint,
  timeout: Duration,
  service_name: String,
  batch_size: usize,
) {
  let mut batch = Vec::with_capacity(batch_size);
  loop {
    match receiver.recv_timeout(Duration::from_secs(1)) {
      Ok(record) => batch.push(record),
      Err(mpsc::RecvTimeoutError::Timeout) => {}
      Err(mpsc::RecvTimeoutError::Disconnected) => {
        flush_otlp_log_batch(&mut batch, &endpoint, timeout, &service_name);
        return;
      }
    }
    while batch.len() < batch_size {
      match receiver.try_recv() {
        Ok(record) => batch.push(record),
        Err(mpsc::TryRecvError::Empty) => break,
        Err(mpsc::TryRecvError::Disconnected) => {
          flush_otlp_log_batch(&mut batch, &endpoint, timeout, &service_name);
          return;
        }
      }
    }
    flush_otlp_log_batch(&mut batch, &endpoint, timeout, &service_name);
  }
}

fn flush_otlp_log_batch(
  batch: &mut Vec<OtlpLogRecord>,
  endpoint: &OtlpHttpEndpoint,
  timeout: Duration,
  service_name: &str,
) {
  if batch.is_empty() {
    return;
  }
  let payload = encode_logs_export_request(service_name, batch);
  batch.clear();
  if let Err(error) = post_otlp_http(endpoint, timeout, &payload) {
    warn!(error = %error, "failed to export OTLP access-log batch");
  }
}

fn post_otlp_http(
  endpoint: &OtlpHttpEndpoint,
  timeout: Duration,
  payload: &[u8],
) -> anyhow::Result<()> {
  let address = (endpoint.host.as_str(), endpoint.port)
    .to_socket_addrs()
    .context("failed to resolve access_log.otlp.endpoint")?
    .next()
    .ok_or_else(|| anyhow::anyhow!("access_log.otlp.endpoint resolved no addresses"))?;
  let mut stream = TcpStream::connect_timeout(&address, timeout)
    .context("failed to connect access_log.otlp.endpoint")?;
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
    .context("failed to write OTLP access-log request headers")?;
  stream
    .write_all(payload)
    .context("failed to write OTLP access-log request body")?;
  let mut response = [0u8; 128];
  let read = stream
    .read(&mut response)
    .context("failed to read OTLP access-log response")?;
  let status_line = std::str::from_utf8(&response[..read]).unwrap_or_default();
  if !status_line.starts_with("HTTP/1.1 2") && !status_line.starts_with("HTTP/1.0 2") {
    bail!("access_log.otlp.endpoint returned non-success status");
  }
  Ok(())
}

fn encode_logs_export_request(service_name: &str, records: &[OtlpLogRecord]) -> Vec<u8> {
  let resource = encode_resource(service_name);
  let scope_logs = encode_scope_logs(records);
  let mut resource_logs = Vec::new();
  write_message_field(&mut resource_logs, 1, &resource);
  write_message_field(&mut resource_logs, 2, &scope_logs);
  let mut request = Vec::new();
  write_message_field(&mut request, 1, &resource_logs);
  request
}

fn encode_resource(service_name: &str) -> Vec<u8> {
  let mut resource = Vec::new();
  write_message_field(
    &mut resource,
    1,
    &encode_key_value("service.name", service_name),
  );
  resource
}

fn encode_scope_logs(records: &[OtlpLogRecord]) -> Vec<u8> {
  let mut scope = Vec::new();
  write_string_field(&mut scope, 1, "oxibelt");
  let mut scope_logs = Vec::new();
  write_message_field(&mut scope_logs, 1, &scope);
  for record in records {
    write_message_field(&mut scope_logs, 2, &encode_log_record(record));
  }
  scope_logs
}

fn encode_log_record(record: &OtlpLogRecord) -> Vec<u8> {
  let mut out = Vec::new();
  write_fixed64_field(&mut out, 1, record.time_unix_nano);
  write_varint_field(&mut out, 2, record.severity_number);
  write_string_field(&mut out, 3, record.severity_text);
  write_message_field(&mut out, 5, &encode_string_any_value(&record.body));
  for attribute in &record.attributes {
    write_message_field(
      &mut out,
      6,
      &encode_key_value(&attribute.key, &attribute.value),
    );
  }
  write_string_field(&mut out, 12, record.event_name);
  out
}

fn encode_key_value(key: &str, value: &str) -> Vec<u8> {
  let mut kv = Vec::new();
  write_string_field(&mut kv, 1, key);
  write_message_field(&mut kv, 2, &encode_string_any_value(value));
  kv
}

fn encode_string_any_value(value: &str) -> Vec<u8> {
  let mut any = Vec::new();
  write_string_field(&mut any, 1, value);
  any
}

fn event_failed(value: &Value) -> bool {
  if let Some(outcome) = value_string(value, &["outcome"]) {
    let normalized = outcome.to_ascii_lowercase();
    if matches!(normalized.as_str(), "failure" | "denied" | "rejected") {
      return true;
    }
    if matches!(normalized.as_str(), "success" | "allowed" | "applied") {
      return false;
    }
  }
  value_u64(value, &["status"]).is_some_and(|status| status >= 400)
}

fn event_name(source: AccessLogSource) -> &'static str {
  match source {
    AccessLogSource::System | AccessLogSource::Waf => "oxibelt.access",
    AccessLogSource::Admin => "oxibelt.admin.access",
  }
}

fn event_dataset(source: AccessLogSource) -> String {
  format!("oxibelt.access.{}", source_scope(source))
}

fn source_scope(source: AccessLogSource) -> &'static str {
  match source {
    AccessLogSource::System => "system",
    AccessLogSource::Waf => "waf",
    AccessLogSource::Admin => "admin",
  }
}

fn schema_name(schema: AccessLogSchema) -> &'static str {
  match schema {
    AccessLogSchema::Ocsf => "ocsf",
    AccessLogSchema::Ecs => "ecs",
  }
}

fn value_string(value: &Value, path: &[&str]) -> Option<String> {
  value_at(value, path)?.as_str().map(str::to_string)
}

fn value_u64(value: &Value, path: &[&str]) -> Option<u64> {
  let value = value_at(value, path)?;
  value
    .as_u64()
    .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok()))
}

fn value_at<'a>(mut value: &'a Value, path: &[&str]) -> Option<&'a Value> {
  for segment in path {
    value = value.get(*segment)?;
  }
  Some(value)
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

#[cfg(test)]
mod tests {
  use serde_json::json;

  use super::*;
  use crate::access_log::projection::{project_ecs, project_ocsf};

  #[test]
  fn otlp_logs_export_request_contains_ecs_payload_and_attributes() {
    let original = json!({
      "event": "oxibelt.access",
      "scope": "system",
      "method": "GET",
      "status": 200,
      "user_agent": {
        "values": ["first-agent", "second-agent"],
        "is_truncated": false
      }
    });
    let record = OtlpLogRecord::from_projected(
      AccessLogSource::System,
      42,
      AccessLogSchema::Ecs,
      &original,
      project_ecs(AccessLogSource::System, 42, &original),
    );

    let bytes = encode_logs_export_request("oxibelt", &[record]);

    assert_payload_contains(&bytes, b"service.name");
    assert_payload_contains(&bytes, b"ecs.version");
    assert_payload_contains(&bytes, b"oxibelt.access_log.schema");
    assert_payload_contains(&bytes, b"oxibelt.access.system");
    assert_payload_contains(&bytes, b"\"oxibelt\"");
    assert_payload_contains(&bytes, b"\"original\"");
    assert_payload_contains(&bytes, b"first-agent");
    assert_payload_contains(&bytes, b"second-agent");
  }

  #[test]
  fn otlp_logs_export_request_contains_ocsf_payload_and_attributes() {
    let original = json!({
      "event": "oxibelt.admin.access",
      "scope": "admin",
      "request_id": "req-1",
      "actor": "alice",
      "principal": "admin",
      "subject": "sub-1",
      "groups": ["ops"],
      "tls": true,
      "method": "POST",
      "path": "/admin/v1/tokens",
      "service": "tokens",
      "operation": "post.tokens.create",
      "action": "admin:CreateToken",
      "resource": "token/*",
      "target_kind": "token",
      "target_id": "tok-1",
      "status": 201,
      "outcome": "applied"
    });
    let record = OtlpLogRecord::from_projected(
      AccessLogSource::Admin,
      42,
      AccessLogSchema::Ocsf,
      &original,
      project_ocsf(AccessLogSource::Admin, 42, &original),
    );

    let bytes = encode_logs_export_request("oxibelt", &[record]);

    assert_payload_contains(&bytes, b"ocsf.version");
    assert_payload_contains(&bytes, b"API Activity");
    assert_payload_contains(&bytes, b"oxibelt.admin.access");
    assert_payload_contains(&bytes, b"admin:CreateToken");
    assert_payload_contains(&bytes, b"tok-1");
  }

  #[test]
  fn failed_status_uses_error_severity() {
    let original = json!({
      "event": "oxibelt.access",
      "scope": "waf",
      "method": "POST",
      "status": 403
    });
    let record = OtlpLogRecord::from_projected(
      AccessLogSource::Waf,
      42,
      AccessLogSchema::Ecs,
      &original,
      project_ecs(AccessLogSource::Waf, 42, &original),
    );

    assert_eq!(record.severity_number, 17);
    assert_eq!(record.severity_text, "ERROR");
  }

  fn assert_payload_contains(payload: &[u8], needle: &[u8]) {
    assert!(
      payload.windows(needle.len()).any(|window| window == needle),
      "payload did not contain {:?}",
      String::from_utf8_lossy(needle)
    );
  }
}

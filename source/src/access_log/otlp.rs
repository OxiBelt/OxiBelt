use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, bail};
use serde_json::Value;
use tracing::warn;
use url::{Host, Url};

use crate::config::{
  AccessLogOtlpConfig, AccessLogSchema, CryptoConfig, UpstreamEchConfig,
  UpstreamTlsResumptionConfig, validate_access_log_otlp_endpoint_url,
};

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

#[derive(Clone, Debug)]
struct OtlpHttpEndpoint {
  scheme: OtlpEndpointScheme,
  host: String,
  port: u16,
  authority: String,
  path_and_query: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OtlpEndpointScheme {
  Http,
  Https,
}

impl OtlpAccessLogSink {
  pub(super) fn start(config: &AccessLogOtlpConfig, crypto: &CryptoConfig) -> anyhow::Result<Self> {
    let endpoint = OtlpHttpEndpoint::parse(&config.endpoint)?;
    let tls_config = if endpoint.scheme == OtlpEndpointScheme::Https {
      Some(build_otlp_tls_config(config, crypto)?)
    } else {
      None
    };
    let timeout = Duration::from_millis(config.export_timeout_ms);
    let batch_size = config.batch_size;
    let service_name = config.service_name.clone();
    let (sender, receiver) = mpsc::sync_channel(config.queue_capacity);
    let exporter = thread::Builder::new()
      .name("oxibelt-otlp-access-log-exporter".to_string())
      .spawn(move || {
        run_otlp_log_exporter(
          receiver,
          endpoint,
          tls_config,
          timeout,
          service_name,
          batch_size,
        )
      })
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
    validate_access_log_otlp_endpoint_url(&url)?;
    let host = url
      .host_str()
      .ok_or_else(|| anyhow::anyhow!("access_log.otlp.endpoint must include a host"))?
      .to_string();
    let scheme = match url.scheme() {
      "http" => OtlpEndpointScheme::Http,
      "https" => OtlpEndpointScheme::Https,
      _ => {
        bail!("access_log.otlp.endpoint must use https://, or http:// for loopback OTLP collectors")
      }
    };
    let default_port = match scheme {
      OtlpEndpointScheme::Http => 80,
      OtlpEndpointScheme::Https => 443,
    };
    let port = url.port_or_known_default().unwrap_or(default_port);
    let host_header = host_header_base(&url)?;
    let authority = if port == default_port {
      host_header
    } else {
      format!("{host_header}:{port}")
    };
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
      scheme,
      host,
      port,
      authority,
      path_and_query,
    })
  }
}

fn host_header_base(url: &Url) -> anyhow::Result<String> {
  match url.host() {
    Some(Host::Domain(domain)) => Ok(domain.to_string()),
    Some(Host::Ipv4(address)) => Ok(address.to_string()),
    Some(Host::Ipv6(address)) => Ok(format!("[{address}]")),
    None => bail!("access_log.otlp.endpoint must include a host"),
  }
}

fn build_otlp_tls_config(
  config: &AccessLogOtlpConfig,
  crypto: &CryptoConfig,
) -> anyhow::Result<Arc<rustls::ClientConfig>> {
  let mut tls_config =
    crate::tls::build_upstream_client_config_with_crypto_resumption_and_revocation(
      crypto,
      &config.trusted_ca_certs,
      &UpstreamEchConfig::default(),
      &UpstreamTlsResumptionConfig::default(),
      None,
      "access_log.otlp",
      None,
    )
    .context("failed to build OTLP access-log TLS client config")?;
  tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
  Ok(Arc::new(tls_config))
}

fn run_otlp_log_exporter(
  receiver: mpsc::Receiver<OtlpLogRecord>,
  endpoint: OtlpHttpEndpoint,
  tls_config: Option<Arc<rustls::ClientConfig>>,
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
        flush_otlp_log_batch(
          &mut batch,
          &endpoint,
          tls_config.as_ref(),
          timeout,
          &service_name,
        );
        return;
      }
    }
    while batch.len() < batch_size {
      match receiver.try_recv() {
        Ok(record) => batch.push(record),
        Err(mpsc::TryRecvError::Empty) => break,
        Err(mpsc::TryRecvError::Disconnected) => {
          flush_otlp_log_batch(
            &mut batch,
            &endpoint,
            tls_config.as_ref(),
            timeout,
            &service_name,
          );
          return;
        }
      }
    }
    flush_otlp_log_batch(
      &mut batch,
      &endpoint,
      tls_config.as_ref(),
      timeout,
      &service_name,
    );
  }
}

fn flush_otlp_log_batch(
  batch: &mut Vec<OtlpLogRecord>,
  endpoint: &OtlpHttpEndpoint,
  tls_config: Option<&Arc<rustls::ClientConfig>>,
  timeout: Duration,
  service_name: &str,
) {
  if batch.is_empty() {
    return;
  }
  let payload = encode_logs_export_request(service_name, batch);
  batch.clear();
  if let Err(error) = post_otlp_http(endpoint, timeout, &payload, tls_config) {
    warn!(error = %error, "failed to export OTLP access-log batch");
  }
}

fn post_otlp_http(
  endpoint: &OtlpHttpEndpoint,
  timeout: Duration,
  payload: &[u8],
  tls_config: Option<&Arc<rustls::ClientConfig>>,
) -> anyhow::Result<()> {
  let mut stream = connect_otlp_endpoint(endpoint, timeout)?;
  stream.set_read_timeout(Some(timeout)).ok();
  stream.set_write_timeout(Some(timeout)).ok();
  match endpoint.scheme {
    OtlpEndpointScheme::Http => post_otlp_over_stream(endpoint, payload, &mut stream),
    OtlpEndpointScheme::Https => {
      let tls_config = tls_config
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("access_log.otlp.endpoint requires TLS client config"))?;
      let server_name = rustls::pki_types::ServerName::try_from(endpoint.host.clone())
        .map_err(|error| anyhow::anyhow!("invalid access_log.otlp TLS server name: {error}"))?;
      let mut tls = rustls::StreamOwned::new(
        rustls::ClientConnection::new(tls_config, server_name)
          .context("failed to create OTLP access-log TLS client connection")?,
        stream,
      );
      post_otlp_over_stream(endpoint, payload, &mut tls)
    }
  }
}

fn connect_otlp_endpoint(
  endpoint: &OtlpHttpEndpoint,
  timeout: Duration,
) -> anyhow::Result<TcpStream> {
  let addresses = crate::upstream_resolution::resolve_socket_addrs_blocking(
    &endpoint.host,
    endpoint.port,
    timeout,
  )
  .context("failed to resolve access_log.otlp.endpoint")?;
  if addresses.is_empty() {
    bail!("access_log.otlp.endpoint resolved no addresses");
  }
  let mut last_error = None;
  for address in addresses {
    match TcpStream::connect_timeout(&address, timeout) {
      Ok(stream) => return Ok(stream),
      Err(error) => last_error = Some((address, error)),
    }
  }
  if let Some((address, error)) = last_error {
    Err(error)
      .with_context(|| format!("failed to connect access_log.otlp.endpoint at {address}"))?;
  }
  bail!("failed to connect access_log.otlp.endpoint")
}

fn post_otlp_over_stream(
  endpoint: &OtlpHttpEndpoint,
  payload: &[u8],
  stream: &mut (impl Read + Write),
) -> anyhow::Result<()> {
  let request = format!(
    "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-protobuf\r\nContent-Length: {}\r\nUser-Agent: oxibelt\r\nConnection: close\r\n\r\n",
    endpoint.path_and_query,
    endpoint.authority,
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
#[path = "otlp_tests.rs"]
mod tests;

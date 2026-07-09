//! Access-log projection and delivery for system, WAF, and Admin API events.
//! Logging failures are isolated from request enforcement decisions.

use std::sync::Arc;

use serde_json::Value;
use tracing::warn;

use crate::admin_audit::AdminAuditEvent;
use crate::config::{AccessLogConfig, AccessLogSchema, LoggingAccessLogConfig};
use crate::waf::{
  AccessLogRecord, CompiledAccessLogFields, WafEngine, WafResponseInput, compile_access_log_fields,
  current_unix_ms,
};

mod otlp;
mod projection;

use otlp::{OtlpAccessLogSink, OtlpLogRecord};
use projection::{admin_event_value, emit_stdout, project_ecs, project_ocsf};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AccessLogSource {
  System,
  Waf,
  Admin,
}

#[derive(Clone)]
pub struct AccessLogRuntime {
  inner: Arc<AccessLogRuntimeInner>,
}

struct AccessLogRuntimeInner {
  config: AccessLogConfig,
  otlp: Option<OtlpAccessLogSink>,
}

#[derive(Clone)]
pub struct AccessLogSinks {
  source: AccessLogSource,
  runtime: AccessLogRuntime,
}

impl AccessLogRuntime {
  pub fn disabled() -> Self {
    let mut config = AccessLogConfig::default();
    config.system.enabled = false;
    config.waf.enabled = false;
    config.admin.enabled = false;
    config.stdout.enabled = false;
    config.otlp.enabled = false;
    Self {
      inner: Arc::new(AccessLogRuntimeInner { config, otlp: None }),
    }
  }

  pub async fn new(config: &AccessLogConfig) -> anyhow::Result<Self> {
    let otlp = if config.otlp.enabled {
      Some(OtlpAccessLogSink::start(&config.otlp)?)
    } else {
      None
    };
    Ok(Self {
      inner: Arc::new(AccessLogRuntimeInner {
        config: config.clone(),
        otlp,
      }),
    })
  }

  fn source_enabled(&self, source: AccessLogSource) -> bool {
    match source {
      AccessLogSource::System => self.inner.config.system.enabled,
      AccessLogSource::Waf => self.inner.config.waf.enabled,
      AccessLogSource::Admin => self.inner.config.admin.enabled,
    }
  }

  fn emit_record(&self, source: AccessLogSource, record: &AccessLogRecord) {
    self.emit_value(source, record.timestamp_unix_ms(), record.to_json_value());
  }

  fn emit_admin_event(&self, event: &AdminAuditEvent) {
    self.emit_value(
      AccessLogSource::Admin,
      current_unix_ms(),
      admin_event_value(event),
    );
  }

  fn emit_value(&self, source: AccessLogSource, timestamp_unix_ms: u64, value: Value) {
    if !self.source_enabled(source) {
      return;
    }

    let ecs = project_ecs(source, timestamp_unix_ms, &value);
    if self.inner.config.stdout.enabled {
      let stdout_record = match self.inner.config.stdout.schema {
        AccessLogSchema::Ecs => ecs.clone(),
        AccessLogSchema::Ocsf => project_ocsf(source, timestamp_unix_ms, &value),
      };
      emit_stdout(source, &stdout_record);
    }

    if let Some(otlp) = &self.inner.otlp {
      otlp.enqueue(OtlpLogRecord::from_ecs(source, timestamp_unix_ms, ecs));
    }
  }
}

impl Default for AccessLogRuntime {
  fn default() -> Self {
    Self::disabled()
  }
}

impl AccessLogSinks {
  pub fn disabled() -> Self {
    Self::new(AccessLogRuntime::disabled(), AccessLogSource::Waf)
  }

  pub fn new(runtime: AccessLogRuntime, source: AccessLogSource) -> Self {
    Self { source, runtime }
  }

  pub fn emit(&self, record: &AccessLogRecord) {
    self.runtime.emit_record(self.source, record);
  }

  pub fn emit_admin_event(&self, event: &AdminAuditEvent) {
    self.runtime.emit_admin_event(event);
  }
}

#[derive(Clone)]
pub struct SystemAccessLog {
  enabled: bool,
  fields: CompiledAccessLogFields,
  sinks: AccessLogSinks,
}

impl SystemAccessLog {
  pub async fn new(
    config: &LoggingAccessLogConfig,
    runtime: AccessLogRuntime,
    enabled: bool,
  ) -> anyhow::Result<Self> {
    let fields = compile_access_log_fields("logging.access_log", &config.fields)?;
    Ok(Self {
      enabled,
      fields,
      sinks: AccessLogSinks::new(runtime, AccessLogSource::System),
    })
  }

  pub fn enabled(&self) -> bool {
    self.enabled
  }

  pub fn emit(&self, waf: &WafEngine, input: WafResponseInput<'_>) {
    if !self.enabled {
      return;
    }
    match waf.build_system_access_log(&self.fields, input) {
      Ok(record) => self.sinks.emit(&record),
      Err(error) => warn!(error = %error, "failed to build system access log record"),
    }
  }
}

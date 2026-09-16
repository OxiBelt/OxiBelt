use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

#[cfg(feature = "admin-runtime")]
use serde::Serialize;
use tokio::sync::Semaphore;
use tracing::warn;

use crate::config::Config;
use crate::metrics::Metrics;

use super::client::{ExternalCacheHttpClient, ExternalCacheLookupHit, ExternalCachePublishBody};
use super::nvs_protocol::{
  ExternalCacheNvsCandidatesRequest, ExternalCacheNvsCandidatesResponse,
  ExternalCacheNvsEpochRequest, ExternalCacheNvsEpochResponse,
};
#[cfg(feature = "admin-runtime")]
use super::protocol::ExternalCachePurgeRequest;
use super::protocol::{
  ExternalCacheEntryMetadata, ExternalCacheLookupRequest, ExternalCacheQueryCleanupRequest,
  ExternalCacheQueryEpochRequest, ExternalCacheQueryEpochResponse,
};

#[derive(Clone)]
pub(crate) struct ExternalCacheRuntime {
  handlers: Arc<HashMap<String, Arc<ExternalCacheHandler>>>,
  metrics: Arc<Metrics>,
}

struct ExternalCacheHandler {
  name: String,
  client: ExternalCacheHttpClient,
  limiter: Arc<Semaphore>,
}

#[cfg(feature = "admin-runtime")]
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ExternalCachePurgeReport {
  pub handler: String,
  pub status: &'static str,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub purged: Option<usize>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct ExternalCacheQueryCleanupReport {
  pub purged: usize,
  pub complete: bool,
}

impl ExternalCacheRuntime {
  pub(crate) fn disabled(metrics: Arc<Metrics>) -> Self {
    Self {
      handlers: Arc::new(HashMap::new()),
      metrics,
    }
  }

  pub(crate) fn new(config: &Config, metrics: Arc<Metrics>) -> anyhow::Result<Self> {
    if config.cache.external_handlers.is_empty() {
      return Ok(Self::disabled(metrics));
    }
    let mut handlers = HashMap::new();
    for handler in &config.cache.external_handlers {
      let max_body_bytes = handler
        .max_body_bytes
        .unwrap_or(config.cache.max_size_bytes);
      let client = ExternalCacheHttpClient::new(
        handler,
        &config.proxy.trusted_ca_certs,
        config.crypto.auxiliary_tls.enable_secp256r1mlkem768,
        config.proxy.buffering.max_memory_body_bytes,
        max_body_bytes,
      )?;
      handlers.insert(
        handler.name.clone(),
        Arc::new(ExternalCacheHandler {
          name: handler.name.clone(),
          client,
          limiter: Arc::new(Semaphore::new(handler.max_inflight_requests)),
        }),
      );
    }
    Ok(Self {
      handlers: Arc::new(handlers),
      metrics,
    })
  }

  pub(crate) async fn lookup(
    &self,
    handler_name: &str,
    request: ExternalCacheLookupRequest,
    temp_dir: Option<&Path>,
  ) -> Option<ExternalCacheLookupHit> {
    let handler = self.handlers.get(handler_name)?;
    let Ok(_permit) = handler.limiter.clone().try_acquire_owned() else {
      self.record(&handler.name, "lookup", "saturated");
      return None;
    };
    match handler.client.lookup(&request, temp_dir).await {
      Ok(Some(hit)) => {
        self.record(&handler.name, "lookup", "hit");
        Some(hit)
      }
      Ok(None) => {
        self.record(&handler.name, "lookup", "miss");
        None
      }
      Err(error) => {
        self.record(&handler.name, "lookup", "error");
        warn!(handler = %handler.name, error = %error, "external cache lookup failed");
        None
      }
    }
  }

  /// Returns `None` for an absent, legacy, saturated, or failed handler. Q1
  /// callers treat that as a fail-closed cache bypass.
  pub(crate) async fn query_epoch(
    &self,
    handler_name: &str,
    request: ExternalCacheQueryEpochRequest,
  ) -> Option<ExternalCacheQueryEpochResponse> {
    let handler = self.handlers.get(handler_name)?;
    let Ok(_permit) = handler.limiter.clone().try_acquire_owned() else {
      self.record(&handler.name, "query_epoch", "saturated");
      return None;
    };
    match handler.client.query_epoch(&request).await {
      Ok(response) => {
        self.record(&handler.name, "query_epoch", "ok");
        Some(response)
      }
      Err(error) => {
        self.record(&handler.name, "query_epoch", "error");
        warn!(handler = %handler.name, error = %error, "external QUERY epoch request failed");
        None
      }
    }
  }

  pub(crate) async fn nvs_epoch(
    &self,
    handler_name: &str,
    request: ExternalCacheNvsEpochRequest,
  ) -> Option<ExternalCacheNvsEpochResponse> {
    let handler = self.handlers.get(handler_name)?;
    let Ok(_permit) = handler.limiter.clone().try_acquire_owned() else {
      self.record(&handler.name, "nvs_epoch", "saturated");
      return None;
    };
    match handler.client.nvs_epoch(&request).await {
      Ok(response) => {
        self.record(&handler.name, "nvs_epoch", "ok");
        Some(response)
      }
      Err(error) => {
        self.record(&handler.name, "nvs_epoch", "error");
        warn!(handler = %handler.name, error = %error, "external No-Vary-Search epoch request failed");
        None
      }
    }
  }

  pub(crate) async fn nvs_candidates(
    &self,
    handler_name: &str,
    request: ExternalCacheNvsCandidatesRequest,
  ) -> Option<ExternalCacheNvsCandidatesResponse> {
    let handler = self.handlers.get(handler_name)?;
    let Ok(_permit) = handler.limiter.clone().try_acquire_owned() else {
      self.record(&handler.name, "nvs_candidates", "saturated");
      return None;
    };
    match handler.client.nvs_candidates(&request).await {
      Ok(response) => {
        self.record(&handler.name, "nvs_candidates", "ok");
        Some(response)
      }
      Err(error) => {
        self.record(&handler.name, "nvs_candidates", "error");
        warn!(handler = %handler.name, error = %error, "external No-Vary-Search candidate request failed");
        None
      }
    }
  }

  /// Attempts bounded external Q1 cleanup without affecting invalidation
  /// correctness. Absence, saturation, and errors are all best-effort misses.
  pub(crate) async fn query_cleanup(
    &self,
    handler_name: &str,
    request: ExternalCacheQueryCleanupRequest,
  ) -> Option<ExternalCacheQueryCleanupReport> {
    let handler = self.handlers.get(handler_name)?;
    let Ok(_permit) = handler.limiter.clone().try_acquire_owned() else {
      self.record(&handler.name, "query_cleanup", "saturated");
      return None;
    };
    match handler.client.query_cleanup(&request).await {
      Ok(response) => {
        let outcome = if response.complete {
          "complete"
        } else {
          "partial"
        };
        self.record(&handler.name, "query_cleanup", outcome);
        Some(ExternalCacheQueryCleanupReport {
          purged: response.purged,
          complete: response.complete,
        })
      }
      Err(error) => {
        self.record(&handler.name, "query_cleanup", "error");
        warn!(handler = %handler.name, error = %error, "external QUERY cleanup request failed");
        None
      }
    }
  }

  pub(crate) fn spawn_fill(
    &self,
    handler_name: String,
    metadata: ExternalCacheEntryMetadata,
    body: ExternalCachePublishBody,
  ) {
    let Some(handler) = self.handlers.get(&handler_name).cloned() else {
      return;
    };
    let metrics = self.metrics.clone();
    let Ok(permit) = handler.limiter.clone().try_acquire_owned() else {
      metrics.record_external_cache_operation(&handler.name, "fill", "saturated");
      return;
    };
    tokio::spawn(async move {
      let _permit = permit;
      match handler.client.fill(metadata, body).await {
        Ok(()) => metrics.record_external_cache_operation(&handler.name, "fill", "stored"),
        Err(error) => {
          metrics.record_external_cache_operation(&handler.name, "fill", "error");
          warn!(handler = %handler.name, error = %error, "external cache fill failed");
        }
      }
    });
  }

  pub(crate) fn spawn_revalidate(
    &self,
    handler_name: String,
    metadata: ExternalCacheEntryMetadata,
  ) {
    let Some(handler) = self.handlers.get(&handler_name).cloned() else {
      return;
    };
    let metrics = self.metrics.clone();
    let Ok(permit) = handler.limiter.clone().try_acquire_owned() else {
      metrics.record_external_cache_operation(&handler.name, "revalidate", "saturated");
      return;
    };
    tokio::spawn(async move {
      let _permit = permit;
      match handler.client.revalidate(&metadata).await {
        Ok(()) => metrics.record_external_cache_operation(&handler.name, "revalidate", "updated"),
        Err(error) => {
          metrics.record_external_cache_operation(&handler.name, "revalidate", "error");
          warn!(handler = %handler.name, error = %error, "external cache revalidation failed");
        }
      }
    });
  }

  #[cfg(feature = "admin-runtime")]
  pub(crate) async fn purge(
    &self,
    handler_name: &str,
    purge: ExternalCachePurgeRequest,
  ) -> ExternalCachePurgeReport {
    let Some(handler) = self.handlers.get(handler_name) else {
      return ExternalCachePurgeReport {
        handler: handler_name.to_string(),
        status: "not_configured",
        purged: None,
      };
    };
    let Ok(_permit) = handler.limiter.clone().try_acquire_owned() else {
      self.record(&handler.name, "purge", "saturated");
      return ExternalCachePurgeReport {
        handler: handler.name.clone(),
        status: "saturated",
        purged: None,
      };
    };
    match handler.client.purge(&purge).await {
      Ok(response) => {
        self.record(&handler.name, "purge", "ok");
        ExternalCachePurgeReport {
          handler: handler.name.clone(),
          status: "ok",
          purged: response.purged,
        }
      }
      Err(error) => {
        self.record(&handler.name, "purge", "error");
        warn!(handler = %handler.name, error = %error, "external cache purge failed");
        ExternalCachePurgeReport {
          handler: handler.name.clone(),
          status: "error",
          purged: None,
        }
      }
    }
  }

  fn record(&self, handler: &str, operation: &str, outcome: &str) {
    self
      .metrics
      .record_external_cache_operation(handler, operation, outcome);
  }
}

impl fmt::Debug for ExternalCacheRuntime {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ExternalCacheRuntime")
      .field("handlers", &self.handlers.keys().collect::<Vec<_>>())
      .finish_non_exhaustive()
  }
}

#[cfg(test)]
mod tests {
  use std::collections::HashMap;
  use std::sync::Arc;

  use super::*;
  use crate::config::{
    ExternalCacheHandlerConfig, ExternalCacheHandlerFailPolicy, ExternalCacheHandlerKind,
    MetricsConfig,
  };
  use crate::tls::TlsServerSessionStorageStats;
  use url::Url;

  fn cleanup_request() -> ExternalCacheQueryCleanupRequest {
    ExternalCacheQueryCleanupRequest::new(
      "default".to_string(),
      "https".to_string(),
      "example.test".to_string(),
      "/asset".to_string(),
      3,
      8,
    )
  }

  #[tokio::test]
  async fn query_cleanup_is_try_admitted_and_uses_fixed_saturation_metrics() {
    let metrics = Metrics::new();
    let config = ExternalCacheHandlerConfig {
      name: "cleanup-test".to_string(),
      kind: ExternalCacheHandlerKind::Http,
      endpoint: Url::parse("http://127.0.0.1:9/").unwrap(),
      token_env: None,
      connect_timeout_ms: 50,
      request_timeout_ms: 50,
      max_metadata_bytes: 1024,
      max_body_bytes: Some(1024),
      max_inflight_requests: 1,
      fail_policy: ExternalCacheHandlerFailPolicy::LocalOnly,
    };
    let handler = Arc::new(ExternalCacheHandler {
      name: config.name.clone(),
      client: ExternalCacheHttpClient::new(&config, &[], false, 1024, 1024).unwrap(),
      limiter: Arc::new(Semaphore::new(0)),
    });
    let runtime = ExternalCacheRuntime {
      handlers: Arc::new(HashMap::from([(config.name.clone(), handler)])),
      metrics: metrics.clone(),
    };

    assert!(
      runtime
        .query_cleanup(&config.name, cleanup_request())
        .await
        .is_none()
    );
    let prometheus = metrics.prometheus(
      &MetricsConfig::default(),
      crate::cache::CacheStats::default(),
      TlsServerSessionStorageStats::default(),
    );
    assert!(prometheus.contains(
      "oxibelt_external_cache_operations_total{handler=\"cleanup-test\",operation=\"query_cleanup\",outcome=\"saturated\"} 1"
    ));
  }
}

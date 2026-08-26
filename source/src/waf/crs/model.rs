//! CRS parsed rule model.
//! The model preserves source intent while exposing a smaller runtime surface.

use std::borrow::Cow;
use std::collections::HashMap;

use super::super::{HybridRegex, WafBodyInput, WafRequestInput, WafResponseInput, body_scan};
use super::actions::CrsAction;
use super::engine::{CrsEngine, CrsHitKey};
use super::operators::CrsOperator;
use super::transforms::{CrsTransform, apply_transforms};
use super::utils::{body_pairs, cookie_pairs, query_pairs, version_string};
use super::variables::CrsVariable;
use http::{HeaderMap, StatusCode, Version};

#[derive(Clone)]
pub(super) enum CrsEntry {
  Rule(Box<CrsRule>),
  Marker(String),
}

#[derive(Clone)]
pub(super) struct CrsRule {
  pub(super) id: String,
  pub(super) phase: u8,
  pub(super) variables: Vec<CrsVariable>,
  pub(super) operator: CrsOperator,
  pub(super) transforms: Vec<CrsTransform>,
  pub(super) actions: Vec<CrsAction>,
  pub(super) tags: Vec<String>,
  pub(super) msg: Option<String>,
  pub(super) skip_after: Option<String>,
  pub(super) chain: Vec<CrsRule>,
  pub(super) expects_chain: bool,
  pub(super) hit_key: Option<CrsHitKey>,
  pub(super) paranoia_level: Option<u8>,
  pub(super) requires_request_body: bool,
  pub(super) requires_response_body: bool,
}

impl CrsRule {
  pub(super) fn matches(&self, tx: &mut CrsTransaction<'_>) -> anyhow::Result<bool> {
    if !self.paranoia_enabled(tx.engine.paranoia_level) {
      return Ok(false);
    }
    if !self.variables_match(tx)? {
      return Ok(false);
    }
    for chained in &self.chain {
      if !chained.variables_match(tx)? {
        return Ok(false);
      }
    }
    Ok(true)
  }

  fn variables_match(&self, tx: &mut CrsTransaction<'_>) -> anyhow::Result<bool> {
    for variable in &self.variables {
      let matched = variable.visit_values(tx, |value, tx| {
        let transformed = apply_transforms(value.as_str(), &self.transforms);
        if self.operator.matches(transformed.as_ref(), &*tx)? {
          tx.matched_var = Some(transformed.into_owned());
          return Ok(true);
        }
        Ok(false)
      });
      match matched {
        Ok(true) => return Ok(true),
        Ok(false) => {}
        Err(error) => return Err(error),
      }
    }
    Ok(false)
  }

  pub(super) fn apply_actions(
    &self,
    tx: &mut CrsTransaction<'_>,
    contribute_to_blocking_score: bool,
  ) -> anyhow::Result<()> {
    for action in &self.actions {
      action.apply(tx, contribute_to_blocking_score)?;
    }
    for chained in &self.chain {
      for action in &chained.actions {
        action.apply(tx, contribute_to_blocking_score)?;
      }
    }
    Ok(())
  }

  fn paranoia_enabled(&self, configured: u8) -> bool {
    self
      .paranoia_level
      .map(|level| level <= configured)
      .unwrap_or(true)
  }
}

pub(super) struct CrsTransaction<'a> {
  pub(super) engine: &'a CrsEngine,
  pub(super) request: WafRequestInput<'a>,
  pub(super) response: Option<CrsResponseView<'a>>,
  pub(super) tx: HashMap<String, String>,
  pub(super) blocking_tx: HashMap<String, String>,
  pub(super) matched_var: Option<String>,
  pub(super) last_blocking_match: Option<CrsAuditRuleMatch>,
  request_cache: CrsRequestCache,
  response_cache: CrsResponseCache,
}

impl<'a> CrsTransaction<'a> {
  pub(super) fn new(engine: &'a CrsEngine, request: WafRequestInput<'a>) -> Self {
    Self {
      engine,
      request,
      response: None,
      tx: HashMap::new(),
      blocking_tx: HashMap::new(),
      matched_var: None,
      last_blocking_match: None,
      request_cache: CrsRequestCache::default(),
      response_cache: CrsResponseCache::default(),
    }
  }

  pub(super) fn request_uri(&mut self) -> String {
    if self.request_cache.uri.is_none() {
      self.request_cache.uri = Some(self.request.uri.to_string());
    }
    self.request_cache.uri.clone().unwrap_or_default()
  }

  pub(super) fn request_path(&mut self) -> String {
    if self.request_cache.path.is_none() {
      self.request_cache.path = Some(self.request.uri.path().to_string());
    }
    self.request_cache.path.clone().unwrap_or_default()
  }

  pub(super) fn request_protocol(&mut self) -> String {
    if self.request_cache.protocol.is_none() {
      self.request_cache.protocol = Some(version_string(self.request.version));
    }
    self.request_cache.protocol.clone().unwrap_or_default()
  }

  pub(super) fn request_header_names(&mut self) -> Vec<String> {
    if self.request_cache.header_names.is_none() {
      self.request_cache.header_names = Some(
        self
          .request
          .headers
          .keys()
          .map(|name| name.as_str().to_string())
          .collect(),
      );
    }
    self.request_cache.header_names.clone().unwrap_or_default()
  }

  pub(super) fn query_pairs(&mut self) -> Vec<(String, String)> {
    if self.request_cache.query_pairs.is_none() {
      self.request_cache.query_pairs = Some(query_pairs(self.request.uri));
    }
    self.request_cache.query_pairs.clone().unwrap_or_default()
  }

  pub(super) fn cookie_pairs(&mut self) -> Vec<(String, String)> {
    if self.request_cache.cookie_pairs.is_none() {
      self.request_cache.cookie_pairs = Some(cookie_pairs(self.request.headers));
    }
    self.request_cache.cookie_pairs.clone().unwrap_or_default()
  }

  pub(super) fn form_body_pairs(&mut self) -> Vec<(String, String)> {
    if self.request_cache.form_body_pairs.is_none() {
      self.request_cache.form_body_pairs =
        Some(body_pairs(self.request.headers, self.request.body));
    }
    self
      .request_cache
      .form_body_pairs
      .clone()
      .unwrap_or_default()
  }

  pub(super) fn request_body_text(&mut self) -> Option<String> {
    if self.request_cache.body_text.is_none() {
      self.request_cache.body_text = Some(
        self
          .request
          .body
          .map(|body| body_scan::body_text(body.bytes)),
      );
    }
    self.request_cache.body_text.clone().unwrap_or_default()
  }

  pub(super) fn response_protocol(&mut self) -> String {
    if self.response_cache.protocol.is_none() {
      self.response_cache.protocol = Some(
        self
          .response
          .as_ref()
          .map(|view| version_string(view.version))
          .unwrap_or_else(|| "HTTP/1.1".to_string()),
      );
    }
    self.response_cache.protocol.clone().unwrap_or_default()
  }

  pub(super) fn response_header_names(&mut self) -> Vec<String> {
    if self.response_cache.header_names.is_none() {
      self.response_cache.header_names = Some(
        self
          .response
          .as_ref()
          .map(|view| {
            view
              .headers
              .keys()
              .map(|name| name.as_str().to_string())
              .collect()
          })
          .unwrap_or_default(),
      );
    }
    self.response_cache.header_names.clone().unwrap_or_default()
  }

  pub(super) fn response_body_text(&mut self) -> Option<String> {
    if self.response_cache.body_text.is_none() {
      self.response_cache.body_text = Some(
        self
          .response
          .as_ref()
          .and_then(|view| view.body)
          .map(|body| body_scan::body_text(body.bytes)),
      );
    }
    self.response_cache.body_text.clone().unwrap_or_default()
  }

  pub(super) fn get_i64(&self, key: &str) -> i64 {
    let key = normalize_tx_key(key);
    self
      .tx
      .get(key.as_ref())
      .and_then(|value| value.parse::<i64>().ok())
      .or_else(|| self.default_tx_i64(key.as_ref()))
      .unwrap_or(0)
  }

  pub(super) fn set_value(&mut self, key: &str, value: String) {
    self.tx.insert(normalize_tx_key(key).into_owned(), value);
  }

  pub(super) fn get_blocking_i64(&self, key: &str) -> i64 {
    let key = normalize_tx_key(key);
    self
      .blocking_tx
      .get(key.as_ref())
      .and_then(|value| value.parse::<i64>().ok())
      .or_else(|| self.default_tx_i64(key.as_ref()))
      .unwrap_or(0)
  }

  pub(super) fn set_blocking_value(&mut self, key: &str, value: String) {
    self
      .blocking_tx
      .insert(normalize_tx_key(key).into_owned(), value);
  }

  pub(super) fn tx_value(&self, key: &str) -> Option<Cow<'_, str>> {
    let key = normalize_tx_key(key);
    self
      .tx
      .get(key.as_ref())
      .map(|value| Cow::Borrowed(value.as_str()))
      .or_else(|| self.default_tx_value(key.as_ref()))
  }

  pub(super) fn tx_values_matching(&self, regex: &HybridRegex) -> anyhow::Result<Vec<String>> {
    let mut values = Vec::new();
    for key in DEFAULT_TX_KEYS {
      if regex.is_match(key)?
        && !self.tx.contains_key(*key)
        && let Some(value) = self.default_tx_value(key)
      {
        values.push(value.into_owned());
      }
    }
    for (name, value) in &self.tx {
      if regex.is_match(name)? {
        values.push(value.clone());
      }
    }
    Ok(values)
  }

  pub(super) fn inbound_score(&self) -> i64 {
    let explicit = self.get_i64("inbound_anomaly_score");
    if explicit > 0 {
      return explicit;
    }
    (1..=self.engine.paranoia_level)
      .map(|level| self.get_i64(anomaly_score_key(level)))
      .sum()
  }

  pub(super) fn inbound_blocking_score(&self) -> i64 {
    let explicit = self.get_blocking_i64("inbound_anomaly_score");
    if explicit > 0 {
      return explicit;
    }
    (1..=self.engine.paranoia_level)
      .map(|level| self.get_blocking_i64(anomaly_score_key(level)))
      .sum()
  }

  pub(super) fn outbound_score(&self) -> i64 {
    let explicit = self.get_i64("outbound_anomaly_score");
    if explicit > 0 {
      return explicit;
    }
    (1..=self.engine.paranoia_level)
      .map(|level| self.get_i64(anomaly_score_key(level)))
      .sum()
  }

  pub(super) fn outbound_blocking_score(&self) -> i64 {
    let explicit = self.get_blocking_i64("outbound_anomaly_score");
    if explicit > 0 {
      return explicit;
    }
    (1..=self.engine.paranoia_level)
      .map(|level| self.get_blocking_i64(anomaly_score_key(level)))
      .sum()
  }

  fn default_tx_i64(&self, key: &str) -> Option<i64> {
    match key {
      "critical_anomaly_score" => Some(5),
      "error_anomaly_score" => Some(4),
      "warning_anomaly_score" => Some(3),
      "notice_anomaly_score" => Some(2),
      "paranoia_level" | "blocking_paranoia_level" | "detection_paranoia_level" => {
        Some(i64::from(self.engine.paranoia_level))
      }
      "inbound_anomaly_score_threshold" => Some(self.engine.inbound_threshold),
      "outbound_anomaly_score_threshold" => Some(self.engine.outbound_threshold),
      "anomaly_score"
      | "anomaly_score_pl1"
      | "anomaly_score_pl2"
      | "anomaly_score_pl3"
      | "anomaly_score_pl4"
      | "inbound_anomaly_score"
      | "outbound_anomaly_score" => Some(0),
      _ => None,
    }
  }

  fn default_tx_value(&self, key: &str) -> Option<Cow<'_, str>> {
    match key {
      "critical_anomaly_score" => Some(Cow::Borrowed("5")),
      "error_anomaly_score" => Some(Cow::Borrowed("4")),
      "warning_anomaly_score" => Some(Cow::Borrowed("3")),
      "notice_anomaly_score" => Some(Cow::Borrowed("2")),
      "paranoia_level" | "blocking_paranoia_level" | "detection_paranoia_level" => {
        Some(Cow::Owned(self.engine.paranoia_level.to_string()))
      }
      "inbound_anomaly_score_threshold" => {
        Some(Cow::Owned(self.engine.inbound_threshold.to_string()))
      }
      "outbound_anomaly_score_threshold" => {
        Some(Cow::Owned(self.engine.outbound_threshold.to_string()))
      }
      "anomaly_score"
      | "anomaly_score_pl1"
      | "anomaly_score_pl2"
      | "anomaly_score_pl3"
      | "anomaly_score_pl4"
      | "inbound_anomaly_score"
      | "outbound_anomaly_score" => Some(Cow::Borrowed("0")),
      _ => None,
    }
  }
}

const DEFAULT_TX_KEYS: &[&str] = &[
  "critical_anomaly_score",
  "error_anomaly_score",
  "warning_anomaly_score",
  "notice_anomaly_score",
  "paranoia_level",
  "blocking_paranoia_level",
  "detection_paranoia_level",
  "inbound_anomaly_score_threshold",
  "outbound_anomaly_score_threshold",
  "anomaly_score",
  "anomaly_score_pl1",
  "anomaly_score_pl2",
  "anomaly_score_pl3",
  "anomaly_score_pl4",
  "inbound_anomaly_score",
  "outbound_anomaly_score",
];

fn normalize_tx_key(key: &str) -> Cow<'_, str> {
  if key.as_bytes().iter().any(u8::is_ascii_uppercase) {
    Cow::Owned(key.to_ascii_lowercase())
  } else {
    Cow::Borrowed(key)
  }
}

fn anomaly_score_key(level: u8) -> &'static str {
  match level {
    1 => "anomaly_score_pl1",
    2 => "anomaly_score_pl2",
    3 => "anomaly_score_pl3",
    4 => "anomaly_score_pl4",
    _ => "anomaly_score",
  }
}

#[derive(Default)]
struct CrsRequestCache {
  uri: Option<String>,
  path: Option<String>,
  protocol: Option<String>,
  header_names: Option<Vec<String>>,
  query_pairs: Option<Vec<(String, String)>>,
  cookie_pairs: Option<Vec<(String, String)>>,
  form_body_pairs: Option<Vec<(String, String)>>,
  body_text: Option<Option<String>>,
}

#[derive(Default)]
struct CrsResponseCache {
  protocol: Option<String>,
  header_names: Option<Vec<String>>,
  body_text: Option<Option<String>>,
}

#[derive(Debug, Clone)]
pub(super) struct CrsAuditRuleMatch {
  pub(super) id: String,
  pub(super) msg: Option<String>,
  pub(super) mode: String,
  pub(super) tuning_name: Option<String>,
}

pub(super) struct CrsResponseView<'a> {
  pub(super) status: StatusCode,
  pub(super) headers: &'a HeaderMap,
  pub(super) body: Option<WafBodyInput<'a>>,
  pub(super) version: Version,
}

impl<'a> CrsResponseView<'a> {
  pub(super) fn from_input(input: WafResponseInput<'a>) -> Self {
    Self {
      status: input.status,
      headers: input.headers,
      body: input.body,
      version: input.version,
    }
  }
}

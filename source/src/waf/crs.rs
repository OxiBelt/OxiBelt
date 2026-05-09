use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, anyhow, bail};
use http::{HeaderMap, StatusCode, Uri, Version};
use regex::Regex;
use serde::Deserialize;
use tracing::warn;

use crate::config::{
  canonicalize_existing_file, resolve_existing_local_config_file_path_with_logical,
  resolve_local_config_file_path,
};

use super::body_scan;
use super::normalization::{normalize_path, normalize_text};
use super::{
  WafBodyInput, WafMode, WafRequestInput, WafResponseInput, WafRuleHitSnapshot, WafTerminalResponse,
};

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct WafCrsConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_crs_mode")]
  pub mode: WafMode,
  #[serde(default = "default_setup_file")]
  pub setup_file: PathBuf,
  #[serde(default = "default_rule_files")]
  pub rule_files: Vec<PathBuf>,
  #[serde(default = "default_paranoia_level")]
  pub paranoia_level: u8,
  #[serde(default = "default_inbound_threshold")]
  pub inbound_anomaly_score_threshold: i64,
  #[serde(default = "default_outbound_threshold")]
  pub outbound_anomaly_score_threshold: i64,
  #[serde(default)]
  pub unsupported_directive_policy: WafCrsUnsupportedDirectivePolicy,
  #[serde(skip)]
  setup_file_resolved: Option<PathBuf>,
  #[serde(skip)]
  setup_file_logical: Option<PathBuf>,
  #[serde(skip)]
  rule_files_resolved: Vec<PathBuf>,
  #[serde(skip)]
  rule_files_logical: Vec<PathBuf>,
}

impl Default for WafCrsConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      mode: WafMode::Monitor,
      setup_file: default_setup_file(),
      rule_files: default_rule_files(),
      paranoia_level: default_paranoia_level(),
      inbound_anomaly_score_threshold: default_inbound_threshold(),
      outbound_anomaly_score_threshold: default_outbound_threshold(),
      unsupported_directive_policy: WafCrsUnsupportedDirectivePolicy::FailClosed,
      setup_file_resolved: None,
      setup_file_logical: None,
      rule_files_resolved: Vec::new(),
      rule_files_logical: Vec::new(),
    }
  }
}

impl WafCrsConfig {
  pub(crate) fn resolve_relative_paths(&mut self, base_dir: &Path) -> anyhow::Result<()> {
    self.setup_file_resolved = None;
    self.setup_file_logical = None;
    self.rule_files_resolved.clear();
    self.rule_files_logical.clear();
    if !self.enabled {
      return Ok(());
    }

    let (setup, setup_logical) = resolve_existing_local_config_file_path_with_logical(
      "waf.crs.setup_file",
      base_dir,
      &self.setup_file,
    )?;
    self.setup_file_resolved = Some(setup);
    self.setup_file_logical = Some(setup_logical);

    let canonical_base = base_dir.canonicalize().with_context(|| {
      format!(
        "failed to resolve CRS base directory {}",
        base_dir.display()
      )
    })?;
    for pattern in &self.rule_files {
      let logical_pattern =
        resolve_local_config_file_path("waf.crs.rule_files", base_dir, pattern)?;
      let pattern_text = logical_pattern.to_str().ok_or_else(|| {
        anyhow!(
          "waf.crs.rule_files entry is not valid UTF-8: {}",
          logical_pattern.display()
        )
      })?;
      let mut matched = Vec::new();
      for path in glob::glob(pattern_text)
        .with_context(|| format!("invalid waf.crs.rule_files glob {}", pattern.display()))?
      {
        let path = path.with_context(|| {
          format!(
            "failed to expand waf.crs.rule_files glob {}",
            pattern.display()
          )
        })?;
        if path.is_file() {
          let canonical = canonicalize_existing_file("waf.crs.rule_files", &path)?;
          if !canonical.starts_with(&canonical_base) {
            bail!("waf.crs.rule_files entries must stay within the OxiRule directory");
          }
          matched.push((canonical, path));
        }
      }
      matched.sort_by(|left, right| left.0.cmp(&right.0));
      if matched.is_empty() {
        bail!(
          "waf.crs.rule_files entry matched no files: {}",
          pattern.display()
        );
      }
      for (canonical, logical) in matched {
        self.rule_files_resolved.push(canonical);
        self.rule_files_logical.push(logical);
      }
    }
    Ok(())
  }

  pub(crate) fn loaded_paths(&self) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(path) = &self.setup_file_logical {
      paths.push(path.clone());
    }
    paths.extend(self.rule_files_logical.iter().cloned());
    paths
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WafCrsUnsupportedDirectivePolicy {
  #[default]
  FailClosed,
}

#[derive(Clone)]
pub(crate) struct CrsEngine {
  enabled: bool,
  mode: WafMode,
  paranoia_level: u8,
  inbound_threshold: i64,
  outbound_threshold: i64,
  rules: Vec<CrsEntry>,
  counters: HashMap<CrsHitKey, Arc<AtomicU64>>,
  latest_scores: Arc<std::sync::Mutex<CrsLatestScores>>,
}

impl Default for CrsEngine {
  fn default() -> Self {
    Self {
      enabled: false,
      mode: WafMode::Monitor,
      paranoia_level: 1,
      inbound_threshold: 5,
      outbound_threshold: 4,
      rules: Vec::new(),
      counters: HashMap::new(),
      latest_scores: Arc::new(std::sync::Mutex::new(CrsLatestScores::default())),
    }
  }
}

impl CrsEngine {
  pub(crate) fn compile(
    config: &WafCrsConfig,
    previous_counters: &HashMap<CrsHitKey, Arc<AtomicU64>>,
  ) -> anyhow::Result<Self> {
    if !config.enabled {
      return Ok(Self::default());
    }
    validate_config(config)?;
    let mut parser = CrsParser::new();
    if let Some(path) = &config.setup_file_resolved {
      parser.load_file(path)?;
    }
    for path in &config.rule_files_resolved {
      parser.load_file(path)?;
    }
    let mut rules = parser.entries;
    let mut counters = HashMap::new();
    for entry in &mut rules {
      if let CrsEntry::Rule(rule) = entry {
        let key = CrsHitKey {
          phase: rule.phase,
          id: rule.id.clone(),
          name: rule.msg.clone(),
          mode: config.mode,
        };
        let counter = previous_counters.get(&key).cloned().unwrap_or_default();
        rule.hit_key = Some(key.clone());
        counters.insert(key, counter);
      }
    }
    Ok(Self {
      enabled: true,
      mode: config.mode,
      paranoia_level: config.paranoia_level,
      inbound_threshold: config.inbound_anomaly_score_threshold,
      outbound_threshold: config.outbound_anomaly_score_threshold,
      rules,
      counters,
      latest_scores: Arc::new(std::sync::Mutex::new(CrsLatestScores::default())),
    })
  }

  pub(crate) fn enabled(&self) -> bool {
    self.enabled
  }

  pub(crate) fn active_hit_counters(&self) -> HashMap<CrsHitKey, Arc<AtomicU64>> {
    self.counters.clone()
  }

  pub(crate) fn requires_request_body_inspection(&self) -> bool {
    self.enabled
      && self.rules.iter().any(|entry| match entry {
        CrsEntry::Rule(rule) => {
          matches!(rule.phase, 2)
            && rule
              .variables
              .iter()
              .any(CrsVariable::requires_request_body)
        }
        CrsEntry::Marker(_) => false,
      })
  }

  pub(crate) fn requires_response_body_inspection(&self) -> bool {
    self.enabled
      && self.rules.iter().any(|entry| match entry {
        CrsEntry::Rule(rule) => {
          matches!(rule.phase, 4)
            && rule
              .variables
              .iter()
              .any(CrsVariable::requires_response_body)
        }
        CrsEntry::Marker(_) => false,
      })
  }

  pub(crate) fn rule_hit_snapshots(&self) -> Vec<WafRuleHitSnapshot> {
    let scores = self
      .latest_scores
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .clone();
    let mut snapshots = self
      .counters
      .iter()
      .map(|(key, counter)| WafRuleHitSnapshot {
        scope: "crs".to_string(),
        route: None,
        phase: crs_phase_name(key.phase).to_string(),
        name: key
          .name
          .clone()
          .unwrap_or_else(|| format!("crs-rule-{}", key.id)),
        id: Some(key.id.clone()),
        effective_mode: key.mode.as_str().to_string(),
        hits: counter.load(Ordering::Relaxed),
        latest_inbound_anomaly_score: Some(scores.inbound),
        latest_outbound_anomaly_score: Some(scores.outbound),
      })
      .collect::<Vec<_>>();
    snapshots.sort_by(|left, right| {
      left
        .phase
        .cmp(&right.phase)
        .then_with(|| left.id.cmp(&right.id))
        .then_with(|| left.name.cmp(&right.name))
    });
    snapshots
  }

  pub(crate) fn evaluate_request(&self, input: WafRequestInput<'_>) -> anyhow::Result<CrsDecision> {
    if !self.enabled {
      return Ok(CrsDecision::default());
    }
    let mut tx = CrsTransaction::new(self, input);
    self.evaluate_phase(&mut tx, 1, None)?;
    self.evaluate_phase(&mut tx, 2, None)?;
    let score = tx.inbound_score();
    self.remember_scores(score, 0);
    if self.mode == WafMode::Enforcing && score >= self.inbound_threshold {
      return Ok(CrsDecision {
        terminal: Some(WafTerminalResponse::new(
          StatusCode::FORBIDDEN,
          "Blocked by CRS".to_string(),
        )),
      });
    }
    Ok(CrsDecision::default())
  }

  pub(crate) fn evaluate_response(
    &self,
    input: WafResponseInput<'_>,
  ) -> anyhow::Result<CrsDecision> {
    if !self.enabled {
      return Ok(CrsDecision::default());
    }
    let mut tx = CrsTransaction::new(self, input.request);
    tx.response = Some(CrsResponseView::from_input(input));
    self.evaluate_phase(&mut tx, 3, Some(input))?;
    self.evaluate_phase(&mut tx, 4, Some(input))?;
    let outbound = tx.outbound_score();
    self.remember_scores(0, outbound);
    if self.mode == WafMode::Enforcing && outbound >= self.outbound_threshold {
      return Ok(CrsDecision {
        terminal: Some(WafTerminalResponse::new(
          StatusCode::BAD_GATEWAY,
          "Blocked by CRS".to_string(),
        )),
      });
    }
    Ok(CrsDecision::default())
  }

  fn remember_scores(&self, inbound: i64, outbound: i64) {
    let mut scores = self
      .latest_scores
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    if inbound > 0 {
      scores.inbound = inbound;
    }
    if outbound > 0 {
      scores.outbound = outbound;
    }
  }

  fn evaluate_phase(
    &self,
    tx: &mut CrsTransaction<'_>,
    phase: u8,
    response: Option<WafResponseInput<'_>>,
  ) -> anyhow::Result<()> {
    let mut index = 0usize;
    while index < self.rules.len() {
      match &self.rules[index] {
        CrsEntry::Marker(_) => {
          index += 1;
        }
        CrsEntry::Rule(rule) if rule.phase != phase => {
          index += 1;
        }
        CrsEntry::Rule(rule) => {
          let matched = rule.matches(tx, response)?;
          if matched {
            self.record_hit(rule);
            rule.apply_actions(tx)?;
            if let Some(marker) = &rule.skip_after {
              index = self
                .rules
                .iter()
                .position(|entry| matches!(entry, CrsEntry::Marker(name) if name == marker))
                .map(|position| position + 1)
                .unwrap_or(index + 1);
              continue;
            }
          }
          index += 1;
        }
      }
    }
    Ok(())
  }

  fn record_hit(&self, rule: &CrsRule) {
    let Some(key) = &rule.hit_key else {
      return;
    };
    if let Some(counter) = self.counters.get(key) {
      counter.fetch_add(1, Ordering::Relaxed);
    }
  }
}

#[derive(Debug, Default)]
pub(crate) struct CrsDecision {
  pub(crate) terminal: Option<WafTerminalResponse>,
}

#[derive(Debug, Clone, Default)]
struct CrsLatestScores {
  inbound: i64,
  outbound: i64,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub(crate) struct CrsHitKey {
  phase: u8,
  id: String,
  name: Option<String>,
  mode: WafMode,
}

#[derive(Clone)]
enum CrsEntry {
  Rule(Box<CrsRule>),
  Marker(String),
}

#[derive(Clone)]
struct CrsRule {
  id: String,
  phase: u8,
  variables: Vec<CrsVariable>,
  operator: CrsOperator,
  transforms: Vec<CrsTransform>,
  actions: Vec<CrsAction>,
  tags: Vec<String>,
  msg: Option<String>,
  skip_after: Option<String>,
  chain: Vec<CrsRule>,
  expects_chain: bool,
  hit_key: Option<CrsHitKey>,
}

impl CrsRule {
  fn matches(
    &self,
    tx: &mut CrsTransaction<'_>,
    response: Option<WafResponseInput<'_>>,
  ) -> anyhow::Result<bool> {
    if !self.paranoia_enabled(tx.engine.paranoia_level) {
      return Ok(false);
    }
    if !self.variables_match(tx, response)? {
      return Ok(false);
    }
    for chained in &self.chain {
      if !chained.variables_match(tx, response)? {
        return Ok(false);
      }
    }
    Ok(true)
  }

  fn variables_match(
    &self,
    tx: &mut CrsTransaction<'_>,
    response: Option<WafResponseInput<'_>>,
  ) -> anyhow::Result<bool> {
    let values = self
      .variables
      .iter()
      .flat_map(|variable| {
        variable.values(tx, response).unwrap_or_else(|error| {
          warn!(error = %error, "failed to resolve CRS variable");
          Vec::new()
        })
      })
      .collect::<Vec<_>>();
    for value in values {
      let transformed = apply_transforms(value.as_str(), &self.transforms);
      if self.operator.matches(&transformed, tx)? {
        tx.matched_var = Some(transformed);
        return Ok(true);
      }
    }
    Ok(false)
  }

  fn apply_actions(&self, tx: &mut CrsTransaction<'_>) -> anyhow::Result<()> {
    for action in &self.actions {
      action.apply(tx)?;
    }
    for chained in &self.chain {
      for action in &chained.actions {
        action.apply(tx)?;
      }
    }
    Ok(())
  }

  fn paranoia_enabled(&self, configured: u8) -> bool {
    self
      .tags
      .iter()
      .filter_map(|tag| tag.strip_prefix("paranoia-level/"))
      .filter_map(|level| level.parse::<u8>().ok())
      .next()
      .map(|level| level <= configured)
      .unwrap_or(true)
  }
}

struct CrsTransaction<'a> {
  engine: &'a CrsEngine,
  request: WafRequestInput<'a>,
  response: Option<CrsResponseView<'a>>,
  tx: HashMap<String, String>,
  matched_var: Option<String>,
}

impl<'a> CrsTransaction<'a> {
  fn new(engine: &'a CrsEngine, request: WafRequestInput<'a>) -> Self {
    let mut tx = HashMap::new();
    tx.insert("critical_anomaly_score".to_string(), "5".to_string());
    tx.insert("error_anomaly_score".to_string(), "4".to_string());
    tx.insert("warning_anomaly_score".to_string(), "3".to_string());
    tx.insert("notice_anomaly_score".to_string(), "2".to_string());
    tx.insert(
      "paranoia_level".to_string(),
      engine.paranoia_level.to_string(),
    );
    tx.insert(
      "blocking_paranoia_level".to_string(),
      engine.paranoia_level.to_string(),
    );
    tx.insert(
      "detection_paranoia_level".to_string(),
      engine.paranoia_level.to_string(),
    );
    tx.insert(
      "inbound_anomaly_score_threshold".to_string(),
      engine.inbound_threshold.to_string(),
    );
    tx.insert(
      "outbound_anomaly_score_threshold".to_string(),
      engine.outbound_threshold.to_string(),
    );
    for key in [
      "anomaly_score",
      "anomaly_score_pl1",
      "anomaly_score_pl2",
      "anomaly_score_pl3",
      "anomaly_score_pl4",
      "inbound_anomaly_score",
      "outbound_anomaly_score",
    ] {
      tx.insert(key.to_string(), "0".to_string());
    }
    Self {
      engine,
      request,
      response: None,
      tx,
      matched_var: None,
    }
  }

  fn get_i64(&self, key: &str) -> i64 {
    self
      .tx
      .get(&key.to_ascii_lowercase())
      .and_then(|value| value.parse::<i64>().ok())
      .unwrap_or(0)
  }

  fn set_value(&mut self, key: &str, value: String) {
    self.tx.insert(key.to_ascii_lowercase(), value);
  }

  fn inbound_score(&self) -> i64 {
    let explicit = self.get_i64("inbound_anomaly_score");
    if explicit > 0 {
      return explicit;
    }
    (1..=self.engine.paranoia_level)
      .map(|level| self.get_i64(&format!("anomaly_score_pl{level}")))
      .sum()
  }

  fn outbound_score(&self) -> i64 {
    let explicit = self.get_i64("outbound_anomaly_score");
    if explicit > 0 {
      return explicit;
    }
    (1..=self.engine.paranoia_level)
      .map(|level| self.get_i64(&format!("anomaly_score_pl{level}")))
      .sum()
  }
}

struct CrsResponseView<'a> {
  status: StatusCode,
  headers: &'a HeaderMap,
  body: Option<WafBodyInput<'a>>,
  version: Version,
}

impl<'a> CrsResponseView<'a> {
  fn from_input(input: WafResponseInput<'a>) -> Self {
    Self {
      status: input.status,
      headers: input.headers,
      body: input.body,
      version: input.version,
    }
  }
}

#[derive(Clone)]
enum CrsVariable {
  RequestUri,
  RequestUriRaw,
  RequestFilename,
  RequestBasename,
  RequestMethod,
  RequestProtocol,
  RequestHeaders(Option<String>),
  RequestHeadersNames,
  Args,
  ArgsGet,
  RequestCookies(Option<String>),
  RequestBody,
  ResponseStatus,
  ResponseProtocol,
  ResponseHeaders(Option<String>),
  ResponseHeadersNames,
  ResponseBody,
  Tx(String),
  TxRegex(Regex),
  MatchedVar,
}

impl CrsVariable {
  fn parse(raw: &str) -> anyhow::Result<Self> {
    let (name, selector) = raw
      .split_once(':')
      .map(|(name, selector)| (name.trim(), Some(selector.trim())))
      .unwrap_or((raw.trim(), None));
    let upper = name.to_ascii_uppercase();
    match upper.as_str() {
      "REQUEST_URI" => Ok(Self::RequestUri),
      "REQUEST_URI_RAW" => Ok(Self::RequestUriRaw),
      "REQUEST_FILENAME" => Ok(Self::RequestFilename),
      "REQUEST_BASENAME" => Ok(Self::RequestBasename),
      "REQUEST_METHOD" => Ok(Self::RequestMethod),
      "REQUEST_PROTOCOL" => Ok(Self::RequestProtocol),
      "REQUEST_HEADERS" => Ok(Self::RequestHeaders(selector.map(unquote_selector))),
      "REQUEST_HEADERS_NAMES" => Ok(Self::RequestHeadersNames),
      "ARGS" => Ok(Self::Args),
      "ARGS_GET" | "QUERY_STRING" => Ok(Self::ArgsGet),
      "REQUEST_COOKIES" => Ok(Self::RequestCookies(selector.map(unquote_selector))),
      "REQUEST_BODY" => Ok(Self::RequestBody),
      "RESPONSE_STATUS" => Ok(Self::ResponseStatus),
      "RESPONSE_PROTOCOL" => Ok(Self::ResponseProtocol),
      "RESPONSE_HEADERS" => Ok(Self::ResponseHeaders(selector.map(unquote_selector))),
      "RESPONSE_HEADERS_NAMES" => Ok(Self::ResponseHeadersNames),
      "RESPONSE_BODY" => Ok(Self::ResponseBody),
      "MATCHED_VAR" => Ok(Self::MatchedVar),
      "TX" => {
        let Some(selector) = selector else {
          bail!("TX variable requires a selector")
        };
        if selector.starts_with('/') && selector.ends_with('/') && selector.len() > 2 {
          Ok(Self::TxRegex(Regex::new(&selector[1..selector.len() - 1])?))
        } else {
          Ok(Self::Tx(unquote_selector(selector).to_ascii_lowercase()))
        }
      }
      _ => bail!("unsupported CRS variable {raw}"),
    }
  }

  fn requires_request_body(&self) -> bool {
    matches!(self, Self::Args | Self::RequestBody)
  }

  fn requires_response_body(&self) -> bool {
    matches!(self, Self::ResponseBody)
  }

  fn values(
    &self,
    tx: &CrsTransaction<'_>,
    response: Option<WafResponseInput<'_>>,
  ) -> anyhow::Result<Vec<String>> {
    match self {
      Self::RequestUri | Self::RequestUriRaw => Ok(vec![tx.request.uri.to_string()]),
      Self::RequestFilename => Ok(vec![tx.request.uri.path().to_string()]),
      Self::RequestBasename => Ok(
        tx.request
          .uri
          .path()
          .rsplit('/')
          .next()
          .map(|value| vec![value.to_string()])
          .unwrap_or_default(),
      ),
      Self::RequestMethod => Ok(vec![tx.request.method.as_str().to_string()]),
      Self::RequestProtocol => Ok(vec![version_string(tx.request.version)]),
      Self::RequestHeaders(selector) => Ok(header_values(tx.request.headers, selector.as_deref())),
      Self::RequestHeadersNames => Ok(
        tx.request
          .headers
          .keys()
          .map(|name| name.as_str().to_string())
          .collect(),
      ),
      Self::Args => {
        let mut pairs = query_pairs(tx.request.uri);
        pairs.extend(body_pairs(tx.request.headers, tx.request.body));
        Ok(pairs.into_iter().map(|(_, value)| value).collect())
      }
      Self::ArgsGet => Ok(
        query_pairs(tx.request.uri)
          .into_iter()
          .map(|(_, value)| value)
          .collect(),
      ),
      Self::RequestCookies(selector) => {
        let pairs = cookie_pairs(tx.request.headers);
        Ok(select_pairs(pairs, selector.as_deref()))
      }
      Self::RequestBody => Ok(
        tx.request
          .body
          .map(|body| vec![body_scan::body_text(body.bytes)])
          .unwrap_or_default(),
      ),
      Self::ResponseStatus => Ok(vec![
        response
          .map(|input| input.status.as_u16().to_string())
          .or_else(|| {
            tx.response
              .as_ref()
              .map(|view| view.status.as_u16().to_string())
          })
          .unwrap_or_default(),
      ]),
      Self::ResponseProtocol => Ok(vec![
        tx.response
          .as_ref()
          .map(|view| version_string(view.version))
          .unwrap_or_else(|| "HTTP/1.1".to_string()),
      ]),
      Self::ResponseHeaders(selector) => {
        let headers = response
          .map(|input| input.headers)
          .or_else(|| tx.response.as_ref().map(|view| view.headers));
        Ok(
          headers
            .map(|headers| header_values(headers, selector.as_deref()))
            .unwrap_or_default(),
        )
      }
      Self::ResponseHeadersNames => Ok(
        tx.response
          .as_ref()
          .map(|view| {
            view
              .headers
              .keys()
              .map(|name| name.as_str().to_string())
              .collect()
          })
          .unwrap_or_default(),
      ),
      Self::ResponseBody => Ok(
        tx.response
          .as_ref()
          .and_then(|view| view.body)
          .map(|body| vec![body_scan::body_text(body.bytes)])
          .unwrap_or_default(),
      ),
      Self::Tx(name) => Ok(tx.tx.get(name).cloned().into_iter().collect()),
      Self::TxRegex(regex) => Ok(
        tx.tx
          .iter()
          .filter(|(name, _)| regex.is_match(name))
          .map(|(_, value)| value.clone())
          .collect(),
      ),
      Self::MatchedVar => Ok(tx.matched_var.clone().into_iter().collect()),
    }
  }
}

#[derive(Clone)]
enum CrsOperator {
  Regex(Regex),
  Contains(String),
  ContainsWord(String),
  BeginsWith(String),
  EndsWith(String),
  Streq(String),
  Pm(Vec<String>),
  Eq(i64),
  Ge(i64),
  Gt(i64),
  Le(i64),
  Lt(i64),
  DetectSqli,
  DetectXss,
  UnconditionalMatch,
  ValidateUrlEncoding,
  ValidateUtf8Encoding,
  Negated(Box<CrsOperator>),
}

impl CrsOperator {
  fn parse(raw: &str) -> anyhow::Result<Self> {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix('!') {
      return Ok(Self::Negated(Box::new(Self::parse(rest)?)));
    }
    if let Some(rest) = raw.strip_prefix('@') {
      let (name, arg) = rest
        .split_once(char::is_whitespace)
        .map(|(name, arg)| (name, arg.trim()))
        .unwrap_or((rest, ""));
      return match name {
        "rx" => Ok(Self::Regex(Regex::new(arg)?)),
        "contains" => Ok(Self::Contains(arg.to_string())),
        "containsWord" => Ok(Self::ContainsWord(arg.to_string())),
        "beginsWith" => Ok(Self::BeginsWith(arg.to_string())),
        "endsWith" => Ok(Self::EndsWith(arg.to_string())),
        "streq" => Ok(Self::Streq(arg.to_string())),
        "pm" => Ok(Self::Pm(split_phrases(arg))),
        "eq" => Ok(Self::Eq(arg.parse()?)),
        "ge" => Ok(Self::Ge(arg.parse()?)),
        "gt" => Ok(Self::Gt(arg.parse()?)),
        "le" => Ok(Self::Le(arg.parse()?)),
        "lt" => Ok(Self::Lt(arg.parse()?)),
        "detectSQLi" => Ok(Self::DetectSqli),
        "detectXSS" => Ok(Self::DetectXss),
        "unconditionalMatch" => Ok(Self::UnconditionalMatch),
        "validateUrlEncoding" => Ok(Self::ValidateUrlEncoding),
        "validateUtf8Encoding" => Ok(Self::ValidateUtf8Encoding),
        _ => bail!("unsupported CRS operator @{name}"),
      };
    }
    Ok(Self::Regex(Regex::new(raw)?))
  }

  fn matches(&self, value: &str, tx: &CrsTransaction<'_>) -> anyhow::Result<bool> {
    let result = match self {
      Self::Regex(regex) => regex.is_match(value),
      Self::Contains(needle) => value.contains(&expand_macros(needle, tx)),
      Self::ContainsWord(needle) => {
        let needle = expand_macros(needle, tx);
        Regex::new(&format!(r"(?i)\b{}\b", regex::escape(&needle)))?.is_match(value)
      }
      Self::BeginsWith(needle) => value.starts_with(&expand_macros(needle, tx)),
      Self::EndsWith(needle) => value.ends_with(&expand_macros(needle, tx)),
      Self::Streq(expected) => value == expand_macros(expected, tx),
      Self::Pm(phrases) => phrases
        .iter()
        .map(|phrase| expand_macros(phrase, tx))
        .any(|phrase| value.contains(&phrase)),
      Self::Eq(expected) => value.parse::<i64>().unwrap_or(0) == *expected,
      Self::Ge(expected) => value.parse::<i64>().unwrap_or(0) >= *expected,
      Self::Gt(expected) => value.parse::<i64>().unwrap_or(0) > *expected,
      Self::Le(expected) => value.parse::<i64>().unwrap_or(0) <= *expected,
      Self::Lt(expected) => value.parse::<i64>().unwrap_or(0) < *expected,
      Self::DetectSqli => Regex::new(
        "(?i)(union\\s+select|sleep\\s*\\(|information_schema|or\\s+1\\s*=\\s*1|drop\\s+table)",
      )?
      .is_match(value),
      Self::DetectXss => {
        Regex::new("(?i)(<\\s*script|javascript:|onerror\\s*=|onload\\s*=)")?.is_match(value)
      }
      Self::UnconditionalMatch => true,
      Self::ValidateUrlEncoding => !invalid_url_encoding(value),
      Self::ValidateUtf8Encoding => std::str::from_utf8(value.as_bytes()).is_ok(),
      Self::Negated(inner) => !inner.matches(value, tx)?,
    };
    Ok(result)
  }
}

#[derive(Clone)]
enum CrsTransform {
  Lowercase,
  UrlDecode,
  NormalizePath,
  RemoveNulls,
  CompressWhitespace,
  RemoveWhitespace,
  Trim,
  HtmlEntityDecode,
}

impl CrsTransform {
  fn parse(raw: &str) -> anyhow::Result<Option<Self>> {
    match raw {
      "none" => Ok(None),
      "lowercase" => Ok(Some(Self::Lowercase)),
      "urlDecode" | "urlDecodeUni" => Ok(Some(Self::UrlDecode)),
      "normalizePath" | "normalizePathWin" => Ok(Some(Self::NormalizePath)),
      "removeNulls" | "replaceNulls" => Ok(Some(Self::RemoveNulls)),
      "compressWhitespace" => Ok(Some(Self::CompressWhitespace)),
      "removeWhitespace" => Ok(Some(Self::RemoveWhitespace)),
      "trim" | "trimLeft" | "trimRight" => Ok(Some(Self::Trim)),
      "htmlEntityDecode" | "jsDecode" | "cssDecode" | "cmdLine" | "utf8toUnicode" => {
        Ok(Some(Self::HtmlEntityDecode))
      }
      _ => bail!("unsupported CRS transform t:{raw}"),
    }
  }
}

#[derive(Clone)]
enum CrsAction {
  SetVar {
    name: String,
    operation: SetVarOperation,
  },
}

impl CrsAction {
  fn apply(&self, tx: &mut CrsTransaction<'_>) -> anyhow::Result<()> {
    match self {
      Self::SetVar { name, operation } => {
        let current = tx.get_i64(name);
        match operation {
          SetVarOperation::Assign(raw) => {
            let expanded = expand_macros(raw, tx);
            tx.set_value(name, expanded);
          }
          SetVarOperation::Add(raw) => {
            let value = expand_macros(raw, tx).parse::<i64>().unwrap_or(0);
            tx.set_value(name, current.saturating_add(value).to_string());
          }
          SetVarOperation::Subtract(raw) => {
            let value = expand_macros(raw, tx).parse::<i64>().unwrap_or(0);
            tx.set_value(name, current.saturating_sub(value).to_string());
          }
        }
      }
    }
    Ok(())
  }
}

#[derive(Clone)]
enum SetVarOperation {
  Assign(String),
  Add(String),
  Subtract(String),
}

struct CrsParser {
  entries: Vec<CrsEntry>,
}

impl CrsParser {
  fn new() -> Self {
    Self {
      entries: Vec::new(),
    }
  }

  fn load_file(&mut self, path: &Path) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(path)
      .with_context(|| format!("failed to read CRS file {}", path.display()))?;
    for (line_number, directive) in logical_lines(&raw).into_iter().enumerate() {
      let directive = strip_comment(&directive);
      if directive.trim().is_empty() {
        continue;
      }
      self
        .parse_directive(&directive)
        .with_context(|| format!("failed to parse CRS {}:{}", path.display(), line_number + 1))?;
    }
    Ok(())
  }

  fn parse_directive(&mut self, raw: &str) -> anyhow::Result<()> {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix("SecMarker") {
      self
        .entries
        .push(CrsEntry::Marker(unquote(rest.trim()).to_string()));
      return Ok(());
    }
    if let Some(rest) = raw.strip_prefix("SecAction") {
      let actions = parse_quoted_sections(rest)?;
      let actions = actions
        .first()
        .ok_or_else(|| anyhow!("SecAction requires an action list"))?;
      let mut rule = CrsRule::from_parts(Vec::new(), CrsOperator::UnconditionalMatch, actions)?;
      rule.variables = vec![CrsVariable::RequestUri];
      self.entries.push(CrsEntry::Rule(Box::new(rule)));
      return Ok(());
    }
    if let Some(rest) = raw.strip_prefix("SecRule") {
      let mut sections = parse_quoted_sections(rest)?;
      if sections.len() < 2 {
        bail!("SecRule requires variables and operator");
      }
      let variables = sections.remove(0);
      let operator = sections.remove(0);
      let actions = sections.first().cloned().unwrap_or_default();
      let rule = CrsRule::from_parts(
        variables
          .split('|')
          .map(CrsVariable::parse)
          .collect::<anyhow::Result<Vec<_>>>()?,
        CrsOperator::parse(&operator)?,
        &actions,
      )?;
      if let Some(CrsEntry::Rule(previous)) = self.entries.last_mut()
        && previous.expects_chain
      {
        previous.chain.push(rule);
        previous.expects_chain = previous
          .chain
          .last()
          .map(|rule| rule.expects_chain)
          .unwrap_or(false);
        return Ok(());
      }
      self.entries.push(CrsEntry::Rule(Box::new(rule)));
      return Ok(());
    }
    if raw.starts_with("SecRuleUpdate")
      || raw.starts_with("SecRuleRemove")
      || raw.starts_with("SecDefaultAction")
      || raw.starts_with("SecComponentSignature")
    {
      return Ok(());
    }
    bail!("unsupported CRS directive {raw}");
  }
}

impl CrsRule {
  fn from_parts(
    variables: Vec<CrsVariable>,
    operator: CrsOperator,
    actions_raw: &str,
  ) -> anyhow::Result<Self> {
    let tokens = split_actions(actions_raw);
    let mut id = String::new();
    let mut phase = 2u8;
    let mut actions = Vec::new();
    let mut transforms = Vec::new();
    let mut tags = Vec::new();
    let mut msg = None;
    let mut skip_after = None;
    let mut chain = false;
    for token in tokens {
      if let Some((key, value)) = token.split_once(':') {
        match key {
          "id" => id = unquote(value).to_string(),
          "phase" => phase = unquote(value).parse::<u8>()?,
          "msg" => msg = Some(unquote(value).to_string()),
          "tag" => tags.push(unquote(value).to_string()),
          "skipAfter" => skip_after = Some(unquote(value).to_string()),
          "setvar" => {
            if let Some(action) = parse_setvar(unquote(value))? {
              actions.push(action);
            }
          }
          "t" => {
            let transform = unquote(value);
            if transform == "none" {
              transforms.clear();
            } else if let Some(transform) = CrsTransform::parse(transform)? {
              transforms.push(transform);
            }
          }
          "severity" | "ver" | "rev" | "status" | "logdata" | "accuracy" | "maturity" | "ctl"
          | "expirevar" | "initcol" | "setuid" | "sanitiseArg" => {}
          _ => bail!("unsupported CRS action {key}"),
        }
      } else {
        match token.as_str() {
          "chain" => chain = true,
          "pass" | "deny" | "block" | "log" | "nolog" | "auditlog" | "noauditlog" | "capture"
          | "multiMatch" | "append" | "prepend" => {}
          "" => {}
          _ => bail!("unsupported CRS action {token}"),
        }
      }
    }
    if id.is_empty() {
      id = format!("generated-{}", crate::waf::new_access_log_id());
    }
    Ok(Self {
      id,
      phase,
      variables,
      operator,
      transforms,
      actions,
      tags,
      msg,
      skip_after,
      chain: Vec::new(),
      expects_chain: chain,
      hit_key: None,
    })
  }
}

fn validate_config(config: &WafCrsConfig) -> anyhow::Result<()> {
  if !(1..=4).contains(&config.paranoia_level) {
    bail!("waf.crs.paranoia_level must be between 1 and 4");
  }
  if config.inbound_anomaly_score_threshold <= 0 {
    bail!("waf.crs.inbound_anomaly_score_threshold must be greater than 0");
  }
  if config.outbound_anomaly_score_threshold <= 0 {
    bail!("waf.crs.outbound_anomaly_score_threshold must be greater than 0");
  }
  if config.rule_files.is_empty() {
    bail!("waf.crs.rule_files must include at least one entry when CRS is enabled");
  }
  Ok(())
}

fn default_setup_file() -> PathBuf {
  PathBuf::from("crs/crs-setup.conf")
}

fn default_crs_mode() -> WafMode {
  WafMode::Monitor
}

fn default_rule_files() -> Vec<PathBuf> {
  vec![PathBuf::from("crs/rules/*.conf")]
}

fn default_paranoia_level() -> u8 {
  1
}

fn default_inbound_threshold() -> i64 {
  5
}

fn default_outbound_threshold() -> i64 {
  4
}

fn crs_phase_name(phase: u8) -> &'static str {
  match phase {
    1 | 2 => "request",
    3 | 4 => "response",
    _ => "unknown",
  }
}

fn version_string(version: Version) -> String {
  match version {
    Version::HTTP_09 => "HTTP/0.9",
    Version::HTTP_10 => "HTTP/1.0",
    Version::HTTP_11 => "HTTP/1.1",
    Version::HTTP_2 => "HTTP/2.0",
    Version::HTTP_3 => "HTTP/3.0",
    _ => "HTTP/1.1",
  }
  .to_string()
}

fn header_values(headers: &HeaderMap, selector: Option<&str>) -> Vec<String> {
  match selector {
    Some(selector)
      if selector.starts_with('/') && selector.ends_with('/') && selector.len() > 2 =>
    {
      let Ok(regex) = Regex::new(&selector[1..selector.len() - 1]) else {
        return Vec::new();
      };
      headers
        .iter()
        .filter(|(name, _)| regex.is_match(name.as_str()))
        .filter_map(|(_, value)| value.to_str().ok().map(ToString::to_string))
        .collect()
    }
    Some(selector) => headers
      .get_all(selector)
      .iter()
      .filter_map(|value| value.to_str().ok().map(ToString::to_string))
      .collect(),
    None => headers
      .values()
      .filter_map(|value| value.to_str().ok().map(ToString::to_string))
      .collect(),
  }
}

fn query_pairs(uri: &Uri) -> Vec<(String, String)> {
  url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
    .map(|(name, value)| (name.into_owned(), value.into_owned()))
    .collect()
}

fn cookie_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
  headers
    .get_all(http::header::COOKIE)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(';'))
    .filter_map(|part| part.trim().split_once('='))
    .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
    .collect()
}

fn body_pairs(headers: &HeaderMap, body: Option<WafBodyInput<'_>>) -> Vec<(String, String)> {
  let content_type = headers
    .get(http::header::CONTENT_TYPE)
    .and_then(|value| value.to_str().ok())
    .unwrap_or_default()
    .to_ascii_lowercase();
  if !content_type.contains("application/x-www-form-urlencoded") {
    return Vec::new();
  }
  let Some(body) = body else {
    return Vec::new();
  };
  url::form_urlencoded::parse(body.bytes)
    .map(|(name, value)| (name.into_owned(), value.into_owned()))
    .collect()
}

fn select_pairs(pairs: Vec<(String, String)>, selector: Option<&str>) -> Vec<String> {
  match selector {
    Some(selector) => pairs
      .into_iter()
      .filter(|(name, _)| name.eq_ignore_ascii_case(selector))
      .map(|(_, value)| value)
      .collect(),
    None => pairs.into_iter().map(|(_, value)| value).collect(),
  }
}

fn apply_transforms(value: &str, transforms: &[CrsTransform]) -> String {
  let mut out = value.to_string();
  for transform in transforms {
    out = match transform {
      CrsTransform::Lowercase => out.to_ascii_lowercase(),
      CrsTransform::UrlDecode => normalize_text(&out),
      CrsTransform::NormalizePath => normalize_path(&out),
      CrsTransform::RemoveNulls => out.replace('\0', ""),
      CrsTransform::CompressWhitespace => compress_whitespace(&out),
      CrsTransform::RemoveWhitespace => out.chars().filter(|ch| !ch.is_whitespace()).collect(),
      CrsTransform::Trim => out.trim().to_string(),
      CrsTransform::HtmlEntityDecode => decode_html_entities(&out),
    };
  }
  out
}

fn compress_whitespace(value: &str) -> String {
  let mut out = String::new();
  let mut space = false;
  for ch in value.chars() {
    if ch.is_whitespace() {
      if !space {
        out.push(' ');
        space = true;
      }
    } else {
      out.push(ch);
      space = false;
    }
  }
  out
}

fn decode_html_entities(value: &str) -> String {
  value
    .replace("&lt;", "<")
    .replace("&gt;", ">")
    .replace("&amp;", "&")
    .replace("&quot;", "\"")
    .replace("&#x27;", "'")
    .replace("&#39;", "'")
}

fn invalid_url_encoding(value: &str) -> bool {
  let bytes = value.as_bytes();
  let mut index = 0;
  while index < bytes.len() {
    if bytes[index] == b'%' {
      if index + 2 >= bytes.len()
        || hex_nibble(bytes[index + 1]).is_none()
        || hex_nibble(bytes[index + 2]).is_none()
      {
        return true;
      }
      index += 3;
    } else {
      index += 1;
    }
  }
  false
}

fn hex_nibble(byte: u8) -> Option<u8> {
  match byte {
    b'0'..=b'9' => Some(byte - b'0'),
    b'a'..=b'f' => Some(byte - b'a' + 10),
    b'A'..=b'F' => Some(byte - b'A' + 10),
    _ => None,
  }
}

fn parse_setvar(raw: &str) -> anyhow::Result<Option<CrsAction>> {
  let Some(rest) = raw.strip_prefix("tx.") else {
    return Ok(None);
  };
  let Some((name, value)) = rest.split_once('=') else {
    bail!("setvar action must contain '='");
  };
  let (operation, value) = if let Some(value) = value.strip_prefix('+') {
    (SetVarOperation::Add(value.to_string()), value)
  } else if let Some(value) = value.strip_prefix('-') {
    (SetVarOperation::Subtract(value.to_string()), value)
  } else {
    (SetVarOperation::Assign(value.to_string()), value)
  };
  let _ = value;
  Ok(Some(CrsAction::SetVar {
    name: name.to_ascii_lowercase(),
    operation,
  }))
}

fn expand_macros(value: &str, tx: &CrsTransaction<'_>) -> String {
  let Ok(regex) = Regex::new(r"%\{tx\.([A-Za-z0-9_.-]+)\}") else {
    return value.to_string();
  };
  regex
    .replace_all(value, |captures: &regex::Captures<'_>| {
      tx.tx
        .get(&captures[1].to_ascii_lowercase())
        .cloned()
        .unwrap_or_default()
    })
    .to_string()
}

fn logical_lines(raw: &str) -> Vec<String> {
  let mut lines = Vec::new();
  let mut current = String::new();
  for line in raw.lines() {
    let trimmed = line.trim_end();
    if let Some(prefix) = trimmed.strip_suffix('\\') {
      current.push_str(prefix);
      current.push(' ');
    } else {
      current.push_str(trimmed);
      lines.push(current.trim().to_string());
      current.clear();
    }
  }
  if !current.trim().is_empty() {
    lines.push(current.trim().to_string());
  }
  lines
}

fn strip_comment(line: &str) -> String {
  let mut quoted = false;
  let mut quote = '\0';
  let mut out = String::new();
  for ch in line.chars() {
    if quoted {
      if ch == quote {
        quoted = false;
      }
      out.push(ch);
      continue;
    }
    if matches!(ch, '"' | '\'') {
      quoted = true;
      quote = ch;
      out.push(ch);
      continue;
    }
    if ch == '#' {
      break;
    }
    out.push(ch);
  }
  out
}

fn parse_quoted_sections(raw: &str) -> anyhow::Result<Vec<String>> {
  let mut sections = Vec::new();
  let mut chars = raw.trim().chars().peekable();
  while chars.peek().is_some() {
    while matches!(chars.peek(), Some(ch) if ch.is_whitespace()) {
      chars.next();
    }
    let Some(ch) = chars.next() else {
      break;
    };
    if matches!(ch, '"' | '\'') {
      let quote = ch;
      let mut section = String::new();
      for ch in chars.by_ref() {
        if ch == quote {
          break;
        } else {
          section.push(ch);
        }
      }
      sections.push(section);
    } else {
      let mut section = String::new();
      section.push(ch);
      while let Some(ch) = chars.peek().copied() {
        if ch.is_whitespace() {
          break;
        }
        section.push(ch);
        chars.next();
      }
      sections.push(section);
    }
  }
  Ok(sections)
}

fn split_actions(raw: &str) -> Vec<String> {
  let mut tokens = Vec::new();
  let mut current = String::new();
  let mut quoted = false;
  let mut quote = '\0';
  for ch in raw.chars() {
    if quoted {
      if ch == quote {
        quoted = false;
      }
      current.push(ch);
    } else if matches!(ch, '"' | '\'') {
      quoted = true;
      quote = ch;
      current.push(ch);
    } else if ch == ',' {
      tokens.push(current.trim().to_string());
      current.clear();
    } else {
      current.push(ch);
    }
  }
  if !current.trim().is_empty() {
    tokens.push(current.trim().to_string());
  }
  tokens
}

fn split_phrases(raw: &str) -> Vec<String> {
  raw
    .split_whitespace()
    .map(unquote)
    .map(ToString::to_string)
    .collect()
}

fn unquote(value: &str) -> &str {
  value
    .trim()
    .strip_prefix('\'')
    .and_then(|value| value.strip_suffix('\''))
    .or_else(|| {
      value
        .trim()
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    })
    .unwrap_or_else(|| value.trim())
}

fn unquote_selector(value: &str) -> String {
  unquote(value).to_string()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_secrule_and_scores_with_setvar() {
    let rule = CrsRule::from_parts(
      vec![CrsVariable::RequestUri],
      CrsOperator::parse("@contains union select").unwrap(),
      "id:942100,phase:2,t:lowercase,tag:'paranoia-level/1',severity:'CRITICAL',setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'",
    )
    .unwrap();

    assert_eq!(rule.id, "942100");
    assert_eq!(rule.phase, 2);
    assert_eq!(rule.actions.len(), 1);
  }
}

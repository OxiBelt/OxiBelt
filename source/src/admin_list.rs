use std::collections::BTreeMap;

use anyhow::{Context, bail};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const CURSOR_VERSION: u8 = 1;
const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 1000;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminListOrder {
  Asc,
  Desc,
}

#[derive(Debug, Clone)]
pub struct AdminListSpec {
  pub endpoint: &'static str,
  pub default_sort: &'static str,
  pub allowed_sorts: &'static [&'static str],
  pub allowed_filters: &'static [&'static str],
}

#[derive(Debug, Clone)]
pub struct AdminListQuery {
  endpoint: &'static str,
  limit: usize,
  sort: String,
  order: AdminListOrder,
  filters: BTreeMap<String, String>,
  cursor_position: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminPagination {
  pub limit: usize,
  pub has_more: bool,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub next_cursor: Option<String>,
  pub sort: String,
  pub order: AdminListOrder,
}

#[derive(Debug, Clone)]
pub struct AdminListPage<T> {
  pub items: Vec<T>,
  pub pagination: AdminPagination,
}

#[derive(Debug, Deserialize, Serialize)]
struct AdminListCursor {
  v: u8,
  endpoint: String,
  sort: String,
  order: AdminListOrder,
  filters: BTreeMap<String, String>,
  position: Value,
}

impl AdminListQuery {
  pub fn parse(query: Option<&str>, spec: &AdminListSpec) -> anyhow::Result<Option<Self>> {
    let mut active = false;
    let mut limit = None;
    let mut sort = None;
    let mut order = None;
    let mut filters = BTreeMap::new();
    let mut cursor = None;

    if let Some(query) = query {
      for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
          "limit" => {
            active = true;
            limit = Some(parse_limit(&value)?);
          }
          "cursor" => {
            active = true;
            cursor = Some(value.into_owned());
          }
          "sort" => {
            active = true;
            let value = value.into_owned();
            if !spec.allowed_sorts.contains(&value.as_str()) {
              bail!("unsupported sort field {value}");
            }
            sort = Some(value);
          }
          "order" => {
            active = true;
            order = Some(parse_order(&value)?);
          }
          key if key.starts_with("filter[") && key.ends_with(']') => {
            active = true;
            let name = &key["filter[".len()..key.len() - 1];
            if name.is_empty() || !spec.allowed_filters.contains(&name) {
              bail!("unsupported filter {name}");
            }
            if filters
              .insert(name.to_string(), value.into_owned())
              .is_some()
            {
              bail!("duplicate filter {name}");
            }
          }
          _ => {}
        }
      }
    }

    if !active {
      return Ok(None);
    }

    let sort = sort.unwrap_or_else(|| spec.default_sort.to_string());
    let order = order.unwrap_or(AdminListOrder::Asc);
    let limit = limit.unwrap_or(DEFAULT_LIMIT);
    let cursor_position = cursor
      .map(|cursor| decode_cursor(&cursor, spec.endpoint, &sort, order, &filters))
      .transpose()?;

    Ok(Some(Self {
      endpoint: spec.endpoint,
      limit,
      sort,
      order,
      filters,
      cursor_position,
    }))
  }

  pub fn limit(&self) -> usize {
    self.limit
  }

  pub fn sort(&self) -> &str {
    &self.sort
  }

  pub fn order(&self) -> AdminListOrder {
    self.order
  }

  pub fn filters(&self) -> &BTreeMap<String, String> {
    &self.filters
  }

  pub fn filter(&self, name: &str) -> Option<&str> {
    self.filters.get(name).map(String::as_str)
  }

  pub fn cursor_position(&self) -> Option<&Value> {
    self.cursor_position.as_ref()
  }

  pub fn pagination(
    &self,
    has_more: bool,
    next_position: Option<Value>,
  ) -> anyhow::Result<AdminPagination> {
    let next_cursor = if has_more {
      Some(encode_cursor(AdminListCursor {
        v: CURSOR_VERSION,
        endpoint: self.endpoint.to_string(),
        sort: self.sort.clone(),
        order: self.order,
        filters: self.filters.clone(),
        position: next_position.context("next cursor position is missing")?,
      })?)
    } else {
      None
    };
    Ok(AdminPagination {
      limit: self.limit,
      has_more,
      next_cursor,
      sort: self.sort.clone(),
      order: self.order,
    })
  }
}

pub fn parse_bool(value: &str) -> anyhow::Result<bool> {
  match value {
    "true" => Ok(true),
    "false" => Ok(false),
    _ => bail!("boolean filters must be true or false"),
  }
}

pub fn offset_from_cursor(query: &AdminListQuery) -> anyhow::Result<usize> {
  let Some(position) = query.cursor_position() else {
    return Ok(0);
  };
  let offset = position
    .get("offset")
    .and_then(Value::as_u64)
    .context("cursor position is invalid")?;
  usize::try_from(offset).context("cursor offset is too large")
}

pub fn offset_position(offset: usize) -> Value {
  json!({ "offset": offset })
}

fn parse_limit(value: &str) -> anyhow::Result<usize> {
  let limit = value
    .parse::<usize>()
    .map_err(|_| anyhow::anyhow!("limit must be an integer"))?;
  if !(1..=MAX_LIMIT).contains(&limit) {
    bail!("limit must be between 1 and 1000");
  }
  Ok(limit)
}

fn parse_order(value: &str) -> anyhow::Result<AdminListOrder> {
  match value {
    "asc" => Ok(AdminListOrder::Asc),
    "desc" => Ok(AdminListOrder::Desc),
    _ => bail!("order must be asc or desc"),
  }
}

fn encode_cursor(cursor: AdminListCursor) -> anyhow::Result<String> {
  let raw = serde_json::to_vec(&cursor)?;
  Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw))
}

fn decode_cursor(
  cursor: &str,
  endpoint: &str,
  sort: &str,
  order: AdminListOrder,
  filters: &BTreeMap<String, String>,
) -> anyhow::Result<Value> {
  let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
    .decode(cursor)
    .map_err(|_| anyhow::anyhow!("cursor is invalid"))?;
  let decoded = serde_json::from_slice::<AdminListCursor>(&raw)
    .map_err(|_| anyhow::anyhow!("cursor is invalid"))?;
  if decoded.v != CURSOR_VERSION
    || decoded.endpoint != endpoint
    || decoded.sort != sort
    || decoded.order != order
    || decoded.filters != *filters
  {
    bail!("cursor does not match this list query");
  }
  Ok(decoded.position)
}

#[cfg(test)]
mod tests {
  use super::*;

  const SPEC: AdminListSpec = AdminListSpec {
    endpoint: "/admin/v1/example",
    default_sort: "name",
    allowed_sorts: &["name", "enabled"],
    allowed_filters: &["enabled", "source"],
  };

  #[test]
  fn list_query_is_inactive_without_recognized_parameters() {
    let query = AdminListQuery::parse(Some("unknown=value"), &SPEC).expect("query should parse");
    assert!(query.is_none());
  }

  #[test]
  fn list_query_parses_limit_sort_order_and_filters() {
    let query = AdminListQuery::parse(
      Some("limit=25&sort=enabled&order=desc&filter%5Bsource%5D=store"),
      &SPEC,
    )
    .expect("query should parse")
    .expect("query should be active");

    assert_eq!(query.limit(), 25);
    assert_eq!(query.sort(), "enabled");
    assert_eq!(query.order(), AdminListOrder::Desc);
    assert_eq!(query.filter("source"), Some("store"));
  }

  #[test]
  fn list_query_rejects_invalid_values() {
    assert!(AdminListQuery::parse(Some("limit=0"), &SPEC).is_err());
    assert!(AdminListQuery::parse(Some("order=sideways"), &SPEC).is_err());
    assert!(AdminListQuery::parse(Some("sort=id"), &SPEC).is_err());
    assert!(AdminListQuery::parse(Some("filter%5Bmissing%5D=x"), &SPEC).is_err());
  }

  #[test]
  fn bool_filter_parses_only_lowercase_json_booleans() {
    assert!(parse_bool("true").expect("true should parse"));
    assert!(!parse_bool("false").expect("false should parse"));
    assert!(parse_bool("TRUE").is_err());
  }

  #[test]
  fn cursor_roundtrips_and_rejects_mismatched_query() {
    let query = AdminListQuery::parse(Some("limit=2&filter%5Bsource%5D=store"), &SPEC)
      .expect("query should parse")
      .expect("query should be active");
    let pagination = query
      .pagination(true, Some(offset_position(2)))
      .expect("cursor should encode");
    let cursor = pagination.next_cursor.expect("next cursor");

    let next = AdminListQuery::parse(
      Some(&format!("limit=2&filter%5Bsource%5D=store&cursor={cursor}")),
      &SPEC,
    )
    .expect("cursor should parse")
    .expect("query should be active");
    assert_eq!(offset_from_cursor(&next).expect("offset"), 2);

    let mismatch = AdminListQuery::parse(
      Some(&format!(
        "limit=2&filter%5Bsource%5D=config&cursor={cursor}"
      )),
      &SPEC,
    );
    assert!(mismatch.is_err());
  }
}

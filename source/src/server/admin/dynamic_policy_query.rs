use anyhow::bail;

pub(super) fn policy_id_from_path(path: &str) -> Option<i64> {
  path
    .strip_prefix("/admin/v1/dynamic-policies/")?
    .parse()
    .ok()
}

pub(super) fn audit_query(query: Option<&str>) -> anyhow::Result<(Option<i64>, i64)> {
  let mut policy_id = None;
  let mut limit = 100_i64;
  if let Some(query) = query {
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
      match key.as_ref() {
        "policy_id" => {
          policy_id = Some(
            value
              .parse::<i64>()
              .map_err(|_| anyhow::anyhow!("policy_id must be an integer"))?,
          );
        }
        "limit" => {
          limit = value
            .parse::<i64>()
            .map_err(|_| anyhow::anyhow!("limit must be an integer"))?;
        }
        _ => {}
      }
    }
  }
  if let Some(policy_id) = policy_id
    && policy_id <= 0
  {
    bail!("policy_id must be greater than 0");
  }
  if !(1..=1000).contains(&limit) {
    bail!("limit must be between 1 and 1000");
  }
  Ok((policy_id, limit))
}

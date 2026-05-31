use std::cmp::Ordering;

use crate::admin_list::{
  AdminListOrder, AdminListPage, AdminListQuery, AdminListSpec, offset_from_cursor,
  offset_position, parse_bool,
};
use crate::ipm::{
  IpmEntrySource, IpmPrincipalRecord, RedactedIpmBinding, RedactedIpmCredential, RedactedIpmPolicy,
};

pub(super) const IPM_PRINCIPALS_LIST: AdminListSpec = AdminListSpec {
  endpoint: "/admin/v1/ipm/principals",
  default_sort: "id",
  allowed_sorts: &["id", "subject", "enabled", "source"],
  allowed_filters: &["source", "enabled", "group"],
};

pub(super) const IPM_CREDENTIALS_LIST: AdminListSpec = AdminListSpec {
  endpoint: "/admin/v1/ipm/credentials",
  default_sort: "name",
  allowed_sorts: &[
    "name",
    "principal",
    "enabled",
    "revoked",
    "source",
    "expires_at",
  ],
  allowed_filters: &["source", "principal", "enabled", "revoked"],
};

pub(super) const IPM_POLICIES_LIST: AdminListSpec = AdminListSpec {
  endpoint: "/admin/v1/ipm/policies",
  default_sort: "name",
  allowed_sorts: &["name", "version", "enabled", "source"],
  allowed_filters: &["source", "enabled"],
};

pub(super) const IPM_BINDINGS_LIST: AdminListSpec = AdminListSpec {
  endpoint: "/admin/v1/ipm/bindings",
  default_sort: "id",
  allowed_sorts: &["id", "principal", "group", "policy", "enabled", "source"],
  allowed_filters: &["source", "principal", "group", "policy", "enabled"],
};

pub(super) fn ipm_principal_page(
  mut principals: Vec<IpmPrincipalRecord>,
  query: &AdminListQuery,
) -> anyhow::Result<AdminListPage<IpmPrincipalRecord>> {
  if let Some(source) = query.filter("source") {
    principals.retain(|principal| source_name(principal.source) == source);
  }
  if let Some(enabled) = query.filter("enabled") {
    let enabled = parse_bool(enabled)?;
    principals.retain(|principal| principal.enabled == enabled);
  }
  if let Some(group) = query.filter("group") {
    principals.retain(|principal| principal.groups.iter().any(|candidate| candidate == group));
  }
  principals.sort_by(|left, right| {
    order_cmp(
      query.order(),
      match query.sort() {
        "id" => left.id.cmp(&right.id),
        "subject" => left
          .subject
          .cmp(&right.subject)
          .then_with(|| left.id.cmp(&right.id)),
        "enabled" => left
          .enabled
          .cmp(&right.enabled)
          .then_with(|| left.id.cmp(&right.id)),
        "source" => source_name(left.source)
          .cmp(source_name(right.source))
          .then_with(|| left.id.cmp(&right.id)),
        _ => Ordering::Equal,
      },
    )
  });
  page_in_memory(principals, query)
}

pub(super) fn ipm_credential_page(
  mut credentials: Vec<RedactedIpmCredential>,
  query: &AdminListQuery,
) -> anyhow::Result<AdminListPage<RedactedIpmCredential>> {
  if let Some(source) = query.filter("source") {
    credentials.retain(|credential| source_name(credential.source) == source);
  }
  if let Some(principal) = query.filter("principal") {
    credentials.retain(|credential| credential.principal == principal);
  }
  if let Some(enabled) = query.filter("enabled") {
    let enabled = parse_bool(enabled)?;
    credentials.retain(|credential| credential.enabled == enabled);
  }
  if let Some(revoked) = query.filter("revoked") {
    let revoked = parse_bool(revoked)?;
    credentials.retain(|credential| credential.revoked == revoked);
  }
  credentials.sort_by(|left, right| {
    order_cmp(
      query.order(),
      match query.sort() {
        "name" => left.name.cmp(&right.name),
        "principal" => left
          .principal
          .cmp(&right.principal)
          .then_with(|| left.name.cmp(&right.name)),
        "enabled" => left
          .enabled
          .cmp(&right.enabled)
          .then_with(|| left.name.cmp(&right.name)),
        "revoked" => left
          .revoked
          .cmp(&right.revoked)
          .then_with(|| left.name.cmp(&right.name)),
        "source" => source_name(left.source)
          .cmp(source_name(right.source))
          .then_with(|| left.name.cmp(&right.name)),
        "expires_at" => left
          .expires_at
          .cmp(&right.expires_at)
          .then_with(|| left.name.cmp(&right.name)),
        _ => Ordering::Equal,
      },
    )
  });
  page_in_memory(credentials, query)
}

pub(super) fn ipm_policy_page(
  mut policies: Vec<RedactedIpmPolicy>,
  query: &AdminListQuery,
) -> anyhow::Result<AdminListPage<RedactedIpmPolicy>> {
  if let Some(source) = query.filter("source") {
    policies.retain(|policy| source_name(policy.source) == source);
  }
  if let Some(enabled) = query.filter("enabled") {
    let enabled = parse_bool(enabled)?;
    policies.retain(|policy| policy.enabled == enabled);
  }
  policies.sort_by(|left, right| {
    order_cmp(
      query.order(),
      match query.sort() {
        "name" => left.name.cmp(&right.name),
        "version" => left
          .version
          .cmp(&right.version)
          .then_with(|| left.name.cmp(&right.name)),
        "enabled" => left
          .enabled
          .cmp(&right.enabled)
          .then_with(|| left.name.cmp(&right.name)),
        "source" => source_name(left.source)
          .cmp(source_name(right.source))
          .then_with(|| left.name.cmp(&right.name)),
        _ => Ordering::Equal,
      },
    )
  });
  page_in_memory(policies, query)
}

pub(super) fn ipm_binding_page(
  mut bindings: Vec<RedactedIpmBinding>,
  query: &AdminListQuery,
) -> anyhow::Result<AdminListPage<RedactedIpmBinding>> {
  if let Some(source) = query.filter("source") {
    bindings.retain(|binding| source_name(binding.source) == source);
  }
  if let Some(principal) = query.filter("principal") {
    bindings.retain(|binding| binding.principal.as_deref() == Some(principal));
  }
  if let Some(group) = query.filter("group") {
    bindings.retain(|binding| binding.group.as_deref() == Some(group));
  }
  if let Some(policy) = query.filter("policy") {
    bindings.retain(|binding| binding.policy == policy);
  }
  if let Some(enabled) = query.filter("enabled") {
    let enabled = parse_bool(enabled)?;
    bindings.retain(|binding| binding.enabled == enabled);
  }
  bindings.sort_by(|left, right| {
    order_cmp(
      query.order(),
      match query.sort() {
        "id" => left.id.cmp(&right.id),
        "principal" => option_str(left.principal.as_deref())
          .cmp(option_str(right.principal.as_deref()))
          .then_with(|| left.id.cmp(&right.id)),
        "group" => option_str(left.group.as_deref())
          .cmp(option_str(right.group.as_deref()))
          .then_with(|| left.id.cmp(&right.id)),
        "policy" => left
          .policy
          .cmp(&right.policy)
          .then_with(|| left.id.cmp(&right.id)),
        "enabled" => left
          .enabled
          .cmp(&right.enabled)
          .then_with(|| left.id.cmp(&right.id)),
        "source" => source_name(left.source)
          .cmp(source_name(right.source))
          .then_with(|| left.id.cmp(&right.id)),
        _ => Ordering::Equal,
      },
    )
  });
  page_in_memory(bindings, query)
}

fn page_in_memory<T>(items: Vec<T>, query: &AdminListQuery) -> anyhow::Result<AdminListPage<T>> {
  let offset = offset_from_cursor(query)?;
  let next_offset = offset.saturating_add(query.limit());
  let has_more = items.len() > next_offset;
  let page = items
    .into_iter()
    .skip(offset)
    .take(query.limit())
    .collect::<Vec<_>>();
  let next_position = has_more.then(|| offset_position(next_offset));
  let pagination = query.pagination(has_more, next_position)?;
  Ok(AdminListPage {
    items: page,
    pagination,
  })
}

fn order_cmp(order: AdminListOrder, ordering: Ordering) -> Ordering {
  match order {
    AdminListOrder::Asc => ordering,
    AdminListOrder::Desc => ordering.reverse(),
  }
}

fn source_name(source: IpmEntrySource) -> &'static str {
  match source {
    IpmEntrySource::Config => "config",
    IpmEntrySource::Store => "store",
  }
}

fn option_str(value: Option<&str>) -> &str {
  value.unwrap_or("")
}

#[cfg(test)]
mod tests {
  use super::*;

  fn query(raw: &str, spec: &AdminListSpec) -> AdminListQuery {
    AdminListQuery::parse(Some(raw), spec)
      .expect("query should parse")
      .expect("query should be active")
  }

  #[test]
  fn ipm_principal_list_legacy_query_is_inactive() {
    let parsed = AdminListQuery::parse(None, &IPM_PRINCIPALS_LIST).expect("query should parse");
    assert!(parsed.is_none());
  }

  #[test]
  fn ipm_principal_list_paginates_with_cursor() {
    let principals = vec![
      principal("alpha", "team-a", true, IpmEntrySource::Config),
      principal("beta", "team-b", true, IpmEntrySource::Store),
      principal("gamma", "team-c", true, IpmEntrySource::Store),
    ];
    let first_query = query("limit=2", &IPM_PRINCIPALS_LIST);
    let first = ipm_principal_page(principals.clone(), &first_query).expect("first page");

    assert_eq!(
      first
        .items
        .iter()
        .map(|principal| principal.id.as_str())
        .collect::<Vec<_>>(),
      vec!["alpha", "beta"]
    );
    assert!(first.pagination.has_more);
    let cursor = first.pagination.next_cursor.expect("next cursor");
    let second_query = query(&format!("limit=2&cursor={cursor}"), &IPM_PRINCIPALS_LIST);
    let second = ipm_principal_page(principals, &second_query).expect("second page");

    assert_eq!(
      second
        .items
        .iter()
        .map(|principal| principal.id.as_str())
        .collect::<Vec<_>>(),
      vec!["gamma"]
    );
    assert!(!second.pagination.has_more);
  }

  #[test]
  fn ipm_principal_list_filters_and_sorts_descending() {
    let principals = vec![
      principal("alpha", "team-a", true, IpmEntrySource::Config),
      principal("beta", "team-b", false, IpmEntrySource::Store),
      principal("gamma", "team-c", true, IpmEntrySource::Store),
    ];
    let query = query(
      "limit=10&filter%5Bsource%5D=store&filter%5Benabled%5D=true&sort=subject&order=desc",
      &IPM_PRINCIPALS_LIST,
    );
    let page = ipm_principal_page(principals, &query).expect("page");

    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].id, "gamma");
  }

  #[test]
  fn ipm_credentials_reject_bad_bool_filter() {
    let query = query("limit=10&filter%5Brevoked%5D=yes", &IPM_CREDENTIALS_LIST);
    let error = ipm_credential_page(Vec::new(), &query).expect_err("bad bool should fail");
    assert!(error.to_string().contains("boolean filters"));
  }

  #[test]
  fn ipm_binding_list_filters_by_policy() {
    let bindings = vec![
      binding("first", Some("alpha"), None, "admin", true),
      binding("second", None, Some("ops"), "viewer", true),
    ];
    let query = query("limit=10&filter%5Bpolicy%5D=viewer", &IPM_BINDINGS_LIST);
    let page = ipm_binding_page(bindings, &query).expect("page");

    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].id, "second");
  }

  #[test]
  fn ipm_list_rejects_unsupported_filter_and_sort() {
    assert!(AdminListQuery::parse(Some("filter%5Bmissing%5D=x"), &IPM_POLICIES_LIST).is_err());
    assert!(AdminListQuery::parse(Some("sort=created_at"), &IPM_POLICIES_LIST).is_err());
  }

  fn principal(id: &str, group: &str, enabled: bool, source: IpmEntrySource) -> IpmPrincipalRecord {
    IpmPrincipalRecord {
      id: id.to_string(),
      subject: format!("subject:{id}"),
      groups: vec![group.to_string()],
      enabled,
      source,
    }
  }

  fn binding(
    id: &str,
    principal: Option<&str>,
    group: Option<&str>,
    policy: &str,
    enabled: bool,
  ) -> RedactedIpmBinding {
    RedactedIpmBinding {
      id: id.to_string(),
      principal: principal.map(str::to_string),
      group: group.map(str::to_string),
      policy: policy.to_string(),
      enabled,
      source: IpmEntrySource::Store,
    }
  }
}

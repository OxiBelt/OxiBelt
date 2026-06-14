use super::*;

pub(super) async fn admin_plan_value(
  client: &AdminClient,
  context: &RulepackReportContext<'_>,
) -> anyhow::Result<Option<Value>> {
  if context.fixture.is_some() || context.replay.is_some() {
    return Ok(None);
  }
  let loaded =
    crate::rulepack::load_rulepack_source(context.source, client.timeout(), true).await?;
  if loaded.git_commit.is_some() {
    return Ok(None);
  }
  let cli_vars = crate::rulepack_fit::parse_key_values(context.vars, "--var")?;
  let cli_binds = crate::rulepack_fit::parse_key_values(context.binds, "--bind")?;
  let resolved = crate::rulepack_values::resolve_rulepack_inputs(
    crate::rulepack_values::RulepackResolveRequest {
      raw: &loaded.manifest,
      source: &loaded.source_label,
      values_file: context.values,
      cli_vars: &cli_vars,
      cli_binds: &cli_binds,
      cli_profile: context.profile,
      cli_mode: context.mode,
      cli_force_mode: context.force_mode,
      default_mode: Some(RulepackModeArg::Monitor),
    },
  )?;
  let input_metadata = inspect_rulepack_inputs(&loaded.manifest, &loaded.source_label)?;
  let missing_bindings = crate::rulepack_fit::missing_required_bindings(
    &input_metadata,
    &resolved.vars,
    &resolved.binds,
  );
  let missing_variables = crate::rulepack_fit::missing_required_variables(
    &input_metadata,
    &resolved.vars,
    &resolved.binds,
  );
  if missing_bindings.is_empty() && missing_variables.is_empty() {
    let render_vars = crate::rulepack_fit::resolve_render_variables(
      &loaded.manifest,
      &loaded.source_label,
      &resolved.vars,
      &resolved.binds,
      true,
    )?;
    let options = render_options(
      render_vars,
      resolved.rule_overrides.clone(),
      resolved.exceptions.clone(),
      resolved.mode,
      resolved.force_mode,
      loaded.git_commit.clone(),
      loaded.source_provenance.clone(),
    );
    if !referenced_rulepack_files(&loaded.manifest, &loaded.source_label, options)?.is_empty() {
      return Ok(None);
    }
  }
  let source = loaded.source_provenance.as_ref().map(|provenance| {
    json!({
      "url": provenance.source_url.clone(),
      "sha256": provenance.source_sha256.clone(),
      "openpgp_signature_url": provenance.source_openpgp_signature_url.clone(),
      "openpgp_signer_fingerprint": provenance.source_openpgp_signer_fingerprint.clone(),
    })
  });
  let mut body = json!({
    "manifest": loaded.manifest,
    "source": source,
    "values": resolved.vars,
    "bindings": resolved.binds,
    "rule_overrides": resolved.rule_overrides,
    "exceptions": resolved.exceptions,
    "profile": resolved.selected_profile,
    "mode": resolved.mode.map(mode_name),
    "force_mode": resolved.force_mode,
    "include_route_candidates": true,
    "include_diff": true,
    "include_cost": true,
  });
  if body.get("source").is_some_and(Value::is_null)
    && let Some(object) = body.as_object_mut()
  {
    object.remove("source");
  }
  let response = client
    .request_json(
      Method::POST,
      "/admin/v1/waf/rulepacks/plan",
      Some(body),
      None,
    )
    .await?;
  if matches!(
    response.status,
    StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
  ) {
    return Ok(None);
  }
  if !response.status.is_success() {
    bail!(
      "Admin rulepack plan request failed with {}",
      response.status
    );
  }
  let mut value: Value =
    serde_json::from_slice(&response.body).context("rulepack plan response was not JSON")?;
  if let Some(object) = value.as_object_mut() {
    object.insert("view".to_string(), json!(context.view));
  }
  Ok(Some(value))
}

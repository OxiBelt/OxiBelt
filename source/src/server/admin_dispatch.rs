//! Admin listener bootstrap, transport dispatch, routing, and audit.

use super::*;

pub(super) async fn serve_admin_listener(
  listener: TcpListener,
  configured_bind: SocketAddr,
  state: AppHandle,
  admin_control: AdminControlHandle,
  admin_operations: AdminOperationRuntime,
  mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
  let bind = listener
    .local_addr()
    .context("failed to read admin listener address")?;
  info!(bind = %bind, "admin listener started");
  let connections = TaskRegistry::new(
    RuntimeTaskKind::AdminConnection,
    state.snapshot().runtime_health.clone(),
  );
  loop {
    tokio::select! {
      biased;
      changed = shutdown.changed() => {
        if changed.is_ok() && *shutdown.borrow() {
          info!(bind = %bind, "admin listener stopped");
        }
        return Ok(());
      }
      accepted = listener.accept() => {
        let (stream, peer_addr) = match accepted {
          Ok(value) => value,
          Err(error) => {
            warn!(error = %error, "failed to accept admin connection");
            continue;
          }
        };
        crate::tcp_socket::enable_tcp_nodelay(&stream, peer_addr, "admin listener");
        let state = state.clone();
        let Some(control_connection) = state
          .snapshot()
          .overload
          .try_admit_control_connection(ControlPlane::Admin)
        else {
          continue;
        };
        let admin_control = admin_control.clone();
        let admin_operations = admin_operations.clone();
        connections.spawn(async move {
          let _control_connection = control_connection;
          if let Err(error) =
            handle_admin_connection(
              stream,
              peer_addr,
              configured_bind,
              state,
              admin_control,
              admin_operations,
            )
            .await
          {
            warn!(peer = %peer_addr, error = %error, "admin connection failed");
          }
        });
      }
    }
  }
}

#[cfg(feature = "admin-runtime")]
pub(super) async fn handle_admin_connection(
  stream: TcpStream,
  peer_addr: SocketAddr,
  listener_bind: SocketAddr,
  state: AppHandle,
  admin_control: AdminControlHandle,
  admin_operations: AdminOperationRuntime,
) -> anyhow::Result<()> {
  let snapshot = state.snapshot();
  if !admin_audit_gate::listener_current(&snapshot, listener_bind) {
    bail!("admin listener is no longer current");
  }
  let plaintext_allowed = admin_plaintext_allowed(&snapshot, peer_addr);
  let transport = snapshot.config.admin.transport;
  drop(snapshot);
  match transport {
    AdminTransportMode::Tls => {
      admin_listener::handle_admin_tls_connection(
        stream,
        peer_addr,
        listener_bind,
        state,
        admin_control,
        admin_operations,
      )
      .await
    }
    AdminTransportMode::Plaintext => {
      admin_listener::handle_admin_plaintext_connection(
        stream,
        peer_addr,
        listener_bind,
        state,
        admin_control,
        admin_operations,
      )
      .await
    }
    AdminTransportMode::PlaintextAllowlist if plaintext_allowed => {
      admin_listener::handle_admin_plaintext_connection(
        stream,
        peer_addr,
        listener_bind,
        state,
        admin_control,
        admin_operations,
      )
      .await
    }
    AdminTransportMode::PlaintextAllowlist => {
      bail!("admin plaintext connection from {peer_addr} is not allowlisted");
    }
    AdminTransportMode::Auto => {
      if plaintext_allowed && !admin_listener::tcp_stream_starts_with_tls(&stream).await {
        admin_listener::handle_admin_plaintext_connection(
          stream,
          peer_addr,
          listener_bind,
          state,
          admin_control,
          admin_operations,
        )
        .await
      } else {
        admin_listener::handle_admin_tls_connection(
          stream,
          peer_addr,
          listener_bind,
          state,
          admin_control,
          admin_operations,
        )
        .await
      }
    }
  }
}

#[cfg(feature = "admin-runtime")]
pub(super) fn admin_plaintext_allowed(snapshot: &AppSnapshot, peer_addr: SocketAddr) -> bool {
  snapshot
    .config
    .admin
    .plaintext_allowed_source_cidrs
    .iter()
    .filter_map(|raw| Cidr::parse(raw).ok())
    .any(|cidr| cidr.contains(peer_addr.ip()))
}

#[cfg(feature = "admin-runtime")]
pub(super) async fn admin_response(
  mut request: hyper::Request<Incoming>,
  state: AppHandle,
  admin_control: AdminControlHandle,
  admin_operations: AdminOperationRuntime,
  peer_addr: SocketAddr,
  listener_bind: SocketAddr,
  scheme: &'static str,
) -> Response<ProxyBody> {
  let Some(_control_request) = state
    .snapshot()
    .overload
    .try_admit_control_request(ControlPlane::Admin)
  else {
    return text_response(
      StatusCode::SERVICE_UNAVAILABLE,
      "control capacity exhausted",
    );
  };
  let (audit, audit_reservation) =
    match admin_audit_gate::reserve_or_reject(&mut request, &state, peer_addr, scheme) {
      Ok(reservation) => reservation,
      Err(response) => return *response,
    };
  let response = admin_error::finalize_response(
    admin_response_inner(
      request,
      state.clone(),
      admin_control,
      admin_operations,
      peer_addr,
      listener_bind,
      scheme,
    )
    .await,
    &audit,
  )
  .await;
  admin_audit_gate::commit_response(audit, audit_reservation, response, &state).await
}
#[cfg(feature = "admin-runtime")]
pub(super) async fn admin_response_inner(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  admin_control: AdminControlHandle,
  admin_operations: AdminOperationRuntime,
  peer_addr: SocketAddr,
  listener_bind: SocketAddr,
  scheme: &'static str,
) -> Response<ProxyBody> {
  let snapshot = state.snapshot();
  if !admin_audit_gate::listener_current(&snapshot, listener_bind) {
    return text_response(StatusCode::NOT_FOUND, "not found");
  }
  let method = request.method().clone();
  let uri = request.uri().clone();
  let query = uri.query().unwrap_or_default();
  let params = url::form_urlencoded::parse(query.as_bytes())
    .into_owned()
    .collect::<std::collections::HashMap<_, _>>();
  let path = uri.path().to_string();
  let admin_context = admin_request_context(&request, peer_addr);
  let audit = AdminAuditHandle::from_request(&request);
  if path == "/cache/purge" || path == "/cache/purge-prefix" || path == "/cache/purge-tag" {
    if method != ::http::Method::POST {
      return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    }
    let authentication = match admin_authentication(&request, &snapshot.config, &snapshot.ipm).await
    {
      Ok(authentication) => authentication,
      Err(failure) if snapshot.config.admin.workload_identity.enabled => {
        if !failure.supports_signed_cache_purge() {
          snapshot
            .metrics
            .record_admin_workload_identity_authentication("rejected", failure.reason());
          if let Some(audit) = &audit {
            failure.record_audit(audit);
          }
          return text_response(StatusCode::UNAUTHORIZED, "unauthorized");
        }
        match admin::signed_cache_purge_actor(&request, snapshot.as_ref(), &method) {
          Ok(_) => match failure.clone().into_signed_cache_purge_authentication() {
            Some(authentication) => authentication,
            None => {
              snapshot
                .metrics
                .record_admin_workload_identity_authentication("rejected", failure.reason());
              if let Some(audit) = &audit {
                failure.record_audit(audit);
              }
              return text_response(StatusCode::UNAUTHORIZED, "unauthorized");
            }
          },
          Err(error) => {
            snapshot
              .metrics
              .record_admin_workload_identity_authentication("rejected", failure.reason());
            if let Some(audit) = &audit {
              failure.record_audit(audit);
            }
            warn!(error = %error, "rejected unsigned bound admin cache purge request");
            return text_response(StatusCode::UNAUTHORIZED, "unauthorized");
          }
        }
      }
      Err(failure) => match admin::signed_cache_purge_actor(&request, snapshot.as_ref(), &method) {
        Ok(actor) => AdminAuthentication::legacy_signed_cache_purge(actor),
        Err(error) => {
          if let Some(audit) = &audit {
            failure.record_audit(audit);
          }
          warn!(error = %error, "rejected unsigned admin cache purge request");
          return text_response(StatusCode::UNAUTHORIZED, "unauthorized");
        }
      },
    };
    if snapshot.config.admin.workload_identity.enabled {
      snapshot
        .metrics
        .record_admin_workload_identity_authentication("accepted", authentication.reason());
    }
    if let Some(audit) = &audit {
      authentication.record_audit(audit);
    }
    let actor = &authentication.actor;
    let authorization = if let Some(audit) = audit.clone() {
      AdminAuthorization::new_with_audit(actor, &snapshot.ipm, &admin_context, audit)
    } else {
      AdminAuthorization::new(actor, &snapshot.ipm, &admin_context)
    };
    if let Err(response) =
      admin_audit_gate::begin_authenticated_mutation(audit.as_ref(), &state, &method, &path, false)
        .await
    {
      return *response;
    }
    let response =
      admin::cache_purge_response(&snapshot, &params, &path, scheme, peer_addr, &authorization)
        .await;
    return response;
  }

  let authentication = match admin_authentication(&request, &snapshot.config, &snapshot.ipm).await {
    Ok(authentication) => authentication,
    Err(failure) => {
      if snapshot.config.admin.workload_identity.enabled {
        snapshot
          .metrics
          .record_admin_workload_identity_authentication("rejected", failure.reason());
      }
      if let Some(audit) = &audit {
        failure.record_audit(audit);
      }
      return text_response(StatusCode::UNAUTHORIZED, "unauthorized");
    }
  };
  if snapshot.config.admin.workload_identity.enabled {
    snapshot
      .metrics
      .record_admin_workload_identity_authentication("accepted", authentication.reason());
  }
  if let Some(audit) = &audit {
    authentication.record_audit(audit);
  }
  let authenticated_with_break_glass = authentication.authenticated_with_break_glass();
  let actor = &authentication.actor;
  if authenticated_with_break_glass
    && snapshot.config.ipm.break_glass.access_mode == IpmBreakGlassAccessMode::TwoFactorActivation
    && !admin_mutations::break_glass_activation_bootstrap_route(&method, &path)
  {
    match snapshot
      .admin_mutations
      .active_break_glass_activation(&actor.principal)
      .await
    {
      Ok(Some(activation)) if activation.scopes.iter().any(|scope| scope == "admin") => {}
      Ok(_) => return text_response(StatusCode::FORBIDDEN, "break-glass activation is required"),
      Err(error) => {
        warn!(error = %error, "failed to verify break-glass activation");
        return text_response(
          StatusCode::SERVICE_UNAVAILABLE,
          "break-glass activation store is unavailable",
        );
      }
    }
  }
  let authorization = if let Some(audit) = audit.clone() {
    AdminAuthorization::new_with_audit(actor, &snapshot.ipm, &admin_context, audit)
  } else {
    AdminAuthorization::new(actor, &snapshot.ipm, &admin_context)
  };

  let handled_by_mutation_runtime =
    admin_mutations::handles(&snapshot.admin_mutations, &method, &path, request.headers());
  if let Err(response) = admin_audit_gate::begin_authenticated_mutation(
    audit.as_ref(),
    &state,
    &method,
    &path,
    handled_by_mutation_runtime,
  )
  .await
  {
    return *response;
  }

  if handled_by_mutation_runtime {
    return admin_mutations::response(
      request,
      state.clone(),
      admin_control.clone(),
      &authorization,
      &authentication,
      &method,
      &path,
    )
    .await;
  }

  if method == ::http::Method::POST && path == "/admin/v1/config/secret-references/update" {
    return admin_mutation_resources::response(
      request,
      state.clone(),
      admin_control.clone(),
      &authorization,
      &method,
      &path,
      None,
      None,
      authenticated_with_break_glass,
    )
    .await
    .unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"));
  }

  if path == "/admin/v1/audit" {
    return admin_audit_endpoint::admin_audit_response(
      snapshot.as_ref(),
      &authorization,
      &method,
      uri.query(),
    )
    .await;
  }

  if let Some(response) = admin_metadata::admin_metadata_response(
    snapshot.as_ref(),
    &admin_operations,
    &authorization,
    &method,
    &path,
  ) {
    return response;
  }

  if path == "/admin/v1/operations" || path.starts_with("/admin/v1/operations/") {
    return admin_operations::admin_operations_response(
      request,
      admin_operations::AdminOperationRouteContext {
        state: state.clone(),
        admin_control: admin_control.clone(),
        operations: admin_operations.clone(),
        peer_addr,
      },
      &authorization,
      &method,
      &path,
    )
    .await
    .unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"));
  }

  if path == "/admin/v1/config/status"
    || path == "/admin/v1/config/effective"
    || path == "/admin/v1/config/explain"
    || path == "/admin/v1/config/validate"
    || path == "/admin/v1/config/diff"
    || path == "/admin/v1/config/load"
    || path == "/admin/v1/config/rollback"
  {
    return admin_ops::admin_config_response(
      request,
      state.clone(),
      admin_control.clone(),
      &authorization,
      &method,
      &path,
    )
    .await;
  }

  if let Some(response) = admin_ops::admin_tls_response(
    &request,
    snapshot.as_ref(),
    admin_control.clone(),
    &authorization,
    &method,
    &path,
  )
  .await
  {
    return response;
  }

  if path == "/admin/v1/files/sync" {
    return admin_ops::admin_files_response(
      request,
      admin_control.clone(),
      snapshot.config.rollout.blocks_per_pod_mutation(),
      &authorization,
      &method,
      &path,
    )
    .await;
  }
  if path == "/admin/v1/cache/key-explain" {
    return admin::cache_key_explain_response(request, snapshot.as_ref(), &authorization, &method)
      .await;
  }
  if path == "/admin/v1/cache/warm" {
    return admin::cache_warm_response(
      request,
      state.clone(),
      admin_operations.clone(),
      &authorization,
      &method,
      peer_addr,
    )
    .await;
  }
  if path == "/admin/v1/cache/purge" {
    return admin::cache_purge_json_response(
      request,
      snapshot.as_ref(),
      &authorization,
      &method,
      scheme,
      peer_addr,
    )
    .await;
  }

  if path.starts_with("/admin/v1/waf/person-proof") {
    return admin_person_proof::admin_person_proof_response(
      request,
      snapshot.as_ref(),
      &authorization,
      &method,
      &path,
    )
    .await
    .unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"));
  }

  if path == "/admin/v1/waf/rulepacks/plan" {
    return admin_rulepacks::plan_response(request, &snapshot.config, &authorization, &method)
      .await;
  }

  if path.starts_with("/admin/v1/waf/oxirule/") {
    return admin_ops::admin_waf_devtools_response(
      request,
      snapshot.as_ref(),
      admin_operations.clone(),
      &authorization,
      &method,
      &path,
    )
    .await
    .unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"));
  }

  if let Some(response) =
    admin_ops::admin_waf_response(snapshot.as_ref(), &authorization, &method, &path)
  {
    return response;
  }
  if let Some(response) =
    admin_ops::admin_lifecycle_response(snapshot.as_ref(), &authorization, &method, &path)
  {
    return response;
  }
  if path == "/admin/v1/diagnostics/preflight"
    || path == "/admin/v1/diagnostics/support-bundle"
    || path == "/admin/v1/runtime/snapshot"
    || path == "/admin/v1/runtime/introspection"
  {
    return admin_diagnostics::admin_diagnostics_response(
      request,
      state.clone(),
      admin_control.clone(),
      admin_operations.clone(),
      &authorization,
      &method,
      &path,
    )
    .await
    .unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"));
  }
  let ipm_path = path.starts_with("/admin/v1/ipm/");
  let dynamic_policy_path = path == "/admin/v1/dynamic-policies"
    || path == "/admin/v1/dynamic-policies/export"
    || path == "/admin/v1/dynamic-policies/import"
    || path.starts_with("/admin/v1/dynamic-policies/");
  if ipm_path || dynamic_policy_path {
    let response = if ipm_path {
      admin_ipm::ipm_response(request, state.clone(), &authorization, &method, &path).await
    } else {
      admin::dynamic_policy_response(
        request,
        state.clone(),
        admin_operations.clone(),
        &authorization,
        &method,
        &path,
      )
      .await
    };
    return response.unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"));
  }

  if path == "/admin/v1/upstream-pools"
    || path == "/admin/v1/upstream-pools/status"
    || path.starts_with("/admin/v1/upstream-pools/")
  {
    return admin_upstream_pools_response(
      request,
      state,
      snapshot.as_ref(),
      peer_addr,
      &authorization,
      &method,
      &path,
    )
    .await
    .unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"));
  }

  if path == "/admin/v1/stream-pools"
    || path == "/admin/v1/stream-pools/status"
    || path.starts_with("/admin/v1/stream-pools/")
  {
    return admin_stream_pools_response(
      request,
      state,
      snapshot.as_ref(),
      peer_addr,
      &authorization,
      &method,
      &path,
    )
    .await
    .unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"));
  }

  text_response(StatusCode::NOT_FOUND, "not found")
}

#[derive(Debug, Clone, Copy)]
#[cfg(feature = "admin-runtime")]
pub(super) enum AdminAuditOutcome {
  Applied,
  Rejected,
}

#[cfg(feature = "admin-runtime")]
impl AdminAuditOutcome {
  pub(super) fn as_str(self) -> &'static str {
    match self {
      Self::Applied => "applied",
      Self::Rejected => "rejected",
    }
  }
}

#[cfg(feature = "admin-runtime")]
pub(super) fn admin_audit(
  peer_addr: SocketAddr,
  actor: &AdminActor,
  operation: &'static str,
  pool: Option<&str>,
  server: Option<&str>,
  outcome: AdminAuditOutcome,
  error: Option<&str>,
) {
  info!(
    event = "oxibelt.admin.audit",
    peer = %peer_addr,
    actor = %actor.name,
    principal = %actor.principal,
    groups = ?actor.groups,
    operation,
    pool,
    server,
    outcome = outcome.as_str(),
    error,
    "admin operation audit"
  );
}

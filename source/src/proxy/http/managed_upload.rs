//! Authenticated managed upload HTTP surface. Durable offsets are committed only
//! after an entire bounded part has passed the same route's WAF.

mod protocol;
mod staging;

use super::*;
use crate::config::{UploadDestinationConfig, UploadIdentityKind, UploadProfileConfig};
use crate::uploads::{UploadCreate, UploadOwner, UploadState, UploadStatus, UploadStore};
use sha2::{Digest as _, Sha256};

/// Shared draft-12 parser predicate used when deciding whether transport must
/// preserve live interop-9 informational responses.
pub(super) fn compatible_interop(headers: &http::HeaderMap) -> bool {
  protocol::compatible_interop(headers)
}

/// Strict creation or append tuple used by transparent relay classification.
pub(super) fn relay_request(method: &Method, headers: &http::HeaderMap) -> bool {
  protocol::relay_request(method, headers)
}

#[derive(Clone)]
pub(super) struct VerifiedIpmActor(pub(crate) crate::ipm::IpmActor);

pub(super) fn handles<B>(request: &Request<B>, state: &AppSnapshot, route: &RouteConfig) -> bool {
  let Some(profile) = route.resumable_upload.as_ref().and_then(|name| {
    state
      .config
      .upload_profiles
      .iter()
      .find(|profile| &profile.name == name)
  }) else {
    return false;
  };
  request
    .headers()
    .contains_key("upload-draft-interop-version")
    || (route.upstream.is_none() && route.upstream_pool.is_none())
    || request.headers().contains_key("upload-complete")
    || request
      .uri()
      .path()
      .starts_with(&format!("{}/", profile.control_path_prefix))
    || request
      .uri()
      .path()
      .starts_with(&format!("{}/", profile.object_path_prefix))
    || request.method() == Method::OPTIONS
}

fn owner(
  request: &Request<ProxyBody>,
  profile: &UploadProfileConfig,
  state: &AppSnapshot,
  tls: &WafTlsMetadata,
) -> Result<UploadOwner, StatusCode> {
  let subject = match profile.identity.kind {
    UploadIdentityKind::Ipm => {
      if profile.identity.source != state.ipm.namespace() {
        return Err(StatusCode::FORBIDDEN);
      }
      let actor = &request
        .extensions()
        .get::<VerifiedIpmActor>()
        .ok_or(StatusCode::UNAUTHORIZED)?
        .0;
      // Credential names can rotate without changing the authenticated owner.
      serde_json::to_string(&(&actor.principal, &actor.subject))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    }
    UploadIdentityKind::ExternalAuth => {
      let identity = request
        .extensions()
        .get::<crate::external_auth::VerifiedExternalIdentity>()
        .ok_or(StatusCode::UNAUTHORIZED)?;
      if identity.provider != profile.identity.source {
        return Err(StatusCode::FORBIDDEN);
      }
      identity
        .attributes
        .get(
          profile
            .identity
            .subject_field
            .as_deref()
            .ok_or(StatusCode::UNAUTHORIZED)?,
        )
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or(StatusCode::UNAUTHORIZED)?
    }
    UploadIdentityKind::Mtls => tls
      .client_certificate
      .as_ref()
      .filter(|_| tls.enabled)
      .map(|cert| cert.fingerprint_sha256.clone())
      .ok_or(StatusCode::UNAUTHORIZED)?,
  };
  if subject.is_empty() || subject.len() > 4096 {
    return Err(StatusCode::UNAUTHORIZED);
  }
  Ok(UploadOwner {
    kind: profile.identity.kind,
    source: profile.identity.source.clone(),
    subject,
  })
}

fn binding(
  context: &pipeline::UpstreamContext<'_, '_, '_, '_, '_>,
  profile: &UploadProfileConfig,
) -> serde_json::Value {
  // Persist only a digest of configuration, never provider or upstream secrets.
  // Conservative changes reject continuation rather than migrating authority.
  let mut route = context.resolved.route.clone();
  // Static-file maps are unordered and irrelevant on a managed route.
  route.static_files = Default::default();
  let route_waf = route.waf.stable_policy_projection();
  route.waf = Default::default();
  let ipm = context.state.ipm.snapshot();
  let dynamic_policy = context.state.dynamic_policy.snapshot_identity();
  // These configuration models contain ordered vectors; the route's only map
  // is cleared above. Length-prefix each projection so field contents cannot
  // create concatenation ambiguity, and include mutable policy snapshot IDs.
  let projections = [
    format!("{profile:?}"),
    format!("{route:?}"),
    route_waf,
    context.state.config.waf.stable_policy_projection(),
    format!("crs:{}", context.state.waf.crs_content_fingerprint()),
    format!("{:?}", context.state.config.external_auth),
    format!("{:?}", context.state.config.upstreams),
    format!("{:?}", context.state.config.upload_stores),
    format!("{:?}", context.state.config.ipm),
    format!("{:?}", context.state.config.dynamic_policy),
    format!(
      "{:?}",
      (
        context.state.config.limits.clone(),
        context.state.config.tls.client_auth.clone()
      )
    ),
    format!("ipm:{:016x}", ipm.content_fingerprint()),
    format!("dynamic-policy:{dynamic_policy:?}"),
  ];
  let mut digest = Sha256::new();
  for projection in projections {
    digest.update(
      u64::try_from(projection.len())
        .unwrap_or(u64::MAX)
        .to_be_bytes(),
    );
    digest.update(projection.as_bytes());
  }
  serde_json::json!({"version": 2, "policy_sha256": hex_digest(digest.finalize().as_ref())})
}

fn hex_digest(bytes: &[u8]) -> String {
  bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn url(
  profile: &UploadProfileConfig,
  prefix: &str,
  id: &str,
) -> Result<http::HeaderValue, StatusCode> {
  let mut url = profile.public_base_url.clone();
  url.set_path(&format!("{prefix}/{id}"));
  http::HeaderValue::from_str(url.as_str()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn response(status: StatusCode, upload: Option<&UploadStatus>) -> Response<ProxyBody> {
  // Managed control responses can acquire a streaming or JSON body later.
  // Do not attach the inline-empty optimization used by text_response.
  let mut response = Response::new(body::known_small_no_trailers_body(bytes::Bytes::new()));
  *response.status_mut() = status;
  response.extensions_mut().insert(status_headers::OriginRole);
  response.headers_mut().insert(
    http::header::CACHE_CONTROL,
    http::HeaderValue::from_static("private, no-store"),
  );
  if let Some(upload) = upload {
    protocol::state_headers(
      response.headers_mut(),
      upload.offset,
      matches!(upload.state, UploadState::Complete),
      upload.declared_total,
    );
  }
  response
}

fn storage_status(error: &anyhow::Error) -> StatusCode {
  match error.downcast_ref::<crate::uploads::UploadRejection>() {
    Some(crate::uploads::UploadRejection::NotFound) => StatusCode::NOT_FOUND,
    Some(crate::uploads::UploadRejection::Conflict) => StatusCode::CONFLICT,
    Some(crate::uploads::UploadRejection::Capacity) | None => StatusCode::SERVICE_UNAVAILABLE,
  }
}

fn limit_headers(
  headers: &mut HeaderMap,
  profile: &UploadProfileConfig,
  upload: Option<&UploadStatus>,
) {
  let lifetime = upload.map_or(profile.ttl_seconds, |upload| {
    let now = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .map_or(u64::MAX, |duration| {
        u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
      });
    upload.expires_at_ms.saturating_sub(now) / 1000
  });
  if let Ok(value) = http::HeaderValue::from_str(&format!(
    "max-size={}, max-append-size={}, min-append-size=0, max-age={}",
    profile.max_upload_bytes, profile.max_part_bytes, lifetime
  )) {
    headers.insert("upload-limit", value);
  }
}

async fn inspect(
  context: &mut pipeline::UpstreamContext<'_, '_, '_, '_, '_>,
  captured: Option<&body::CapturedBody>,
  person_proof: Option<&crate::waf::EvaluatedPersonProofRequest>,
  mutation_added: bool,
) -> Result<crate::waf::RequestWafDecision, Response<ProxyBody>> {
  if !context.resolved.execution_plan.waf.request.enabled() {
    return Ok(Default::default());
  }
  context.access_log.ensure_request_ids();
  let mut decision = context
    .state
    .waf
    .evaluate_request_with_person_proof_async(
      WafRequestInput {
        request_id: context.access_log.request_id(),
        transaction_id: context.access_log.transaction_id(),
        received_at_unix_ms: context.access_log.request_received_at_unix_ms,
        method: context.request.method(),
        uri: context.request.uri(),
        version: context.request_version,
        headers: context.request.headers(),
        body: captured.map(waf_body_input),
        peer_addr: context.client_addr,
        client_asn: context.client_asn,
        downstream_host: context.host,
        downstream_scheme: context.downstream_scheme,
        route_name: &context.resolved.route.name,
        tcp_max_hop: context.tcp_max_hop,
        tls: context.tls,
        protocol: context.protocol,
        transport_network: context.transport_network,
        transport_metadata: context.transport_metadata,
        tags: tags_ref(&context.tags),
        dynamic_policy: &context.access_log.dynamic_policy,
      },
      person_proof,
      mutation_added,
    )
    .await;
  if let Some(terminal) = decision.terminal.take() {
    return Err(
      RouteSecurityHeaders::new(&context.state.config.security, context.resolved.route)
        .waf_http_terminal(terminal, &decision.response_header_mutations),
    );
  }
  if decision.upstream_override.is_some() || decision.upstream_pool_override.is_some() {
    return Err(response(StatusCode::FORBIDDEN, None));
  }
  if !decision.tags.is_empty() {
    context
      .tags
      .get_or_insert_with(HashMap::new)
      .extend(decision.tags.iter().cloned());
    context.access_log.set_tags(&context.tags);
  }
  Ok(decision)
}

pub(super) async fn run(
  mut context: pipeline::UpstreamContext<'_, '_, '_, '_, '_>,
  person_proof: Option<&crate::waf::EvaluatedPersonProofRequest>,
  mutation_added: bool,
) -> Response<ProxyBody> {
  let route = context.resolved.route;
  let Some(profile) = context
    .resolved
    .route
    .resumable_upload
    .as_ref()
    .and_then(|name| {
      context
        .state
        .config
        .upload_profiles
        .iter()
        .find(|profile| &profile.name == name)
    })
    .cloned()
  else {
    return response(StatusCode::NOT_FOUND, None);
  };
  let result = execute(&mut context, &profile, person_proof, mutation_added).await;
  match result {
    Outcome::Response(mut result) => {
      result.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("private, no-store"),
      );
      // Error responses can leave a request body unread. Do not reuse H1's
      // framing until the transport has retired that body.
      if matches!(
        context.request_version,
        http::Version::HTTP_10 | http::Version::HTTP_11
      ) && (!context.request.body().is_end_stream()
        || result.status().is_client_error()
        || result.status().is_server_error())
      {
        result.headers_mut().insert(
          http::header::CONNECTION,
          http::HeaderValue::from_static("close"),
        );
      }
      super::response::record_route_digest_removals(&mut result, route);
      with_circuit_breaker_request_lease(result, context.route_circuit_breaker_lease)
    }
    Outcome::Dispatch { store, claim } => {
      let observed = resumable::UpstreamResponseObserved::default();
      context.request.extensions_mut().insert(observed.clone());
      let mut dispatch = DispatchCancellationGuard::new(store, claim);
      let mut result = pipeline::upstream::run(context).await;
      // Only final response headers from the fixed origin prove a definite
      // result. Local responses and transport failures remain indeterminate,
      // regardless of their status code.
      let terminal = if observed.get() {
        crate::uploads::DispatchTerminal::Complete
      } else {
        crate::uploads::DispatchTerminal::Indeterminate
      };
      let status = match dispatch.finish(terminal).await {
        Ok(status) => status,
        Err(_) => {
          let mut response = response(StatusCode::SERVICE_UNAVAILABLE, None);
          super::response::record_route_digest_removals(&mut response, route);
          return response;
        }
      };
      protocol::state_headers(
        result.headers_mut(),
        status.offset,
        status.state == UploadState::Complete,
        Some(status.offset),
      );
      result
    }
  }
}

enum Outcome {
  Response(Response<ProxyBody>),
  Dispatch {
    store: Arc<UploadStore>,
    claim: crate::uploads::DispatchClaim,
  },
}

struct DispatchCancellationGuard {
  store: Option<Arc<UploadStore>>,
  claim: Option<crate::uploads::DispatchClaim>,
}

impl DispatchCancellationGuard {
  fn new(store: Arc<UploadStore>, claim: crate::uploads::DispatchClaim) -> Self {
    Self {
      store: Some(store),
      claim: Some(claim),
    }
  }

  async fn finish(
    &mut self,
    terminal: crate::uploads::DispatchTerminal,
  ) -> anyhow::Result<UploadStatus> {
    let Some(store) = self.store.as_ref() else {
      anyhow::bail!("managed upload dispatch guard is not armed");
    };
    let Some(claim) = self.claim.as_ref() else {
      anyhow::bail!("managed upload dispatch claim is missing");
    };
    let result = store.finish_dispatch(claim, terminal).await;
    if result.is_ok() {
      self.store = None;
      self.claim = None;
    }
    result
  }
}

impl Drop for DispatchCancellationGuard {
  fn drop(&mut self) {
    let (Some(store), Some(claim)) = (self.store.take(), self.claim.take()) else {
      return;
    };
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
      runtime.spawn(async move {
        let _ = store
          .finish_dispatch(&claim, crate::uploads::DispatchTerminal::Indeterminate)
          .await;
      });
    }
  }
}

impl From<Response<ProxyBody>> for Outcome {
  fn from(value: Response<ProxyBody>) -> Self {
    Self::Response(value)
  }
}

async fn execute(
  context: &mut pipeline::UpstreamContext<'_, '_, '_, '_, '_>,
  profile: &UploadProfileConfig,
  person_proof: Option<&crate::waf::EvaluatedPersonProofRequest>,
  mutation_added: bool,
) -> Outcome {
  macro_rules! reject {
    ($status:expr) => {
      return response($status, None).into()
    };
  }
  macro_rules! checked {
    ($value:expr) => {
      match $value {
        Ok(value) => value,
        Err(status) => reject!(status),
      }
    };
  }
  if context.verified_early_data {
    reject!(StatusCode::TOO_EARLY);
  }
  if context.downstream_scheme != "https"
    || profile.public_base_url.host_str() != Some(context.host)
    || profile.public_base_url.port_or_known_default() != Some(context.downstream_port)
  {
    reject!(StatusCode::MISDIRECTED_REQUEST);
  }
  let owner = checked!(owner(&context.request, profile, context.state, context.tls));
  let binding = binding(context, profile);
  let Ok(runtime_profile) = context.state.uploads.profile(&profile.name).cloned() else {
    reject!(StatusCode::SERVICE_UNAVAILABLE);
  };
  let store = runtime_profile.store().clone();
  let path = context.request.uri().path().to_owned();
  let resource = checked!(protocol::resource(
    &path,
    &profile.control_path_prefix,
    &profile.object_path_prefix
  ));
  let method = context.request.method().clone();
  if method == Method::OPTIONS {
    if let Err(result) = inspect(context, None, person_proof, mutation_added).await {
      return result.into();
    }
    let mut result = response(StatusCode::NO_CONTENT, None);
    result.headers_mut().insert(
      "upload-draft-interop-version",
      http::HeaderValue::from_static("9"),
    );
    result.headers_mut().insert(
      http::header::ALLOW,
      http::HeaderValue::from_static("OPTIONS, POST, PUT, PATCH, HEAD, GET, DELETE"),
    );
    limit_headers(result.headers_mut(), profile, None);
    return result.into();
  }
  let creation = matches!(resource, protocol::Resource::Creation);
  if !creation && method != Method::PATCH {
    return control(
      context,
      profile,
      &store,
      &owner,
      &binding,
      resource,
      person_proof,
      mutation_added,
    )
    .await
    .into();
  }
  if creation && !protocol::creation_method(&method) {
    reject!(StatusCode::METHOD_NOT_ALLOWED);
  }
  if !creation && !matches!(resource, protocol::Resource::Upload(_)) {
    reject!(StatusCode::METHOD_NOT_ALLOWED);
  }
  checked!(protocol::negotiate(context.request.headers()));
  checked!(protocol::identity_encoding(context.request.headers()));
  let complete = checked!(protocol::completion(context.request.headers()));
  let declared = checked!(protocol::integer(
    context.request.headers(),
    "upload-length"
  ));
  if declared.is_some_and(|length| length > profile.max_upload_bytes) {
    reject!(StatusCode::PAYLOAD_TOO_LARGE);
  }
  let length = context
    .request
    .headers()
    .get(http::header::CONTENT_LENGTH)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.parse::<u64>().ok());
  if length.is_some_and(|length| length > profile.max_part_bytes) {
    reject!(StatusCode::PAYLOAD_TOO_LARGE);
  }
  let requested_offset = if creation {
    0
  } else {
    checked!(protocol::validate_append(context.request.headers()))
  };
  if creation
    && checked!(protocol::integer(
      context.request.headers(),
      "upload-offset"
    ))
    .is_some_and(|offset| offset != 0)
  {
    reject!(StatusCode::BAD_REQUEST);
  }
  if complete
    && let (Some(total), Some(length)) = (declared, length)
    && requested_offset.checked_add(length) != Some(total)
  {
    reject!(StatusCode::BAD_REQUEST);
  }
  let need = context.resolved.execution_plan.waf.request.body_need() != BodyNeed::None;
  let _inspection_admission = if need {
    match context
      .state
      .circuit_breakers
      .admit_body_inspection(&context.resolved.route.name, None)
      .await
    {
      Ok(lease) => Some(lease),
      Err(rejection) => return circuit_breaker_rejection_response(context.state, rejection).into(),
    }
  } else {
    None
  };
  let _create_admission = if creation {
    match runtime_profile.try_admit_create() {
      Ok(permit) => Some(permit),
      Err(_) => reject!(StatusCode::SERVICE_UNAVAILABLE),
    }
  } else {
    None
  };
  let part_admission =
    match runtime_profile.try_admit_part(length.unwrap_or(profile.max_part_bytes).max(1)) {
      Ok(permit) => permit,
      Err(_) => reject!(StatusCode::SERVICE_UNAVAILABLE),
    };
  let mut upload = if creation {
    let safe_headers = serde_json::json!({"content-type": context.request.headers().get(http::header::CONTENT_TYPE).and_then(|value| value.to_str().ok())});
    match store
      .create(UploadCreate {
        profile: profile.clone(),
        owner: owner.clone(),
        binding: binding.clone(),
        method: method.clone(),
        uri: context.request.uri().clone(),
        safe_headers,
        declared_total: declared,
      })
      .await
    {
      Ok(upload) => upload,
      Err(_) => reject!(StatusCode::SERVICE_UNAVAILABLE),
    }
  } else {
    let protocol::Resource::Upload(id) = resource else {
      reject!(StatusCode::NOT_FOUND);
    };
    match store.lookup(id, &owner, &binding).await {
      Ok(upload) => upload,
      Err(error) => reject!(storage_status(&error)),
    }
  };
  let resume_completion = complete
    && (length == Some(0) || context.request.body().is_end_stream())
    && matches!(upload.state, UploadState::Completing | UploadState::Ready);
  if requested_offset != upload.offset
    || (upload.state != UploadState::Active && !resume_completion)
  {
    return response(StatusCode::CONFLICT, Some(&upload)).into();
  }
  if declared.is_some() && upload.declared_total.is_some() && declared != upload.declared_total {
    reject!(StatusCode::BAD_REQUEST);
  }
  if let Some(declared) = declared
    && upload.declared_total.is_none()
  {
    if store
      .declare_length(&upload.id, &owner, &binding, declared)
      .await
      .is_err()
    {
      reject!(StatusCode::BAD_REQUEST);
    }
    upload.declared_total = Some(declared);
  }
  let has_part = length != Some(0) && !context.request.body().is_end_stream();
  let reservation = if has_part {
    let reserve = length.unwrap_or(
      profile
        .max_part_bytes
        .min(profile.max_upload_bytes.saturating_sub(upload.offset))
        .min(
          upload
            .declared_total
            .unwrap_or(u64::MAX)
            .saturating_sub(upload.offset),
        ),
    );
    if reserve == 0 {
      None
    } else {
      match store
        .begin_append(&upload.id, &owner, &binding, upload.offset, reserve)
        .await
      {
        Ok(reservation) => Some(reservation),
        Err(error) => return response(storage_status(&error), Some(&upload)).into(),
      }
    }
  } else {
    None
  };
  if creation {
    let mut head = Response::new(());
    *head.status_mut() = StatusCode::from_u16(104).unwrap_or(StatusCode::CONTINUE);
    protocol::state_headers(head.headers_mut(), 0, false, upload.declared_total);
    head.headers_mut().insert(
      http::header::LOCATION,
      checked!(url(profile, &profile.control_path_prefix, &upload.id)),
    );
    limit_headers(head.headers_mut(), profile, Some(&upload));
    if informational::send(context.request.extensions(), head).is_err() {
      if let Some(reservation) = &reservation {
        let _ = store.abort_append(reservation).await;
      }
      reject!(StatusCode::BAD_GATEWAY);
    }
  }
  let body = std::mem::replace(
    context.request.body_mut(),
    body::known_small_no_trailers_body(bytes::Bytes::new()),
  );
  let maximum = reservation
    .as_ref()
    .map_or(length.unwrap_or(0), |reservation| reservation.length);
  let mut staged = match staging::Spool::read_body(body, profile, need, maximum).await {
    Ok(staged) => staged,
    Err(status) => {
      if let Some(reservation) = &reservation {
        let _ = store.abort_append(reservation).await;
      }
      reject!(status);
    }
  };
  let decision = match inspect(
    context,
    staged.capture.as_ref(),
    person_proof,
    mutation_added,
  )
  .await
  {
    Ok(decision) => decision,
    Err(result) => {
      if let Some(reservation) = &reservation {
        let _ = store.abort_append(reservation).await;
      }
      return result.into();
    }
  };
  if let Some(reservation) = &reservation {
    if staged.bytes == 0 {
      if store.abort_append(reservation).await.is_err() {
        reject!(StatusCode::SERVICE_UNAVAILABLE);
      }
    } else {
      let evidence = crate::uploads::InspectedPart {
        bytes: staged.bytes,
        sha256: staged.digest.clone(),
      };
      let stream = checked!(staged.stream().await);
      upload = match store
        .commit_fully_inspected_part(reservation, &evidence, stream)
        .await
      {
        Ok(upload) => upload,
        Err(_) => {
          let _ = store.abort_append(reservation).await;
          reject!(StatusCode::SERVICE_UNAVAILABLE);
        }
      };
    }
  } else if staged.bytes != 0 {
    reject!(StatusCode::BAD_REQUEST);
  }
  drop(staged);
  drop(part_admission);
  if !complete {
    let mut result = response(
      if creation {
        StatusCode::CREATED
      } else {
        StatusCode::NO_CONTENT
      },
      Some(&upload),
    );
    if creation {
      result.headers_mut().insert(
        http::header::LOCATION,
        checked!(url(profile, &profile.control_path_prefix, &upload.id)),
      );
    }
    limit_headers(result.headers_mut(), profile, Some(&upload));
    super::response::apply_response_header_mutations(
      &mut result,
      &decision.response_header_mutations,
    );
    protocol::state_headers(
      result.headers_mut(),
      upload.offset,
      false,
      upload.declared_total,
    );
    if creation {
      result.headers_mut().insert(
        http::header::LOCATION,
        checked!(url(profile, &profile.control_path_prefix, &upload.id)),
      );
    }
    return result.into();
  }
  complete_upload(
    context,
    profile,
    store,
    owner,
    binding,
    upload,
    person_proof,
    mutation_added,
  )
  .await
}

#[allow(clippy::too_many_arguments)]
async fn control(
  context: &mut pipeline::UpstreamContext<'_, '_, '_, '_, '_>,
  profile: &UploadProfileConfig,
  store: &UploadStore,
  owner: &UploadOwner,
  binding: &serde_json::Value,
  resource: protocol::Resource<'_>,
  person_proof: Option<&crate::waf::EvaluatedPersonProofRequest>,
  mutation_added: bool,
) -> Response<ProxyBody> {
  let id = match resource {
    protocol::Resource::Upload(id)
    | protocol::Resource::Status(id)
    | protocol::Resource::Object(id) => id,
    protocol::Resource::Creation => return response(StatusCode::METHOD_NOT_ALLOWED, None),
  };
  if !context.request.body().is_end_stream()
    && context
      .request
      .headers()
      .get(http::header::CONTENT_LENGTH)
      .is_none_or(|value| value != "0")
  {
    return response(StatusCode::BAD_REQUEST, None);
  }
  if let Err(result) = inspect(
    context,
    Some(&body::CapturedBody {
      bytes: bytes::Bytes::new(),
      is_truncated: false,
    }),
    person_proof,
    mutation_added,
  )
  .await
  {
    return result;
  }
  let upload = match store.lookup(id, owner, binding).await {
    Ok(upload) => upload,
    Err(error) => return response(storage_status(&error), None),
  };
  if context.request.method() == Method::DELETE {
    return match store.delete(id, owner, binding).await {
      Ok(()) => response(StatusCode::NO_CONTENT, None),
      Err(error) => response(storage_status(&error), None),
    };
  }
  if !matches!(*context.request.method(), Method::GET | Method::HEAD) {
    return response(StatusCode::METHOD_NOT_ALLOWED, None);
  }
  if matches!(resource, protocol::Resource::Object(_)) {
    if profile.destination != UploadDestinationConfig::Object
      || upload.state != UploadState::Complete
    {
      return response(StatusCode::NOT_FOUND, None);
    }
    let mut result = response(StatusCode::OK, None);
    protocol::set_integer(result.headers_mut(), "content-length", upload.offset);
    result.headers_mut().insert(
      http::header::CONTENT_TYPE,
      http::HeaderValue::from_static("application/octet-stream"),
    );
    result.headers_mut().insert(
      http::header::CONTENT_DISPOSITION,
      http::HeaderValue::from_static("attachment"),
    );
    result.headers_mut().insert(
      http::header::X_CONTENT_TYPE_OPTIONS,
      http::HeaderValue::from_static("nosniff"),
    );
    if context.request.method() == Method::GET {
      let Ok(runtime) = context.state.uploads.profile(&profile.name) else {
        return response(StatusCode::SERVICE_UNAVAILABLE, None);
      };
      let Ok(_admission) = runtime.try_admit_part(upload.offset.max(1)) else {
        return response(StatusCode::SERVICE_UNAVAILABLE, None);
      };
      let stream = match store.read_object(id, owner, binding).await {
        Ok(stream) => stream,
        Err(_) => return response(StatusCode::SERVICE_UNAVAILABLE, None),
      };
      let spool = match staging::Spool::read_stream(stream, profile, false).await {
        Ok(spool) if spool.bytes == upload.offset => spool,
        Ok(_) => return response(StatusCode::SERVICE_UNAVAILABLE, None),
        Err(status) => return response(status, None),
      };
      // Keep disk quota reserved until the response body is retired.
      *result.body_mut() = staging::hold_admission(spool.into_body(), _admission);
    }
    return result;
  }
  let mut result = response(StatusCode::NO_CONTENT, Some(&upload));
  if matches!(resource, protocol::Resource::Status(_)) {
    *result.status_mut() = StatusCode::OK;
    result.headers_mut().insert(
      http::header::CONTENT_TYPE,
      http::HeaderValue::from_static("application/json"),
    );
    let public_status = serde_json::json!({"offset": upload.offset, "state": upload.state,
      "length": upload.declared_total, "expires_at_ms": upload.expires_at_ms});
    if let Ok(bytes) = serde_json::to_vec(&public_status) {
      protocol::set_integer(result.headers_mut(), "content-length", bytes.len() as u64);
      if context.request.method() == Method::GET {
        *result.body_mut() = body::known_small_no_trailers_body(bytes.into());
      }
    }
  }
  limit_headers(result.headers_mut(), profile, Some(&upload));
  result
}

#[allow(clippy::too_many_arguments)]
async fn complete_upload(
  context: &mut pipeline::UpstreamContext<'_, '_, '_, '_, '_>,
  profile: &UploadProfileConfig,
  store: Arc<UploadStore>,
  owner: UploadOwner,
  binding: serde_json::Value,
  mut upload: UploadStatus,
  person_proof: Option<&crate::waf::EvaluatedPersonProofRequest>,
  mutation_added: bool,
) -> Outcome {
  macro_rules! reject {
    ($status:expr) => {
      return response($status, Some(&upload)).into()
    };
  }
  if upload
    .declared_total
    .is_some_and(|length| length != upload.offset)
  {
    reject!(StatusCode::BAD_REQUEST);
  }
  if upload.declared_total.is_none() {
    if store
      .declare_length(&upload.id, &owner, &binding, upload.offset)
      .await
      .is_err()
    {
      reject!(StatusCode::SERVICE_UNAVAILABLE);
    }
    upload.declared_total = Some(upload.offset);
  }
  let Ok(runtime) = context.state.uploads.profile(&profile.name) else {
    reject!(StatusCode::SERVICE_UNAVAILABLE);
  };
  let Ok(admission) = runtime.try_admit_part(upload.offset.max(1)) else {
    reject!(StatusCode::SERVICE_UNAVAILABLE);
  };
  let metadata = match store.request_metadata(&upload.id, &owner, &binding).await {
    Ok(metadata) => metadata,
    Err(error) => reject!(storage_status(&error)),
  };
  // Reconstruct only the original target and safe representation metadata. All
  // credentials come from this freshly authenticated completion request.
  *context.request.method_mut() = metadata.method.clone();
  *context.request.uri_mut() = metadata.uri.clone();
  context.request_method = metadata.method;
  context.request_uri = metadata.uri;
  for header in [
    "upload-complete",
    "upload-offset",
    "upload-length",
    "upload-draft-interop-version",
    "upload-limit",
    "content-length",
    "content-type",
    "content-encoding",
    "transfer-encoding",
    "trailer",
    "expect",
  ] {
    context.request.headers_mut().remove(header);
  }
  if let Some(content_type) = metadata
    .safe_headers
    .get("content-type")
    .and_then(|value| value.as_str())
    && let Ok(value) = http::HeaderValue::from_str(content_type)
  {
    context
      .request
      .headers_mut()
      .insert(http::header::CONTENT_TYPE, value);
  }
  protocol::set_integer(
    context.request.headers_mut(),
    "content-length",
    upload.offset,
  );
  if context.state.request_path_features.dynamic_policy {
    let decision = context
      .state
      .dynamic_policy
      .evaluate_async(
        DynamicPolicyRequest {
          client_ip: context.client_addr.ip(),
          route_name: &context.resolved.route.name,
          method: context.request.method(),
          path: context.request.uri().path(),
          headers: Some(context.request.headers()),
          tls_fingerprint: context.tls.fingerprint.as_deref(),
          client_asn: context.client_asn,
          tcp_max_hop: context.tcp_max_hop,
          person_proof_clearance_hash: person_proof.and_then(|proof| proof.clearance_hash()),
        },
        &context.state.limits,
      )
      .await;
    context.access_log.dynamic_policy = decision.context;
    if let Some(terminal) = decision.terminal {
      return match terminal {
        DynamicPolicyTerminal::Text { status, body } => text_response(status, &body).into(),
        DynamicPolicyTerminal::SilentClose => silent_close_response().into(),
        DynamicPolicyTerminal::Challenge { .. } => {
          response(StatusCode::FORBIDDEN, Some(&upload)).into()
        }
      };
    }
  }
  if context.resolved.execution_plan.features.ipm {
    let Some(actor) = context
      .state
      .ipm
      .actor_from_headers(context.request.headers())
    else {
      reject!(StatusCode::UNAUTHORIZED);
    };
    let request_context = IpmRequestContext {
      source_ip: Some(context.client_addr.ip()),
      method: Some(context.request.method().to_string()),
      host: Some(context.host.to_owned()),
      path: Some(context.request.uri().path().to_owned()),
      route: Some(context.resolved.route.name.clone()),
      protocol: Some(format!("{:?}", context.request_version)),
      claims: HashMap::new(),
    };
    if context.state.ipm.authorize(
      &actor,
      context
        .resolved
        .route
        .ipm
        .action
        .as_deref()
        .unwrap_or("route:Invoke"),
      &ipm_resource(
        context.state.ipm.namespace(),
        "route",
        &context.resolved.route.name,
      ),
      &request_context,
    ) != IpmDecision::Allow
    {
      reject!(StatusCode::FORBIDDEN);
    }
    context
      .request
      .extensions_mut()
      .insert(VerifiedIpmActor(actor));
  }
  let need = context.resolved.execution_plan.waf.request.body_need() != BodyNeed::None;
  let stream = match store.read_assembled(&upload.id, &owner, &binding).await {
    Ok(stream) => stream,
    Err(_) => reject!(StatusCode::SERVICE_UNAVAILABLE),
  };
  let spool = match staging::Spool::read_stream(stream, profile, need).await {
    Ok(spool) if spool.bytes == upload.offset => spool,
    Ok(_) => reject!(StatusCode::SERVICE_UNAVAILABLE),
    Err(status) => reject!(status),
  };
  let captured = spool.capture.clone();
  *context.request.body_mut() = staging::hold_admission(spool.into_body(), admission);
  if let Some(provider) = context.resolved.route.external_auth.as_deref() {
    match context
      .state
      .external_auth
      .authorize_http(
        provider,
        &mut context.request,
        context.client_addr.ip(),
        context.host,
        context.downstream_scheme,
        &context.resolved.route.name,
        usize::try_from(profile.max_upload_bytes).unwrap_or(usize::MAX),
        None,
      )
      .await
    {
      ExternalAuthOutcome::Allowed => {}
      ExternalAuthOutcome::Denied(terminal) => return external_auth_response(terminal).into(),
    }
  }
  match self::owner(&context.request, profile, context.state, context.tls) {
    Ok(current) if current == owner => {}
    _ => reject!(StatusCode::FORBIDDEN),
  }
  context.request_waf =
    match inspect(context, captured.as_ref(), person_proof, mutation_added).await {
      Ok(decision) => decision,
      Err(result) => return result.into(),
    };
  context.captured_body = captured;
  context
    .request
    .extensions_mut()
    .insert(resumable::NoReplayRequest);
  context
    .request
    .extensions_mut()
    .insert(incremental::BodyWasBuffered);
  if upload.state == UploadState::Active {
    upload = match store
      .claim_complete(&upload.id, &owner, &binding, upload.offset)
      .await
    {
      Ok(upload) => upload,
      Err(error) => reject!(storage_status(&error)),
    };
  }
  match profile.destination {
    UploadDestinationConfig::Object => {
      upload = match store.publish_object(&upload.id, &owner, &binding).await {
        Ok(upload) => upload,
        Err(_) => reject!(StatusCode::SERVICE_UNAVAILABLE),
      };
      let mut result = response(StatusCode::CREATED, Some(&upload));
      if let Ok(location) = url(profile, &profile.object_path_prefix, &upload.id) {
        result
          .headers_mut()
          .insert(http::header::LOCATION, location);
      }
      super::response::apply_response_header_mutations(
        &mut result,
        &context.request_waf.response_header_mutations,
      );
      protocol::state_headers(
        result.headers_mut(),
        upload.offset,
        true,
        Some(upload.offset),
      );
      if let Ok(location) = url(profile, &profile.object_path_prefix, &upload.id) {
        result
          .headers_mut()
          .insert(http::header::LOCATION, location);
      }
      result.into()
    }
    UploadDestinationConfig::Upstream { ref upstream } => {
      // The same assembly is made durable before obtaining the irreversible
      // dispatch claim. A crash after the claim is never automatically retried.
      if upload.state != UploadState::Ready
        && store
          .publish_object(&upload.id, &owner, &binding)
          .await
          .is_err()
      {
        reject!(StatusCode::SERVICE_UNAVAILABLE);
      }
      context.request_waf.upstream_override = Some(upstream.clone());
      match store.begin_dispatch(&upload.id, &owner, &binding).await {
        Ok(claim) => Outcome::Dispatch { store, claim },
        Err(_) => response(StatusCode::CONFLICT, Some(&upload)).into(),
      }
    }
  }
}

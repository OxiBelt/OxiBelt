//! Source-bound TURN authentication and response integrity helpers.

use super::*;

#[derive(Clone, Copy)]
pub(super) enum EdgeRequestFailure {
  AllocationMismatch,
  Turn(u16, &'static str),
}

impl EdgeRequestFailure {
  pub(super) async fn send(
    self,
    sender: &EdgeSender,
    request_type: u16,
    transaction_id: [u8; 12],
    auth: &AuthenticatedContext,
  ) -> anyhow::Result<()> {
    let (code, reason) = match self {
      Self::AllocationMismatch => (437, "Allocation Mismatch"),
      Self::Turn(code, reason) => (code, reason),
    };
    send(
      sender,
      encode_authenticated_error(auth, request_type, transaction_id, code, reason),
    )
    .await
  }
}

pub(super) fn encode_unknown_attribute_error(
  message: &StunMessage<'_>,
  unknown: &[u16],
  auth: Option<&AuthenticatedContext>,
) -> Vec<u8> {
  let attrs = vec![
    (ATTR_ERROR_CODE, encode_error_code(420, "Unknown Attribute")),
    (ATTR_UNKNOWN_ATTRIBUTES, encode_unknown_attributes(unknown)),
    (ATTR_SOFTWARE, SOFTWARE_VALUE.to_vec()),
  ];
  let response = encode_message(
    error_type(message.message_type),
    message.transaction_id,
    &attrs,
  );
  match auth {
    Some(context) => with_fingerprint(context.with_response_integrity(response)),
    None => with_fingerprint(response),
  }
}

pub(super) async fn authenticate_request(
  config: &WebRtcTurnListenerConfig,
  message: &StunMessage<'_>,
  client: EdgeClient,
  sender: &EdgeSender,
) -> anyhow::Result<Option<Arc<AuthenticatedContext>>> {
  match request_authentication(config, message, client)? {
    RequestAuthentication::Pass(context) => Ok(Some(context)),
    RequestAuthentication::Challenge(response) => {
      send(sender, response).await?;
      Ok(None)
    }
  }
}

pub(super) fn authenticated_context_if_present(
  config: &WebRtcTurnListenerConfig,
  message: &StunMessage<'_>,
  client: EdgeClient,
) -> anyhow::Result<Option<AuthenticatedContext>> {
  let source = NonceSourceBinding::from_peer(client.peer());
  Ok(
    match auth::authenticated_context_for_source(
      &config.auth,
      &config.realm,
      Some(source),
      message,
    )? {
      AuthenticatedContextDecision::Pass(context) => Some(context),
      _ => None,
    },
  )
}

pub(super) enum RequestAuthentication {
  Pass(Arc<AuthenticatedContext>),
  Challenge(Vec<u8>),
}

pub(super) fn request_authentication(
  config: &WebRtcTurnListenerConfig,
  message: &StunMessage<'_>,
  client: EdgeClient,
) -> anyhow::Result<RequestAuthentication> {
  let source = NonceSourceBinding::from_peer(client.peer());
  match auth::enforce_authenticated_context_for_source(
    &config.auth,
    &config.realm,
    source,
    message,
  )? {
    AuthenticatedContextDecision::Pass(context) => {
      Ok(RequestAuthentication::Pass(Arc::new(context)))
    }
    AuthenticatedContextDecision::PassThrough => {
      anyhow::bail!("TURN edge authentication unexpectedly allowed pass-through")
    }
    decision => {
      let (code, reason) = authentication_failure_status(&decision);
      let context = match decision {
        AuthenticatedContextDecision::BadRequestAuthenticated(context)
        | AuthenticatedContextDecision::StaleNonce(context) => Some(context),
        AuthenticatedContextDecision::BadRequest
        | AuthenticatedContextDecision::Missing
        | AuthenticatedContextDecision::Invalid => None,
        _ => unreachable!("handled authenticated decisions above"),
      };
      let nonce = if matches!(code, 401 | 438) {
        Some(auth::create_nonce_for_source(
          &config.realm,
          source,
          &config.auth,
        )?)
      } else {
        None
      };
      Ok(RequestAuthentication::Challenge(encode_auth_response(
        config,
        message.message_type,
        message.transaction_id,
        code,
        reason,
        nonce.as_deref(),
        context.as_ref(),
      )))
    }
  }
}

fn authentication_failure_status(decision: &AuthenticatedContextDecision) -> (u16, &'static str) {
  match decision {
    AuthenticatedContextDecision::BadRequest
    | AuthenticatedContextDecision::BadRequestAuthenticated(_) => (400, "Bad Request"),
    AuthenticatedContextDecision::StaleNonce(_) => (438, "Stale Nonce"),
    AuthenticatedContextDecision::Missing | AuthenticatedContextDecision::Invalid => {
      (401, "Unauthenticated")
    }
    AuthenticatedContextDecision::Pass(_) | AuthenticatedContextDecision::PassThrough => {
      unreachable!("authenticated decision cannot be a failure")
    }
  }
}

fn encode_auth_response(
  config: &WebRtcTurnListenerConfig,
  request_type: u16,
  transaction_id: [u8; 12],
  code: u16,
  reason: &str,
  nonce: Option<&str>,
  context: Option<&AuthenticatedContext>,
) -> Vec<u8> {
  let mut attrs = vec![(ATTR_ERROR_CODE, encode_error_code(code, reason))];
  if let Some(nonce) = nonce {
    attrs.push((ATTR_REALM, config.realm.as_bytes().to_vec()));
    attrs.push((ATTR_NONCE, nonce.as_bytes().to_vec()));
    attrs.push(auth::password_algorithms_challenge_attribute(&config.auth));
  }
  attrs.push((ATTR_SOFTWARE, SOFTWARE_VALUE.to_vec()));
  let message = encode_message(error_type(request_type), transaction_id, &attrs);
  with_fingerprint(match context {
    Some(context) => context.with_response_integrity(message),
    None => message,
  })
}

pub(super) fn encode_authenticated_success(
  auth: &AuthenticatedContext,
  request_type: u16,
  transaction_id: [u8; 12],
  attrs: &[(u16, Vec<u8>)],
) -> Vec<u8> {
  let mut attrs = attrs.to_vec();
  attrs.push((ATTR_SOFTWARE, SOFTWARE_VALUE.to_vec()));
  with_fingerprint(auth.with_response_integrity(encode_message(
    success_type(request_type),
    transaction_id,
    &attrs,
  )))
}

pub(super) fn encode_authenticated_error(
  auth: &AuthenticatedContext,
  request_type: u16,
  transaction_id: [u8; 12],
  code: u16,
  reason: &str,
) -> Vec<u8> {
  with_fingerprint(auth.with_response_integrity(encode_message(
    error_type(request_type),
    transaction_id,
    &[
      (ATTR_ERROR_CODE, encode_error_code(code, reason)),
      (ATTR_SOFTWARE, SOFTWARE_VALUE.to_vec()),
    ],
  )))
}

pub(super) async fn send_authenticated_error(
  sender: &EdgeSender,
  auth: &AuthenticatedContext,
  request_type: u16,
  transaction_id: [u8; 12],
  code: u16,
  reason: &str,
) -> anyhow::Result<()> {
  send(
    sender,
    encode_authenticated_error(auth, request_type, transaction_id, code, reason),
  )
  .await
}

fn encode_error_code(code: u16, reason: &str) -> Vec<u8> {
  let mut value = vec![0, 0, (code / 100) as u8, (code % 100) as u8];
  value.extend_from_slice(reason.as_bytes());
  value
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn malformed_and_unauthenticated_requests_use_distinct_statuses() {
    assert_eq!(
      authentication_failure_status(&AuthenticatedContextDecision::BadRequest),
      (400, "Bad Request")
    );
    assert_eq!(
      authentication_failure_status(&AuthenticatedContextDecision::Missing),
      (401, "Unauthenticated")
    );
    assert_eq!(
      authentication_failure_status(&AuthenticatedContextDecision::Invalid),
      (401, "Unauthenticated")
    );
  }
}

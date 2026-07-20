//! Object-member projection for request, response, and stream contexts.

use super::*;

pub(super) fn eval_member(
  value: Value,
  field: &str,
  ctx: &EvalContext<'_>,
) -> anyhow::Result<Value> {
  if let Value::StringList(list) = value {
    return eval_string_list_member(list, field);
  }
  if let Value::BodyScanResult(result) = value {
    return eval_body_scan_result_member(result, field);
  }

  let object = match value {
    Value::Object(object) => object,
    Value::Null => bail!("attempted to access {field} on null"),
    _ => bail!("cannot access member {field} on {:?}", value),
  };

  match (object, field) {
    (ObjectRef::Context, "Phase") => Ok(Value::String(ctx.phase.as_str().to_string())),
    (ObjectRef::Context, "RuleName") => Ok(Value::String(ctx.rule_name.to_string())),
    (ObjectRef::Context, "RuleId") => Ok(
      ctx
        .rule_id
        .map(|id| Value::String(id.to_string()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::Context, "RuleTags") => Ok(Value::Object(ObjectRef::ContextRuleTags)),
    (ObjectRef::Context, "RouteName") => Ok(if ctx.request.route_name.is_empty() {
      Value::Null
    } else {
      Value::String(ctx.request.route_name.to_string())
    }),
    (ObjectRef::Context, "TransactionId") => {
      Ok(Value::String(ctx.request.transaction_id.to_string()))
    }
    (ObjectRef::Context, "Mode") => Ok(Value::String(ctx.mode.as_str().to_string())),
    (ObjectRef::DynamicPolicy, "Matched") => Ok(Value::Bool(ctx.request.dynamic_policy.matched)),
    (ObjectRef::DynamicPolicy, "Action") => {
      Ok(optional_string_value(&ctx.request.dynamic_policy.action))
    }
    (ObjectRef::DynamicPolicy, "Name") => {
      Ok(optional_string_value(&ctx.request.dynamic_policy.name))
    }
    (ObjectRef::DynamicPolicy, "Reason") => {
      Ok(optional_string_value(&ctx.request.dynamic_policy.reason))
    }
    (ObjectRef::DynamicPolicy, "Code") => {
      Ok(optional_string_value(&ctx.request.dynamic_policy.code))
    }
    (ObjectRef::DynamicPolicy, "Mode") => {
      Ok(optional_string_value(&ctx.request.dynamic_policy.mode))
    }
    (ObjectRef::DynamicPolicy, "Source") => {
      Ok(optional_string_value(&ctx.request.dynamic_policy.source))
    }
    (ObjectRef::Stream, "Protocol") => Ok(Value::String(
      ctx
        .stream
        .context("missing stream context")?
        .protocol
        .as_str()
        .to_string(),
    )),
    (ObjectRef::Stream, "Direction") => Ok(Value::String(
      ctx
        .stream
        .context("missing stream context")?
        .direction
        .as_str()
        .to_string(),
    )),
    (ObjectRef::Stream, "Unit") => Ok(Value::String(
      ctx
        .stream
        .context("missing stream context")?
        .unit
        .as_str()
        .to_string(),
    )),
    (ObjectRef::Stream, "Payload") => Ok(Value::Object(ObjectRef::StreamPayload)),
    (ObjectRef::Stream, "WebSocket") => {
      if ctx
        .stream
        .context("missing stream context")?
        .websocket
        .is_some()
      {
        Ok(Value::Object(ObjectRef::StreamWebSocket))
      } else {
        Ok(Value::Null)
      }
    }
    (ObjectRef::Stream, "WebTransport") => {
      if ctx
        .stream
        .context("missing stream context")?
        .webtransport
        .is_some()
      {
        Ok(Value::Object(ObjectRef::StreamWebTransport))
      } else {
        Ok(Value::Null)
      }
    }
    (ObjectRef::StreamPayload, "Size") => Ok(Value::Int(
      ctx
        .stream
        .context("missing stream context")?
        .payload
        .bytes
        .len() as i64,
    )),
    (ObjectRef::StreamPayload, "IsTruncated") => Ok(Value::Bool(
      ctx
        .stream
        .context("missing stream context")?
        .payload
        .is_truncated,
    )),
    (ObjectRef::StreamPayload, "Bytes") => Ok(Value::Bytes(
      ctx
        .stream
        .context("missing stream context")?
        .payload
        .bytes
        .to_vec(),
    )),
    (ObjectRef::StreamPayload, "Text") => {
      let body = ctx.stream.context("missing stream context")?.payload;
      Ok(Value::String(
        ctx
          .body_text_caches
          .text(BodyTextSlot::Stream, body)
          .to_string(),
      ))
    }
    (ObjectRef::StreamWebSocket, "Opcode") => Ok(Value::String(
      ctx
        .stream
        .and_then(|stream| stream.websocket)
        .context("missing WebSocket stream context")?
        .opcode
        .to_string(),
    )),
    (ObjectRef::StreamWebSocket, "Fin") => Ok(Value::Bool(
      ctx
        .stream
        .and_then(|stream| stream.websocket)
        .context("missing WebSocket stream context")?
        .fin,
    )),
    (ObjectRef::StreamWebSocket, "IsControl") => Ok(Value::Bool(
      ctx
        .stream
        .and_then(|stream| stream.websocket)
        .context("missing WebSocket stream context")?
        .is_control,
    )),
    (ObjectRef::StreamWebSocket, "MessageOpcode") => Ok(
      ctx
        .stream
        .and_then(|stream| stream.websocket)
        .context("missing WebSocket stream context")?
        .message_opcode
        .map(|opcode| Value::String(opcode.to_string()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::StreamWebSocket, "FramePayloadSize") => Ok(Value::Int(
      ctx
        .stream
        .and_then(|stream| stream.websocket)
        .context("missing WebSocket stream context")?
        .frame_payload_size as i64,
    )),
    (ObjectRef::StreamWebTransport, "StreamKind") => Ok(
      ctx
        .stream
        .and_then(|stream| stream.webtransport)
        .context("missing WebTransport stream context")?
        .stream_kind
        .map(|kind| Value::String(kind.as_str().to_string()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::StreamWebTransport, "StreamId") => Ok(
      ctx
        .stream
        .and_then(|stream| stream.webtransport)
        .context("missing WebTransport stream context")?
        .stream_id
        .and_then(|id| i64::try_from(id).ok())
        .map(Value::Int)
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::StreamWebTransport, "DatagramSize") => Ok(
      ctx
        .stream
        .and_then(|stream| stream.webtransport)
        .context("missing WebTransport stream context")?
        .datagram_size
        .map(|size| Value::Int(size as i64))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::Request, "Id") => Ok(Value::String(ctx.request.request_id.to_string())),
    (ObjectRef::Request, "ReceivedAtUnixMs") => Ok(Value::Int(
      i64::try_from(ctx.request.received_at_unix_ms).unwrap_or(i64::MAX),
    )),
    (ObjectRef::Request, "Protocol") => {
      Ok(Value::String(ctx.request.protocol.as_str().to_string()))
    }
    (ObjectRef::Request, "Client") => Ok(Value::Object(ObjectRef::RequestClient)),
    (ObjectRef::Request, "Transport") => Ok(Value::Object(ObjectRef::RequestTransport)),
    (ObjectRef::Request, "Http") => Ok(Value::Object(ObjectRef::RequestHttp)),
    (ObjectRef::Request, "Normalized") => Ok(Value::Object(ObjectRef::RequestNormalized)),
    (ObjectRef::Request, "Headers") => Ok(Value::Object(ObjectRef::RequestHeaders)),
    (ObjectRef::Request, "QueryParams") => Ok(Value::Object(ObjectRef::RequestQueryParams)),
    (ObjectRef::Request, "Cookies") => Ok(Value::Object(ObjectRef::RequestCookies)),
    (ObjectRef::Request, "Body") => Ok(Value::Object(ObjectRef::RequestBody)),
    (ObjectRef::Request, "Tags") => Ok(Value::Object(ObjectRef::RequestTags)),
    (ObjectRef::Request, "Tls") => Ok(Value::Object(ObjectRef::RequestTls)),
    (ObjectRef::Request, "TokenBindings") => Ok(Value::Object(ObjectRef::RequestTokenBindings)),
    (ObjectRef::RequestClient, "Kind") => Ok(Value::String(
      if ctx.person_proof.state == PersonProofState::Valid {
        "person"
      } else {
        "unknown"
      }
      .to_string(),
    )),
    (ObjectRef::RequestClient, "Ip") => Ok(Value::String(ctx.request.peer_addr.ip().to_string())),
    (ObjectRef::RequestClient, "Port") => Ok(Value::Int(ctx.request.peer_addr.port().into())),
    (ObjectRef::RequestClient, "SourceAddress") => {
      Ok(Value::String(ctx.request.peer_addr.to_string()))
    }
    (ObjectRef::RequestClient, "UserAgent") => header_single(ctx.request.headers, USER_AGENT, ctx),
    (ObjectRef::RequestClient, "PersonProof") => {
      Ok(Value::Object(ObjectRef::RequestClientPersonProof))
    }
    (ObjectRef::RequestClient, "Agent") => Ok(Value::Object(ObjectRef::RequestClientAgent)),
    (ObjectRef::RequestClient, "Bot") => Ok(Value::Object(ObjectRef::RequestClientBot)),
    (ObjectRef::RequestClient, "GeoCountry") => Ok(Value::Null),
    (ObjectRef::RequestClient, "Asn") => Ok(
      ctx
        .request
        .client_asn
        .map(|asn| Value::Int(asn.into()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestClientPersonProof, "State") => {
      Ok(Value::String(ctx.person_proof.state.as_str().to_string()))
    }
    (ObjectRef::RequestClientPersonProof, "Mode") => Ok(
      ctx
        .person_proof
        .mode
        .map(|mode| Value::String(mode.to_string()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestClientPersonProof, "Difficulty") => Ok(
      ctx
        .person_proof
        .difficulty
        .map(|difficulty| Value::Int(difficulty.into()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestClientPersonProof, "IssuedAtUnixMs") => Ok(
      ctx
        .person_proof
        .issued_at_unix_ms
        .map(Value::Int)
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestClientPersonProof, "ExpiresAtUnixMs") => Ok(
      ctx
        .person_proof
        .expires_at_unix_ms
        .map(Value::Int)
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestClientPersonProof, "Weight") => Ok(Value::Int(ctx.person_proof.weight)),
    (ObjectRef::RequestClientPersonProof, "Allowed") => Ok(Value::Bool(ctx.person_proof.allowed)),
    (ObjectRef::RequestClientAgent, "Verified") => Ok(Value::Bool(false)),
    (ObjectRef::RequestClientAgent, "Kind")
    | (ObjectRef::RequestClientAgent, "Provider")
    | (ObjectRef::RequestClientAgent, "Model")
    | (ObjectRef::RequestClientAgent, "AuthMethod") => Ok(Value::Null),
    (ObjectRef::RequestClientBot, "Disposition") => Ok(Value::String(
      mi_score::request_bot_assessment(ctx.request)
        .disposition
        .to_string(),
    )),
    (ObjectRef::RequestClientBot, "Malicious") => Ok(
      mi_score::request_bot_assessment(ctx.request)
        .malicious
        .map(Value::Bool)
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestClientBot, "Score") => Ok(Value::Int(
      mi_score::request_bot_assessment(ctx.request).score,
    )),
    (ObjectRef::RequestClientBot, "Reason") => Ok(
      mi_score::request_bot_assessment(ctx.request)
        .reason
        .map(Value::String)
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTransport, "Network") => Ok(Value::String(
      ctx.request.transport_network.as_str().to_string(),
    )),
    (ObjectRef::RequestTransport, "RemoteIp") => {
      Ok(Value::String(ctx.request.peer_addr.ip().to_string()))
    }
    (ObjectRef::RequestTransport, "RemotePort") => {
      Ok(Value::Int(ctx.request.peer_addr.port().into()))
    }
    (ObjectRef::RequestTransport, "IsEncrypted") => Ok(Value::Bool(ctx.request.tls.enabled)),
    (ObjectRef::RequestTransport, "Tcp") => {
      if ctx.request.transport_network == WafTransportNetwork::Tcp {
        Ok(Value::Object(ObjectRef::RequestTransportTcp))
      } else {
        Ok(Value::Null)
      }
    }
    (ObjectRef::RequestTransport, "Udp") => {
      if ctx.request.transport_network == WafTransportNetwork::Udp {
        Ok(Value::Object(ObjectRef::RequestTransportUdp))
      } else {
        Ok(Value::Null)
      }
    }
    (ObjectRef::RequestTransportTcp, "State") => Ok(Value::String("accepted".to_string())),
    (ObjectRef::RequestTransportTcp, "TlsDetected") => Ok(Value::Bool(true)),
    (ObjectRef::RequestTransportTcp, "MaxHop") => Ok(
      ctx
        .request
        .tcp_max_hop
        .map(|max_hop| Value::Int(i64::from(max_hop)))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTransportTcp, "Sni") => Ok(
      ctx
        .request
        .tls
        .sni
        .as_ref()
        .map(|value| Value::String(value.clone()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTransportTcp, "Alpn") => Ok(
      ctx
        .request
        .tls
        .alpn
        .as_ref()
        .map(|value| Value::String(value.clone()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTransportTcp, "Mss") => Ok(
      ctx
        .request
        .transport_metadata
        .tcp_mss
        .map(|mss| Value::Int(i64::from(mss)))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTransportTcp, "RttMs") => Ok(
      ctx
        .request
        .transport_metadata
        .tcp_rtt_ms
        .and_then(|rtt| i64::try_from(rtt).ok())
        .map(Value::Int)
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTransportUdp, "DatagramSize") => Ok(
      ctx
        .request
        .transport_metadata
        .udp_datagram_size
        .and_then(|size| i64::try_from(size).ok())
        .map(Value::Int)
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTransportUdp, "FlowId") => Ok(Value::Null),
    (ObjectRef::RequestTransportUdp, "ConnectionId") => Ok(
      ctx
        .request
        .transport_metadata
        .udp_connection_id
        .map(|id| Value::String(id.to_string()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTransportUdp, "QuicDetected") => Ok(Value::Bool(true)),
    (ObjectRef::RequestNormalized, "Http") => Ok(Value::Object(ObjectRef::RequestNormalizedHttp)),
    (ObjectRef::RequestNormalized, "Headers") => {
      Ok(Value::Object(ObjectRef::RequestNormalizedHeaders))
    }
    (ObjectRef::RequestNormalized, "QueryParams") => {
      Ok(Value::Object(ObjectRef::RequestNormalizedQueryParams))
    }
    (ObjectRef::RequestNormalized, "Cookies") => {
      Ok(Value::Object(ObjectRef::RequestNormalizedCookies))
    }
    (ObjectRef::RequestNormalizedHttp, "Path") => {
      Ok(Value::String(normalized_http_path(ctx.request.uri)))
    }
    (ObjectRef::RequestNormalizedHttp, "Query") => {
      Ok(Value::String(normalized_http_query(ctx.request.uri)))
    }
    (ObjectRef::RequestNormalizedHttp, "Uri") => {
      Ok(Value::String(normalized_http_uri(ctx.request.uri)))
    }
    (ObjectRef::RequestHttp, "Version") => Ok(Value::String(version_string(ctx.request.version))),
    (ObjectRef::RequestHttp, "Method") => {
      Ok(Value::String(ctx.request.method.as_str().to_string()))
    }
    (ObjectRef::RequestHttp, "Scheme") => {
      Ok(Value::String(ctx.request.downstream_scheme.to_string()))
    }
    (ObjectRef::RequestHttp, "Host") => Ok(Value::String(ctx.request.downstream_host.to_string())),
    (ObjectRef::RequestHttp, "Path") => Ok(Value::String(ctx.request.uri.path().to_string())),
    (ObjectRef::RequestHttp, "Query") => Ok(Value::String(
      ctx.request.uri.query().unwrap_or_default().to_string(),
    )),
    (ObjectRef::RequestHttp, "Uri") => Ok(Value::String(ctx.request.uri.to_string())),
    (ObjectRef::RequestHttp, "Body") => Ok(Value::Object(ObjectRef::RequestBody)),
    (ObjectRef::RequestBody, "Size") => {
      Ok(Value::Int(body_size(ctx.request.headers, ctx.request.body)))
    }
    (ObjectRef::RequestBody, "IsTruncated") => Ok(Value::Bool(
      ctx
        .request
        .body
        .map(|body| body.is_truncated)
        .unwrap_or(false),
    )),
    (ObjectRef::RequestBody, "Bytes") => Ok(
      ctx
        .request
        .body
        .map(|body| Value::Bytes(body.bytes.to_vec()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestBody, "Text") => Ok(
      ctx
        .request
        .body
        .map(|body| {
          Value::String(
            ctx
              .body_text_caches
              .text(BodyTextSlot::Request, body)
              .to_string(),
          )
        })
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTls, field) => object_model::eval_request_tls_member(ctx, field),
    (ObjectRef::RequestTokenBindings, "UserAgent") => Ok(Value::String(
      request_token_binding_value(ctx.request, PersonProofTokenBinding::UserAgent),
    )),
    (ObjectRef::RequestTokenBindings, "TlsFingerprint") => Ok(Value::String(
      request_token_binding_value(ctx.request, PersonProofTokenBinding::TlsFingerprint),
    )),
    (ObjectRef::RequestTokenBindings, "Route") => Ok(Value::String(request_token_binding_value(
      ctx.request,
      PersonProofTokenBinding::Route,
    ))),
    (ObjectRef::RequestTokenBindings, "DirectPeerIpNetworkPrefix") => {
      Ok(Value::String(request_token_binding_value(
        ctx.request,
        PersonProofTokenBinding::DirectPeerIpNetworkPrefix,
      )))
    }
    (ObjectRef::RequestTokenBindings, "TcpMaxHop") => Ok(Value::String(
      request_token_binding_value(ctx.request, PersonProofTokenBinding::TcpMaxHop),
    )),
    (ObjectRef::Response, "Id") => Ok(Value::String(
      ctx
        .response
        .context("missing response context")?
        .response_id
        .to_string(),
    )),
    (ObjectRef::Response, "ReceivedAtUnixMs") => Ok(Value::Int(
      i64::try_from(
        ctx
          .response
          .context("missing response context")?
          .received_at_unix_ms,
      )
      .unwrap_or(i64::MAX),
    )),
    (ObjectRef::Response, "Protocol") => Ok(Value::String(
      ctx
        .response
        .context("missing response context")?
        .request
        .protocol
        .as_str()
        .to_string(),
    )),
    (ObjectRef::Response, "Http") => Ok(Value::Object(ObjectRef::ResponseHttp)),
    (ObjectRef::Response, "Headers") => Ok(Value::Object(ObjectRef::ResponseHeaders)),
    (ObjectRef::Response, "Cookies") => Ok(Value::Object(ObjectRef::ResponseCookies)),
    (ObjectRef::Response, "Body") => Ok(Value::Object(ObjectRef::ResponseBody)),
    (ObjectRef::Response, "Tags") => Ok(Value::Object(ObjectRef::ResponseTags)),
    (ObjectRef::Response, "Tls") => Ok(Value::Object(ObjectRef::ResponseTls)),
    (ObjectRef::Response, "Transport") => Ok(Value::Object(ObjectRef::ResponseTransport)),
    (ObjectRef::Response, "Upstream") => Ok(Value::Object(ObjectRef::ResponseUpstream)),
    (ObjectRef::ResponseHttp, "Version") => Ok(Value::String(version_string(
      ctx.response.context("missing response context")?.version,
    ))),
    (ObjectRef::ResponseHttp, "Status") => Ok(Value::Int(
      ctx
        .response
        .context("missing response context")?
        .status
        .as_u16()
        .into(),
    )),
    (ObjectRef::ResponseHttp, "Reason") => Ok(
      ctx
        .response
        .context("missing response context")?
        .status
        .canonical_reason()
        .map(|reason| Value::String(reason.to_string()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::ResponseHttp, "Body") => Ok(Value::Object(ObjectRef::ResponseBody)),
    (ObjectRef::ResponseBody, "Size") => {
      let response = ctx.response.context("missing response context")?;
      Ok(Value::Int(body_size(response.headers, response.body)))
    }
    (ObjectRef::ResponseBody, "IsTruncated") => Ok(Value::Bool(
      ctx
        .response
        .and_then(|response| response.body)
        .map(|body| body.is_truncated)
        .unwrap_or(false),
    )),
    (ObjectRef::ResponseBody, "Text") => Ok(
      ctx
        .response
        .and_then(|response| response.body)
        .map(|body| {
          Value::String(
            ctx
              .body_text_caches
              .text(BodyTextSlot::Response, body)
              .to_string(),
          )
        })
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::ResponseBody, "Bytes") => Ok(
      ctx
        .response
        .and_then(|response| response.body)
        .map(|body| Value::Bytes(body.bytes.to_vec()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::ResponseUpstream, "Name") => {
      let upstream_name = ctx
        .response
        .context("missing response context")?
        .upstream_name;
      Ok(if upstream_name.is_empty() {
        Value::Null
      } else {
        Value::String(upstream_name.to_string())
      })
    }
    (ObjectRef::ResponseUpstream, "Pool") => Ok(
      ctx
        .response
        .context("missing response context")?
        .upstream_pool
        .map(|pool| Value::String(pool.to_string()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::ResponseUpstream, "Scheme") => {
      let upstream_scheme = ctx
        .response
        .context("missing response context")?
        .upstream_scheme;
      Ok(if upstream_scheme.is_empty() {
        Value::Null
      } else {
        Value::String(upstream_scheme.to_string())
      })
    }
    (ObjectRef::ResponseUpstream, "ConnectTimeMs") => Ok(
      ctx
        .response
        .context("missing response context")?
        .upstream_connect_time_ms
        .and_then(|value| i64::try_from(value).ok())
        .map(Value::Int)
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::ResponseUpstream, "FirstByteTimeMs") => Ok(
      ctx
        .response
        .context("missing response context")?
        .upstream_first_byte_time_ms
        .and_then(|value| i64::try_from(value).ok())
        .map(Value::Int)
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::ResponseUpstream, "Error") => {
      if ctx
        .response
        .context("missing response context")?
        .upstream_error
        .is_some()
      {
        Ok(Value::Object(ObjectRef::ResponseUpstreamError))
      } else {
        Ok(Value::Null)
      }
    }
    (ObjectRef::ResponseUpstreamError, "Code") => Ok(Value::String(
      ctx
        .response
        .context("missing response context")?
        .upstream_error
        .context("missing upstream error")?
        .code
        .to_string(),
    )),
    (ObjectRef::ResponseUpstreamError, "Message") => Ok(Value::String(
      ctx
        .response
        .context("missing response context")?
        .upstream_error
        .context("missing upstream error")?
        .message
        .chars()
        .take(ctx.limits.max_helper_result_bytes)
        .collect(),
    )),
    (ObjectRef::ResponseTls, "Enabled") => Ok(Value::Bool(false)),
    (ObjectRef::ResponseTls, "Version")
    | (ObjectRef::ResponseTls, "CipherSuite")
    | (ObjectRef::ResponseTls, "Sni")
    | (ObjectRef::ResponseTls, "Alpn")
    | (ObjectRef::ResponseTls, "Fingerprint")
    | (ObjectRef::ResponseTls, "FingerprintScheme") => Ok(Value::Null),
    (ObjectRef::ResponseTls, "ClientCertificatePresent") => Ok(Value::Bool(false)),
    (ObjectRef::ResponseTransport, field) => {
      object_model::eval_response_transport_member(ctx, field)
    }
    _ => bail!("unknown WAF object property {:?}.{field}", object),
  }
}

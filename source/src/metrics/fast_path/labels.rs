//! Typed fixed labels for fast-path metrics.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum FastPathMetricPath {
  PlainProxy = 0,
  H3Downstream = 1,
  StaticFiles = 2,
}

impl FastPathMetricPath {
  pub(crate) const ALL: [Self; 3] = [Self::PlainProxy, Self::H3Downstream, Self::StaticFiles];
  pub(crate) const COUNT: usize = Self::ALL.len();

  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::PlainProxy => "plain_proxy",
      Self::H3Downstream => "h3_downstream",
      Self::StaticFiles => "static_files",
    }
  }

  pub(crate) fn from_str(value: &str) -> Option<Self> {
    match value {
      "plain_proxy" => Some(Self::PlainProxy),
      "h3_downstream" => Some(Self::H3Downstream),
      "static_files" => Some(Self::StaticFiles),
      _ => None,
    }
  }

  pub(crate) fn index(self) -> usize {
    self as usize
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum FastPathMetricProtocol {
  H1 = 0,
  H2 = 1,
  H3 = 2,
  Other = 3,
}

impl FastPathMetricProtocol {
  pub(crate) const ALL: [Self; 4] = [Self::H1, Self::H2, Self::H3, Self::Other];
  pub(crate) const COUNT: usize = Self::ALL.len();

  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::H1 => "h1",
      Self::H2 => "h2",
      Self::H3 => "h3",
      Self::Other => "other",
    }
  }

  pub(crate) fn from_str(value: &str) -> Option<Self> {
    match value {
      "h1" => Some(Self::H1),
      "h2" => Some(Self::H2),
      "h3" => Some(Self::H3),
      "other" => Some(Self::Other),
      _ => None,
    }
  }

  pub(crate) fn index(self) -> usize {
    self as usize
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum DirectH1ResponseProtocolFailure {
  HeadTooLarge = 0,
  TooManyHeaders = 1,
  HeaderFieldTooLarge = 2,
  TooManyInterimResponses = 3,
  InvalidStatusLine = 4,
  InvalidHeaderSyntax = 5,
  InvalidTransferCodingSequence = 6,
  ChunkLineTooLarge = 7,
  InvalidChunkSize = 8,
  InvalidChunkExtension = 9,
  InvalidChunkTerminator = 10,
  ChunkExtensionTooLarge = 11,
  TrailerBlockTooLarge = 12,
  TooManyTrailers = 13,
  InvalidTrailerField = 14,
  TrailerFieldTooLarge = 15,
  UnexpectedEof = 16,
  IdleTimeout = 17,
  DownstreamCancellation = 18,
  UnsupportedUpgrade = 19,
}

impl DirectH1ResponseProtocolFailure {
  pub(crate) const ALL: [Self; 20] = [
    Self::HeadTooLarge,
    Self::TooManyHeaders,
    Self::HeaderFieldTooLarge,
    Self::TooManyInterimResponses,
    Self::InvalidStatusLine,
    Self::InvalidHeaderSyntax,
    Self::InvalidTransferCodingSequence,
    Self::ChunkLineTooLarge,
    Self::InvalidChunkSize,
    Self::InvalidChunkExtension,
    Self::InvalidChunkTerminator,
    Self::ChunkExtensionTooLarge,
    Self::TrailerBlockTooLarge,
    Self::TooManyTrailers,
    Self::InvalidTrailerField,
    Self::TrailerFieldTooLarge,
    Self::UnexpectedEof,
    Self::IdleTimeout,
    Self::DownstreamCancellation,
    Self::UnsupportedUpgrade,
  ];
  pub(crate) const COUNT: usize = Self::ALL.len();

  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::HeadTooLarge => "head_too_large",
      Self::TooManyHeaders => "too_many_headers",
      Self::HeaderFieldTooLarge => "header_field_too_large",
      Self::TooManyInterimResponses => "too_many_interim_responses",
      Self::InvalidStatusLine => "invalid_status_line",
      Self::InvalidHeaderSyntax => "invalid_header_syntax",
      Self::InvalidTransferCodingSequence => "invalid_transfer_coding_sequence",
      Self::ChunkLineTooLarge => "chunk_line_too_large",
      Self::InvalidChunkSize => "invalid_chunk_size",
      Self::InvalidChunkExtension => "invalid_chunk_extension",
      Self::InvalidChunkTerminator => "invalid_chunk_terminator",
      Self::ChunkExtensionTooLarge => "chunk_extension_too_large",
      Self::TrailerBlockTooLarge => "trailer_block_too_large",
      Self::TooManyTrailers => "too_many_trailers",
      Self::InvalidTrailerField => "invalid_trailer_field",
      Self::TrailerFieldTooLarge => "trailer_field_too_large",
      Self::UnexpectedEof => "unexpected_eof",
      Self::IdleTimeout => "idle_timeout",
      Self::DownstreamCancellation => "downstream_cancellation",
      Self::UnsupportedUpgrade => "unsupported_upgrade",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum FastPathPlainProxyMissReason {
  PlanDisabled = 0,
  UnsupportedVersion = 1,
  UnsupportedRoute = 2,
  PersonProofApi = 3,
  CachePolicy = 4,
  NativeGrpc = 5,
  Upgrade = 6,
  Connect = 7,
}

impl FastPathPlainProxyMissReason {
  pub(crate) fn index(self) -> usize {
    self as usize
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum FastPathRequestBodyOutcome {
  AlreadyEmpty = 0,
  VerifiedEmpty = 1,
  ProbeEof = 2,
  Streaming = 3,
}

impl FastPathRequestBodyOutcome {
  pub(crate) const ALL: [Self; 4] = [
    Self::AlreadyEmpty,
    Self::VerifiedEmpty,
    Self::ProbeEof,
    Self::Streaming,
  ];
  pub(crate) const COUNT: usize = Self::ALL.len();

  pub(crate) fn index(self) -> usize {
    self as usize
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum FastPathMetricStage {
  DirectH1Connect = 0,
  DirectH1PoolTake = 1,
  DirectH1RequestBuild = 2,
  DirectH1SendRequest = 3,
  FastPathPrepare = 4,
  RequestBodyPrepare = 5,
  TransportDirectH1 = 6,
  TransportDirectH2 = 7,
  TransportGeneral = 8,
  ResponseBodyPrepare = 9,
  ResponseFinalize = 10,
  H3IngressPrepare = 11,
  H3DownstreamSend = 12,
  DirectH1SenderReady = 13,
  DirectH1RequestSubmit = 14,
  DirectH1ResponseHead = 15,
  DirectH1ResponseBodyFirstFrame = 16,
  H2DownstreamResponseReturn = 17,
  StaticPlan = 18,
  StaticHotObjectRevalidate = 19,
  StaticHeadPrepare = 20,
  StaticWriteHead = 21,
  StaticWriteBody = 22,
  StaticSendfileBody = 23,
  H3RequestTaskReap = 24,
  H3RequestPermitAcquire = 25,
  H3RequestTaskSpawn = 26,
  H3KnownSmallFinalize = 27,
  H3ResponseBodyFrame = 28,
  RouteResolution = 29,
  FastPathEligibility = 30,
  TransportSelection = 31,
  DirectH2SendRequest = 32,
  H3StreamFinish = 33,
  DownstreamProtocolReceive = 34,
  UpstreamRequestRebuild = 35,
  H2ResponseSend = 36,
  H3RequestTaskJoin = 37,
  DirectH2PoolTake = 38,
  DirectH2Connect = 39,
  DirectH2CapacityWait = 40,
}

impl FastPathMetricStage {
  pub(crate) const ALL: [Self; 41] = [
    Self::DirectH1Connect,
    Self::DirectH1PoolTake,
    Self::DirectH1RequestBuild,
    Self::DirectH1SendRequest,
    Self::FastPathPrepare,
    Self::RequestBodyPrepare,
    Self::TransportDirectH1,
    Self::TransportDirectH2,
    Self::TransportGeneral,
    Self::ResponseBodyPrepare,
    Self::ResponseFinalize,
    Self::H3IngressPrepare,
    Self::H3DownstreamSend,
    Self::DirectH1SenderReady,
    Self::DirectH1RequestSubmit,
    Self::DirectH1ResponseHead,
    Self::DirectH1ResponseBodyFirstFrame,
    Self::H2DownstreamResponseReturn,
    Self::StaticPlan,
    Self::StaticHotObjectRevalidate,
    Self::StaticHeadPrepare,
    Self::StaticWriteHead,
    Self::StaticWriteBody,
    Self::StaticSendfileBody,
    Self::H3RequestTaskReap,
    Self::H3RequestPermitAcquire,
    Self::H3RequestTaskSpawn,
    Self::H3KnownSmallFinalize,
    Self::H3ResponseBodyFrame,
    Self::RouteResolution,
    Self::FastPathEligibility,
    Self::TransportSelection,
    Self::DirectH2SendRequest,
    Self::H3StreamFinish,
    Self::DownstreamProtocolReceive,
    Self::UpstreamRequestRebuild,
    Self::H2ResponseSend,
    Self::H3RequestTaskJoin,
    Self::DirectH2PoolTake,
    Self::DirectH2Connect,
    Self::DirectH2CapacityWait,
  ];
  pub(crate) const COUNT: usize = Self::ALL.len();

  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::DirectH1Connect => "direct_h1_connect",
      Self::DirectH1PoolTake => "direct_h1_pool_take",
      Self::DirectH1RequestBuild => "direct_h1_request_build",
      Self::DirectH1SendRequest => "direct_h1_send_request",
      Self::FastPathPrepare => "fast_path_prepare",
      Self::RequestBodyPrepare => "request_body_prepare",
      Self::TransportDirectH1 => "transport_direct_h1",
      Self::TransportDirectH2 => "transport_direct_h2",
      Self::TransportGeneral => "transport_general",
      Self::ResponseBodyPrepare => "response_body_prepare",
      Self::ResponseFinalize => "response_finalize",
      Self::H3IngressPrepare => "h3_ingress_prepare",
      Self::H3DownstreamSend => "h3_downstream_send",
      Self::DirectH1SenderReady => "direct_h1_sender_ready",
      Self::DirectH1RequestSubmit => "direct_h1_request_submit",
      Self::DirectH1ResponseHead => "direct_h1_response_head",
      Self::DirectH1ResponseBodyFirstFrame => "direct_h1_response_body_first_frame",
      Self::H2DownstreamResponseReturn => "h2_downstream_response_return",
      Self::StaticPlan => "static_plan",
      Self::StaticHotObjectRevalidate => "static_hot_object_revalidate",
      Self::StaticHeadPrepare => "static_head_prepare",
      Self::StaticWriteHead => "static_write_head",
      Self::StaticWriteBody => "static_write_body",
      Self::StaticSendfileBody => "static_sendfile_body",
      Self::H3RequestTaskReap => "h3_request_task_reap",
      Self::H3RequestPermitAcquire => "h3_request_permit_acquire",
      Self::H3RequestTaskSpawn => "h3_request_task_spawn",
      Self::H3KnownSmallFinalize => "h3_known_small_finalize",
      Self::H3ResponseBodyFrame => "h3_response_body_frame",
      Self::RouteResolution => "route_resolution",
      Self::FastPathEligibility => "fast_path_eligibility",
      Self::TransportSelection => "transport_selection",
      Self::DirectH2SendRequest => "direct_h2_send_request",
      Self::H3StreamFinish => "h3_stream_finish",
      Self::DownstreamProtocolReceive => "downstream_protocol_receive",
      Self::UpstreamRequestRebuild => "upstream_request_rebuild",
      Self::H2ResponseSend => "h2_response_send",
      Self::H3RequestTaskJoin => "h3_request_task_join",
      Self::DirectH2PoolTake => "direct_h2_pool_take",
      Self::DirectH2Connect => "direct_h2_connect",
      Self::DirectH2CapacityWait => "direct_h2_capacity_wait",
    }
  }

  pub(crate) fn from_str(value: &str) -> Option<Self> {
    match value {
      "direct_h1_connect" => Some(Self::DirectH1Connect),
      "direct_h1_pool_take" => Some(Self::DirectH1PoolTake),
      "direct_h1_request_build" => Some(Self::DirectH1RequestBuild),
      "direct_h1_send_request" => Some(Self::DirectH1SendRequest),
      "fast_path_prepare" => Some(Self::FastPathPrepare),
      "request_body_prepare" => Some(Self::RequestBodyPrepare),
      "transport_direct_h1" => Some(Self::TransportDirectH1),
      "transport_direct_h2" => Some(Self::TransportDirectH2),
      "transport_general" => Some(Self::TransportGeneral),
      "response_body_prepare" => Some(Self::ResponseBodyPrepare),
      "response_finalize" => Some(Self::ResponseFinalize),
      "h3_ingress_prepare" => Some(Self::H3IngressPrepare),
      "h3_downstream_send" => Some(Self::H3DownstreamSend),
      "direct_h1_sender_ready" => Some(Self::DirectH1SenderReady),
      "direct_h1_request_submit" => Some(Self::DirectH1RequestSubmit),
      "direct_h1_response_head" => Some(Self::DirectH1ResponseHead),
      "direct_h1_response_body_first_frame" => Some(Self::DirectH1ResponseBodyFirstFrame),
      "h2_downstream_response_return" => Some(Self::H2DownstreamResponseReturn),
      "static_plan" => Some(Self::StaticPlan),
      "static_hot_object_revalidate" => Some(Self::StaticHotObjectRevalidate),
      "static_head_prepare" => Some(Self::StaticHeadPrepare),
      "static_write_head" => Some(Self::StaticWriteHead),
      "static_write_body" => Some(Self::StaticWriteBody),
      "static_sendfile_body" => Some(Self::StaticSendfileBody),
      "h3_request_task_reap" => Some(Self::H3RequestTaskReap),
      "h3_request_permit_acquire" => Some(Self::H3RequestPermitAcquire),
      "h3_request_task_spawn" => Some(Self::H3RequestTaskSpawn),
      "h3_known_small_finalize" => Some(Self::H3KnownSmallFinalize),
      "h3_response_body_frame" => Some(Self::H3ResponseBodyFrame),
      "route_resolution" => Some(Self::RouteResolution),
      "fast_path_eligibility" => Some(Self::FastPathEligibility),
      "transport_selection" => Some(Self::TransportSelection),
      "direct_h2_send_request" => Some(Self::DirectH2SendRequest),
      "h3_stream_finish" => Some(Self::H3StreamFinish),
      "downstream_protocol_receive" => Some(Self::DownstreamProtocolReceive),
      "upstream_request_rebuild" => Some(Self::UpstreamRequestRebuild),
      "h2_response_send" => Some(Self::H2ResponseSend),
      "h3_request_task_join" => Some(Self::H3RequestTaskJoin),
      "direct_h2_pool_take" => Some(Self::DirectH2PoolTake),
      "direct_h2_connect" => Some(Self::DirectH2Connect),
      "direct_h2_capacity_wait" => Some(Self::DirectH2CapacityWait),
      _ => None,
    }
  }

  pub(crate) fn index(self) -> usize {
    self as usize
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum FastPathMetricOutcome {
  Ok = 0,
  Fallback = 1,
  Error = 2,
}

impl FastPathMetricOutcome {
  pub(crate) const ALL: [Self; 3] = [Self::Ok, Self::Fallback, Self::Error];
  pub(crate) const COUNT: usize = Self::ALL.len();

  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::Ok => "ok",
      Self::Fallback => "fallback",
      Self::Error => "error",
    }
  }

  pub(crate) fn from_str(value: &str) -> Option<Self> {
    match value {
      "ok" => Some(Self::Ok),
      "fallback" => Some(Self::Fallback),
      "error" => Some(Self::Error),
      _ => None,
    }
  }

  pub(crate) fn index(self) -> usize {
    self as usize
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum FastPathMetricTransport {
  DirectH1 = 0,
  DirectH2 = 1,
}

impl FastPathMetricTransport {
  pub(crate) fn index(self) -> usize {
    self as usize
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum DirectH1IoBackend {
  TokioHyper = 0,
  Compio = 1,
}

impl DirectH1IoBackend {
  pub(crate) const ALL: [Self; 2] = [Self::TokioHyper, Self::Compio];
  pub(crate) const COUNT: usize = Self::ALL.len();

  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::TokioHyper => "tokio_hyper",
      Self::Compio => "compio",
    }
  }

  pub(crate) fn from_str(value: &str) -> Option<Self> {
    match value {
      "tokio_hyper" => Some(Self::TokioHyper),
      "compio" => Some(Self::Compio),
      _ => None,
    }
  }

  pub(crate) fn index(self) -> usize {
    self as usize
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum DirectH1IoBackendOutcome {
  Selected = 0,
  Fallback = 1,
  Error = 2,
}

impl DirectH1IoBackendOutcome {
  pub(crate) const ALL: [Self; 3] = [Self::Selected, Self::Fallback, Self::Error];
  pub(crate) const COUNT: usize = Self::ALL.len();

  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::Selected => "selected",
      Self::Fallback => "fallback",
      Self::Error => "error",
    }
  }

  pub(crate) fn from_str(value: &str) -> Option<Self> {
    match value {
      "selected" => Some(Self::Selected),
      "fallback" => Some(Self::Fallback),
      "error" => Some(Self::Error),
      _ => None,
    }
  }

  pub(crate) fn index(self) -> usize {
    self as usize
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum FastPathTransportMissReason {
  UnsupportedRequest = 0,
  UnsupportedUpstream = 1,
  RequestBody = 2,
  ConnectError = 3,
  SendError = 4,
  ResponseError = 5,
  NotReusable = 6,
  PoolFull = 7,
}

impl FastPathTransportMissReason {
  pub(crate) fn from_str(value: &str) -> Option<Self> {
    match value {
      "unsupported_request" => Some(Self::UnsupportedRequest),
      "unsupported_upstream" => Some(Self::UnsupportedUpstream),
      "request_body" => Some(Self::RequestBody),
      "connect_error" => Some(Self::ConnectError),
      "send_error" => Some(Self::SendError),
      "response_error" => Some(Self::ResponseError),
      "not_reusable" => Some(Self::NotReusable),
      "pool_full" => Some(Self::PoolFull),
      _ => None,
    }
  }

  pub(crate) fn index(self) -> usize {
    self as usize
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum DirectH1PoolEvent {
  Hit = 0,
  Miss = 1,
  MissEmpty = 2,
  MissLocked = 3,
  Reconnect = 4,
  Stale = 5,
  Drop = 6,
  DropFull = 7,
  DropLocked = 8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum DirectH2PoolEvent {
  Hit = 0,
  Miss = 1,
  MissEmpty = 2,
  MissSaturated = 3,
  MissLocked = 4,
  Connect = 5,
  ConnectError = 6,
  Reconnect = 7,
  Stale = 8,
  Drop = 9,
  ConnectLeader = 10,
  ConnectCoalesced = 11,
  CapacityWait = 12,
  CapacityReady = 13,
  CapacityTimeout = 14,
  CapacityFull = 15,
  DrainStarted = 16,
  DrainCompleted = 17,
  GracefulClose = 18,
  CooldownEntered = 19,
  CooldownExpired = 20,
  StaleGeneration = 21,
}

impl DirectH2PoolEvent {
  pub(crate) const ALL: [Self; 22] = [
    Self::Hit,
    Self::Miss,
    Self::MissEmpty,
    Self::MissSaturated,
    Self::MissLocked,
    Self::Connect,
    Self::ConnectError,
    Self::Reconnect,
    Self::Stale,
    Self::Drop,
    Self::ConnectLeader,
    Self::ConnectCoalesced,
    Self::CapacityWait,
    Self::CapacityReady,
    Self::CapacityTimeout,
    Self::CapacityFull,
    Self::DrainStarted,
    Self::DrainCompleted,
    Self::GracefulClose,
    Self::CooldownEntered,
    Self::CooldownExpired,
    Self::StaleGeneration,
  ];
  pub(crate) const COUNT: usize = Self::ALL.len();

  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::Hit => "hit",
      Self::Miss => "miss",
      Self::MissEmpty => "miss_empty",
      Self::MissSaturated => "miss_saturated",
      Self::MissLocked => "miss_locked",
      Self::Connect => "connect",
      Self::ConnectError => "connect_error",
      Self::Reconnect => "reconnect",
      Self::Stale => "stale",
      Self::Drop => "drop",
      Self::ConnectLeader => "connect_leader",
      Self::ConnectCoalesced => "connect_coalesced",
      Self::CapacityWait => "capacity_wait",
      Self::CapacityReady => "capacity_ready",
      Self::CapacityTimeout => "capacity_timeout",
      Self::CapacityFull => "capacity_full",
      Self::DrainStarted => "drain_started",
      Self::DrainCompleted => "drain_completed",
      Self::GracefulClose => "graceful_close",
      Self::CooldownEntered => "cooldown_entered",
      Self::CooldownExpired => "cooldown_expired",
      Self::StaleGeneration => "stale_generation",
    }
  }

  pub(crate) fn from_str(value: &str) -> Option<Self> {
    Self::ALL
      .into_iter()
      .find(|candidate| candidate.as_str() == value)
  }

  pub(crate) fn index(self) -> usize {
    self as usize
  }
}

impl DirectH1PoolEvent {
  pub(crate) fn from_str(value: &str) -> Option<Self> {
    match value {
      "hit" => Some(Self::Hit),
      "miss" => Some(Self::Miss),
      "miss_empty" => Some(Self::MissEmpty),
      "miss_locked" => Some(Self::MissLocked),
      "reconnect" => Some(Self::Reconnect),
      "stale" => Some(Self::Stale),
      "drop" => Some(Self::Drop),
      "drop_full" => Some(Self::DropFull),
      "drop_locked" => Some(Self::DropLocked),
      _ => None,
    }
  }

  pub(crate) fn index(self) -> usize {
    self as usize
  }
}

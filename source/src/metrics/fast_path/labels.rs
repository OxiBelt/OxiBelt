//! Typed fixed labels for fast-path metrics.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum FastPathMetricPath {
  PlainProxy = 0,
  H3Downstream = 1,
}

impl FastPathMetricPath {
  pub(crate) const ALL: [Self; 2] = [Self::PlainProxy, Self::H3Downstream];
  pub(crate) const COUNT: usize = Self::ALL.len();

  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::PlainProxy => "plain_proxy",
      Self::H3Downstream => "h3_downstream",
    }
  }

  pub(crate) fn from_str(value: &str) -> Option<Self> {
    match value {
      "plain_proxy" => Some(Self::PlainProxy),
      "h3_downstream" => Some(Self::H3Downstream),
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
}

impl FastPathMetricStage {
  pub(crate) const ALL: [Self; 13] = [
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

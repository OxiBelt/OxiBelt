//! Downstream HTTP/3 response send helpers.
//! Fast branches stay limited to responses already proven safe by the HTTP fast path.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ::http::Response;
use anyhow::Context;
use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use hyper::body::Body as _;

use crate::metrics::fast_path::labels::FastPathMetricStage;
use crate::proxy::http as http_proxy;
use crate::proxy::http::body::{
  CompiledKnownSmallNoopResponse, InlinedKnownSmallResponseBody, KNOWN_SMALL_BODY_MAX_BYTES,
  KnownSmallResponseBody, ProxyBody,
};
use crate::proxy::http::fast_path::stage_timing as timing;
use crate::state::AppSnapshot;

#[derive(Clone)]
pub(super) struct H3ResponseTiming {
  state: Arc<AppSnapshot>,
  enabled: bool,
}

impl H3ResponseTiming {
  pub(super) fn from_state(state: &Arc<AppSnapshot>) -> Self {
    Self {
      state: state.clone(),
      enabled: state.request_path_features.stage_timing_metrics,
    }
  }

  fn start(&self) -> Option<Instant> {
    timing::start(self.enabled)
  }

  fn record(&self, stage: FastPathMetricStage, success: bool, started_at: Option<Instant>) {
    timing::record(
      self.state.as_ref(),
      timing::PATH_H3_DOWNSTREAM,
      timing::protocol(::http::Version::HTTP_3),
      stage,
      if success {
        timing::OUTCOME_OK
      } else {
        timing::OUTCOME_ERROR
      },
      started_at,
    );
  }
}

pub(super) async fn respond_to_h3_request<S>(
  stream: h3::server::RequestStream<S, Bytes>,
  response: Response<ProxyBody>,
) -> anyhow::Result<()>
where
  S: h3::quic::SendStream<Bytes>,
{
  respond_to_h3_request_with_timing(stream, response, None).await
}

pub(super) async fn respond_to_h3_request_with_timing<S>(
  mut stream: h3::server::RequestStream<S, Bytes>,
  response: Response<ProxyBody>,
  response_timing: Option<H3ResponseTiming>,
) -> anyhow::Result<()>
where
  S: h3::quic::SendStream<Bytes>,
{
  let response_send_timeout = http_proxy::downstream_response_send_timeout(&response);
  let (parts, mut body) = response.into_parts();
  let mut parts = parts;
  if let Some(interim) = parts
    .extensions
    .remove::<crate::proxy::http::semantics::InterimResponses>()
  {
    for response in interim.responses {
      let head = Response::builder()
        .status(response.status)
        .body(())
        .context("failed to build downstream HTTP/3 interim response")?;
      let (mut interim_parts, _) = head.into_parts();
      interim_parts.headers = response.headers;
      stream
        .send_response(Response::from_parts(interim_parts, ()))
        .await
        .context("failed to send downstream HTTP/3 interim response")?;
    }
  }

  let known_small_body_plan = take_h3_known_small_body_plan(&mut parts.extensions);
  let use_known_small_response_body = matches!(known_small_body_plan, H3KnownSmallBodyPlan::None)
    && use_h3_known_small_body_path(
      parts.extensions.get::<KnownSmallResponseBody>().is_some(),
      &body,
    );
  let head = Response::from_parts(parts, ());
  stream
    .send_response(head)
    .await
    .context("failed to send downstream HTTP/3 response headers")?;

  match known_small_body_plan {
    H3KnownSmallBodyPlan::CompiledNoopNoTrailers(data) => {
      let finalize_started = response_timing_start(response_timing.as_ref());
      let result = respond_to_h3_compiled_known_small_no_trailers(
        stream,
        data,
        response_send_timeout,
        response_timing.as_ref(),
      )
      .await;
      response_timing_record(
        response_timing.as_ref(),
        timing::STAGE_H3_KNOWN_SMALL_FINALIZE,
        result.is_ok(),
        finalize_started,
      );
      return result;
    }
    H3KnownSmallBodyPlan::Inlined(inlined) => {
      let finalize_started = response_timing_start(response_timing.as_ref());
      let result = respond_to_h3_inlined_known_small_body(
        stream,
        inlined,
        response_send_timeout,
        response_timing.as_ref(),
      )
      .await;
      response_timing_record(
        response_timing.as_ref(),
        timing::STAGE_H3_KNOWN_SMALL_FINALIZE,
        result.is_ok(),
        finalize_started,
      );
      return result;
    }
    H3KnownSmallBodyPlan::None => {}
  }

  if use_known_small_response_body {
    let finalize_started = response_timing_start(response_timing.as_ref());
    let result = respond_to_h3_known_small_body(
      stream,
      body,
      response_send_timeout,
      response_timing.as_ref(),
    )
    .await;
    response_timing_record(
      response_timing.as_ref(),
      timing::STAGE_H3_KNOWN_SMALL_FINALIZE,
      result.is_ok(),
      finalize_started,
    );
    return result;
  }

  loop {
    let frame_started = response_timing_start(response_timing.as_ref());
    let Some(frame) = body.frame().await else {
      break;
    };
    let frame = match frame {
      Ok(frame) => frame,
      Err(error) => {
        response_timing_record(
          response_timing.as_ref(),
          timing::STAGE_H3_RESPONSE_BODY_FRAME,
          false,
          frame_started,
        );
        return Err(anyhow::anyhow!(
          "failed to read downstream HTTP/3 response body: {error}"
        ));
      }
    };
    let frame = frame.into_data();
    response_timing_record(
      response_timing.as_ref(),
      timing::STAGE_H3_RESPONSE_BODY_FRAME,
      true,
      frame_started,
    );
    match frame {
      Ok(data) => {
        maybe_timeout(response_send_timeout, stream.send_data(data))
          .await
          .context("failed to send downstream HTTP/3 response data")?;
      }
      Err(frame) => {
        if let Ok(trailers) = frame.into_trailers() {
          maybe_timeout(response_send_timeout, stream.send_trailers(trailers))
            .await
            .context("failed to send downstream HTTP/3 response trailers")?;
        }
      }
    }
  }
  finish_h3_stream_with_timing(stream, response_send_timeout, response_timing.as_ref()).await?;

  Ok(())
}

fn response_timing_start(response_timing: Option<&H3ResponseTiming>) -> Option<Instant> {
  response_timing.and_then(H3ResponseTiming::start)
}

fn response_timing_record(
  response_timing: Option<&H3ResponseTiming>,
  stage: FastPathMetricStage,
  success: bool,
  started_at: Option<Instant>,
) {
  if let Some(response_timing) = response_timing {
    response_timing.record(stage, success, started_at);
  }
}

pub(super) fn use_h3_known_small_body_path(marked_known_small: bool, body: &ProxyBody) -> bool {
  marked_known_small
    && body
      .size_hint()
      .upper()
      .is_some_and(|upper| upper <= KNOWN_SMALL_BODY_MAX_BYTES as u64)
}

#[derive(Debug)]
pub(super) enum H3KnownSmallBodyPlan {
  CompiledNoopNoTrailers(Bytes),
  Inlined(InlinedKnownSmallResponseBody),
  None,
}

pub(super) fn take_h3_known_small_body_plan(
  extensions: &mut http::Extensions,
) -> H3KnownSmallBodyPlan {
  let compiled_noop = extensions
    .remove::<CompiledKnownSmallNoopResponse>()
    .is_some();
  let Some(inlined) = extensions.remove::<InlinedKnownSmallResponseBody>() else {
    return H3KnownSmallBodyPlan::None;
  };

  if compiled_noop && inlined.trailers.is_none() {
    return H3KnownSmallBodyPlan::CompiledNoopNoTrailers(inlined.data);
  }

  H3KnownSmallBodyPlan::Inlined(inlined)
}

async fn respond_to_h3_compiled_known_small_no_trailers<S>(
  stream: h3::server::RequestStream<S, Bytes>,
  data: Bytes,
  response_send_timeout: Option<Duration>,
  response_timing: Option<&H3ResponseTiming>,
) -> anyhow::Result<()>
where
  S: h3::quic::SendStream<Bytes>,
{
  if data.len() > KNOWN_SMALL_BODY_MAX_BYTES {
    anyhow::bail!(
      "downstream HTTP/3 compiled known-small response body exceeded {} bytes",
      KNOWN_SMALL_BODY_MAX_BYTES
    );
  }
  timeout_h3_compiled_known_small_send(
    response_send_timeout,
    send_h3_compiled_known_small_no_trailers(stream, data, response_timing),
  )
  .await
}

async fn send_h3_compiled_known_small_no_trailers<S>(
  mut stream: h3::server::RequestStream<S, Bytes>,
  data: Bytes,
  response_timing: Option<&H3ResponseTiming>,
) -> anyhow::Result<()>
where
  S: h3::quic::SendStream<Bytes>,
{
  if !data.is_empty() {
    stream
      .send_data(data)
      .await
      .context("failed to send downstream HTTP/3 response data")?;
  }
  finish_h3_stream_with_timing(stream, None, response_timing).await?;
  Ok(())
}

async fn timeout_h3_compiled_known_small_send<F>(
  timeout: Option<Duration>,
  future: F,
) -> anyhow::Result<()>
where
  F: std::future::Future<Output = anyhow::Result<()>>,
{
  match timeout {
    Some(timeout) => tokio::time::timeout(timeout, future)
      .await
      .context("downstream HTTP/3 response send timed out")?,
    None => future.await,
  }
}

async fn respond_to_h3_known_small_body<S>(
  mut stream: h3::server::RequestStream<S, Bytes>,
  body: ProxyBody,
  response_send_timeout: Option<Duration>,
  response_timing: Option<&H3ResponseTiming>,
) -> anyhow::Result<()>
where
  S: h3::quic::SendStream<Bytes>,
{
  let collected = collect_h3_known_small_body(body).await?;
  let trailers = collected.trailers;
  let data = collected.data;
  if !data.is_empty() {
    maybe_timeout(response_send_timeout, stream.send_data(data))
      .await
      .context("failed to send downstream HTTP/3 response data")?;
  }
  if let Some(trailers) = trailers {
    maybe_timeout(response_send_timeout, stream.send_trailers(trailers))
      .await
      .context("failed to send downstream HTTP/3 response trailers")?;
  }
  finish_h3_stream_with_timing(stream, response_send_timeout, response_timing).await?;
  Ok(())
}

async fn respond_to_h3_inlined_known_small_body<S>(
  mut stream: h3::server::RequestStream<S, Bytes>,
  inlined: InlinedKnownSmallResponseBody,
  response_send_timeout: Option<Duration>,
  response_timing: Option<&H3ResponseTiming>,
) -> anyhow::Result<()>
where
  S: h3::quic::SendStream<Bytes>,
{
  let (data, trailers) = inlined.into_parts();
  if data.len() > KNOWN_SMALL_BODY_MAX_BYTES {
    anyhow::bail!(
      "downstream HTTP/3 inlined known-small response body exceeded {} bytes",
      KNOWN_SMALL_BODY_MAX_BYTES
    );
  }
  if !data.is_empty() {
    maybe_timeout(response_send_timeout, stream.send_data(data))
      .await
      .context("failed to send downstream HTTP/3 response data")?;
  }
  if let Some(trailers) = trailers {
    maybe_timeout(response_send_timeout, stream.send_trailers(trailers))
      .await
      .context("failed to send downstream HTTP/3 response trailers")?;
  }
  finish_h3_stream_with_timing(stream, response_send_timeout, response_timing).await?;
  Ok(())
}

async fn finish_h3_stream_with_timing<S>(
  mut stream: h3::server::RequestStream<S, Bytes>,
  response_send_timeout: Option<Duration>,
  response_timing: Option<&H3ResponseTiming>,
) -> anyhow::Result<()>
where
  S: h3::quic::SendStream<Bytes>,
{
  let finish_started = response_timing_start(response_timing);
  let result = maybe_timeout(response_send_timeout, stream.finish())
    .await
    .context("failed to finish downstream HTTP/3 response");
  response_timing_record(
    response_timing,
    timing::STAGE_H3_STREAM_FINISH,
    result.is_ok(),
    finish_started,
  );
  result
}

#[derive(Debug)]
pub(super) struct H3KnownSmallBody {
  data: Bytes,
  trailers: Option<http::HeaderMap>,
}

pub(super) async fn collect_h3_known_small_body(
  mut body: ProxyBody,
) -> anyhow::Result<H3KnownSmallBody> {
  let mut first_chunk = None;
  let mut buffered = BytesMut::new();
  let mut total = 0usize;
  let mut trailers = None;

  while let Some(frame) = body.frame().await {
    let frame = frame.map_err(|error| {
      anyhow::anyhow!("failed to read downstream HTTP/3 response body: {error}")
    })?;
    match frame.into_data() {
      Ok(data) => {
        if data.is_empty() {
          continue;
        }
        total = total
          .checked_add(data.len())
          .context("downstream HTTP/3 known-small response body length overflow")?;
        if total > KNOWN_SMALL_BODY_MAX_BYTES {
          anyhow::bail!(
            "downstream HTTP/3 known-small response body exceeded {} bytes",
            KNOWN_SMALL_BODY_MAX_BYTES
          );
        }
        if first_chunk.is_none() && buffered.is_empty() {
          first_chunk = Some(data);
        } else {
          if let Some(first) = first_chunk.take() {
            buffered.reserve(total);
            buffered.extend_from_slice(&first);
          }
          buffered.extend_from_slice(&data);
        }
      }
      Err(frame) => {
        if let Ok(frame_trailers) = frame.into_trailers() {
          trailers = Some(frame_trailers);
          break;
        }
      }
    }
  }

  let data = if let Some(chunk) = first_chunk {
    chunk
  } else if buffered.is_empty() {
    Bytes::new()
  } else {
    buffered.freeze()
  };

  Ok(H3KnownSmallBody { data, trailers })
}

async fn maybe_timeout<F, T, E>(timeout: Option<Duration>, future: F) -> anyhow::Result<T>
where
  F: std::future::Future<Output = Result<T, E>>,
  E: std::error::Error + Send + Sync + 'static,
{
  match timeout {
    Some(timeout) => tokio::time::timeout(timeout, future)
      .await
      .context("downstream HTTP/3 response send timed out")?
      .map_err(Into::into),
    None => future.await.map_err(Into::into),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn compiled_known_small_send_timeout_covers_entire_future() {
    let result = timeout_h3_compiled_known_small_send(Some(Duration::from_millis(5)), async {
      tokio::time::sleep(Duration::from_secs(60)).await;
      Ok(())
    })
    .await;

    assert!(result.is_err());
    assert!(
      result
        .expect_err("pending send future should time out")
        .to_string()
        .contains("downstream HTTP/3 response send timed out")
    );
  }

  #[tokio::test]
  async fn compiled_known_small_send_timeout_allows_ready_future() {
    timeout_h3_compiled_known_small_send(Some(Duration::from_secs(1)), async { Ok(()) })
      .await
      .expect("ready send future should complete");
  }
}

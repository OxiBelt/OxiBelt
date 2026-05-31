use ::http::{Response, StatusCode};
use bytes::Bytes;
use hyper::body::Frame;
use serde_json::json;
use tokio::sync::broadcast;
use tokio::time::{Duration, interval};

use crate::proxy::http::body::{ProxyBody, boxed_error, channel_body};

use super::types::AdminOperationEvent;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum AdminOperationEventFormat {
  Sse,
  Ndjson,
}

pub(super) fn event_stream_response(
  history: Vec<AdminOperationEvent>,
  mut receiver: broadcast::Receiver<AdminOperationEvent>,
  format: AdminOperationEventFormat,
) -> Response<ProxyBody> {
  let (sender, body) = channel_body(8);
  tokio::spawn(async move {
    for event in history {
      let terminal = event.operation.state.is_terminal();
      if sender
        .send(Ok(Frame::data(encode_event(&event, format))))
        .await
        .is_err()
      {
        return;
      }
      if terminal {
        return;
      }
    }
    let mut heartbeat = interval(Duration::from_secs(15));
    loop {
      tokio::select! {
        biased;
        received = receiver.recv() => {
          match received {
            Ok(event) => {
              let terminal = event.operation.state.is_terminal();
              if sender.send(Ok(Frame::data(encode_event(&event, format)))).await.is_err() {
                return;
              }
              if terminal {
                return;
              }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => {
              let error = boxed_error(std::io::Error::other("operation event stream lagged"));
              let _ = sender.send(Err(error)).await;
              return;
            }
            Err(broadcast::error::RecvError::Closed) => return,
          }
        }
        _ = heartbeat.tick() => {
          let bytes = match format {
            AdminOperationEventFormat::Sse => Bytes::from_static(b": heartbeat\n\n"),
            AdminOperationEventFormat::Ndjson => Bytes::from_static(br#"{"event":"heartbeat"}"#),
          };
          let bytes = if format == AdminOperationEventFormat::Ndjson {
            let mut line = bytes.to_vec();
            line.push(b'\n');
            Bytes::from(line)
          } else {
            bytes
          };
          if sender.send(Ok(Frame::data(bytes))).await.is_err() {
            return;
          }
        }
      }
    }
  });

  let mut response = Response::new(body);
  *response.status_mut() = StatusCode::OK;
  response.headers_mut().insert(
    ::http::header::CONTENT_TYPE,
    ::http::HeaderValue::from_static(match format {
      AdminOperationEventFormat::Sse => "text/event-stream",
      AdminOperationEventFormat::Ndjson => "application/x-ndjson",
    }),
  );
  response.headers_mut().insert(
    ::http::header::CACHE_CONTROL,
    ::http::HeaderValue::from_static("no-store"),
  );
  response
}

fn encode_event(event: &AdminOperationEvent, format: AdminOperationEventFormat) -> Bytes {
  match format {
    AdminOperationEventFormat::Sse => encode_sse_event(event),
    AdminOperationEventFormat::Ndjson => encode_ndjson_event(event),
  }
}

pub(in crate::server) fn encode_ndjson_event(event: &AdminOperationEvent) -> Bytes {
  let mut bytes =
    serde_json::to_vec(event).unwrap_or_else(|_| br#"{"event":"operation.error"}"#.to_vec());
  bytes.push(b'\n');
  Bytes::from(bytes)
}

fn encode_sse_event(event: &AdminOperationEvent) -> Bytes {
  let data = serde_json::to_string(event).unwrap_or_else(|_| {
    json!({
      "sequence": event.sequence,
      "event": "operation.error",
      "created_at_unix_ms": event.created_at_unix_ms,
    })
    .to_string()
  });
  Bytes::from(format!(
    "id: {}\nevent: {}\ndata: {}\n\n",
    event.sequence, event.event, data
  ))
}

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use http_body_util::{BodyExt, Empty, Full};

use super::*;

#[tokio::test]
async fn clean_response_eof_does_not_cancel_upload() {
  let exchange = IncrementalExchange::new();
  let response = wrap_response_body(
    Empty::<Bytes>::new()
      .map_err(|never| match never {})
      .boxed(),
    exchange.clone(),
  );
  response.collect().await.expect("response should complete");
  assert!(!exchange.is_cancelled());
  assert!(!exchange.is_complete());
  exchange.mark_upload_complete();
  assert!(exchange.is_complete());
}

#[tokio::test]
async fn response_drop_cancels_pending_request_body() {
  let exchange = IncrementalExchange::new();
  let response = wrap_response_body(
    Full::new(Bytes::from_static(b"response"))
      .map_err(|never| match never {})
      .boxed(),
    exchange.clone(),
  );
  drop(response);

  let request = wrap_request_body(
    Empty::<Bytes>::new()
      .map_err(|never| match never {})
      .boxed(),
    exchange.clone(),
  );
  assert!(request.collect().await.is_err());
  assert!(exchange.is_cancelled());
  assert!(exchange.is_complete());
}

#[tokio::test]
async fn exact_content_length_final_data_completes_without_eof_poll() {
  let exchange = IncrementalExchange::new();
  let source = observe_upstream_response_body(
    Full::new(Bytes::from_static(b"ok"))
      .map_err(|never| match never {})
      .boxed(),
    exchange.clone(),
  );
  let mut response = wrap_response_body_with_length(source, exchange.clone(), Some(2));
  let frame = response
    .frame()
    .await
    .expect("final data frame should exist")
    .expect("final data frame should succeed");
  assert_eq!(frame.data_ref().expect("data frame").as_ref(), b"ok");
  assert!(response.is_end_stream());
  drop(response);
  assert!(!exchange.is_cancelled());
  assert!(exchange.response_is_complete());
  assert!(
    !exchange.is_complete(),
    "upload may still outlive response data"
  );
  exchange.mark_upload_complete();
  assert!(exchange.is_complete());
}

#[tokio::test]
async fn incomplete_content_length_still_cancels_on_drop() {
  let exchange = IncrementalExchange::new();
  let mut response = wrap_response_body_with_length(
    Full::new(Bytes::from_static(b"o"))
      .map_err(|never| match never {})
      .boxed(),
    exchange.clone(),
    Some(2),
  );
  response
    .frame()
    .await
    .expect("data frame should exist")
    .expect("data frame should succeed");
  assert!(!response.is_end_stream());
  drop(response);
  assert!(exchange.is_cancelled());
}

#[tokio::test]
async fn short_content_length_eof_fails_response_and_cancels_upload() {
  let exchange = IncrementalExchange::new();
  let mut response = wrap_response_body_with_length(
    Full::new(Bytes::from_static(b"o"))
      .map_err(|never| match never {})
      .boxed(),
    exchange.clone(),
    Some(2),
  );
  response
    .frame()
    .await
    .expect("short data frame should exist")
    .expect("short data frame should succeed");
  let error = response
    .frame()
    .await
    .expect("short EOF should become an error")
    .expect_err("short EOF must not complete cleanly");
  assert!(error.to_string().contains("ended before Content-Length"));
  assert!(exchange.is_cancelled());
  assert!(exchange.response_is_complete());
}

#[tokio::test]
async fn overlong_content_length_fails_response_and_cancels_upload() {
  let exchange = IncrementalExchange::new();
  let mut response = wrap_response_body_with_length(
    Full::new(Bytes::from_static(b"too"))
      .map_err(|never| match never {})
      .boxed(),
    exchange.clone(),
    Some(2),
  );
  let error = response
    .frame()
    .await
    .expect("overlong frame should become an error")
    .expect_err("overlong body must not complete cleanly");
  assert!(error.to_string().contains("exceeded Content-Length"));
  assert!(exchange.is_cancelled());
}

#[tokio::test]
async fn upload_can_finish_after_response_eof() {
  let exchange = IncrementalExchange::new();
  let response = wrap_response_body(
    Empty::<Bytes>::new()
      .map_err(|never| match never {})
      .boxed(),
    exchange.clone(),
  );
  response.collect().await.expect("response should complete");

  let (sender, request) = super::super::body::channel_body(2);
  sender
    .send(Ok(Frame::data(Bytes::from_static(b"later upload"))))
    .await
    .expect("request frame should queue");
  drop(sender);
  let request = wrap_request_body(request, exchange.clone());
  assert_eq!(
    request
      .collect()
      .await
      .expect("upload should remain live")
      .to_bytes(),
    Bytes::from_static(b"later upload")
  );
  assert!(exchange.is_complete());
  assert!(!exchange.is_cancelled());
}

#[tokio::test]
async fn transport_owned_request_eof_waits_for_transport_completion() {
  let exchange = IncrementalExchange::new();
  exchange.mark_response_complete();
  let request = wrap_request_body_for_transport(
    Empty::<Bytes>::new()
      .map_err(|never| match never {})
      .boxed(),
    exchange.clone(),
  );
  request
    .collect()
    .await
    .expect("empty source should complete");
  assert!(
    !exchange.is_complete(),
    "HTTP/3 source EOF alone must not release retained resources before FIN/reset"
  );
  exchange.mark_upload_complete();
  assert!(exchange.is_complete());
}

#[tokio::test]
async fn upload_failure_reaches_response_body() {
  let exchange = IncrementalExchange::new();
  exchange.fail_upload("upstream upload failed");
  let mut response = wrap_response_body(
    Empty::<Bytes>::new()
      .map_err(|never| match never {})
      .boxed(),
    exchange.clone(),
  );
  let frame = response.frame().await.expect("failure frame should exist");
  assert!(frame.is_err());
  assert!(exchange.is_complete());
}

#[tokio::test]
async fn upload_failure_wakes_a_pending_response_read() {
  let exchange = IncrementalExchange::new();
  let (sender, body) = super::super::body::channel_body(1);
  let mut response = wrap_response_body(body, exchange.clone());
  let failed = exchange.clone();
  tokio::spawn(async move {
    tokio::task::yield_now().await;
    failed.fail_upload("upstream upload failed");
    drop(sender);
  });
  let frame = tokio::time::timeout(std::time::Duration::from_secs(1), response.frame())
    .await
    .expect("response read should be woken")
    .expect("failure frame should exist");
  assert!(frame.is_err());
}

#[test]
fn retained_resources_release_only_after_both_halves_finish() {
  let exchange = IncrementalExchange::new();
  let dropped = Arc::new(AtomicBool::new(false));
  struct Guard(Arc<AtomicBool>);
  impl Drop for Guard {
    fn drop(&mut self) {
      self.0.store(true, Ordering::Release);
    }
  }
  exchange.retain(Guard(Arc::clone(&dropped)));
  exchange.mark_response_complete();
  assert!(!dropped.load(Ordering::Acquire));
  exchange.mark_upload_complete();
  assert!(dropped.load(Ordering::Acquire));
}

#[test]
fn concurrent_terminal_halves_release_retained_resources() {
  struct Guard(Arc<AtomicBool>);
  impl Drop for Guard {
    fn drop(&mut self) {
      self.0.store(true, Ordering::Release);
    }
  }

  // Exercise the release race repeatedly: the two halves complete on
  // separate threads at the same barrier, so neither may rely on seeing a
  // distinct atomic store from the other half.
  for _ in 0..256 {
    let exchange = IncrementalExchange::new();
    let dropped = Arc::new(AtomicBool::new(false));
    exchange.retain(Guard(Arc::clone(&dropped)));
    let barrier = Arc::new(std::sync::Barrier::new(3));

    let upload_exchange = exchange.clone();
    let upload_barrier = Arc::clone(&barrier);
    let upload = std::thread::spawn(move || {
      upload_barrier.wait();
      upload_exchange.mark_upload_complete();
    });

    let response_exchange = exchange.clone();
    let response_barrier = Arc::clone(&barrier);
    let response = std::thread::spawn(move || {
      response_barrier.wait();
      response_exchange.mark_response_complete();
    });

    barrier.wait();
    upload
      .join()
      .expect("upload terminal thread should not panic");
    response
      .join()
      .expect("response terminal thread should not panic");
    assert!(exchange.is_complete());
    assert!(
      dropped.load(Ordering::Acquire),
      "retained resource must release once both terminal bits are set"
    );
  }
}

#[test]
fn retained_drop_can_reenter_exchange_without_deadlocking() {
  struct Reentrant(IncrementalExchange);
  impl Drop for Reentrant {
    fn drop(&mut self) {
      self.0.mark_response_complete();
    }
  }

  let exchange = IncrementalExchange::new();
  exchange.mark_upload_complete();
  exchange.retain(Reentrant(exchange.clone()));
  exchange.mark_response_complete();
  assert!(exchange.is_complete());
}

#[test]
fn response_guard_finishes_an_unstarted_h3_upload_on_unwind() {
  let exchange = IncrementalExchange::new();
  exchange.arm_unstarted_upload();
  drop(exchange.begin_response());
  assert!(exchange.is_cancelled());
  assert!(exchange.is_complete());
}

#[test]
fn managed_h3_dispatch_guard_leaves_upload_to_fin_or_reset() {
  let exchange = IncrementalExchange::new();
  exchange.arm_unstarted_upload();
  assert!(exchange.claim_unstarted_upload());
  drop(exchange.begin_dispatch().uploader_started());
  assert!(exchange.is_cancelled());
  assert!(
    !exchange.is_complete(),
    "post-spawn response failure must wait for sender FIN/reset"
  );
  exchange.mark_upload_complete();
  assert!(exchange.is_complete());
}

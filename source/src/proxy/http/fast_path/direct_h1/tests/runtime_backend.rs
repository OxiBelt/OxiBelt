use http::Request;
use http::header::TRANSFER_ENCODING;
use url::Url;

use super::*;

#[test]
fn compio_transport_stays_h1_only_for_empty_wire_requests() {
  let origin = DirectH1Origin::from_url(&Url::parse("http://backend.internal:18080").unwrap())
    .expect("origin should be direct-H1 eligible");
  let request = Request::builder()
    .method(Method::GET)
    .version(http::Version::HTTP_11)
    .uri("/perf/h1?body=ok")
    .body(empty_body())
    .unwrap();

  let prepared = PreparedDirectH1Request::from_request(request, &origin).unwrap();

  assert!(compio_transport_eligible(
    FastPathMetricProtocol::H1,
    &prepared
  ));
  assert!(!compio_transport_eligible(
    FastPathMetricProtocol::H2,
    &prepared
  ));
  assert!(!compio_transport_eligible(
    FastPathMetricProtocol::H3,
    &prepared
  ));
}

#[test]
fn compio_transport_rejects_empty_transfer_encoded_wire_request() {
  let origin = DirectH1Origin::from_url(&Url::parse("http://backend.internal:18080").unwrap())
    .expect("origin should be direct-H1 eligible");
  let request = Request::builder()
    .method(Method::GET)
    .version(http::Version::HTTP_11)
    .uri("/perf/h1?body=ok")
    .header(TRANSFER_ENCODING, "chunked")
    .body(empty_body())
    .unwrap();

  let prepared = PreparedDirectH1Request::from_request(request, &origin).unwrap();

  assert!(!compio_transport_eligible(
    FastPathMetricProtocol::H1,
    &prepared
  ));
}

#[test]
fn compio_h2_fallback_records_hyper_selection() {
  let metrics = Metrics::new();

  record_runtime_backend_selection(
    &metrics,
    FastPathMetricProtocol::H2,
    DirectH1RuntimeBackend::Compio,
    false,
  );

  let body = metrics_prometheus(&metrics);
  assert!(
    body.contains(
      "oxibelt_http_direct_h1_io_backend_total{backend=\"compio\",protocol=\"h2\",outcome=\"fallback\"} 1"
    ),
    "missing compio fallback metric:\n{body}"
  );
  assert!(
    body.contains(
      "oxibelt_http_direct_h1_io_backend_total{backend=\"tokio_hyper\",protocol=\"h2\",outcome=\"selected\"} 1"
    ),
    "missing tokio_hyper selection metric:\n{body}"
  );
  assert!(
    body.contains(
      "oxibelt_http_direct_h1_io_backend_total{backend=\"compio\",protocol=\"h2\",outcome=\"selected\"} 0"
    ),
    "compio h2 should not be selected:\n{body}"
  );
}

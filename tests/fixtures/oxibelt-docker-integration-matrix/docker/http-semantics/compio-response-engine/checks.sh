direct_h1_io_backend_metric_value() {
  local metrics="$1" backend="$2" outcome="$3"
  jq -r \
    --arg backend "${backend}" \
    --arg outcome "${outcome}" '
      (
        "oxibelt_http_direct_h1_io_backend_total{backend=\""
        + $backend
        + "\",protocol=\"h1\",outcome=\""
        + $outcome
        + "\"} "
      ) as $prefix
      | .body
      | split("\n")
      | map(select(startswith($prefix)))
      | .[0] // ""
      | split(" ")
      | .[1] // empty
    ' <<<"${metrics}"
}

run_case_checks() {
  local response metrics compio_selected compio_fallback compio_errors tokio_selected

  response="$(client_request \
    "example.test" \
    "/app/fixed?body=compio-fixed&content_type=text/plain" \
    200)"
  assert_response_jq "${response}" '
    .headers["content-type"] == "text/plain"
    and .body == "compio-fixed"
  '

  response="$(client_request \
    "example.test" \
    "/app/interim?early_hints=1&early_link=%3C/app.css%3E;%20rel=preload;%20as=style&body=compio-final&content_type=text/plain" \
    200)"
  assert_response_jq "${response}" '
    .status == 200
    and .headers["content-type"] == "text/plain"
    and .body == "compio-final"
  '

  response="$(client_request \
    "example.test" \
    "/app/chunked?body=chunk-one-chunk-two&content_type=text/plain&chunked_response=1&body_split_at=9&body_split_delay_ms=400" \
    200)"
  assert_response_jq "${response}" '
    .headers["content-type"] == "text/plain"
    and .body == "chunk-one-chunk-two"
  '

  response="$(client_request \
    "example.test" \
    "/events/progress?body=data:%20first%0A%0Adata:%20second%0A%0A&content_type=text/event-stream&body_split_at=13&body_split_delay_ms=1200" \
    200)"
  assert_response_jq "${response}" '
    .headers["content-type"] == "text/event-stream"
    and .body == "data: first\n\ndata: second\n\n"
  '

  metrics="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  assert_response_jq "${metrics}" '.body | contains("oxibelt_requests_total")'

  compio_selected="$(
    direct_h1_io_backend_metric_value "${metrics}" compio selected
  )"
  compio_fallback="$(
    direct_h1_io_backend_metric_value "${metrics}" compio fallback
  )"
  compio_errors="$(
    direct_h1_io_backend_metric_value "${metrics}" compio error
  )"
  tokio_selected="$(
    direct_h1_io_backend_metric_value "${metrics}" tokio_hyper selected
  )"

  if [[ ! "${compio_selected}" =~ ^[0-9]+$ ]] || ((compio_selected < 4)); then
    fail_with_diagnostics "Compio direct-H1 backend was not selected for all response-engine checks"
  fi
  if [[ "${compio_fallback}" != "0" || "${compio_errors}" != "0" || "${tokio_selected}" != "0" ]]; then
    fail_with_diagnostics "Compio response-engine checks unexpectedly fell back or failed"
  fi
}

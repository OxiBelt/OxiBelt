
run_case_checks() {
  local response
  response="$(client_request "example.test" "/events/stream?body=data:%20hello%0A%0A&content_type=text/event-stream" 200)"
  assert_response_jq "${response}" '.headers["content-type"] == "text/event-stream" and .body == "data: hello\n\n"'

  response="$(client_request_with_headers_to_target "proxy" 8443 "missing.example.test" "/app/error" 502,504 "GET" "")"
  assert_response_jq "${response}" '(.status == 502 or .status == 504) and (.body | fromjson | (.code == "connect_error" or .code == "read_timeout"))'

  response="$(client_request_with_headers "grpc.example.test" "/grpc.Matrix/Unary" 200 "POST" "" "Content-Type: application/grpc" "Grpc-Timeout: 1S")"
  assert_response_jq "${response}" '.headers["grpc-status"] == "14"'
}

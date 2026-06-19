
run_case_checks() {
  local response
  response="$(client_request_with_headers "example.test" "/grpc.Matrix/Unary" 200 "POST" "abcde" "Content-Type: application/grpc-web+proto" "X-Grpc-Web: 1")"
  assert_response_jq "${response}" '.headers["content-type"] == "application/grpc-web"'
  assert_response_jq "${response}" '.body | contains("h2c-upstream")'
  assert_response_jq "${response}" '.body | contains("application/grpc")'
}

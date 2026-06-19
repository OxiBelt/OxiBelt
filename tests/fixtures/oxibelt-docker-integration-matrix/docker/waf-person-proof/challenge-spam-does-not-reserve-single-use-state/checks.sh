
run_case_checks() {
  local pow_one pow_two redirect_one redirect_two redirect_three session verify_path verify_body first_verify second_verify

  pow_one="$(client_request "example.test" "/app/proof" 403)"
  assert_response_jq "${pow_one}" '.body | contains("person-proof")'

  pow_two="$(client_request "example.test" "/app/proof" 403)"
  assert_response_jq "${pow_two}" '.body | contains("person-proof")'

  redirect_one="$(client_request "example.test" "/app/provider-proof?next=%2Fapp%2Fdone" 303)"
  assert_response_jq "${redirect_one}" '.headers.location | startswith("/person-proof/index.html?")'

  redirect_two="$(client_request "example.test" "/app/provider-proof?next=%2Fapp%2Fdone" 303)"
  assert_response_jq "${redirect_two}" '.headers.location | startswith("/person-proof/index.html?")'

  read -r session verify_path < <(jq -r '.headers.location' <<<"${redirect_one}" | python3 -c '
import sys
from urllib.parse import parse_qs, urlsplit
query = parse_qs(urlsplit(sys.stdin.read().strip()).query)
print(query["session"][0], query["verify_path"][0])
')
  verify_body="$(printf '{"session":"%s","response":{"token":"mock-token","fields":{"fixture":"capacity"}}}' "${session}")"
  first_verify="$(client_request_with_headers "example.test" "${verify_path}" 403 "POST" "${verify_body}" "Content-Type: application/json")"
  assert_response_jq "${first_verify}" '.body == "person proof verification failed"'

  redirect_three="$(client_request "example.test" "/app/provider-proof?next=%2Fapp%2Fdone" 303)"
  read -r session verify_path < <(jq -r '.headers.location' <<<"${redirect_three}" | python3 -c '
import sys
from urllib.parse import parse_qs, urlsplit
query = parse_qs(urlsplit(sys.stdin.read().strip()).query)
print(query["session"][0], query["verify_path"][0])
')
  verify_body="$(printf '{"session":"%s","response":{"token":"mock-token","fields":{"fixture":"capacity"}}}' "${session}")"
  second_verify="$(client_request_with_headers "example.test" "${verify_path}" 429 "POST" "${verify_body}" "Content-Type: application/json")"
  assert_response_jq "${second_verify}" '.body == "person proof token capacity exhausted"'
}

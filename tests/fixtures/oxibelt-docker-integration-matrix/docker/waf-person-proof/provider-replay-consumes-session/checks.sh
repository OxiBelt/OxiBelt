
run_case_checks() {
  local redirect session verify_path verify_body first replay

  redirect="$(client_request "example.test" "/app/provider-proof?next=%2Fapp%2Fdone" 303)"
  read -r session verify_path < <(jq -r '.headers.location' <<<"${redirect}" | python3 -c '
import sys
from urllib.parse import parse_qs, urlsplit
query = parse_qs(urlsplit(sys.stdin.read().strip()).query)
print(query["session"][0], query["verify_path"][0])
')

  verify_body="$(printf '{"session":"%s","response":{"token":"mock-token","fields":{"fixture":"replay"}}}' "${session}")"
  first="$(client_request_with_headers "example.test" "${verify_path}" 403 "POST" "${verify_body}" "Content-Type: application/json")"
  assert_response_jq "${first}" '.body == "person proof verification failed"'

  replay="$(client_request_with_headers "example.test" "${verify_path}" 403 "POST" "${verify_body}" "Content-Type: application/json")"
  assert_response_jq "${replay}" '.body == "person proof session is invalid"'
}


run_case_checks() {
  local ui redirect session session_doc openapi verify cookie allowed session_path verify_path openapi_path verify_body

  ui="$(client_request "example.test" "/person-proof/index.html" 200)"
  assert_response_jq "${ui}" '.body | contains("provider challenge fixture")'

  redirect="$(client_request "example.test" "/app/provider-proof?next=%2Fapp%2Fdone" 303)"
  assert_response_jq "${redirect}" '.headers.location | startswith("/person-proof/index.html?")'
  assert_response_jq "${redirect}" '.headers.location | contains("session=")'
  assert_response_jq "${redirect}" '.headers.location | contains("session_path=%2F.oxibelt%2Fperson-proof%2Fsession")'
  assert_response_jq "${redirect}" '.headers.location | contains("verify_path=%2F.oxibelt%2Fperson-proof%2Fverify")'
  assert_response_jq "${redirect}" '.headers.location | contains("openapi_path=%2F.oxibelt%2Fperson-proof%2Fopenapi.json")'
  assert_response_jq "${redirect}" '.headers.location | contains("site_key") | not'
  read -r session session_path verify_path openapi_path < <(jq -r '.headers.location' <<<"${redirect}" | python3 -c '
import sys
from urllib.parse import parse_qs, urlsplit
query = parse_qs(urlsplit(sys.stdin.read().strip()).query)
print(query["session"][0], query["session_path"][0], query["verify_path"][0], query["openapi_path"][0])
')

  session_doc="$(client_request "example.test" "${session_path}?session=${session}" 200)"
  assert_body_jq "${session_doc}" '.person_proof_mode == "custom_provider"'
  assert_body_jq "${session_doc}" '.provider == "matrix-provider"'
  assert_body_jq "${session_doc}" '.challenge.kind == "proof_of_knowledge_v1"'
  assert_body_jq "${session_doc}" '.challenge.proof_kind == "knowledge"'
  assert_body_jq "${session_doc}" '.challenge.label == "matrix-knowledge"'
  assert_body_jq "${session_doc}" '.challenge.provider == "matrix-provider"'
  assert_body_jq "${session_doc}" '.challenge.metadata.fixture == "provider-mock-verify"'
  assert_body_jq "${session_doc}" '.verify_path == "/.oxibelt/person-proof/verify"'
  assert_body_jq "${session_doc}" '.clearance.issue_to == "cookie"'
  assert_body_jq "${session_doc}" '.clearance.cookie.key == "__matrix_provider_person_proof"'
  assert_body_jq "${session_doc}" '.clearance.sources[0].type == "cookie"'
  assert_body_jq "${session_doc}" '.clearance.sources[0].key == "__matrix_provider_person_proof"'

  openapi="$(client_request "example.test" "${openapi_path}" 200)"
  assert_response_jq "${openapi}" '.headers["cache-control"] == "no-store"'
  assert_response_jq "${openapi}" '.body | contains("/.oxibelt/person-proof/session")'
  assert_response_jq "${openapi}" '.body | contains("ClearanceMetadata")'
  assert_response_jq "${openapi}" '.body | contains("proof_kind")'

  verify_body="$(printf '{"session":"%s","response":{"token":"mock-token","fields":{"fixture":"matrix"}}}' "${session}")"
  verify="$(client_request_with_headers "example.test" "${verify_path}" 200 "POST" "${verify_body}" "Content-Type: application/json")"
  assert_body_jq "${verify}" '.ok == true'
  assert_body_jq "${verify}" '.return_path == "/app/provider-proof?next=%2Fapp%2Fdone"'
  assert_body_jq "${verify}" '.clearance.issue_to == "cookie"'
  assert_body_jq "${verify}" '.clearance.cookie.key == "__matrix_provider_person_proof"'
  assert_body_jq "${verify}" '.clearance | has("token") | not'
  assert_response_jq "${verify}" '.headers["set-cookie"] | contains("__matrix_provider_person_proof=clearance.v2.")
    and contains("Secure")
    and contains("HttpOnly")'
  cookie="$(jq -r '.headers["set-cookie"]' <<<"${verify}" | cut -d';' -f1)"

  allowed="$(client_request_with_headers "example.test" "/app/provider-proof?next=%2Fapp%2Fdone" 200 "GET" "" "Cookie: ${cookie}")"
  assert_body_jq "${allowed}" '.path == "/origin/app/provider-proof?next=%2Fapp%2Fdone"'
}

digest_want='sha-512=5, sha-256=5'

digest_response() {
  local protocol="$1"
  local path="$2"
  local expected_status=200
  shift 2
  if [[ $# -gt 0 && "$1" =~ ^[1-5][0-9]{2}$ ]]; then
    expected_status="$1"
    shift
  fi
  local args=(
    --header "Want-Content-Digest: ${digest_want}"
    --header "Want-Repr-Digest: ${digest_want}"
    --header "Want-Unencoded-Digest: ${digest_want}"
  )
  if [[ "${protocol}" == "h1" ]]; then
    args+=(--header "TE: trailers")
  fi
  protocol_probe_client "${protocol}" "example.test" "${path}" "${expected_status}" "${args[@]}" "$@"
}

assert_digest_fields() {
  local response="$1"
  local location="$2"
  local encoding="$3"
  local algorithm="${4:-sha-256}"
  python3 -c '
import base64
import gzip
import hashlib
import json
import re
import sys

response = json.load(sys.stdin)
location, encoding, algorithm = sys.argv[1:]
other = "trailers" if location == "headers" else "headers"
body = base64.b64decode(response["body_base64"])
representation = gzip.decompress(body) if encoding == "gzip" else body
digest = hashlib.sha512 if algorithm == "sha-512" else hashlib.sha256
expected = {
    "content-digest": digest(body).digest(),
    "repr-digest": digest(body).digest(),
    "unencoded-digest": digest(representation).digest(),
}
for name, digest in expected.items():
    value = response[location].get(name)
    if value is None:
        raise SystemExit(f"{name} was not emitted in {location}: {response}")
    if response[other].get(name) is not None:
        raise SystemExit(f"{name} appeared in both headers and trailers: {response}")
    match = re.fullmatch(re.escape(algorithm) + r"=:([A-Za-z0-9+/]+={0,2}):", value)
    if match is None:
        raise SystemExit(f"{name} did not choose exactly {algorithm}: {value!r}")
    if base64.b64decode(match.group(1), validate=True) != digest:
        raise SystemExit(f"{name} did not match its selected representation")
' "${location}" "${encoding}" "${algorithm}" <<<"${response}"
}

assert_digest_fields_anywhere() {
  local response="$1"
  local encoding="$2"
  local algorithm="${3:-sha-256}"
  python3 -c '
import base64
import gzip
import hashlib
import json
import re
import sys

response = json.load(sys.stdin)
encoding, algorithm = sys.argv[1:]
body = base64.b64decode(response["body_base64"])
representation = gzip.decompress(body) if encoding == "gzip" else body
digest = hashlib.sha512 if algorithm == "sha-512" else hashlib.sha256
expected = {
    "content-digest": digest(body).digest(),
    "repr-digest": digest(body).digest(),
    "unencoded-digest": digest(representation).digest(),
}
for name, digest in expected.items():
    locations = [container for container in ("headers", "trailers") if response[container].get(name)]
    if len(locations) != 1:
        raise SystemExit(f"{name} did not appear exactly once: {response}")
    value = response[locations[0]][name]
    match = re.fullmatch(re.escape(algorithm) + r"=:([A-Za-z0-9+/]+={0,2}):", value)
    if match is None or base64.b64decode(match.group(1), validate=True) != digest:
        raise SystemExit(f"{name} did not match its selected representation")
' "${encoding}" "${algorithm}" <<<"${response}"
}

assert_no_generated_digests() {
  local response="$1"
  if ! jq -e '
    (.headers["content-digest"] == null and .headers["repr-digest"] == null and .headers["unencoded-digest"] == null)
    and (.trailers["content-digest"] == null and .trailers["repr-digest"] == null and .trailers["unencoded-digest"] == null)
  ' <<<"${response}" >/dev/null; then
    echo "${response}" >&2
    fail_with_diagnostics "response unexpectedly carried generated digest fields"
  fi
}

assert_static_digest_fields() {
  local response="$1"
  local content_mode="$2"
  python3 -c '
import base64
import hashlib
import json
import re
import sys

response = json.load(sys.stdin)
content_mode = sys.argv[1]
body = base64.b64decode(response["body_base64"])
full = b"0123456789abcdef\n"
content = b"" if content_mode == "empty" else body
expected = {
    "content-digest": hashlib.sha256(content).digest(),
    "repr-digest": hashlib.sha256(full).digest(),
    "unencoded-digest": hashlib.sha256(full).digest(),
}
for name, digest in expected.items():
    locations = [container for container in ("headers", "trailers") if response[container].get(name)]
    if len(locations) != 1:
        raise SystemExit(f"{name} did not appear exactly once: {response}")
    value = response[locations[0]][name]
    match = re.fullmatch(r"sha-256=:([A-Za-z0-9+/]+={0,2}):", value)
    if match is None or base64.b64decode(match.group(1), validate=True) != digest:
        raise SystemExit(f"{name} did not cover the expected static bytes")
' "${content_mode}" <<<"${response}"
}

assert_content_digest_anywhere() {
  local response="$1"
  python3 -c '
import base64
import hashlib
import json
import re
import sys

response = json.load(sys.stdin)
body = base64.b64decode(response["body_base64"])
locations = [container for container in ("headers", "trailers") if response[container].get("content-digest")]
if len(locations) != 1:
    raise SystemExit(f"Content-Digest did not appear exactly once: {response}")
value = response[locations[0]]["content-digest"]
match = re.fullmatch(r"sha-256=:([A-Za-z0-9+/]+={0,2}):", value)
if match is None or base64.b64decode(match.group(1), validate=True) != hashlib.sha256(body).digest():
    raise SystemExit("Content-Digest did not cover the delivered bytes")
if response["headers"].get("repr-digest") or response["trailers"].get("repr-digest") or response["headers"].get("unencoded-digest") or response["trailers"].get("unencoded-digest"):
    raise SystemExit(f"mutation response generated representation fields: {response}")
' <<<"${response}"
}

run_case_checks() {
  local downstream upstream response origin first cached compressed ranged head no_te request_reencoded

  # Every HTTP/1.1, HTTP/2, and HTTP/3 ingress/upstream pairing negotiates the
  # equal-weight preference to sha-256. Upstream bytes are streamed, so each
  # verified field can correctly land in either headers or trailers.
  for downstream in h1 h2 h3; do
    for upstream in h1 h2 h3; do
      response="$(digest_response "${downstream}" "/${upstream}/known?body=${downstream}-${upstream}")"
      assert_response_jq "${response}" '.status == 200'
      assert_digest_fields_anywhere "${response}" identity
    done
  done

  # A strictly higher positive weight chooses sha-512; equal weights above
  # deliberately choose sha-256 in the matrix above.
  response="$(protocol_probe_client h2 example.test "/h1/sha512?body=sha512-preferred" 200 \
    --header "Want-Content-Digest: sha-512=6, sha-256=5" \
    --header "Want-Repr-Digest: sha-512=6, sha-256=5" \
    --header "Want-Unencoded-Digest: sha-512=6, sha-256=5")"
  assert_digest_fields_anywhere "${response}" identity sha-512

  response="$(digest_response h2 "/h2c/known?body=h2c")"
  assert_response_jq "${response}" '.negotiated_protocol == "h2" and .status == 200'
  assert_digest_fields_anywhere "${response}" identity

  # A negotiated field is not created when there is no positive preference.
  response="$(protocol_probe_client h2 example.test "/h1/no-want?body=no-want" 200)"
  assert_no_generated_digests "${response}"
  response="$(protocol_probe_client h3 example.test "/h3/q-zero?body=q-zero" 200 \
    --header "Want-Content-Digest: sha-256=0" \
    --header "Want-Repr-Digest: sha-256=0" \
    --header "Want-Unencoded-Digest: sha-256=0")"
  assert_no_generated_digests "${response}"

  # Origin values remain transparent even when their digest payload is not a
  # valid SHA-256 length and a positive preference would otherwise generate one.
  origin="$(protocol_probe_client h2 example.test "/h1/origin?content_digest=sha-256=:AQ==:" 200 \
    --header "Want-Content-Digest: sha-256=1")"
  assert_response_jq "${origin}" '.headers["content-digest"] == "sha-256=:AQ==:"'

  # An upstream without a known length requires actual late trailers. HTTP/1.1
  # only receives them after advertising TE: trailers; HTTP/2 and HTTP/3 do not.
  for downstream in h1 h2 h3; do
    response="$(digest_response "${downstream}" "/h1/stream?chunked_response=1&body=late-${downstream}")"
    if [[ "${downstream}" == "h1" ]]; then
      assert_response_jq "${response}" '.wire.chunked == true and .wire.chunk_count >= 1'
    fi
    assert_digest_fields "${response}" trailers identity
  done
  no_te="$(protocol_probe_client h1 example.test "/h1/no-te?chunked_response=1&body=no-te" 200 \
    --header "Want-Content-Digest: sha-256=1" \
    --header "Want-Repr-Digest: sha-256=1" \
    --header "Want-Unencoded-Digest: sha-256=1")"
  assert_response_jq "${no_te}" '.wire.chunked == true and .body == "no-te"'
  assert_no_generated_digests "${no_te}"

  # Content-Digest and Repr-Digest cover compressed transfer bytes.
  # Unencoded-Digest covers the representation before local gzip.
  compressed="$(digest_response h2 "/h1/compressed?body=compressed-representation" \
    --header "Accept-Encoding: gzip")"
  assert_response_jq "${compressed}" '.headers["content-encoding"] == "gzip"'
  assert_digest_fields_anywhere "${compressed}" gzip

  # Warm the small static object first. Its hot bounded copy makes a complete
  # representation available for later range and HEAD responses without a read.
  response="$(digest_response h1 "/static/asset.txt")"
  assert_digest_fields "${response}" headers identity

  # Byte ranges carry a digest of selected bytes while the hot, bounded static
  # object supplies Repr-Digest and Unencoded-Digest without an extra read.
  ranged="$(digest_response h1 "/static/asset.txt" 206 --header "Range: bytes=2-5")"
  assert_response_jq "${ranged}" '.status == 206 and .body == "2345"'
  assert_static_digest_fields "${ranged}" body

  head="$(digest_response h1 "/static/asset.txt" --method HEAD)"
  assert_response_jq "${head}" '.status == 200 and .body_bytes == 0'
  assert_static_digest_fields "${head}" empty

  # An uncached disk file does not get a full-resource read for range or HEAD.
  ranged="$(protocol_probe_client h1 static-disk.example.test "/static/disk.txt" 206 \
    --header "TE: trailers" \
    --header "Range: bytes=0-3" \
    --header "Want-Content-Digest: sha-256=1" \
    --header "Want-Repr-Digest: sha-256=1" \
    --header "Want-Unencoded-Digest: sha-256=1")"
  assert_response_jq "${ranged}" '.body == "disk"'
  assert_content_digest_anywhere "${ranged}"
  head="$(protocol_probe_client h1 static-disk.example.test "/static/disk.txt" 200 \
    --method HEAD \
    --header "TE: trailers" \
    --header "Want-Content-Digest: sha-256=1" \
    --header "Want-Repr-Digest: sha-256=1" \
    --header "Want-Unencoded-Digest: sha-256=1")"
  assert_response_jq "${head}" '.body_bytes == 0'
  assert_content_digest_anywhere "${head}"
  response="$(digest_response h1 "/h1/status?status=204&body=no-content" 204)"
  assert_response_jq "${response}" '.status == 204 and .body_bytes == 0'
  assert_no_generated_digests "${response}"
  response="$(protocol_probe_client h1 static.example.test "/static/missing.txt" 404 \
    --header "TE: trailers" \
    --header "Want-Content-Digest: sha-256=1" \
    --header "Want-Repr-Digest: sha-256=1" \
    --header "Want-Unencoded-Digest: sha-256=1")"
  assert_response_jq "${response}" '.status == 404'
  assert_digest_fields_anywhere "${response}" identity

  # Request content coding remains an upstream request property. The response
  # digest is derived from the response only and does not decode or replay it.
  request_reencoded="$(digest_response h2 "/h2/request-encoding" --method POST \
    --body "encoded-request" --content-encoding gzip)"
  assert_body_jq "${request_reencoded}" '.headers["content-encoding"] == "gzip"'
  assert_content_digest_anywhere "${request_reencoded}"

  # A cache hit has locally materialized bytes, so delivery can generate fields
  # after the origin is gone without treating prior response fields as stored.
  first="$(digest_response h1 "/cache/value?body=cache-value&cache_control=public")"
  assert_digest_fields_anywhere "${first}" identity
  docker rm -f "${http_container}" >/dev/null
  cached="$(digest_response h1 "/cache/value?body=cache-value&cache_control=public")"
  assert_response_jq "${cached}" '.status == 200 and .body == "cache-value"'
  assert_digest_fields "${cached}" headers identity
}

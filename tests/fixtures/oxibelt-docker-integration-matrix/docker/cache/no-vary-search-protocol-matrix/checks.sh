nvs_request() {
  local downstream="$1"
  local path="$2"
  local method="$3"
  local body="$4"
  if [[ "${downstream}" == "h1" ]]; then
    client_request_with_headers "example.test" "${path}" 200 "${method}" "${body}" 'Content-Type: application/json'
  else
    protocol_probe_client_with_headers "${downstream}" "example.test" "${path}" 200 "${method}" "${body}" 'Content-Type: application/json'
  fi
}

assert_nvs() {
  assert_response_jq "$1" '.headers["no-vary-search"] == "params=(\"noise\")"'
}

run_case_checks() {
  local downstream target path first alias retained query_first query_alias query_changed head_seed head_alias
  local nvs="no_vary_search=params%3D%28%22noise%22%29"
  for downstream in h1 h2 h3; do
    for target in h1 h2 h3; do
      path="/${target}/nvs-get-${downstream}?body=get-${downstream}-${target}&noise=one&keep=stable&content_type=text/plain&${nvs}"
      first="$(nvs_request "${downstream}" "${path}" GET "")"
      assert_response_jq "${first}" '.headers["x-oxibelt-cache"] == "miss" and .body != ""'
      assert_nvs "${first}"

      alias="$(nvs_request "${downstream}" "${path/noise=one/noise=two}" GET "")"
      assert_response_jq "${alias}" '.headers["x-oxibelt-cache"] == "hit"'
      assert_nvs "${alias}"

      retained="$(nvs_request "${downstream}" "${path/keep=stable/keep=changed}" GET "")"
      assert_response_jq "${retained}" '.headers["x-oxibelt-cache"] == "miss"'

      query_first="$(nvs_request "${downstream}" "/${target}/nvs-query-${downstream}?noise=one&keep=stable&${nvs}" QUERY '{"selector":"one"}')"
      assert_response_jq "${query_first}" '.headers["x-oxibelt-cache"] == "miss"'
      assert_nvs "${query_first}"

      query_alias="$(nvs_request "${downstream}" "/${target}/nvs-query-${downstream}?noise=two&keep=stable&${nvs}" QUERY '{"selector":"one"}')"
      assert_response_jq "${query_alias}" '.headers["x-oxibelt-cache"] == "hit"'

      query_changed="$(nvs_request "${downstream}" "/${target}/nvs-query-${downstream}?noise=three&keep=stable&${nvs}" QUERY '{"selector":"two"}')"
      assert_response_jq "${query_changed}" '.headers["x-oxibelt-cache"] == "miss"'

      head_seed="$(nvs_request "${downstream}" "/${target}/nvs-head-${downstream}?body=head-${downstream}-${target}&noise=one&keep=stable&content_type=text/plain&${nvs}" GET "")"
      assert_response_jq "${head_seed}" '.headers["x-oxibelt-cache"] == "miss"'
      head_alias="$(nvs_request "${downstream}" "/${target}/nvs-head-${downstream}?body=head-${downstream}-${target}&noise=two&keep=stable&content_type=text/plain&${nvs}" HEAD "")"
      assert_response_jq "${head_alias}" '.headers["x-oxibelt-cache"] == "hit" and .body == ""'
      assert_nvs "${head_alias}"
    done
  done

  first="$(nvs_request h1 "/h1/nvs-order?a=one&b=two&body=order&content_type=text/plain&no_vary_search=params%3D%28%29%2Ckey-order%3D%3F1" GET "")"
  assert_response_jq "${first}" '.headers["x-oxibelt-cache"] == "miss"'
  alias="$(nvs_request h1 "/h1/nvs-order?b=two&a=one&body=order&content_type=text/plain&no_vary_search=params%3D%28%29%2Ckey-order%3D%3F1" GET "")"
  assert_response_jq "${alias}" '.headers["x-oxibelt-cache"] == "hit"'

  first="$(nvs_request h1 "/h1/nvs-except?noise=one&keep=stable&body=except&content_type=text/plain&no_vary_search=except%3D%28%22keep%22%29" GET "")"
  assert_response_jq "${first}" '.headers["x-oxibelt-cache"] == "miss"'
  alias="$(nvs_request h1 "/h1/nvs-except?noise=two&keep=stable&body=except&content_type=text/plain&no_vary_search=except%3D%28%22keep%22%29" GET "")"
  assert_response_jq "${alias}" '.headers["x-oxibelt-cache"] == "hit"'
  retained="$(nvs_request h1 "/h1/nvs-except?noise=two&keep=changed&body=except&content_type=text/plain&no_vary_search=except%3D%28%22keep%22%29" GET "")"
  assert_response_jq "${retained}" '.headers["x-oxibelt-cache"] == "miss"'

  first="$(nvs_request h1 "/h1/nvs-invalid?noise=one&body=invalid&content_type=text/plain&no_vary_search=params%3D%28%22noise%22%29%2Cexcept%3D%28%22keep%22%29" GET "")"
  assert_response_jq "${first}" '.headers["x-oxibelt-cache"] == "miss"'
  alias="$(nvs_request h1 "/h1/nvs-invalid?noise=two&body=invalid&content_type=text/plain&no_vary_search=params%3D%28%22noise%22%29%2Cexcept%3D%28%22keep%22%29" GET "")"
  assert_response_jq "${alias}" '.headers["x-oxibelt-cache"] == "miss"'

  first="$(nvs_request h1 "/key/nvs-token?v=one&noise=one&body=token&content_type=text/plain&${nvs}" GET "")"
  assert_response_jq "${first}" '.headers["x-oxibelt-cache"] == "miss"'
  alias="$(nvs_request h1 "/key/nvs-token?v=two&noise=two&body=token&content_type=text/plain&${nvs}" GET "")"
  assert_response_jq "${alias}" '.headers["x-oxibelt-cache"] == "miss"'
}

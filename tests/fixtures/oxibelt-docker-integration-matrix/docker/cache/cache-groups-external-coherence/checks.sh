run_case_checks() {
  local ordinary grouped cross_node safe ignored mutation invalidated port_seed port_other swr_first swr_stale swr_refreshed chain_a chain_b chain_c chain_a_hit chain_b_hit chain_c_hit chain_mutated chain_a_after chain_b_after chain_c_after

  ordinary="/app/ordinary?sequence_key=groups-ordinary&body_sequence=ordinary-one%7Cordinary-two&cache_control=public&content_type=text/plain"
  grouped="/app/grouped?sequence_key=groups-alpha&body_sequence=alpha-one%7Calpha-two&cache_control=public&content_type=text/plain&cache_groups=%22alpha%22"

  ordinary="$(client_request "example.test" "${ordinary}" 200)"
  assert_response_jq "${ordinary}" '.body == "ordinary-one" and .headers["x-oxibelt-cache"] == "miss"'
  sleep 1
  cross_node="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/ordinary?sequence_key=groups-ordinary&body_sequence=ordinary-one%7Cordinary-two&cache_control=public&content_type=text/plain" 200 "GET" "")"
  assert_response_jq "${cross_node}" '.body == "ordinary-one" and .headers["x-oxibelt-cache"] == "hit"'

  grouped="$(client_request "example.test" "${grouped}" 200)"
  assert_response_jq "${grouped}" '.body == "alpha-one" and .headers["x-oxibelt-cache"] == "miss"'
  sleep 1
  cross_node="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/grouped?sequence_key=groups-alpha&body_sequence=alpha-one%7Calpha-two&cache_control=public&content_type=text/plain&cache_groups=%22alpha%22" 200 "GET" "")"
  assert_response_jq "${cross_node}" '.body == "alpha-one" and .headers["x-oxibelt-cache"] == "hit"'

  safe="$(client_request "example.test" "/app/safe-ignore?body=safe&cache_control=public&content_type=text/plain&cache_group_invalidation=%22alpha%22" 200)"
  assert_response_jq "${safe}" '.body == "safe"'
  ignored="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/grouped?sequence_key=groups-alpha&body_sequence=alpha-one%7Calpha-two&cache_control=public&content_type=text/plain&cache_groups=%22alpha%22" 200 "GET" "")"
  assert_response_jq "${ignored}" '.body == "alpha-one" and .headers["x-oxibelt-cache"] == "hit"'

  mutation="$(client_request_with_headers "example.test" "/app/mutate?status=404&cache_group_invalidation=%22alpha%22" 404 "POST" "")"
  assert_response_jq "${mutation}" '.status == 404'
  invalidated="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/grouped?sequence_key=groups-alpha&body_sequence=alpha-one%7Calpha-two&cache_control=public&content_type=text/plain&cache_groups=%22alpha%22" 200 "GET" "")"
  assert_response_jq "${invalidated}" '.body == "alpha-two" and .headers["x-oxibelt-cache"] == "miss"'

  port_seed="$(client_request "example.test" "/app/port-scope?sequence_key=groups-port&body_sequence=port-one%7Cport-two&cache_control=public&content_type=text/plain&cache_groups=%22port%22" 200)"
  assert_response_jq "${port_seed}" '.body == "port-one"'
  port_other="$(client_request_with_headers "example.test:9443" "/app/port-scope?sequence_key=groups-port&body_sequence=port-one%7Cport-two&cache_control=public&content_type=text/plain&cache_groups=%22port%22" 200 "GET" "")"
  assert_response_jq "${port_other}" '.body == "port-two" and .headers["x-oxibelt-cache"] == "miss"'

  swr_first="$(client_request_with_headers "example.test:9443" "/app/group-swr?sequence_key=groups-swr-port&body_sequence=swr-old%7Cswr-new&cache_control_value=public%2C%20max-age%3D5%2C%20stale-while-revalidate%3D30&content_type=text/plain&cache_groups=%22swr%22" 200 "GET" "")"
  assert_response_jq "${swr_first}" '.body == "swr-old" and .headers["x-oxibelt-cache"] == "miss"'
  sleep 6
  swr_stale="$(client_request_with_headers "example.test:9443" "/app/group-swr?sequence_key=groups-swr-port&body_sequence=swr-old%7Cswr-new&cache_control_value=public%2C%20max-age%3D5%2C%20stale-while-revalidate%3D30&content_type=text/plain&cache_groups=%22swr%22" 200 "GET" "")"
  assert_response_jq "${swr_stale}" '.body == "swr-old" and .headers["x-oxibelt-cache"] == "stale" and .headers["x-oxibelt-cache-reason"] == "background_refresh"'
  sleep 0.2
  swr_refreshed="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test:9443" "/app/group-swr?sequence_key=groups-swr-port&body_sequence=swr-old%7Cswr-new&cache_control_value=public%2C%20max-age%3D5%2C%20stale-while-revalidate%3D30&content_type=text/plain&cache_groups=%22swr%22" 200 "GET" "")"
  assert_response_jq "${swr_refreshed}" '.body == "swr-new" and .headers["x-oxibelt-cache"] == "hit"'

  chain_a="$(client_request "example.test" "/app/chain-a?sequence_key=groups-chain-a&body_sequence=chain-a-one%7Cchain-a-two&cache_control=public&content_type=text/plain&cache_groups=%22seed%22%2C%20%22bridge%22" 200)"
  chain_b="$(client_request "example.test" "/app/chain-b?sequence_key=groups-chain-b&body_sequence=chain-b-one%7Cchain-b-two&cache_control=public&content_type=text/plain&cache_groups=%22bridge%22%2C%20%22leaf%22" 200)"
  chain_c="$(client_request "example.test" "/app/chain-c?sequence_key=groups-chain-c&body_sequence=chain-c-one%7Cchain-c-two&cache_control=public&content_type=text/plain&cache_groups=%22leaf%22" 200)"
  assert_response_jq "${chain_a}" '.body == "chain-a-one" and .headers["x-oxibelt-cache"] == "miss"'
  assert_response_jq "${chain_b}" '.body == "chain-b-one" and .headers["x-oxibelt-cache"] == "miss"'
  assert_response_jq "${chain_c}" '.body == "chain-c-one" and .headers["x-oxibelt-cache"] == "miss"'
  chain_a_hit="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/chain-a?sequence_key=groups-chain-a&body_sequence=chain-a-one%7Cchain-a-two&cache_control=public&content_type=text/plain&cache_groups=%22seed%22%2C%20%22bridge%22" 200 "GET" "")"
  chain_b_hit="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/chain-b?sequence_key=groups-chain-b&body_sequence=chain-b-one%7Cchain-b-two&cache_control=public&content_type=text/plain&cache_groups=%22bridge%22%2C%20%22leaf%22" 200 "GET" "")"
  chain_c_hit="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/chain-c?sequence_key=groups-chain-c&body_sequence=chain-c-one%7Cchain-c-two&cache_control=public&content_type=text/plain&cache_groups=%22leaf%22" 200 "GET" "")"
  assert_response_jq "${chain_a_hit}" '.body == "chain-a-one" and .headers["x-oxibelt-cache"] == "hit"'
  assert_response_jq "${chain_b_hit}" '.body == "chain-b-one" and .headers["x-oxibelt-cache"] == "hit"'
  assert_response_jq "${chain_c_hit}" '.body == "chain-c-one" and .headers["x-oxibelt-cache"] == "hit"'
  chain_mutated="$(client_request_with_headers "example.test" "/app/chain-mutate?status=404&cache_group_invalidation=%22bridge%22" 404 "POST" "")"
  assert_response_jq "${chain_mutated}" '.status == 404'
  chain_a_after="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/chain-a?sequence_key=groups-chain-a&body_sequence=chain-a-one%7Cchain-a-two&cache_control=public&content_type=text/plain&cache_groups=%22seed%22%2C%20%22bridge%22" 200 "GET" "")"
  chain_b_after="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/chain-b?sequence_key=groups-chain-b&body_sequence=chain-b-one%7Cchain-b-two&cache_control=public&content_type=text/plain&cache_groups=%22bridge%22%2C%20%22leaf%22" 200 "GET" "")"
  chain_c_after="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "/app/chain-c?sequence_key=groups-chain-c&body_sequence=chain-c-one%7Cchain-c-two&cache_control=public&content_type=text/plain&cache_groups=%22leaf%22" 200 "GET" "")"
  assert_response_jq "${chain_a_after}" '.body == "chain-a-two" and .headers["x-oxibelt-cache"] == "miss"'
  assert_response_jq "${chain_b_after}" '.body == "chain-b-two" and .headers["x-oxibelt-cache"] == "miss"'
  assert_response_jq "${chain_c_after}" '.body == "chain-c-one" and .headers["x-oxibelt-cache"] == "hit"'
}

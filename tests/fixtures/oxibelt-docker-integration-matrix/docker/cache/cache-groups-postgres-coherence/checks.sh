run_case_checks() {
  local ordinary grouped cross_node absolute_path absolute_sibling absolute_peer absolute_chain absolute_seed absolute_sibling_seed absolute_peer_seed absolute_chain_seed absolute_hit absolute_sibling_hit absolute_peer_hit absolute_chain_hit absolute_mutation absolute_after absolute_sibling_after absolute_peer_after absolute_chain_after safe ignored mutation invalidated port_seed port_other swr_first swr_stale swr_refreshed chain_a chain_b chain_c chain_a_hit chain_b_hit chain_c_hit chain_mutated chain_a_after chain_b_after chain_c_after

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

  absolute_path="/app/absolute?sequence_key=groups-absolute&body_sequence=absolute-one%7Cabsolute-two&cache_control=public&content_type=text/plain&cache_groups=%22absolute-seed%22"
  absolute_sibling="/app/absolute?sequence_key=groups-absolute-sibling&body_sequence=sibling-one%7Csibling-two&cache_control=public&content_type=text/plain&variant=two"
  absolute_peer="/app/absolute-peer?sequence_key=groups-absolute-peer&body_sequence=peer-one%7Cpeer-two&cache_control=public&content_type=text/plain&cache_groups=%22absolute-seed%22%2C%20%22absolute-leaf%22"
  absolute_chain="/app/absolute-chain?sequence_key=groups-absolute-chain&body_sequence=chain-one%7Cchain-two&cache_control=public&content_type=text/plain&cache_groups=%22absolute-leaf%22"
  absolute_seed="$(client_request "example.test" "${absolute_path}" 200)"
  absolute_sibling_seed="$(client_request "example.test" "${absolute_sibling}" 200)"
  absolute_peer_seed="$(client_request "example.test" "${absolute_peer}" 200)"
  absolute_chain_seed="$(client_request "example.test" "${absolute_chain}" 200)"
  assert_response_jq "${absolute_seed}" '.body == "absolute-one" and .headers["x-oxibelt-cache"] == "miss"'
  assert_response_jq "${absolute_sibling_seed}" '.body == "sibling-one" and .headers["x-oxibelt-cache"] == "miss"'
  assert_response_jq "${absolute_peer_seed}" '.body == "peer-one" and .headers["x-oxibelt-cache"] == "miss"'
  assert_response_jq "${absolute_chain_seed}" '.body == "chain-one" and .headers["x-oxibelt-cache"] == "miss"'
  sleep 1
  absolute_hit="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "${absolute_path}" 200 "GET" "")"
  absolute_sibling_hit="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "${absolute_sibling}" 200 "GET" "")"
  absolute_peer_hit="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "${absolute_peer}" 200 "GET" "")"
  absolute_chain_hit="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "${absolute_chain}" 200 "GET" "")"
  assert_response_jq "${absolute_hit}" '.body == "absolute-one" and .headers["x-oxibelt-cache"] == "hit"'
  assert_response_jq "${absolute_sibling_hit}" '.body == "sibling-one" and .headers["x-oxibelt-cache"] == "hit"'
  assert_response_jq "${absolute_peer_hit}" '.body == "peer-one" and .headers["x-oxibelt-cache"] == "hit"'
  assert_response_jq "${absolute_chain_hit}" '.body == "chain-one" and .headers["x-oxibelt-cache"] == "hit"'
  absolute_mutation="$(client_request_absolute_with_headers_to_target "proxy" 8443 "example.test" "${absolute_path}" 200 "POST" "")"
  assert_response_jq "${absolute_mutation}" '.body == "absolute-two"'
  absolute_after="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "${absolute_path}" 200 "GET" "")"
  absolute_sibling_after="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "${absolute_sibling}" 200 "GET" "")"
  absolute_peer_after="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "${absolute_peer}" 200 "GET" "")"
  absolute_chain_after="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "${absolute_chain}" 200 "GET" "")"
  assert_response_jq "${absolute_after}" '.body == "absolute-two" and .headers["x-oxibelt-cache"] == "miss"'
  assert_response_jq "${absolute_sibling_after}" '.body == "sibling-one" and .headers["x-oxibelt-cache"] == "hit"'
  assert_response_jq "${absolute_peer_after}" '.body == "peer-two" and .headers["x-oxibelt-cache"] == "miss"'
  assert_response_jq "${absolute_chain_after}" '.body == "chain-one" and .headers["x-oxibelt-cache"] == "hit"'

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

run_case_checks() {
  local response effective
  response="$(client_request "example.test" "/app/profile?case=edge-secure-medium" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/profile?case=edge-secure-medium"'

  effective="$(docker exec "${proxy_container}" /usr/local/bin/oxibelt \
    --config /etc/oxibelt/config/oxibelt.toml \
    --dump-effective-config)"
  grep -F 'profile = "edge-secure-medium"' <<<"${effective}" >/dev/null
  grep -F 'profile_version = 1' <<<"${effective}" >/dev/null
  grep -F 'min_version = "tls1.3"' <<<"${effective}" >/dev/null
  awk '
    /^\[waf\]$/ { in_waf = 1; next }
    in_waf && /^\[/ { exit }
    in_waf && $0 == "enabled = true" { enabled = 1 }
    in_waf && $0 == "mode = \"enforcing\"" { enforcing = 1 }
    END { exit !(enabled && enforcing) }
  ' <<<"${effective}"
}

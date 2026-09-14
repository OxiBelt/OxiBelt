run_case_checks() {
  local downstream
  for downstream in h1 h2 h3; do
    incremental_probe_client "${downstream}" /h3/duplex
  done
  incremental_probe_client h1 /h3/early204 204
  incremental_probe_client h1 /h3/fixedlength200 200 fixed-length-200
}

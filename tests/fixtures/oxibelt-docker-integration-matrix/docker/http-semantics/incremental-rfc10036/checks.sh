run_case_checks() {
  local downstream upstream
  for downstream in h1 h2 h3; do
    for upstream in h1 h2 h3; do
      incremental_probe_client "${downstream}" "/${upstream}/duplex"
    done
  done
  incremental_probe_client h3 /h1/early204 204
  incremental_probe_client h1 /h3/early204 204
  incremental_probe_client h1 /h3/fixedlength200 200 fixed-length-200
}

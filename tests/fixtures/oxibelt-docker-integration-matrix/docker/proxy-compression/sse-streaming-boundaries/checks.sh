run_case_checks() {
  local downstream coding
  for downstream in h1 h2 h3; do
    for coding in br zstd gzip deflate; do
      sse_probe_client "${downstream}" "/sse-compression" "${coding}"
    done
  done
}

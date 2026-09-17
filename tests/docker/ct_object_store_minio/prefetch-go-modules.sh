#!/bin/sh
# Fetch MinIO's Go modules before compilation so transient module acquisition
# failures are bounded and never turn a compile step into an implicit retry.
set -eu

attempt=1
while [ "${attempt}" -le 2 ]; do
  if timeout -s TERM -k 5 600 go mod download; then
    exit 0
  else
    status=$?
  fi

  if [ "${attempt}" -eq 2 ]; then
    printf '%s\n' "MinIO Go module prefetch failed after ${attempt} attempts (status ${status})" >&2
    exit "${status}"
  fi

  printf '%s\n' "MinIO Go module prefetch attempt ${attempt} failed (status ${status}); retrying" >&2
  sleep 5
  attempt=$((attempt + 1))
done

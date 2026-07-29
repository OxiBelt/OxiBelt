import argparse
import concurrent.futures
import json
import math
import os
import re
import sys
import threading

import client


MAX_CONCURRENCY = 64
MAX_TIMEOUT_SECONDS = 30
BARRIER_GRACE_SECONDS = 2
TARGET_HOST_RE = re.compile(r"^[A-Za-z0-9_.-]{1,253}$")


def parser():
  result = argparse.ArgumentParser()
  result.add_argument("--target-host", required=True)
  result.add_argument("--port", type=int, required=True)
  result.add_argument("--scheme", choices=("http", "https"), required=True)
  result.add_argument("--host", required=True)
  result.add_argument("--path", required=True)
  result.add_argument("--concurrency", type=int, required=True)
  result.add_argument("--timeout", type=float, required=True)
  result.add_argument("--ca-file")
  return result


def validate_args(args):
  if not TARGET_HOST_RE.fullmatch(args.target_host):
    raise ValueError("target host must contain only DNS-safe characters")
  if not 1 <= args.port <= 65535:
    raise ValueError("port must be in the range 1..65535")
  if not 1 <= args.concurrency <= MAX_CONCURRENCY:
    raise ValueError(f"concurrency must be in the range 1..{MAX_CONCURRENCY}")
  if (
    not math.isfinite(args.timeout)
    or not 1 <= args.timeout <= MAX_TIMEOUT_SECONDS
  ):
    raise ValueError(
      f"timeout must be in the range 1..{MAX_TIMEOUT_SECONDS} seconds"
    )
  if args.ca_file is not None and (
    not os.path.isfile(args.ca_file) or not os.access(args.ca_file, os.R_OK)
  ):
    raise ValueError("CA file must name a readable regular file")
  if args.scheme == "https" and args.ca_file is None:
    raise ValueError("HTTPS bursts require --ca-file")

  args.server_name = None
  return (
    client.validate_origin_form_path(args.path),
    client.validate_host_header(args.host),
  )


def error_document(index, error):
  return {
    "burst_index": index,
    "error": {
      "kind": type(error).__name__,
      "message": str(error),
    },
  }


def run_request(
  index,
  args,
  target_path,
  host_header,
  barrier,
  open_socket,
  send_request,
):
  sock = None
  barrier_passed = False
  try:
    sock = open_socket(args)
    try:
      barrier.wait(timeout=args.timeout + BARRIER_GRACE_SECONDS)
    except threading.BrokenBarrierError as error:
      raise RuntimeError(
        "request launch barrier aborted before every connection was ready"
      ) from error
    barrier_passed = True
    response, response_body_bytes = send_request(
      sock,
      "GET",
      target_path,
      host_header,
      [("Host", host_header)],
      b"",
      "close",
    )
    return {
      "burst_index": index,
      **client.response_document(response, response_body_bytes),
    }
  except Exception as error:
    if not barrier_passed:
      barrier.abort()
    return error_document(index, error)
  finally:
    if sock is not None:
      sock.close()


def run_burst(
  args,
  target_path,
  host_header,
  *,
  open_socket=None,
  send_request=None,
):
  open_socket = open_socket or client.open_proxy_socket
  send_request = send_request or client.send_http_request
  barrier = threading.Barrier(args.concurrency)
  with concurrent.futures.ThreadPoolExecutor(
    max_workers=args.concurrency,
    thread_name_prefix="oxibelt-burst",
  ) as executor:
    futures = [
      executor.submit(
        run_request,
        index,
        args,
        target_path,
        host_header,
        barrier,
        open_socket,
        send_request,
      )
      for index in range(1, args.concurrency + 1)
    ]
    results = [future.result() for future in futures]
  return sorted(results, key=lambda result: result["burst_index"])


def main(argv=None):
  args = parser().parse_args(argv)
  try:
    target_path, host_header = validate_args(args)
  except ValueError as error:
    sys.stderr.write(f"{error}\n")
    return 2

  try:
    results = run_burst(args, target_path, host_header)
  except Exception as error:
    sys.stderr.write(f"burst orchestration failed: {error}\n")
    return 1

  sys.stdout.write(json.dumps(results, sort_keys=True))
  failures = [result for result in results if "error" in result]
  for failure in failures:
    error = failure["error"]
    sys.stderr.write(
      "burst request "
      f"{failure['burst_index']} failed with {error['kind']}: {error['message']}\n"
    )
  return 1 if failures else 0


if __name__ == "__main__":
  raise SystemExit(main())

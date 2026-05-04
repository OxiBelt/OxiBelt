import argparse
import http.client
import ssl
import sys
import urllib.parse

TARGET_HOST = "proxy"
TARGET_PORT = 8443
TARGET_PATHS = {
  "http-ping": "/app/ping?source=http",
  "secure-health": "/secure/v1/health?source=https",
  "waf-blocked": "/app/blocked",
}


def validate_host_header(raw_host: str) -> str:
  if not raw_host:
    raise ValueError("Host header must not be empty")
  if any(ch.isspace() or ch == "\0" for ch in raw_host):
    raise ValueError("Host header must not contain whitespace or control characters")

  try:
    parsed = urllib.parse.urlsplit(f"//{raw_host}")
    _ = parsed.port
  except ValueError as error:
    raise ValueError(f"invalid Host header: {error}") from error

  if parsed.hostname is None or parsed.username or parsed.password:
    raise ValueError("Host header must contain only a host and optional port")

  return raw_host

def main() -> int:
  parser = argparse.ArgumentParser()
  parser.add_argument("--target", choices=sorted(TARGET_PATHS), required=True)
  parser.add_argument("--host", required=True)
  parser.add_argument("--ca-file")
  parser.add_argument("--timeout", type=float, default=5.0)
  args = parser.parse_args()

  try:
    target_path = TARGET_PATHS[args.target]
    host_header = validate_host_header(args.host)
  except ValueError as error:
    sys.stderr.write(f"{error}\n")
    return 2

  if args.ca_file:
    context = ssl.create_default_context(cafile=args.ca_file)
  else:
    context = ssl.create_default_context()

  connection = http.client.HTTPSConnection(
    TARGET_HOST,
    TARGET_PORT,
    context=context,
    timeout=args.timeout,
  )
  try:
    connection.request("GET", target_path, headers={"Host": host_header})
    response = connection.getresponse()
    sys.stdout.write(response.read().decode("utf-8"))
    if 200 <= response.status < 400:
      return 0
    return 1
  finally:
    connection.close()


if __name__ == "__main__":
  raise SystemExit(main())
